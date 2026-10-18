//! The reusing stage itself.
//!
//! For a testcase the scan left taint data for: overwrite one of its tainted
//! byte ranges with a pool value of the same shape, run it, put the bytes
//! back, repeat.
//!
//! A visit does not try to work through an input. An nm seed can carry a
//! thousand range sets over half a million pool values, so the choice is
//! between trying a few values at many sites and many values at a few. This
//! takes the first: [`TRIES_PER_RANGE_SET`] values at each set in turn, round
//! and round until the budget is gone, leaving a cursor per set so the next
//! visit picks each one up where this one stopped. Draining one set before
//! starting the next would spend a whole visit inside the first, and every
//! site past it would go untouched for the campaign.
//!
//! Ported from `AFLplusplus_reusing/src/afl-fuzz-reusing.c` (`reusing_stage`).

use core::{marker::PhantomData, ops::Range};
use std::path::PathBuf;

use libafl::{
    inputs::{HasMutatorBytes, Input},
    stages::Stage,
    state::{HasCorpus, HasCurrentTestcase, HasRand, UsesState},
    Error, Evaluator, HasMetadata,
};

use crate::{
    dtaint::TaintMap,
    meta::ReusingCursors,
    pool::ReusingPool,
    MAX_EXEC, MIN_EXEC, TRIES_PER_RANGE_SET,
};

/// See the module docs.
#[derive(Debug)]
pub struct ReusingStage<E, EM, Z> {
    /// Where the scan's output lives. Read-only, and shared by every trial of
    /// every campaign against this corpus.
    dir: PathBuf,
    /// `value_pool.dict` and `unsolved_condition`, loaded once.
    pool: ReusingPool,
    stats: StageStats,
    phantom: PhantomData<(E, EM, Z)>,
}

/// What the stage has done so far, for the log.
#[derive(Debug, Default, Clone, Copy)]
pub struct StageStats {
    /// Visits that found something to try.
    pub visits: u64,
    /// Target executions asked for.
    pub execs: u64,
    /// Testcases retired: nothing left in the pool for what they read.
    pub retired: u64,
    /// Testcases passed over for having no `.dtaint`.
    pub no_taint: u64,
}

impl<E, EM, Z> ReusingStage<E, EM, Z> {
    /// Loads the scan's output from `dir`.
    ///
    /// Fails loudly when it is not there: a campaign that quietly fuzzes
    /// without its pool is indistinguishable from a baseline afterwards.
    pub fn new(dir: PathBuf) -> Result<Self, Error> {
        let pool = ReusingPool::load(&dir).map_err(|e| Error::illegal_argument(e.to_string()))?;

        Ok(Self {
            dir,
            pool,
            stats: StageStats::default(),
            phantom: PhantomData,
        })
    }

    #[must_use]
    pub fn pool(&self) -> &ReusingPool {
        &self.pool
    }

    #[must_use]
    pub fn stats(&self) -> StageStats {
        self.stats
    }
}

impl<E, EM, Z> UsesState for ReusingStage<E, EM, Z>
where
    E: UsesState,
{
    type State = E::State;
}

impl<E, EM, Z> Stage<E, EM, Z> for ReusingStage<E, EM, Z>
where
    E: UsesState,
    EM: UsesState<State = Self::State>,
    Z: Evaluator<E, EM, State = Self::State>,
    Self::State: HasCorpus + HasRand + HasMetadata + HasCurrentTestcase<Self::Input>,
    Self::Input: HasMutatorBytes + Clone,
{
    fn perform(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut Self::State,
        manager: &mut EM,
    ) -> Result<(), Error> {
        let Some((map, mut cursors)) = self.taint_for_current(state)? else {
            return Ok(());
        };

        // Which sets can actually be written to, and with what.
        let mut live: Vec<LiveSet> = map
            .sets
            .iter()
            .filter_map(|set| {
                let bucket = self.pool.bucket(&set.pattern())?;
                let cursor = cursors.get(set.idx);

                (bucket.entries.len() as u32 > cursor).then_some(LiveSet {
                    set_idx: set.idx,
                    ranges: &set.ranges,
                    bucket,
                    cursor,
                })
            })
            .collect();

        // Budget is per live set, not per site: sites reading the same bytes
        // already share a set, and a set with nothing left in the pool would
        // otherwise inflate the figure without being able to spend it.
        let remaining: usize = live.iter().map(LiveSet::untried).sum();
        let budget = (live.len() * TRIES_PER_RANGE_SET).clamp(MIN_EXEC, MAX_EXEC);
        let total = remaining.min(budget);

        if total == 0 {
            cursors.set_done();
            self.stats.retired += 1;
            return save_cursors(state, cursors);
        }

        let original = state.current_input_cloned()?;
        let mut scratch = original.clone();
        let mut spent = 0usize;

        // Round-robin. The second and later laps only matter when some sets
        // ran dry early: with every set still holding values, the first lap
        // spends the budget exactly, in one pass over the array.
        'budget: while spent < total {
            let mut progressed = false;

            for live in &mut live {
                for _ in 0..TRIES_PER_RANGE_SET {
                    if spent == total {
                        break 'budget;
                    }

                    let Some(entry) = live.next_entry() else { break };
                    progressed = true;

                    apply(scratch.bytes_mut(), live.ranges, &entry.segs);
                    fuzzer.evaluate_input(state, executor, manager, scratch.clone())?;
                    restore(scratch.bytes_mut(), original.bytes(), live.ranges);

                    cursors.advance(live.set_idx);
                    spent += 1;
                }
            }

            // Every live set is exhausted; the budget cannot be spent.
            if !progressed {
                break;
            }
        }

        self.stats.visits += 1;
        self.stats.execs += spent as u64;

        // The budget covered everything that was left, so saying so here saves
        // the next visit from re-reading and re-parsing the .dtaint only to
        // find nothing. Compared against the budget this visit actually got,
        // not against the constant it came from.
        if remaining <= total {
            cursors.set_done();
            self.stats.retired += 1;
        }

        save_cursors(state, cursors)
    }

    fn should_restart(&mut self, _state: &mut Self::State) -> Result<bool, Error> {
        // Cursors live on the testcase and only ever move forward, so a
        // restart resumes correctly with no extra tracking.
        Ok(true)
    }

    fn clear_progress(&mut self, _state: &mut Self::State) -> Result<(), Error> {
        Ok(())
    }
}

impl<E, EM, Z> ReusingStage<E, EM, Z> {
    /// The current testcase's taint map and cursors, or `None` when there is
    /// nothing for this stage to do.
    ///
    /// The map is parsed fresh every visit, as the C fuzzer does: a parsed map
    /// for a large input is tens of megabytes, far more than re-parsing costs.
    fn taint_for_current<S, I>(
        &mut self,
        state: &S,
    ) -> Result<Option<(TaintMap, ReusingCursors)>, Error>
    where
        S: HasCurrentTestcase<I> + HasMetadata,
        I: Input,
    {
        let testcase = state.current_testcase()?;

        let cursors = testcase
            .metadata::<ReusingCursors>()
            .cloned()
            .unwrap_or_default();

        // Everything below needs the .dtaint parsed just to find out there is
        // nothing to do, so a retired testcase is remembered instead of
        // reaching the same conclusion on every visit.
        if cursors.is_done() {
            return Ok(None);
        }

        // Keyed by the name the scan saw, which is the name the seed carried
        // when it was imported.
        let Some(name) = testcase.filename().clone() else {
            return Ok(None);
        };

        drop(testcase);

        // A seed with no .dtaint is normal, not an error: the scan writes no
        // file for an input the target had nothing taint-worthy to say about.
        let Ok(mut map) = TaintMap::load(&self.dir, &name) else {
            self.stats.no_taint += 1;
            return Ok(None);
        };

        map.filter_unsolved(|site| self.pool.is_unsolved(site));

        let mut cursors = cursors;
        cursors.resize(map.n_all);

        Ok(Some((map, cursors)))
    }
}

/// One range set this visit can write to, with where its cursor stands.
struct LiveSet<'a> {
    /// Index into the cursor array -- the set's position *before* filtering.
    set_idx: usize,
    ranges: &'a [Range<u32>],
    bucket: &'a crate::pool::ValueBucket,
    /// Next untried entry in `bucket`.
    cursor: u32,
}

impl<'a> LiveSet<'a> {
    fn next_entry(&mut self) -> Option<&'a crate::pool::PoolEntry> {
        let entry = self.bucket.entries.get(self.cursor as usize)?;
        self.cursor += 1;
        Some(entry)
    }

    fn untried(&self) -> usize {
        self.bucket.entries.len().saturating_sub(self.cursor as usize)
    }
}

fn save_cursors<S, I>(state: &mut S, cursors: ReusingCursors) -> Result<(), Error>
where
    S: HasCurrentTestcase<I> + HasMetadata,
    I: Input,
{
    state.current_testcase_mut()?.add_metadata(cursors);
    Ok(())
}

/// Writes one pool entry's segments over a range set's ranges.
///
/// A range reaching past the end of the input is skipped rather than clamped:
/// the pool entry was derived for the whole span, and writing a prefix of it
/// would be a value the scan never saw work.
#[inline]
pub fn apply(buf: &mut [u8], ranges: &[Range<u32>], segs: &[Vec<u8>]) {
    for (range, seg) in ranges.iter().zip(segs) {
        let at = range.start as usize;

        if at + seg.len() <= buf.len() {
            buf[at..at + seg.len()].copy_from_slice(seg);
        }
    }
}

/// Puts back what [`apply`] overwrote.
#[inline]
pub fn restore(buf: &mut [u8], original: &[u8], ranges: &[Range<u32>]) {
    for range in ranges {
        let (start, end) = (range.start as usize, range.end as usize);

        if end <= buf.len() && end <= original.len() {
            buf[start..end].copy_from_slice(&original[start..end]);
        }
    }
}
