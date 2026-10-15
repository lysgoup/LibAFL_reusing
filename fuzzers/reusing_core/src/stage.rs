//! The reusing stage itself.
//!
//! One visit does not try to work through an input: an nm seed can carry a
//! thousand range sets over half a million pool values. It spends
//! [`TRIES_PER_RANGE_SET`](crate::TRIES_PER_RANGE_SET) values on each set in
//! turn, round and round until the budget is gone, and leaves a cursor per set
//! so the next visit picks each one up where this left it. Draining one set
//! before starting the next would spend a whole visit inside the first.

use core::marker::PhantomData;
use std::path::PathBuf;

use libafl::{
    stages::Stage,
    state::{HasCorpus, HasRand, UsesState},
    Error, HasMetadata,
};

/// See the module docs.
#[derive(Debug)]
pub struct ReusingStage<E, EM, Z> {
    /// Where `value_pool.dict`, `unsolved_condition` and the `.dtaint` files
    /// live. Read-only, and shared by every trial of every campaign against
    /// this corpus.
    dir: PathBuf,
    phantom: PhantomData<(E, EM, Z)>,
}

impl<E, EM, Z> ReusingStage<E, EM, Z> {
    #[must_use]
    pub fn new(dir: PathBuf) -> Self {
        Self {
            dir,
            phantom: PhantomData,
        }
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
    Z: UsesState<State = Self::State>,
    Self::State: HasCorpus + HasRand + HasMetadata,
{
    fn perform(
        &mut self,
        _fuzzer: &mut Z,
        _executor: &mut E,
        _state: &mut Self::State,
        _manager: &mut EM,
    ) -> Result<(), Error> {
        // 1. cursors.done -> return
        //
        // 2. load this testcase's .dtaint (by its corpus filename, which is
        //    what the scan keyed it by); none -> done = true, return
        //
        // 3. filter out the sites the scan already solved
        //
        // 4. size the cursor array to the unfiltered set count
        //
        // 5. walk the sets once: look each one's pool bucket up by shape, and
        //    count
        //      live      -- sets with a bucket and an unexhausted cursor
        //      remaining -- untried (set, value) pairs, for the progress total
        //
        // 6. budget = clamp(live * TRIES_PER_RANGE_SET, MIN_EXEC, MAX_EXEC)
        //    total  = min(remaining, budget);  zero -> done = true, return
        //
        // 7. round-robin until the budget is gone:
        //      for each set with a bucket:
        //          up to TRIES_PER_RANGE_SET times, cursor permitting:
        //              write the entry's segments over the set's ranges
        //              evaluate_input
        //              put the original bytes back
        //
        //    The second and later laps only matter when some sets ran dry
        //    early; with every set still holding values the first lap spends
        //    the budget exactly, in one pass.
        //
        // 8. if the budget covered everything left, done = true -- that saves
        //    the next visit from re-reading and re-parsing the .dtaint only to
        //    find nothing. Compare against the budget this visit actually got,
        //    not the constant it came from.
        todo!("see the outline above and afl-fuzz-reusing.c:1279 reusing_stage")
    }

    fn should_restart(&mut self, _state: &mut Self::State) -> Result<bool, Error> {
        // Cursors live on the testcase and only ever move forward, so a
        // restart resumes correctly without extra tracking.
        Ok(true)
    }

    fn clear_progress(&mut self, _state: &mut Self::State) -> Result<(), Error> {
        Ok(())
    }
}

/// Writes one pool entry's segments over a range set's ranges.
#[inline]
pub fn apply(_buf: &mut [u8], _ranges: &[core::ops::Range<u32>], _segs: &[Vec<u8>]) {
    todo!("memcpy per segment")
}

/// Puts back what [`apply`] overwrote.
#[inline]
pub fn restore(_buf: &mut [u8], _orig: &[u8], _ranges: &[core::ops::Range<u32>]) {
    todo!("memcpy per range from the untouched copy")
}

/// Attaches the scan's per-seed data to the corpus after the initial inputs
/// are loaded.
///
/// AFL++ did this in the dry run's pivot, the one moment it held both the
/// seed's own filename and the name the entry got in the queue. LibAFL loads
/// the corpus in one call instead, so this walks it afterwards: for each
/// testcase, mark it [`FromSeed`](crate::meta::FromSeed) and, if the cache has
/// a `.dtaint` under its filename, note that it has taint data.
pub fn attach_seed_taint<S>(_state: &mut S, _dir: &PathBuf) -> Result<(usize, usize), String>
where
    S: HasCorpus + HasMetadata,
{
    todo!("walk the corpus, mark from_seed, report (with_taint, without)")
}
