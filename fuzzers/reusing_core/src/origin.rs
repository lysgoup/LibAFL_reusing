//! Where each corpus entry came from: its parent, the stage that produced it,
//! and the havoc mutations or the reusing write that made it.
//!
//! The record has to be on the testcase before the corpus adds it: an
//! `OnDiskCorpus` writes an entry's `.metadata` once, at that point, and
//! metadata added afterwards (`LoggerScheduledMutator`'s, the reusing cursors)
//! never reaches the disk. So the pieces are staged on the state as the
//! fuzzer goes -- [`StageLabel`] names the running stage, [`OriginMutator`]
//! the mutations it just drew, the reusing stage its write -- and
//! [`OriginFeedback`], which never calls anything interesting, copies them
//! onto the testcase in `append_metadata`, the one hook the fuzzer runs on a
//! new entry before adding it.
//!
//! None of it changes what the fuzzer does: [`OriginMutator`] draws exactly
//! the random numbers `StdScheduledMutator::scheduled_mutate` draws, and the
//! feedback's verdict is always `false` inside an OR.
//!
//! This file is copied verbatim into unibench's forkserver_libafl patch, which
//! cannot depend on this crate; keep the two the same.

use std::{borrow::Cow, marker::PhantomData};

use libafl::{
    corpus::{Corpus, Testcase},
    events::EventFirer,
    executors::ExitKind,
    feedbacks::Feedback,
    mutators::{MutationResult, Mutator, MutatorsTuple, ScheduledMutator},
    observers::ObserversTuple,
    stages::Stage,
    state::{HasCorpus, HasRand, State, UsesState},
    Error, HasMetadata,
};
use libafl_bolts::{impl_serdeany, rands::Rand, tuples::NamedTuple, Named};
use serde::{Deserialize, Serialize};

/// One reusing-stage write, as the stage made it.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ReusingWrite {
    /// The seed written over, by the name its `.dtaint` has.
    pub seed: String,
    /// The range set's index in that `.dtaint`'s sets.
    pub set_idx: usize,
    /// The pool entry's index in its bucket (the set's cursor).
    pub entry_idx: u32,
    /// Where the values went, as `[start, end)` byte offsets.
    pub ranges: Vec<(u32, u32)>,
    /// The segments written, one per range, as hex.
    pub written_hex: Vec<String>,
    /// The seed's bytes they replaced, as hex.
    pub original_hex: Vec<String>,
}

/// A reusing write as the stage stages it, raw: it is made for every try,
/// and only the few that become corpus entries are turned into hex.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PendingWrite {
    pub seed: String,
    pub set_idx: usize,
    pub entry_idx: u32,
    pub ranges: Vec<(u32, u32)>,
    pub written: Vec<Vec<u8>>,
    pub original: Vec<Vec<u8>>,
}

impl PendingWrite {
    fn to_write(&self) -> ReusingWrite {
        ReusingWrite {
            seed: self.seed.clone(),
            set_idx: self.set_idx,
            entry_idx: self.entry_idx,
            ranges: self.ranges.clone(),
            written_hex: self.written.iter().map(|b| hex(b)).collect(),
            original_hex: self.original.iter().map(|b| hex(b)).collect(),
        }
    }
}

/// What the running stage has done to the input being executed; the state
/// carries it until the next execution replaces it.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PendingOrigin {
    pub stage: String,
    pub mutations: Vec<String>,
    pub reusing: Option<PendingWrite>,
}
impl_serdeany!(PendingOrigin);

/// The record on a corpus entry: where it came from.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Origin {
    /// The corpus entry being fuzzed when this one was found (its file
    /// name); none for an initial input.
    pub parent: Option<String>,
    /// The stage that produced it; "seed" for an initial input.
    pub stage: String,
    /// The havoc mutations applied, in order, for a mutational stage.
    pub mutations: Vec<String>,
    /// The write, for the reusing stage.
    pub reusing: Option<ReusingWrite>,
}
impl_serdeany!(Origin);

/// Hex of a byte slice, for [`ReusingWrite`].
#[must_use]
pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// A stage under a name: while it runs, what it produces is recorded as
/// coming from `label`.
#[derive(Debug)]
pub struct StageLabel<ST> {
    label: &'static str,
    inner: ST,
}

impl<ST> StageLabel<ST> {
    pub fn new(label: &'static str, inner: ST) -> Self {
        Self { label, inner }
    }
}

impl<ST> UsesState for StageLabel<ST>
where
    ST: UsesState,
{
    type State = ST::State;
}

impl<E, EM, Z, ST> Stage<E, EM, Z> for StageLabel<ST>
where
    ST: Stage<E, EM, Z>,
    E: UsesState<State = ST::State>,
    EM: UsesState<State = ST::State>,
    Z: UsesState<State = ST::State>,
    ST::State: HasMetadata,
{
    fn should_restart(&mut self, state: &mut Self::State) -> Result<bool, Error> {
        self.inner.should_restart(state)
    }

    fn clear_progress(&mut self, state: &mut Self::State) -> Result<(), Error> {
        self.inner.clear_progress(state)
    }

    fn perform(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut Self::State,
        manager: &mut EM,
    ) -> Result<(), Error> {
        state.add_metadata(PendingOrigin {
            stage: self.label.into(),
            ..PendingOrigin::default()
        });
        let res = self.inner.perform(fuzzer, executor, state, manager);
        state.add_metadata(PendingOrigin::default());
        res
    }
}

/// A `StdScheduledMutator` that also records which mutations it applied.
///
/// It draws the same numbers in the same order as
/// `ScheduledMutator::scheduled_mutate` over `StdScheduledMutator`
/// (`iterations()`, then `below(number of mutations)` per stacked mutation),
/// so wrapping does not change the fuzzer; it only needs the index to name
/// the mutation, which `MutationId` does not give out.
#[derive(Debug)]
pub struct OriginMutator<I, MT, S, SM> {
    name: Cow<'static, str>,
    inner: SM,
    phantom: PhantomData<(I, MT, S)>,
}

impl<I, MT, S, SM> OriginMutator<I, MT, S, SM>
where
    SM: Named,
{
    pub fn new(inner: SM) -> Self {
        Self {
            name: Cow::from(format!("OriginMutator[{}]", inner.name())),
            inner,
            phantom: PhantomData,
        }
    }
}

impl<I, MT, S, SM> Named for OriginMutator<I, MT, S, SM> {
    fn name(&self) -> &Cow<'static, str> {
        &self.name
    }
}

impl<I, MT, S, SM> Mutator<I, S> for OriginMutator<I, MT, S, SM>
where
    MT: MutatorsTuple<I, S> + NamedTuple,
    S: HasRand + HasMetadata,
    SM: ScheduledMutator<I, MT, S>,
{
    fn mutate(&mut self, state: &mut S, input: &mut I) -> Result<MutationResult, Error> {
        let mut res = MutationResult::Skipped;
        let num = self.inner.iterations(state, input);
        let mut names = Vec::with_capacity(num as usize);
        for _ in 0..num {
            let idx = state.rand_mut().below(MT::LEN);
            names.push(
                self.inner
                    .mutations()
                    .name(idx)
                    .map_or_else(String::new, |n| n.to_string()),
            );
            if self.inner.mutations_mut().get_and_mutate(idx.into(), state, input)?
                == MutationResult::Mutated
            {
                res = MutationResult::Mutated;
            }
        }
        if let Ok(pending) = state.metadata_mut::<PendingOrigin>() {
            pending.mutations = names;
            pending.reusing = None;
        }
        Ok(res)
    }

    fn post_exec(
        &mut self,
        state: &mut S,
        new_corpus_id: Option<libafl::corpus::CorpusId>,
    ) -> Result<(), Error> {
        self.inner.post_exec(state, new_corpus_id)
    }
}

/// Copies the staged [`PendingOrigin`] and the parent's name onto every new
/// corpus entry as an [`Origin`]. Never interesting by itself.
#[derive(Debug, Default)]
pub struct OriginFeedback;

impl OriginFeedback {
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl Named for OriginFeedback {
    fn name(&self) -> &Cow<'static, str> {
        static NAME: Cow<'static, str> = Cow::Borrowed("OriginFeedback");
        &NAME
    }
}

impl<S> Feedback<S> for OriginFeedback
where
    S: State + HasCorpus + HasMetadata,
{
    fn is_interesting<EM, OT>(
        &mut self,
        _state: &mut S,
        _manager: &mut EM,
        _input: &S::Input,
        _observers: &OT,
        _exit_kind: &ExitKind,
    ) -> Result<bool, Error>
    where
        EM: EventFirer<State = S>,
        OT: ObserversTuple<S>,
    {
        Ok(false)
    }

    #[cfg(feature = "track_hit_feedbacks")]
    fn last_result(&self) -> Result<bool, Error> {
        Ok(false)
    }

    fn append_metadata<EM, OT>(
        &mut self,
        state: &mut S,
        _manager: &mut EM,
        _observers: &OT,
        testcase: &mut Testcase<S::Input>,
    ) -> Result<(), Error>
    where
        OT: ObserversTuple<S>,
        EM: EventFirer<State = S>,
    {
        let pending = state
            .metadata::<PendingOrigin>()
            .cloned()
            .unwrap_or_default();
        let parent = match *state.corpus().current() {
            Some(id) => state.corpus().get(id)?.borrow().filename().clone(),
            None => None,
        };
        let stage = if pending.stage.is_empty() {
            String::from("seed")
        } else {
            pending.stage
        };
        testcase.add_metadata(Origin {
            parent,
            stage,
            mutations: pending.mutations,
            reusing: pending.reusing.as_ref().map(PendingWrite::to_write),
        });
        Ok(())
    }
}
