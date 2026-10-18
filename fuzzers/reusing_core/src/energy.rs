//! The energy split, as far as this baseline has an energy to split.
//!
//! AFL++ scales `perf_score`: an entry this campaign found itself gets
//! [`NEW_ENERGY_MULT`](crate::NEW_ENERGY_MULT) times its share, a seed gives
//! up [`SEED_ENERGY_DIV`](crate::SEED_ENERGY_DIV) of its own. The reasoning is
//! measured, not guessed: reusing saturates early, and seeds outnumber real
//! finds by a lot (objdump: 3782 seeds against 131 finds in 24 h), so paying
//! seeds the same would spend the budget on the inputs a previous campaign
//! already fuzzed for 24 h.
//!
//! This fuzzer has no `perf_score`. `StdMutationalStage` draws its iteration
//! count as `1 + rand(128)`, flat, whatever the input. So the same trade is
//! made where the count is drawn instead, which leaves the scheduler and the
//! baseline arm untouched -- the alternative, swapping in `PowerQueueScheduler`,
//! would change what we are comparing against.
//!
//! The shape: [`ReusingEnergyStage`] wraps the inner stage as a
//! [`MutationalStage`] rather than a plain [`Stage`], overrides only
//! [`iterations`](MutationalStage::iterations), and leaves the mutator and the
//! mutate-evaluate loop to the trait's own `perform_mutational`. Repeating the
//! inner stage's `perform` would redraw the count per repeat and re-enter the
//! restart bookkeeping each time; this scales the one draw AFL++ scales.
//!
//! Ported from `AFLplusplus_reusing/src/afl-fuzz-one.c` (the
//! `afl->reusing_mode` block after `PERFORMANCE SCORE`).

use core::marker::PhantomData;

use libafl::{
    mutators::Mutator,
    stages::{
        mutational::{MutatedTransform, DEFAULT_MUTATIONAL_MAX_ITERATIONS},
        MutationalStage, Stage,
    },
    state::{HasCorpus, HasCurrentTestcase, HasRand, UsesState},
    Error, Evaluator, HasMetadata,
};

use crate::{meta::FromSeed, NEW_ENERGY_MULT, SEED_ENERGY_DIV};

/// Scales one iteration draw the way AFL++ scales `perf_score`.
///
/// A seed gives up [`SEED_ENERGY_DIV`] of its share but never reaches zero --
/// AFL++ floors at 1, and a zero here would skip the entry entirely rather
/// than deprioritize it. Everything else gets [`NEW_ENERGY_MULT`] times its
/// draw, capped at the mult times the ordinary ceiling, as AFL++ caps the
/// boost at `havoc_max_mult * 100 * REUSING_NEW_ENERGY_MULT`.
#[must_use]
pub fn scale(base: usize, from_seed: bool) -> usize {
    if from_seed {
        (base / SEED_ENERGY_DIV).max(1)
    } else {
        (base * NEW_ENERGY_MULT).min(DEFAULT_MUTATIONAL_MAX_ITERATIONS * NEW_ENERGY_MULT)
    }
}

/// Wraps a mutational stage and rescales how many iterations it runs.
///
/// Seeds get half, everything else eight times, capped the way AFL++ caps the
/// boost at the ordinary havoc ceiling.
#[derive(Debug)]
pub struct ReusingEnergyStage<ST, E, EM, I, M, Z> {
    inner: ST,
    #[allow(clippy::type_complexity)]
    phantom: PhantomData<(E, EM, I, M, Z)>,
}

impl<ST, E, EM, I, M, Z> ReusingEnergyStage<ST, E, EM, I, M, Z> {
    #[must_use]
    pub fn new(inner: ST) -> Self {
        Self {
            inner,
            phantom: PhantomData,
        }
    }
}

impl<ST, E, EM, I, M, Z> UsesState for ReusingEnergyStage<ST, E, EM, I, M, Z>
where
    E: UsesState,
{
    type State = E::State;
}

impl<ST, E, EM, I, M, Z> MutationalStage<E, EM, I, M, Z>
    for ReusingEnergyStage<ST, E, EM, I, M, Z>
where
    E: UsesState,
    EM: UsesState<State = Self::State>,
    Z: Evaluator<E, EM, State = Self::State>,
    M: Mutator<I, Self::State>,
    ST: MutationalStage<E, EM, I, M, Z, State = Self::State>,
    Self::State: HasCorpus + HasRand + HasMetadata + HasCurrentTestcase<Self::Input>,
    I: MutatedTransform<Self::Input, Self::State> + Clone,
{
    fn mutator(&self) -> &M {
        self.inner.mutator()
    }

    fn mutator_mut(&mut self) -> &mut M {
        self.inner.mutator_mut()
    }

    /// The inner stage's draw, rescaled by whether the current testcase is a
    /// seed. [`FromSeed`] is set at load time and never afterwards, so this is
    /// the only place the split exists.
    fn iterations(&self, state: &mut Self::State) -> Result<usize, Error> {
        let base = self.inner.iterations(state)?;
        let from_seed = state.current_testcase()?.has_metadata::<FromSeed>();

        Ok(scale(base, from_seed))
    }
}

impl<ST, E, EM, I, M, Z> Stage<E, EM, Z> for ReusingEnergyStage<ST, E, EM, I, M, Z>
where
    E: UsesState,
    EM: UsesState<State = Self::State>,
    Z: Evaluator<E, EM, State = Self::State>,
    M: Mutator<I, Self::State>,
    ST: MutationalStage<E, EM, I, M, Z, State = Self::State>,
    Self::State: HasCorpus + HasRand + HasMetadata + HasCurrentTestcase<Self::Input>,
    I: MutatedTransform<Self::Input, Self::State> + Clone,
{
    fn perform(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut Self::State,
        manager: &mut EM,
    ) -> Result<(), Error> {
        self.perform_mutational(fuzzer, executor, state, manager)
    }

    fn should_restart(&mut self, state: &mut Self::State) -> Result<bool, Error> {
        self.inner.should_restart(state)
    }

    fn clear_progress(&mut self, state: &mut Self::State) -> Result<(), Error> {
        self.inner.clear_progress(state)
    }
}
