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

use core::marker::PhantomData;

use libafl::{
    stages::Stage,
    state::{HasCorpus, HasRand, UsesState},
    Error, HasMetadata,
};

/// Wraps a mutational stage and rescales how many iterations it runs.
///
/// Seeds get half, everything else eight times, capped the way AFL++ caps the
/// boost at the ordinary havoc ceiling.
#[derive(Debug)]
pub struct ReusingEnergyStage<ST, E, EM, Z> {
    inner: ST,
    phantom: PhantomData<(E, EM, Z)>,
}

impl<ST, E, EM, Z> ReusingEnergyStage<ST, E, EM, Z> {
    #[must_use]
    pub fn new(inner: ST) -> Self {
        Self {
            inner,
            phantom: PhantomData,
        }
    }
}

impl<ST, E, EM, Z> UsesState for ReusingEnergyStage<ST, E, EM, Z>
where
    E: UsesState,
{
    type State = E::State;
}

impl<ST, E, EM, Z> Stage<E, EM, Z> for ReusingEnergyStage<ST, E, EM, Z>
where
    E: UsesState,
    EM: UsesState<State = Self::State>,
    Z: UsesState<State = Self::State>,
    ST: Stage<E, EM, Z, State = Self::State>,
    Self::State: HasCorpus + HasRand + HasMetadata,
{
    fn perform(
        &mut self,
        _fuzzer: &mut Z,
        _executor: &mut E,
        _state: &mut Self::State,
        _manager: &mut EM,
    ) -> Result<(), Error> {
        // Read FromSeed off the current testcase, then run the inner stage
        // that many more or fewer times. Which of the two shapes this takes --
        // repeating the inner stage, or reimplementing MutationalStage with
        // our own iterations() -- is the one open question in this module.
        todo!("scale by FromSeed, then delegate to self.inner")
    }

    fn should_restart(&mut self, state: &mut Self::State) -> Result<bool, Error> {
        self.inner.should_restart(state)
    }

    fn clear_progress(&mut self, state: &mut Self::State) -> Result<(), Error> {
        self.inner.clear_progress(state)
    }
}
