//! Per-testcase state, kept where LibAFL keeps testcase state.
//!
//! AFL++ hung all of this off `queue_entry`. Here it goes in the testcase's
//! metadata map, which is also what carries it across a restart.
//!
//! The corpus-wide half -- the value pool and the unsolved set -- is *not*
//! here. It is loaded once and never mutated, nothing but the stage reads it,
//! and putting it in the state's metadata map would mean making every pool
//! type `SerdeAny` for no gain. [`ReusingStage`](crate::ReusingStage) owns it
//! directly and reloads it from disk if the fuzzer is restarted.

use serde::{Deserialize, Serialize};

use libafl_bolts::impl_serdeany;

/// How far each range set of one input has been worked through.
///
/// Indexed by [`RangeSet::idx`](crate::dtaint::RangeSet::idx) -- the position
/// a set had *before* solved sites were filtered out -- so the array keeps its
/// meaning even when a later visit filters differently.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ReusingCursors {
    /// Next pool entry to try, one per range set.
    cursors: Vec<u32>,
    /// Nothing left to try, so the stage can skip reading the `.dtaint`
    /// altogether.
    ///
    /// Must be cleared for every entry if the pool can ever gain values or a
    /// site can go back to being unsolved. Today neither happens during a
    /// campaign, so it is set once and stays.
    done: bool,
}

impl_serdeany!(ReusingCursors);

impl ReusingCursors {
    /// Grows the array to cover `n_sets` range sets, keeping what is there.
    ///
    /// Only ever grows: a `.dtaint` is written once and does not change under
    /// us, so a shrink would mean the file was swapped for a different one,
    /// and keeping the old cursors is still the safer answer than resetting
    /// progress.
    pub fn resize(&mut self, n_sets: usize) {
        if self.cursors.len() < n_sets {
            self.cursors.resize(n_sets, 0);
        }
    }

    /// How many pool entries of this range set have already been tried.
    #[must_use]
    pub fn get(&self, set_idx: usize) -> u32 {
        self.cursors.get(set_idx).copied().unwrap_or(0)
    }

    /// Records that one more entry of this range set has been tried.
    pub fn advance(&mut self, set_idx: usize) {
        if let Some(c) = self.cursors.get_mut(set_idx) {
            *c += 1;
        }
    }

    #[must_use]
    pub fn is_done(&self) -> bool {
        self.done
    }

    pub fn set_done(&mut self) {
        self.done = true;
    }
}

/// Marks a testcase that came in with `-i` rather than being found by this
/// campaign.
///
/// Deliberately separate from "has taint data": a seed the scan had nothing to
/// say about gets no reusing stage either, but it is still corpus a previous
/// campaign already fuzzed, not new ground -- and the energy split cares about
/// that difference, not about the `.dtaint`.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
pub struct FromSeed;

impl_serdeany!(FromSeed);
