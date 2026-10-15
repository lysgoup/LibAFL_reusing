//! What the stage keeps, and where LibAFL keeps it for us.
//!
//! AFL++ stored all of this on `afl_state_t` and `queue_entry`; here the
//! corpus-wide half goes in the state's metadata map and the per-input half
//! on the testcase, which is also what makes it survive a restart.


use serde::{Deserialize, Serialize};

use crate::{dtaint::TaintMap, pool::ReusingPool};

/// The scan's output, loaded once and never mutated.
///
/// Not `Serialize`: it is rebuilt from the files on a restart rather than
/// carried in the state, and the pool is megabytes.
#[derive(Debug)]
pub struct ReusingData {
    pub pool: ReusingPool,
    /// Where the cache lives, for the per-seed `.dtaint` reads.
    pub dir: String,
}

/// How far each range set of one input has been worked through.
///
/// Indexed by [`RangeSet::idx`](crate::dtaint::RangeSet::idx) -- the position
/// before solved sites were filtered out -- so the array keeps its meaning
/// even as filtering changes which sets are live.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ReusingCursors {
    /// Next pool entry to try, one per range set.
    pub cur: Vec<u32>,
    /// Nothing left to try, so the stage can skip reading the `.dtaint` at
    /// all. Must be cleared for every entry once the pool can gain values.
    pub done: bool,
}

libafl_bolts::impl_serdeany!(ReusingCursors);

/// Marks a testcase that came in with `-i` rather than being found by this
/// campaign. Drives the energy split, and is deliberately separate from
/// "has taint data": a seed without a `.dtaint` gets no reusing stage either,
/// but it is still corpus a previous campaign already fuzzed, not new ground.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
pub struct FromSeed;

libafl_bolts::impl_serdeany!(FromSeed);

/// A testcase's parsed taint data, cached between visits.
///
/// Held separately from [`ReusingCursors`] because it is derived from a file
/// on disk and need not be serialized.
#[derive(Debug)]
pub struct CachedTaint {
    pub map: TaintMap,
}
