//! Reusing: replay the values a taint scan already proved interesting.
//!
//! A scan (Reusing_scanner's `taint_scan`) runs over the seed corpus once,
//! before the campaign, and writes three things next to each other:
//!
//! * `value_pool.dict`    -- values that opened a branch during the scan,
//!                           grouped by the shape of the input bytes they
//!                           were read from
//! * `unsolved_condition` -- comparison sites the scan never saw go both ways
//! * `<seed>.dtaint`      -- per seed: which input byte ranges each site read
//!
//! This crate reads all three and turns them into a [`Stage`](libafl::stages::Stage):
//! for a testcase that has taint data, overwrite one of its tainted ranges
//! with a pool value of the same shape, run it, put the bytes back, repeat.
//!
//! Nothing here depends on how the target is executed, so the same stage
//! serves a forkserver fuzzer and an in-process one.
//!
//! Ported from AFLplusplus_reusing's `src/afl-fuzz-reusing.c`.

pub mod dtaint;
pub mod energy;
pub mod meta;
pub mod pool;
pub mod stage;

pub use energy::ReusingEnergyStage;
pub use meta::{FromSeed, ReusingCursors};
pub use pool::ReusingPool;
pub use stage::ReusingStage;

/// How many pool values one range set gets before the stage moves to the next.
///
/// Small on purpose: an nm seed can carry a thousand range sets over half a
/// million pool values, so no visit can ever work through one input. The
/// choice is between a few values at many sites and many values at a few, and
/// the first values a site gets are the ones its pool entry was derived for.
pub const TRIES_PER_RANGE_SET: usize = 3;

/// Floor and ceiling on a single visit's execution budget.
///
/// The floor keeps a visit worthwhile for an input whose taint covers only a
/// handful of ranges; the ceiling stops one unusually heavy input from holding
/// the stage while every other entry waits. Whatever a visit does not get
/// through is picked up by the next one.
pub const MIN_EXEC: usize = 256;
/// See [`MIN_EXEC`].
pub const MAX_EXEC: usize = 8192;

/// Energy multiplier for an entry this campaign found itself.
///
/// Reusing saturates early (measured on objdump: 88% of its 24 h coverage gain
/// landed in the first 8 h), so the rest of the campaign is better spent on
/// the new ground it turned up.
pub const NEW_ENERGY_MULT: usize = 8;

/// Energy divisor for a seed, the other side of the same trade.
pub const SEED_ENERGY_DIV: usize = 2;

/// Segments per pool entry, bounding a `value_pool.dict` line together with
/// [`MAX_SEG_LEN`]: a wider group is a malformed line, and a range set wider
/// than this is skipped rather than looked up.
pub const MAX_SEGS_PER_ENTRY: usize = 64;

/// Longest single segment a pool entry may carry. A line claiming more is
/// treated as malformed rather than decoded.
pub const MAX_SEG_LEN: usize = 4096;
