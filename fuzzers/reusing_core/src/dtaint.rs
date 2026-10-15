//! Reader for the per-seed `.dtaint` file a scan writes.
//!
//! Wire format v3, little-endian throughout. The writer is
//! `Reusing_scanner`'s `scanner/src/bin/taint_scan.rs` (`write_dtaint`), and
//! this is its inverse; `AFLplusplus_reusing/include/dtaint.h` documents the
//! records.
//!
//! What the stage actually needs out of the file is narrow: for each set of
//! input byte ranges, which comparison sites read exactly those bytes. Sites
//! sharing a range set share an entry, since the same value would be written
//! for all of them.

use core::ops::Range;
use std::path::Path;

/// `'DTNT'`
pub const MAGIC: u32 = 0x444e_5454;
/// The only version anything still writes or reads.
pub const VERSION_GROUPED: u32 = 3;

/// A comparison site, keyed the way the scan's `unsolved_condition` keys it.
///
/// `context` is a per-call-stack value, not a location hash, so the same
/// `cmpid` reached down two different call paths is two sites. `order` counts
/// repeated hits of the same site within one execution (loops).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SiteKey {
    pub cmpid: u32,
    pub context: u32,
    pub order: u32,
}

/// One set of input byte ranges, plus every site that reads exactly them.
#[derive(Debug, Clone)]
pub struct RangeSet {
    /// The tainted byte ranges, in file order.
    pub ranges: Vec<Range<u32>>,
    /// Sites reading those ranges.
    pub sites: Vec<SiteKey>,
    /// Position in the unfiltered list. Cursors are indexed by this, so that
    /// dropping solved sites does not shift what a later visit resumes from.
    pub idx: usize,
}

impl RangeSet {
    /// The shape a pool entry must have to be written here: one length per
    /// range, in order. This is the key the value pool is grouped by.
    #[must_use]
    pub fn pattern(&self) -> Vec<u32> {
        self.ranges.iter().map(|r| r.end - r.start).collect()
    }
}

/// A parsed `.dtaint`: the range sets of one input.
#[derive(Debug, Clone, Default)]
pub struct TaintMap {
    pub sets: Vec<RangeSet>,
    /// How many sets the file held before any filtering, which is what
    /// [`RangeSet::idx`] indexes into.
    pub n_all: usize,
}

impl TaintMap {
    /// Reads `<dir>/<name>.dtaint`.
    ///
    /// `Ok(None)` for a file that is absent or unparsable: a seed the scan had
    /// nothing taint-worthy to say about is normal, not an error.
    pub fn load(_dir: &Path, _name: &str) -> Result<Option<Self>, String> {
        todo!("parse the v3 records; inverse of taint_scan.rs write_dtaint")
    }

    /// Drops the sites the scan already saw go both ways, and then any range
    /// set left with no sites at all. Keeps [`RangeSet::idx`] untouched.
    pub fn filter_unsolved(&mut self, _unsolved: &dyn Fn(&SiteKey) -> bool) {
        todo!("retain sites that are still unsolved, then retain non-empty sets")
    }
}
