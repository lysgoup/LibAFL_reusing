//! Readers for the two corpus-wide files a scan writes.
//!
//! `value_pool.dict` holds the values that opened a branch during the scan.
//! One entry per line, each entry one or more segments:
//!
//! ```text
//! ["\x7fELF"]
//! ["\x00\x01", "\xff\xff"]
//! ```
//!
//! A multi-segment entry came from a site reading several separate byte
//! ranges, and is only ever written back to a range set of the same shape --
//! same number of ranges, same length each. That shape is the key entries are
//! grouped by, so looking up "what can I write here" is one map lookup.
//!
//! `unsolved_condition` lists the sites the scan never saw go both ways:
//!
//! ```text
//! cmpid=12345 context=678 order=0 seen=1
//! ```
//!
//! Only those are worth aiming at; a site the scan already solved needs no
//! help. The set is read once and never updated during the campaign.

use std::{collections::{HashMap, HashSet}, path::Path};

use crate::dtaint::SiteKey;

/// One value the scan recorded, as the segments it is written back in.
#[derive(Debug, Clone)]
pub struct PoolEntry {
    pub segs: Vec<Vec<u8>>,
}

/// Every pool entry of one shape, in the order the file listed them.
///
/// Cursors index into `entries`, so the order must stay stable across a
/// campaign; entries appended by a later scan go on the end, where an
/// already-advanced cursor will still reach them.
#[derive(Debug, Clone, Default)]
pub struct ValueBucket {
    pub entries: Vec<PoolEntry>,
}

/// The whole cache: pool and unsolved set, loaded once at startup.
#[derive(Debug, Default)]
pub struct ReusingPool {
    /// Keyed by shape: one length per segment, in order.
    pub buckets: HashMap<Vec<u32>, ValueBucket>,
    pub unsolved: HashSet<SiteKey>,
    /// Totals, for the one-line summary the fuzzer prints at startup.
    pub n_entries: usize,
    pub n_segs: usize,
}

impl ReusingPool {
    /// Reads `value_pool.dict` and `unsolved_condition` from `dir`.
    pub fn load(_dir: &Path) -> Result<Self, String> {
        todo!("parse both files; see load_value_pool / load_unsolved_sites")
    }

    /// The entries that may be written into a range set of this shape.
    #[must_use]
    pub fn bucket(&self, _pattern: &[u32]) -> Option<&ValueBucket> {
        todo!("map lookup")
    }
}

/// Decodes one `value_pool.dict` line into its segments.
///
/// Returns `None` for a malformed line, a group wider than
/// [`MAX_SEGS_PER_ENTRY`](crate::MAX_SEGS_PER_ENTRY), or a segment longer than
/// [`MAX_SEG_LEN`](crate::MAX_SEG_LEN) -- a bad line is skipped, not fatal.
#[must_use]
pub fn parse_pool_line(_line: &str) -> Option<PoolEntry> {
    todo!("unescape \\xNN and split the quoted, comma-separated segments")
}

/// Decodes one `unsolved_condition` line.
#[must_use]
pub fn parse_unsolved_line(_line: &str) -> Option<SiteKey> {
    todo!("four fixed-width fields: cmpid, context, order, seen")
}
