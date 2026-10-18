//! Readers for the two corpus-wide files a scan writes.
//!
//! Both are read once at startup and never change afterwards. Ported from
//! `AFLplusplus_reusing/src/afl-fuzz-reusing.c` (`load_value_pool`,
//! `load_unsolved_sites`, `parse_pool_line`, `unescape_segment`) and meant to
//! accept exactly the same files.
//!
//! # `value_pool.dict`
//!
//! The values that opened a branch during the scan, one per line, written in
//! the same escaping the C side used -- printable ASCII as itself, `\\` and
//! `\"` escaped, everything else `\xNN`:
//!
//! ```text
//! # extracted by taint_scan -- one value candidate per line,
//! # pattern [1, 1]: 6 record(s)
//! ["\xef","\xa9"]
//! ["\x7fELF\x02\x01"]
//! ```
//!
//! A multi-segment entry came from a site reading several separate byte
//! ranges, and is only ever written back to a range set of the same *shape* --
//! same number of ranges, same length each. That shape is what entries are
//! grouped by here, so the stage's "what may I write at this range set" is one
//! map lookup.
//!
//! # `unsolved_condition`
//!
//! The sites the scan never saw go both ways:
//!
//! ```text
//! # unsolved conditions -- 14051 of 15343 tracked site(s) never seen both ways
//! cmpid=35970050 context=6251862 order=5 seen=0
//! ```
//!
//! Only those are worth aiming at. The `seen` field says which way the site
//! did go, which nothing on this side uses -- the set is read once and never
//! updated during the campaign, exactly as in the C fuzzer (whose
//! `unsolved_remove` is declared and never called).

use std::{
    collections::{HashMap, HashSet},
    fs,
    path::{Path, PathBuf},
};

use crate::{dtaint::SiteKey, MAX_SEGS_PER_ENTRY, MAX_SEG_LEN};

/// One value the scan recorded, as the segments it is written back in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PoolEntry {
    pub segs: Vec<Vec<u8>>,
}

impl PoolEntry {
    /// The shape this entry fits: one length per segment, in order. Equal to
    /// [`RangeSet::pattern`](crate::dtaint::RangeSet::pattern) for any range
    /// set it may be written to.
    #[must_use]
    pub fn pattern(&self) -> Vec<u32> {
        self.segs.iter().map(|s| s.len() as u32).collect()
    }
}

/// Every pool entry of one shape, in the order the file listed them.
///
/// The order matters and must stay stable: a queue entry's cursor is an index
/// into this vector, and the next visit resumes from where the last one
/// stopped. Entries a later scan appends land at the end, where an
/// already-advanced cursor still reaches them.
#[derive(Debug, Clone, Default)]
pub struct ValueBucket {
    pub entries: Vec<PoolEntry>,
}

/// What a scan left behind for the whole corpus.
#[derive(Debug, Default)]
pub struct ReusingPool {
    buckets: HashMap<Vec<u32>, ValueBucket>,
    unsolved: HashSet<SiteKey>,
    stats: PoolStats,
}

/// Counts for the one-line summary the fuzzer prints at startup. A pool that
/// silently lost half its lines to a format change should be visible there,
/// not inferred later from a campaign that found nothing.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct PoolStats {
    pub entries: usize,
    pub segments: usize,
    pub patterns: usize,
    /// Lines that looked like entries but would not parse.
    pub malformed: usize,
    pub unsolved_sites: usize,
    /// `unsolved_condition` lines naming a site already in the set.
    pub unsolved_duplicates: usize,
}

#[derive(Debug)]
pub enum PoolError {
    /// The directory has no `value_pool.dict` or no `unsolved_condition`.
    ///
    /// Fatal on purpose: a campaign that quietly fuzzes without its pool is
    /// indistinguishable from a baseline run afterwards.
    Missing { path: PathBuf, reason: String },
}

impl std::fmt::Display for PoolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Missing { path, reason } => {
                write!(f, "cannot read {}: {reason}", path.display())
            }
        }
    }
}

impl ReusingPool {
    /// Reads `value_pool.dict` and `unsolved_condition` out of `dir`.
    pub fn load(dir: &Path) -> Result<Self, PoolError> {
        let pool_text = read(dir.join("value_pool.dict"))?;
        let unsolved_text = read(dir.join("unsolved_condition"))?;

        let mut pool = Self::default();
        pool.add_pool_lines(&pool_text);
        pool.add_unsolved_lines(&unsolved_text);
        Ok(pool)
    }

    /// The entries that may be written into a range set of this shape.
    ///
    /// A range set wider than [`MAX_SEGS_PER_ENTRY`] is refused rather than
    /// looked up, the way `reusing_bucket()` refuses it: the stage would have
    /// to build a scratch key that size on every visit, and a set that wide is
    /// a sprawl of input bytes rather than a field worth aiming a value at.
    #[must_use]
    pub fn bucket(&self, pattern: &[u32]) -> Option<&ValueBucket> {
        if pattern.len() > MAX_SEGS_PER_ENTRY {
            return None;
        }

        self.buckets.get(pattern)
    }

    /// Whether the scan left this site unsolved. Hand this to
    /// [`TaintMap::filter_unsolved`](crate::dtaint::TaintMap::filter_unsolved).
    #[must_use]
    pub fn is_unsolved(&self, site: &SiteKey) -> bool {
        self.unsolved.contains(site)
    }

    #[must_use]
    pub fn stats(&self) -> PoolStats {
        self.stats
    }

    /// Parses `value_pool.dict`'s text, in file order.
    ///
    /// Split out from [`load`](Self::load) so tests can feed it a string. A
    /// line that will not parse is counted and skipped: a pool is thousands of
    /// lines of machine-written text, and losing one is not worth refusing to
    /// fuzz over.
    pub fn add_pool_lines(&mut self, text: &str) {
        for line in text.lines() {
            match parse_pool_line(line) {
                Ok(Some(entry)) => {
                    self.stats.entries += 1;
                    self.stats.segments += entry.segs.len();
                    self.buckets
                        .entry(entry.pattern())
                        .or_default()
                        .entries
                        .push(entry);
                }
                Ok(None) => {} // comment, blank, or anything not starting '['
                Err(_) => self.stats.malformed += 1,
            }
        }

        self.stats.patterns = self.buckets.len();
    }

    /// Parses `unsolved_condition`'s text.
    pub fn add_unsolved_lines(&mut self, text: &str) {
        for line in text.lines() {
            if let Some(site) = parse_unsolved_line(line) {
                if !self.unsolved.insert(site) {
                    self.stats.unsolved_duplicates += 1;
                }
            }
        }

        self.stats.unsolved_sites = self.unsolved.len();
    }
}

fn read(path: PathBuf) -> Result<String, PoolError> {
    // Not read_to_string: a value pool is escaped ASCII by construction, but a
    // stray byte in it should not take the campaign down.
    match fs::read(&path) {
        Ok(bytes) => Ok(String::from_utf8_lossy(&bytes).into_owned()),
        Err(e) => Err(PoolError::Missing { path, reason: e.to_string() }),
    }
}

/* -------------------------------------------------------------------------
   value_pool.dict
   ------------------------------------------------------------------------- */

/// Why one pool line was thrown away.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LineError {
    /// A segment was not quoted, or its closing quote is missing.
    UnterminatedSegment,
    /// A `\` followed by something other than `\`, `"` or `xNN`.
    BadEscape,
    /// A segment carries no bytes. Its length would make the entry's shape
    /// disagree with any real range set, so the whole line goes.
    EmptySegment,
    /// `[]`, or a line that has a `[` and nothing usable after it.
    NoSegments,
    /// Over [`MAX_SEG_LEN`] bytes in one segment.
    TooLong,
}

/// Decodes one `value_pool.dict` line.
///
/// `Ok(None)` for a line that is not an entry at all -- comments, blanks,
/// anything not starting with `[`. `Err` for a line that tried to be one and
/// failed.
pub fn parse_pool_line(line: &str) -> Result<Option<PoolEntry>, LineError> {
    let body = line.trim_start();

    let Some(body) = body.strip_prefix('[') else {
        return Ok(None);
    };

    let mut rest = body.as_bytes();
    let mut segs: Vec<Vec<u8>> = Vec::new();

    loop {
        // Separators are permissive on purpose: the writer emits `","` but the
        // C reader skipped any run of spaces and commas, and files in the wild
        // were written by both.
        while matches!(rest.first(), Some(b' ' | b'\t' | b'\r' | b'\n' | b',')) {
            rest = &rest[1..];
        }

        if matches!(rest.first(), None | Some(b']')) {
            break;
        }

        // No cap on the number of segments here. The C reader has none
        // either, and real pools exceed any reasonable one -- jq's has entries
        // 433 segments wide. The cap lives on the lookup side instead, where
        // MAX_SEGS_PER_ENTRY bounds how wide a range set may be before the
        // stage gives up on it.
        let seg = unescape_segment(&mut rest)?;

        if seg.is_empty() {
            return Err(LineError::EmptySegment);
        }

        segs.push(seg);
    }

    if segs.is_empty() {
        return Err(LineError::NoSegments);
    }

    Ok(Some(PoolEntry { segs }))
}

/// Reads one `"..."` segment, advancing `rest` past the closing quote.
fn unescape_segment(rest: &mut &[u8]) -> Result<Vec<u8>, LineError> {
    let mut p = rest.strip_prefix(b"\"").ok_or(LineError::UnterminatedSegment)?;
    let mut out = Vec::new();

    loop {
        let (&byte, tail) = p.split_first().ok_or(LineError::UnterminatedSegment)?;

        match byte {
            b'"' => {
                *rest = tail;
                return Ok(out);
            }

            b'\\' => {
                let (&esc, tail) = tail.split_first().ok_or(LineError::BadEscape)?;

                match esc {
                    b'\\' | b'"' => {
                        out.push(esc);
                        p = tail;
                    }
                    b'x' => {
                        let hi = tail.first().and_then(|c| hex_digit(*c));
                        let lo = tail.get(1).and_then(|c| hex_digit(*c));
                        let (Some(hi), Some(lo)) = (hi, lo) else {
                            return Err(LineError::BadEscape);
                        };
                        out.push(hi << 4 | lo);
                        p = &tail[2..];
                    }
                    _ => return Err(LineError::BadEscape),
                }
            }

            _ => {
                out.push(byte);
                p = tail;
            }
        }

        if out.len() > MAX_SEG_LEN {
            return Err(LineError::TooLong);
        }
    }
}

fn hex_digit(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/* -------------------------------------------------------------------------
   unsolved_condition
   ------------------------------------------------------------------------- */

/// Decodes one `unsolved_condition` line.
///
/// `None` for comments and anything that does not match the four fields. The
/// `seen` value is parsed only to insist the line is complete; which way the
/// site went is not something the stage acts on.
#[must_use]
pub fn parse_unsolved_line(line: &str) -> Option<SiteKey> {
    let mut fields = line.split_whitespace();

    let cmpid = field(fields.next()?, "cmpid=")?;
    let context = field(fields.next()?, "context=")?;
    let order = field(fields.next()?, "order=")?;
    let _seen: i32 = fields.next()?.strip_prefix("seen=")?.parse().ok()?;

    Some(SiteKey { cmpid, context, order })
}

fn field(token: &str, name: &str) -> Option<u32> {
    token.strip_prefix(name)?.parse().ok()
}
