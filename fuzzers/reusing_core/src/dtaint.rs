//! Reader for the per-seed `.dtaint` file a scan writes.
//!
//! Wire format v3, little-endian throughout. The writer is
//! `Reusing_scanner`'s `scanner/src/bin/taint_scan.rs` (`write_dtaint`), and
//! `AFLplusplus_reusing/include/dtaint.h` documents the records. This is a
//! port of that fuzzer's own reader, `src/afl-fuzz-reusing.c`
//! (`taint_map_load`), and has to produce the same range sets from the same
//! file -- the two arms are only comparable if they target the same sites.
//!
//! The file is a flat log of comparison sites, not the thing the stage wants.
//! Turning one into the other is four steps, each its own function below:
//!
//! 1. [`parse_header`] / [`parse_tags`] -- split the bytes into the cond list
//!    and the label table.
//! 2. [`Cond::ranges`] -- resolve each cond's label to byte ranges and glue
//!    touching ranges together.
//! 3. [`fold_into_sets`] -- sites reading exactly the same ranges become one
//!    [`RangeSet`], because one write serves all of them.
//! 4. [`TaintMap::filter_unsolved`] -- drop sites the scan already solved.

use core::ops::Range;
use std::{collections::HashMap, fs, path::Path};

/// `'DTNT'`
pub const MAGIC: u32 = 0x444e_5454;
/// The only version anything still writes or reads.
pub const VERSION_GROUPED: u32 = 3;

/// magic, version, n_conds, n_tags, n_magic_bytes.
const HEADER_LEN: usize = 5 * 4;
/// 10 u32 + 2 u64 + the 2 u32 group span v3 added.
const COND_LEN: usize = 10 * 4 + 2 * 8 + 2 * 4;
/// label + n_segs.
const TAG_REC_LEN: usize = 2 * 4;
/// sign, begin, end.
const SEG_LEN: usize = 3 * 4;

/// A comparison site, keyed the way the scan's `unsolved_condition` keys it.
///
/// `context` is a per-call-stack value, not a location hash, so one `cmpid`
/// reached down two different call paths is two sites. `order` counts repeated
/// hits of the same site within one execution (loops).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SiteKey {
    pub cmpid: u32,
    pub context: u32,
    pub order: u32,
}

/// One set of input byte ranges, plus every site that reads exactly them.
#[derive(Debug, Clone)]
pub struct RangeSet {
    /// The tainted byte ranges, in the order the tag table listed them.
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

/// Why a file produced nothing.
///
/// The stage treats all of these alike -- a seed the scan had nothing to say
/// about is normal, not an error -- but it counts them, and the tests want to
/// tell a truncated file from an empty one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoadError {
    /// No such file. The common case: the scan skipped this seed.
    Missing,
    /// Shorter than a header, or the cond list runs past the end.
    TooShort,
    /// Not a v3 dtaint file.
    BadMagic { magic: u32, version: u32 },
    Io(String),
}

impl TaintMap {
    /// Reads `<dir>/<name>.dtaint`.
    pub fn load(dir: &Path, name: &str) -> Result<Self, LoadError> {
        let path = dir.join(format!("{name}.dtaint"));

        let buf = match fs::read(&path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(LoadError::Missing)
            }
            Err(e) => return Err(LoadError::Io(e.to_string())),
        };

        Self::parse(&buf)
    }

    /// The body of [`load`](Self::load), split out so tests can hand it bytes.
    pub fn parse(buf: &[u8]) -> Result<Self, LoadError> {
        let header = parse_header(buf)?;

        // The tags table starts right after the cond list.
        let tags_at = HEADER_LEN + header.n_conds * COND_LEN;
        let tags = parse_tags(&buf[tags_at..], header.n_tags);

        let mut candidates = Vec::with_capacity(header.n_conds);

        for i in 0..header.n_conds {
            let cond = parse_cond(&buf[HEADER_LEN + i * COND_LEN..]);

            if let Some(ranges) = cond.ranges(&tags) {
                candidates.push(Candidate { ranges, site: cond.site });
            }
        }

        Ok(fold_into_sets(candidates))
    }

    /// Drops the sites the scan already saw go both ways, and then any range
    /// set left with no sites at all.
    ///
    /// [`RangeSet::idx`] is deliberately left alone: it is the cursor index,
    /// and a visit that filters differently from the last one must still
    /// resume each set where it stopped.
    pub fn filter_unsolved(&mut self, is_unsolved: impl Fn(&SiteKey) -> bool) {
        for set in &mut self.sets {
            set.sites.retain(&is_unsolved);
        }

        self.sets.retain(|s| !s.sites.is_empty());
    }

    /// Range sets still holding at least one site.
    #[must_use]
    pub fn len(&self) -> usize {
        self.sets.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.sets.is_empty()
    }
}

/* -------------------------------------------------------------------------
   Step 1: the bytes
   ------------------------------------------------------------------------- */

fn u32_at(buf: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]])
}

struct Header {
    n_conds: usize,
    n_tags: usize,
}

fn parse_header(buf: &[u8]) -> Result<Header, LoadError> {
    if buf.len() < HEADER_LEN {
        return Err(LoadError::TooShort);
    }

    let magic = u32_at(buf, 0);
    let version = u32_at(buf, 4);

    if magic != MAGIC || version != VERSION_GROUPED {
        return Err(LoadError::BadMagic { magic, version });
    }

    let n_conds = u32_at(buf, 8) as usize;
    let n_tags = u32_at(buf, 12) as usize;
    // Offset 16 is n_magic_bytes. The writer always puts 0 there and nothing
    // on this side has ever read that section.

    // A truncated tags table is survivable (parse_tags stops early); a cond
    // list that runs past the end is not.
    if HEADER_LEN + n_conds * COND_LEN > buf.len() {
        return Err(LoadError::TooShort);
    }

    Ok(Header { n_conds, n_tags })
}

/// label -> the byte ranges it stands for.
///
/// Each segment's `sign` is dropped on the way in; the fuzzer side has never
/// used it.
type Tags = HashMap<u32, Vec<Range<u32>>>;

/// Reads up to `n_tags` entries, stopping early if the file ends mid-table.
///
/// A truncated table is tolerated the way the C reader tolerates it: the
/// labels that did parse stay usable, and a cond pointing at one that did not
/// simply finds nothing and is skipped.
fn parse_tags(buf: &[u8], n_tags: usize) -> Tags {
    let mut tags = Tags::with_capacity(n_tags);
    let mut off = 0usize;

    for _ in 0..n_tags {
        if off + TAG_REC_LEN > buf.len() {
            break;
        }

        let label = u32_at(buf, off);
        let n_segs = u32_at(buf, off + 4) as usize;
        off += TAG_REC_LEN;

        if off + n_segs * SEG_LEN > buf.len() {
            break;
        }

        let segs = (0..n_segs)
            .map(|i| {
                let at = off + i * SEG_LEN;
                // at + 0 is `sign`, unused.
                u32_at(buf, at + 4)..u32_at(buf, at + 8)
            })
            .collect();

        off += n_segs * SEG_LEN;
        tags.insert(label, segs);
    }

    tags
}

/* -------------------------------------------------------------------------
   Step 2: one cond -> byte ranges
   ------------------------------------------------------------------------- */

struct Cond {
    site: SiteKey,
    lb1: u32,
    lb2: u32,
    /// The span Angora's grouping merged this cond into, or an empty range.
    group: Range<u32>,
}

fn parse_cond(buf: &[u8]) -> Cond {
    Cond {
        site: SiteKey {
            cmpid: u32_at(buf, 0),
            context: u32_at(buf, 4),
            order: u32_at(buf, 8),
        },
        // 12 belong, 16 condition, 20 level, 24 op, 28 size.
        lb1: u32_at(buf, 32),
        lb2: u32_at(buf, 36),
        // 40 arg1 (u64), 48 arg2 (u64).
        group: u32_at(buf, 56)..u32_at(buf, 60),
    }
}

impl Cond {
    /// The byte ranges a pool value should be written over for this cond, or
    /// `None` if it has nothing usable.
    fn ranges(&self, tags: &Tags) -> Option<Vec<Range<u32>>> {
        // An untainted comparison: neither operand came from the input.
        if self.lb1 == 0 && self.lb2 == 0 {
            return None;
        }

        // A magic-byte group wins over the labels. The scan split e.g.
        // memcmp("ELF", ..) into one cond per byte and then recorded the
        // combined span on each of them; that span is what the pool entry was
        // derived for, so it is what has to be written back.
        //
        // Tested as end > start rather than nonzero: offset 0 is a valid
        // start, and the writer leaves 0/0 for an ungrouped cond.
        let segs = if self.group.end > self.group.start {
            vec![self.group.clone()]
        } else {
            pick_primary(tags, self.lb1, self.lb2)?.clone()
        };

        if segs.is_empty() {
            return None;
        }

        Some(merge_touching(segs))
    }
}

/// Which operand's label to take the ranges from.
///
/// Prefers the side with fewer segments: that is the one more likely to be a
/// compact field being compared, rather than a sprawl of input bytes that
/// happened to reach the same comparison. Mirrors `pick_primary` in
/// afl-fuzz-reusing.c, including its preference for `lb1` on a tie.
fn pick_primary<'a>(tags: &'a Tags, lb1: u32, lb2: u32) -> Option<&'a Vec<Range<u32>>> {
    let t1 = tags.get(&lb1).filter(|s| !s.is_empty());
    let t2 = tags.get(&lb2).filter(|s| !s.is_empty());

    match (t1, t2) {
        (_, None) => t1,
        (Some(a), Some(b)) if a.len() <= b.len() => Some(a),
        (_, Some(b)) => Some(b),
    }
}

/// Glues ranges that touch into one, the way Angora's
/// `merge_continuous_segments()` does.
///
/// The pool is keyed on the merged lengths and the mutation writes the merged
/// span, so a run of single bytes has to arrive as one range -- split up,
/// nothing in the pool would ever match its shape.
fn merge_touching(segs: Vec<Range<u32>>) -> Vec<Range<u32>> {
    let mut out: Vec<Range<u32>> = Vec::with_capacity(segs.len());

    for seg in segs {
        match out.last_mut() {
            Some(last) if last.end == seg.start => last.end = seg.end,
            _ => out.push(seg),
        }
    }

    out
}

/* -------------------------------------------------------------------------
   Step 3: fold sites that read the same ranges
   ------------------------------------------------------------------------- */

struct Candidate {
    ranges: Vec<Range<u32>>,
    site: SiteKey,
}

/// Orders by the ranges alone: how many, then every length, then every start.
///
/// Lengths before starts because the length tuple is the pool lookup key --
/// ordering that way keeps sets sharing a key adjacent, which is what lets the
/// stage walk them in one pass.
fn cmp_ranges(a: &[Range<u32>], b: &[Range<u32>]) -> core::cmp::Ordering {
    a.len()
        .cmp(&b.len())
        .then_with(|| {
            a.iter()
                .map(|r| r.end - r.start)
                .cmp(b.iter().map(|r| r.end - r.start))
        })
        .then_with(|| a.iter().map(|r| r.start).cmp(b.iter().map(|r| r.start)))
}

/// Sorts candidates by range key, then folds each run of identical ranges into
/// one [`RangeSet`] listing the distinct sites that read them.
///
/// One write serves every site in a run, so collapsing them is the difference
/// between a handful of executions and thousands.
fn fold_into_sets(mut candidates: Vec<Candidate>) -> TaintMap {
    candidates.sort_by(|x, y| cmp_ranges(&x.ranges, &y.ranges).then_with(|| x.site.cmp(&y.site)));

    let mut sets: Vec<RangeSet> = Vec::new();
    let mut i = 0;

    while i < candidates.len() {
        let mut j = i + 1;

        while j < candidates.len() && cmp_ranges(&candidates[i].ranges, &candidates[j].ranges).is_eq()
        {
            j += 1;
        }

        // The sort put this run's duplicate sites next to each other, so one
        // pass drops them.
        let mut sites: Vec<SiteKey> = Vec::with_capacity(j - i);

        for cand in &candidates[i..j] {
            if sites.last() != Some(&cand.site) {
                sites.push(cand.site);
            }
        }

        sets.push(RangeSet {
            ranges: candidates[i].ranges.clone(),
            sites,
            idx: sets.len(),
        });

        i = j;
    }

    TaintMap { n_all: sets.len(), sets }
}
