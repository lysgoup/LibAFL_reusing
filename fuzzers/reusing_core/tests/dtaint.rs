//! Checks the .dtaint reader against hand-built files, and -- when pointed at
//! one -- against a real scan.
//!
//! The synthetic cases pin down the decisions that are easy to get subtly
//! wrong: which label a cond takes its ranges from, when a magic-byte group
//! overrides that, and how touching ranges are glued.
//!
//! The real-corpus case is opt-in because it needs a scan on disk:
//!
//!     REUSING_DTAINT_DIR=/home/yunseo/seed/dev_scan_10/taint/ar/\
//!     reusing-scanner/jq/0/findings cargo test --test dtaint -- --nocapture

use std::{fs, path::PathBuf};

use reusing_core::dtaint::{LoadError, SiteKey, TaintMap};

/* ---------------------------------------------------------------- builder */

#[derive(Default)]
struct DtaintBuilder {
    conds: Vec<u8>,
    n_conds: u32,
    tags: Vec<u8>,
    n_tags: u32,
}

impl DtaintBuilder {
    /// One cond record. `group` is the merged magic-byte span, 0..0 when the
    /// cond is not part of one.
    fn cond(mut self, site: (u32, u32, u32), lb1: u32, lb2: u32, group: (u32, u32)) -> Self {
        let (cmpid, context, order) = site;
        for v in [cmpid, context, order, 0 /*belong*/, 0 /*condition*/, 0 /*level*/, 0 /*op*/, 0 /*size*/, lb1, lb2] {
            self.conds.extend_from_slice(&v.to_le_bytes());
        }
        self.conds.extend_from_slice(&0u64.to_le_bytes()); // arg1
        self.conds.extend_from_slice(&0u64.to_le_bytes()); // arg2
        self.conds.extend_from_slice(&group.0.to_le_bytes());
        self.conds.extend_from_slice(&group.1.to_le_bytes());
        self.n_conds += 1;
        self
    }

    fn tag(mut self, label: u32, segs: &[(u32, u32)]) -> Self {
        self.tags.extend_from_slice(&label.to_le_bytes());
        self.tags.extend_from_slice(&(segs.len() as u32).to_le_bytes());
        for (begin, end) in segs {
            self.tags.extend_from_slice(&0u32.to_le_bytes()); // sign
            self.tags.extend_from_slice(&begin.to_le_bytes());
            self.tags.extend_from_slice(&end.to_le_bytes());
        }
        self.n_tags += 1;
        self
    }

    fn build(self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&0x444e_5454u32.to_le_bytes()); // 'DTNT'
        out.extend_from_slice(&3u32.to_le_bytes());           // v3
        out.extend_from_slice(&self.n_conds.to_le_bytes());
        out.extend_from_slice(&self.n_tags.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());           // n_magic_bytes
        out.extend_from_slice(&self.conds);
        out.extend_from_slice(&self.tags);
        out
    }
}

fn site(cmpid: u32, context: u32, order: u32) -> SiteKey {
    SiteKey { cmpid, context, order }
}

/* ------------------------------------------------------------ header cases */

#[test]
fn rejects_a_short_or_foreign_file() {
    assert_eq!(TaintMap::parse(&[]).unwrap_err(), LoadError::TooShort);
    assert_eq!(TaintMap::parse(&[0u8; 19]).unwrap_err(), LoadError::TooShort);

    let mut wrong = DtaintBuilder::default().build();
    wrong[0..4].copy_from_slice(&0xdead_beefu32.to_le_bytes());
    assert!(matches!(TaintMap::parse(&wrong).unwrap_err(), LoadError::BadMagic { .. }));

    // A header claiming more conds than the file holds.
    let mut lying = DtaintBuilder::default().cond((1, 0, 0), 1, 0, (0, 0)).build();
    lying[8..12].copy_from_slice(&99u32.to_le_bytes());
    assert_eq!(TaintMap::parse(&lying).unwrap_err(), LoadError::TooShort);
}

#[test]
fn an_empty_file_is_an_empty_map() {
    let map = TaintMap::parse(&DtaintBuilder::default().build()).unwrap();
    assert!(map.is_empty());
    assert_eq!(map.n_all, 0);
}

/* ----------------------------------------------------------- cond handling */

#[test]
fn untainted_conds_are_skipped() {
    let bytes = DtaintBuilder::default()
        .cond((1, 0, 0), 0, 0, (0, 0)) // neither operand came from the input
        .cond((2, 0, 0), 7, 0, (0, 0))
        .tag(7, &[(4, 8)])
        .build();

    let map = TaintMap::parse(&bytes).unwrap();
    assert_eq!(map.len(), 1);
    assert_eq!(map.sets[0].sites, vec![site(2, 0, 0)]);
}

#[test]
fn a_cond_whose_label_is_missing_is_skipped() {
    let bytes = DtaintBuilder::default()
        .cond((1, 0, 0), 42, 0, (0, 0)) // label 42 is not in the table
        .build();

    assert!(TaintMap::parse(&bytes).unwrap().is_empty());
}

#[test]
fn the_fewer_segment_label_wins() {
    // lb1 sprawls over three ranges, lb2 is one: lb2 should be taken.
    let bytes = DtaintBuilder::default()
        .cond((1, 0, 0), 1, 2, (0, 0))
        .tag(1, &[(0, 1), (10, 11), (20, 21)])
        .tag(2, &[(40, 44)])
        .build();

    let map = TaintMap::parse(&bytes).unwrap();
    assert_eq!(map.sets[0].ranges, vec![40..44]);
}

#[test]
fn a_tie_goes_to_the_first_label() {
    let bytes = DtaintBuilder::default()
        .cond((1, 0, 0), 1, 2, (0, 0))
        .tag(1, &[(0, 4)])
        .tag(2, &[(8, 12)])
        .build();

    assert_eq!(TaintMap::parse(&bytes).unwrap().sets[0].ranges, vec![0..4]);
}

#[test]
fn an_empty_second_label_falls_back_to_the_first() {
    let bytes = DtaintBuilder::default()
        .cond((1, 0, 0), 1, 2, (0, 0))
        .tag(1, &[(0, 4)])
        .tag(2, &[])
        .build();

    assert_eq!(TaintMap::parse(&bytes).unwrap().sets[0].ranges, vec![0..4]);
}

#[test]
fn a_magic_group_overrides_the_labels() {
    // The scan split memcmp("ELF", ..) into per-byte conds and recorded the
    // combined span on each; that span is what the pool entry was derived for.
    let bytes = DtaintBuilder::default()
        .cond((1, 0, 0), 1, 0, (16, 20))
        .tag(1, &[(3, 4)])
        .build();

    assert_eq!(TaintMap::parse(&bytes).unwrap().sets[0].ranges, vec![16..20]);
}

#[test]
fn a_group_starting_at_zero_still_counts() {
    // 0/0 means "no group", but a real group may legitimately start at 0 --
    // so the test is end > start, not nonzero.
    let grouped = DtaintBuilder::default()
        .cond((1, 0, 0), 1, 0, (0, 4))
        .tag(1, &[(9, 10)])
        .build();
    assert_eq!(TaintMap::parse(&grouped).unwrap().sets[0].ranges, vec![0..4]);

    let ungrouped = DtaintBuilder::default()
        .cond((1, 0, 0), 1, 0, (0, 0))
        .tag(1, &[(9, 10)])
        .build();
    assert_eq!(TaintMap::parse(&ungrouped).unwrap().sets[0].ranges, vec![9..10]);
}

#[test]
fn touching_ranges_are_glued_into_one() {
    // Four single bytes in a row have to arrive as one 4-byte range: the pool
    // is keyed on merged lengths, and nothing in it has shape [1,1,1,1].
    let bytes = DtaintBuilder::default()
        .cond((1, 0, 0), 1, 0, (0, 0))
        .tag(1, &[(4, 5), (5, 6), (6, 7), (7, 8), (12, 13)])
        .build();

    let map = TaintMap::parse(&bytes).unwrap();
    assert_eq!(map.sets[0].ranges, vec![4..8, 12..13]);
    assert_eq!(map.sets[0].pattern(), vec![4, 1]);
}

/* --------------------------------------------------------------- folding */

#[test]
fn sites_reading_the_same_ranges_share_one_set() {
    let bytes = DtaintBuilder::default()
        .cond((10, 0, 0), 1, 0, (0, 0))
        .cond((11, 0, 0), 2, 0, (0, 0)) // different label, same ranges
        .cond((12, 0, 0), 3, 0, (0, 0))
        .tag(1, &[(4, 8)])
        .tag(2, &[(4, 8)])
        .tag(3, &[(20, 24)])
        .build();

    let map = TaintMap::parse(&bytes).unwrap();
    assert_eq!(map.len(), 2);

    let shared = map.sets.iter().find(|s| s.ranges == vec![4..8]).unwrap();
    assert_eq!(shared.sites, vec![site(10, 0, 0), site(11, 0, 0)]);
}

#[test]
fn the_same_site_twice_is_listed_once() {
    // A site hit twice in one run with the same label shows up as two conds.
    let bytes = DtaintBuilder::default()
        .cond((10, 5, 0), 1, 0, (0, 0))
        .cond((10, 5, 0), 1, 0, (0, 0))
        .tag(1, &[(4, 8)])
        .build();

    let map = TaintMap::parse(&bytes).unwrap();
    assert_eq!(map.sets[0].sites, vec![site(10, 5, 0)]);
}

#[test]
fn context_and_order_make_sites_distinct() {
    let bytes = DtaintBuilder::default()
        .cond((10, 1, 0), 1, 0, (0, 0))
        .cond((10, 2, 0), 1, 0, (0, 0)) // same cmpid, other call path
        .cond((10, 1, 1), 1, 0, (0, 0)) // same site, second time round a loop
        .tag(1, &[(4, 8)])
        .build();

    let map = TaintMap::parse(&bytes).unwrap();
    assert_eq!(map.len(), 1);
    assert_eq!(map.sets[0].sites.len(), 3);
}

#[test]
fn sets_are_ordered_by_shape_then_position() {
    let bytes = DtaintBuilder::default()
        .cond((1, 0, 0), 1, 0, (0, 0))
        .cond((2, 0, 0), 2, 0, (0, 0))
        .cond((3, 0, 0), 3, 0, (0, 0))
        .tag(1, &[(100, 104)]) // one range, len 4, late
        .tag(2, &[(0, 2)])     // one range, len 2
        .tag(3, &[(0, 1), (8, 9)]) // two ranges
        .build();

    let map = TaintMap::parse(&bytes).unwrap();
    let shapes: Vec<_> = map.sets.iter().map(|s| s.pattern()).collect();
    assert_eq!(shapes, vec![vec![2], vec![4], vec![1, 1]]);

    // idx is the position in this list, and is what cursors are keyed on.
    assert_eq!(map.sets.iter().map(|s| s.idx).collect::<Vec<_>>(), vec![0, 1, 2]);
}

/* -------------------------------------------------------------- filtering */

#[test]
fn filtering_keeps_cursor_indices_stable() {
    let bytes = DtaintBuilder::default()
        .cond((1, 0, 0), 1, 0, (0, 0))
        .cond((2, 0, 0), 2, 0, (0, 0))
        .cond((3, 0, 0), 3, 0, (0, 0))
        .tag(1, &[(0, 2)])
        .tag(2, &[(0, 4)])
        .tag(3, &[(0, 8)])
        .build();

    let mut map = TaintMap::parse(&bytes).unwrap();
    assert_eq!(map.len(), 3);

    // Keep only the middle one.
    map.filter_unsolved(|s| s.cmpid == 2);

    assert_eq!(map.len(), 1);
    assert_eq!(map.sets[0].idx, 1, "idx must survive filtering: cursors use it");
    assert_eq!(map.n_all, 3, "n_all sizes the cursor array");
}

/* ------------------------------------------------------- a real scan, opt-in */

#[test]
fn reads_a_real_scan() {
    let Ok(dir) = std::env::var("REUSING_DTAINT_DIR") else {
        eprintln!("REUSING_DTAINT_DIR unset, skipping");
        return;
    };
    let dir = PathBuf::from(dir);

    let mut files: Vec<_> = fs::read_dir(&dir)
        .expect("scan dir")
        .filter_map(Result::ok)
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.ends_with(".dtaint"))
        .collect();
    files.sort();
    assert!(!files.is_empty(), "no .dtaint files in {}", dir.display());

    for file in &files {
        let name = file.strip_suffix(".dtaint").unwrap();
        let map = TaintMap::load(&dir, name).expect("parses");

        let sites: usize = map.sets.iter().map(|s| s.sites.len()).sum();
        let widest = map.sets.iter().map(|s| s.ranges.len()).max().unwrap_or(0);
        eprintln!(
            "{name}: {} range sets, {sites} sites, widest {widest} range(s)",
            map.len()
        );

        for set in &map.sets {
            assert!(!set.ranges.is_empty(), "a set with no ranges");
            assert!(!set.sites.is_empty(), "a set with no sites");

            for r in &set.ranges {
                assert!(r.end > r.start, "empty range {r:?} in {name}");
            }

            // merge_touching should have left no range abutting the next.
            for pair in set.ranges.windows(2) {
                assert_ne!(pair[0].end, pair[1].start, "unmerged ranges in {name}");
            }

            // Sites within a set are distinct.
            let mut seen = set.sites.clone();
            seen.sort();
            seen.dedup();
            assert_eq!(seen.len(), set.sites.len(), "duplicate site in {name}");
        }
    }
}
