//! Checks the parts of the stage that do not need a target: writing a pool
//! value over an input and putting it back, and how the two readers meet --
//! a range set's shape has to find the pool bucket that fits it.
//!
//! The budgeting and the round-robin itself are exercised end to end by a
//! campaign; what is pinned here is that the pieces line up at all.
//!
//!     REUSING_SCAN_DIR=/home/yunseo/seed/dev_scan_10/taint/ar/\
//!     reusing-scanner/jq/0/findings cargo test --test stage -- --nocapture

use std::{fs, path::PathBuf};

use reusing_core::{
    dtaint::TaintMap,
    pool::ReusingPool,
    stage::{apply, restore},
    MAX_EXEC, MIN_EXEC, TRIES_PER_RANGE_SET,
};

/* ------------------------------------------------------- apply and restore */

#[test]
fn a_value_lands_on_its_ranges() {
    let mut buf = b"0123456789".to_vec();
    apply(&mut buf, &[2..4, 7..8], &[b"AB".to_vec(), b"Z".to_vec()]);
    assert_eq!(buf, b"01AB456Z89");
}

#[test]
fn restore_undoes_exactly_what_apply_wrote() {
    let original = b"0123456789".to_vec();
    let mut buf = original.clone();

    apply(&mut buf, &[0..3, 6..9], &[b"xyz".to_vec(), b"XYZ".to_vec()]);
    assert_ne!(buf, original);

    restore(&mut buf, &original, &[0..3, 6..9]);
    assert_eq!(buf, original, "the next value must start from a clean input");
}

#[test]
fn a_range_past_the_end_is_skipped_not_clamped() {
    // The pool entry was derived for the whole span; writing a prefix of it
    // would be a value the scan never saw work.
    let mut buf = b"0123".to_vec();
    apply(&mut buf, &[2..6], &[b"ABCD".to_vec()]);
    assert_eq!(buf, b"0123", "nothing written");
}

#[test]
fn a_shorter_value_writes_only_its_own_bytes() {
    // Shapes are matched before this point, so this is defensive -- but a
    // mismatched pair must not corrupt the bytes after the range.
    let mut buf = b"0123456789".to_vec();
    apply(&mut buf, &[2..6], &[b"AB".to_vec()]);
    assert_eq!(buf, b"01AB456789");
}

#[test]
fn ranges_without_a_matching_segment_are_left_alone() {
    let mut buf = b"0123456789".to_vec();
    apply(&mut buf, &[0..1, 5..6], &[b"X".to_vec()]);
    assert_eq!(buf, b"X123456789");
}

/* ----------------------------------------------------------------- budget */

/// The stage's own arithmetic, kept here so the constants cannot drift
/// without a test noticing.
fn budget_for(live_sets: usize) -> usize {
    (live_sets * TRIES_PER_RANGE_SET).clamp(MIN_EXEC, MAX_EXEC)
}

#[test]
fn the_budget_is_per_live_set_within_a_floor_and_ceiling() {
    // A handful of ranges still gets a worthwhile visit...
    assert_eq!(budget_for(1), MIN_EXEC);
    assert_eq!(budget_for(10), MIN_EXEC);

    // ...the middle is three values per set...
    assert_eq!(budget_for(100), 300);
    assert_eq!(budget_for(1000), 3000);

    // ...and one unusually heavy input cannot hold the stage forever.
    assert_eq!(budget_for(100_000), MAX_EXEC);
}

/* --------------------------------------------- the two readers meeting up */

#[test]
fn range_set_shapes_find_pool_buckets() {
    let Ok(dir) = std::env::var("REUSING_SCAN_DIR") else {
        eprintln!("REUSING_SCAN_DIR unset, skipping");
        return;
    };
    let dir = PathBuf::from(dir);

    let pool = ReusingPool::load(&dir).expect("pool loads");

    let mut files: Vec<_> = fs::read_dir(&dir)
        .expect("scan dir")
        .filter_map(Result::ok)
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.ends_with(".dtaint"))
        .collect();
    files.sort();

    let (mut sets_total, mut sets_live, mut values_reachable) = (0usize, 0usize, 0usize);

    for file in &files {
        let name = file.strip_suffix(".dtaint").unwrap();
        let mut map = TaintMap::load(&dir, name).expect("parses");

        let before = map.len();
        map.filter_unsolved(|site| pool.is_unsolved(site));
        let after = map.len();
        assert!(after <= before);

        for set in &map.sets {
            sets_total += 1;

            if let Some(bucket) = pool.bucket(&set.pattern()) {
                sets_live += 1;
                values_reachable += bucket.entries.len();

                // Whatever the bucket holds has to fit the set exactly: same
                // number of segments, same length each.
                for entry in &bucket.entries {
                    assert_eq!(entry.pattern(), set.pattern());
                }
            }
        }

        eprintln!("{name}: {before} sets, {after} after filtering");
    }

    eprintln!(
        "{sets_live}/{sets_total} range sets have a bucket, {values_reachable} (set, value) pairs reachable"
    );

    assert!(sets_live > 0, "no range set matched any pool entry -- the two sides disagree");
}
