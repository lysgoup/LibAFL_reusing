//! Checks the value-pool and unsolved-site readers.
//!
//! The synthetic cases pin the escaping rules and what counts as a malformed
//! line. The real-corpus case is opt-in and compares against the numbers the
//! scan itself printed:
//!
//!     REUSING_POOL_DIR=/home/yunseo/seed/dev_scan_10/taint/ar/\
//!     reusing-scanner/jq/0/findings cargo test --test pool -- --nocapture

use std::path::PathBuf;

use reusing_core::{
    dtaint::SiteKey,
    pool::{parse_pool_line, parse_unsolved_line, LineError, PoolEntry, ReusingPool},
};

fn entry(segs: &[&[u8]]) -> PoolEntry {
    PoolEntry { segs: segs.iter().map(|s| s.to_vec()).collect() }
}

fn parsed(line: &str) -> PoolEntry {
    parse_pool_line(line).expect("not malformed").expect("an entry")
}

/* ----------------------------------------------------------- what is a line */

#[test]
fn comments_and_blanks_are_not_entries() {
    for line in ["", "   ", "# extracted by taint_scan", "# pattern [1, 1]: 6 record(s)"] {
        assert_eq!(parse_pool_line(line), Ok(None), "{line:?}");
    }
}

#[test]
fn leading_space_is_allowed() {
    assert_eq!(parsed("   [\"ab\"]"), entry(&[b"ab"]));
}

/* --------------------------------------------------------------- escaping */

#[test]
fn printable_bytes_pass_through() {
    assert_eq!(parsed(r#"["jq is fine"]"#), entry(&[b"jq is fine"]));
}

#[test]
fn hex_escapes_decode() {
    assert_eq!(parsed(r#"["\x7fELF\x02\x01"]"#), entry(&[b"\x7fELF\x02\x01"]));
    // Upper and lower case hex both, the way different writers emit them.
    assert_eq!(parsed(r#"["\xAB\xcd"]"#), entry(&[b"\xab\xcd"]));
}

#[test]
fn backslash_and_quote_are_escaped() {
    assert_eq!(parsed(r#"["a\\b"]"#), entry(&[br"a\b"]));
    assert_eq!(parsed(r#"["say \"hi\""]"#), entry(&[b"say \"hi\""]));
}

#[test]
fn a_bad_escape_kills_the_line() {
    // \n is not one of the three the writer emits; a reader inventing a
    // meaning for it would silently disagree with the scan.
    assert_eq!(parse_pool_line(r#"["a\nb"]"#), Err(LineError::BadEscape));
    assert_eq!(parse_pool_line(r#"["\xZZ"]"#), Err(LineError::BadEscape));
    assert_eq!(parse_pool_line(r#"["\x4"]"#), Err(LineError::BadEscape));
}

#[test]
fn an_unterminated_segment_kills_the_line() {
    assert_eq!(parse_pool_line(r#"["abc]"#), Err(LineError::UnterminatedSegment));
    assert_eq!(parse_pool_line("[abc]"), Err(LineError::UnterminatedSegment));
}

#[test]
fn an_empty_segment_kills_the_line() {
    // A zero-length segment would make the entry's shape disagree with any
    // real range set, so the whole entry goes rather than storing a hole.
    assert_eq!(parse_pool_line(r#"["ab",""]"#), Err(LineError::EmptySegment));
}

#[test]
fn an_entry_with_no_segments_kills_the_line() {
    assert_eq!(parse_pool_line("[]"), Err(LineError::NoSegments));
}

/* ------------------------------------------------------- multiple segments */

#[test]
fn segments_keep_their_order() {
    let e = parsed(r#"["\xef","\xa9","z"]"#);
    assert_eq!(e, entry(&[b"\xef", b"\xa9", b"z"]));
    assert_eq!(e.pattern(), vec![1, 1, 1]);
}

#[test]
fn spacing_between_segments_does_not_matter() {
    let tight = parsed(r#"["ab","cd"]"#);
    let loose = parsed(r#"[ "ab" , "cd" ]"#);
    assert_eq!(tight, loose);
}

/* -------------------------------------------------------------- grouping */

#[test]
fn entries_are_grouped_by_shape() {
    let mut pool = ReusingPool::default();
    pool.add_pool_lines(
        r#"# a comment
["\xef","\xa9"]
["ab","cd"]
["\x7fELF"]
["xy"]
"#,
    );

    // Shape is lengths, not just segment count: ["\xef","\xa9"] is [1,1]
    // while ["ab","cd"] is [2,2], and they do not share a bucket.
    assert_eq!(pool.bucket(&[1, 1]).unwrap().entries.len(), 1);
    assert_eq!(pool.bucket(&[2, 2]).unwrap().entries.len(), 1);
    assert_eq!(pool.bucket(&[4]).unwrap().entries.len(), 1);
    assert_eq!(pool.bucket(&[2]).unwrap().entries.len(), 1);
    assert!(pool.bucket(&[3]).is_none(), "no entry of this shape");

    let stats = pool.stats();
    assert_eq!(stats.entries, 4);
    assert_eq!(stats.segments, 6);
    assert_eq!(stats.patterns, 4);
    assert_eq!(stats.malformed, 0);
}

#[test]
fn a_bucket_keeps_file_order() {
    // Cursors are indices into the bucket, so the order a later visit resumes
    // into has to be the order the file gave.
    let mut pool = ReusingPool::default();
    pool.add_pool_lines("[\"aa\"]\n[\"bb\"]\n[\"cc\"]\n");

    let got: Vec<_> = pool.bucket(&[2]).unwrap().entries.iter().map(|e| e.segs[0].clone()).collect();
    assert_eq!(got, vec![b"aa".to_vec(), b"bb".to_vec(), b"cc".to_vec()]);
}

#[test]
fn a_very_wide_entry_still_parses() {
    // jq's pool has entries 433 segments wide. The C reader has no cap at
    // parse time either -- the width limit belongs to the lookup.
    let line = format!("[{}]", vec!["\"a\""; 200].join(","));
    let e = parse_pool_line(&line).unwrap().unwrap();
    assert_eq!(e.segs.len(), 200);
}

#[test]
fn a_range_set_too_wide_to_aim_at_finds_no_bucket() {
    let mut pool = ReusingPool::default();
    pool.add_pool_lines(&format!("[{}]\n", vec!["\"a\""; 200].join(",")));

    assert_eq!(pool.stats().entries, 1, "stored");
    assert!(pool.bucket(&vec![1u32; 200]).is_none(), "but never looked up");
}

#[test]
fn malformed_lines_are_counted_not_fatal() {
    let mut pool = ReusingPool::default();
    pool.add_pool_lines("[\"ok\"]\n[\"bad\\q\"]\n[]\n[\"fine\"]\n");

    assert_eq!(pool.stats().entries, 2);
    assert_eq!(pool.stats().malformed, 2);
}

/* ------------------------------------------------------ unsolved condition */

#[test]
fn an_unsolved_line_parses() {
    assert_eq!(
        parse_unsolved_line("cmpid=35970050 context=6251862 order=5 seen=0"),
        Some(SiteKey { cmpid: 35_970_050, context: 6_251_862, order: 5 })
    );
}

#[test]
fn junk_unsolved_lines_are_ignored() {
    for line in [
        "# unsolved conditions -- 14051 of 15343 tracked site(s)",
        "",
        "cmpid=1 context=2 order=3",            // no seen field
        "cmpid=1 context=two order=3 seen=0",   // not a number
        "garbage",
    ] {
        assert_eq!(parse_unsolved_line(line), None, "{line:?}");
    }
}

#[test]
fn the_unsolved_set_dedups() {
    let mut pool = ReusingPool::default();
    pool.add_unsolved_lines(
        "# header\n\
         cmpid=1 context=2 order=0 seen=0\n\
         cmpid=1 context=2 order=0 seen=1\n\
         cmpid=1 context=2 order=1 seen=0\n",
    );

    assert_eq!(pool.stats().unsolved_sites, 2);
    assert_eq!(pool.stats().unsolved_duplicates, 1);

    assert!(pool.is_unsolved(&SiteKey { cmpid: 1, context: 2, order: 0 }));
    assert!(!pool.is_unsolved(&SiteKey { cmpid: 1, context: 2, order: 9 }));
}

#[test]
fn order_and_context_are_part_of_the_key() {
    let mut pool = ReusingPool::default();
    pool.add_unsolved_lines("cmpid=7 context=1 order=0 seen=0\n");

    let site = |c, o| SiteKey { cmpid: 7, context: c, order: o };
    assert!(pool.is_unsolved(&site(1, 0)));
    assert!(!pool.is_unsolved(&site(2, 0)), "another call path is another site");
    assert!(!pool.is_unsolved(&site(1, 1)), "another loop iteration is another site");
}

/* ------------------------------------------------------- a real scan, opt-in */

#[test]
fn reads_a_real_scan() {
    let Ok(dir) = std::env::var("REUSING_POOL_DIR") else {
        eprintln!("REUSING_POOL_DIR unset, skipping");
        return;
    };

    let pool = ReusingPool::load(&PathBuf::from(dir)).expect("loads");
    let stats = pool.stats();

    eprintln!(
        "{} entries, {} segments, {} patterns, {} malformed; {} unsolved sites ({} dups)",
        stats.entries, stats.segments, stats.patterns, stats.malformed,
        stats.unsolved_sites, stats.unsolved_duplicates
    );

    // The scan's own summary is the reference: a reader that drops lines shows
    // up here as a shortfall, not as a campaign that quietly finds less.
    assert_eq!(stats.malformed, 0, "the scan writes what this reader accepts");
    assert!(stats.entries > 0 && stats.unsolved_sites > 0);

    // Every entry has to be reachable through its own shape -- that is the
    // only way the stage ever looks one up.
    for pattern in [vec![1u32], vec![2], vec![4], vec![1, 1]] {
        let Some(bucket) = pool.bucket(&pattern) else { continue };
        assert!(!bucket.entries.is_empty());

        for e in &bucket.entries {
            assert_eq!(e.pattern(), pattern, "entry filed under the wrong shape");
            assert!(e.segs.iter().all(|s| !s.is_empty()), "an empty segment survived");
        }
    }
}
