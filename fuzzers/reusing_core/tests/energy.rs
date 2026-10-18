//! Pins the numbers of the energy split: the scaling itself is three lines,
//! but the floor, the cap, and which side of the split a draw lands on are
//! exactly the kind of thing a refactor flips silently.

use reusing_core::{
    energy::scale, NEW_ENERGY_MULT, SEED_ENERGY_DIV,
};

/// `StdMutationalStage` draws `1 + rand(128)`, so this is the range `scale`
/// actually sees.
const DRAW_MIN: usize = 1;
const DRAW_MAX: usize = 129;

#[test]
fn a_find_gets_the_multiplier() {
    assert_eq!(scale(10, false), 10 * NEW_ENERGY_MULT);
}

#[test]
fn a_seed_gives_up_the_divisor() {
    assert_eq!(scale(10, true), 10 / SEED_ENERGY_DIV);
}

#[test]
fn a_seed_never_reaches_zero() {
    // AFL++ floors perf_score at 1; a zero here would skip the entry
    // entirely rather than deprioritize it.
    assert_eq!(scale(DRAW_MIN, true), 1);
    assert_eq!(scale(0, true), 1);
}

#[test]
fn the_boost_is_capped_at_mult_times_the_ceiling() {
    // 129 * 8 = 1032 would leak past AFL++'s `havoc_max_mult * 100 * MULT`
    // analog (128 * 8 = 1024); the cap trims exactly that overhang.
    assert_eq!(scale(DRAW_MAX, false), 128 * NEW_ENERGY_MULT);
}

#[test]
fn an_ordinary_draw_is_not_touched_by_the_cap() {
    for base in DRAW_MIN..=128 {
        assert_eq!(scale(base, false), base * NEW_ENERGY_MULT);
    }
}
