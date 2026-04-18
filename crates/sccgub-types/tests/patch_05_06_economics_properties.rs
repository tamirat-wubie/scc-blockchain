//! Property-based tests for the fee-oracle invariants.
//!
//! Continues the v0.7.1/v0.7.2 property-test pattern over the
//! Patch-05/06 economic surface:
//!
//! - **INV-FEE-ORACLE-BOUNDED (PATCH_05 §20)**: `effective_fee_median`
//!   produces a fee bounded by `[fee_at_min_window, fee_at_max_window]`.
//!   Random windows must satisfy this.
//! - **INV-FEE-FLOOR-ENFORCED (PATCH_06 §31)**:
//!   `effective_fee_median_floored` produces a fee `>=
//!   ceilings.min_effective_fee_floor` for every combination of
//!   base_fee, window, budget, and α.
//! - **Median monotonicity**: increasing every window element by the
//!   same delta increases the floored fee monotonically (modulo the
//!   floor clamp).
//!
//! Same deterministic xorshift PRNG pattern as
//! `tests/property_test.rs` and `tests/patch_06_consensus_properties.rs`
//! — no new dependency.

use sccgub_types::consensus_params::ConsensusParams;
use sccgub_types::constitutional_ceilings::ConstitutionalCeilings;
use sccgub_types::economics::{median_of_tensions, EconomicState};
use sccgub_types::tension::TensionValue;

fn prng(seed: &mut u64) -> u64 {
    *seed ^= *seed << 13;
    *seed ^= *seed >> 7;
    *seed ^= *seed << 17;
    *seed
}

fn random_tension(seed: &mut u64) -> TensionValue {
    // Bounded to keep arithmetic well-behaved (no overflow at the
    // multiply step) while still covering realistic ranges. i64 max is
    // ~9.2e18; cap at 1e9 fixed-point units to stay well below.
    let raw = (prng(seed) % 1_000_000_000) as i64;
    TensionValue::from_integer(raw)
}

fn random_window(seed: &mut u64, n: usize) -> Vec<TensionValue> {
    (0..n).map(|_| random_tension(seed)).collect()
}

fn econ_with_base(base: i128) -> EconomicState {
    EconomicState {
        base_fee: TensionValue(base),
        alpha: TensionValue(TensionValue::SCALE / 10),
        fees_collected: TensionValue::ZERO,
        rewards_distributed: TensionValue::ZERO,
    }
}

// ── INV-FEE-FLOOR-ENFORCED (PATCH_06 §31) ────────────────────────────

#[test]
fn prop_floor_always_at_or_above_floor_constant() {
    // For any (base_fee, window, budget) the floored fee is never
    // below ceilings.min_effective_fee_floor.
    let mut seed = 0xfee0_f100_b0a7_face_u64;
    let params = ConsensusParams::default();
    let ceilings = ConstitutionalCeilings::default();
    let floor = TensionValue(ceilings.min_effective_fee_floor);

    for _ in 0..100 {
        // Random base_fee covering near-zero to far-above-floor.
        let base = (prng(&mut seed) % 10_000_000) as i128;
        let econ = econ_with_base(base);
        // Random window 1-7 elements (odd, matches default median_tension_window).
        let n = ((prng(&mut seed) % 4) * 2 + 1) as usize; // 1, 3, 5, 7
        let window = random_window(&mut seed, n);
        // Random budget — non-zero positive.
        let budget = TensionValue::from_integer((prng(&mut seed) % 10000) as i64 + 1);
        let floored = econ.effective_fee_median_floored(&window, budget, &params, &ceilings);
        assert!(
            floored >= floor,
            "INV-FEE-FLOOR-ENFORCED violated: floored={} < floor={}",
            floored,
            floor
        );
    }
}

#[test]
fn prop_floor_with_empty_window_at_or_above_floor() {
    // The warming-window path (empty prior_tensions) must also respect
    // the floor — verifying v0.6.2's coverage at randomized base_fee
    // values.
    let mut seed = 0xc01dcafedeadbeefu64;
    let params = ConsensusParams::default();
    let ceilings = ConstitutionalCeilings::default();
    let floor = TensionValue(ceilings.min_effective_fee_floor);

    for _ in 0..50 {
        let base = (prng(&mut seed) % 10_000_000) as i128;
        let econ = econ_with_base(base);
        let budget = TensionValue::from_integer((prng(&mut seed) % 10000) as i64 + 1);
        let floored = econ.effective_fee_median_floored(&[], budget, &params, &ceilings);
        assert!(
            floored >= floor,
            "warming-window floor violated: base={} floored={} < floor={}",
            base,
            floored,
            floor
        );
    }
}

#[test]
fn prop_floor_is_noop_when_unfloored_is_above() {
    // When the unfloored fee is already above the floor, the floored
    // value MUST equal the unfloored value (the floor is a clamp, not
    // a perturbation).
    let mut seed = 0xa11_5677_b22b_ee5_u64;
    let params = ConsensusParams::default();
    let ceilings = ConstitutionalCeilings::default();
    let floor = TensionValue(ceilings.min_effective_fee_floor);

    for _ in 0..80 {
        // base well above the floor → unfloored guaranteed above floor.
        let base = TensionValue::SCALE * (1 + (prng(&mut seed) % 100) as i128);
        let econ = econ_with_base(base);
        let n = ((prng(&mut seed) % 4) * 2 + 1) as usize;
        let window = random_window(&mut seed, n);
        let budget = TensionValue::from_integer((prng(&mut seed) % 10000) as i64 + 1);

        let unfloored = econ.effective_fee_median(&window, budget, &params);
        let floored = econ.effective_fee_median_floored(&window, budget, &params, &ceilings);

        if unfloored >= floor {
            assert_eq!(
                unfloored, floored,
                "floor must be no-op when unfloored ({}) >= floor ({})",
                unfloored, floor
            );
        }
    }
}

// ── INV-FEE-ORACLE-BOUNDED (PATCH_05 §20) ────────────────────────────

#[test]
fn prop_median_is_input_bounded() {
    // For every non-empty random window, min(window) <= median <= max(window).
    let mut seed = 0xbabe_face_b0a7_b00b_u64;
    for _ in 0..200 {
        let n = ((prng(&mut seed) % 7) + 1) as usize; // 1..=7
        let window = random_window(&mut seed, n);
        let median = median_of_tensions(&window);
        let min = window.iter().copied().min().unwrap();
        let max = window.iter().copied().max().unwrap();
        assert!(
            min <= median && median <= max,
            "median {} outside [{}, {}] for window {:?}",
            median,
            min,
            max,
            window
        );
    }
}

#[test]
fn prop_median_is_order_independent() {
    // Median of a window is independent of input order.
    let mut seed = 0xfade_c001_a51_dead_u64;
    for _ in 0..80 {
        let n = ((prng(&mut seed) % 6) + 1) as usize;
        let mut window = random_window(&mut seed, n);
        let m1 = median_of_tensions(&window);
        // Reverse and re-median.
        window.reverse();
        let m2 = median_of_tensions(&window);
        assert_eq!(m1, m2, "median must be order-independent");
        // Swap first and last to produce a third arrangement.
        if window.len() >= 2 {
            let last = window.len() - 1;
            window.swap(0, last);
            let m3 = median_of_tensions(&window);
            assert_eq!(m1, m3, "median must be order-independent on swap");
        }
    }
}

#[test]
fn prop_single_sample_cannot_move_odd_window_median() {
    // Manipulation-resistance property (extended): any single-element
    // change in an odd-length window where the changed element is not
    // the median MUST NOT change the median.
    let mut seed = 0xc0de_bad1_dec1_5101_u64;
    for _ in 0..60 {
        // Odd-length windows only: 1, 3, 5, 7.
        let n = ((prng(&mut seed) % 4) * 2 + 1) as usize;
        let window: Vec<TensionValue> = (0..n)
            .map(|i| TensionValue::from_integer((100 + i as i64 * 10) as i64))
            .collect();
        let baseline_median = median_of_tensions(&window);
        let baseline_max = window.iter().copied().max().unwrap();

        // Replace the maximum with an even-larger value; median should NOT move.
        let mut bigger = window.clone();
        let max_idx = bigger
            .iter()
            .position(|v| *v == baseline_max)
            .expect("max must be present");
        bigger[max_idx] = TensionValue::from_integer(1_000_000);
        let new_median = median_of_tensions(&bigger);

        assert_eq!(
            baseline_median, new_median,
            "lifting the max in an odd window MUST NOT change median"
        );

        // Equally, lowering the minimum should NOT move the median.
        let baseline_min = window.iter().copied().min().unwrap();
        let mut smaller = window.clone();
        let min_idx = smaller
            .iter()
            .position(|v| *v == baseline_min)
            .expect("min must be present");
        smaller[min_idx] = TensionValue::from_integer(-1_000_000);
        let new_median_low = median_of_tensions(&smaller);
        assert_eq!(
            baseline_median, new_median_low,
            "lowering the min in an odd window MUST NOT change median"
        );
    }
}

#[test]
fn prop_higher_tension_produces_at_least_as_high_a_fee() {
    // Monotonicity: a window where every element is >= a baseline
    // window's corresponding element produces a fee >= baseline
    // (modulo the floor clamp at the bottom).
    let mut seed = 0xdef1_50ad_b00b_face_u64;
    let params = ConsensusParams::default();
    let ceilings = ConstitutionalCeilings::default();
    let econ = EconomicState::default();

    for _ in 0..60 {
        // Window of N=5 (odd, matches default).
        let baseline_ints: Vec<i64> = (0..5)
            .map(|_| (prng(&mut seed) % 1000) as i64)
            .collect();
        let baseline: Vec<TensionValue> = baseline_ints
            .iter()
            .map(|n| TensionValue::from_integer(*n))
            .collect();
        // Bumped: each element +delta where delta > 0.
        let delta = (prng(&mut seed) % 100 + 1) as i64;
        let bumped: Vec<TensionValue> = baseline_ints
            .iter()
            .map(|n| TensionValue::from_integer(n + delta))
            .collect();
        let budget = TensionValue::from_integer(10_000);

        let fee_baseline =
            econ.effective_fee_median_floored(&baseline, budget, &params, &ceilings);
        let fee_bumped = econ.effective_fee_median_floored(&bumped, budget, &params, &ceilings);

        assert!(
            fee_bumped >= fee_baseline,
            "monotonicity violated: fee_bumped={} < fee_baseline={}",
            fee_bumped,
            fee_baseline
        );
    }
}

#[test]
fn prop_zero_or_negative_budget_returns_base_fee() {
    // Both effective_fee paths bail to base_fee on non-positive budget;
    // floored variant clamps the result to the floor.
    let mut seed = 0x1f1ee_ed_b0a7_d00d_u64;
    let params = ConsensusParams::default();
    let ceilings = ConstitutionalCeilings::default();

    for _ in 0..40 {
        let base = (prng(&mut seed) % 10_000_000) as i128;
        let econ = econ_with_base(base);
        // Random non-positive budget.
        let budget_raw = -((prng(&mut seed) % 1_000_000) as i64);
        let budget = TensionValue::from_integer(budget_raw);

        let unfloored = econ.effective_fee_median(&[TensionValue::from_integer(1)], budget, &params);
        assert_eq!(
            unfloored, econ.base_fee,
            "non-positive budget must return base_fee on unfloored path"
        );

        let floored =
            econ.effective_fee_median_floored(&[TensionValue::from_integer(1)], budget, &params, &ceilings);
        let expected = if econ.base_fee >= TensionValue(ceilings.min_effective_fee_floor) {
            econ.base_fee
        } else {
            TensionValue(ceilings.min_effective_fee_floor)
        };
        assert_eq!(
            floored, expected,
            "non-positive budget floored path must return max(base_fee, floor)"
        );
    }
}
