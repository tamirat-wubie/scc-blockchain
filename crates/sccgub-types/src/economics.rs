use serde::{Deserialize, Serialize};

use crate::consensus_params::ConsensusParams;
use crate::constitutional_ceilings::ConstitutionalCeilings;
use crate::tension::TensionValue;

/// Economic model per v2.0 spec Section 13.
/// Fee = base_fee * (1 + alpha * T_total_prev / T_budget)
/// Per v2.1 FIX B-10: uses PRIOR block's tension to avoid circular dependency.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EconomicState {
    /// Base fee for a transition (in tension units).
    pub base_fee: TensionValue,
    /// Multiplier for tension-based fee scaling.
    pub alpha: TensionValue,
    /// Total fees collected in the current epoch.
    pub fees_collected: TensionValue,
    /// Total validator rewards distributed in the current epoch.
    pub rewards_distributed: TensionValue,
}

impl Default for EconomicState {
    fn default() -> Self {
        Self {
            base_fee: TensionValue::from_integer(1),
            alpha: TensionValue(TensionValue::SCALE / 10), // 0.1
            fees_collected: TensionValue::ZERO,
            rewards_distributed: TensionValue::ZERO,
        }
    }
}

impl EconomicState {
    /// Compute the effective fee for a transition.
    /// Per v2.1 FIX B-10: tension_total is from the PREVIOUS block (not current).
    pub fn effective_fee(
        &self,
        prior_block_tension: TensionValue,
        tension_budget: TensionValue,
    ) -> TensionValue {
        if tension_budget.raw() <= 0 {
            return self.base_fee; // Reject zero or negative budget.
        }
        // fee = base_fee * (1 + alpha * T_prev / T_budget)
        // Safe ratio: use split division to prevent overflow.
        let one = TensionValue(TensionValue::SCALE);
        let ratio = TensionValue(
            prior_block_tension
                .raw()
                .saturating_mul(TensionValue::SCALE)
                / tension_budget.raw(),
        );
        let multiplier = one + self.alpha.mul_fp(ratio);
        self.base_fee.mul_fp(multiplier)
    }

    /// Record a fee payment.
    pub fn record_fee(&mut self, amount: TensionValue) {
        self.fees_collected = self.fees_collected + amount;
    }

    /// Distribute rewards to a validator.
    pub fn distribute_reward(&mut self, amount: TensionValue) {
        self.rewards_distributed = self.rewards_distributed + amount;
    }

    /// Reset epoch counters.
    pub fn reset_epoch(&mut self) {
        self.fees_collected = TensionValue::ZERO;
        self.rewards_distributed = TensionValue::ZERO;
    }

    /// Patch-05 §20.1: compute the v4 gas price using median-over-window
    /// instead of single-block `T_prior`.
    ///
    /// - `prior_tensions`: the window of recent per-block tension values
    ///   (most recent last). Length must satisfy
    ///   `params.median_tension_window`; if the chain is younger than
    ///   the window size, the caller passes whatever is available
    ///   (a shorter slice — see §20.1 warming window).
    /// - `tension_budget`: current budget used as the divisor.
    /// - `params`: `ConsensusParams` supplying `fee_tension_alpha` and
    ///   the window-size reference value. `self.alpha` is ignored in
    ///   the v4 path; `self.base_fee` is retained.
    ///
    /// Formula: `gas_price = base_fee * (1 + alpha * T_median / T_budget)`.
    /// Median is the sorted middle element (§20.1 oddness invariant).
    ///
    /// Pure and deterministic: no wall-clock, no randomness. Same
    /// `(window, budget, params)` always produces the same result.
    pub fn effective_fee_median(
        &self,
        prior_tensions: &[TensionValue],
        tension_budget: TensionValue,
        params: &ConsensusParams,
    ) -> TensionValue {
        if tension_budget.raw() <= 0 {
            return self.base_fee;
        }
        // Warming window: chain younger than W. Use whatever prior
        // tensions exist. With zero prior blocks, use ZERO (equivalent
        // to base_fee).
        if prior_tensions.is_empty() {
            return self.base_fee;
        }
        let t_median = median_of_tensions(prior_tensions);
        // fee = base_fee * (1 + alpha * T_median / T_budget)
        let one = TensionValue(TensionValue::SCALE);
        let ratio =
            TensionValue(t_median.raw().saturating_mul(TensionValue::SCALE) / tension_budget.raw());
        let alpha = TensionValue(params.fee_tension_alpha);
        let multiplier = one + alpha.mul_fp(ratio);
        self.base_fee.mul_fp(multiplier)
    }

    /// Patch-06 §31.2: v5 fee composition with a post-multiplier floor.
    ///
    /// Computes `effective_fee_median(...)` then clamps the result to
    /// `max(computed, ceilings.min_effective_fee_floor)`. Closes
    /// INV-FEE-FLOOR-ENFORCED: no matter how coordinated low-tension
    /// blocks drive the median down, the returned fee cannot fall below
    /// the floor.
    ///
    /// Callers that do not have access to `ConstitutionalCeilings` (e.g.,
    /// tests or pre-v5 replay paths) continue to call
    /// `effective_fee_median` directly; no existing call site is broken.
    pub fn effective_fee_median_floored(
        &self,
        prior_tensions: &[TensionValue],
        tension_budget: TensionValue,
        params: &ConsensusParams,
        ceilings: &ConstitutionalCeilings,
    ) -> TensionValue {
        let computed = self.effective_fee_median(prior_tensions, tension_budget, params);
        let floor = TensionValue(ceilings.min_effective_fee_floor);
        if computed < floor {
            floor
        } else {
            computed
        }
    }
}

/// Median of a non-empty slice of `TensionValue`. Sorts a copy; input
/// is not mutated. For odd-length slices returns the middle element
/// (§20.1 spec). For even-length slices returns the lower-middle
/// element — deterministic but not formally spec-specified (the
/// `median_tension_window` validator ensures odd-length in practice).
///
/// Bounded by input: `min(slice) <= median <= max(slice)`. This is the
/// core of `INV-FEE-ORACLE-BOUNDED`.
pub fn median_of_tensions(values: &[TensionValue]) -> TensionValue {
    debug_assert!(!values.is_empty(), "median_of_tensions: empty slice");
    let mut sorted: Vec<TensionValue> = values.to_vec();
    sorted.sort();
    let mid = sorted.len() / 2;
    if sorted.len().is_multiple_of(2) {
        // Even length: lower-middle element. See §20.1 — the
        // ConsensusParams validator pins odd window size; this branch
        // only fires during warming or under misconfiguration.
        sorted[mid - 1]
    } else {
        sorted[mid]
    }
}

/// Fee breakdown for different resource types.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FeeBreakdown {
    pub compute_fee: TensionValue,
    pub storage_fee: TensionValue,
    pub proof_fee: TensionValue,
}

impl FeeBreakdown {
    pub fn total(&self) -> TensionValue {
        self.compute_fee + self.storage_fee + self.proof_fee
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_effective_fee_zero_tension() {
        let econ = EconomicState::default();
        let fee = econ.effective_fee(TensionValue::ZERO, TensionValue::from_integer(1000));
        // With zero tension, fee should be close to base_fee * 1.0.
        assert_eq!(fee, econ.base_fee);
    }

    #[test]
    fn test_effective_fee_increases_with_tension() {
        let econ = EconomicState::default();
        let budget = TensionValue::from_integer(100);

        let fee_low = econ.effective_fee(TensionValue::from_integer(10), budget);
        let fee_high = econ.effective_fee(TensionValue::from_integer(90), budget);

        assert!(
            fee_high > fee_low,
            "Higher tension should mean higher fee: {} vs {}",
            fee_high,
            fee_low
        );
    }

    #[test]
    fn test_fee_collection() {
        let mut econ = EconomicState::default();
        econ.record_fee(TensionValue::from_integer(5));
        econ.record_fee(TensionValue::from_integer(3));
        assert_eq!(econ.fees_collected, TensionValue::from_integer(8));

        econ.reset_epoch();
        assert_eq!(econ.fees_collected, TensionValue::ZERO);
    }

    #[test]
    fn test_effective_fee_zero_budget_returns_base_fee() {
        let econ = EconomicState::default();
        let fee = econ.effective_fee(TensionValue::from_integer(50), TensionValue::ZERO);
        assert_eq!(
            fee, econ.base_fee,
            "zero budget should return base_fee (div-by-zero guard)"
        );
    }

    #[test]
    fn test_effective_fee_negative_budget_returns_base_fee() {
        let econ = EconomicState::default();
        let fee = econ.effective_fee(
            TensionValue::from_integer(50),
            TensionValue::from_integer(-10),
        );
        assert_eq!(fee, econ.base_fee, "negative budget should return base_fee");
    }

    #[test]
    fn test_distribute_reward_accumulates() {
        let mut econ = EconomicState::default();
        econ.distribute_reward(TensionValue::from_integer(10));
        econ.distribute_reward(TensionValue::from_integer(7));
        assert_eq!(econ.rewards_distributed, TensionValue::from_integer(17));

        econ.reset_epoch();
        assert_eq!(econ.rewards_distributed, TensionValue::ZERO);
    }

    // ── Patch-05 §20 median-over-window fee oracle ─────────────────────

    fn t(n: i64) -> TensionValue {
        TensionValue::from_integer(n)
    }

    #[test]
    fn patch_05_median_of_odd_slice() {
        // Sorted middle of [1, 2, 3, 4, 5] is 3.
        let values = vec![t(4), t(1), t(3), t(5), t(2)];
        assert_eq!(median_of_tensions(&values), t(3));
    }

    #[test]
    fn patch_05_median_of_single_element() {
        assert_eq!(median_of_tensions(&[t(42)]), t(42));
    }

    #[test]
    fn patch_05_median_of_tensions_bounded() {
        // Property: min(slice) <= median <= max(slice). Core of
        // INV-FEE-ORACLE-BOUNDED.
        for &vals in &[
            &[1i64, 2, 3, 4, 5][..],
            &[100, -50, 20, 0, 75][..],
            &[i64::MIN / 2, 0, i64::MAX / 2][..],
            &[7, 7, 7, 7, 7][..],
            &[0, 1000000][..],
        ] {
            let tv: Vec<TensionValue> = vals.iter().copied().map(t).collect();
            let med = median_of_tensions(&tv);
            let min = tv.iter().copied().min().unwrap();
            let max = tv.iter().copied().max().unwrap();
            assert!(
                min <= med && med <= max,
                "median {} outside [{}, {}] for {:?}",
                med,
                min,
                max,
                vals
            );
        }
    }

    #[test]
    fn patch_05_median_does_not_mutate_input() {
        let values = vec![t(5), t(1), t(3)];
        let before = values.clone();
        let _ = median_of_tensions(&values);
        assert_eq!(values, before);
    }

    #[test]
    fn patch_05_effective_fee_median_warming_window_uses_base_fee() {
        let econ = EconomicState::default();
        let params = ConsensusParams::default();
        // No prior tensions (genesis or very young chain): fee = base_fee.
        let fee = econ.effective_fee_median(&[], t(1000), &params);
        assert_eq!(fee, econ.base_fee);
    }

    #[test]
    fn patch_05_effective_fee_median_zero_budget_returns_base_fee() {
        let econ = EconomicState::default();
        let params = ConsensusParams::default();
        let window = vec![t(100), t(200), t(300)];
        let fee = econ.effective_fee_median(&window, TensionValue::ZERO, &params);
        assert_eq!(fee, econ.base_fee);
    }

    #[test]
    fn patch_05_effective_fee_median_increases_with_tension() {
        let econ = EconomicState::default();
        let params = ConsensusParams::default();
        let budget = t(1000);
        // Low-tension window vs high-tension window — same length, same
        // α — high window produces a larger fee.
        let low = vec![t(10), t(20), t(30), t(40), t(50)];
        let high = vec![t(100), t(200), t(300), t(400), t(500)];
        let fee_low = econ.effective_fee_median(&low, budget, &params);
        let fee_high = econ.effective_fee_median(&high, budget, &params);
        assert!(
            fee_high > fee_low,
            "higher-tension window must produce higher fee: {} vs {}",
            fee_high,
            fee_low
        );
    }

    #[test]
    fn patch_05_fee_bounded_between_min_and_max() {
        // INV-FEE-ORACLE-BOUNDED: gas_price is bounded because median is
        // bounded. This test exercises the boundedness by computing fees
        // over three windows with identical min and max but different
        // interior values, and asserting all three fees lie inside
        // [fee_at_min, fee_at_max].
        let econ = EconomicState::default();
        let params = ConsensusParams::default();
        let budget = t(1000);

        // Fee assuming every sample in the window is the min.
        let fee_at_min = econ.effective_fee_median(&[t(10); 5], budget, &params);
        // Fee assuming every sample is the max.
        let fee_at_max = econ.effective_fee_median(&[t(500); 5], budget, &params);

        // Various mixes with min=10, max=500 — all medians must fall
        // between those values, so fees must fall in [fee_at_min, fee_at_max].
        for mix in &[
            vec![t(10), t(100), t(200), t(300), t(500)],
            vec![t(10), t(20), t(30), t(400), t(500)],
            vec![t(10), t(250), t(300), t(499), t(500)],
            vec![t(10), t(10), t(10), t(10), t(500)],
        ] {
            let fee = econ.effective_fee_median(mix, budget, &params);
            assert!(
                fee_at_min <= fee && fee <= fee_at_max,
                "fee {} outside [{}, {}] for {:?}",
                fee,
                fee_at_min,
                fee_at_max,
                mix
            );
        }
    }

    #[test]
    fn patch_05_single_block_cannot_move_median_on_odd_window() {
        // Manipulation-resistance property: flipping ONE sample in a
        // 5-element window cannot change the median if the other four
        // samples bracket it.
        let econ = EconomicState::default();
        let params = ConsensusParams::default();
        let budget = t(1000);

        // Baseline: four "normal" samples at 100 + one "normal" at 100.
        let baseline = vec![t(100), t(100), t(100), t(100), t(100)];
        let baseline_fee = econ.effective_fee_median(&baseline, budget, &params);

        // Attacker flips one sample to extreme high.
        let attacked_high = vec![t(100), t(100), t(100), t(100), t(1_000_000)];
        let attacked_high_fee = econ.effective_fee_median(&attacked_high, budget, &params);

        // Attacker flips one sample to extreme low.
        let attacked_low = vec![t(0), t(100), t(100), t(100), t(100)];
        let attacked_low_fee = econ.effective_fee_median(&attacked_low, budget, &params);

        // All three must produce identical fees — the median of every
        // window above is 100.
        assert_eq!(baseline_fee, attacked_high_fee);
        assert_eq!(baseline_fee, attacked_low_fee);
    }

    // ── Patch-06 §31 base-fee floor ────────────────────────────────────

    #[test]
    fn patch_06_floor_is_noop_when_computed_exceeds_floor() {
        // Default ConstitutionalCeilings.min_effective_fee_floor = SCALE/100
        // (= 0.01). Default EconomicState.base_fee = SCALE (= 1.0). With
        // any non-degenerate window, computed_fee >= base_fee = 1.0 > 0.01,
        // so the floor is a no-op.
        let econ = EconomicState::default();
        let params = ConsensusParams::default();
        let ceilings = ConstitutionalCeilings::default();
        let window = vec![t(100), t(100), t(100), t(100), t(100)];
        let unfloored = econ.effective_fee_median(&window, t(1000), &params);
        let floored = econ.effective_fee_median_floored(&window, t(1000), &params, &ceilings);
        assert_eq!(
            unfloored, floored,
            "default floor must not change healthy-chain fees"
        );
    }

    #[test]
    fn patch_06_floor_lifts_attacker_collapsed_fee() {
        // Adversarial construction: base_fee near zero, ceiling floor at
        // 0.01. Unfloored returns near-zero; floored returns the ceiling.
        let near_zero = TensionValue(1); // 1 scale-unit = 1e-6 fee units
        let econ = EconomicState {
            base_fee: near_zero,
            alpha: TensionValue(TensionValue::SCALE / 10),
            fees_collected: TensionValue::ZERO,
            rewards_distributed: TensionValue::ZERO,
        };
        let params = ConsensusParams::default();
        let ceilings = ConstitutionalCeilings::default();
        let window = vec![t(0), t(0), t(0), t(0), t(0)];

        let unfloored = econ.effective_fee_median(&window, t(1000), &params);
        let floored = econ.effective_fee_median_floored(&window, t(1000), &params, &ceilings);

        assert!(
            unfloored < TensionValue(ceilings.min_effective_fee_floor),
            "test precondition: unfloored must be below the floor"
        );
        assert_eq!(
            floored,
            TensionValue(ceilings.min_effective_fee_floor),
            "INV-FEE-FLOOR-ENFORCED: floored fee must equal the floor"
        );
    }

    #[test]
    fn patch_06_floor_lifts_warming_window_fee() {
        // Warming-window path: prior_tensions is empty. Without the floor
        // the returned value is self.base_fee (verified by the
        // patch_05_effective_fee_median_warming_window_uses_base_fee
        // test). With an adversarial base_fee below the floor, the
        // floored variant must still lift to the floor. This closes a
        // subtle INV-FEE-FLOOR-ENFORCED coverage gap — a freshly-reset
        // chain with no tension history is the exact condition an
        // attacker would engineer for fee bypass.
        let near_zero = TensionValue(1);
        let econ = EconomicState {
            base_fee: near_zero,
            alpha: TensionValue(TensionValue::SCALE / 10),
            fees_collected: TensionValue::ZERO,
            rewards_distributed: TensionValue::ZERO,
        };
        let params = ConsensusParams::default();
        let ceilings = ConstitutionalCeilings::default();
        let floored = econ.effective_fee_median_floored(&[], t(1000), &params, &ceilings);
        assert_eq!(
            floored,
            TensionValue(ceilings.min_effective_fee_floor),
            "warming window (empty prior_tensions) must still respect floor"
        );
    }

    #[test]
    fn patch_06_floor_respects_configured_ceiling_value() {
        // If an operator genesis-pins a floor higher than default, the
        // floored fee reflects that value exactly.
        let econ = EconomicState {
            base_fee: TensionValue(1),
            alpha: TensionValue(0),
            fees_collected: TensionValue::ZERO,
            rewards_distributed: TensionValue::ZERO,
        };
        let params = ConsensusParams::default();
        let ceilings = ConstitutionalCeilings {
            min_effective_fee_floor: TensionValue::SCALE / 2, // 0.5
            ..ConstitutionalCeilings::default()
        };
        let window = vec![t(0), t(0), t(0), t(0), t(0)];
        let floored = econ.effective_fee_median_floored(&window, t(1000), &params, &ceilings);
        assert_eq!(floored, TensionValue(TensionValue::SCALE / 2));
    }

    #[test]
    fn patch_05_fee_uses_params_alpha_not_self_alpha() {
        // `self.alpha` is the v3 path's default (0.1). v4 fees must
        // pull α from `params.fee_tension_alpha` (0.5 default).
        let econ = EconomicState::default();
        let params_low_alpha = ConsensusParams {
            fee_tension_alpha: TensionValue::SCALE / 100, // 0.01
            ..Default::default()
        };
        let params_high_alpha = ConsensusParams {
            fee_tension_alpha: TensionValue::SCALE, // 1.0
            ..Default::default()
        };
        let window = vec![t(100), t(100), t(100), t(100), t(100)];
        let budget = t(1000);
        let fee_low = econ.effective_fee_median(&window, budget, &params_low_alpha);
        let fee_high = econ.effective_fee_median(&window, budget, &params_high_alpha);
        assert!(
            fee_high > fee_low,
            "higher α must produce higher fee: {} vs {}",
            fee_high,
            fee_low
        );
    }
}
