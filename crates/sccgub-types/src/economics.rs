use serde::{Deserialize, Serialize};

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
        if tension_budget.raw() == 0 {
            return self.base_fee;
        }
        // fee = base_fee * (1 + alpha * T_prev / T_budget)
        let one = TensionValue(TensionValue::SCALE);
        let ratio = TensionValue(
            prior_block_tension.raw() * TensionValue::SCALE / tension_budget.raw(),
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
}
