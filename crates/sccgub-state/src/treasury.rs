use sccgub_types::tension::TensionValue;
use sccgub_types::AgentId;

/// Treasury — collects fees, distributes block rewards, and tracks burn.
///
/// In a policy-aware financial chain, the treasury is system law:
/// - Every accepted transaction pays a fee into the treasury.
/// - Block rewards are drawn from treasury (or minted up to cap).
/// - Burns reduce total supply permanently.
/// - All treasury operations produce auditable receipts.
#[derive(Debug, Clone, Default)]
pub struct Treasury {
    /// Accumulated fees not yet distributed.
    pub pending_fees: TensionValue,
    /// Total fees collected across all epochs.
    pub total_fees_collected: TensionValue,
    /// Total rewards distributed to validators.
    pub total_rewards_distributed: TensionValue,
    /// Total burned (permanently removed from supply).
    pub total_burned: TensionValue,
    /// Current epoch number.
    pub epoch: u64,
    /// Fees collected in current epoch.
    pub epoch_fees: TensionValue,
    /// Rewards distributed in current epoch.
    pub epoch_rewards: TensionValue,
}

/// Record of a treasury operation for audit trail.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TreasuryReceipt {
    pub operation: TreasuryOperation,
    pub amount: TensionValue,
    pub block_height: u64,
    pub agent: Option<AgentId>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum TreasuryOperation {
    FeeCollected,
    RewardDistributed,
    Burned,
    EpochRollover,
}

impl Treasury {
    pub fn new() -> Self {
        Self::default()
    }

    /// Collect a transaction fee into the treasury.
    pub fn collect_fee(&mut self, amount: TensionValue) {
        self.pending_fees = self.pending_fees + amount;
        self.total_fees_collected = self.total_fees_collected + amount;
        self.epoch_fees = self.epoch_fees + amount;
    }

    /// Distribute a reward to a validator. Drawn from pending fees.
    /// Returns the actual amount distributed (capped at available pending fees).
    pub fn distribute_reward(&mut self, amount: TensionValue) -> TensionValue {
        let actual = if amount.raw() > self.pending_fees.raw() {
            self.pending_fees
        } else {
            amount
        };
        self.pending_fees = self.pending_fees - actual;
        self.total_rewards_distributed = self.total_rewards_distributed + actual;
        self.epoch_rewards = self.epoch_rewards + actual;
        actual
    }

    /// Burn tokens (permanently remove from supply).
    pub fn burn(&mut self, amount: TensionValue) -> Result<(), String> {
        if amount.raw() > self.pending_fees.raw() {
            return Err("Cannot burn more than pending fees".into());
        }
        self.pending_fees = self.pending_fees - amount;
        self.total_burned = self.total_burned + amount;
        Ok(())
    }

    /// Advance to next epoch. Returns summary of prior epoch.
    pub fn advance_epoch(&mut self) -> EpochSummary {
        let summary = EpochSummary {
            epoch: self.epoch,
            fees_collected: self.epoch_fees,
            rewards_distributed: self.epoch_rewards,
            pending_balance: self.pending_fees,
        };
        self.epoch += 1;
        self.epoch_fees = TensionValue::ZERO;
        self.epoch_rewards = TensionValue::ZERO;
        summary
    }

    /// Net treasury balance (fees collected minus distributed and burned).
    pub fn net_balance(&self) -> TensionValue {
        self.pending_fees
    }
}

#[derive(Debug, Clone)]
pub struct EpochSummary {
    pub epoch: u64,
    pub fees_collected: TensionValue,
    pub rewards_distributed: TensionValue,
    pub pending_balance: TensionValue,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fee_collection_and_distribution() {
        let mut treasury = Treasury::new();
        treasury.collect_fee(TensionValue::from_integer(100));
        treasury.collect_fee(TensionValue::from_integer(50));

        assert_eq!(treasury.pending_fees, TensionValue::from_integer(150));
        assert_eq!(
            treasury.total_fees_collected,
            TensionValue::from_integer(150)
        );

        let distributed = treasury.distribute_reward(TensionValue::from_integer(80));
        assert_eq!(distributed, TensionValue::from_integer(80));
        assert_eq!(treasury.pending_fees, TensionValue::from_integer(70));
    }

    #[test]
    fn test_reward_capped_at_available() {
        let mut treasury = Treasury::new();
        treasury.collect_fee(TensionValue::from_integer(30));

        let distributed = treasury.distribute_reward(TensionValue::from_integer(100));
        assert_eq!(distributed, TensionValue::from_integer(30));
        assert_eq!(treasury.pending_fees, TensionValue::ZERO);
    }

    #[test]
    fn test_burn() {
        let mut treasury = Treasury::new();
        treasury.collect_fee(TensionValue::from_integer(100));

        assert!(treasury.burn(TensionValue::from_integer(40)).is_ok());
        assert_eq!(treasury.pending_fees, TensionValue::from_integer(60));
        assert_eq!(treasury.total_burned, TensionValue::from_integer(40));

        assert!(treasury.burn(TensionValue::from_integer(200)).is_err());
    }

    #[test]
    fn test_epoch_advancement() {
        let mut treasury = Treasury::new();
        treasury.collect_fee(TensionValue::from_integer(200));
        treasury.distribute_reward(TensionValue::from_integer(50));

        let summary = treasury.advance_epoch();
        assert_eq!(summary.epoch, 0);
        assert_eq!(summary.fees_collected, TensionValue::from_integer(200));
        assert_eq!(summary.rewards_distributed, TensionValue::from_integer(50));
        assert_eq!(treasury.epoch, 1);
        assert_eq!(treasury.epoch_fees, TensionValue::ZERO);
    }

    #[test]
    fn test_conservation() {
        let mut treasury = Treasury::new();
        treasury.collect_fee(TensionValue::from_integer(1000));
        treasury.distribute_reward(TensionValue::from_integer(300));
        treasury.burn(TensionValue::from_integer(200)).unwrap();

        // pending = 1000 - 300 - 200 = 500
        assert_eq!(treasury.pending_fees, TensionValue::from_integer(500));
        // total_collected = distributed + burned + pending
        let sum = treasury.total_rewards_distributed.raw()
            + treasury.total_burned.raw()
            + treasury.pending_fees.raw();
        assert_eq!(sum, treasury.total_fees_collected.raw());
    }
}
