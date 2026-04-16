use crate::world::ManagedWorldState;
use sccgub_types::namespace::NS_TREASURY;
use sccgub_types::tension::TensionValue;
use sccgub_types::transition::{StateDelta, StateWrite};
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
    /// Negative amounts are clamped to zero to prevent conservation violations.
    pub fn collect_fee(&mut self, amount: TensionValue) {
        let safe = TensionValue(amount.raw().max(0));
        self.pending_fees = self.pending_fees + safe;
        self.total_fees_collected = self.total_fees_collected + safe;
        self.epoch_fees = self.epoch_fees + safe;
    }

    /// Distribute a reward to a validator. Drawn from pending fees.
    /// Returns the actual amount distributed (capped at available pending fees).
    /// Negative amounts are clamped to zero to prevent conservation violations.
    pub fn distribute_reward(&mut self, amount: TensionValue) -> TensionValue {
        let safe_amount = TensionValue(amount.raw().max(0));
        let actual = if safe_amount.raw() > self.pending_fees.raw() {
            self.pending_fees
        } else {
            safe_amount
        };
        self.pending_fees = self.pending_fees - actual;
        self.total_rewards_distributed = self.total_rewards_distributed + actual;
        self.epoch_rewards = self.epoch_rewards + actual;
        actual
    }

    /// Burn tokens (permanently remove from supply).
    /// Negative amounts are rejected to prevent conservation violations.
    pub fn burn(&mut self, amount: TensionValue) -> Result<(), String> {
        if amount.raw() < 0 {
            return Err("Cannot burn negative amount".into());
        }
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

pub fn default_block_reward() -> TensionValue {
    TensionValue::from_integer(10)
}

fn treasury_counter_key(suffix: &[u8]) -> Vec<u8> {
    let mut key = Vec::with_capacity(NS_TREASURY.len() + suffix.len());
    key.extend_from_slice(NS_TREASURY);
    key.extend_from_slice(suffix);
    key
}

fn encode_tension(value: TensionValue) -> Vec<u8> {
    value.raw().to_le_bytes().to_vec()
}

fn decode_tension(key: &[u8], value: &[u8]) -> Result<TensionValue, String> {
    if value.len() != 16 {
        return Err(format!(
            "Malformed treasury entry: {} has value length {} (expected 16)",
            String::from_utf8_lossy(key),
            value.len()
        ));
    }
    let mut raw = [0u8; 16];
    raw.copy_from_slice(value);
    Ok(TensionValue(i128::from_le_bytes(raw)))
}

fn decode_epoch(key: &[u8], value: &[u8]) -> Result<u64, String> {
    if value.len() != 8 {
        return Err(format!(
            "Malformed treasury epoch entry: {} has value length {} (expected 8)",
            String::from_utf8_lossy(key),
            value.len()
        ));
    }
    let mut raw = [0u8; 8];
    raw.copy_from_slice(value);
    Ok(u64::from_le_bytes(raw))
}

pub fn treasury_state_writes(treasury: &Treasury) -> Vec<StateWrite> {
    vec![
        StateWrite {
            address: treasury_counter_key(b"pending_fees"),
            value: encode_tension(treasury.pending_fees),
        },
        StateWrite {
            address: treasury_counter_key(b"total_fees_collected"),
            value: encode_tension(treasury.total_fees_collected),
        },
        StateWrite {
            address: treasury_counter_key(b"total_rewards_distributed"),
            value: encode_tension(treasury.total_rewards_distributed),
        },
        StateWrite {
            address: treasury_counter_key(b"total_burned"),
            value: encode_tension(treasury.total_burned),
        },
        StateWrite {
            address: treasury_counter_key(b"epoch"),
            value: treasury.epoch.to_le_bytes().to_vec(),
        },
        StateWrite {
            address: treasury_counter_key(b"epoch_fees"),
            value: encode_tension(treasury.epoch_fees),
        },
        StateWrite {
            address: treasury_counter_key(b"epoch_rewards"),
            value: encode_tension(treasury.epoch_rewards),
        },
    ]
}

pub fn state_has_treasury_keys(state: &ManagedWorldState) -> bool {
    state
        .trie
        .iter()
        .any(|(key, _)| key.starts_with(NS_TREASURY))
}

pub fn commit_treasury_state(state: &mut ManagedWorldState, treasury: &Treasury) {
    state.apply_delta(&StateDelta {
        writes: treasury_state_writes(treasury),
        deletes: vec![],
    });
}

pub fn treasury_from_trie(state: &ManagedWorldState) -> Result<Treasury, String> {
    let mut treasury = Treasury::new();

    for (key, value) in state.trie.iter() {
        if !key.starts_with(NS_TREASURY) {
            continue;
        }

        match key.as_slice() {
            b"treasury/pending_fees" => treasury.pending_fees = decode_tension(key, value)?,
            b"treasury/total_fees_collected" => {
                treasury.total_fees_collected = decode_tension(key, value)?
            }
            b"treasury/total_rewards_distributed" => {
                treasury.total_rewards_distributed = decode_tension(key, value)?
            }
            b"treasury/total_burned" => treasury.total_burned = decode_tension(key, value)?,
            b"treasury/epoch" => treasury.epoch = decode_epoch(key, value)?,
            b"treasury/epoch_fees" => treasury.epoch_fees = decode_tension(key, value)?,
            b"treasury/epoch_rewards" => treasury.epoch_rewards = decode_tension(key, value)?,
            _ => {
                return Err(format!(
                    "Unknown treasury key in trie: {}",
                    String::from_utf8_lossy(key)
                ));
            }
        }
    }

    Ok(treasury)
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
    use crate::world::ManagedWorldState;

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

    #[test]
    fn test_treasury_trie_roundtrip() {
        let mut state = ManagedWorldState::new();
        let mut treasury = Treasury::new();
        treasury.collect_fee(TensionValue::from_integer(125));
        treasury.distribute_reward(TensionValue::from_integer(25));
        treasury.advance_epoch();

        commit_treasury_state(&mut state, &treasury);
        let recovered = treasury_from_trie(&state).expect("treasury trie must decode");

        assert_eq!(recovered.pending_fees, treasury.pending_fees);
        assert_eq!(
            recovered.total_fees_collected,
            treasury.total_fees_collected
        );
        assert_eq!(
            recovered.total_rewards_distributed,
            treasury.total_rewards_distributed
        );
        assert_eq!(recovered.epoch, treasury.epoch);
        assert_eq!(recovered.epoch_fees, treasury.epoch_fees);
        assert_eq!(recovered.epoch_rewards, treasury.epoch_rewards);
    }

    #[test]
    fn test_treasury_from_trie_rejects_unknown_key() {
        let mut state = ManagedWorldState::new();
        state
            .trie
            .insert(b"treasury/unknown".to_vec(), 1i128.to_le_bytes().to_vec());

        let result = treasury_from_trie(&state);
        assert!(result.is_err(), "unknown treasury key must fail closed");
    }

    // ── N-49 coverage: negative amounts + edge cases ─────────────────

    #[test]
    fn test_collect_fee_negative_clamped_to_zero() {
        let mut treasury = Treasury::new();
        treasury.collect_fee(TensionValue::from_integer(100));
        // Attempt to collect a negative fee — should be clamped to zero.
        treasury.collect_fee(TensionValue((-50) * TensionValue::SCALE));
        // Balance should not decrease.
        assert_eq!(treasury.pending_fees, TensionValue::from_integer(100));
    }

    #[test]
    fn test_distribute_reward_negative_clamped_to_zero() {
        let mut treasury = Treasury::new();
        treasury.collect_fee(TensionValue::from_integer(100));
        let distributed = treasury.distribute_reward(TensionValue((-30) * TensionValue::SCALE));
        assert_eq!(distributed, TensionValue::ZERO);
        assert_eq!(treasury.pending_fees, TensionValue::from_integer(100));
    }

    #[test]
    fn test_burn_negative_rejected() {
        let mut treasury = Treasury::new();
        treasury.collect_fee(TensionValue::from_integer(100));
        let result = treasury.burn(TensionValue((-10) * TensionValue::SCALE));
        assert!(result.is_err());
        assert_eq!(treasury.pending_fees, TensionValue::from_integer(100));
    }

    #[test]
    fn test_collect_fee_zero_amount_is_noop() {
        let mut treasury = Treasury::new();
        treasury.collect_fee(TensionValue::from_integer(50));
        treasury.collect_fee(TensionValue::ZERO);
        assert_eq!(treasury.pending_fees, TensionValue::from_integer(50));
    }

    #[test]
    fn test_burn_zero_amount_succeeds() {
        let mut treasury = Treasury::new();
        treasury.collect_fee(TensionValue::from_integer(50));
        assert!(treasury.burn(TensionValue::ZERO).is_ok());
        assert_eq!(treasury.pending_fees, TensionValue::from_integer(50));
    }

    #[test]
    fn test_distribute_zero_reward() {
        let mut treasury = Treasury::new();
        treasury.collect_fee(TensionValue::from_integer(50));
        let distributed = treasury.distribute_reward(TensionValue::ZERO);
        assert_eq!(distributed, TensionValue::ZERO);
        assert_eq!(treasury.pending_fees, TensionValue::from_integer(50));
    }
}
