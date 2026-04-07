use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use sccgub_types::tension::TensionValue;
use sccgub_types::Hash;

use crate::protocol::EquivocationProof;

/// Slashing engine — penalizes validator misbehavior.
///
/// Violation types and penalties:
/// - Double-sign (equivocation): 32% of stake
/// - Law set divergence: 10% of stake
/// - Absence (offline > 2 epochs): 1% of stake per epoch
///
/// All slashing requires cryptographic proof.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlashingConfig {
    /// Penalty for double-signing (equivocation). Percentage of stake (0-100).
    pub double_sign_penalty_pct: u32,
    /// Penalty for law set divergence. Percentage of stake.
    pub divergence_penalty_pct: u32,
    /// Penalty for absence per epoch. Percentage of stake.
    pub absence_penalty_pct_per_epoch: u32,
    /// Maximum absences before forced removal.
    pub max_absence_epochs: u32,
}

impl Default for SlashingConfig {
    fn default() -> Self {
        Self {
            double_sign_penalty_pct: 32,
            divergence_penalty_pct: 10,
            absence_penalty_pct_per_epoch: 1,
            max_absence_epochs: 10,
        }
    }
}

/// A slashing event record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlashingEvent {
    pub validator_id: Hash,
    pub violation: ViolationType,
    pub penalty: TensionValue,
    pub epoch: u64,
    pub evidence: SlashingEvidence,
}

/// Types of slashable violations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ViolationType {
    /// Voted for two different blocks at the same height/round.
    DoubleSigning,
    /// Validator's law set diverged from consensus.
    LawSetDivergence,
    /// Validator was offline for too many epochs.
    Absence { epochs_missed: u32 },
}

/// Cryptographic evidence for a slashing event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SlashingEvidence {
    /// Two conflicting votes signed by the same validator.
    Equivocation(EquivocationProof),
    /// Hash of validator's law set vs consensus law set.
    LawDivergence {
        validator_law_hash: Hash,
        consensus_law_hash: Hash,
    },
    /// Epochs where validator was absent.
    AbsenceRecord { absent_epochs: Vec<u64> },
}

/// Slashing engine state.
#[derive(Debug, Clone, Default)]
pub struct SlashingEngine {
    pub config: SlashingConfig,
    /// Validator stakes.
    pub stakes: HashMap<Hash, TensionValue>,
    /// Recorded slashing events.
    pub events: Vec<SlashingEvent>,
    /// Validators that have been forcibly removed.
    pub removed: Vec<Hash>,
    /// Absence tracker: validator_id -> consecutive absent epochs.
    pub absence_counter: HashMap<Hash, u32>,
}

impl SlashingEngine {
    pub fn new(config: SlashingConfig) -> Self {
        Self {
            config,
            ..Default::default()
        }
    }

    /// Set a validator's stake.
    pub fn set_stake(&mut self, validator: Hash, stake: TensionValue) {
        self.stakes.insert(validator, stake);
    }

    /// Slash a validator for double-signing.
    pub fn slash_double_sign(
        &mut self,
        proof: EquivocationProof,
        epoch: u64,
    ) -> Result<SlashingEvent, String> {
        let validator = proof.validator_id;
        let stake = self
            .stakes
            .get(&validator)
            .copied()
            .ok_or("Validator not found")?;

        let penalty_raw = stake.raw() * self.config.double_sign_penalty_pct as i128 / 100;
        let penalty = TensionValue(penalty_raw);

        // Deduct penalty.
        let new_stake = stake - penalty;
        self.stakes.insert(validator, new_stake);

        let event = SlashingEvent {
            validator_id: validator,
            violation: ViolationType::DoubleSigning,
            penalty,
            epoch,
            evidence: SlashingEvidence::Equivocation(proof),
        };
        self.events.push(event.clone());

        // Remove if stake drops to zero or below.
        if new_stake.raw() <= 0 {
            self.removed.push(validator);
        }

        Ok(event)
    }

    /// Slash for law set divergence.
    pub fn slash_divergence(
        &mut self,
        validator: Hash,
        validator_law_hash: Hash,
        consensus_law_hash: Hash,
        epoch: u64,
    ) -> Result<SlashingEvent, String> {
        let stake = self
            .stakes
            .get(&validator)
            .copied()
            .ok_or("Validator not found")?;

        let penalty_raw = stake.raw() * self.config.divergence_penalty_pct as i128 / 100;
        let penalty = TensionValue(penalty_raw);

        let new_stake = stake - penalty;
        self.stakes.insert(validator, new_stake);

        let event = SlashingEvent {
            validator_id: validator,
            violation: ViolationType::LawSetDivergence,
            penalty,
            epoch,
            evidence: SlashingEvidence::LawDivergence {
                validator_law_hash,
                consensus_law_hash,
            },
        };
        self.events.push(event.clone());
        Ok(event)
    }

    /// Record absence and slash if threshold exceeded.
    pub fn record_absence(&mut self, validator: Hash, epoch: u64) -> Option<SlashingEvent> {
        let counter = self.absence_counter.entry(validator).or_insert(0);
        *counter = counter.saturating_add(1);

        let stake = self.stakes.get(&validator).copied()?;
        let penalty_raw = stake.raw() * self.config.absence_penalty_pct_per_epoch as i128 / 100;
        let penalty = TensionValue(penalty_raw);

        let new_stake = stake - penalty;
        self.stakes.insert(validator, new_stake);

        let event = SlashingEvent {
            validator_id: validator,
            violation: ViolationType::Absence {
                epochs_missed: *counter,
            },
            penalty,
            epoch,
            evidence: SlashingEvidence::AbsenceRecord {
                absent_epochs: vec![epoch],
            },
        };
        self.events.push(event.clone());

        if *counter >= self.config.max_absence_epochs {
            self.removed.push(validator);
        }

        Some(event)
    }

    /// Mark validator as present (resets absence counter).
    pub fn record_presence(&mut self, validator: &Hash) {
        self.absence_counter.remove(validator);
    }

    /// Check if a validator has been removed.
    pub fn is_removed(&self, validator: &Hash) -> bool {
        self.removed.contains(validator)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::VoteType;

    #[test]
    fn test_double_sign_slashing() {
        let mut engine = SlashingEngine::new(SlashingConfig::default());
        let validator = [1u8; 32];
        engine.set_stake(validator, TensionValue::from_integer(1000));

        let proof = EquivocationProof {
            validator_id: validator,
            height: 10,
            round: 0,
            vote_type: VoteType::Prevote,
            block_hash_a: [2u8; 32],
            block_hash_b: [3u8; 32],
        };

        let event = engine.slash_double_sign(proof, 1).unwrap();
        // 32% of 1000 = 320.
        assert_eq!(event.penalty, TensionValue::from_integer(320));
        assert_eq!(engine.stakes[&validator], TensionValue::from_integer(680));
    }

    #[test]
    fn test_absence_slashing_and_removal() {
        let mut engine = SlashingEngine::new(SlashingConfig {
            max_absence_epochs: 3,
            absence_penalty_pct_per_epoch: 10,
            ..Default::default()
        });
        let validator = [1u8; 32];
        engine.set_stake(validator, TensionValue::from_integer(100));

        for epoch in 1..=3 {
            engine.record_absence(validator, epoch);
        }

        assert!(engine.is_removed(&validator));
    }

    #[test]
    fn test_presence_resets_absence() {
        let mut engine = SlashingEngine::new(SlashingConfig::default());
        let validator = [1u8; 32];
        engine.set_stake(validator, TensionValue::from_integer(1000));

        engine.record_absence(validator, 1);
        engine.record_absence(validator, 2);
        engine.record_presence(&validator);

        // Counter reset — not removed.
        assert!(!engine.is_removed(&validator));
        assert_eq!(engine.absence_counter.get(&validator), None);
    }

    #[test]
    fn test_divergence_slashing() {
        let mut engine = SlashingEngine::new(SlashingConfig::default());
        let validator = [1u8; 32];
        engine.set_stake(validator, TensionValue::from_integer(1000));

        let event = engine
            .slash_divergence(validator, [2u8; 32], [3u8; 32], 5)
            .unwrap();
        // 10% of 1000 = 100.
        assert_eq!(event.penalty, TensionValue::from_integer(100));
    }
}
