use std::collections::BTreeMap;

use sccgub_types::Hash;

/// Phase 4 law set synchronization across validators.
///
/// Before Phase 5 (policy synthesis), all validators must agree on the
/// canonical law set Λ̂. This module coordinates that agreement.
///
/// Protocol:
/// 1. Each validator computes Λ̂_local from its observations.
/// 2. All validators exchange law set hashes.
/// 3. Canonical Λ̂ = law set with supermajority support.
/// 4. Validators with divergent Λ̂ must adopt canonical or be slashed.
#[derive(Debug, Clone)]
pub struct LawSyncRound {
    /// Height being synchronized.
    pub height: u64,
    /// Law set hashes proposed by each validator.
    pub proposals: BTreeMap<Hash, Hash>, // validator_id -> law_set_hash
    /// Quorum threshold (⌊2n/3⌋ + 1).
    pub quorum: u32,
    /// Total validator count.
    pub validator_count: u32,
}

/// Result of law synchronization.
#[derive(Debug, Clone)]
pub enum LawSyncResult {
    /// Supermajority agrees on a canonical law set hash.
    Consensus {
        canonical_hash: Hash,
        agreeing_validators: u32,
        divergent_validators: Vec<Hash>,
    },
    /// No supermajority — cannot proceed with block production.
    NoConsensus {
        proposals: BTreeMap<Hash, u32>, // law_hash -> vote count
    },
}

impl LawSyncRound {
    pub fn new(height: u64, validator_count: u32) -> Self {
        // Use u64 intermediate to prevent overflow on large validator sets.
        let quorum = ((2u64 * validator_count as u64) / 3 + 1).min(u32::MAX as u64) as u32;
        Self {
            height,
            proposals: BTreeMap::new(),
            quorum,
            validator_count,
        }
    }

    /// Submit a validator's law set hash.
    pub fn submit(&mut self, validator_id: Hash, law_set_hash: Hash) -> Result<(), String> {
        if self.proposals.contains_key(&validator_id) {
            return Err("Validator already submitted".into());
        }
        self.proposals.insert(validator_id, law_set_hash);
        Ok(())
    }

    /// Evaluate: determine if consensus on law set is reached.
    pub fn evaluate(&self) -> LawSyncResult {
        // Count votes per law set hash.
        let mut votes: BTreeMap<Hash, u32> = BTreeMap::new();
        for law_hash in self.proposals.values() {
            *votes.entry(*law_hash).or_insert(0) += 1;
        }

        // Find the hash with supermajority.
        for (law_hash, count) in &votes {
            if *count >= self.quorum {
                // Identify divergent validators.
                let divergent: Vec<Hash> = self
                    .proposals
                    .iter()
                    .filter(|(_, hash)| *hash != law_hash)
                    .map(|(validator_id, _)| *validator_id)
                    .collect();

                return LawSyncResult::Consensus {
                    canonical_hash: *law_hash,
                    agreeing_validators: *count,
                    divergent_validators: divergent,
                };
            }
        }

        LawSyncResult::NoConsensus { proposals: votes }
    }

    /// Check if all validators have submitted.
    pub fn is_complete(&self) -> bool {
        self.proposals.len().min(u32::MAX as usize) as u32 >= self.validator_count
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_law_sync_consensus() {
        let mut round = LawSyncRound::new(10, 4);
        let canonical = [1u8; 32];

        round.submit([10u8; 32], canonical).unwrap();
        round.submit([11u8; 32], canonical).unwrap();
        round.submit([12u8; 32], canonical).unwrap();
        round.submit([13u8; 32], [99u8; 32]).unwrap(); // Divergent.

        match round.evaluate() {
            LawSyncResult::Consensus {
                canonical_hash,
                agreeing_validators,
                divergent_validators,
            } => {
                assert_eq!(canonical_hash, canonical);
                assert_eq!(agreeing_validators, 3);
                assert_eq!(divergent_validators.len(), 1);
                assert_eq!(divergent_validators[0], [13u8; 32]);
            }
            other => panic!("Expected Consensus, got {:?}", other),
        }
    }

    #[test]
    fn test_law_sync_no_consensus() {
        let mut round = LawSyncRound::new(10, 4);
        // 4 validators, all different law sets. No supermajority.
        round.submit([10u8; 32], [1u8; 32]).unwrap();
        round.submit([11u8; 32], [2u8; 32]).unwrap();
        round.submit([12u8; 32], [3u8; 32]).unwrap();
        round.submit([13u8; 32], [4u8; 32]).unwrap();

        match round.evaluate() {
            LawSyncResult::NoConsensus { proposals } => {
                assert_eq!(proposals.len(), 4);
                assert!(proposals.values().all(|&v| v == 1));
            }
            other => panic!("Expected NoConsensus, got {:?}", other),
        }
    }

    #[test]
    fn test_duplicate_submission_rejected() {
        let mut round = LawSyncRound::new(10, 3);
        round.submit([1u8; 32], [10u8; 32]).unwrap();
        assert!(round.submit([1u8; 32], [20u8; 32]).is_err());
    }

    #[test]
    fn test_is_complete() {
        let mut round = LawSyncRound::new(10, 3);
        assert!(!round.is_complete());

        round.submit([1u8; 32], [10u8; 32]).unwrap();
        assert!(!round.is_complete());

        round.submit([2u8; 32], [10u8; 32]).unwrap();
        assert!(!round.is_complete());

        round.submit([3u8; 32], [10u8; 32]).unwrap();
        assert!(round.is_complete());
    }
}
