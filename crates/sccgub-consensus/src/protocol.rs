use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use sccgub_types::Hash;

/// Multi-validator consensus protocol.
/// Two-round voting with ⌊2n/3⌋ + 1 supermajority quorum.
/// Byzantine fault tolerance: f < n/3 malicious validators tolerated.
///
/// Round 1 (PREVOTE): validators vote on proposed block.
/// Round 2 (PRECOMMIT): validators vote on prevote results.
/// Block is finalized when both rounds reach supermajority.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsensusRound {
    /// Block being voted on.
    pub block_hash: Hash,
    /// Block height.
    pub height: u64,
    /// Round number within this height (0-indexed, increments on timeout).
    pub round: u32,
    /// Current phase of the round.
    pub phase: ConsensusPhase,
    /// Prevotes received.
    pub prevotes: HashMap<Hash, Vote>,
    /// Precommits received.
    pub precommits: HashMap<Hash, Vote>,
    /// Total validator count (n).
    pub validator_count: u32,
    /// Quorum threshold: ⌊2n/3⌋ + 1.
    pub quorum: u32,
    /// Maximum rounds before timeout (abort block).
    pub max_rounds: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConsensusPhase {
    Propose,
    Prevote,
    Precommit,
    Commit,
    Abort,
}

/// A vote cast by a validator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vote {
    pub validator_id: Hash,
    pub block_hash: Hash,
    pub height: u64,
    pub round: u32,
    pub vote_type: VoteType,
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VoteType {
    Prevote,
    Precommit,
    /// Nil vote: validator did not receive the proposal in time.
    Nil,
}

/// Result of a consensus round.
#[derive(Debug, Clone)]
pub enum ConsensusResult {
    /// Block finalized with supermajority.
    Finalized {
        block_hash: Hash,
        prevote_count: u32,
        precommit_count: u32,
    },
    /// No supermajority reached, advance to next round.
    NextRound { reason: String },
    /// Maximum rounds exceeded, abort this height.
    Aborted { reason: String },
}

impl ConsensusRound {
    /// Create a new consensus round.
    pub fn new(block_hash: Hash, height: u64, round: u32, validator_count: u32, max_rounds: u32) -> Self {
        let quorum = (2 * validator_count) / 3 + 1;
        Self {
            block_hash,
            height,
            round,
            phase: ConsensusPhase::Propose,
            prevotes: HashMap::new(),
            precommits: HashMap::new(),
            validator_count,
            quorum,
            max_rounds,
        }
    }

    /// Add a prevote. Returns Ok if accepted, Err if duplicate or invalid.
    pub fn add_prevote(&mut self, vote: Vote) -> Result<(), String> {
        if vote.vote_type != VoteType::Prevote {
            return Err("Expected Prevote".into());
        }
        if vote.height != self.height || vote.round != self.round {
            return Err("Vote height/round mismatch".into());
        }
        if self.prevotes.contains_key(&vote.validator_id) {
            return Err("Duplicate prevote from validator".into());
        }
        self.prevotes.insert(vote.validator_id, vote);
        Ok(())
    }

    /// Add a precommit. Returns Ok if accepted.
    pub fn add_precommit(&mut self, vote: Vote) -> Result<(), String> {
        if vote.vote_type != VoteType::Precommit {
            return Err("Expected Precommit".into());
        }
        if vote.height != self.height || vote.round != self.round {
            return Err("Vote height/round mismatch".into());
        }
        if self.precommits.contains_key(&vote.validator_id) {
            return Err("Duplicate precommit from validator".into());
        }
        self.precommits.insert(vote.validator_id, vote);
        Ok(())
    }

    /// Count prevotes for the proposed block.
    pub fn prevote_count(&self) -> u32 {
        self.prevotes
            .values()
            .filter(|v| v.block_hash == self.block_hash && v.vote_type == VoteType::Prevote)
            .count() as u32
    }

    /// Count precommits for the proposed block.
    pub fn precommit_count(&self) -> u32 {
        self.precommits
            .values()
            .filter(|v| v.block_hash == self.block_hash && v.vote_type == VoteType::Precommit)
            .count() as u32
    }

    /// Check if prevote quorum is reached.
    pub fn has_prevote_quorum(&self) -> bool {
        self.prevote_count() >= self.quorum
    }

    /// Check if precommit quorum is reached.
    pub fn has_precommit_quorum(&self) -> bool {
        self.precommit_count() >= self.quorum
    }

    /// Advance the consensus round. Returns the result.
    pub fn evaluate(&mut self) -> ConsensusResult {
        // Check if both rounds have supermajority.
        if self.has_prevote_quorum() && self.has_precommit_quorum() {
            self.phase = ConsensusPhase::Commit;
            return ConsensusResult::Finalized {
                block_hash: self.block_hash,
                prevote_count: self.prevote_count(),
                precommit_count: self.precommit_count(),
            };
        }

        // Check if we've exceeded max rounds.
        if self.round >= self.max_rounds {
            self.phase = ConsensusPhase::Abort;
            return ConsensusResult::Aborted {
                reason: format!("Exceeded max rounds ({})", self.max_rounds),
            };
        }

        // If we have enough votes total but not quorum on the block, move to next round.
        let total_prevotes = self.prevotes.len() as u32;
        let total_precommits = self.precommits.len() as u32;

        if total_prevotes >= self.validator_count && !self.has_prevote_quorum() {
            return ConsensusResult::NextRound {
                reason: format!(
                    "All prevotes received but no quorum: {}/{} for block",
                    self.prevote_count(),
                    self.quorum
                ),
            };
        }

        if total_precommits >= self.validator_count && !self.has_precommit_quorum() {
            return ConsensusResult::NextRound {
                reason: format!(
                    "All precommits received but no quorum: {}/{} for block",
                    self.precommit_count(),
                    self.quorum
                ),
            };
        }

        // Still waiting for votes.
        ConsensusResult::NextRound {
            reason: format!(
                "Waiting: {}/{} prevotes, {}/{} precommits",
                total_prevotes,
                self.validator_count,
                total_precommits,
                self.validator_count,
            ),
        }
    }

    /// Detect equivocation: a validator voting for two different blocks.
    pub fn detect_equivocation(&self) -> Vec<EquivocationProof> {
        let mut proofs = Vec::new();

        // Check prevotes: same validator, different block hashes.
        let mut seen: HashMap<Hash, Hash> = HashMap::new();
        for vote in self.prevotes.values() {
            if let Some(&prev_block) = seen.get(&vote.validator_id) {
                if prev_block != vote.block_hash {
                    proofs.push(EquivocationProof {
                        validator_id: vote.validator_id,
                        height: vote.height,
                        round: vote.round,
                        vote_type: VoteType::Prevote,
                        block_hash_a: prev_block,
                        block_hash_b: vote.block_hash,
                    });
                }
            } else {
                seen.insert(vote.validator_id, vote.block_hash);
            }
        }

        proofs
    }
}

/// Proof that a validator voted for two different blocks (equivocation).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EquivocationProof {
    pub validator_id: Hash,
    pub height: u64,
    pub round: u32,
    pub vote_type: VoteType,
    pub block_hash_a: Hash,
    pub block_hash_b: Hash,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_vote(validator: u8, block: Hash, height: u64, round: u32, vtype: VoteType) -> Vote {
        Vote {
            validator_id: [validator; 32],
            block_hash: block,
            height,
            round,
            vote_type: vtype,
            signature: vec![0u8; 64],
        }
    }

    #[test]
    fn test_quorum_calculation() {
        // 3 validators: quorum = ⌊2*3/3⌋ + 1 = 3
        let round = ConsensusRound::new([1u8; 32], 1, 0, 3, 10);
        assert_eq!(round.quorum, 3);

        // 4 validators: quorum = ⌊2*4/3⌋ + 1 = 3
        let round = ConsensusRound::new([1u8; 32], 1, 0, 4, 10);
        assert_eq!(round.quorum, 3);

        // 21 validators: quorum = ⌊2*21/3⌋ + 1 = 15
        let round = ConsensusRound::new([1u8; 32], 1, 0, 21, 10);
        assert_eq!(round.quorum, 15);
    }

    #[test]
    fn test_two_round_finality() {
        let block = [1u8; 32];
        let mut round = ConsensusRound::new(block, 1, 0, 3, 10);

        // All 3 validators prevote.
        for i in 1..=3 {
            round.add_prevote(make_vote(i, block, 1, 0, VoteType::Prevote)).unwrap();
        }
        assert!(round.has_prevote_quorum());

        // All 3 validators precommit.
        for i in 1..=3 {
            round.add_precommit(make_vote(i, block, 1, 0, VoteType::Precommit)).unwrap();
        }
        assert!(round.has_precommit_quorum());

        match round.evaluate() {
            ConsensusResult::Finalized { prevote_count, precommit_count, .. } => {
                assert_eq!(prevote_count, 3);
                assert_eq!(precommit_count, 3);
            }
            other => panic!("Expected Finalized, got {:?}", other),
        }
    }

    #[test]
    fn test_no_quorum_without_supermajority() {
        let block = [1u8; 32];
        let other_block = [2u8; 32];
        let mut round = ConsensusRound::new(block, 1, 0, 4, 10);

        // 2 prevote for block, 2 for other_block. Quorum=3, neither reaches it.
        round.add_prevote(make_vote(1, block, 1, 0, VoteType::Prevote)).unwrap();
        round.add_prevote(make_vote(2, block, 1, 0, VoteType::Prevote)).unwrap();
        round.add_prevote(make_vote(3, other_block, 1, 0, VoteType::Prevote)).unwrap();
        round.add_prevote(make_vote(4, other_block, 1, 0, VoteType::Prevote)).unwrap();

        assert!(!round.has_prevote_quorum());
    }

    #[test]
    fn test_duplicate_vote_rejected() {
        let block = [1u8; 32];
        let mut round = ConsensusRound::new(block, 1, 0, 3, 10);

        round.add_prevote(make_vote(1, block, 1, 0, VoteType::Prevote)).unwrap();
        let result = round.add_prevote(make_vote(1, block, 1, 0, VoteType::Prevote));
        assert!(result.is_err());
    }

    #[test]
    fn test_max_rounds_abort() {
        let block = [1u8; 32];
        let mut round = ConsensusRound::new(block, 1, 5, 3, 5); // round=5, max=5

        match round.evaluate() {
            ConsensusResult::Aborted { .. } => {}
            other => panic!("Expected Aborted, got {:?}", other),
        }
    }

    #[test]
    fn test_byzantine_tolerance() {
        // 4 validators, 1 Byzantine (f=1, n/3=1.33, f < n/3 holds).
        let block = [1u8; 32];
        let bad_block = [99u8; 32];
        let mut round = ConsensusRound::new(block, 1, 0, 4, 10);

        // 3 honest validators prevote for block, 1 Byzantine votes for bad_block.
        round.add_prevote(make_vote(1, block, 1, 0, VoteType::Prevote)).unwrap();
        round.add_prevote(make_vote(2, block, 1, 0, VoteType::Prevote)).unwrap();
        round.add_prevote(make_vote(3, block, 1, 0, VoteType::Prevote)).unwrap();
        round.add_prevote(make_vote(4, bad_block, 1, 0, VoteType::Prevote)).unwrap();

        // Quorum = 3, we have 3 prevotes for block. Passes!
        assert!(round.has_prevote_quorum());

        // 3 honest precommit.
        round.add_precommit(make_vote(1, block, 1, 0, VoteType::Precommit)).unwrap();
        round.add_precommit(make_vote(2, block, 1, 0, VoteType::Precommit)).unwrap();
        round.add_precommit(make_vote(3, block, 1, 0, VoteType::Precommit)).unwrap();
        round.add_precommit(make_vote(4, bad_block, 1, 0, VoteType::Precommit)).unwrap();

        match round.evaluate() {
            ConsensusResult::Finalized { .. } => {} // Byzantine validator's vote didn't prevent finality.
            other => panic!("Should finalize despite 1 Byzantine: {:?}", other),
        }
    }
}
