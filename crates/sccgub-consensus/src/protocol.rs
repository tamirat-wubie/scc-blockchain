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
///
/// Security: votes are verified at admission (signature + validator set membership).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsensusRound {
    /// Chain identifier — binds votes to this specific chain (prevents cross-chain replay).
    pub chain_id: Hash,
    /// Validator set epoch — incremented when the validator set changes.
    /// Votes signed under a different epoch are rejected.
    pub epoch: u64,
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
    /// Authorized validator set (public keys). Votes from non-members are rejected.
    pub validator_set: HashMap<Hash, [u8; 32]>,
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
    /// Create a new consensus round with an authorized validator set.
    /// validator_set maps validator_id -> public_key for signature verification.
    /// chain_id and epoch are bound into every vote signature to prevent
    /// cross-chain replay and stale-epoch attacks.
    pub fn new(
        chain_id: Hash,
        epoch: u64,
        block_hash: Hash,
        height: u64,
        round: u32,
        validator_set: HashMap<Hash, [u8; 32]>,
        max_rounds: u32,
    ) -> Self {
        let validator_count = validator_set.len().min(u32::MAX as usize) as u32;
        if validator_count > 0 && validator_count < 4 {
            tracing::warn!(
                "Consensus round with {} validators provides no BFT fault tolerance (need >= 4)",
                validator_count
            );
        }
        // Use u64 intermediate to prevent overflow on large validator sets.
        let quorum = ((2u64 * validator_count as u64) / 3 + 1).min(u32::MAX as u64) as u32;
        Self {
            chain_id,
            epoch,
            block_hash,
            height,
            round,
            phase: ConsensusPhase::Propose,
            prevotes: HashMap::new(),
            precommits: HashMap::new(),
            validator_count,
            quorum,
            max_rounds,
            validator_set,
        }
    }

    /// Verify a vote: check membership, height/round, type, duplicate, and signature.
    fn verify_vote(
        &self,
        vote: &Vote,
        expected_type: VoteType,
        store: &HashMap<Hash, Vote>,
    ) -> Result<(), String> {
        if vote.vote_type != expected_type {
            return Err(format!("Expected {:?}", expected_type));
        }
        if vote.height != self.height || vote.round != self.round {
            return Err("Vote height/round mismatch".into());
        }
        // Validator set membership check.
        let public_key = self.validator_set.get(&vote.validator_id).ok_or_else(|| {
            format!(
                "Validator {} not in authorized set",
                hex::encode(vote.validator_id)
            )
        })?;
        // Duplicate check.
        if store.contains_key(&vote.validator_id) {
            return Err("Duplicate vote from validator".into());
        }
        // Signature verification — domain-separated with chain_id and epoch.
        if vote.signature.len() < 64 {
            return Err("Vote signature must be at least 64 bytes (Ed25519)".into());
        }
        {
            let vote_data = vote_sign_data(
                &self.chain_id,
                self.epoch,
                &vote.block_hash,
                vote.height,
                vote.round,
                vote.vote_type,
            );
            if !sccgub_crypto::signature::verify(public_key, &vote_data, &vote.signature) {
                return Err("Vote signature verification failed".into());
            }
        }
        Ok(())
    }

    /// Add a prevote. Verifies signature and validator set membership.
    pub fn add_prevote(&mut self, vote: Vote) -> Result<(), String> {
        self.verify_vote(&vote, VoteType::Prevote, &self.prevotes)?;
        self.prevotes.insert(vote.validator_id, vote);
        Ok(())
    }

    /// Add a precommit. Verifies signature and validator set membership.
    pub fn add_precommit(&mut self, vote: Vote) -> Result<(), String> {
        self.verify_vote(&vote, VoteType::Precommit, &self.precommits)?;
        self.precommits.insert(vote.validator_id, vote);
        Ok(())
    }

    /// Count prevotes for the proposed block.
    pub fn prevote_count(&self) -> u32 {
        self.prevotes
            .values()
            .filter(|v| v.block_hash == self.block_hash && v.vote_type == VoteType::Prevote)
            .count()
            .min(u32::MAX as usize) as u32
    }

    /// Count precommits for the proposed block.
    pub fn precommit_count(&self) -> u32 {
        self.precommits
            .values()
            .filter(|v| v.block_hash == self.block_hash && v.vote_type == VoteType::Precommit)
            .count()
            .min(u32::MAX as usize) as u32
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
        let total_prevotes = self.prevotes.len().min(u32::MAX as usize) as u32;
        let total_precommits = self.precommits.len().min(u32::MAX as usize) as u32;

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
                total_prevotes, self.validator_count, total_precommits, self.validator_count,
            ),
        }
    }

    /// Detect equivocation: a validator voting for two different blocks.
    /// NOTE: Within a single ConsensusRound, add_prevote/add_precommit reject
    /// duplicate validator IDs, so equivocation within one round is prevented
    /// at admission. This method detects cross-evidence equivocation — e.g.,
    /// when gossip reveals a validator signed conflicting votes in different
    /// rounds or received from external sources. In the current single-round
    /// implementation, this will always return empty. It becomes useful when
    /// multi-round or cross-node evidence is aggregated.
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

/// Compute domain-separated vote data for signing/verification.
/// Includes chain_id and epoch to prevent cross-chain replay and stale-epoch attacks.
/// All vote signers and verifiers MUST use this function for consistency.
pub fn vote_sign_data(
    chain_id: &Hash,
    epoch: u64,
    block_hash: &Hash,
    height: u64,
    round: u32,
    vote_type: VoteType,
) -> Vec<u8> {
    sccgub_crypto::canonical::canonical_bytes(&(
        chain_id,
        epoch,
        block_hash,
        height,
        round,
        vote_type as u8,
    ))
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
    use sccgub_crypto::keys::generate_keypair;

    /// Create N validator keypairs and return (validator_set, keys).
    type ValidatorSet = (
        HashMap<Hash, [u8; 32]>,
        Vec<(Hash, ed25519_dalek::SigningKey)>,
    );

    fn make_validators(n: u8) -> ValidatorSet {
        let mut set = HashMap::new();
        let mut keys = Vec::new();
        for i in 1..=n {
            let key = generate_keypair();
            let pk = *key.verifying_key().as_bytes();
            let id = [i; 32];
            set.insert(id, pk);
            keys.push((id, key));
        }
        (set, keys)
    }

    const TEST_CHAIN_ID: Hash = [0xCC; 32];
    const TEST_EPOCH: u64 = 1;

    /// Create a properly signed vote with domain separation.
    fn signed_vote(
        id: Hash,
        key: &ed25519_dalek::SigningKey,
        block: Hash,
        height: u64,
        round: u32,
        vtype: VoteType,
    ) -> Vote {
        let data = vote_sign_data(&TEST_CHAIN_ID, TEST_EPOCH, &block, height, round, vtype);
        let sig = sccgub_crypto::signature::sign(key, &data);
        Vote {
            validator_id: id,
            block_hash: block,
            height,
            round,
            vote_type: vtype,
            signature: sig,
        }
    }

    fn test_round(
        block: Hash,
        height: u64,
        round: u32,
        vs: HashMap<Hash, [u8; 32]>,
    ) -> ConsensusRound {
        ConsensusRound::new(TEST_CHAIN_ID, TEST_EPOCH, block, height, round, vs, 10)
    }

    #[test]
    fn test_quorum_calculation() {
        let (vs3, _) = make_validators(3);
        let round = ConsensusRound::new(TEST_CHAIN_ID, TEST_EPOCH, [1u8; 32], 1, 0, vs3, 10);
        assert_eq!(round.quorum, 3);

        let (vs4, _) = make_validators(4);
        let round = ConsensusRound::new(TEST_CHAIN_ID, TEST_EPOCH, [1u8; 32], 1, 0, vs4, 10);
        assert_eq!(round.quorum, 3);
    }

    #[test]
    fn test_two_round_finality() {
        let block = [1u8; 32];
        let (vs, keys) = make_validators(3);
        let mut round = test_round(block, 1, 0, vs);

        for (id, key) in &keys {
            round
                .add_prevote(signed_vote(*id, key, block, 1, 0, VoteType::Prevote))
                .unwrap();
        }
        assert!(round.has_prevote_quorum());

        for (id, key) in &keys {
            round
                .add_precommit(signed_vote(*id, key, block, 1, 0, VoteType::Precommit))
                .unwrap();
        }
        assert!(round.has_precommit_quorum());

        match round.evaluate() {
            ConsensusResult::Finalized {
                prevote_count,
                precommit_count,
                ..
            } => {
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
        let (vs, keys) = make_validators(4);
        let mut round = test_round(block, 1, 0, vs);

        // 2 for block, 2 for other_block.
        round
            .add_prevote(signed_vote(
                keys[0].0,
                &keys[0].1,
                block,
                1,
                0,
                VoteType::Prevote,
            ))
            .unwrap();
        round
            .add_prevote(signed_vote(
                keys[1].0,
                &keys[1].1,
                block,
                1,
                0,
                VoteType::Prevote,
            ))
            .unwrap();
        round
            .add_prevote(signed_vote(
                keys[2].0,
                &keys[2].1,
                other_block,
                1,
                0,
                VoteType::Prevote,
            ))
            .unwrap();
        round
            .add_prevote(signed_vote(
                keys[3].0,
                &keys[3].1,
                other_block,
                1,
                0,
                VoteType::Prevote,
            ))
            .unwrap();

        assert!(!round.has_prevote_quorum());
    }

    #[test]
    fn test_duplicate_vote_rejected() {
        let block = [1u8; 32];
        let (vs, keys) = make_validators(3);
        let mut round = test_round(block, 1, 0, vs);

        round
            .add_prevote(signed_vote(
                keys[0].0,
                &keys[0].1,
                block,
                1,
                0,
                VoteType::Prevote,
            ))
            .unwrap();
        let result = round.add_prevote(signed_vote(
            keys[0].0,
            &keys[0].1,
            block,
            1,
            0,
            VoteType::Prevote,
        ));
        assert!(result.is_err());
    }

    #[test]
    fn test_max_rounds_abort() {
        let block = [1u8; 32];
        let (vs, _) = make_validators(3);
        let mut round = ConsensusRound::new(TEST_CHAIN_ID, TEST_EPOCH, block, 1, 5, vs, 5);

        match round.evaluate() {
            ConsensusResult::Aborted { .. } => {}
            other => panic!("Expected Aborted, got {:?}", other),
        }
    }

    #[test]
    fn test_byzantine_tolerance() {
        let block = [1u8; 32];
        let bad_block = [99u8; 32];
        let (vs, keys) = make_validators(4);
        let mut round = test_round(block, 1, 0, vs);

        // 3 honest for block, 1 Byzantine for bad_block.
        for (id, key) in keys.iter().take(3) {
            round
                .add_prevote(signed_vote(*id, key, block, 1, 0, VoteType::Prevote))
                .unwrap();
        }
        round
            .add_prevote(signed_vote(
                keys[3].0,
                &keys[3].1,
                bad_block,
                1,
                0,
                VoteType::Prevote,
            ))
            .unwrap();
        assert!(round.has_prevote_quorum());

        for (id, key) in keys.iter().take(3) {
            round
                .add_precommit(signed_vote(*id, key, block, 1, 0, VoteType::Precommit))
                .unwrap();
        }
        round
            .add_precommit(signed_vote(
                keys[3].0,
                &keys[3].1,
                bad_block,
                1,
                0,
                VoteType::Precommit,
            ))
            .unwrap();

        match round.evaluate() {
            ConsensusResult::Finalized { .. } => {}
            other => panic!("Should finalize despite 1 Byzantine: {:?}", other),
        }
    }

    #[test]
    fn test_non_member_vote_rejected() {
        let block = [1u8; 32];
        let (vs, _) = make_validators(3);
        let mut round = test_round(block, 1, 0, vs);

        // Vote from validator not in the set.
        let outsider_key = generate_keypair();
        let outsider_id = [99u8; 32];
        let vote = signed_vote(outsider_id, &outsider_key, block, 1, 0, VoteType::Prevote);
        assert!(round.add_prevote(vote).is_err());
    }

    #[test]
    fn test_prevote_and_precommit_counts() {
        let block = [1u8; 32];
        let (vs, keys) = make_validators(3);
        let mut round = test_round(block, 1, 0, vs);

        assert_eq!(round.prevote_count(), 0);
        assert_eq!(round.precommit_count(), 0);

        round
            .add_prevote(signed_vote(
                keys[0].0,
                &keys[0].1,
                block,
                1,
                0,
                VoteType::Prevote,
            ))
            .unwrap();
        assert_eq!(round.prevote_count(), 1);
        assert_eq!(round.precommit_count(), 0);

        round
            .add_precommit(signed_vote(
                keys[0].0,
                &keys[0].1,
                block,
                1,
                0,
                VoteType::Precommit,
            ))
            .unwrap();
        assert_eq!(round.prevote_count(), 1);
        assert_eq!(round.precommit_count(), 1);
    }

    #[test]
    fn test_detect_equivocation_empty_when_no_conflict() {
        let block = [1u8; 32];
        let (vs, keys) = make_validators(3);
        let mut round = test_round(block, 1, 0, vs);

        for (id, key) in &keys {
            round
                .add_prevote(signed_vote(*id, key, block, 1, 0, VoteType::Prevote))
                .unwrap();
        }

        let proofs = round.detect_equivocation();
        assert!(
            proofs.is_empty(),
            "no equivocation expected with honest votes"
        );
    }

    #[test]
    fn test_detect_equivocation_finds_conflicting_prevotes() {
        let block_a = [1u8; 32];
        let block_b = [2u8; 32];
        let (vs, keys) = make_validators(3);
        let mut round = test_round(block_a, 1, 0, vs);

        // Validator 0 votes for block_a.
        round
            .add_prevote(signed_vote(
                keys[0].0,
                &keys[0].1,
                block_a,
                1,
                0,
                VoteType::Prevote,
            ))
            .unwrap();

        // Manually inject a conflicting prevote for block_b from the same validator.
        // (In production, add_prevote rejects duplicates; this simulates cross-round evidence.)
        let conflicting = signed_vote(keys[0].0, &keys[0].1, block_b, 1, 0, VoteType::Prevote);
        round.prevotes.insert([99u8; 32], conflicting);

        let proofs = round.detect_equivocation();
        assert_eq!(proofs.len(), 1);
        assert_eq!(proofs[0].validator_id, keys[0].0);
        // HashMap iteration order is non-deterministic, so check both hashes are present.
        let hashes = [proofs[0].block_hash_a, proofs[0].block_hash_b];
        assert!(hashes.contains(&block_a));
        assert!(hashes.contains(&block_b));
    }
}
