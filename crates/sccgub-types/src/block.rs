use serde::{Deserialize, Serialize};

use crate::causal::CausalGraphDelta;
use crate::governance::GovernanceSnapshot;
use crate::mfidel::MfidelAtomicSeal;
use crate::proof::CausalProof;
use crate::receipt::CausalReceipt;
use crate::tension::TensionValue;
use crate::timestamp::CausalTimestamp;
use crate::transition::SymbolicTransition;
use crate::{ConstraintId, Hash, MerkleRoot, ZERO_HASH};

pub const LEGACY_BLOCK_VERSION: u32 = 1;
pub const CANONICAL_AGENT_BLOCK_VERSION: u32 = 2;
pub const CURRENT_BLOCK_VERSION: u32 = CANONICAL_AGENT_BLOCK_VERSION;

pub fn is_supported_block_version(version: u32) -> bool {
    matches!(
        version,
        LEGACY_BLOCK_VERSION | CANONICAL_AGENT_BLOCK_VERSION
    )
}

/// A block is a governed symbolic state transition carrying its own causal proof.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Block {
    pub header: BlockHeader,
    pub body: BlockBody,
    pub receipts: Vec<CausalReceipt>,
    pub causal_delta: CausalGraphDelta,
    pub proof: CausalProof,
    pub governance: GovernanceSnapshot,
}

/// Block header containing all roots and metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockHeader {
    /// Hash of the chain (genesis parameter).
    pub chain_id: Hash,
    /// Hash of this block.
    pub block_id: Hash,
    /// Hash of the parent block.
    pub parent_id: Hash,
    /// Block height (0 = genesis).
    pub height: u64,
    /// Causal timestamp.
    pub timestamp: CausalTimestamp,
    /// Merkle root of the world state after applying this block.
    pub state_root: MerkleRoot,
    /// Merkle root of transitions in the body.
    pub transition_root: MerkleRoot,
    /// Merkle root of receipts.
    pub receipt_root: MerkleRoot,
    /// Merkle root of the causal graph delta.
    pub causal_root: MerkleRoot,
    /// Merkle root of the proof.
    pub proof_root: MerkleRoot,
    /// Hash of the governance snapshot.
    pub governance_hash: Hash,
    /// Tension before applying this block.
    pub tension_before: TensionValue,
    /// Tension after applying this block.
    pub tension_after: TensionValue,
    /// Mfidel atomic seal (deterministic from height).
    pub mfidel_seal: MfidelAtomicSeal,
    /// Hash of the balance ledger state (enables light-client balance proofs).
    pub balance_root: Hash,
    /// Node identity of the validator/proposer.
    pub validator_id: Hash,
    /// Block format version.
    pub version: u32,
}

/// Block body containing the transitions.
/// Per v2.1 FIX B-13: explicit BlockBody definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockBody {
    pub transitions: Vec<SymbolicTransition>,
    pub transition_count: u32,
    pub total_tension_delta: TensionValue,
    pub constraint_satisfaction: Vec<(ConstraintId, bool)>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub genesis_consensus_params: Option<Vec<u8>>,
}

impl Block {
    /// Check basic structural validity (not full CPoG — just format).
    pub fn is_structurally_valid(&self) -> bool {
        // Height 0 means genesis: parent must be ZERO_HASH.
        if self.header.height == 0 && self.header.parent_id != ZERO_HASH {
            return false;
        }
        // Non-genesis blocks must have non-zero parent.
        if self.header.height > 0 && self.header.parent_id == ZERO_HASH {
            return false;
        }
        // Mfidel seal must match deterministic assignment.
        let expected_seal = MfidelAtomicSeal::from_height(self.header.height);
        if self.header.mfidel_seal != expected_seal {
            return false;
        }
        // Body transition count must match actual transitions.
        if u32::try_from(self.body.transitions.len()) != Ok(self.body.transition_count) {
            return false;
        }
        // Only genesis may carry embedded consensus parameters.
        if self.header.height > 0 && self.body.genesis_consensus_params.is_some() {
            return false;
        }
        // Receipt count must match transition count (one receipt per transition).
        // Genesis blocks may have zero receipts with zero transitions.
        if !self.receipts.is_empty() && self.receipts.len() != self.body.transitions.len() {
            return false;
        }
        // Version check.
        if !is_supported_block_version(self.header.version) {
            return false;
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::governance::FinalityMode;
    use crate::proof::PhiTraversalLog;

    fn genesis_block() -> Block {
        let gov = GovernanceSnapshot {
            state_hash: ZERO_HASH,
            active_norm_count: 0,
            emergency_mode: false,
            finality_mode: FinalityMode::Deterministic,
            governance_limits: crate::governance::GovernanceLimitsSnapshot::default(),
            finality_config: crate::governance::FinalityConfigSnapshot::default(),
        };
        Block {
            header: BlockHeader {
                chain_id: [1u8; 32],
                block_id: [2u8; 32],
                parent_id: ZERO_HASH,
                height: 0,
                timestamp: CausalTimestamp::genesis(),
                state_root: ZERO_HASH,
                transition_root: ZERO_HASH,
                receipt_root: ZERO_HASH,
                causal_root: ZERO_HASH,
                proof_root: ZERO_HASH,
                governance_hash: ZERO_HASH,
                tension_before: TensionValue::ZERO,
                tension_after: TensionValue::ZERO,
                mfidel_seal: MfidelAtomicSeal::from_height(0),
                balance_root: ZERO_HASH,
                validator_id: [3u8; 32],
                version: 1,
            },
            body: BlockBody {
                transitions: vec![],
                transition_count: 0,
                total_tension_delta: TensionValue::ZERO,
                constraint_satisfaction: vec![],
                genesis_consensus_params: None,
            },
            receipts: vec![],
            causal_delta: CausalGraphDelta::default(),
            proof: CausalProof {
                block_height: 0,
                transitions_proven: vec![],
                phi_traversal_log: PhiTraversalLog::default(),
                governance_snapshot_hash: ZERO_HASH,
                tension_before: TensionValue::ZERO,
                tension_after: TensionValue::ZERO,
                constraint_results: vec![],
                recursion_depth: 0,
                validator_signature: vec![],
                causal_hash: ZERO_HASH,
            },
            governance: gov,
        }
    }

    #[test]
    fn test_valid_genesis_is_structurally_valid() {
        assert!(genesis_block().is_structurally_valid());
    }

    #[test]
    fn test_v2_genesis_is_structurally_valid() {
        let mut b = genesis_block();
        b.header.version = CURRENT_BLOCK_VERSION;
        assert!(b.is_structurally_valid());
    }

    #[test]
    fn test_genesis_with_wrong_parent_invalid() {
        let mut b = genesis_block();
        b.header.parent_id = [0xFFu8; 32];
        assert!(!b.is_structurally_valid());
    }

    #[test]
    fn test_non_genesis_with_zero_parent_invalid() {
        let mut b = genesis_block();
        b.header.height = 5;
        b.header.mfidel_seal = MfidelAtomicSeal::from_height(5);
        b.header.parent_id = ZERO_HASH;
        assert!(!b.is_structurally_valid());
    }

    #[test]
    fn test_wrong_mfidel_seal_invalid() {
        let mut b = genesis_block();
        b.header.mfidel_seal = MfidelAtomicSeal::from_height(999);
        assert!(!b.is_structurally_valid());
    }

    #[test]
    fn test_transition_count_mismatch_invalid() {
        let mut b = genesis_block();
        b.body.transition_count = 5;
        assert!(!b.is_structurally_valid());
    }

    #[test]
    fn test_wrong_version_invalid() {
        let mut b = genesis_block();
        b.header.version = 0;
        assert!(!b.is_structurally_valid());
    }

    #[test]
    fn test_non_genesis_with_embedded_genesis_params_invalid() {
        let mut b = genesis_block();
        b.header.height = 1;
        b.header.parent_id = [9u8; 32];
        b.header.mfidel_seal = MfidelAtomicSeal::from_height(1);
        b.body.genesis_consensus_params = Some(vec![1, 2, 3]);
        assert!(!b.is_structurally_valid());
    }
}
