use serde::{Deserialize, Serialize};

use crate::causal::CausalGraphDelta;
use crate::governance::GovernanceSnapshot;
use crate::mfidel::MfidelAtomicSeal;
use crate::proof::CausalProof;
use crate::receipt::CausalReceipt;
use crate::tension::TensionValue;
use crate::timestamp::CausalTimestamp;
use crate::transition::SymbolicTransition;
use crate::validator_set::{EquivocationEvidence, ValidatorSetChange};
use crate::{ConstraintId, Hash, MerkleRoot, ZERO_HASH};

pub const LEGACY_BLOCK_VERSION: u32 = 1;
pub const CANONICAL_AGENT_BLOCK_VERSION: u32 = 2;
/// Patch-04 introduces v3: validator-set management, view-change, constitutional
/// ceilings, key rotation. v3 blocks carry `round_history_root` in the header.
pub const PATCH_04_BLOCK_VERSION: u32 = 3;
pub const CURRENT_BLOCK_VERSION: u32 = CANONICAL_AGENT_BLOCK_VERSION;

pub fn is_supported_block_version(version: u32) -> bool {
    matches!(
        version,
        LEGACY_BLOCK_VERSION | CANONICAL_AGENT_BLOCK_VERSION | PATCH_04_BLOCK_VERSION
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
    /// Patch-04 §16.6: commits to `BLAKE3(canonical_bytes(body.round_history))`
    /// for v3 blocks at `round > 0`. For v2 blocks and v3 blocks at `round == 0`,
    /// this is `ZERO_HASH`. Always emitted to keep canonical bincode positional;
    /// v2 chains read legacy bytes via `BlockHeader::from_canonical_bytes`.
    #[serde(default = "zero_hash_default")]
    pub round_history_root: Hash,
}

fn zero_hash_default() -> Hash {
    ZERO_HASH
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
    /// Patch-04 §15.4: `ValidatorSetChange` events admitted in this block.
    /// `None` for v2 blocks and v3 blocks carrying no set-change events.
    /// Matches the existing `genesis_consensus_params` serde discipline:
    /// `None` emits zero bytes under bincode, preserving v2 canonical encoding.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub validator_set_changes: Option<Vec<ValidatorSetChange>>,
    /// Patch-05 §22: `EquivocationEvidence` records admitted in this block.
    /// Each record pairs with a synthetic `ValidatorSetChange::Remove` in
    /// `validator_set_changes` (§22.4 INV-SLASHING-LIVENESS). `None` for
    /// v3 and earlier; same Option-discipline as other v4 fields.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub equivocation_evidence: Option<Vec<EquivocationEvidence>>,
}

impl BlockHeader {
    /// Canonical bincode bytes of this header (used for block ID hashing and
    /// persisted block storage).
    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        bincode::serialize(self).expect("BlockHeader serialization is infallible")
    }

    /// Deserialize from canonical bincode with a fallback to the v2 schema.
    ///
    /// v2-encoded headers predate the Patch-04 `round_history_root` field.
    /// The fallback decodes them with `round_history_root = ZERO_HASH`,
    /// preserving replay of v2 chains under v3 code.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, String> {
        bincode::deserialize::<Self>(bytes)
            .or_else(|_| bincode::deserialize::<LegacyBlockHeaderV2>(bytes).map(BlockHeader::from))
            .map_err(|e| format!("BlockHeader deserialize: {}", e))
    }
}

/// v0.3.0 block-header schema (pre-Patch-04). Retained as a deserialization
/// fallback so v2 chain data replays under v3 code without re-encoding.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct LegacyBlockHeaderV2 {
    chain_id: Hash,
    block_id: Hash,
    parent_id: Hash,
    height: u64,
    timestamp: CausalTimestamp,
    state_root: MerkleRoot,
    transition_root: MerkleRoot,
    receipt_root: MerkleRoot,
    causal_root: MerkleRoot,
    proof_root: MerkleRoot,
    governance_hash: Hash,
    tension_before: TensionValue,
    tension_after: TensionValue,
    mfidel_seal: MfidelAtomicSeal,
    balance_root: Hash,
    validator_id: Hash,
    version: u32,
}

impl From<LegacyBlockHeaderV2> for BlockHeader {
    fn from(v: LegacyBlockHeaderV2) -> Self {
        Self {
            chain_id: v.chain_id,
            block_id: v.block_id,
            parent_id: v.parent_id,
            height: v.height,
            timestamp: v.timestamp,
            state_root: v.state_root,
            transition_root: v.transition_root,
            receipt_root: v.receipt_root,
            causal_root: v.causal_root,
            proof_root: v.proof_root,
            governance_hash: v.governance_hash,
            tension_before: v.tension_before,
            tension_after: v.tension_after,
            mfidel_seal: v.mfidel_seal,
            balance_root: v.balance_root,
            validator_id: v.validator_id,
            version: v.version,
            round_history_root: ZERO_HASH,
        }
    }
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
                round_history_root: ZERO_HASH,
            },
            body: BlockBody {
                transitions: vec![],
                transition_count: 0,
                total_tension_delta: TensionValue::ZERO,
                constraint_satisfaction: vec![],
                genesis_consensus_params: None,
                validator_set_changes: None,
                equivocation_evidence: None,
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

    #[test]
    fn test_is_supported_block_version_v1() {
        assert!(is_supported_block_version(LEGACY_BLOCK_VERSION));
    }

    #[test]
    fn test_is_supported_block_version_v2() {
        assert!(is_supported_block_version(CANONICAL_AGENT_BLOCK_VERSION));
    }

    #[test]
    fn test_is_supported_block_version_unknown() {
        assert!(!is_supported_block_version(0));
        assert!(!is_supported_block_version(4));
        assert!(!is_supported_block_version(u32::MAX));
    }

    #[test]
    fn patch_04_is_supported_block_version_v3() {
        assert!(is_supported_block_version(PATCH_04_BLOCK_VERSION));
    }

    #[test]
    fn patch_04_block_header_canonical_roundtrip_with_round_history_root() {
        let mut b = genesis_block();
        b.header.round_history_root = [0xABu8; 32];
        let bytes = b.header.to_canonical_bytes();
        let back = BlockHeader::from_canonical_bytes(&bytes).unwrap();
        assert_eq!(back.round_history_root, [0xABu8; 32]);
    }

    #[test]
    fn patch_04_block_header_legacy_v2_bytes_decode_with_zero_round_history_root() {
        // Simulate v0.3.0 on-disk bytes: encode the legacy struct directly.
        let legacy = LegacyBlockHeaderV2 {
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
            version: 2,
        };
        let v2_bytes = bincode::serialize(&legacy).unwrap();
        let header = BlockHeader::from_canonical_bytes(&v2_bytes)
            .expect("v2 legacy bytes must decode via fallback");
        assert_eq!(header.round_history_root, ZERO_HASH);
        assert_eq!(header.version, 2);
    }
}
