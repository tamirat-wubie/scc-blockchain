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
}

impl Block {
    /// Check basic structural validity (not full CPoG — just format).
    pub fn is_structurally_valid(&self) -> bool {
        // Height 0 means genesis: parent must be ZERO_HASH.
        if self.header.height == 0 && self.header.parent_id != ZERO_HASH {
            return false;
        }
        // Mfidel seal must match deterministic assignment.
        let expected_seal = MfidelAtomicSeal::from_height(self.header.height);
        if self.header.mfidel_seal != expected_seal {
            return false;
        }
        // Body transition count must match.
        if self.body.transition_count != self.body.transitions.len() as u32 {
            return false;
        }
        // Version check.
        if self.header.version != 1 {
            return false;
        }
        true
    }
}
