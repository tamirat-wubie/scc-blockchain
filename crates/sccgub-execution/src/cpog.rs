use sccgub_crypto::canonical::{canonical_bytes, canonical_hash};
use sccgub_crypto::merkle::merkle_root_of_bytes;
use sccgub_state::world::ManagedWorldState;
use sccgub_types::block::Block;
use sccgub_types::mfidel::MfidelAtomicSeal;
use sccgub_types::transition::{StateDelta, StateWrite};
use sccgub_types::ZERO_HASH;

use crate::phi::phi_traversal_block;

/// Maximum recursion depth for causal proofs.
pub const MAX_PROOF_DEPTH: u32 = 256;

/// Causal Proof-of-Governance (CPoG) validation.
/// A block is valid if and only if all structural, governance, Phi, and
/// state integrity checks pass. This includes speculative replay of
/// transitions to verify the state_root commitment.
pub fn validate_cpog(
    block: &Block,
    state: &ManagedWorldState,
    parent_block_id: &[u8; 32],
) -> CpogResult {
    let mut errors = Vec::new();

    // 1. Parent linkage.
    if block.header.height == 0 {
        if block.header.parent_id != ZERO_HASH {
            errors.push("Genesis block must have ZERO_HASH parent".into());
        }
    } else if block.header.parent_id != *parent_block_id {
        errors.push(format!(
            "Parent ID mismatch: expected {}, got {}",
            hex::encode(parent_block_id),
            hex::encode(block.header.parent_id)
        ));
    }

    // 2. Mfidel seal must match deterministic assignment.
    let expected_seal = MfidelAtomicSeal::from_height(block.header.height);
    if block.header.mfidel_seal != expected_seal {
        errors.push(format!(
            "Mfidel seal mismatch at height {}",
            block.header.height
        ));
    }

    // 3. Proof recursion depth.
    if block.proof.recursion_depth > MAX_PROOF_DEPTH {
        errors.push(format!(
            "Proof recursion depth {} exceeds max {}",
            block.proof.recursion_depth, MAX_PROOF_DEPTH
        ));
    }

    // 4. Tension within budget.
    let budget = state.state.tension_field.budget.current_budget;
    if block.header.tension_after > block.header.tension_before + budget {
        errors.push("Tension exceeds budget".into());
    }

    // 5. Transition root must match body.
    let tx_bytes: Vec<&[u8]> = block
        .body
        .transitions
        .iter()
        .map(|tx| tx.tx_id.as_slice())
        .collect();
    let computed_tx_root = merkle_root_of_bytes(&tx_bytes);
    if block.header.transition_root != computed_tx_root {
        errors.push("Transition root mismatch".into());
    }

    // 6. Transition count.
    if u32::try_from(block.body.transitions.len()) != Ok(block.body.transition_count) {
        errors.push("Transition count mismatch".into());
    }

    // 7. Receipt root.
    if !block.receipts.is_empty() {
        let receipt_hashes: Vec<&[u8]> =
            block.receipts.iter().map(|r| r.tx_id.as_slice()).collect();
        let computed = merkle_root_of_bytes(&receipt_hashes);
        if block.header.receipt_root != computed {
            errors.push("Receipt root mismatch".into());
        }
    }

    // 8. Governance hash.
    let computed_gov = canonical_hash(&block.governance);
    if block.header.governance_hash != computed_gov {
        errors.push("Governance hash mismatch".into());
    }

    // 9. Causal root.
    if !block.causal_delta.new_edges.is_empty() {
        let edge_bytes: Vec<Vec<u8>> = block
            .causal_delta
            .new_edges
            .iter()
            .map(canonical_bytes)
            .collect();
        let edge_refs: Vec<&[u8]> = edge_bytes.iter().map(|b| b.as_slice()).collect();
        let computed = merkle_root_of_bytes(&edge_refs);
        if block.header.causal_root != computed {
            errors.push("Causal root mismatch".into());
        }
    }

    // 10. State root verification via speculative replay.
    // Clone the state, apply all transitions, and verify the resulting root
    // matches what the block header claims. This is the key integrity check.
    if block.header.height > 0 {
        let mut speculative = state.clone();
        for tx in &block.body.transitions {
            match &tx.payload {
                sccgub_types::transition::OperationPayload::Write { key, value } => {
                    speculative.apply_delta(&StateDelta {
                        writes: vec![StateWrite {
                            address: key.clone(),
                            value: value.clone(),
                        }],
                        deletes: vec![],
                    });
                }
                sccgub_types::transition::OperationPayload::AssetTransfer { .. } => {
                    // Asset transfers modify the balance ledger (tracked separately).
                }
                _ => {}
            }
            // Replay nonces for symmetry with chain.rs produce_block.
            let _ = speculative.check_nonce(&tx.actor.agent_id, tx.nonce);
        }
        let computed_state_root = speculative.state_root();
        if block.header.state_root != computed_state_root {
            errors.push(format!(
                "State root mismatch: header={}, computed={}",
                hex::encode(block.header.state_root),
                hex::encode(computed_state_root),
            ));
        }
    }

    // 11. Run full 13-phase Phi traversal.
    let phi_log = phi_traversal_block(block, state);
    if !phi_log.is_all_passed() {
        for phase_result in &phi_log.phases_completed {
            if !phase_result.passed {
                errors.push(format!(
                    "Phi {:?}: {}",
                    phase_result.phase, phase_result.details
                ));
            }
        }
    }

    if errors.is_empty() {
        CpogResult::Valid
    } else {
        CpogResult::Invalid { errors }
    }
}

/// Result of CPoG validation.
#[derive(Debug, Clone)]
pub enum CpogResult {
    Valid,
    Invalid { errors: Vec<String> },
}

impl CpogResult {
    pub fn is_valid(&self) -> bool {
        matches!(self, CpogResult::Valid)
    }
}
