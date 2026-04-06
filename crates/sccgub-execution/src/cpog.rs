use sccgub_state::world::ManagedWorldState;
use sccgub_types::block::Block;
use sccgub_types::mfidel::MfidelAtomicSeal;
use sccgub_types::ZERO_HASH;

use crate::phi::phi_traversal_block;
use crate::wh_check::check_transition_wh;

/// Maximum recursion depth for causal proofs.
pub const MAX_PROOF_DEPTH: u32 = 256;

/// Causal Proof-of-Governance (CPoG) validation.
/// A block is valid if and only if:
/// 1. Every transition carries valid causal proof under current governance.
/// 2. All WHBindings are complete.
/// 3. Governance authority is valid.
/// 4. Precedence order is respected.
/// 5. Parent linkage is correct.
/// 6. State root matches.
/// 7. Recursion depth within bounds.
/// 8. All 13 Φ phases pass.
pub fn validate_cpog(
    block: &Block,
    state: &ManagedWorldState,
    parent_block_id: &[u8; 32],
) -> CpogResult {
    let mut errors = Vec::new();

    // INV-1: Parent linkage.
    if block.header.height == 0 {
        if block.header.parent_id != ZERO_HASH {
            errors.push("Genesis block must have ZERO_HASH parent".into());
        }
    } else if block.header.parent_id != *parent_block_id {
        errors.push(format!(
            "Parent ID mismatch: expected {:?}, got {:?}",
            hex::encode(parent_block_id),
            hex::encode(block.header.parent_id)
        ));
    }

    // INV-6: Mfidel seal must match deterministic assignment.
    let expected_seal = MfidelAtomicSeal::from_height(block.header.height);
    if block.header.mfidel_seal != expected_seal {
        errors.push(format!(
            "Mfidel seal mismatch at height {}: expected [{},{}], got [{},{}]",
            block.header.height,
            expected_seal.row,
            expected_seal.column,
            block.header.mfidel_seal.row,
            block.header.mfidel_seal.column
        ));
    }

    // INV-7: All transitions must have complete WHBinding.
    for tx in &block.body.transitions {
        if let Err(e) = check_transition_wh(tx) {
            errors.push(format!("WHBinding incomplete for tx {}: {}", hex::encode(tx.tx_id), e));
        }
    }

    // Check proof recursion depth.
    if block.proof.recursion_depth > MAX_PROOF_DEPTH {
        errors.push(format!(
            "Proof recursion depth {} exceeds max {}",
            block.proof.recursion_depth, MAX_PROOF_DEPTH
        ));
    }

    // INV-5: Tension within budget.
    let tension_delta = block.header.tension_after - block.header.tension_before;
    if tension_delta > state.state.tension_field.budget.current_budget {
        errors.push("Tension delta exceeds budget".into());
    }

    // Run full 13-phase Φ traversal (INV-1: every block passes Φ).
    let phi_log = phi_traversal_block(block, state);
    if !phi_log.all_phases_passed {
        for phase_result in &phi_log.phases_completed {
            if !phase_result.passed {
                errors.push(format!(
                    "Φ phase {:?} failed: {}",
                    phase_result.phase, phase_result.details
                ));
            }
        }
    }

    // Body count consistency.
    if block.body.transition_count != block.body.transitions.len() as u32 {
        errors.push("Transition count mismatch in block body".into());
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
