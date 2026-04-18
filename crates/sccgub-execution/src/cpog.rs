use sccgub_crypto::canonical::{canonical_bytes, canonical_hash};
use sccgub_crypto::merkle::merkle_root_of_bytes;
use sccgub_state::apply::{apply_block_economics, apply_block_transitions, balances_from_trie};
use sccgub_state::treasury::{commit_treasury_state, default_block_reward, treasury_from_trie};
use sccgub_state::world::ManagedWorldState;
use sccgub_types::block::Block;
use sccgub_types::economics::EconomicState;
use sccgub_types::mfidel::MfidelAtomicSeal;
use sccgub_types::ZERO_HASH;

use crate::phi::phi_traversal_block;

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
    if block.proof.recursion_depth > state.consensus_params.max_proof_depth {
        errors.push(format!(
            "Proof recursion depth {} exceeds max {}",
            block.proof.recursion_depth, state.consensus_params.max_proof_depth
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

    // 7. Receipt root (empty sections must be ZERO_HASH).
    if block.receipts.is_empty() {
        if block.header.receipt_root != sccgub_types::ZERO_HASH {
            errors.push("Non-zero receipt root for empty receipts".into());
        }
    } else {
        let receipt_bytes: Vec<Vec<u8>> = block.receipts.iter().map(canonical_bytes).collect();
        let receipt_refs: Vec<&[u8]> = receipt_bytes.iter().map(|b| b.as_slice()).collect();
        let computed = merkle_root_of_bytes(&receipt_refs);
        if block.header.receipt_root != computed {
            errors.push("Receipt root mismatch".into());
        }
    }

    // 8. Governance hash.
    let computed_gov = canonical_hash(&block.governance);
    if block.header.governance_hash != computed_gov {
        errors.push("Governance hash mismatch".into());
    }

    // 9. Causal root (empty sections must be ZERO_HASH).
    if block.causal_delta.new_edges.is_empty() {
        if block.header.causal_root != sccgub_types::ZERO_HASH {
            errors.push("Non-zero causal root for empty edges".into());
        }
    } else if !block.causal_delta.new_edges.is_empty() {
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
        if block.header.tension_before != state.state.tension_field.total {
            errors.push(format!(
                "tension_before mismatch: header={}, parent_state={}",
                block.header.tension_before, state.state.tension_field.total
            ));
        }

        // Speculative replay using shared apply function (single source of truth).
        let mut speculative = state.clone();
        let mut spec_balances = match balances_from_trie(&speculative) {
            Ok(b) => b,
            Err(e) => {
                errors.push(format!("Malformed balance trie: {}", e));
                return CpogResult::Invalid { errors };
            }
        };
        let mut spec_treasury = match treasury_from_trie(&speculative) {
            Ok(t) => t,
            Err(e) => {
                errors.push(format!("Malformed treasury trie: {}", e));
                return CpogResult::Invalid { errors };
            }
        };
        // Validate nonces atomically BEFORE mutating the speculative state.
        // Any failure surfaces as a CPoG error and stops replay cleanly.
        if let Err(e) = speculative.validate_nonces(&block.body.transitions) {
            errors.push(format!("Nonce violation during replay: {}", e));
            return CpogResult::Invalid { errors };
        }

        // Patch-05 §20: v4 blocks use the median-over-window fee oracle.
        // v1/v2/v3 continue to use the single-block `effective_fee`
        // (frozen per PROTOCOL.md §9).
        let econ = EconomicState::default();
        let tension_budget = state.state.tension_field.budget.current_budget;
        let gas_price = if block.header.version >= sccgub_types::block::PATCH_05_BLOCK_VERSION {
            // v4: pull the last W tensions from state and median them.
            match sccgub_state::tension_history::tension_history_from_trie(state) {
                Ok(history) => {
                    let w = state.consensus_params.median_tension_window as usize;
                    let window = sccgub_state::tension_history::window(&history, w);
                    econ.effective_fee_median(&window, tension_budget, &state.consensus_params)
                }
                Err(e) => {
                    errors.push(format!(
                        "tension_history unreadable for v4 fee oracle: {}",
                        e
                    ));
                    return CpogResult::Invalid { errors };
                }
            }
        } else {
            // Legacy path (v1/v2/v3): unchanged PROTOCOL.md §9 formula.
            econ.effective_fee(state.state.tension_field.total, tension_budget)
        };
        if let Err(e) = apply_block_economics(
            &mut speculative,
            &mut spec_balances,
            &mut spec_treasury,
            &block.body.transitions,
            &block.receipts,
            block.header.version,
            &block.header.validator_id,
            gas_price,
            default_block_reward(),
        ) {
            errors.push(format!("Economics replay failed: {}", e));
            return CpogResult::Invalid { errors };
        }
        apply_block_transitions(
            &mut speculative,
            &mut spec_balances,
            &block.body.transitions,
        );

        if block.header.height.is_multiple_of(100) {
            spec_treasury.advance_epoch();
            commit_treasury_state(&mut speculative, &spec_treasury);
        }

        let computed_state_root = speculative.state_root();
        if block.header.state_root != computed_state_root {
            errors.push(format!(
                "State root mismatch: header={}, computed={}",
                hex::encode(block.header.state_root),
                hex::encode(computed_state_root),
            ));
        }

        // 10b. Balance root verification.
        let computed_balance_root = spec_balances.balance_root();
        if block.header.balance_root != computed_balance_root {
            errors.push(format!(
                "Balance root mismatch: header={}, computed={}",
                hex::encode(block.header.balance_root),
                hex::encode(computed_balance_root),
            ));
        }
    }

    // 12. Patch-04 §15.5 capture-prevention: if the block carries
    //     ValidatorSetChange events, the ACTIVE set used for quorum
    //     verification must be the one derived from genesis +
    //     already-committed changes at this height — NEVER a set that
    //     includes the post-change projection. This duplicates the
    //     §15.5 admission check at the block-envelope level to close the
    //     capture-prevention invariant across both the Feedback-phase
    //     check and the top-level CPoG gate.
    if let Some(changes) = block.body.validator_set_changes.as_deref() {
        if !changes.is_empty() {
            match sccgub_state::validator_set_state::validator_set_from_trie(state) {
                Ok(Some(current_set)) => {
                    // Patch-05 §24: confirmation_depth now read from
                    // ConsensusParams. Only proposer-sourced changes are
                    // §15.5-validated here; evidence-sourced Removes
                    // (empty quorum_signatures) flow through phase 12
                    // via evidence_admission.
                    let proposer_sourced: Vec<_> = changes
                        .iter()
                        .filter(|c| !c.quorum_signatures.is_empty())
                        .cloned()
                        .collect();
                    let result = crate::validator_set::validate_all_validator_set_changes(
                        &proposer_sourced,
                        &current_set,
                        block.header.height,
                        state.consensus_params.confirmation_depth,
                    );
                    if let crate::validator_set::ValidatorSetChangeValidation::Invalid(rej) = result
                    {
                        errors.push(format!(
                            "CPoG #12 (validator set capture-prevention): {}",
                            rej
                        ));
                    }
                }
                Ok(None) => {
                    errors.push(
                        "CPoG #12: block carries ValidatorSetChange events but \
                         system/validator_set is not initialized"
                            .into(),
                    );
                }
                Err(e) => {
                    errors.push(format!(
                        "CPoG #12: validator set unreadable during check: {}",
                        e
                    ));
                }
            }
        }
    }

    // 13. Run full 13-phase Phi traversal.
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

#[cfg(test)]
mod tests {
    use super::*;
    use sccgub_types::block::{Block, BlockBody, BlockHeader};
    use sccgub_types::causal::CausalGraphDelta;
    use sccgub_types::governance::{FinalityMode, GovernanceSnapshot};
    use sccgub_types::proof::{CausalProof, PhiTraversalLog};
    use sccgub_types::tension::TensionValue;
    use sccgub_types::timestamp::CausalTimestamp;

    fn genesis_block(chain_id: [u8; 32]) -> Block {
        let gov = GovernanceSnapshot {
            state_hash: ZERO_HASH,
            active_norm_count: 0,
            emergency_mode: false,
            finality_mode: FinalityMode::Deterministic,
            governance_limits: sccgub_types::governance::GovernanceLimitsSnapshot::default(),
            finality_config: sccgub_types::governance::FinalityConfigSnapshot::default(),
        };
        Block {
            header: BlockHeader {
                chain_id,
                block_id: ZERO_HASH,
                parent_id: ZERO_HASH,
                height: 0,
                timestamp: CausalTimestamp::genesis(),
                state_root: ZERO_HASH,
                transition_root: ZERO_HASH,
                receipt_root: ZERO_HASH,
                causal_root: ZERO_HASH,
                proof_root: ZERO_HASH,
                governance_hash: canonical_hash(&gov),
                tension_before: TensionValue::ZERO,
                tension_after: TensionValue::ZERO,
                mfidel_seal: MfidelAtomicSeal::from_height(0),
                balance_root: ZERO_HASH,
                validator_id: [1u8; 32],
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
    fn test_valid_genesis_passes_cpog() {
        let state = ManagedWorldState::new();
        let block = genesis_block([1u8; 32]);
        let result = validate_cpog(&block, &state, &ZERO_HASH);
        assert!(
            result.is_valid(),
            "Valid genesis must pass CPoG: {:?}",
            result
        );
    }

    #[test]
    fn test_genesis_with_wrong_parent_fails() {
        let state = ManagedWorldState::new();
        let mut block = genesis_block([1u8; 32]);
        block.header.parent_id = [0xFFu8; 32]; // Not ZERO_HASH.
        let result = validate_cpog(&block, &state, &ZERO_HASH);
        assert!(!result.is_valid());
    }

    #[test]
    fn test_wrong_mfidel_seal_fails() {
        let state = ManagedWorldState::new();
        let mut block = genesis_block([1u8; 32]);
        block.header.mfidel_seal = MfidelAtomicSeal::from_height(999); // Wrong.
        let result = validate_cpog(&block, &state, &ZERO_HASH);
        assert!(!result.is_valid());
    }

    #[test]
    fn test_excessive_proof_depth_fails() {
        let state = ManagedWorldState::new();
        let mut block = genesis_block([1u8; 32]);
        block.proof.recursion_depth = state.consensus_params.max_proof_depth + 1;
        let result = validate_cpog(&block, &state, &ZERO_HASH);
        assert!(!result.is_valid());
    }

    #[test]
    fn test_transition_count_mismatch_fails() {
        let state = ManagedWorldState::new();
        let mut block = genesis_block([1u8; 32]);
        block.body.transition_count = 5; // Claims 5 but has 0.
        let result = validate_cpog(&block, &state, &ZERO_HASH);
        assert!(!result.is_valid());
    }

    #[test]
    fn test_wrong_governance_hash_fails() {
        let state = ManagedWorldState::new();
        let mut block = genesis_block([1u8; 32]);
        block.header.governance_hash = [0xABu8; 32]; // Tampered.
        let result = validate_cpog(&block, &state, &ZERO_HASH);
        assert!(!result.is_valid());
    }

    #[test]
    fn test_non_zero_receipt_root_for_empty_receipts_fails() {
        let state = ManagedWorldState::new();
        let mut block = genesis_block([1u8; 32]);
        block.header.receipt_root = [0xFFu8; 32]; // Should be ZERO for empty.
        let result = validate_cpog(&block, &state, &ZERO_HASH);
        assert!(!result.is_valid());
    }

    #[test]
    fn test_non_zero_causal_root_for_empty_edges_fails() {
        let state = ManagedWorldState::new();
        let mut block = genesis_block([1u8; 32]);
        block.header.causal_root = [0xFFu8; 32]; // Should be ZERO for empty.
        let result = validate_cpog(&block, &state, &ZERO_HASH);
        assert!(!result.is_valid());
    }

    // ── N-48 coverage: height>0 and tension paths ────────────────────

    #[test]
    fn test_height1_parent_id_mismatch_fails() {
        let state = ManagedWorldState::new();
        let mut block = genesis_block([1u8; 32]);
        block.header.height = 1;
        block.header.parent_id = [0xAAu8; 32]; // Wrong parent
        block.header.mfidel_seal = MfidelAtomicSeal::from_height(1);
        block.proof.block_height = 1;
        let expected_parent = [0xBBu8; 32]; // Different from block's claim
        let result = validate_cpog(&block, &state, &expected_parent);
        assert!(!result.is_valid());
        match result {
            CpogResult::Invalid { ref errors } => {
                assert!(
                    errors.iter().any(|e| e.contains("Parent ID mismatch")),
                    "Expected parent mismatch error, got: {:?}",
                    errors
                );
            }
            _ => panic!("Expected Invalid"),
        }
    }

    #[test]
    fn test_height1_tension_before_mismatch_fails() {
        let state = ManagedWorldState::new();
        let mut block = genesis_block([1u8; 32]);
        block.header.height = 1;
        block.header.parent_id = [0xAAu8; 32];
        block.header.mfidel_seal = MfidelAtomicSeal::from_height(1);
        block.proof.block_height = 1;
        // State has total tension = ZERO, but block claims tension_before = 999.
        block.header.tension_before = TensionValue::from_integer(999);
        let result = validate_cpog(&block, &state, &[0xAAu8; 32]);
        assert!(!result.is_valid());
        match result {
            CpogResult::Invalid { ref errors } => {
                assert!(
                    errors.iter().any(|e| e.contains("tension_before mismatch")),
                    "Expected tension_before error, got: {:?}",
                    errors
                );
            }
            _ => panic!("Expected Invalid"),
        }
    }

    #[test]
    fn test_tension_exceeds_budget_fails() {
        let state = ManagedWorldState::new();
        let mut block = genesis_block([1u8; 32]);
        // tension_after > tension_before + budget
        block.header.tension_after = TensionValue::from_integer(999_999_999);
        let result = validate_cpog(&block, &state, &ZERO_HASH);
        assert!(!result.is_valid());
        match result {
            CpogResult::Invalid { ref errors } => {
                assert!(
                    errors.iter().any(|e| e.contains("Tension exceeds budget")),
                    "Expected tension budget error, got: {:?}",
                    errors
                );
            }
            _ => panic!("Expected Invalid"),
        }
    }
}
