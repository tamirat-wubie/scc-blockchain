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
        let gas_price = EconomicState::default().effective_fee(
            state.state.tension_field.total,
            state.state.tension_field.budget.current_budget,
        );
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
        for tx in &block.body.transitions {
            if let Err(e) = speculative.check_nonce(&tx.actor.agent_id, tx.nonce) {
                errors.push(format!("Nonce violation during replay: {}", e));
            }
        }

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
}
