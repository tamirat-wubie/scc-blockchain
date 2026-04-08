use sccgub_state::world::{ManagedWorldState, MAX_STATE_ENTRY_SIZE};
use sccgub_types::receipt::{CausalReceipt, ResourceUsage, Verdict};
use sccgub_types::tension::TensionValue;
use sccgub_types::transition::{
    StateDelta, SymbolicTransition, ValidationResult, WHBindingResolved,
};
use sccgub_types::MAX_SYMBOL_ADDRESS_LEN;

use crate::gas::GasMeter;
use crate::phi::phi_traversal_tx;
use crate::wh_check::check_transition_wh;

/// Sentinel value for an unsealed receipt (post_state_root not yet committed).
/// Any receipt with this root is NOT final and must be sealed before inclusion.
pub const UNSEALED_ROOT: [u8; 32] = [0xFF; 32];

/// Seal a receipt's post_state_root after state has been applied.
/// This is the ONLY correct way to finalize an accepted receipt.
/// Returns Err if the receipt was already sealed or is a reject.
pub fn seal_receipt_post_state(
    receipt: &mut CausalReceipt,
    post_state_root: [u8; 32],
) -> Result<(), String> {
    if !receipt.verdict.is_accepted() {
        return Err("Cannot seal a rejected receipt".into());
    }
    if receipt.post_state_root != UNSEALED_ROOT {
        return Err("Receipt already sealed".into());
    }
    receipt.post_state_root = post_state_root;
    Ok(())
}

/// Validate a single transition before inclusion in a block.
/// Checks: WHBinding, signature, agent_id binding, nonce, size limits, Phi traversal.
/// Returns errors list on failure.
pub fn validate_transition(
    tx: &SymbolicTransition,
    state: &ManagedWorldState,
) -> Result<(), Vec<String>> {
    let mut errors = Vec::new();

    // 1. WHBinding completeness + cross-checks.
    if let Err(e) = check_transition_wh(tx) {
        errors.push(format!("WHBinding: {}", e));
    }

    // 1b. WHY cross-check: invoking_rule must reference an active norm.
    // Skip for genesis height (no norms yet) or if norm registry is empty
    // (single-validator bootstrap mode).
    if !state.state.governance_state.active_norms.is_empty()
        && !state
            .state
            .governance_state
            .active_norms
            .contains_key(&tx.wh_binding_intent.why.invoking_rule)
    {
        errors.push(format!(
            "WHBinding 'why.invoking_rule' ({}) is not an active norm",
            hex::encode(tx.wh_binding_intent.why.invoking_rule)
        ));
    }

    // 2. Signature must be present and correct length (Ed25519 = 64 bytes).
    if tx.signature.len() < 64 {
        errors.push(format!(
            "Signature too short: {} bytes, need >= 64",
            tx.signature.len()
        ));
    }

    // 3. Verify Ed25519 signature against actor's public key.
    if tx.signature.len() >= 64 {
        let tx_data = canonical_tx_bytes(tx);
        if !sccgub_crypto::signature::verify(&tx.actor.public_key, &tx_data, &tx.signature) {
            errors.push("Ed25519 signature verification failed".into());
        }
    }

    // 4. Verify agent_id = Hash(public_key ++ mfidel_seal) per spec.
    let expected_agent_id = sccgub_crypto::hash::blake3_hash_concat(&[
        &tx.actor.public_key,
        &sccgub_crypto::canonical::canonical_bytes(&tx.actor.mfidel_seal),
    ]);
    if tx.actor.agent_id != expected_agent_id {
        errors.push("agent_id does not match Hash(public_key ++ mfidel_seal)".into());
    }

    // 5. Nonce must be >= 1 (nonce 0 is never valid).
    if tx.nonce == 0 {
        errors.push("Nonce must be >= 1".into());
    }

    // 6. Nonce must be strictly sequential (exactly last + 1, no gaps).
    let last_nonce = state
        .agent_nonces
        .get(&tx.actor.agent_id)
        .copied()
        .unwrap_or(0);
    if tx.nonce != last_nonce + 1 {
        errors.push(format!(
            "Nonce must be sequential: expected {}, got {}",
            last_nonce + 1,
            tx.nonce
        ));
    }

    // 7. Size limits on target address and payload.
    if tx.intent.target.len() > MAX_SYMBOL_ADDRESS_LEN {
        errors.push(format!(
            "Target address {} bytes exceeds max {}",
            tx.intent.target.len(),
            MAX_SYMBOL_ADDRESS_LEN
        ));
    }
    if let sccgub_types::transition::OperationPayload::Write { key, value } = &tx.payload {
        if key.len() > MAX_STATE_ENTRY_SIZE || value.len() > MAX_STATE_ENTRY_SIZE {
            errors.push("Payload key or value exceeds 1MB size limit".into());
        }
    }

    // 8. Per-tx Phi traversal (13 phases).
    let phi_log = phi_traversal_tx(tx, state);
    if !phi_log.is_all_passed() {
        for result in &phi_log.phases_completed {
            if !result.passed {
                errors.push(format!("Phi {:?}: {}", result.phase, result.details));
            }
        }
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

/// Validate a transition with gas metering and produce a typed receipt.
/// Every transition — accepted or rejected — produces a CausalReceipt.
/// This is the function that should be used in block production for auditable execution.
pub fn validate_transition_metered(
    tx: &SymbolicTransition,
    state: &ManagedWorldState,
    gas_limit: u64,
) -> (CausalReceipt, u64) {
    let mut gas = GasMeter::new(gas_limit);
    let state_root_before = state.state_root();

    // Charge base transaction overhead.
    if let Err(e) = gas.charge_tx_base() {
        return (
            make_reject_receipt(tx, state_root_before, &format!("{}", e), &gas),
            gas.used,
        );
    }

    // Charge for payload size.
    let payload_size = sccgub_crypto::canonical::canonical_bytes(&tx.payload).len() as u64;
    if let Err(e) = gas.charge_payload(payload_size) {
        return (
            make_reject_receipt(tx, state_root_before, &format!("{}", e), &gas),
            gas.used,
        );
    }

    // Charge for signature verification.
    if let Err(e) = gas.charge_sig_verify() {
        return (
            make_reject_receipt(tx, state_root_before, &format!("{}", e), &gas),
            gas.used,
        );
    }

    // Charge for hashing (agent_id derivation).
    if let Err(e) = gas.charge_hash() {
        return (
            make_reject_receipt(tx, state_root_before, &format!("{}", e), &gas),
            gas.used,
        );
    }

    // Run the core validation.
    let validation_result = validate_transition(tx, state);

    // Charge for Phi traversal compute (13 phases).
    let _ = gas.charge_compute(13);

    match validation_result {
        Ok(()) => {
            // Receipt is created with post_state_root = UNSEALED.
            // Caller MUST call seal_receipt_post_state() after state apply.
            // This prevents a receipt from existing with a finalized state root
            // before the state is actually committed.
            let receipt = CausalReceipt {
                tx_id: tx.tx_id,
                verdict: Verdict::Accept,
                pre_state_root: state_root_before,
                post_state_root: UNSEALED_ROOT,
                read_set: vec![],
                write_set: extract_write_set(tx),
                causes: vec![],
                resource_used: ResourceUsage {
                    compute_steps: gas.used,
                    state_reads: (gas.breakdown.state_reads / crate::gas::costs::STATE_READ.max(1))
                        as u32,
                    state_writes: (gas.breakdown.state_writes
                        / crate::gas::costs::STATE_WRITE.max(1))
                        as u32,
                    proof_size_bytes: gas.breakdown.proof,
                },
                emitted_events: vec![],
                wh_binding: empty_wh_resolved(tx),
                phi_phase_reached: 13,
                tension_delta: TensionValue::ZERO,
            };
            (receipt, gas.used)
        }
        Err(errors) => {
            let reason = errors.join("; ");
            (
                make_reject_receipt(tx, state_root_before, &reason, &gas),
                gas.used,
            )
        }
    }
}

fn make_reject_receipt(
    tx: &SymbolicTransition,
    state_root: [u8; 32],
    reason: &str,
    gas: &GasMeter,
) -> CausalReceipt {
    CausalReceipt {
        tx_id: tx.tx_id,
        verdict: Verdict::Reject {
            reason: reason.to_string(),
        },
        pre_state_root: state_root,
        post_state_root: state_root, // No state change on rejection.
        read_set: vec![],
        write_set: vec![],
        causes: vec![],
        resource_used: ResourceUsage {
            compute_steps: gas.used,
            state_reads: 0,
            state_writes: 0,
            proof_size_bytes: 0,
        },
        emitted_events: vec![],
        wh_binding: empty_wh_resolved(tx),
        phi_phase_reached: 0,
        tension_delta: TensionValue::ZERO,
    }
}

fn empty_wh_resolved(tx: &SymbolicTransition) -> WHBindingResolved {
    WHBindingResolved {
        intent: tx.wh_binding_intent.clone(),
        what_actual: StateDelta::default(),
        whether: ValidationResult::Valid,
    }
}

fn extract_write_set(tx: &SymbolicTransition) -> Vec<[u8; 32]> {
    match &tx.payload {
        sccgub_types::transition::OperationPayload::Write { key, .. } => {
            vec![sccgub_crypto::hash::blake3_hash(key)]
        }
        _ => vec![],
    }
}

/// Compute canonical bytes for a transaction (signing and verification).
/// Covers ALL semantically meaningful fields to prevent any field from being
/// swapped after signing.
pub fn canonical_tx_bytes(tx: &SymbolicTransition) -> Vec<u8> {
    let payload_tag = match &tx.payload {
        sccgub_types::transition::OperationPayload::Write { key, value } => {
            sccgub_crypto::hash::blake3_hash_concat(&[key.as_slice(), value.as_slice()])
        }
        sccgub_types::transition::OperationPayload::Noop => [0u8; 32],
        _ => {
            let serialized = sccgub_crypto::canonical::canonical_bytes(&tx.payload);
            sccgub_crypto::hash::blake3_hash(&serialized)
        }
    };

    let pre_hash = sccgub_crypto::hash::blake3_hash(&sccgub_crypto::canonical::canonical_bytes(
        &tx.preconditions,
    ));
    let post_hash = sccgub_crypto::hash::blake3_hash(&sccgub_crypto::canonical::canonical_bytes(
        &tx.postconditions,
    ));
    let wh_hash = sccgub_crypto::hash::blake3_hash(&sccgub_crypto::canonical::canonical_bytes(
        &tx.wh_binding_intent,
    ));
    let causal_hash = sccgub_crypto::hash::blake3_hash(&sccgub_crypto::canonical::canonical_bytes(
        &tx.causal_chain,
    ));

    sccgub_crypto::canonical::canonical_bytes(&(
        &tx.actor.agent_id,
        tx.intent.kind as u8,
        &tx.intent.target,
        &tx.nonce,
        &payload_tag,
        &pre_hash,
        &post_hash,
        &wh_hash,
        &causal_hash,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use sccgub_crypto::hash::blake3_hash;
    use sccgub_crypto::keys::generate_keypair;
    use sccgub_crypto::signature::sign;
    use sccgub_types::agent::{AgentIdentity, ResponsibilityState};
    use sccgub_types::governance::PrecedenceLevel;
    use sccgub_types::mfidel::MfidelAtomicSeal;
    use sccgub_types::timestamp::CausalTimestamp;
    use sccgub_types::transition::*;
    use std::collections::HashSet;

    fn make_signed_tx() -> SymbolicTransition {
        let key = generate_keypair();
        let pk = *key.verifying_key().as_bytes();
        let seal = MfidelAtomicSeal::from_height(1);
        let agent_id = sccgub_crypto::hash::blake3_hash_concat(&[
            &pk,
            &sccgub_crypto::canonical::canonical_bytes(&seal),
        ]);
        let agent = AgentIdentity {
            agent_id,
            public_key: pk,
            mfidel_seal: seal,
            registration_block: 0,
            governance_level: PrecedenceLevel::Meaning,
            norm_set: HashSet::new(),
            responsibility: ResponsibilityState::default(),
        };

        let target = b"test/key".to_vec();
        let nonce = 1u128;
        let payload = OperationPayload::Write {
            key: b"test/key".to_vec(),
            value: b"value".to_vec(),
        };

        let intent = WHBindingIntent {
            who: agent_id,
            when: CausalTimestamp::genesis(),
            r#where: target.clone(),
            why: CausalJustification {
                invoking_rule: blake3_hash(b"rule"),
                precedence_level: PrecedenceLevel::Meaning,
                causal_ancestors: vec![],
                constraint_proof: vec![],
            },
            how: TransitionMechanism::DirectStateWrite,
            which: HashSet::new(),
            what_declared: "test write".into(),
        };

        let mut tx = SymbolicTransition {
            tx_id: [0u8; 32],
            actor: agent,
            intent: TransitionIntent {
                kind: TransitionKind::StateWrite,
                target,
                declared_purpose: "test".into(),
            },
            preconditions: vec![],
            postconditions: vec![],
            payload,
            causal_chain: vec![],
            wh_binding_intent: intent,
            nonce,
            signature: vec![],
        };

        let canonical = canonical_tx_bytes(&tx);
        tx.tx_id = blake3_hash(&canonical);
        tx.signature = sign(&key, &canonical);
        tx
    }

    #[test]
    fn test_valid_signature_passes() {
        let tx = make_signed_tx();
        let state = ManagedWorldState::new();
        let result = validate_transition(&tx, &state);
        assert!(result.is_ok(), "Valid tx should pass: {:?}", result);
    }

    #[test]
    fn test_tampered_signature_fails() {
        let mut tx = make_signed_tx();
        tx.signature[0] ^= 0xFF;
        let state = ManagedWorldState::new();
        let result = validate_transition(&tx, &state);
        assert!(result.is_err());
    }

    #[test]
    fn test_nonce_zero_rejected() {
        let mut tx = make_signed_tx();
        tx.nonce = 0;
        let state = ManagedWorldState::new();
        let result = validate_transition(&tx, &state);
        assert!(result.is_err());
        assert!(result.unwrap_err().iter().any(|e| e.contains("Nonce")));
    }

    #[test]
    fn test_nonce_replay_rejected() {
        let tx = make_signed_tx();
        let mut state = ManagedWorldState::new();
        state.agent_nonces.insert(tx.actor.agent_id, 100);
        let result = validate_transition(&tx, &state);
        assert!(result.is_err());
    }

    #[test]
    fn test_different_intent_kind_different_canonical() {
        let tx1 = make_signed_tx();
        let mut tx2 = tx1.clone();
        tx2.intent.kind = TransitionKind::GovernanceUpdate;
        assert_ne!(canonical_tx_bytes(&tx1), canonical_tx_bytes(&tx2));
    }

    #[test]
    fn test_different_preconditions_different_canonical() {
        let tx1 = make_signed_tx();
        let mut tx2 = tx1.clone();
        tx2.preconditions = vec![Constraint {
            id: [99u8; 32],
            expression: "x > 0".into(),
        }];
        assert_ne!(canonical_tx_bytes(&tx1), canonical_tx_bytes(&tx2));
    }
}
