use crate::gas::{GasMeter, GasPricing};
use crate::phi::{is_per_tx_phase, phi_check_single_tx};
use crate::wh_check::check_transition_wh;
use sccgub_state::world::ManagedWorldState;
use sccgub_types::receipt::{CausalReceipt, ResourceUsage, Verdict};
use sccgub_types::tension::TensionValue;
use sccgub_types::transition::{
    StateDelta, SymbolicTransition, ValidationResult, WHBindingResolved,
};

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

/// Lightweight mempool admission check — cheap, structural only.
///
/// This is the ONLY validation that runs at mempool drain time. It checks:
/// - Signature length (malformed input defense)
/// - Nonce sequence (replay defense)
/// - Target/payload size (memory exhaustion defense)
/// - WHBinding structural completeness (non-zero who, non-empty where/what)
///
/// It does NOT run: Ed25519 verification, agent_id binding, WHBinding cross-checks,
/// Phi traversal, SCCE constraint propagation, ontology check, payload consistency.
/// Those all run in `validate_transition_metered` inside the gas loop, where every
/// rejection produces a receipt (closing N-3-mempool).
pub fn admit_check(tx: &SymbolicTransition, state: &ManagedWorldState) -> Result<(), String> {
    // Nonce must be >= 1 and sequential against committed state.
    if tx.nonce == 0 {
        return Err("Nonce must be >= 1".into());
    }
    let last_nonce = state
        .agent_nonces
        .get(&tx.actor.agent_id)
        .copied()
        .unwrap_or(0);
    let expected_nonce = last_nonce.checked_add(1).ok_or_else(|| {
        format!(
            "Nonce overflow: last nonce {} has no valid successor",
            last_nonce
        )
    })?;
    if tx.nonce != expected_nonce {
        return Err(format!(
            "Nonce sequence: expected {}, got {}",
            expected_nonce, tx.nonce
        ));
    }

    admit_check_structural(tx, state)
}

/// Structural admission checks WITHOUT nonce validation.
///
/// Use this when the caller already tracks nonces locally (e.g. `drain_validated`
/// which maintains a local nonce map across a batch of transactions from the
/// same agent). Calling `admit_check` in that case would reject sequential
/// nonces (2, 3, ...) because committed state still shows the pre-batch value.
pub fn admit_check_structural(
    tx: &SymbolicTransition,
    state: &ManagedWorldState,
) -> Result<(), String> {
    // 1. Signature length (cheap, defends against malformed input).
    if tx.signature.len() < 64 {
        return Err(format!(
            "Signature too short: {} bytes, need >= 64",
            tx.signature.len()
        ));
    }

    // 2. Size limits.
    let max_symbol_address_len = state.consensus_params.max_symbol_address_len as usize;
    let max_state_entry_size = state.consensus_params.max_state_entry_size as usize;
    if tx.intent.target.len() > max_symbol_address_len {
        return Err(format!(
            "Target address {} bytes exceeds max {}",
            tx.intent.target.len(),
            max_symbol_address_len
        ));
    }
    // Per-variant size checks. Using match guards so the outer `match` is the
    // single source of control flow (satisfies clippy::collapsible_match).
    match &tx.payload {
        sccgub_types::transition::OperationPayload::Write { key, value }
            if key.len() > max_state_entry_size || value.len() > max_state_entry_size =>
        {
            return Err("Payload key or value exceeds 1MB size limit".into());
        }
        sccgub_types::transition::OperationPayload::DeployContract { code, .. }
            if code.len() > max_state_entry_size =>
        {
            return Err(format!(
                "Contract code {} bytes exceeds 1MB limit",
                code.len()
            ));
        }
        sccgub_types::transition::OperationPayload::InvokeContract { args, .. }
            if args.len() > max_state_entry_size =>
        {
            return Err(format!(
                "Contract args {} bytes exceeds 1MB limit",
                args.len()
            ));
        }
        _ => {} // Noop, AssetTransfer, RegisterAgent, ProposeNorm — all bounded by fixed fields;
                // and the size-checked variants above only hit this arm when their guard fails (size OK).
    }

    // 3. WHBinding structural completeness (cheap checks only, no cross-checks).
    if tx.wh_binding_intent.who == sccgub_types::ZERO_HASH {
        return Err("WHBinding: 'who' is zero".into());
    }
    if tx.wh_binding_intent.r#where.is_empty() {
        return Err("WHBinding: 'where' is empty".into());
    }
    if tx.wh_binding_intent.what_declared.is_empty() {
        return Err("WHBinding: 'what_declared' is empty".into());
    }

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
    let expected_nonce = match last_nonce.checked_add(1) {
        Some(n) => n,
        None => {
            errors.push(format!(
                "Nonce overflow: last nonce {} has no valid successor",
                last_nonce
            ));
            return Err(errors);
        }
    };
    if tx.nonce != expected_nonce {
        errors.push(format!(
            "Nonce must be sequential: expected {}, got {}",
            expected_nonce, tx.nonce
        ));
    }

    // 7. Size limits on target address and payload.
    let max_symbol_address_len = state.consensus_params.max_symbol_address_len as usize;
    let max_state_entry_size = state.consensus_params.max_state_entry_size as usize;
    if tx.intent.target.len() > max_symbol_address_len {
        errors.push(format!(
            "Target address {} bytes exceeds max {}",
            tx.intent.target.len(),
            max_symbol_address_len
        ));
    }
    if let sccgub_types::transition::OperationPayload::AssetTransfer { from, .. } = &tx.payload {
        if *from != tx.actor.agent_id && *from != tx.actor.public_key {
            errors.push(format!(
                "AssetTransfer source {} is not authorized for actor {} / signer {}",
                hex::encode(from),
                hex::encode(tx.actor.agent_id),
                hex::encode(tx.actor.public_key)
            ));
        }
    }
    if let sccgub_types::transition::OperationPayload::Write { key, value } = &tx.payload {
        if key.len() > max_state_entry_size || value.len() > max_state_entry_size {
            errors.push("Payload key or value exceeds 1MB size limit".into());
        }
    }

    // 8. Per-tx Phi phases — calls phi_check_single_tx directly.
    // No wrapper function, no intermediary. The shared checker is the
    // single source of truth for per-tx semantics.
    for phase in sccgub_types::proof::PhiPhase::ALL {
        if is_per_tx_phase(phase) {
            let result = phi_check_single_tx(phase, tx, state);
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
    let mut gas = GasMeter::with_pricing(gas_limit, GasPricing::from(&state.consensus_params));
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
    if let Err(e) = gas.charge_compute(13) {
        return (
            make_reject_receipt(tx, state_root_before, &format!("{}", e), &gas),
            gas.used,
        );
    }

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
                    state_reads: (gas.breakdown.state_reads / gas.pricing.state_read.max(1))
                        .min(u32::MAX as u64) as u32,
                    state_writes: (gas.breakdown.state_writes / gas.pricing.state_write.max(1))
                        .min(u32::MAX as u64) as u32,
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
    use sccgub_types::consensus_params::ConsensusParams;
    use sccgub_types::governance::PrecedenceLevel;
    use sccgub_types::mfidel::MfidelAtomicSeal;
    use sccgub_types::timestamp::CausalTimestamp;
    use sccgub_types::transition::*;
    use std::collections::BTreeSet;

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
            norm_set: BTreeSet::new(),
            responsibility: ResponsibilityState::default(),
        };

        let target = b"data/test/key".to_vec();
        let nonce = 1u128;
        let payload = OperationPayload::Write {
            key: b"data/test/key".to_vec(),
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
            which: BTreeSet::new(),
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
    fn test_validate_transition_respects_consensus_size_limits() {
        let mut tx = make_signed_tx();
        tx.intent.target = b"data/too-long".to_vec();
        if let OperationPayload::Write { key, .. } = &mut tx.payload {
            *key = tx.intent.target.clone();
        }

        let state = ManagedWorldState::with_consensus_params(ConsensusParams {
            max_symbol_address_len: 4,
            ..ConsensusParams::default()
        });
        let result = validate_transition(&tx, &state);

        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .iter()
                .any(|e| e.contains("Target address")),
            "validation must use consensus-bound address limits"
        );
    }

    #[test]
    fn test_validate_transition_metered_uses_consensus_gas_pricing() {
        let tx = make_signed_tx();
        let state = ManagedWorldState::with_consensus_params(ConsensusParams {
            gas_tx_base: 7,
            gas_payload_byte: 3,
            gas_sig_verify: 11,
            gas_hash_op: 13,
            gas_compute_step: 2,
            ..ConsensusParams::default()
        });

        let payload_size = sccgub_crypto::canonical::canonical_bytes(&tx.payload).len() as u64;
        let (receipt, gas_used) = validate_transition_metered(&tx, &state, 10_000);
        let expected = 7 + payload_size * 3 + 11 + 13 + 13 * 2;

        assert!(receipt.verdict.is_accepted());
        assert_eq!(gas_used, expected);
        assert_eq!(receipt.resource_used.compute_steps, expected);
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

    #[test]
    fn test_asset_transfer_from_actor_public_key_is_authorized() {
        let key = generate_keypair();
        let pk = *key.verifying_key().as_bytes();
        let seal = MfidelAtomicSeal::from_height(1);
        let agent_id = sccgub_crypto::hash::blake3_hash_concat(&[
            &pk,
            &sccgub_crypto::canonical::canonical_bytes(&seal),
        ]);
        let target = sccgub_types::namespace::balance_key(&pk);
        let mut tx = SymbolicTransition {
            tx_id: [0u8; 32],
            actor: AgentIdentity {
                agent_id,
                public_key: pk,
                mfidel_seal: seal,
                registration_block: 0,
                governance_level: PrecedenceLevel::Meaning,
                norm_set: BTreeSet::new(),
                responsibility: ResponsibilityState::default(),
            },
            intent: TransitionIntent {
                kind: TransitionKind::AssetTransfer,
                target: target.clone(),
                declared_purpose: "compat transfer".into(),
            },
            preconditions: vec![],
            postconditions: vec![],
            payload: OperationPayload::AssetTransfer {
                from: pk,
                to: [9u8; 32],
                amount: TensionValue::from_integer(1).raw(),
            },
            causal_chain: vec![],
            wh_binding_intent: WHBindingIntent {
                who: agent_id,
                when: CausalTimestamp::genesis(),
                r#where: target,
                why: CausalJustification {
                    invoking_rule: blake3_hash(b"rule"),
                    precedence_level: PrecedenceLevel::Meaning,
                    causal_ancestors: vec![],
                    constraint_proof: vec![],
                },
                how: TransitionMechanism::DirectStateWrite,
                which: BTreeSet::new(),
                what_declared: "compat transfer".into(),
            },
            nonce: 1,
            signature: vec![],
        };
        let canonical = canonical_tx_bytes(&tx);
        tx.tx_id = blake3_hash(&canonical);
        tx.signature = sign(&key, &canonical);

        let state = ManagedWorldState::new();
        let result = validate_transition(&tx, &state);
        assert!(
            result.is_ok(),
            "actor must be allowed to spend from its signer compatibility account: {:?}",
            result
        );
    }

    #[test]
    fn test_asset_transfer_from_unrelated_account_rejected() {
        let key = generate_keypair();
        let pk = *key.verifying_key().as_bytes();
        let seal = MfidelAtomicSeal::from_height(1);
        let agent_id = sccgub_crypto::hash::blake3_hash_concat(&[
            &pk,
            &sccgub_crypto::canonical::canonical_bytes(&seal),
        ]);
        let unauthorized_from = [7u8; 32];
        let target = sccgub_types::namespace::balance_key(&unauthorized_from);
        let mut tx = SymbolicTransition {
            tx_id: [0u8; 32],
            actor: AgentIdentity {
                agent_id,
                public_key: pk,
                mfidel_seal: seal,
                registration_block: 0,
                governance_level: PrecedenceLevel::Meaning,
                norm_set: BTreeSet::new(),
                responsibility: ResponsibilityState::default(),
            },
            intent: TransitionIntent {
                kind: TransitionKind::AssetTransfer,
                target: target.clone(),
                declared_purpose: "unauthorized transfer".into(),
            },
            preconditions: vec![],
            postconditions: vec![],
            payload: OperationPayload::AssetTransfer {
                from: unauthorized_from,
                to: [9u8; 32],
                amount: TensionValue::from_integer(1).raw(),
            },
            causal_chain: vec![],
            wh_binding_intent: WHBindingIntent {
                who: agent_id,
                when: CausalTimestamp::genesis(),
                r#where: target,
                why: CausalJustification {
                    invoking_rule: blake3_hash(b"rule"),
                    precedence_level: PrecedenceLevel::Meaning,
                    causal_ancestors: vec![],
                    constraint_proof: vec![],
                },
                how: TransitionMechanism::DirectStateWrite,
                which: BTreeSet::new(),
                what_declared: "unauthorized transfer".into(),
            },
            nonce: 1,
            signature: vec![],
        };
        let canonical = canonical_tx_bytes(&tx);
        tx.tx_id = blake3_hash(&canonical);
        tx.signature = sign(&key, &canonical);

        let state = ManagedWorldState::new();
        let result = validate_transition(&tx, &state);
        assert!(result.is_err(), "unrelated source account must be rejected");
        assert!(
            result
                .unwrap_err()
                .iter()
                .any(|e| e.contains("AssetTransfer source")),
            "rejection must mention the unauthorized transfer source"
        );
    }

    // --- admit_check tests ---

    #[test]
    fn test_admit_check_valid_tx_passes() {
        let tx = make_signed_tx();
        let state = ManagedWorldState::new();
        assert!(admit_check(&tx, &state).is_ok());
    }

    #[test]
    fn test_admit_check_short_signature_rejected() {
        let mut tx = make_signed_tx();
        tx.signature = vec![0u8; 32]; // Too short.
        let state = ManagedWorldState::new();
        let err = admit_check(&tx, &state).unwrap_err();
        assert!(err.contains("Signature too short"));
    }

    #[test]
    fn test_admit_check_nonce_zero_rejected() {
        let mut tx = make_signed_tx();
        tx.nonce = 0;
        let state = ManagedWorldState::new();
        let err = admit_check(&tx, &state).unwrap_err();
        assert!(err.contains("Nonce"));
    }

    #[test]
    fn test_admit_check_nonce_replay_rejected() {
        let tx = make_signed_tx();
        let mut state = ManagedWorldState::new();
        state.agent_nonces.insert(tx.actor.agent_id, 100);
        let err = admit_check(&tx, &state).unwrap_err();
        assert!(err.contains("Nonce sequence"));
    }

    #[test]
    fn test_admit_check_zero_who_rejected() {
        let mut tx = make_signed_tx();
        tx.wh_binding_intent.who = sccgub_types::ZERO_HASH;
        let state = ManagedWorldState::new();
        let err = admit_check(&tx, &state).unwrap_err();
        assert!(err.contains("who"));
    }

    #[test]
    fn test_admit_check_empty_where_rejected() {
        let mut tx = make_signed_tx();
        tx.wh_binding_intent.r#where = vec![];
        let state = ManagedWorldState::new();
        let err = admit_check(&tx, &state).unwrap_err();
        assert!(err.contains("where"));
    }

    #[test]
    fn test_admit_check_empty_what_rejected() {
        let mut tx = make_signed_tx();
        tx.wh_binding_intent.what_declared = String::new();
        let state = ManagedWorldState::new();
        let err = admit_check(&tx, &state).unwrap_err();
        assert!(err.contains("what_declared"));
    }

    // --- seal_receipt_post_state tests ---

    #[test]
    fn test_seal_receipt_post_state_accepted() {
        let mut receipt = CausalReceipt {
            tx_id: [0u8; 32],
            verdict: Verdict::Accept,
            pre_state_root: [1u8; 32],
            post_state_root: UNSEALED_ROOT,
            read_set: vec![],
            write_set: vec![],
            causes: vec![],
            resource_used: ResourceUsage {
                compute_steps: 0,
                state_reads: 0,
                state_writes: 0,
                proof_size_bytes: 0,
            },
            emitted_events: vec![],
            wh_binding: WHBindingResolved {
                intent: WHBindingIntent {
                    who: [1u8; 32],
                    when: CausalTimestamp::genesis(),
                    r#where: b"test".to_vec(),
                    why: CausalJustification {
                        invoking_rule: [0u8; 32],
                        precedence_level: PrecedenceLevel::Meaning,
                        causal_ancestors: vec![],
                        constraint_proof: vec![],
                    },
                    how: TransitionMechanism::DirectStateWrite,
                    which: BTreeSet::new(),
                    what_declared: "test".into(),
                },
                what_actual: StateDelta::default(),
                whether: ValidationResult::Valid,
            },
            phi_phase_reached: 13,
            tension_delta: TensionValue::ZERO,
        };
        let new_root = [42u8; 32];
        assert!(seal_receipt_post_state(&mut receipt, new_root).is_ok());
        assert_eq!(receipt.post_state_root, new_root);
    }

    #[test]
    fn test_seal_receipt_reject_fails() {
        let mut receipt = CausalReceipt {
            tx_id: [0u8; 32],
            verdict: Verdict::Reject {
                reason: "bad".into(),
            },
            pre_state_root: [1u8; 32],
            post_state_root: UNSEALED_ROOT,
            read_set: vec![],
            write_set: vec![],
            causes: vec![],
            resource_used: ResourceUsage::default(),
            emitted_events: vec![],
            wh_binding: WHBindingResolved {
                intent: WHBindingIntent {
                    who: [1u8; 32],
                    when: CausalTimestamp::genesis(),
                    r#where: b"test".to_vec(),
                    why: CausalJustification {
                        invoking_rule: [0u8; 32],
                        precedence_level: PrecedenceLevel::Meaning,
                        causal_ancestors: vec![],
                        constraint_proof: vec![],
                    },
                    how: TransitionMechanism::DirectStateWrite,
                    which: BTreeSet::new(),
                    what_declared: "test".into(),
                },
                what_actual: StateDelta::default(),
                whether: ValidationResult::Valid,
            },
            phi_phase_reached: 0,
            tension_delta: TensionValue::ZERO,
        };
        let err = seal_receipt_post_state(&mut receipt, [42u8; 32]).unwrap_err();
        assert!(err.contains("rejected"));
    }

    #[test]
    fn test_seal_receipt_already_sealed_fails() {
        let mut receipt = CausalReceipt {
            tx_id: [0u8; 32],
            verdict: Verdict::Accept,
            pre_state_root: [1u8; 32],
            post_state_root: [99u8; 32], // Already sealed.
            read_set: vec![],
            write_set: vec![],
            causes: vec![],
            resource_used: ResourceUsage::default(),
            emitted_events: vec![],
            wh_binding: WHBindingResolved {
                intent: WHBindingIntent {
                    who: [1u8; 32],
                    when: CausalTimestamp::genesis(),
                    r#where: b"test".to_vec(),
                    why: CausalJustification {
                        invoking_rule: [0u8; 32],
                        precedence_level: PrecedenceLevel::Meaning,
                        causal_ancestors: vec![],
                        constraint_proof: vec![],
                    },
                    how: TransitionMechanism::DirectStateWrite,
                    which: BTreeSet::new(),
                    what_declared: "test".into(),
                },
                what_actual: StateDelta::default(),
                whether: ValidationResult::Valid,
            },
            phi_phase_reached: 13,
            tension_delta: TensionValue::ZERO,
        };
        let err = seal_receipt_post_state(&mut receipt, [42u8; 32]).unwrap_err();
        assert!(err.contains("already sealed"));
    }

    // --- admit_check_structural tests (nonce-free path) ---

    #[test]
    fn test_admit_check_structural_short_sig_rejected() {
        let mut tx = make_signed_tx();
        tx.signature = vec![0u8; 10]; // Too short.
        let state = ManagedWorldState::new();
        let err = admit_check_structural(&tx, &state).unwrap_err();
        assert!(err.contains("Signature too short"));
    }

    #[test]
    fn test_admit_check_structural_oversized_target_rejected() {
        let mut tx = make_signed_tx();
        tx.intent.target = vec![0u8; 2048]; // Over default max_symbol_address_len.
        let state = ManagedWorldState::with_consensus_params(
            sccgub_types::consensus_params::ConsensusParams {
                max_symbol_address_len: 512,
                ..sccgub_types::consensus_params::ConsensusParams::default()
            },
        );
        let err = admit_check_structural(&tx, &state).unwrap_err();
        assert!(err.contains("Target address"));
    }

    #[test]
    fn test_admit_check_structural_valid_passes() {
        let tx = make_signed_tx();
        let state = ManagedWorldState::new();
        // admit_check_structural skips nonce, so it should pass.
        assert!(admit_check_structural(&tx, &state).is_ok());
    }

    #[test]
    fn test_admit_check_does_not_run_ed25519() {
        // A tampered signature should PASS admit_check (it only checks length).
        // Ed25519 verification runs in validate_transition, not admit_check.
        let mut tx = make_signed_tx();
        tx.signature[0] ^= 0xFF; // Tamper.
        let state = ManagedWorldState::new();
        assert!(
            admit_check(&tx, &state).is_ok(),
            "admit_check should not verify Ed25519 — that's the gas loop's job"
        );
    }

    // ── N-48 coverage: nonce overflow + invoking rule ────────────────

    #[test]
    fn test_validate_transition_nonce_overflow_fails() {
        let tx = make_signed_tx();
        let mut state = ManagedWorldState::new();
        // Set the agent's last nonce to u128::MAX so checked_add(1) returns None.
        state.agent_nonces.insert(tx.actor.agent_id, u128::MAX);
        let result = validate_transition(&tx, &state);
        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert!(
            errors.iter().any(|e| e.contains("Nonce overflow")),
            "Expected nonce overflow error, got: {:?}",
            errors
        );
    }

    #[test]
    fn test_validate_transition_unknown_invoking_rule_rejected() {
        // Populate active_norms so the check fires.
        let tx = make_signed_tx();
        let mut state = ManagedWorldState::new();
        // Insert one norm so the registry is non-empty.
        let norm_id = [42u8; 32];
        state.state.governance_state.active_norms.insert(
            norm_id,
            sccgub_types::governance::Norm {
                id: norm_id,
                name: "test norm".into(),
                description: "test".into(),
                precedence: sccgub_types::governance::PrecedenceLevel::Meaning,
                population_share: sccgub_types::tension::TensionValue::ZERO,
                fitness: sccgub_types::tension::TensionValue::ZERO,
                enforcement_cost: sccgub_types::tension::TensionValue::ZERO,
                active: true,
                created_at_height: 0,
            },
        );
        // tx.wh_binding_intent.why.invoking_rule is [2u8;32] which is NOT norm_id [42u8;32].
        let result = validate_transition(&tx, &state);
        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert!(
            errors.iter().any(|e| e.contains("not an active norm")),
            "Expected invoking_rule error, got: {:?}",
            errors
        );
    }
}
