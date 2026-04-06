use sccgub_state::world::{ManagedWorldState, MAX_STATE_ENTRY_SIZE};
use sccgub_types::transition::SymbolicTransition;
use sccgub_types::MAX_SYMBOL_ADDRESS_LEN;

use crate::phi::phi_traversal_tx;
use crate::wh_check::check_transition_wh;

/// Validate a single transition before inclusion in a block.
/// Checks: WHBinding, signature, agent_id binding, nonce, size limits, Phi traversal.
pub fn validate_transition(
    tx: &SymbolicTransition,
    state: &ManagedWorldState,
) -> Result<(), Vec<String>> {
    let mut errors = Vec::new();

    // 1. WHBinding completeness + cross-checks.
    if let Err(e) = check_transition_wh(tx) {
        errors.push(format!("WHBinding: {}", e));
    }

    // 2. Signature must be present.
    if tx.signature.is_empty() {
        errors.push("Missing signature".into());
    }

    // 3. Verify Ed25519 signature against actor's public key.
    if !tx.signature.is_empty() {
        let tx_data = canonical_tx_bytes(tx);
        if !sccgub_crypto::signature::verify(&tx.actor.public_key, &tx_data, &tx.signature) {
            errors.push("Ed25519 signature verification failed".into());
        }
    }

    // 4. Verify agent_id = Hash(public_key ++ mfidel_seal) per spec.
    let expected_agent_id = sccgub_crypto::hash::blake3_hash_concat(&[
        &tx.actor.public_key,
        &serde_json::to_vec(&tx.actor.mfidel_seal).expect("mfidel seal serialization"),
    ]);
    if tx.actor.agent_id != expected_agent_id {
        errors.push("agent_id does not match Hash(public_key ++ mfidel_seal)".into());
    }

    // 5. Nonce must be >= 1 (nonce 0 is never valid).
    if tx.nonce == 0 {
        errors.push("Nonce must be >= 1".into());
    }

    // 6. Nonce replay protection (strictly increasing).
    let last_nonce = state
        .agent_nonces
        .get(&tx.actor.agent_id)
        .copied()
        .unwrap_or(0);
    if tx.nonce <= last_nonce {
        errors.push(format!("Nonce replay: {} <= last {}", tx.nonce, last_nonce));
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
            let serialized = serde_json::to_vec(&tx.payload)
                .expect("canonical_tx_bytes: payload serialization cannot fail");
            sccgub_crypto::hash::blake3_hash(&serialized)
        }
    };

    let pre_hash = sccgub_crypto::hash::blake3_hash(
        &serde_json::to_vec(&tx.preconditions).unwrap_or_default(),
    );
    let post_hash = sccgub_crypto::hash::blake3_hash(
        &serde_json::to_vec(&tx.postconditions).unwrap_or_default(),
    );
    let wh_hash = sccgub_crypto::hash::blake3_hash(
        &serde_json::to_vec(&tx.wh_binding_intent).unwrap_or_default(),
    );
    let causal_hash = sccgub_crypto::hash::blake3_hash(
        &serde_json::to_vec(&tx.causal_chain).unwrap_or_default(),
    );

    serde_json::to_vec(&(
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
    .expect("canonical_tx_bytes: serialization cannot fail")
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
            &serde_json::to_vec(&seal).unwrap(),
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
