use sccgub_state::world::ManagedWorldState;
use sccgub_types::transition::SymbolicTransition;

use crate::phi::phi_traversal_tx;
use crate::wh_check::check_transition_wh;

/// Validate a single transition before inclusion in a block.
/// Checks: WHBinding, signature, nonce replay, and per-tx Phi traversal.
pub fn validate_transition(
    tx: &SymbolicTransition,
    state: &ManagedWorldState,
) -> Result<(), Vec<String>> {
    let mut errors = Vec::new();

    // Check WHBinding completeness.
    if let Err(e) = check_transition_wh(tx) {
        errors.push(format!("WHBinding: {}", e));
    }

    // Check signature is present.
    if tx.signature.is_empty() {
        errors.push("Missing signature".into());
    }

    // Verify Ed25519 signature against the actor's public key.
    if !tx.signature.is_empty() {
        let tx_data = canonical_tx_bytes(tx);
        if !sccgub_crypto::signature::verify(&tx.actor.public_key, &tx_data, &tx.signature) {
            errors.push("Ed25519 signature verification failed".into());
        }
    }

    // Nonce must be >= 1 (nonce 0 is not valid).
    if tx.nonce == 0 {
        errors.push("Nonce must be >= 1".into());
    }

    // Check nonce for replay protection (strictly increasing).
    let last_nonce = state
        .agent_nonces
        .get(&tx.actor.agent_id)
        .copied()
        .unwrap_or(0);
    if tx.nonce <= last_nonce {
        errors.push(format!(
            "Nonce replay: {} <= last seen {}",
            tx.nonce, last_nonce
        ));
    }

    // Run per-tx Phi traversal.
    let phi_log = phi_traversal_tx(tx, state);
    if !phi_log.all_phases_passed {
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

/// Compute canonical bytes for a transaction (used for signing and verification).
/// Covers all semantically meaningful fields to prevent cross-type replay.
/// Must match what was signed at submission time.
pub fn canonical_tx_bytes(tx: &SymbolicTransition) -> Vec<u8> {
    // Canonical form includes: agent_id, intent kind, target, nonce, payload hash.
    // This prevents replaying a StateWrite signature as a GovernanceUpdate.
    let payload_tag = match &tx.payload {
        sccgub_types::transition::OperationPayload::Write { key, value } => {
            sccgub_crypto::hash::blake3_hash(
                &[key.as_slice(), value.as_slice()].concat(),
            )
        }
        sccgub_types::transition::OperationPayload::Noop => [0u8; 32],
        _ => {
            let serialized = serde_json::to_vec(&tx.payload)
                .expect("canonical_tx_bytes: payload serialization cannot fail");
            sccgub_crypto::hash::blake3_hash(&serialized)
        }
    };

    serde_json::to_vec(&(
        &tx.actor.agent_id,
        tx.intent.kind as u8,
        &tx.intent.target,
        &tx.nonce,
        &payload_tag,
    ))
    .expect("canonical_tx_bytes: serialization of primitive types cannot fail")
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
        let agent_id = blake3_hash(&pk);
        let agent = AgentIdentity {
            agent_id,
            public_key: pk,
            mfidel_seal: MfidelAtomicSeal::from_height(1),
            registration_block: 0,
            governance_level: PrecedenceLevel::Meaning,
            norm_set: HashSet::new(),
            responsibility: ResponsibilityState::default(),
        };

        let target = b"test/key".to_vec();
        let nonce = 42u128;
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

        // Build the tx first to compute canonical bytes, then sign.
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
        assert!(result.is_err(), "Tampered signature should fail");
        let errors = result.unwrap_err();
        assert!(errors.iter().any(|e| e.contains("signature")));
    }

    #[test]
    fn test_empty_signature_fails() {
        let mut tx = make_signed_tx();
        tx.signature = vec![];
        let state = ManagedWorldState::new();
        let result = validate_transition(&tx, &state);
        assert!(result.is_err());
    }

    #[test]
    fn test_nonce_replay_rejected() {
        let tx = make_signed_tx();
        let mut state = ManagedWorldState::new();
        // Set last seen nonce to 100 (higher than tx.nonce=42).
        state.agent_nonces.insert(tx.actor.agent_id, 100);
        let result = validate_transition(&tx, &state);
        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert!(errors.iter().any(|e| e.contains("Nonce replay")));
    }

    #[test]
    fn test_different_intent_kind_different_canonical() {
        let tx1 = make_signed_tx();
        let mut tx2 = tx1.clone();
        tx2.intent.kind = TransitionKind::GovernanceUpdate;
        // Canonical bytes should differ when intent kind differs.
        assert_ne!(canonical_tx_bytes(&tx1), canonical_tx_bytes(&tx2));
    }
}
