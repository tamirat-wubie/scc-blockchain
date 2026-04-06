use sccgub_state::world::ManagedWorldState;
use sccgub_types::transition::SymbolicTransition;

use crate::phi::phi_traversal_tx;
use crate::wh_check::check_transition_wh;

/// Validate a single transition before inclusion in a block.
/// Returns Ok(()) if the transition passes per-transaction Phi phases
/// and has a valid Ed25519 signature.
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
/// This must match what was signed at submission time.
pub fn canonical_tx_bytes(tx: &SymbolicTransition) -> Vec<u8> {
    // Canonical form: (agent_id, target, nonce) serialized as JSON.
    // This is what the test transition creator signs.
    serde_json::to_vec(&(&tx.actor.agent_id, &tx.intent.target, &tx.nonce))
        .unwrap_or_default()
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

        // Sign using canonical bytes.
        let canonical = serde_json::to_vec(&(&agent_id, &target, &nonce)).unwrap();
        let tx_id = blake3_hash(&canonical);
        let signature = sign(&key, &canonical);

        SymbolicTransition {
            tx_id,
            actor: agent,
            intent: TransitionIntent {
                kind: TransitionKind::StateWrite,
                target,
                declared_purpose: "test".into(),
            },
            preconditions: vec![],
            postconditions: vec![],
            payload: OperationPayload::Write {
                key: b"test/key".to_vec(),
                value: b"value".to_vec(),
            },
            causal_chain: vec![],
            wh_binding_intent: intent,
            nonce,
            signature,
        }
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
        tx.signature[0] ^= 0xFF; // Corrupt signature.
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
}
