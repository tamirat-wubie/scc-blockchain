//! Phase-8 (Execution) superseded-key rejection (Patch-04 §18.5).
//!
//! At phase 8, a transaction signed by a key that has been rotated away
//! is rejected with a distinct error from "signature absent" so
//! equivocation detectors can distinguish "wrong key" from "unsigned".
//!
//! The check is a pure lookup: `active_public_key(agent_id, block.height)`
//! must equal `tx.actor.public_key`. Any mismatch is a §18.5 violation.

use sccgub_state::key_rotation_state::active_public_key;
use sccgub_state::world::ManagedWorldState;
use sccgub_types::transition::SymbolicTransition;

/// Result of the per-tx phase-8 superseded-key check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SupersededKeyCheck {
    /// `tx.actor.public_key` matches the active key at this height (or
    /// the agent is not in the key index, in which case §18 does not
    /// apply — phase 8 does not reject on missing registration).
    Ok,
    /// `tx.actor.public_key` has been superseded by a later rotation.
    Superseded {
        agent_id: [u8; 32],
        stale_key: [u8; 32],
        active_key: [u8; 32],
    },
    /// State lookup failed. Surfaces as a rejection; phase-level callers
    /// treat this as a non-pass so a corrupt registry does not silently
    /// admit otherwise-stale keys.
    StorageError(String),
}

impl SupersededKeyCheck {
    pub fn is_ok(&self) -> bool {
        matches!(self, Self::Ok)
    }
}

/// Verify that `tx.actor.public_key` equals
/// `active_public_key(tx.actor.agent_id, block_height)`.
///
/// Returns `Ok` if they match, or if the agent has no entry in the key
/// index (pre-registration or non-v3 chain). The latter avoids falsely
/// rejecting v2 transactions against v3 registry lookups — v2 chains
/// never populate `system/key_index`, so the lookup returns `None`.
pub fn check_tx_superseded_key(
    tx: &SymbolicTransition,
    state: &ManagedWorldState,
    block_height: u64,
) -> SupersededKeyCheck {
    match active_public_key(state, tx.actor.agent_id, block_height) {
        Ok(None) => SupersededKeyCheck::Ok, // Not in key index; §18 does not apply.
        Ok(Some(active)) => {
            if active == tx.actor.public_key {
                SupersededKeyCheck::Ok
            } else {
                SupersededKeyCheck::Superseded {
                    agent_id: tx.actor.agent_id,
                    stale_key: tx.actor.public_key,
                    active_key: active,
                }
            }
        }
        Err(e) => SupersededKeyCheck::StorageError(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use sccgub_crypto::signature::sign;
    use sccgub_state::key_rotation_state::{apply_key_rotation, register_original_key};
    use sccgub_types::agent::{AgentIdentity, ResponsibilityState};
    use sccgub_types::governance::PrecedenceLevel;
    use sccgub_types::key_rotation::KeyRotation;
    use sccgub_types::mfidel::MfidelAtomicSeal;
    use sccgub_types::timestamp::CausalTimestamp;
    use sccgub_types::transition::{
        CausalJustification, OperationPayload, TransitionIntent, TransitionKind,
        TransitionMechanism, WHBindingIntent,
    };
    use std::collections::BTreeSet;

    fn keypair(seed: u8) -> (SigningKey, [u8; 32]) {
        let sk = SigningKey::from_bytes(&[seed; 32]);
        let pk = *sk.verifying_key().as_bytes();
        (sk, pk)
    }

    fn make_tx(agent_id: [u8; 32], public_key: [u8; 32]) -> SymbolicTransition {
        SymbolicTransition {
            tx_id: [0u8; 32],
            actor: AgentIdentity {
                agent_id,
                public_key,
                mfidel_seal: MfidelAtomicSeal::from_height(0),
                registration_block: 0,
                governance_level: PrecedenceLevel::Optimization,
                norm_set: BTreeSet::new(),
                responsibility: ResponsibilityState::default(),
            },
            intent: TransitionIntent {
                kind: TransitionKind::StateWrite,
                target: b"foo".to_vec(),
                declared_purpose: String::new(),
            },
            preconditions: vec![],
            postconditions: vec![],
            payload: OperationPayload::Noop,
            causal_chain: vec![],
            wh_binding_intent: WHBindingIntent {
                who: agent_id,
                when: CausalTimestamp::genesis(),
                r#where: b"foo".to_vec(),
                why: CausalJustification {
                    invoking_rule: [0u8; 32],
                    precedence_level: PrecedenceLevel::Optimization,
                    causal_ancestors: vec![],
                    constraint_proof: vec![],
                },
                how: TransitionMechanism::DirectStateWrite,
                which: BTreeSet::new(),
                what_declared: "test".into(),
            },
            nonce: 1,
            signature: vec![0u8; 64],
        }
    }

    fn make_rotation(
        agent_id: [u8; 32],
        old_sk: &SigningKey,
        old_pk: [u8; 32],
        new_sk: &SigningKey,
        new_pk: [u8; 32],
        height: u64,
    ) -> KeyRotation {
        let payload = KeyRotation::canonical_rotation_bytes(&agent_id, &old_pk, &new_pk, height);
        KeyRotation {
            agent_id,
            old_public_key: old_pk,
            new_public_key: new_pk,
            rotation_height: height,
            signature_by_old_key: sign(old_sk, &payload),
            signature_by_new_key: sign(new_sk, &payload),
        }
    }

    #[test]
    fn patch_04_superseded_key_rejected() {
        let mut state = ManagedWorldState::new();
        let agent = [1u8; 32];
        let (sk_a, pk_a) = keypair(10);
        let (sk_b, pk_b) = keypair(11);
        register_original_key(&mut state, agent, pk_a, 0).unwrap();

        // Rotate at height 50.
        apply_key_rotation(
            &mut state,
            &make_rotation(agent, &sk_a, pk_a, &sk_b, pk_b, 50),
        )
        .unwrap();

        // At height >= 50, signing with pk_a (the superseded key) is rejected.
        let tx = make_tx(agent, pk_a);
        let res = check_tx_superseded_key(&tx, &state, 50);
        assert!(matches!(res, SupersededKeyCheck::Superseded { .. }));
    }

    #[test]
    fn patch_04_current_key_accepted() {
        let mut state = ManagedWorldState::new();
        let agent = [1u8; 32];
        let (sk_a, pk_a) = keypair(10);
        let (sk_b, pk_b) = keypair(11);
        register_original_key(&mut state, agent, pk_a, 0).unwrap();
        apply_key_rotation(
            &mut state,
            &make_rotation(agent, &sk_a, pk_a, &sk_b, pk_b, 50),
        )
        .unwrap();

        let tx = make_tx(agent, pk_b);
        let res = check_tx_superseded_key(&tx, &state, 50);
        assert!(res.is_ok(), "expected Ok, got {:?}", res);
    }

    #[test]
    fn patch_04_pre_rotation_original_key_accepted() {
        let mut state = ManagedWorldState::new();
        let agent = [1u8; 32];
        let (sk_a, pk_a) = keypair(10);
        let (sk_b, pk_b) = keypair(11);
        register_original_key(&mut state, agent, pk_a, 0).unwrap();
        apply_key_rotation(
            &mut state,
            &make_rotation(agent, &sk_a, pk_a, &sk_b, pk_b, 50),
        )
        .unwrap();

        // At height < 50, pk_a is still the active key.
        let tx = make_tx(agent, pk_a);
        let res = check_tx_superseded_key(&tx, &state, 49);
        assert!(res.is_ok());
    }

    #[test]
    fn patch_04_unregistered_agent_is_ok() {
        // Agent has no key index entry (pre-registration or v2 chain).
        // §18 enforcement does not apply → Ok.
        let state = ManagedWorldState::new();
        let tx = make_tx([42u8; 32], [42u8; 32]);
        let res = check_tx_superseded_key(&tx, &state, 5);
        assert!(res.is_ok());
    }
}
