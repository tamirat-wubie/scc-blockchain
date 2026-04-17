//! Key-rotation state management for Patch-04 v3 (§18).
//!
//! Two state entries cooperate:
//!
//! - `system/key_rotations` stores the append-only `KeyRotationRegistry`,
//!   sorted canonically by `(agent_id, rotation_height)`.
//!
//! - `system/key_index` stores the global `KeyIndex` — every public key
//!   ever bound to any agent, sorted by `(public_key, active_from)`. This
//!   index is what §18.2 rule 7 consults to reject key reuse across
//!   agents, and it is what lets `mark_superseded` flag the old key when
//!   a rotation lands.
//!
//! `apply_key_rotation` verifies both required signatures under
//! `verify_strict` (defense-in-depth: the execution layer also verifies,
//! per §18.2 rules 5 and 6), then:
//!
//! 1. Confirms the `old_public_key` is the current active key for the
//!    agent (§18.2 rule 3).
//! 2. Confirms the `new_public_key` is not already in the global key
//!    index (§18.2 rule 7).
//! 3. Appends the event to the rotation registry.
//! 4. Registers the new key and marks the old key superseded in the
//!    key index.

use sccgub_crypto::signature::verify_strict;
use sccgub_types::key_rotation::{
    KeyIndex, KeyRotation, KeyRotationRegistry, KEY_INDEX_TRIE_KEY, KEY_ROTATIONS_TRIE_KEY,
};
use sccgub_types::transition::{StateDelta, StateWrite};
use sccgub_types::validator_set::Ed25519PublicKey;
use sccgub_types::AgentId;

use crate::world::ManagedWorldState;

/// Read the append-only rotation registry, defaulting to empty when
/// `system/key_rotations` is not yet committed (pre-v3 chains).
pub fn key_rotation_registry_from_trie(
    state: &ManagedWorldState,
) -> Result<KeyRotationRegistry, String> {
    match state.get(&KEY_ROTATIONS_TRIE_KEY.to_vec()) {
        Some(bytes) => KeyRotationRegistry::from_canonical_bytes(bytes),
        None => Ok(KeyRotationRegistry::new()),
    }
}

fn commit_key_rotation_registry(state: &mut ManagedWorldState, reg: &KeyRotationRegistry) {
    state.apply_delta(&StateDelta {
        writes: vec![StateWrite {
            address: KEY_ROTATIONS_TRIE_KEY.to_vec(),
            value: reg.to_canonical_bytes(),
        }],
        deletes: vec![],
    });
}

/// Read the global key index, defaulting to empty when not yet committed.
pub fn key_index_from_trie(state: &ManagedWorldState) -> Result<KeyIndex, String> {
    match state.get(&KEY_INDEX_TRIE_KEY.to_vec()) {
        Some(bytes) => KeyIndex::from_canonical_bytes(bytes),
        None => Ok(KeyIndex::new()),
    }
}

fn commit_key_index(state: &mut ManagedWorldState, idx: &KeyIndex) {
    state.apply_delta(&StateDelta {
        writes: vec![StateWrite {
            address: KEY_INDEX_TRIE_KEY.to_vec(),
            value: idx.to_canonical_bytes(),
        }],
        deletes: vec![],
    });
}

/// Register an agent's original (registration-time) public key in the
/// global key index. Called from the agent-registration code path so the
/// first key an agent ever uses is indexed and protected against reuse.
pub fn register_original_key(
    state: &mut ManagedWorldState,
    agent_id: AgentId,
    public_key: Ed25519PublicKey,
    active_from: u64,
) -> Result<(), KeyRotationStateError> {
    let mut idx = key_index_from_trie(state).map_err(KeyRotationStateError::Storage)?;
    idx.register(public_key, agent_id, active_from)
        .map_err(|e| KeyRotationStateError::KeyIndex(e.to_string()))?;
    commit_key_index(state, &idx);
    Ok(())
}

/// Apply a validated `KeyRotation` event: verify signatures, confirm
/// admission predicates (§18.2 rules 3, 4, 7), append to the registry,
/// and update the global key index.
///
/// `original_public_key` is the key returned by the agent's registration
/// record and must be supplied by the caller (the state crate does not
/// own the agent registry). `current_active_public_key` is the key the
/// rotation is meant to replace (§18.2 rule 3 consistency).
pub fn apply_key_rotation(
    state: &mut ManagedWorldState,
    rotation: &KeyRotation,
) -> Result<(), KeyRotationStateError> {
    // §18.2 rule 4: old and new keys must differ.
    if rotation.old_public_key == rotation.new_public_key {
        return Err(KeyRotationStateError::NoOp);
    }

    // Recompute the canonical signed payload and verify both signatures
    // under verify_strict (§18.2 rules 5 and 6). This is defense-in-depth:
    // the execution layer performs the same check at admission.
    let payload = rotation.payload_bytes();
    if !verify_strict(
        &rotation.old_public_key,
        &payload,
        &rotation.signature_by_old_key,
    ) {
        return Err(KeyRotationStateError::OldKeySignatureInvalid);
    }
    if !verify_strict(
        &rotation.new_public_key,
        &payload,
        &rotation.signature_by_new_key,
    ) {
        return Err(KeyRotationStateError::NewKeySignatureInvalid);
    }

    let mut registry =
        key_rotation_registry_from_trie(state).map_err(KeyRotationStateError::Storage)?;
    let mut key_index = key_index_from_trie(state).map_err(KeyRotationStateError::Storage)?;

    // §18.2 rule 3: old_public_key must be the currently active key.
    let current_active = active_public_key_from_index_and_registry(
        &key_index,
        &registry,
        rotation.agent_id,
        rotation.rotation_height,
    )
    .ok_or(KeyRotationStateError::AgentNotRegistered)?;
    if current_active != rotation.old_public_key {
        return Err(KeyRotationStateError::OldKeyNotCurrent);
    }

    // §18.2 rule 7: new_public_key must not be in the global index
    // (would conflict with another agent's current or past key).
    if key_index.contains_key(&rotation.new_public_key) {
        return Err(KeyRotationStateError::NewKeyAlreadyIndexed);
    }

    // Append the rotation to the registry.
    registry
        .append(rotation.clone())
        .map_err(|e| KeyRotationStateError::RegistryAppend(e.to_string()))?;

    // Mark old key superseded, register new key.
    key_index
        .mark_superseded(&rotation.old_public_key, rotation.rotation_height)
        .map_err(|e| KeyRotationStateError::KeyIndex(e.to_string()))?;
    key_index
        .register(
            rotation.new_public_key,
            rotation.agent_id,
            rotation.rotation_height,
        )
        .map_err(|e| KeyRotationStateError::KeyIndex(e.to_string()))?;

    commit_key_rotation_registry(state, &registry);
    commit_key_index(state, &key_index);
    Ok(())
}

/// Resolve `active_public_key(agent_id, H)` per §18.4. Returns the
/// current rotation's `new_public_key` if any rotation has landed at or
/// before `height`; otherwise returns the agent's original registration
/// key derived from the key index.
pub fn active_public_key(
    state: &ManagedWorldState,
    agent_id: AgentId,
    height: u64,
) -> Result<Option<Ed25519PublicKey>, String> {
    let registry = key_rotation_registry_from_trie(state)?;
    let key_index = key_index_from_trie(state)?;
    Ok(active_public_key_from_index_and_registry(
        &key_index, &registry, agent_id, height,
    ))
}

/// Resolution helper that does not touch state — useful for tests and
/// for callers that already have the registry/index loaded.
fn active_public_key_from_index_and_registry(
    key_index: &KeyIndex,
    registry: &KeyRotationRegistry,
    agent_id: AgentId,
    height: u64,
) -> Option<Ed25519PublicKey> {
    if let Some(rot) = registry.active_rotation_at(agent_id, height) {
        return Some(rot.new_public_key);
    }
    // No rotation has taken effect yet: look up the agent's original
    // public key in the global index. The original key is the entry
    // with the smallest `active_from` for this agent that is not
    // superseded before `height`.
    key_index
        .entries()
        .iter()
        .filter(|e| e.agent_id == agent_id && e.active_from <= height)
        .filter(|e| match e.superseded_at {
            Some(s) => s > height,
            None => true,
        })
        .min_by_key(|e| e.active_from)
        .map(|e| e.public_key)
}

#[derive(Debug, thiserror::Error)]
pub enum KeyRotationStateError {
    #[error("rotation is a no-op (old == new)")]
    NoOp,
    #[error("signature by old key fails verify_strict")]
    OldKeySignatureInvalid,
    #[error("signature by new key fails verify_strict")]
    NewKeySignatureInvalid,
    #[error("agent not registered in key index")]
    AgentNotRegistered,
    #[error("old_public_key is not the currently active key for this agent at rotation_height")]
    OldKeyNotCurrent,
    #[error("new_public_key already present in global key index")]
    NewKeyAlreadyIndexed,
    #[error("registry append failed: {0}")]
    RegistryAppend(String),
    #[error("key index update failed: {0}")]
    KeyIndex(String),
    #[error("state storage: {0}")]
    Storage(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use sccgub_crypto::signature::sign;
    use sccgub_types::validator_set::Ed25519Signature;

    fn keypair(seed: u8) -> (SigningKey, Ed25519PublicKey) {
        let bytes = [seed; 32];
        let sk = SigningKey::from_bytes(&bytes);
        let pk = *sk.verifying_key().as_bytes();
        (sk, pk)
    }

    fn make_rotation(
        agent_id: AgentId,
        old_sk: &SigningKey,
        old_pk: Ed25519PublicKey,
        new_sk: &SigningKey,
        new_pk: Ed25519PublicKey,
        height: u64,
    ) -> KeyRotation {
        let payload = KeyRotation::canonical_rotation_bytes(&agent_id, &old_pk, &new_pk, height);
        let sig_old: Ed25519Signature = sign(old_sk, &payload);
        let sig_new: Ed25519Signature = sign(new_sk, &payload);
        KeyRotation {
            agent_id,
            old_public_key: old_pk,
            new_public_key: new_pk,
            rotation_height: height,
            signature_by_old_key: sig_old,
            signature_by_new_key: sig_new,
        }
    }

    fn seed_agent(
        state: &mut ManagedWorldState,
        agent_id: AgentId,
        public_key: Ed25519PublicKey,
    ) {
        register_original_key(state, agent_id, public_key, 0).unwrap();
    }

    #[test]
    fn patch_04_trie_keys_under_system_namespace() {
        assert!(KEY_ROTATIONS_TRIE_KEY.starts_with(b"system/"));
        assert!(KEY_INDEX_TRIE_KEY.starts_with(b"system/"));
    }

    #[test]
    fn patch_04_register_original_key_indexed() {
        let mut state = ManagedWorldState::new();
        let (_sk, pk) = keypair(1);
        register_original_key(&mut state, [1; 32], pk, 0).unwrap();
        let idx = key_index_from_trie(&state).unwrap();
        assert!(idx.contains_key(&pk));
    }

    #[test]
    fn patch_04_register_original_key_rejects_reuse() {
        let mut state = ManagedWorldState::new();
        let (_sk, pk) = keypair(1);
        register_original_key(&mut state, [1; 32], pk, 0).unwrap();
        let err = register_original_key(&mut state, [2; 32], pk, 0);
        assert!(err.is_err());
    }

    #[test]
    fn patch_04_apply_key_rotation_happy_path() {
        let mut state = ManagedWorldState::new();
        let agent: AgentId = [1; 32];
        let (old_sk, old_pk) = keypair(1);
        let (new_sk, new_pk) = keypair(2);
        seed_agent(&mut state, agent, old_pk);

        let rotation = make_rotation(agent, &old_sk, old_pk, &new_sk, new_pk, 10);
        apply_key_rotation(&mut state, &rotation).unwrap();

        // Registry now has one rotation; key index has both keys, old superseded.
        let reg = key_rotation_registry_from_trie(&state).unwrap();
        assert_eq!(reg.rotations().len(), 1);
        let idx = key_index_from_trie(&state).unwrap();
        assert!(idx.contains_key(&old_pk));
        assert!(idx.contains_key(&new_pk));
        let old_entry = idx
            .entries()
            .iter()
            .find(|e| e.public_key == old_pk)
            .unwrap();
        assert_eq!(old_entry.superseded_at, Some(10));
    }

    #[test]
    fn patch_04_active_public_key_before_rotation_is_original() {
        let mut state = ManagedWorldState::new();
        let agent: AgentId = [1; 32];
        let (_sk, pk) = keypair(1);
        seed_agent(&mut state, agent, pk);
        let active = active_public_key(&state, agent, 5).unwrap();
        assert_eq!(active, Some(pk));
    }

    #[test]
    fn patch_04_active_public_key_after_rotation_is_new() {
        let mut state = ManagedWorldState::new();
        let agent: AgentId = [1; 32];
        let (old_sk, old_pk) = keypair(1);
        let (new_sk, new_pk) = keypair(2);
        seed_agent(&mut state, agent, old_pk);
        let rotation = make_rotation(agent, &old_sk, old_pk, &new_sk, new_pk, 10);
        apply_key_rotation(&mut state, &rotation).unwrap();

        assert_eq!(active_public_key(&state, agent, 9).unwrap(), Some(old_pk));
        assert_eq!(active_public_key(&state, agent, 10).unwrap(), Some(new_pk));
        assert_eq!(active_public_key(&state, agent, 100).unwrap(), Some(new_pk));
    }

    #[test]
    fn patch_04_key_rotation_chain_a_b_c() {
        let mut state = ManagedWorldState::new();
        let agent: AgentId = [7; 32];
        let (sk_a, pk_a) = keypair(10);
        let (sk_b, pk_b) = keypair(11);
        let (sk_c, pk_c) = keypair(12);
        seed_agent(&mut state, agent, pk_a);

        apply_key_rotation(
            &mut state,
            &make_rotation(agent, &sk_a, pk_a, &sk_b, pk_b, 50),
        )
        .unwrap();
        apply_key_rotation(
            &mut state,
            &make_rotation(agent, &sk_b, pk_b, &sk_c, pk_c, 200),
        )
        .unwrap();

        assert_eq!(active_public_key(&state, agent, 49).unwrap(), Some(pk_a));
        assert_eq!(active_public_key(&state, agent, 50).unwrap(), Some(pk_b));
        assert_eq!(active_public_key(&state, agent, 199).unwrap(), Some(pk_b));
        assert_eq!(active_public_key(&state, agent, 200).unwrap(), Some(pk_c));
    }

    #[test]
    fn patch_04_double_rotation_at_same_height_rejected() {
        let mut state = ManagedWorldState::new();
        let agent: AgentId = [1; 32];
        let (sk_a, pk_a) = keypair(10);
        let (sk_b, pk_b) = keypair(11);
        let (sk_c, pk_c) = keypair(12);
        seed_agent(&mut state, agent, pk_a);

        apply_key_rotation(
            &mut state,
            &make_rotation(agent, &sk_a, pk_a, &sk_b, pk_b, 50),
        )
        .unwrap();
        // Second rotation at the same height: `old_public_key` (pk_a) is no longer current.
        let err = apply_key_rotation(
            &mut state,
            &make_rotation(agent, &sk_a, pk_a, &sk_c, pk_c, 50),
        );
        assert!(matches!(err, Err(KeyRotationStateError::OldKeyNotCurrent)));
    }

    #[test]
    fn patch_04_rotation_without_old_key_signature_rejected() {
        let mut state = ManagedWorldState::new();
        let agent: AgentId = [1; 32];
        let (_sk_a, pk_a) = keypair(10);
        let (sk_wrong, _pk_wrong) = keypair(99);
        let (sk_b, pk_b) = keypair(11);
        seed_agent(&mut state, agent, pk_a);

        // Sign with the wrong old key → verification fails.
        let mut rotation = make_rotation(agent, &sk_wrong, pk_a, &sk_b, pk_b, 10);
        // The signature was produced by sk_wrong (not pk_a's key); replace
        // signature_by_old_key with the bogus signature.
        let payload = rotation.payload_bytes();
        rotation.signature_by_old_key = sk_wrong.sign(&payload).to_bytes().to_vec();
        let err = apply_key_rotation(&mut state, &rotation);
        assert!(matches!(
            err,
            Err(KeyRotationStateError::OldKeySignatureInvalid)
        ));
    }

    #[test]
    fn patch_04_rotation_without_new_key_signature_rejected() {
        let mut state = ManagedWorldState::new();
        let agent: AgentId = [1; 32];
        let (sk_a, pk_a) = keypair(10);
        let (sk_b, pk_b) = keypair(11);
        let (sk_wrong, _) = keypair(99);
        seed_agent(&mut state, agent, pk_a);

        let mut rotation = make_rotation(agent, &sk_a, pk_a, &sk_b, pk_b, 10);
        // Replace signature_by_new_key with a signature from the wrong key.
        let payload = rotation.payload_bytes();
        rotation.signature_by_new_key = sk_wrong.sign(&payload).to_bytes().to_vec();
        let err = apply_key_rotation(&mut state, &rotation);
        assert!(matches!(
            err,
            Err(KeyRotationStateError::NewKeySignatureInvalid)
        ));
    }

    #[test]
    fn patch_04_rotation_noop_rejected() {
        let mut state = ManagedWorldState::new();
        let agent: AgentId = [1; 32];
        let (sk, pk) = keypair(1);
        seed_agent(&mut state, agent, pk);
        // old == new
        let rotation = make_rotation(agent, &sk, pk, &sk, pk, 10);
        let err = apply_key_rotation(&mut state, &rotation);
        assert!(matches!(err, Err(KeyRotationStateError::NoOp)));
    }

    #[test]
    fn patch_04_rotation_to_already_indexed_key_rejected() {
        let mut state = ManagedWorldState::new();
        let agent1: AgentId = [1; 32];
        let agent2: AgentId = [2; 32];
        let (sk_a1, pk_a1) = keypair(10);
        let (_sk_a2, pk_a2) = keypair(20);
        let (sk_attempt, _) = keypair(30);
        seed_agent(&mut state, agent1, pk_a1);
        seed_agent(&mut state, agent2, pk_a2);

        // agent1 tries to rotate to pk_a2 (already in use by agent2).
        let rotation = make_rotation(agent1, &sk_a1, pk_a1, &sk_attempt, pk_a2, 10);
        let err = apply_key_rotation(&mut state, &rotation);
        // The sk_attempt doesn't match pk_a2, so the new-key signature check
        // catches it first. We also want a test where the new-key signature
        // is valid but the key is still indexed — construct one below.
        assert!(err.is_err());
    }

    #[test]
    fn patch_04_rotation_to_existing_indexed_key_rejected_even_with_valid_sig() {
        // Build a legitimate signature for the new key, then try to rotate
        // an agent onto it. §18.2 rule 7 rejects regardless.
        let mut state = ManagedWorldState::new();
        let agent1: AgentId = [1; 32];
        let agent2: AgentId = [2; 32];
        let (sk_a1, pk_a1) = keypair(10);
        let (sk_a2, pk_a2) = keypair(20);
        seed_agent(&mut state, agent1, pk_a1);
        seed_agent(&mut state, agent2, pk_a2);

        // Agent1 tries to rotate to pk_a2 (already agent2's key). Use sk_a2
        // to produce a valid new-key signature.
        let rotation = make_rotation(agent1, &sk_a1, pk_a1, &sk_a2, pk_a2, 10);
        let err = apply_key_rotation(&mut state, &rotation);
        assert!(matches!(
            err,
            Err(KeyRotationStateError::NewKeyAlreadyIndexed)
        ));
    }

    #[test]
    fn patch_04_rotation_with_stale_old_key_rejected() {
        // After rotating A→B, attempting to rotate with old_public_key=A
        // must be rejected even though A was once active.
        let mut state = ManagedWorldState::new();
        let agent: AgentId = [1; 32];
        let (sk_a, pk_a) = keypair(10);
        let (sk_b, pk_b) = keypair(11);
        let (sk_c, pk_c) = keypair(12);
        seed_agent(&mut state, agent, pk_a);

        apply_key_rotation(
            &mut state,
            &make_rotation(agent, &sk_a, pk_a, &sk_b, pk_b, 50),
        )
        .unwrap();

        // Now try to rotate using pk_a as "current"; should be rejected.
        let stale = make_rotation(agent, &sk_a, pk_a, &sk_c, pk_c, 100);
        let err = apply_key_rotation(&mut state, &stale);
        assert!(matches!(err, Err(KeyRotationStateError::OldKeyNotCurrent)));
    }

    #[test]
    fn patch_04_active_public_key_unregistered_agent_is_none() {
        let state = ManagedWorldState::new();
        let active = active_public_key(&state, [42; 32], 5).unwrap();
        assert_eq!(active, None);
    }

    #[test]
    fn patch_04_key_rotation_registry_roundtrip_via_trie() {
        let mut state = ManagedWorldState::new();
        let agent: AgentId = [1; 32];
        let (sk_a, pk_a) = keypair(1);
        let (sk_b, pk_b) = keypair(2);
        seed_agent(&mut state, agent, pk_a);
        apply_key_rotation(
            &mut state,
            &make_rotation(agent, &sk_a, pk_a, &sk_b, pk_b, 10),
        )
        .unwrap();

        let reg = key_rotation_registry_from_trie(&state).unwrap();
        let bytes = reg.to_canonical_bytes();
        let back = KeyRotationRegistry::from_canonical_bytes(&bytes).unwrap();
        assert_eq!(reg, back);
    }

    #[test]
    fn patch_04_key_index_replay_determinism() {
        // Independently replay the same rotation sequence; both runs
        // must produce identical state roots.
        fn run() -> sccgub_types::Hash {
            let mut state = ManagedWorldState::new();
            for i in 0u8..20 {
                let agent = [i; 32];
                let (sk, pk) = keypair(i.wrapping_add(100));
                register_original_key(&mut state, agent, pk, 0).unwrap();
                // every third agent also rotates once
                if i % 3 == 0 {
                    let (new_sk, new_pk) = keypair(i.wrapping_add(200));
                    let rotation =
                        make_rotation(agent, &sk, pk, &new_sk, new_pk, 10 + i as u64);
                    apply_key_rotation(&mut state, &rotation).unwrap();
                }
            }
            state.state_root()
        }
        assert_eq!(run(), run());
    }
}
