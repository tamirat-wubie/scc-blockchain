//! Identity-preserving key rotation (Patch-04 §18).
//!
//! §3 binds `agent_id` to the original public key at registration. If the
//! original key is compromised, the attacker gains permanent control of the
//! agent_id with no on-chain remediation. §18 introduces a signed
//! `KeyRotation` event that replaces the active signing key while preserving
//! `agent_id`.
//!
//! For validators (§18.6), key rotation is additionally gated by a coupled
//! `ValidatorSetChange::RotateKey` that requires quorum signatures; an
//! attacker who compromises a single validator key cannot unilaterally
//! transfer that identity to themselves.
//!
//! Phase enforcement lives in `sccgub-execution` (§18.2, §18.5, §18.6);
//! registry replay lives in `sccgub-state` (§18.3, §18.4).

use serde::{Deserialize, Serialize};

use crate::validator_set::{Ed25519PublicKey, Ed25519Signature};
use crate::AgentId;

/// A signed key-rotation event (§18.1).
///
/// `signature_by_old_key` proves the incumbent authorized the change;
/// `signature_by_new_key` proves the new-key holder consented (preventing
/// a compromised old key from binding an unwilling new-key holder).
///
/// Canonical bincode field order: `agent_id, old_public_key, new_public_key,
/// rotation_height, signature_by_old_key, signature_by_new_key`.
///
/// `canonical_rotation_bytes` (the signed payload) covers
/// `bincode(agent_id, old_public_key, new_public_key, rotation_height)`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyRotation {
    pub agent_id: AgentId,
    pub old_public_key: Ed25519PublicKey,
    pub new_public_key: Ed25519PublicKey,
    pub rotation_height: u64,
    pub signature_by_old_key: Ed25519Signature,
    pub signature_by_new_key: Ed25519Signature,
}

impl KeyRotation {
    /// Canonical bytes signed by both the old key and the new key. Excludes
    /// the two signatures to keep the signed payload stable across any
    /// signature-byte serialization details.
    pub fn canonical_rotation_bytes(
        agent_id: &AgentId,
        old_public_key: &Ed25519PublicKey,
        new_public_key: &Ed25519PublicKey,
        rotation_height: u64,
    ) -> Vec<u8> {
        bincode::serialize(&(agent_id, old_public_key, new_public_key, rotation_height))
            .expect("KeyRotation canonical_rotation_bytes serialization is infallible")
    }

    /// Convenience: bytes for this instance (for signing or re-verification).
    pub fn payload_bytes(&self) -> Vec<u8> {
        Self::canonical_rotation_bytes(
            &self.agent_id,
            &self.old_public_key,
            &self.new_public_key,
            self.rotation_height,
        )
    }
}

/// On-chain registry of all key rotations ever admitted.
///
/// Canonical ordering: sorted ascending by `(agent_id, rotation_height)`.
/// §18.2 rules 1 and 3 together make two rotations for the same `agent_id`
/// at the same block height impossible (the second rotation's `old_public_key`
/// would not match the post-first-rotation active key).
///
/// Append-only: records are never removed or modified.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct KeyRotationRegistry {
    rotations: Vec<KeyRotation>,
}

/// Canonical trie key: `system/key_rotations`.
pub const KEY_ROTATIONS_TRIE_KEY: &[u8] = b"system/key_rotations";

impl KeyRotationRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// All rotations in canonical order.
    pub fn rotations(&self) -> &[KeyRotation] {
        &self.rotations
    }

    /// Append a new rotation. Maintains canonical ordering. Returns an error
    /// if a rotation for the same (agent_id, rotation_height) already exists
    /// (would indicate a caller bug; §18.2 admission rules prevent this at
    /// the protocol level).
    pub fn append(&mut self, rotation: KeyRotation) -> Result<(), KeyRotationError> {
        let conflict = self.rotations.iter().any(|r| {
            r.agent_id == rotation.agent_id && r.rotation_height == rotation.rotation_height
        });
        if conflict {
            return Err(KeyRotationError::DuplicateAtHeight {
                agent_id: rotation.agent_id,
                rotation_height: rotation.rotation_height,
            });
        }
        self.rotations.push(rotation);
        self.rotations
            .sort_by_key(|r| (r.agent_id, r.rotation_height));
        Ok(())
    }

    /// All rotations for `agent_id` with `rotation_height <= H`, in ascending
    /// order. Used by `active_public_key` resolution (§18.4).
    ///
    /// `agent_id` is taken by value (AgentId is `[u8; 32]`, cheap to copy)
    /// so the returned iterator borrows only from `self`.
    pub fn rotations_for_at(
        &self,
        agent_id: AgentId,
        h: u64,
    ) -> impl Iterator<Item = &KeyRotation> {
        self.rotations
            .iter()
            .filter(move |r| r.agent_id == agent_id && r.rotation_height <= h)
    }

    /// Active public key for `agent_id` at height H, per §18.4.
    /// Returns `None` if there are no rotations; caller then uses the
    /// agent's `original_public_key` from the registration record.
    pub fn active_rotation_at(&self, agent_id: AgentId, h: u64) -> Option<&KeyRotation> {
        self.rotations_for_at(agent_id, h).last()
    }

    /// Canonical bincode bytes for storage under `system/key_rotations`.
    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        bincode::serialize(self).expect("KeyRotationRegistry serialization is infallible")
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, String> {
        bincode::deserialize(bytes).map_err(|e| format!("KeyRotationRegistry deserialize: {}", e))
    }
}

/// An entry in the global public-key index (§18.3).
///
/// Every public key ever bound to any agent appears here exactly once,
/// retained permanently. Used to enforce §18.2 rule 7: a new rotation's
/// `new_public_key` MUST NOT already be present.
///
/// Canonical bincode field order: `public_key, agent_id, active_from,
/// superseded_at`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyIndexEntry {
    pub public_key: Ed25519PublicKey,
    pub agent_id: AgentId,
    pub active_from: u64,
    pub superseded_at: Option<u64>,
}

/// Global public-key index (§18.3). Sorted ascending by
/// `(public_key, active_from)`.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct KeyIndex {
    entries: Vec<KeyIndexEntry>,
}

/// Canonical trie key: `system/key_index`.
pub const KEY_INDEX_TRIE_KEY: &[u8] = b"system/key_index";

impl KeyIndex {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn entries(&self) -> &[KeyIndexEntry] {
        &self.entries
    }

    /// True iff `public_key` is in the index (i.e., has ever been bound to
    /// any agent). §18.2 rule 7 rejects rotations whose `new_public_key`
    /// returns true here.
    pub fn contains_key(&self, public_key: &Ed25519PublicKey) -> bool {
        self.entries.iter().any(|e| &e.public_key == public_key)
    }

    /// Register a newly-bound key (agent registration or successful rotation).
    /// Returns an error if the key is already present; admission-layer
    /// enforcement of §18.2 rule 7 should prevent this at the protocol level.
    pub fn register(
        &mut self,
        public_key: Ed25519PublicKey,
        agent_id: AgentId,
        active_from: u64,
    ) -> Result<(), KeyRotationError> {
        if self.contains_key(&public_key) {
            return Err(KeyRotationError::KeyAlreadyIndexed(public_key));
        }
        self.entries.push(KeyIndexEntry {
            public_key,
            agent_id,
            active_from,
            superseded_at: None,
        });
        self.entries
            .sort_by_key(|e| (e.public_key, e.active_from));
        Ok(())
    }

    /// Mark a key as superseded. Used when a rotation replaces it.
    /// Returns an error if the key is not in the index.
    pub fn mark_superseded(
        &mut self,
        public_key: &Ed25519PublicKey,
        superseded_at: u64,
    ) -> Result<(), KeyRotationError> {
        for entry in self.entries.iter_mut() {
            if &entry.public_key == public_key {
                entry.superseded_at = Some(superseded_at);
                return Ok(());
            }
        }
        Err(KeyRotationError::KeyNotIndexed(*public_key))
    }

    /// Lookup the agent that owns (or owned) a given public key, if any.
    pub fn owning_agent(&self, public_key: &Ed25519PublicKey) -> Option<AgentId> {
        self.entries
            .iter()
            .find(|e| &e.public_key == public_key)
            .map(|e| e.agent_id)
    }

    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        bincode::serialize(self).expect("KeyIndex serialization is infallible")
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, String> {
        bincode::deserialize(bytes).map_err(|e| format!("KeyIndex deserialize: {}", e))
    }
}

#[derive(Debug, thiserror::Error)]
pub enum KeyRotationError {
    #[error("duplicate KeyRotation for agent {agent_id:?} at height {rotation_height}")]
    DuplicateAtHeight {
        agent_id: AgentId,
        rotation_height: u64,
    },
    #[error("public key already present in global index: {0:?}")]
    KeyAlreadyIndexed(Ed25519PublicKey),
    #[error("public key not present in global index: {0:?}")]
    KeyNotIndexed(Ed25519PublicKey),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_rotation(agent: u8, old_k: u8, new_k: u8, h: u64) -> KeyRotation {
        KeyRotation {
            agent_id: [agent; 32],
            old_public_key: [old_k; 32],
            new_public_key: [new_k; 32],
            rotation_height: h,
            signature_by_old_key: vec![0xAA; 64],
            signature_by_new_key: vec![0xBB; 64],
        }
    }

    #[test]
    fn patch_04_key_rotation_canonical_bytes() {
        let r = make_rotation(1, 10, 20, 100);
        let bytes = bincode::serialize(&r).unwrap();
        let back: KeyRotation = bincode::deserialize(&bytes).unwrap();
        assert_eq!(r, back);
    }

    #[test]
    fn patch_04_key_rotation_payload_excludes_signatures() {
        let r = make_rotation(1, 10, 20, 100);
        let p1 = r.payload_bytes();
        let mut r2 = r.clone();
        r2.signature_by_old_key = vec![0xFF; 64];
        r2.signature_by_new_key = vec![0xEE; 64];
        let p2 = r2.payload_bytes();
        assert_eq!(p1, p2, "payload bytes must not depend on signature values");
    }

    #[test]
    fn patch_04_key_rotation_registry_sorts_canonically() {
        let mut reg = KeyRotationRegistry::new();
        reg.append(make_rotation(2, 20, 21, 10)).unwrap();
        reg.append(make_rotation(1, 10, 11, 20)).unwrap();
        reg.append(make_rotation(1, 11, 12, 50)).unwrap();
        let order: Vec<(u8, u64)> = reg
            .rotations()
            .iter()
            .map(|r| (r.agent_id[0], r.rotation_height))
            .collect();
        assert_eq!(order, vec![(1, 20), (1, 50), (2, 10)]);
    }

    #[test]
    fn patch_04_key_rotation_registry_rejects_duplicate_at_height() {
        let mut reg = KeyRotationRegistry::new();
        reg.append(make_rotation(1, 10, 11, 5)).unwrap();
        let err = reg.append(make_rotation(1, 12, 13, 5));
        assert!(matches!(err, Err(KeyRotationError::DuplicateAtHeight { .. })));
    }

    #[test]
    fn patch_04_active_rotation_at_returns_latest() {
        let mut reg = KeyRotationRegistry::new();
        reg.append(make_rotation(1, 10, 11, 5)).unwrap();
        reg.append(make_rotation(1, 11, 12, 50)).unwrap();
        reg.append(make_rotation(1, 12, 13, 100)).unwrap();

        let agent = [1u8; 32];
        assert_eq!(
            reg.active_rotation_at(agent, 4).map(|r| r.new_public_key[0]),
            None
        );
        assert_eq!(
            reg.active_rotation_at(agent, 5).map(|r| r.new_public_key[0]),
            Some(11)
        );
        assert_eq!(
            reg.active_rotation_at(agent, 49)
                .map(|r| r.new_public_key[0]),
            Some(11)
        );
        assert_eq!(
            reg.active_rotation_at(agent, 50)
                .map(|r| r.new_public_key[0]),
            Some(12)
        );
        assert_eq!(
            reg.active_rotation_at(agent, 200)
                .map(|r| r.new_public_key[0]),
            Some(13)
        );
    }

    #[test]
    fn patch_04_key_rotation_chain() {
        // A -> B -> C chain for a single agent.
        let mut reg = KeyRotationRegistry::new();
        reg.append(make_rotation(42, 0xAA, 0xBB, 100)).unwrap();
        reg.append(make_rotation(42, 0xBB, 0xCC, 200)).unwrap();
        let agent = [42u8; 32];
        let at_150 = reg.active_rotation_at(agent, 150).unwrap();
        assert_eq!(at_150.new_public_key[0], 0xBB);
        let at_250 = reg.active_rotation_at(agent, 250).unwrap();
        assert_eq!(at_250.new_public_key[0], 0xCC);
    }

    #[test]
    fn patch_04_key_index_rejects_reused_key() {
        let mut idx = KeyIndex::new();
        idx.register([1u8; 32], [100u8; 32], 0).unwrap();
        let err = idx.register([1u8; 32], [200u8; 32], 50);
        assert!(matches!(err, Err(KeyRotationError::KeyAlreadyIndexed(_))));
    }

    #[test]
    fn patch_04_key_index_mark_superseded() {
        let mut idx = KeyIndex::new();
        idx.register([1u8; 32], [100u8; 32], 0).unwrap();
        idx.mark_superseded(&[1u8; 32], 50).unwrap();
        let entry = idx.entries().iter().find(|e| e.public_key[0] == 1).unwrap();
        assert_eq!(entry.superseded_at, Some(50));
    }

    #[test]
    fn patch_04_key_index_sorted_canonically() {
        let mut idx = KeyIndex::new();
        idx.register([3u8; 32], [30u8; 32], 0).unwrap();
        idx.register([1u8; 32], [10u8; 32], 0).unwrap();
        idx.register([2u8; 32], [20u8; 32], 0).unwrap();
        let order: Vec<u8> = idx.entries().iter().map(|e| e.public_key[0]).collect();
        assert_eq!(order, vec![1, 2, 3]);
    }

    #[test]
    fn patch_04_key_rotation_registry_roundtrip() {
        let mut reg = KeyRotationRegistry::new();
        reg.append(make_rotation(1, 10, 11, 5)).unwrap();
        reg.append(make_rotation(2, 20, 21, 8)).unwrap();
        let bytes = reg.to_canonical_bytes();
        let back = KeyRotationRegistry::from_canonical_bytes(&bytes).unwrap();
        assert_eq!(reg, back);
    }

    #[test]
    fn patch_04_key_index_roundtrip() {
        let mut idx = KeyIndex::new();
        idx.register([1u8; 32], [10u8; 32], 0).unwrap();
        idx.register([2u8; 32], [20u8; 32], 5).unwrap();
        let bytes = idx.to_canonical_bytes();
        let back = KeyIndex::from_canonical_bytes(&bytes).unwrap();
        assert_eq!(idx, back);
    }

    #[test]
    fn patch_04_trie_keys_in_system_namespace() {
        assert!(KEY_ROTATIONS_TRIE_KEY.starts_with(b"system/"));
        assert!(KEY_INDEX_TRIE_KEY.starts_with(b"system/"));
    }
}
