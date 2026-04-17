//! Validator set primitives for v3 (Patch-04 §15).
//!
//! Implements the on-chain validator-set membership model. Before Patch-04,
//! validator membership was implicit (genesis signer list) with no on-chain
//! mutation rule; two honest nodes could admit different quorums. §15 makes
//! membership a replay-deterministic function of signed `ValidatorSetChange`
//! events committed to blocks.
//!
//! Canonical bincode field order is declared at each struct definition and
//! MUST NOT be reordered without a chain hard fork.
//!
//! Wire formats here are consensus-critical. The behavior and phase-level
//! enforcement lives in `sccgub-execution` (§15.5 admission), `sccgub-state`
//! (§15.6 replay), and `sccgub-consensus` (§15.7 equivocation).

use serde::{Deserialize, Serialize};

use crate::mfidel::MfidelAtomicSeal;
use crate::{AgentId, Hash};

/// Ed25519 public key (32 bytes). Re-declared here with a semantic alias to
/// avoid pulling `ed25519-dalek` into `sccgub-types`.
pub type Ed25519PublicKey = [u8; 32];

/// Ed25519 signature as raw bytes. Verified with `verify_strict` in consensus
/// paths (see §15.5, §16.4, §18.2).
pub type Ed25519Signature = Vec<u8>;

/// A single validator record in the on-chain `ValidatorSet`.
///
/// `agent_id` is the persistent identity (stable across key rotation);
/// `validator_id` is the current Ed25519 signing key. A `RotateKey` event
/// (§15.4) replaces `validator_id` while preserving `agent_id`.
///
/// Canonical bincode field order: `agent_id, validator_id, mfidel_seal,
/// voting_power, active_from, active_until`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidatorRecord {
    pub agent_id: AgentId,
    pub validator_id: Ed25519PublicKey,
    pub mfidel_seal: MfidelAtomicSeal,
    pub voting_power: u64,
    pub active_from: u64,
    pub active_until: Option<u64>,
}

impl ValidatorRecord {
    /// True iff this record is active at the given height, per §15.1.
    pub fn is_active_at(&self, height: u64) -> bool {
        if self.voting_power == 0 {
            return false;
        }
        if height < self.active_from {
            return false;
        }
        match self.active_until {
            Some(u) => height <= u,
            None => true,
        }
    }
}

/// On-chain validator set, canonically sorted ascending by `agent_id`.
///
/// Canonical ordering is by `agent_id` rather than `validator_id` so that
/// `RotateKey` does not reorder the set and cause unrelated state-root churn.
/// Duplicate `agent_id` or duplicate `validator_id` values are invalid.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct ValidatorSet {
    records: Vec<ValidatorRecord>,
}

/// Canonical trie key: `system/validator_set`.
pub const VALIDATOR_SET_TRIE_KEY: &[u8] = b"system/validator_set";

impl ValidatorSet {
    /// Construct a canonical set from a vec of records. Returns an error if
    /// duplicates are present; sorts records into canonical order.
    pub fn new(mut records: Vec<ValidatorRecord>) -> Result<Self, ValidatorSetError> {
        records.sort_by_key(|r| r.agent_id);
        for window in records.windows(2) {
            if window[0].agent_id == window[1].agent_id {
                return Err(ValidatorSetError::DuplicateAgentId(window[0].agent_id));
            }
        }
        let mut seen_validator_ids: Vec<Ed25519PublicKey> =
            records.iter().map(|r| r.validator_id).collect();
        seen_validator_ids.sort();
        for window in seen_validator_ids.windows(2) {
            if window[0] == window[1] {
                return Err(ValidatorSetError::DuplicateValidatorId(window[0]));
            }
        }
        Ok(Self { records })
    }

    /// All records (active and inactive), in canonical order.
    pub fn records(&self) -> &[ValidatorRecord] {
        &self.records
    }

    /// Active subset at height H, in canonical order (sorted by `agent_id`).
    pub fn active_at(&self, height: u64) -> Vec<&ValidatorRecord> {
        self.records
            .iter()
            .filter(|r| r.is_active_at(height))
            .collect()
    }

    /// Total voting power of the active subset at H.
    pub fn total_power_at(&self, height: u64) -> u128 {
        self.records
            .iter()
            .filter(|r| r.is_active_at(height))
            .map(|r| r.voting_power as u128)
            .sum()
    }

    /// Quorum threshold per §15.3: `floor(2 * total_power / 3) + 1`.
    pub fn quorum_power_at(&self, height: u64) -> u128 {
        let total = self.total_power_at(height);
        (total * 2) / 3 + 1
    }

    /// Lookup by `agent_id`.
    pub fn find_by_agent(&self, agent_id: &AgentId) -> Option<&ValidatorRecord> {
        self.records.iter().find(|r| &r.agent_id == agent_id)
    }

    /// Lookup by current `validator_id` among active records at height H.
    pub fn find_active_by_validator_id(
        &self,
        validator_id: &Ed25519PublicKey,
        height: u64,
    ) -> Option<&ValidatorRecord> {
        self.records
            .iter()
            .find(|r| &r.validator_id == validator_id && r.is_active_at(height))
    }

    /// Canonical bincode bytes for storage under `system/validator_set`.
    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        bincode::serialize(self).expect("ValidatorSet serialization is infallible")
    }

    /// Deserialize from canonical bincode.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, String> {
        bincode::deserialize(bytes).map_err(|e| format!("ValidatorSet deserialize: {}", e))
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ValidatorSetError {
    #[error("duplicate agent_id in validator set: {0:?}")]
    DuplicateAgentId(AgentId),
    #[error("duplicate validator_id in validator set: {0:?}")]
    DuplicateValidatorId(Ed25519PublicKey),
}

/// Reason a validator was removed from the set. Purely informational in v3;
/// downstream tooling may key on this to surface slashing events distinctly
/// from voluntary exits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RemovalReason {
    Voluntary,
    Equivocation,
    Inactivity,
    Governance,
}

/// A change to the validator set. See §15.4 for the four variants.
///
/// `RotatePower` and `RotateKey` are split (rather than a single `Rotate`
/// with optional fields) so neither may silently carry the other's effect,
/// and so phase-level validators can apply each with a distinct predicate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ValidatorSetChangeKind {
    Add(ValidatorRecord),
    Remove {
        agent_id: AgentId,
        reason: RemovalReason,
        effective_height: u64,
    },
    RotatePower {
        agent_id: AgentId,
        new_voting_power: u64,
        effective_height: u64,
    },
    RotateKey {
        agent_id: AgentId,
        old_validator_id: Ed25519PublicKey,
        new_validator_id: Ed25519PublicKey,
        effective_height: u64,
    },
}

impl ValidatorSetChangeKind {
    /// Effective height of the change (per-variant field).
    pub fn effective_height(&self) -> u64 {
        match self {
            Self::Add(r) => r.active_from,
            Self::Remove {
                effective_height, ..
            }
            | Self::RotatePower {
                effective_height, ..
            }
            | Self::RotateKey {
                effective_height, ..
            } => *effective_height,
        }
    }

    /// The agent_id targeted by this change.
    pub fn target_agent_id(&self) -> AgentId {
        match self {
            Self::Add(r) => r.agent_id,
            Self::Remove { agent_id, .. }
            | Self::RotatePower { agent_id, .. }
            | Self::RotateKey { agent_id, .. } => *agent_id,
        }
    }
}

/// A signed validator-set change event. `quorum_signatures` are verified
/// against `active_set(proposed_at)` at admission (§15.5); `change_id`
/// is `BLAKE3(canonical_change_bytes)` where canonical_change_bytes
/// covers `bincode(kind, proposed_at)`.
///
/// Canonical bincode field order: `change_id, kind, proposed_at, quorum_signatures`.
/// `quorum_signatures` is sorted ascending by signer public key bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidatorSetChange {
    pub change_id: Hash,
    pub kind: ValidatorSetChangeKind,
    pub proposed_at: u64,
    pub quorum_signatures: Vec<(Ed25519PublicKey, Ed25519Signature)>,
}

impl ValidatorSetChange {
    /// Canonical bytes signed by each quorum participant and hashed into
    /// `change_id`. Excludes `quorum_signatures` to prevent signature
    /// malleability from affecting `change_id`.
    pub fn canonical_change_bytes(kind: &ValidatorSetChangeKind, proposed_at: u64) -> Vec<u8> {
        bincode::serialize(&(kind, proposed_at))
            .expect("ValidatorSetChange canonical_change_bytes serialization is infallible")
    }

    /// Compute the expected `change_id` from the signed payload.
    pub fn compute_change_id(kind: &ValidatorSetChangeKind, proposed_at: u64) -> Hash {
        let bytes = Self::canonical_change_bytes(kind, proposed_at);
        *blake3::hash(&bytes).as_bytes()
    }

    /// Sort `quorum_signatures` into canonical ascending-by-pubkey order
    /// and reject duplicate signers.
    pub fn canonicalize_signatures(&mut self) -> Result<(), ValidatorSetError> {
        self.quorum_signatures.sort_by_key(|pair| pair.0);
        for w in self.quorum_signatures.windows(2) {
            if w[0].0 == w[1].0 {
                return Err(ValidatorSetError::DuplicateValidatorId(w[0].0));
            }
        }
        Ok(())
    }

    /// True iff this change's `change_id` matches the recomputed hash of
    /// its canonical signed payload.
    pub fn change_id_is_consistent(&self) -> bool {
        self.change_id == Self::compute_change_id(&self.kind, self.proposed_at)
    }
}

/// Minimal vote payload used by `EquivocationEvidence` (§15.7). Mirrors the
/// signed-over fields of `sccgub-consensus::protocol::Vote` but is declared
/// here so `sccgub-types` need not depend on the consensus crate. Conforming
/// implementations MUST use an identical canonical encoding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EquivocationVote {
    pub validator_id: Ed25519PublicKey,
    pub block_hash: Hash,
    pub height: u64,
    pub round: u32,
    pub vote_type: EquivocationVoteType,
    pub signature: Ed25519Signature,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EquivocationVoteType {
    Prevote,
    Precommit,
}

/// Two distinct signatures from the same validator on the same
/// (height, round, vote_type) with different block hashes. Admission
/// triggers the two-stage slashing event of §15.7.
///
/// Canonical bincode field order: `vote_a, vote_b`, with the pair
/// internally sorted ascending by `vote.signature` bytes so that the
/// same evidence has a single canonical encoding regardless of which
/// signature arrived first.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EquivocationEvidence {
    pub vote_a: EquivocationVote,
    pub vote_b: EquivocationVote,
}

impl EquivocationEvidence {
    /// Construct evidence with the two votes in canonical order
    /// (sorted ascending by signature bytes).
    pub fn new(v1: EquivocationVote, v2: EquivocationVote) -> Self {
        if v1.signature <= v2.signature {
            Self {
                vote_a: v1,
                vote_b: v2,
            }
        } else {
            Self {
                vote_a: v2,
                vote_b: v1,
            }
        }
    }

    /// Structural well-formedness: same signer, same (height, round, type),
    /// distinct block hashes, distinct signatures. Does not verify signatures
    /// (that is a consensus-layer concern).
    pub fn is_structurally_equivocation(&self) -> bool {
        self.vote_a.validator_id == self.vote_b.validator_id
            && self.vote_a.height == self.vote_b.height
            && self.vote_a.round == self.vote_b.round
            && self.vote_a.vote_type == self.vote_b.vote_type
            && self.vote_a.block_hash != self.vote_b.block_hash
            && self.vote_a.signature != self.vote_b.signature
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(agent_byte: u8, validator_byte: u8, power: u64, from: u64) -> ValidatorRecord {
        ValidatorRecord {
            agent_id: [agent_byte; 32],
            validator_id: [validator_byte; 32],
            mfidel_seal: MfidelAtomicSeal::from_height(from),
            voting_power: power,
            active_from: from,
            active_until: None,
        }
    }

    #[test]
    fn patch_04_validator_record_canonical_bytes() {
        let r = record(1, 2, 10, 5);
        let bytes = bincode::serialize(&r).unwrap();
        let back: ValidatorRecord = bincode::deserialize(&bytes).unwrap();
        assert_eq!(r, back);
    }

    #[test]
    fn patch_04_validator_set_canonical_order_by_agent_id() {
        let out_of_order = vec![record(3, 30, 1, 0), record(1, 10, 1, 0), record(2, 20, 1, 0)];
        let set = ValidatorSet::new(out_of_order).unwrap();
        let agent_ids: Vec<u8> = set.records().iter().map(|r| r.agent_id[0]).collect();
        assert_eq!(agent_ids, vec![1, 2, 3]);
    }

    #[test]
    fn patch_04_validator_set_rejects_duplicate_agent_id() {
        let dup = vec![record(1, 10, 1, 0), record(1, 20, 1, 0)];
        assert!(matches!(
            ValidatorSet::new(dup),
            Err(ValidatorSetError::DuplicateAgentId(_))
        ));
    }

    #[test]
    fn patch_04_validator_set_rejects_duplicate_validator_id() {
        let dup = vec![record(1, 10, 1, 0), record(2, 10, 1, 0)];
        assert!(matches!(
            ValidatorSet::new(dup),
            Err(ValidatorSetError::DuplicateValidatorId(_))
        ));
    }

    #[test]
    fn patch_04_active_and_quorum_power() {
        let set = ValidatorSet::new(vec![
            record(1, 10, 30, 0),
            record(2, 20, 30, 0),
            record(3, 30, 40, 0),
        ])
        .unwrap();
        assert_eq!(set.total_power_at(5), 100);
        assert_eq!(set.quorum_power_at(5), 67);
    }

    #[test]
    fn patch_04_inactive_validators_excluded_from_quorum() {
        let mut r2 = record(2, 20, 30, 0);
        r2.active_until = Some(2);
        let set = ValidatorSet::new(vec![record(1, 10, 30, 0), r2, record(3, 30, 40, 0)]).unwrap();
        assert_eq!(set.total_power_at(5), 70);
    }

    #[test]
    fn patch_04_validator_set_change_canonical_bytes() {
        let kind = ValidatorSetChangeKind::Add(record(5, 50, 10, 100));
        let bytes = ValidatorSetChange::canonical_change_bytes(&kind, 99);
        let change_id = ValidatorSetChange::compute_change_id(&kind, 99);
        let expected = *blake3::hash(&bytes).as_bytes();
        assert_eq!(change_id, expected);
    }

    #[test]
    fn patch_04_validator_set_change_variants_effective_height() {
        let add_kind = ValidatorSetChangeKind::Add(record(1, 10, 5, 42));
        assert_eq!(add_kind.effective_height(), 42);
        let rm_kind = ValidatorSetChangeKind::Remove {
            agent_id: [1; 32],
            reason: RemovalReason::Voluntary,
            effective_height: 7,
        };
        assert_eq!(rm_kind.effective_height(), 7);
        let rp_kind = ValidatorSetChangeKind::RotatePower {
            agent_id: [1; 32],
            new_voting_power: 20,
            effective_height: 9,
        };
        assert_eq!(rp_kind.effective_height(), 9);
        let rk_kind = ValidatorSetChangeKind::RotateKey {
            agent_id: [1; 32],
            old_validator_id: [10; 32],
            new_validator_id: [11; 32],
            effective_height: 13,
        };
        assert_eq!(rk_kind.effective_height(), 13);
    }

    #[test]
    fn patch_04_change_id_is_consistent_detects_tamper() {
        let kind = ValidatorSetChangeKind::Remove {
            agent_id: [1; 32],
            reason: RemovalReason::Governance,
            effective_height: 10,
        };
        let cid = ValidatorSetChange::compute_change_id(&kind, 5);
        let change = ValidatorSetChange {
            change_id: cid,
            kind: kind.clone(),
            proposed_at: 5,
            quorum_signatures: vec![],
        };
        assert!(change.change_id_is_consistent());

        let tampered = ValidatorSetChange {
            change_id: [0xFF; 32],
            kind,
            proposed_at: 5,
            quorum_signatures: vec![],
        };
        assert!(!tampered.change_id_is_consistent());
    }

    #[test]
    fn patch_04_canonicalize_signatures_sorts_and_dedupes() {
        let kind = ValidatorSetChangeKind::Remove {
            agent_id: [1; 32],
            reason: RemovalReason::Inactivity,
            effective_height: 3,
        };
        let cid = ValidatorSetChange::compute_change_id(&kind, 1);
        let mut change = ValidatorSetChange {
            change_id: cid,
            kind,
            proposed_at: 1,
            quorum_signatures: vec![
                ([3u8; 32], vec![0xCC]),
                ([1u8; 32], vec![0xAA]),
                ([2u8; 32], vec![0xBB]),
            ],
        };
        change.canonicalize_signatures().unwrap();
        let order: Vec<u8> = change
            .quorum_signatures
            .iter()
            .map(|(pk, _)| pk[0])
            .collect();
        assert_eq!(order, vec![1, 2, 3]);
    }

    #[test]
    fn patch_04_canonicalize_signatures_rejects_duplicate_signer() {
        let kind = ValidatorSetChangeKind::Remove {
            agent_id: [1; 32],
            reason: RemovalReason::Voluntary,
            effective_height: 3,
        };
        let cid = ValidatorSetChange::compute_change_id(&kind, 1);
        let mut change = ValidatorSetChange {
            change_id: cid,
            kind,
            proposed_at: 1,
            quorum_signatures: vec![([1u8; 32], vec![0xAA]), ([1u8; 32], vec![0xAB])],
        };
        assert!(change.canonicalize_signatures().is_err());
    }

    #[test]
    fn patch_04_equivocation_evidence_canonical_order() {
        let v_high = EquivocationVote {
            validator_id: [1; 32],
            block_hash: [0xAA; 32],
            height: 10,
            round: 0,
            vote_type: EquivocationVoteType::Prevote,
            signature: vec![0xFF, 0xFF],
        };
        let v_low = EquivocationVote {
            validator_id: [1; 32],
            block_hash: [0xBB; 32],
            height: 10,
            round: 0,
            vote_type: EquivocationVoteType::Prevote,
            signature: vec![0x00, 0x01],
        };
        let ev = EquivocationEvidence::new(v_high.clone(), v_low.clone());
        assert_eq!(ev.vote_a.signature, v_low.signature);
        assert_eq!(ev.vote_b.signature, v_high.signature);
        assert!(ev.is_structurally_equivocation());
    }

    #[test]
    fn patch_04_equivocation_rejects_same_block_hash() {
        let v = EquivocationVote {
            validator_id: [1; 32],
            block_hash: [0xAA; 32],
            height: 10,
            round: 0,
            vote_type: EquivocationVoteType::Prevote,
            signature: vec![0x01],
        };
        let v2 = EquivocationVote {
            signature: vec![0x02],
            ..v.clone()
        };
        let ev = EquivocationEvidence::new(v, v2);
        assert!(!ev.is_structurally_equivocation());
    }

    #[test]
    fn patch_04_validator_set_roundtrip_canonical_bytes() {
        let set = ValidatorSet::new(vec![
            record(1, 10, 30, 0),
            record(2, 20, 30, 0),
            record(3, 30, 40, 0),
        ])
        .unwrap();
        let bytes = set.to_canonical_bytes();
        let back = ValidatorSet::from_canonical_bytes(&bytes).unwrap();
        assert_eq!(set, back);
    }

    #[test]
    fn patch_04_trie_key_in_system_namespace() {
        assert!(VALIDATOR_SET_TRIE_KEY.starts_with(b"system/"));
    }
}
