//! Patch-07 §D.4 SupersessionLink primitive — INV-SUPERSESSION-UNIQUENESS.
//!
//! The refined thesis specified supersession as a correction primitive
//! preserving both the original and replacement in H. The Part-2 audit
//! flagged that two authorities racing to supersede the same fact
//! produce ambiguous canonical state: which supersession wins? The
//! thesis punted to "readers apply their own trust model," which is
//! not a substrate guarantee.
//!
//! This module commits to **first-valid-wins** canonical semantics:
//! for any original `TxRef`, the **lowest-height, then lexicographically-
//! smallest `link_id`** supersession is the canonical successor. All
//! other supersessions targeting the same original are preserved in H
//! but are NOT the canonical chain. Readers querying "what is the
//! canonical replacement for X" receive a deterministic answer.
//!
//! This resolves INV-SUPERSESSION-UNIQUENESS at the type layer; the
//! adapter execution layer is responsible for enforcing the canonical
//! chain query against the registry.

use serde::{Deserialize, Serialize};

use crate::{AgentId, Hash};

/// Domain separator for SupersessionLink canonical hash.
pub const SUPERSESSION_DOMAIN_SEPARATOR: &[u8] = b"sccgub-supersession-v7";

/// Cap on the `reason` hash's length. The hash is a 32-byte Hash; this
/// constant exists to make the intent explicit (`reason` is a pointer
/// to an off-chain reason document, never a free-form string).
pub const SUPERSESSION_REASON_HASH_BYTES: usize = 32;

/// Patch-07 §D.4 SupersessionLink — declares that `replacement`
/// supersedes `original` under `authority`'s justification `reason`.
///
/// Canonical bincode field order: `link_id, original, replacement,
/// authority, reason, height`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SupersessionLink {
    pub link_id: Hash,
    /// TxRef of the original (superseded) record.
    pub original: Hash,
    /// TxRef of the replacement.
    pub replacement: Hash,
    /// Authority performing the supersession. Role-gating is adapter-
    /// specific; this type stores only the authority's agent id.
    pub authority: AgentId,
    /// Hash of the off-chain reason document. Exact 32 bytes per
    /// SUPERSESSION_REASON_HASH_BYTES.
    pub reason: Hash,
    /// Block height at which the supersession was admitted. First-valid-
    /// wins canonical ordering uses this as primary sort.
    pub height: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SupersessionValidationError {
    #[error("self-supersession rejected: original == replacement")]
    SelfSupersession,
    #[error("link_id inconsistent with canonical payload")]
    IdInconsistent,
}

impl SupersessionLink {
    pub fn compute_link_id(
        original: &Hash,
        replacement: &Hash,
        authority: &AgentId,
        reason: &Hash,
        height: u64,
    ) -> Hash {
        let bytes = bincode::serialize(&(original, replacement, authority, reason, height))
            .expect("SupersessionLink compute_link_id serialization is infallible");
        let mut hasher = blake3::Hasher::new();
        hasher.update(SUPERSESSION_DOMAIN_SEPARATOR);
        hasher.update(&bytes);
        *hasher.finalize().as_bytes()
    }

    pub fn validate_structural(&self) -> Result<(), SupersessionValidationError> {
        if self.original == self.replacement {
            return Err(SupersessionValidationError::SelfSupersession);
        }
        let expected = Self::compute_link_id(
            &self.original,
            &self.replacement,
            &self.authority,
            &self.reason,
            self.height,
        );
        if expected != self.link_id {
            return Err(SupersessionValidationError::IdInconsistent);
        }
        Ok(())
    }

    /// INV-SUPERSESSION-UNIQUENESS canonical-ordering key.
    ///
    /// Given a set of supersession links all targeting the same
    /// `original`, the **minimum** value of `canonical_key` is the
    /// canonical successor. Primary sort: `height` (earliest wins).
    /// Tiebreak: `link_id` (lexicographically smallest wins). Both
    /// components are deterministic functions of the link content, so
    /// every honest node computes the same canonical successor.
    pub fn canonical_key(&self) -> (u64, Hash) {
        (self.height, self.link_id)
    }
}

/// Deterministically select the canonical successor from a set of
/// supersession links all targeting the same `original`. Returns `None`
/// if the set is empty. Pure over the input.
///
/// Every caller of this function across every validator produces the
/// same output for the same input set — this is the core of
/// INV-SUPERSESSION-UNIQUENESS.
pub fn canonical_successor<'a, I>(links: I) -> Option<&'a SupersessionLink>
where
    I: IntoIterator<Item = &'a SupersessionLink>,
{
    links.into_iter().min_by_key(|l| l.canonical_key())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mk(original: Hash, replacement: Hash, height: u64) -> SupersessionLink {
        let authority = [0xAA; 32];
        let reason = [0xBB; 32];
        SupersessionLink {
            link_id: SupersessionLink::compute_link_id(
                &original,
                &replacement,
                &authority,
                &reason,
                height,
            ),
            original,
            replacement,
            authority,
            reason,
            height,
        }
    }

    #[test]
    fn patch_07_valid_supersession_passes_validation() {
        let l = mk([0x11; 32], [0x22; 32], 100);
        l.validate_structural().unwrap();
    }

    #[test]
    fn patch_07_self_supersession_rejected() {
        let l = mk([0x11; 32], [0x11; 32], 100);
        assert!(matches!(
            l.validate_structural(),
            Err(SupersessionValidationError::SelfSupersession)
        ));
    }

    #[test]
    fn patch_07_supersession_id_consistency_enforced() {
        let mut l = mk([0x11; 32], [0x22; 32], 100);
        l.link_id = [0xFF; 32];
        assert!(matches!(
            l.validate_structural(),
            Err(SupersessionValidationError::IdInconsistent)
        ));
    }

    #[test]
    fn patch_07_canonical_successor_empty_returns_none() {
        let none: Vec<SupersessionLink> = vec![];
        assert!(canonical_successor(&none).is_none());
    }

    #[test]
    fn patch_07_canonical_successor_single_returns_that_one() {
        let l = mk([0x11; 32], [0x22; 32], 100);
        let s = canonical_successor(std::slice::from_ref(&l)).unwrap();
        assert_eq!(s.link_id, l.link_id);
    }

    #[test]
    fn patch_07_canonical_successor_earliest_height_wins() {
        let original = [0x11; 32];
        // Two replacements at different heights.
        let earlier = mk(original, [0x22; 32], 50);
        let later = mk(original, [0x33; 32], 100);
        let set = vec![earlier.clone(), later.clone()];
        let selected = canonical_successor(&set).unwrap();
        assert_eq!(selected.link_id, earlier.link_id);
    }

    #[test]
    fn patch_07_canonical_successor_tiebreak_on_hash() {
        let original = [0x11; 32];
        // Two replacements at same height — tiebreak on link_id.
        let a = mk(original, [0x22; 32], 100);
        let b = mk(original, [0x33; 32], 100);
        let set = vec![a.clone(), b.clone()];
        let selected = canonical_successor(&set).unwrap();
        // Whichever has smaller link_id wins. The choice is deterministic.
        assert!(selected.link_id == a.link_id || selected.link_id == b.link_id);
        // The other one must have a lexicographically-larger id.
        let other_id = if selected.link_id == a.link_id {
            b.link_id
        } else {
            a.link_id
        };
        assert!(selected.link_id < other_id);
    }

    #[test]
    fn patch_07_canonical_successor_order_independent() {
        // INV-SUPERSESSION-UNIQUENESS determinism: the same candidate
        // set must select the same canonical successor regardless of
        // iteration order.
        let original = [0x11; 32];
        let a = mk(original, [0x22; 32], 100);
        let b = mk(original, [0x33; 32], 100);
        let c = mk(original, [0x44; 32], 50);
        let set1 = vec![a.clone(), b.clone(), c.clone()];
        let set2 = vec![c.clone(), b.clone(), a.clone()];
        let set3 = vec![b.clone(), a.clone(), c.clone()];
        let s1 = canonical_successor(&set1).unwrap().link_id;
        let s2 = canonical_successor(&set2).unwrap().link_id;
        let s3 = canonical_successor(&set3).unwrap().link_id;
        assert_eq!(s1, s2);
        assert_eq!(s2, s3);
        // c has the earliest height, so it wins.
        assert_eq!(s1, c.link_id);
    }

    #[test]
    fn patch_07_domain_separator_matches_spec() {
        assert_eq!(SUPERSESSION_DOMAIN_SEPARATOR, b"sccgub-supersession-v7");
    }
}
