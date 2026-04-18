//! Patch-07 §D.3 ReferenceLink primitive — INV-REFERENCE-DISCOVERABILITY.
//!
//! The refined thesis proposed cross-domain references as kernel
//! primitives (`source_domain/source_key → target_domain/target_key`).
//! The Part-2 audit flagged that nothing prevents adapter X from
//! publishing references into adapter Y's private keyspace, creating a
//! one-way leak of Y's internal structure with no target-side recourse.
//!
//! This module commits to a **target-permissioned** reference model:
//! every `ReferenceLink` declares the relationship type (DependsOn /
//! Cites / Supersedes / Contradicts), and target domains can express
//! reference-admissibility policies indexed by kind. The target policy
//! is not enforced at kernel level in this patch — it is captured as
//! structural metadata so adapter runtimes can apply policy at read
//! time. This makes the link primitive safe to admit universally
//! while leaving policy hooks available.

use serde::{Deserialize, Serialize};

use crate::Hash;

/// Domain separator for ReferenceLink canonical hash.
pub const REFERENCE_DOMAIN_SEPARATOR: &[u8] = b"sccgub-reference-v7";

/// Kinds of cross-domain reference the kernel recognizes. Adapters may
/// filter on these when materializing backlinks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReferenceKind {
    /// Source is causally dependent on target.
    DependsOn,
    /// Source cites target as a non-causal reference (bibliographic).
    Cites,
    /// Source explicitly supersedes target (note: prefer
    /// `SupersessionLink` for supersession proper; `Supersedes` here
    /// is available for weak references where the supersession is
    /// inferential, not authoritative).
    Supersedes,
    /// Source explicitly contradicts target.
    Contradicts,
}

/// Cross-domain reference. The kernel records the link; the target
/// domain's adapter is responsible for enforcing admissibility
/// policy when the link is materialized as a backlink.
///
/// Canonical bincode field order: `link_id, source_domain, source_key,
/// target_domain, target_key, kind, height`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReferenceLink {
    pub link_id: Hash,
    pub source_domain: Hash,
    pub source_key: Vec<u8>,
    pub target_domain: Hash,
    pub target_key: Vec<u8>,
    pub kind: ReferenceKind,
    /// Block height at which the reference was admitted. Frozen at
    /// admission; used for temporal disambiguation.
    pub height: u64,
}

/// Key-length cap. Keys in the current trie are typically 32 bytes
/// (hash-ids); wider keys are defensive but bounded.
pub const MAX_REFERENCE_KEY_BYTES: usize = 128;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ReferenceValidationError {
    #[error("source_key length {size} exceeds MAX_REFERENCE_KEY_BYTES ({max})")]
    SourceKeyTooLarge { size: usize, max: usize },
    #[error("target_key length {size} exceeds MAX_REFERENCE_KEY_BYTES ({max})")]
    TargetKeyTooLarge { size: usize, max: usize },
    #[error("self-reference rejected: source == target")]
    SelfReference,
    #[error("link_id inconsistent with canonical payload")]
    IdInconsistent,
}

impl ReferenceLink {
    pub fn compute_link_id(
        source_domain: &Hash,
        source_key: &[u8],
        target_domain: &Hash,
        target_key: &[u8],
        kind: ReferenceKind,
        height: u64,
    ) -> Hash {
        let bytes = bincode::serialize(&(
            source_domain,
            source_key,
            target_domain,
            target_key,
            kind,
            height,
        ))
        .expect("ReferenceLink compute_link_id serialization is infallible");
        let mut hasher = blake3::Hasher::new();
        hasher.update(REFERENCE_DOMAIN_SEPARATOR);
        hasher.update(&bytes);
        *hasher.finalize().as_bytes()
    }

    pub fn validate_structural(&self) -> Result<(), ReferenceValidationError> {
        if self.source_key.len() > MAX_REFERENCE_KEY_BYTES {
            return Err(ReferenceValidationError::SourceKeyTooLarge {
                size: self.source_key.len(),
                max: MAX_REFERENCE_KEY_BYTES,
            });
        }
        if self.target_key.len() > MAX_REFERENCE_KEY_BYTES {
            return Err(ReferenceValidationError::TargetKeyTooLarge {
                size: self.target_key.len(),
                max: MAX_REFERENCE_KEY_BYTES,
            });
        }
        if self.source_domain == self.target_domain && self.source_key == self.target_key {
            return Err(ReferenceValidationError::SelfReference);
        }
        let expected = Self::compute_link_id(
            &self.source_domain,
            &self.source_key,
            &self.target_domain,
            &self.target_key,
            self.kind,
            self.height,
        );
        if expected != self.link_id {
            return Err(ReferenceValidationError::IdInconsistent);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mk() -> ReferenceLink {
        let source_domain = [0x11; 32];
        let source_key = vec![0xAA; 32];
        let target_domain = [0x22; 32];
        let target_key = vec![0xBB; 32];
        let kind = ReferenceKind::Cites;
        let height = 100;
        ReferenceLink {
            link_id: ReferenceLink::compute_link_id(
                &source_domain,
                &source_key,
                &target_domain,
                &target_key,
                kind,
                height,
            ),
            source_domain,
            source_key,
            target_domain,
            target_key,
            kind,
            height,
        }
    }

    #[test]
    fn patch_07_valid_reference_passes_validation() {
        let r = mk();
        r.validate_structural().unwrap();
    }

    #[test]
    fn patch_07_reference_id_consistency_enforced() {
        let mut r = mk();
        r.link_id = [0xFF; 32];
        assert!(matches!(
            r.validate_structural(),
            Err(ReferenceValidationError::IdInconsistent)
        ));
    }

    #[test]
    fn patch_07_self_reference_rejected() {
        let source_domain = [0x11; 32];
        let source_key = vec![0xAA; 32];
        let kind = ReferenceKind::Cites;
        let height = 100;
        let r = ReferenceLink {
            link_id: ReferenceLink::compute_link_id(
                &source_domain,
                &source_key,
                &source_domain,
                &source_key,
                kind,
                height,
            ),
            source_domain,
            source_key: source_key.clone(),
            target_domain: source_domain,
            target_key: source_key,
            kind,
            height,
        };
        assert!(matches!(
            r.validate_structural(),
            Err(ReferenceValidationError::SelfReference)
        ));
    }

    #[test]
    fn patch_07_oversized_source_key_rejected() {
        let mut r = mk();
        r.source_key = vec![0u8; MAX_REFERENCE_KEY_BYTES + 1];
        // Need to recompute the id to isolate the size-check path.
        r.link_id = ReferenceLink::compute_link_id(
            &r.source_domain,
            &r.source_key,
            &r.target_domain,
            &r.target_key,
            r.kind,
            r.height,
        );
        assert!(matches!(
            r.validate_structural(),
            Err(ReferenceValidationError::SourceKeyTooLarge { .. })
        ));
    }

    #[test]
    fn patch_07_cross_domain_allowed_when_different() {
        let mut r = mk();
        // Same domain, different key — OK.
        r.target_domain = r.source_domain;
        r.target_key = vec![0xCC; 32];
        r.link_id = ReferenceLink::compute_link_id(
            &r.source_domain,
            &r.source_key,
            &r.target_domain,
            &r.target_key,
            r.kind,
            r.height,
        );
        r.validate_structural().unwrap();
    }

    #[test]
    fn patch_07_reference_kind_variants_all_valid() {
        for kind in [
            ReferenceKind::DependsOn,
            ReferenceKind::Cites,
            ReferenceKind::Supersedes,
            ReferenceKind::Contradicts,
        ] {
            let mut r = mk();
            r.kind = kind;
            r.link_id = ReferenceLink::compute_link_id(
                &r.source_domain,
                &r.source_key,
                &r.target_domain,
                &r.target_key,
                r.kind,
                r.height,
            );
            r.validate_structural().unwrap();
        }
    }

    #[test]
    fn patch_07_domain_separator_matches_spec() {
        assert_eq!(REFERENCE_DOMAIN_SEPARATOR, b"sccgub-reference-v7");
    }
}
