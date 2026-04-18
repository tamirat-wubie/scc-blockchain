//! Patch-07 §D.1 Message primitive — INV-MESSAGE-RETENTION-PAID.
//!
//! The refined thesis proposed a kernel-level `Message` primitive
//! carrying arbitrary `Bytes`. The Part-2 audit flagged this as an
//! unbounded DoS vector against the substrate: at 1KB × 1000 msgs/block
//! × multi-year retention, message payload dominates state storage.
//!
//! This module commits to a **size-capped** variant of the primitive
//! that is safe to declare as a kernel type without creating the DoS
//! surface. Larger payloads (manuscript scans, datasets, PDFs) must be
//! carried off-chain and **referenced** by content hash through
//! `ReferenceLink` — the kernel stores only the hash + metadata, not
//! the body.

use serde::{Deserialize, Serialize};

use crate::validator_set::{Ed25519PublicKey, Ed25519Signature};
use crate::{AgentId, Hash};

/// Hard cap on message body bytes (1 KiB). A Message with a larger
/// body is structurally invalid; the caller must externalize the
/// payload and reference it via `ReferenceLink`.
///
/// Rationale (Patch-07 §D.1): every Message byte is paid for forever
/// in H's retention cost. Without an in-type cap, a single
/// mis-configured adapter can inflate substrate storage by orders of
/// magnitude before governance can react. 1 KiB accommodates typed
/// headers, small structured payloads, and short human-readable
/// subjects; anything larger externalizes.
pub const MAX_MESSAGE_BODY_BYTES: usize = 1024;

/// Domain separator for Message canonical hash. MUST NOT collide.
pub const MESSAGE_DOMAIN_SEPARATOR: &[u8] = b"sccgub-message-v7";

/// Recipient of a Message. Three cases per the refined-thesis spec:
/// a specific `Identity`, a `Role` name (interpreted by adapters), or
/// `Broadcast` for domain-public messages.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MessageRecipient {
    Identity(AgentId),
    /// Role name, adapter-interpreted. Capped at 64 bytes — role names
    /// are enum-like identifiers, not free-form strings.
    Role(String),
    Broadcast,
}

/// Maximum role-name byte length. Roles are identifiers, not
/// user-facing strings.
pub const MAX_ROLE_NAME_BYTES: usize = 64;

/// Patch-07 §D.1 Message primitive.
///
/// Canonical bincode field order: `domain_id, from, to, subject,
/// body, causal_anchor, nonce, signer, signature`. `signer` and
/// `signature` are excluded from the canonical hash (they are bound
/// by the signature itself, not by the id).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Message {
    /// Domain this message belongs to. Used for namespace-scoping when
    /// adapters are introduced; for now, an opaque id.
    pub domain_id: Hash,
    pub from: AgentId,
    pub to: MessageRecipient,
    /// Subject is a schema-id (not free-form text). 32-byte hash of
    /// the adapter's schema identifier.
    pub subject: Hash,
    /// Body bytes. MUST satisfy `body.len() <= MAX_MESSAGE_BODY_BYTES`.
    pub body: Vec<u8>,
    /// Causal anchors: transitions or messages this message causally
    /// depends on. Bounded at 16 anchors — a message with more than
    /// 16 direct causal parents is structurally suspicious.
    pub causal_anchor: Vec<Hash>,
    /// Per-sender monotonic nonce (prevents replay).
    pub nonce: u64,
    pub signer: Ed25519PublicKey,
    pub signature: Ed25519Signature,
}

/// Hard cap on per-message causal anchors. Beyond this, messages must
/// reference their history via `ReferenceLink` aggregation.
pub const MAX_MESSAGE_CAUSAL_ANCHORS: usize = 16;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum MessageValidationError {
    #[error("body size {size} exceeds MAX_MESSAGE_BODY_BYTES ({max})")]
    BodyTooLarge { size: usize, max: usize },
    #[error("role name length {size} exceeds MAX_ROLE_NAME_BYTES ({max})")]
    RoleNameTooLarge { size: usize, max: usize },
    #[error("causal anchor count {count} exceeds MAX_MESSAGE_CAUSAL_ANCHORS ({max})")]
    TooManyCausalAnchors { count: usize, max: usize },
    #[error("duplicate causal anchor: {0:?}")]
    DuplicateCausalAnchor(Hash),
}

impl Message {
    /// Canonical bytes to be signed. Excludes `signer` and `signature`
    /// so signature malleability cannot affect the message id.
    pub fn canonical_message_bytes(&self) -> Vec<u8> {
        bincode::serialize(&(
            &self.domain_id,
            &self.from,
            &self.to,
            &self.subject,
            &self.body,
            &self.causal_anchor,
            self.nonce,
        ))
        .expect("Message canonical_message_bytes serialization is infallible")
    }

    /// Signing bytes with domain separator prepended. Use with
    /// `sign` / `verify_strict`.
    pub fn signing_bytes(&self) -> Vec<u8> {
        let canonical = self.canonical_message_bytes();
        let mut out = Vec::with_capacity(MESSAGE_DOMAIN_SEPARATOR.len() + canonical.len());
        out.extend_from_slice(MESSAGE_DOMAIN_SEPARATOR);
        out.extend_from_slice(&canonical);
        out
    }

    /// Deterministic message id: `BLAKE3(domain || canonical_bytes)`.
    /// Excludes signature; two signatures over the same payload yield
    /// the same id.
    pub fn message_id(&self) -> Hash {
        let mut hasher = blake3::Hasher::new();
        hasher.update(MESSAGE_DOMAIN_SEPARATOR);
        hasher.update(&self.canonical_message_bytes());
        *hasher.finalize().as_bytes()
    }

    /// Enforce INV-MESSAGE-RETENTION-PAID constraints. Must pass
    /// before admission to any adapter.
    pub fn validate_structural(&self) -> Result<(), MessageValidationError> {
        if self.body.len() > MAX_MESSAGE_BODY_BYTES {
            return Err(MessageValidationError::BodyTooLarge {
                size: self.body.len(),
                max: MAX_MESSAGE_BODY_BYTES,
            });
        }
        if let MessageRecipient::Role(r) = &self.to {
            if r.len() > MAX_ROLE_NAME_BYTES {
                return Err(MessageValidationError::RoleNameTooLarge {
                    size: r.len(),
                    max: MAX_ROLE_NAME_BYTES,
                });
            }
        }
        if self.causal_anchor.len() > MAX_MESSAGE_CAUSAL_ANCHORS {
            return Err(MessageValidationError::TooManyCausalAnchors {
                count: self.causal_anchor.len(),
                max: MAX_MESSAGE_CAUSAL_ANCHORS,
            });
        }
        // Anchors must be unique — duplicates indicate author error
        // or a replay-across-messages pattern that should not canonicalize.
        let mut seen = std::collections::BTreeSet::new();
        for anchor in &self.causal_anchor {
            if !seen.insert(*anchor) {
                return Err(MessageValidationError::DuplicateCausalAnchor(*anchor));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mk(body_bytes: usize) -> Message {
        Message {
            domain_id: [0x11; 32],
            from: [0x22; 32],
            to: MessageRecipient::Identity([0x33; 32]),
            subject: [0x44; 32],
            body: vec![0xAB; body_bytes],
            causal_anchor: vec![],
            nonce: 1,
            signer: [0x55; 32],
            signature: vec![0x66; 64],
        }
    }

    #[test]
    fn patch_07_message_under_cap_validates() {
        let m = mk(512);
        m.validate_structural().unwrap();
    }

    #[test]
    fn patch_07_message_at_cap_validates() {
        let m = mk(MAX_MESSAGE_BODY_BYTES);
        m.validate_structural().unwrap();
    }

    #[test]
    fn patch_07_message_over_cap_rejected() {
        let m = mk(MAX_MESSAGE_BODY_BYTES + 1);
        assert!(matches!(
            m.validate_structural(),
            Err(MessageValidationError::BodyTooLarge { .. })
        ));
    }

    #[test]
    fn patch_07_role_over_cap_rejected() {
        let mut m = mk(0);
        m.to = MessageRecipient::Role("a".repeat(MAX_ROLE_NAME_BYTES + 1));
        assert!(matches!(
            m.validate_structural(),
            Err(MessageValidationError::RoleNameTooLarge { .. })
        ));
    }

    #[test]
    fn patch_07_too_many_causal_anchors_rejected() {
        let mut m = mk(0);
        m.causal_anchor = (0..(MAX_MESSAGE_CAUSAL_ANCHORS as u8 + 1))
            .map(|i| [i; 32])
            .collect();
        assert!(matches!(
            m.validate_structural(),
            Err(MessageValidationError::TooManyCausalAnchors { .. })
        ));
    }

    #[test]
    fn patch_07_duplicate_causal_anchor_rejected() {
        let mut m = mk(0);
        m.causal_anchor = vec![[0xAA; 32], [0xAA; 32]];
        assert!(matches!(
            m.validate_structural(),
            Err(MessageValidationError::DuplicateCausalAnchor(_))
        ));
    }

    #[test]
    fn patch_07_message_id_excludes_signature() {
        let mut m1 = mk(100);
        let mut m2 = m1.clone();
        m2.signature = vec![0xFF; 64];
        m2.signer = [0xEE; 32];
        // Different signature → same id (signature is excluded from canonical).
        // Note signer IS in canonical per spec; mutate only signature.
        m1.signer = m2.signer;
        assert_eq!(m1.message_id(), m2.message_id());
    }

    #[test]
    fn patch_07_message_id_changes_on_body_change() {
        let m1 = mk(100);
        let mut m2 = m1.clone();
        m2.body[0] ^= 0xFF;
        assert_ne!(m1.message_id(), m2.message_id());
    }

    #[test]
    fn patch_07_signing_bytes_start_with_domain_separator() {
        let m = mk(100);
        assert!(m.signing_bytes().starts_with(MESSAGE_DOMAIN_SEPARATOR));
    }

    #[test]
    fn patch_07_domain_separator_matches_spec() {
        assert_eq!(MESSAGE_DOMAIN_SEPARATOR, b"sccgub-message-v7");
    }

    #[test]
    fn patch_07_broadcast_recipient_valid() {
        let mut m = mk(0);
        m.to = MessageRecipient::Broadcast;
        m.validate_structural().unwrap();
    }
}
