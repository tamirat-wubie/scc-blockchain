//! Patch-06 §30 authorized forgery-proof veto envelope.
//!
//! Before Patch-06, `sccgub-consensus::equivocation::check_forgery_proof`
//! performed the raw cryptographic malleability test but imposed no rule on
//! WHO could submit such a proof. If wired into a live admission path
//! without authorization, any party (including an adversary outside the
//! validator set) could veto a legitimate synthetic Remove during its
//! activation-delay window.
//!
//! §30 closes the gap by making `ForgeryVeto` the only admission-layer
//! vehicle for forgery-based veto. A `ForgeryVeto`:
//!
//! 1. Wraps the cryptographic `ForgeryProof` material in an owned form.
//! 2. Binds the proof to a specific `target_change_id` (the synthetic
//!    Remove being vetoed) at a specific submission height.
//! 3. Carries `≥ ⅓` voting-power of active-set attestations signed over a
//!    domain-separated canonical byte string.
//!
//! This module declares the wire types only. The admission predicate is in
//! `sccgub-execution::forgery_veto::validate_forgery_veto_admission`.

use serde::{Deserialize, Serialize};

use crate::validator_set::{Ed25519PublicKey, Ed25519Signature};
use crate::Hash;

/// Domain separator for §30 attestation signatures. MUST NOT collide with
/// any other signed-payload domain in the system.
pub const FORGERY_VETO_DOMAIN_SEPARATOR: &[u8] = b"sccgub-forgery-veto-v5";

/// Owned form of `sccgub-consensus::equivocation::ForgeryProof`. The
/// consensus-crate type holds slice references and is used for transient
/// in-function checks; this owned form travels across admission boundaries
/// and into canonical byte streams.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OwnedForgeryProof {
    pub canonical_bytes: Vec<u8>,
    pub public_key: Ed25519PublicKey,
    pub signature_a: Ed25519Signature,
    pub signature_b: Ed25519Signature,
}

/// A single validator attestation that the `ForgeryVeto` is well-formed.
/// Signed over `canonical_veto_bytes(...)` with `FORGERY_VETO_DOMAIN_SEPARATOR`
/// prepended.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VetoAttestation {
    pub signer: Ed25519PublicKey,
    pub signature: Ed25519Signature,
}

/// §30.2 admission envelope for a forgery-based veto of a synthetic Remove.
///
/// Canonical bincode field order: `proof, target_change_id,
/// submitted_at_height, attestations`. Attestations are sorted ascending
/// by `signer` public-key bytes so the canonical encoding is unique.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForgeryVeto {
    pub proof: OwnedForgeryProof,
    pub target_change_id: Hash,
    pub submitted_at_height: u64,
    pub attestations: Vec<VetoAttestation>,
}

impl ForgeryVeto {
    /// Canonical attestation-signed payload. Domain separator is NOT
    /// included here; callers MUST prepend `FORGERY_VETO_DOMAIN_SEPARATOR`
    /// before verifying or signing.
    pub fn canonical_veto_bytes(&self) -> Vec<u8> {
        bincode::serialize(&(
            &self.proof,
            &self.target_change_id,
            self.submitted_at_height,
        ))
        .expect("ForgeryVeto canonical_veto_bytes serialization is infallible")
    }

    /// Canonical bytes with domain separator prepended, suitable for
    /// `verify_strict` and `sign`.
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(FORGERY_VETO_DOMAIN_SEPARATOR.len() + 256);
        out.extend_from_slice(FORGERY_VETO_DOMAIN_SEPARATOR);
        out.extend_from_slice(&self.canonical_veto_bytes());
        out
    }

    /// Sort `attestations` ascending by `signer` and reject duplicate
    /// signers. Callers MUST canonicalize before submitting.
    pub fn canonicalize_attestations(&mut self) -> Result<(), ForgeryVetoError> {
        self.attestations.sort_by_key(|a| a.signer);
        for w in self.attestations.windows(2) {
            if w[0].signer == w[1].signer {
                return Err(ForgeryVetoError::DuplicateAttester(w[0].signer));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ForgeryVetoError {
    #[error("duplicate attester in forgery veto: {0:?}")]
    DuplicateAttester(Ed25519PublicKey),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_proof() -> OwnedForgeryProof {
        OwnedForgeryProof {
            canonical_bytes: b"test message".to_vec(),
            public_key: [0x11u8; 32],
            signature_a: vec![0xAA; 64],
            signature_b: vec![0xBB; 64],
        }
    }

    #[test]
    fn patch_06_canonical_veto_bytes_deterministic() {
        let v = ForgeryVeto {
            proof: dummy_proof(),
            target_change_id: [0xCC; 32],
            submitted_at_height: 42,
            attestations: vec![],
        };
        // Same envelope → same bytes twice.
        assert_eq!(v.canonical_veto_bytes(), v.canonical_veto_bytes());
    }

    #[test]
    fn patch_06_signing_bytes_include_domain_separator() {
        let v = ForgeryVeto {
            proof: dummy_proof(),
            target_change_id: [0xCC; 32],
            submitted_at_height: 42,
            attestations: vec![],
        };
        let signed = v.signing_bytes();
        assert!(signed.starts_with(FORGERY_VETO_DOMAIN_SEPARATOR));
    }

    #[test]
    fn patch_06_domain_separator_matches_spec() {
        // §30.3 spec declares the exact byte string. A regression here is
        // a chain-break and must be caught at compile time.
        assert_eq!(FORGERY_VETO_DOMAIN_SEPARATOR, b"sccgub-forgery-veto-v5");
    }

    #[test]
    fn patch_06_canonicalize_sorts_attestations() {
        let mut v = ForgeryVeto {
            proof: dummy_proof(),
            target_change_id: [0xCC; 32],
            submitted_at_height: 42,
            attestations: vec![
                VetoAttestation {
                    signer: [0x03; 32],
                    signature: vec![1; 64],
                },
                VetoAttestation {
                    signer: [0x01; 32],
                    signature: vec![2; 64],
                },
                VetoAttestation {
                    signer: [0x02; 32],
                    signature: vec![3; 64],
                },
            ],
        };
        v.canonicalize_attestations().unwrap();
        assert_eq!(v.attestations[0].signer, [0x01; 32]);
        assert_eq!(v.attestations[1].signer, [0x02; 32]);
        assert_eq!(v.attestations[2].signer, [0x03; 32]);
    }

    #[test]
    fn patch_06_canonicalize_rejects_duplicate_signer() {
        let mut v = ForgeryVeto {
            proof: dummy_proof(),
            target_change_id: [0xCC; 32],
            submitted_at_height: 42,
            attestations: vec![
                VetoAttestation {
                    signer: [0x01; 32],
                    signature: vec![1; 64],
                },
                VetoAttestation {
                    signer: [0x01; 32],
                    signature: vec![2; 64],
                },
            ],
        };
        assert!(matches!(
            v.canonicalize_attestations(),
            Err(ForgeryVetoError::DuplicateAttester(_))
        ));
    }

    #[test]
    fn patch_06_veto_roundtrip_via_bincode() {
        let v = ForgeryVeto {
            proof: dummy_proof(),
            target_change_id: [0xCC; 32],
            submitted_at_height: 42,
            attestations: vec![VetoAttestation {
                signer: [0x01; 32],
                signature: vec![9; 64],
            }],
        };
        let bytes = bincode::serialize(&v).unwrap();
        let back: ForgeryVeto = bincode::deserialize(&bytes).unwrap();
        assert_eq!(v, back);
    }
}
