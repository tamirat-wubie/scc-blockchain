use serde::{Deserialize, Serialize};

use crate::artifact::{ArtifactId, MAX_STRING_LEN};
use crate::{AgentId, Hash};

/// Attestation — a signed claim about an artifact by an authority.
///
/// Binds: who did what to which artifact, when, with what software,
/// under what authority. Supports device, operator, pipeline, model,
/// and policy attestations.

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AttestationKind {
    Capture,
    Processing,
    Policy,
    Delivery,
    Redaction,
    Reconstruction,
    Inference,
    Verification,
    Notarization,
}

/// On-chain attestation record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactAttestation {
    pub attestation_id: Hash,
    pub kind: AttestationKind,
    pub artifact_id: ArtifactId,
    /// Who performed the action.
    pub subject: AgentId,
    /// Who authorized the attestation.
    pub authority: AgentId,
    /// Software/pipeline version string.
    pub software_version: String,
    /// Optional hash of environment/device claims.
    pub environment_hash: Option<Hash>,
    /// Hash of the full claims document (off-chain).
    pub claims_hash: Hash,
    /// Block height at which this attestation becomes valid.
    pub valid_from_block: u64,
    /// Block height at which this attestation expires (None = no expiry).
    pub valid_to_block: Option<u64>,
    /// Ed25519 signature over canonical attestation content.
    pub signature: Vec<u8>,
}

impl ArtifactAttestation {
    pub fn validate(&self) -> Result<(), String> {
        if self.attestation_id == [0u8; 32] {
            return Err("attestation_id is required".into());
        }
        if self.artifact_id == [0u8; 32] {
            return Err("artifact_id is required".into());
        }
        if self.claims_hash == [0u8; 32] {
            return Err("claims_hash is required".into());
        }
        if self.subject == [0u8; 32] {
            return Err("subject identity is required".into());
        }
        if self.authority == [0u8; 32] {
            return Err("authority identity is required".into());
        }
        if self.signature.is_empty() {
            return Err("signature is required".into());
        }
        if self.signature.len() < 64 {
            return Err("signature must be at least 64 bytes (Ed25519)".into());
        }
        // N-59: Ed25519 signatures are exactly 64 bytes.  Previously only a
        // minimum was enforced; a peer could gossip an attestation with a
        // 1 MiB signature field, pass validation, and have it committed
        // into a block forever.  128 bytes is twice the canonical length,
        // leaving room for future signature schemes while still closing the
        // unbounded-bloat vector.
        if self.signature.len() > 128 {
            return Err(format!(
                "signature too long: {} bytes (max 128)",
                self.signature.len()
            ));
        }
        if self.software_version.len() > MAX_STRING_LEN {
            return Err("software_version too long".into());
        }
        if let Some(end) = self.valid_to_block {
            if end < self.valid_from_block {
                return Err("valid_to_block must be >= valid_from_block".into());
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_attestation() -> ArtifactAttestation {
        ArtifactAttestation {
            attestation_id: [1u8; 32],
            kind: AttestationKind::Capture,
            artifact_id: [2u8; 32],
            subject: [3u8; 32],
            authority: [4u8; 32],
            software_version: "virecai-capture/1.0".into(),
            environment_hash: Some([5u8; 32]),
            claims_hash: [6u8; 32],
            valid_from_block: 100,
            valid_to_block: Some(200),
            signature: vec![0u8; 64],
        }
    }

    #[test]
    fn test_valid_attestation() {
        assert!(valid_attestation().validate().is_ok());
    }

    #[test]
    fn test_missing_signature_rejected() {
        let mut a = valid_attestation();
        a.signature = vec![];
        assert!(a.validate().is_err());
    }

    #[test]
    fn test_missing_authority_rejected() {
        let mut a = valid_attestation();
        a.authority = [0u8; 32];
        assert!(a.validate().is_err());
    }

    // N-59: Attestation signature upper bound.

    #[test]
    fn test_oversized_signature_rejected() {
        let mut a = valid_attestation();
        a.signature = vec![0u8; 129]; // > 128-byte cap
        let err = a.validate().unwrap_err();
        assert!(err.contains("signature too long"), "got: {}", err);
    }

    #[test]
    fn test_signature_at_upper_bound_accepted() {
        let mut a = valid_attestation();
        a.signature = vec![0u8; 128];
        assert!(a.validate().is_ok());
    }

    #[test]
    fn test_enormous_signature_rejected() {
        let mut a = valid_attestation();
        a.signature = vec![0u8; 1_000_000]; // 1 MiB attack
        assert!(a.validate().is_err());
    }
}
