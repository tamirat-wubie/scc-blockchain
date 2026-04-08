use serde::{Deserialize, Serialize};

use crate::artifact::ArtifactId;
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
}
