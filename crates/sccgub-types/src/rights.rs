use serde::{Deserialize, Serialize};

use crate::artifact::ArtifactId;
use crate::{AgentId, Hash};

/// Rights and licensing — who may do what with which artifact.
///
/// Invariant: no grant may exceed the grantor's current rights.
/// Every grant is either revocable or explicitly irrevocable.

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ArtifactAction {
    View,
    Derive,
    Reconstruct,
    Infer,
    Export,
    Deliver,
    Share,
    Sublicense,
    Retain,
    Delete,
    Redact,
}

/// An access grant — specific actions on a specific artifact.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessGrant {
    pub grant_id: Hash,
    pub artifact_id: ArtifactId,
    pub grantee: AgentId,
    pub actions: Vec<ArtifactAction>,
    /// Optional hash of the purpose/justification document.
    pub purpose_hash: Option<Hash>,
    pub valid_from_block: u64,
    pub valid_to_block: Option<u64>,
    pub revocable: bool,
    pub revoked: bool,
    pub granted_by: AgentId,
}

impl AccessGrant {
    pub fn is_active(&self, current_height: u64) -> bool {
        !self.revoked
            && current_height >= self.valid_from_block
            && self.valid_to_block.is_none_or(|exp| current_height <= exp)
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.artifact_id == [0u8; 32] {
            return Err("artifact_id is required".into());
        }
        if self.grantee == [0u8; 32] {
            return Err("grantee is required".into());
        }
        if self.granted_by == [0u8; 32] {
            return Err("granted_by is required".into());
        }
        if self.actions.is_empty() {
            return Err("at least one action is required".into());
        }
        if self.grantee == self.granted_by {
            return Err("cannot grant access to self".into());
        }
        Ok(())
    }
}

/// A usage license — broader commercial/legal terms.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsageLicense {
    pub license_id: Hash,
    pub artifact_id: ArtifactId,
    pub licensor: AgentId,
    pub licensee: AgentId,
    /// Hash of the full legal terms document (off-chain).
    pub terms_hash: Hash,
    pub exclusivity: bool,
    pub transfer_allowed: bool,
    pub sublicense_allowed: bool,
    pub expires_at_block: Option<u64>,
    pub revoked: bool,
}

impl UsageLicense {
    pub fn validate(&self) -> Result<(), String> {
        if self.artifact_id == [0u8; 32] {
            return Err("artifact_id is required".into());
        }
        if self.licensor == [0u8; 32] {
            return Err("licensor is required".into());
        }
        if self.licensee == [0u8; 32] {
            return Err("licensee is required".into());
        }
        if self.licensor == self.licensee {
            return Err("cannot license to self".into());
        }
        if self.terms_hash == [0u8; 32] {
            return Err("terms_hash is required".into());
        }
        Ok(())
    }
}

/// Policy verdict on an artifact — governance bridge.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PolicyVerdict {
    Allow,
    Deny,
    Quarantine,
    Redact,
    HumanReview,
}

/// Policy verdict receipt — a signed governance decision about an artifact.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyVerdictReceipt {
    pub receipt_id: Hash,
    pub artifact_id: ArtifactId,
    pub verdict: PolicyVerdict,
    pub policy_set_id: Hash,
    pub reason_codes: Vec<String>,
    /// Hash of the full evidence bundle (off-chain).
    pub evidence_root: Hash,
    pub issued_by: AgentId,
    /// If this verdict supersedes a prior one, reference it.
    pub supersedes: Option<Hash>,
    pub block_height: u64,
    pub signature: Vec<u8>,
}

impl PolicyVerdictReceipt {
    pub fn validate(&self) -> Result<(), String> {
        if self.artifact_id == [0u8; 32] {
            return Err("artifact_id is required".into());
        }
        if self.issued_by == [0u8; 32] {
            return Err("authority (issued_by) is required".into());
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

    #[test]
    fn test_access_grant_active() {
        let grant = AccessGrant {
            grant_id: [1u8; 32],
            artifact_id: [2u8; 32],
            grantee: [3u8; 32],
            actions: vec![ArtifactAction::View],
            purpose_hash: None,
            valid_from_block: 10,
            valid_to_block: Some(100),
            revocable: true,
            revoked: false,
            granted_by: [4u8; 32],
        };

        assert!(!grant.is_active(5)); // Too early.
        assert!(grant.is_active(50)); // In range.
        assert!(!grant.is_active(101)); // Expired.
    }

    #[test]
    fn test_revoked_grant_inactive() {
        let grant = AccessGrant {
            grant_id: [1u8; 32],
            artifact_id: [2u8; 32],
            grantee: [3u8; 32],
            actions: vec![ArtifactAction::View],
            purpose_hash: None,
            valid_from_block: 0,
            valid_to_block: None,
            revocable: true,
            revoked: true,
            granted_by: [4u8; 32],
        };
        assert!(!grant.is_active(50));
    }

    #[test]
    fn test_self_grant_rejected() {
        let grant = AccessGrant {
            grant_id: [1u8; 32],
            artifact_id: [2u8; 32],
            grantee: [3u8; 32],
            actions: vec![ArtifactAction::View],
            purpose_hash: None,
            valid_from_block: 0,
            valid_to_block: None,
            revocable: true,
            revoked: false,
            granted_by: [3u8; 32], // Same as grantee.
        };
        assert!(grant.validate().is_err());
    }

    #[test]
    fn test_empty_actions_rejected() {
        let grant = AccessGrant {
            grant_id: [1u8; 32],
            artifact_id: [2u8; 32],
            grantee: [3u8; 32],
            actions: vec![],
            purpose_hash: None,
            valid_from_block: 0,
            valid_to_block: None,
            revocable: true,
            revoked: false,
            granted_by: [4u8; 32],
        };
        assert!(grant.validate().is_err());
    }

    #[test]
    fn test_policy_verdict_missing_sig_rejected() {
        let receipt = PolicyVerdictReceipt {
            receipt_id: [1u8; 32],
            artifact_id: [2u8; 32],
            verdict: PolicyVerdict::Allow,
            policy_set_id: [3u8; 32],
            reason_codes: vec![],
            evidence_root: [4u8; 32],
            issued_by: [5u8; 32],
            supersedes: None,
            block_height: 100,
            signature: vec![], // Empty.
        };
        assert!(receipt.validate().is_err());
    }
}
