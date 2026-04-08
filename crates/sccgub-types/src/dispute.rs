use serde::{Deserialize, Serialize};

use crate::artifact::ArtifactId;
use crate::{AgentId, Hash};

/// Dispute and challenge — on-chain arbitration primitives.
///
/// Once artifacts, rights, and settlement exist, someone will dispute
/// authenticity, rights, derivation, timing, or delivery.
/// This grammar makes disputes first-class chain objects.

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DisputeState {
    Open,
    EvidenceSubmitted,
    UnderReview,
    Resolved,
    Dismissed,
}

/// A dispute claim against an artifact or settlement.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DisputeClaim {
    pub dispute_id: Hash,
    pub target_artifact: ArtifactId,
    pub claimant: AgentId,
    pub reason_code: String,
    /// Hash of the evidence bundle (off-chain).
    pub evidence_hash: Hash,
    pub filed_at_block: u64,
    pub state: DisputeState,
    /// Block height after which the dispute auto-resolves if no action.
    pub challenge_window_end: u64,
}

impl DisputeClaim {
    pub fn validate(&self) -> Result<(), String> {
        if self.target_artifact == [0u8; 32] {
            return Err("target_artifact is required".into());
        }
        if self.claimant == [0u8; 32] {
            return Err("claimant is required".into());
        }
        if self.reason_code.is_empty() {
            return Err("reason_code is required".into());
        }
        if self.evidence_hash == [0u8; 32] {
            return Err("evidence_hash is required".into());
        }
        if self.challenge_window_end <= self.filed_at_block {
            return Err("challenge window must extend beyond filing block".into());
        }
        Ok(())
    }

    pub fn is_open(&self) -> bool {
        matches!(
            self.state,
            DisputeState::Open | DisputeState::EvidenceSubmitted | DisputeState::UnderReview
        )
    }
}

/// Resolution verdict for a dispute.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArbitrationVerdict {
    pub dispute_id: Hash,
    pub arbiter: AgentId,
    pub verdict_hash: Hash,
    pub in_favor_of: AgentId,
    /// Penalty applied to the losing party (if any).
    pub penalty_hash: Option<Hash>,
    pub resolved_at_block: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_dispute() -> DisputeClaim {
        DisputeClaim {
            dispute_id: [1u8; 32],
            target_artifact: [2u8; 32],
            claimant: [3u8; 32],
            reason_code: "unauthorized_derivation".into(),
            evidence_hash: [4u8; 32],
            filed_at_block: 100,
            state: DisputeState::Open,
            challenge_window_end: 200,
        }
    }

    #[test]
    fn test_valid_dispute() {
        assert!(valid_dispute().validate().is_ok());
    }

    #[test]
    fn test_missing_evidence_rejected() {
        let mut d = valid_dispute();
        d.evidence_hash = [0u8; 32];
        assert!(d.validate().is_err());
    }

    #[test]
    fn test_zero_window_rejected() {
        let mut d = valid_dispute();
        d.challenge_window_end = d.filed_at_block; // No window.
        assert!(d.validate().is_err());
    }

    #[test]
    fn test_is_open() {
        let d = valid_dispute();
        assert!(d.is_open());

        let mut resolved = valid_dispute();
        resolved.state = DisputeState::Resolved;
        assert!(!resolved.is_open());
    }
}
