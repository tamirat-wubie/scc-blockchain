use serde::{Deserialize, Serialize};

use crate::artifact::ArtifactId;
use crate::Hash;

/// Session and epoch — time-coherent batching for long-running workflows.
///
/// Avoids per-frame or per-packet on-chain spam.
/// Sessions support open → checkpoint → close lifecycle.
/// Epoch commits within a session are strictly monotonic.

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SessionState {
    Open,
    Checkpointed,
    Closed,
    Disputed,
}

/// Session commitment — a long-running workflow anchored on-chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionCommit {
    pub session_id: Hash,
    /// Root artifact this session produces/governs.
    pub root_artifact: ArtifactId,
    pub state: SessionState,
    pub start_block: u64,
    pub end_block: Option<u64>,
    /// Latest epoch index committed in this session.
    pub latest_epoch: u64,
    /// Merkle root of all commitments up to latest_epoch.
    pub latest_commitment_root: Hash,
}

impl SessionCommit {
    pub fn validate(&self) -> Result<(), String> {
        if self.session_id == [0u8; 32] {
            return Err("session_id is required".into());
        }
        if self.root_artifact == [0u8; 32] {
            return Err("root_artifact is required".into());
        }
        Ok(())
    }
}

/// Epoch commitment — a batch of events/artifacts within a session.
/// Epoch index must be strictly monotonic within a session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EpochCommit {
    pub epoch_id: Hash,
    pub session_id: Hash,
    /// Must be > previous epoch_index in the same session.
    pub epoch_index: u64,
    /// Merkle root of artifacts in this epoch.
    pub artifact_root: Hash,
    /// Merkle root of lineage edges in this epoch.
    pub lineage_root: Hash,
    /// Merkle root of policy verdicts in this epoch.
    pub policy_root: Hash,
    /// Number of events in this epoch.
    pub event_count: u64,
    /// Block height at which this epoch was committed.
    pub closed_at_block: u64,
}

impl EpochCommit {
    pub fn validate(&self, prev_epoch_index: u64) -> Result<(), String> {
        if self.session_id == [0u8; 32] {
            return Err("session_id is required".into());
        }
        if self.epoch_index == 0 {
            return Err("epoch_index must be >= 1".into());
        }
        if self.epoch_index <= prev_epoch_index {
            return Err(format!(
                "epoch_index {} must be > previous {}",
                self.epoch_index, prev_epoch_index
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_session() {
        let s = SessionCommit {
            session_id: [1u8; 32],
            root_artifact: [2u8; 32],
            state: SessionState::Open,
            start_block: 100,
            end_block: None,
            latest_epoch: 0,
            latest_commitment_root: [0u8; 32],
        };
        assert!(s.validate().is_ok());
    }

    #[test]
    fn test_epoch_monotonic() {
        let e = EpochCommit {
            epoch_id: [1u8; 32],
            session_id: [2u8; 32],
            epoch_index: 3,
            artifact_root: [3u8; 32],
            lineage_root: [4u8; 32],
            policy_root: [5u8; 32],
            event_count: 100,
            closed_at_block: 50,
        };
        assert!(e.validate(2).is_ok()); // 3 > 2.
        assert!(e.validate(3).is_err()); // 3 <= 3.
        assert!(e.validate(5).is_err()); // 3 <= 5.
    }

    #[test]
    fn test_epoch_zero_rejected() {
        let e = EpochCommit {
            epoch_id: [1u8; 32],
            session_id: [2u8; 32],
            epoch_index: 0,
            artifact_root: [3u8; 32],
            lineage_root: [4u8; 32],
            policy_root: [5u8; 32],
            event_count: 0,
            closed_at_block: 50,
        };
        assert!(e.validate(0).is_err());
    }
}
