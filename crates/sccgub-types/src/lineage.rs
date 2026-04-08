use serde::{Deserialize, Serialize};

use crate::artifact::ArtifactId;
use crate::{AgentId, Hash};

/// Lineage — typed derivation graph for external artifacts.
///
/// Every derived artifact MUST link to parents through typed edges.
/// Lineage is a graph, not free-form metadata.

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TransformType {
    Capture,
    Segment,
    Merge,
    Split,
    Reconstruct,
    Infer,
    Redact,
    Summarize,
    Transcode,
    Export,
    Deliver,
    Sign,
    Notarize,
    Custom,
}

/// A directed edge in the artifact lineage graph.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LineageEdge {
    pub edge_id: Hash,
    /// Parent artifact (source of derivation).
    pub parent: ArtifactId,
    /// Child artifact (result of derivation).
    pub child: ArtifactId,
    /// What transform produced the child from the parent.
    pub transform: TransformType,
    /// Who performed the transform.
    pub actor: AgentId,
    /// Optional hash of the transform proof/log.
    pub proof_hash: Option<Hash>,
    /// Block height at which this edge was recorded.
    pub created_at_block: u64,
}

impl LineageEdge {
    pub fn validate(&self) -> Result<(), String> {
        if self.parent == [0u8; 32] {
            return Err("parent artifact_id is required".into());
        }
        if self.child == [0u8; 32] {
            return Err("child artifact_id is required".into());
        }
        if self.parent == self.child {
            return Err("self-referencing lineage edge".into());
        }
        if self.actor == [0u8; 32] {
            return Err("actor is required".into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_lineage_edge() {
        let edge = LineageEdge {
            edge_id: [1u8; 32],
            parent: [2u8; 32],
            child: [3u8; 32],
            transform: TransformType::Reconstruct,
            actor: [4u8; 32],
            proof_hash: Some([5u8; 32]),
            created_at_block: 50,
        };
        assert!(edge.validate().is_ok());
    }

    #[test]
    fn test_self_referencing_rejected() {
        let edge = LineageEdge {
            edge_id: [1u8; 32],
            parent: [2u8; 32],
            child: [2u8; 32], // Same as parent.
            transform: TransformType::Infer,
            actor: [4u8; 32],
            proof_hash: None,
            created_at_block: 50,
        };
        assert!(edge.validate().is_err());
    }

    #[test]
    fn test_missing_actor_rejected() {
        let edge = LineageEdge {
            edge_id: [1u8; 32],
            parent: [2u8; 32],
            child: [3u8; 32],
            transform: TransformType::Export,
            actor: [0u8; 32],
            proof_hash: None,
            created_at_block: 50,
        };
        assert!(edge.validate().is_err());
    }
}
