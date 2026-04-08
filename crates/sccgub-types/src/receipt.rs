use serde::{Deserialize, Serialize};

use crate::causal::CausalEdge;
use crate::tension::TensionValue;
use crate::transition::WHBindingResolved;
use crate::{Hash, ObjectId, TransitionId};

/// Causal receipt — produced for every processed transition, including rejected ones.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CausalReceipt {
    pub tx_id: TransitionId,
    pub verdict: Verdict,
    pub pre_state_root: Hash,
    pub post_state_root: Hash,
    pub read_set: Vec<ObjectId>,
    pub write_set: Vec<ObjectId>,
    pub causes: Vec<CausalEdge>,
    pub resource_used: ResourceUsage,
    pub emitted_events: Vec<Event>,
    pub wh_binding: WHBindingResolved,
    /// How far Φ traversal got before the verdict (1-13).
    pub phi_phase_reached: u8,
    pub tension_delta: TensionValue,
}

/// Multi-judgment verdict per v2.0 spec.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Verdict {
    /// Transition valid, state committed.
    Accept,
    /// Transition invalid.
    Reject { reason: String },
    /// Valid but waiting for dependency.
    Defer { condition: String },
    /// Partial failure, compensation applied.
    Compensate { plan: String },
    /// Requires higher governance authority.
    Escalate { level: u8 },
}

impl std::fmt::Display for Verdict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Accept => write!(f, "Accept"),
            Self::Reject { reason } => write!(f, "Reject: {}", reason),
            Self::Defer { condition } => write!(f, "Defer: {}", condition),
            Self::Compensate { plan } => write!(f, "Compensate: {}", plan),
            Self::Escalate { level } => write!(f, "Escalate to level {}", level),
        }
    }
}

impl Verdict {
    pub fn is_accepted(&self) -> bool {
        matches!(self, Verdict::Accept)
    }
}

/// Resource usage tracking for a transition.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ResourceUsage {
    pub compute_steps: u64,
    pub state_reads: u32,
    pub state_writes: u32,
    pub proof_size_bytes: u64,
}

/// Event emitted by a transition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    pub event_type: String,
    pub data: Vec<u8>,
    pub source_tx: TransitionId,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verdict_is_accepted() {
        assert!(Verdict::Accept.is_accepted());
        assert!(!Verdict::Reject {
            reason: "bad".into()
        }
        .is_accepted());
        assert!(!Verdict::Defer {
            condition: "wait".into()
        }
        .is_accepted());
        assert!(!Verdict::Compensate { plan: "fix".into() }.is_accepted());
        assert!(!Verdict::Escalate { level: 1 }.is_accepted());
    }

    #[test]
    fn test_verdict_display() {
        assert_eq!(format!("{}", Verdict::Accept), "Accept");
        assert!(format!(
            "{}",
            Verdict::Reject {
                reason: "nonce".into()
            }
        )
        .contains("nonce"));
        assert!(format!("{}", Verdict::Escalate { level: 2 }).contains("2"));
    }

    #[test]
    fn test_resource_usage_default() {
        let r = ResourceUsage::default();
        assert_eq!(r.compute_steps, 0);
        assert_eq!(r.state_reads, 0);
        assert_eq!(r.state_writes, 0);
        assert_eq!(r.proof_size_bytes, 0);
    }

    #[test]
    fn test_verdict_serialization_roundtrip() {
        let v = Verdict::Reject {
            reason: "test failure".into(),
        };
        let json = serde_json::to_string(&v).unwrap();
        let recovered: Verdict = serde_json::from_str(&json).unwrap();
        assert!(!recovered.is_accepted());
    }
}
