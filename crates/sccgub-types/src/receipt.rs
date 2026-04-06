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
