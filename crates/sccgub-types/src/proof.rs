use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::tension::TensionValue;
use crate::transition::WHBindingResolved;
use crate::{ConstraintId, Hash, TransitionId};

/// Causal proof attached to each block.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CausalProof {
    pub block_height: u64,
    pub transitions_proven: Vec<TransitionProof>,
    pub phi_traversal_log: PhiTraversalLog,
    pub governance_snapshot_hash: Hash,
    pub tension_before: TensionValue,
    pub tension_after: TensionValue,
    pub constraint_map: HashMap<ConstraintId, bool>,
    pub recursion_depth: u32,
    pub validator_signature: Vec<u8>,
    /// Hash(parent_proof ++ transitions ++ governance).
    pub causal_hash: Hash,
}

/// Proof for an individual transition within a block.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransitionProof {
    pub transition_id: TransitionId,
    pub wh_binding: WHBindingResolved,
    pub precondition_results: Vec<(ConstraintId, bool)>,
    pub postcondition_results: Vec<(ConstraintId, bool)>,
    pub causal_ancestors: Vec<TransitionId>,
    pub state_delta_hash: Hash,
    pub governance_auth_level: u8,
    pub tension_contribution: TensionValue,
}

/// Log of the 13-phase Φ traversal.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PhiTraversalLog {
    pub phases_completed: Vec<PhiPhaseResult>,
    pub all_phases_passed: bool,
    pub total_phases: u8,
}

impl PhiTraversalLog {
    pub fn new() -> Self {
        Self {
            phases_completed: Vec::new(),
            all_phases_passed: false,
            total_phases: 13,
        }
    }
}

impl Default for PhiTraversalLog {
    fn default() -> Self {
        Self::new()
    }
}

/// Result of a single Φ phase.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PhiPhaseResult {
    pub phase: PhiPhase,
    pub passed: bool,
    pub details: String,
}

/// The 13 phases of Φ traversal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum PhiPhase {
    Distinction = 1,
    Constraint = 2,
    Ontology = 3,
    Topology = 4,
    Form = 5,
    Organization = 6,
    Module = 7,
    Execution = 8,
    Body = 9,
    Architecture = 10,
    Performance = 11,
    Feedback = 12,
    Evolution = 13,
}

impl PhiPhase {
    pub const ALL: [PhiPhase; 13] = [
        Self::Distinction,
        Self::Constraint,
        Self::Ontology,
        Self::Topology,
        Self::Form,
        Self::Organization,
        Self::Module,
        Self::Execution,
        Self::Body,
        Self::Architecture,
        Self::Performance,
        Self::Feedback,
        Self::Evolution,
    ];

    /// Phases that only run at block level (not per-transaction).
    pub fn is_block_only(self) -> bool {
        matches!(
            self,
            Self::Topology | Self::Body | Self::Architecture | Self::Performance
        )
    }

    /// Phases that run per-transaction.
    pub fn is_per_tx(self) -> bool {
        !self.is_block_only()
    }
}
