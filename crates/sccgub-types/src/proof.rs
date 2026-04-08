use serde::{Deserialize, Serialize};

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
    pub constraint_results: Vec<(ConstraintId, bool)>,
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
    /// Stored for serialization; always recomputed via `is_all_passed()` for validation.
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

    /// Compute whether all phases passed (source of truth — don't trust stored field).
    pub fn is_all_passed(&self) -> bool {
        self.phases_completed.len() >= self.total_phases as usize
            && self.phases_completed.iter().all(|p| p.passed)
    }

    /// Finalize the log: set the stored field to match computed value.
    pub fn finalize(&mut self) {
        self.all_phases_passed = self.is_all_passed();
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

impl std::fmt::Display for PhiPhase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Distinction => write!(f, "Distinction"),
            Self::Constraint => write!(f, "Constraint"),
            Self::Ontology => write!(f, "Ontology"),
            Self::Topology => write!(f, "Topology"),
            Self::Form => write!(f, "Form"),
            Self::Organization => write!(f, "Organization"),
            Self::Module => write!(f, "Module"),
            Self::Execution => write!(f, "Execution"),
            Self::Body => write!(f, "Body"),
            Self::Architecture => write!(f, "Architecture"),
            Self::Performance => write!(f, "Performance"),
            Self::Feedback => write!(f, "Feedback"),
            Self::Evolution => write!(f, "Evolution"),
        }
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_phi_phase_all_13() {
        assert_eq!(PhiPhase::ALL.len(), 13);
    }

    #[test]
    fn test_phi_phase_display() {
        assert_eq!(format!("{}", PhiPhase::Distinction), "Distinction");
        assert_eq!(format!("{}", PhiPhase::Evolution), "Evolution");
    }

    #[test]
    fn test_phi_phase_block_only() {
        assert!(PhiPhase::Topology.is_block_only());
        assert!(PhiPhase::Body.is_block_only());
        assert!(PhiPhase::Architecture.is_block_only());
        assert!(PhiPhase::Performance.is_block_only());
        assert!(!PhiPhase::Distinction.is_block_only());
        assert!(!PhiPhase::Constraint.is_block_only());
    }

    #[test]
    fn test_phi_traversal_log_empty() {
        let log = PhiTraversalLog::new();
        assert!(!log.is_all_passed()); // No phases completed.
        assert_eq!(log.total_phases, 13);
    }

    #[test]
    fn test_phi_traversal_log_all_passed() {
        let mut log = PhiTraversalLog::new();
        for phase in PhiPhase::ALL {
            log.phases_completed.push(PhiPhaseResult {
                phase,
                passed: true,
                details: "ok".into(),
            });
        }
        assert!(log.is_all_passed());
        log.finalize();
        assert!(log.all_phases_passed);
    }

    #[test]
    fn test_phi_traversal_log_one_failed() {
        let mut log = PhiTraversalLog::new();
        for (i, phase) in PhiPhase::ALL.iter().enumerate() {
            log.phases_completed.push(PhiPhaseResult {
                phase: *phase,
                passed: i != 5, // Phase 6 (Organization) fails.
                details: "test".into(),
            });
        }
        assert!(!log.is_all_passed());
    }

    #[test]
    fn test_causal_proof_default_fields() {
        let proof = CausalProof {
            block_height: 0,
            transitions_proven: vec![],
            phi_traversal_log: PhiTraversalLog::default(),
            governance_snapshot_hash: [0u8; 32],
            tension_before: TensionValue::ZERO,
            tension_after: TensionValue::ZERO,
            constraint_results: vec![],
            recursion_depth: 0,
            validator_signature: vec![],
            causal_hash: [0u8; 32],
        };
        assert_eq!(proof.recursion_depth, 0);
        assert!(proof.transitions_proven.is_empty());
    }
}
