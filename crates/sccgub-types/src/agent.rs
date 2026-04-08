use serde::{Deserialize, Serialize};
use std::collections::HashSet;

use crate::governance::PrecedenceLevel;
use crate::mfidel::MfidelAtomicSeal;
use crate::tension::TensionValue;
use crate::{AgentId, Hash, NormId, TransitionId};

/// Agent identity on the chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentIdentity {
    /// agent_id = Hash(public_key ++ mfidel_seal).
    pub agent_id: AgentId,
    /// Ed25519 public key (32 bytes).
    pub public_key: [u8; 32],
    /// Mfidel atomic seal for symbolic identity.
    pub mfidel_seal: MfidelAtomicSeal,
    /// Block height at which the agent was registered.
    pub registration_block: u64,
    /// Governance level of this agent.
    pub governance_level: PrecedenceLevel,
    /// Set of norms this agent is bound by.
    pub norm_set: HashSet<NormId>,
    /// Responsibility state (causal gradient, not reputation score).
    pub responsibility: ResponsibilityState,
}

/// Responsibility state per Φ²-R — causal contribution tracking.
/// Per v2.1: |Σ R_i_net| <= R_max_imbalance (enforceable invariant).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponsibilityState {
    /// Stabilizing contributions.
    pub positive_contributions: Vec<ResponsibilityEntry>,
    /// Destabilizing contributions.
    pub negative_contributions: Vec<ResponsibilityEntry>,
    /// R_pos - R_neg.
    pub net_responsibility: TensionValue,
    /// Consistency of valid transitions.
    pub reliability_score: TensionValue,
    /// Adherence to active norms.
    pub norm_compliance_score: TensionValue,
    /// Temporal decay factor λ.
    pub decay_factor: TensionValue,
}

impl Default for ResponsibilityState {
    fn default() -> Self {
        Self {
            positive_contributions: Vec::new(),
            negative_contributions: Vec::new(),
            net_responsibility: TensionValue::ZERO,
            reliability_score: TensionValue::from_integer(1),
            norm_compliance_score: TensionValue::from_integer(1),
            decay_factor: TensionValue(TensionValue::SCALE / 10), // 0.1
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponsibilityEntry {
    pub transition_id: TransitionId,
    pub r_value: TensionValue,
    pub block_height: u64,
}

/// Node types in the network.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NodeType {
    /// Produces blocks, executes Φ traversal.
    Validator,
    /// Verifies proofs, maintains state, read-only.
    Observer,
    /// Submits transitions, receives state.
    Agent,
    /// Proposes norm/constraint changes.
    Governance,
    /// Maintains full causal history.
    Archive,
}

/// Validator authority for consensus participation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorAuthority {
    pub node_id: Hash,
    pub governance_level: PrecedenceLevel,
    pub norm_compliance: TensionValue,
    pub causal_reliability: TensionValue,
    pub active: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_responsibility_state_default() {
        let state = ResponsibilityState::default();
        assert_eq!(state.net_responsibility, TensionValue::ZERO);
        assert_eq!(state.reliability_score, TensionValue::from_integer(1));
        assert!(state.positive_contributions.is_empty());
        assert!(state.negative_contributions.is_empty());
    }

    #[test]
    fn test_agent_identity_serialization() {
        let agent = AgentIdentity {
            agent_id: [1u8; 32],
            public_key: [2u8; 32],
            mfidel_seal: MfidelAtomicSeal::from_height(0),
            registration_block: 100,
            governance_level: PrecedenceLevel::Meaning,
            norm_set: HashSet::new(),
            responsibility: ResponsibilityState::default(),
        };
        let json = serde_json::to_string(&agent).unwrap();
        let recovered: AgentIdentity = serde_json::from_str(&json).unwrap();
        assert_eq!(recovered.agent_id, [1u8; 32]);
        assert_eq!(recovered.registration_block, 100);
    }

    #[test]
    fn test_node_type_variants() {
        let types = [
            NodeType::Validator,
            NodeType::Observer,
            NodeType::Agent,
            NodeType::Governance,
            NodeType::Archive,
        ];
        assert_eq!(types.len(), 5);
        assert_ne!(NodeType::Validator, NodeType::Observer);
    }

    #[test]
    fn test_validator_authority_active() {
        let auth = ValidatorAuthority {
            node_id: [1u8; 32],
            governance_level: PrecedenceLevel::Safety,
            norm_compliance: TensionValue::from_integer(1),
            causal_reliability: TensionValue::from_integer(1),
            active: true,
        };
        assert!(auth.active);
    }
}
