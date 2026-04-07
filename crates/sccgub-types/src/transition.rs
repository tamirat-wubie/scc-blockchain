use serde::{Deserialize, Serialize};
use std::collections::HashSet;

use crate::agent::AgentIdentity;
use crate::governance::PrecedenceLevel;
use crate::timestamp::CausalTimestamp;
use crate::{ConstraintId, Hash, RuleId, SymbolAddress, TransitionId};

/// The fundamental unit of state change — a governed causal transition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SymbolicTransition {
    /// Hash of the transition content.
    pub tx_id: TransitionId,
    /// Who submits this transition.
    pub actor: AgentIdentity,
    /// What kind of transition.
    pub intent: TransitionIntent,
    /// Pre-execution constraints that must hold.
    pub preconditions: Vec<Constraint>,
    /// Post-execution constraints that must hold.
    pub postconditions: Vec<Constraint>,
    /// The state change payload.
    pub payload: OperationPayload,
    /// What caused this transition (causal ancestors).
    pub causal_chain: Vec<TransitionId>,
    /// WH-binding at submission (intent stage).
    pub wh_binding_intent: WHBindingIntent,
    /// Monotonic nonce for replay protection.
    pub nonce: u128,
    /// Ed25519 signature over the transition.
    pub signature: Vec<u8>,
}

/// What kind of state change this transition performs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransitionIntent {
    pub kind: TransitionKind,
    pub target: SymbolAddress,
    pub declared_purpose: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TransitionKind {
    StateWrite,
    StateRead,
    GovernanceUpdate,
    NormProposal,
    ConstraintAddition,
    AgentRegistration,
    DisputeResolution,
    AssetTransfer,
    ContractDeploy,
    ContractInvoke,
}

/// WHBinding split into intent and resolved per v2.1 FIX-7.
/// Intent stage: known at submission time.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WHBindingIntent {
    /// Who initiates.
    pub who: Hash,
    /// Causal ordering.
    pub when: CausalTimestamp,
    /// Which state region.
    pub r#where: SymbolAddress,
    /// Governance reason.
    pub why: CausalJustification,
    /// Execution path.
    pub how: TransitionMechanism,
    /// Which rules apply.
    pub which: HashSet<ConstraintId>,
    /// Declared intent (not actual delta — that comes after execution).
    pub what_declared: String,
}

impl WHBindingIntent {
    /// Check completeness — all fields must be non-empty.
    pub fn is_complete(&self) -> bool {
        self.who != [0u8; 32] && !self.r#where.is_empty() && !self.what_declared.is_empty()
    }
}

/// Resolved WHBinding — filled after execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WHBindingResolved {
    pub intent: WHBindingIntent,
    /// Actual state delta produced by execution.
    pub what_actual: StateDelta,
    /// Validation result.
    pub whether: ValidationResult,
}

/// Causal justification for why this transition should happen.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CausalJustification {
    pub invoking_rule: RuleId,
    pub precedence_level: PrecedenceLevel,
    pub causal_ancestors: Vec<TransitionId>,
    pub constraint_proof: Vec<ConstraintSatisfaction>,
}

/// How the transition is executed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TransitionMechanism {
    DirectStateWrite,
    ContractExecution { contract_id: Hash },
    GovernanceAction,
}

/// A constraint that must be satisfied.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Constraint {
    pub id: ConstraintId,
    pub expression: String,
}

/// Result of constraint satisfaction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConstraintSatisfaction {
    pub constraint_id: ConstraintId,
    pub satisfied: bool,
    pub evidence: Option<String>,
}

/// The actual state change performed by a transition.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StateDelta {
    pub writes: Vec<StateWrite>,
    pub deletes: Vec<SymbolAddress>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateWrite {
    pub address: SymbolAddress,
    pub value: Vec<u8>,
}

/// Validation result attached to a resolved WHBinding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ValidationResult {
    Valid,
    Invalid { reason: String },
}

/// Operation payload — the data being written/changed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum OperationPayload {
    /// Raw key-value write.
    Write { key: SymbolAddress, value: Vec<u8> },
    /// Asset transfer between agents.
    AssetTransfer {
        from: crate::AgentId,
        to: crate::AgentId,
        /// Amount as raw fixed-point i128 (TensionValue scale).
        /// Serialized as string to avoid JSON i128 limitations.
        #[serde(with = "crate::transition::i128_as_string")]
        amount: i128,
    },
    /// Agent registration data.
    RegisterAgent { public_key: [u8; 32] },
    /// Norm proposal.
    ProposeNorm { name: String, description: String },
    /// Contract deployment.
    DeployContract { code: Vec<u8> },
    /// Contract invocation.
    InvokeContract {
        contract_id: Hash,
        method: String,
        args: Vec<u8>,
    },
    /// No-op (for testing).
    Noop,
}

/// Custom serialization for i128 as string (JSON doesn't support i128 natively).
pub mod i128_as_string {
    use serde::{self, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(value: &i128, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&value.to_string())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<i128, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        s.parse::<i128>().map_err(serde::de::Error::custom)
    }
}
