use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::governance::PrecedenceLevel;
use crate::transition::Constraint;
use crate::{AgentId, ContractId, TransitionId};

/// Symbolic Causal Contract — decidable constraint programs, not Turing-complete code.
/// Contracts terminate by construction (no halting problem, no gas estimation).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SymbolicCausalContract {
    /// Hash of the contract body.
    pub contract_id: ContractId,
    /// Immutable identity after deployment.
    pub name: String,
    /// The constraints this contract enforces.
    pub laws: Vec<Constraint>,
    /// Current contract state.
    pub state: HashMap<String, Vec<u8>>,
    /// Append-only lineage of transitions that modified this contract.
    pub history: Vec<TransitionId>,
    /// Who deployed this contract.
    pub deployer: AgentId,
    /// Minimum governance level required to modify laws.
    pub governance_level: PrecedenceLevel,
    /// Block height at deployment.
    pub deployed_at: u64,
}
