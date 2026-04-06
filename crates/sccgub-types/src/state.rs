use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

use crate::agent::AgentIdentity;
use crate::contract::SymbolicCausalContract;
use crate::governance::GovernanceState;
use crate::tension::TensionField;
use crate::{AgentId, ConstraintId, ContractId, Hash, SymbolAddress};

/// World state — the entire chain state at a given block height.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct WorldState {
    /// Symbol-addressed state store.
    pub symbol_store: HashMap<SymbolAddress, SymbolState>,
    /// Agent registry.
    pub agent_registry: HashMap<AgentId, AgentIdentity>,
    /// Active constraints.
    pub constraint_set: HashSet<ConstraintId>,
    /// Tension field.
    pub tension_field: TensionField,
    /// Governance state.
    pub governance_state: GovernanceState,
    /// Contract registry.
    pub contract_registry: HashMap<ContractId, SymbolicCausalContract>,
    /// Current block height.
    pub height: u64,
}

/// State of a symbol in the state trie.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SymbolState {
    pub address: SymbolAddress,
    pub data: Vec<u8>,
    pub owner: AgentId,
    pub version: u64,
    pub constraints: HashSet<ConstraintId>,
    pub causal_history: Vec<Hash>,
}

impl SymbolState {
    pub fn new(address: SymbolAddress, data: Vec<u8>, owner: AgentId) -> Self {
        Self {
            address,
            data,
            owner,
            version: 1,
            constraints: HashSet::new(),
            causal_history: Vec::new(),
        }
    }
}
