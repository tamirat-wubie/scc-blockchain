use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashMap, VecDeque};

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
    pub constraint_set: BTreeSet<ConstraintId>,
    /// Tension field.
    pub tension_field: TensionField,
    /// Governance state.
    pub governance_state: GovernanceState,
    /// Contract registry.
    pub contract_registry: HashMap<ContractId, SymbolicCausalContract>,
    /// Current block height.
    pub height: u64,
}

/// Maximum causal history entries per symbol (ring buffer behavior).
pub const MAX_CAUSAL_HISTORY: usize = 256;

/// State of a symbol in the state trie.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SymbolState {
    pub address: SymbolAddress,
    pub data: Vec<u8>,
    pub owner: AgentId,
    pub version: u64,
    pub constraints: BTreeSet<ConstraintId>,
    pub causal_history: VecDeque<Hash>,
}

impl SymbolState {
    /// Append to causal history with bounded size. O(1) using VecDeque.
    pub fn push_history(&mut self, hash: Hash) {
        if self.causal_history.len() >= MAX_CAUSAL_HISTORY {
            self.causal_history.pop_front();
        }
        self.causal_history.push_back(hash);
    }
}

impl SymbolState {
    pub fn new(address: SymbolAddress, data: Vec<u8>, owner: AgentId) -> Self {
        Self {
            address,
            data,
            owner,
            version: 1,
            constraints: BTreeSet::new(),
            causal_history: VecDeque::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_push_history_appends() {
        let mut state = SymbolState::new(b"test".to_vec(), vec![], [0u8; 32]);
        let h1 = [1u8; 32];
        let h2 = [2u8; 32];
        state.push_history(h1);
        state.push_history(h2);
        assert_eq!(state.causal_history.len(), 2);
        assert_eq!(state.causal_history[0], h1);
        assert_eq!(state.causal_history[1], h2);
    }

    #[test]
    fn test_push_history_bounded_at_max() {
        let mut state = SymbolState::new(b"test".to_vec(), vec![], [0u8; 32]);
        // Fill to MAX_CAUSAL_HISTORY.
        for i in 0..MAX_CAUSAL_HISTORY {
            let mut h = [0u8; 32];
            h[0] = i as u8;
            h[1] = (i >> 8) as u8;
            state.push_history(h);
        }
        assert_eq!(state.causal_history.len(), MAX_CAUSAL_HISTORY);

        // Push one more — should evict the oldest.
        let overflow = [0xFFu8; 32];
        state.push_history(overflow);
        assert_eq!(state.causal_history.len(), MAX_CAUSAL_HISTORY);
        // First element should now be [1, 0, ...] (the second push).
        assert_eq!(state.causal_history[0][0], 1);
        // Last element should be the overflow hash.
        assert_eq!(*state.causal_history.back().unwrap(), overflow);
    }

    #[test]
    fn test_push_history_empty_then_push() {
        let mut state = SymbolState::new(b"addr".to_vec(), vec![42], [5u8; 32]);
        assert!(state.causal_history.is_empty());
        state.push_history([99u8; 32]);
        assert_eq!(state.causal_history.len(), 1);
    }
}
