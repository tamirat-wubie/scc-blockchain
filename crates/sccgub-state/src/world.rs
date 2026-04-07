use std::collections::HashMap;

use sccgub_types::state::{SymbolState, WorldState};
use sccgub_types::transition::StateDelta;
use sccgub_types::{AgentId, MerkleRoot, SymbolAddress, ZERO_HASH};

use crate::trie::StateTrie;

/// Maximum allowed key or value size (1 MB).
pub const MAX_STATE_ENTRY_SIZE: usize = 1_048_576;

/// Managed world state with an underlying Merkle trie and nonce tracking.
#[derive(Debug, Clone)]
pub struct ManagedWorldState {
    pub state: WorldState,
    pub trie: StateTrie,
    /// Per-agent nonce tracking for replay protection.
    pub agent_nonces: HashMap<AgentId, u128>,
}

impl ManagedWorldState {
    pub fn new() -> Self {
        Self {
            state: WorldState::default(),
            trie: StateTrie::new(),
            agent_nonces: HashMap::new(),
        }
    }

    /// Apply a state delta to the world state.
    /// Validates entry sizes to prevent memory exhaustion.
    pub fn apply_delta(&mut self, delta: &StateDelta) {
        for write in &delta.writes {
            // Enforce size limits.
            if write.address.len() > MAX_STATE_ENTRY_SIZE
                || write.value.len() > MAX_STATE_ENTRY_SIZE
            {
                continue; // Skip oversized entries.
            }
            self.trie
                .insert(write.address.clone(), write.value.clone());
            let symbol = self
                .state
                .symbol_store
                .entry(write.address.clone())
                .or_insert_with(|| SymbolState::new(write.address.clone(), Vec::new(), ZERO_HASH));
            symbol.data = write.value.clone();
            symbol.version = symbol.version.saturating_add(1);
        }
        for addr in &delta.deletes {
            self.trie.remove(addr);
            self.state.symbol_store.remove(addr);
        }
    }

    /// Check and update nonce for an agent.
    /// Nonce must be >= 1 and strictly greater than last seen.
    pub fn check_nonce(&mut self, agent_id: &AgentId, nonce: u128) -> Result<(), String> {
        if nonce == 0 {
            return Err("Nonce must be >= 1".into());
        }
        let last = self.agent_nonces.get(agent_id).copied().unwrap_or(0);
        if nonce <= last {
            return Err(format!(
                "Nonce replay: got {} but last seen was {} for agent {}",
                nonce, last, hex::encode(agent_id)
            ));
        }
        self.agent_nonces.insert(*agent_id, nonce);
        Ok(())
    }

    /// Get the current Merkle state root (uses cache if clean).
    pub fn state_root(&self) -> MerkleRoot {
        self.trie.root_readonly()
    }

    /// Read a value from the state.
    pub fn get(&self, address: &SymbolAddress) -> Option<&Vec<u8>> {
        self.trie.get(address)
    }

    /// Set the current block height.
    pub fn set_height(&mut self, height: u64) {
        self.state.height = height;
    }
}

impl Default for ManagedWorldState {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sccgub_types::transition::{StateDelta, StateWrite};

    #[test]
    fn test_apply_delta() {
        let mut ws = ManagedWorldState::new();
        let delta = StateDelta {
            writes: vec![StateWrite {
                address: b"key1".to_vec(),
                value: b"value1".to_vec(),
            }],
            deletes: vec![],
        };
        ws.apply_delta(&delta);
        assert_eq!(ws.get(&b"key1".to_vec()), Some(&b"value1".to_vec()));
    }

    #[test]
    fn test_state_root_changes() {
        let mut ws = ManagedWorldState::new();
        let root_before = ws.state_root();

        ws.apply_delta(&StateDelta {
            writes: vec![StateWrite {
                address: b"x".to_vec(),
                value: b"y".to_vec(),
            }],
            deletes: vec![],
        });

        assert_ne!(ws.state_root(), root_before);
    }
}
