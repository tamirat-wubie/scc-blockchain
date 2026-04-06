use sccgub_types::state::{SymbolState, WorldState};
use sccgub_types::transition::StateDelta;
use sccgub_types::{MerkleRoot, SymbolAddress, ZERO_HASH};

use crate::trie::StateTrie;

/// Managed world state with an underlying Merkle trie.
#[derive(Debug, Clone)]
pub struct ManagedWorldState {
    pub state: WorldState,
    pub trie: StateTrie,
}

impl ManagedWorldState {
    pub fn new() -> Self {
        Self {
            state: WorldState::default(),
            trie: StateTrie::new(),
        }
    }

    /// Apply a state delta to the world state.
    pub fn apply_delta(&mut self, delta: &StateDelta) {
        for write in &delta.writes {
            self.trie
                .insert(write.address.clone(), write.value.clone());
            let symbol = self
                .state
                .symbol_store
                .entry(write.address.clone())
                .or_insert_with(|| SymbolState::new(write.address.clone(), Vec::new(), ZERO_HASH));
            symbol.data = write.value.clone();
            symbol.version += 1;
        }
        for addr in &delta.deletes {
            self.trie.remove(addr);
            self.state.symbol_store.remove(addr);
        }
    }

    /// Get the current Merkle state root.
    pub fn state_root(&self) -> MerkleRoot {
        self.trie.root()
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
