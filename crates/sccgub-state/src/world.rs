use std::collections::HashMap;

use sccgub_types::consensus_params::ConsensusParams;
use sccgub_types::state::{SymbolState, WorldState};
use sccgub_types::transition::StateDelta;
use sccgub_types::{AgentId, MerkleRoot, SymbolAddress, ZERO_HASH};

use crate::store::StateStore;
use crate::trie::StateTrie;

/// Managed world state with an underlying Merkle trie and nonce tracking.
#[derive(Debug, Clone)]
pub struct ManagedWorldState {
    pub state: WorldState,
    pub trie: StateTrie,
    /// Per-agent nonce tracking for replay protection.
    pub agent_nonces: HashMap<AgentId, u128>,
    /// Consensus-critical parameters loaded from the genesis state root.
    /// Patch 03: replaces compile-time constants with chain-bound values.
    pub consensus_params: ConsensusParams,
}

impl ManagedWorldState {
    pub fn new() -> Self {
        Self {
            state: WorldState::default(),
            trie: StateTrie::new(),
            agent_nonces: HashMap::new(),
            consensus_params: ConsensusParams::default(),
        }
    }

    /// Construct with explicit consensus parameters (for migration / testing).
    pub fn with_consensus_params(params: ConsensusParams) -> Self {
        Self {
            state: WorldState::default(),
            trie: StateTrie::new(),
            agent_nonces: HashMap::new(),
            consensus_params: params,
        }
    }

    /// Construct with explicit consensus parameters and a durable state store.
    pub fn with_store_and_params(
        store: std::sync::Arc<dyn StateStore>,
        params: ConsensusParams,
    ) -> Result<Self, String> {
        Ok(Self {
            state: WorldState::default(),
            trie: StateTrie::with_store(store)?,
            agent_nonces: HashMap::new(),
            consensus_params: params,
        })
    }

    /// Bind a durable store to the trie and persist the current entries.
    pub fn bind_store(&mut self, store: std::sync::Arc<dyn StateStore>) -> Result<(), String> {
        for (key, value) in self.trie.iter() {
            store.put(key, value)?;
        }
        store.flush()?;
        self.trie = StateTrie::with_store(store)?;
        Ok(())
    }

    /// Apply a state delta to the world state.
    /// Rejects oversized entries (fail-closed, not silent skip).
    /// Returns list of rejected addresses.
    pub fn apply_delta(&mut self, delta: &StateDelta) -> Vec<SymbolAddress> {
        let mut rejected = Vec::new();
        let max_state_entry_size = self.consensus_params.max_state_entry_size as usize;
        for write in &delta.writes {
            if write.address.len() > max_state_entry_size
                || write.value.len() > max_state_entry_size
            {
                rejected.push(write.address.clone());
                continue;
            }
            self.trie.insert(write.address.clone(), write.value.clone());
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
        rejected
    }

    /// Check and update nonce for an agent.
    /// Nonce must be exactly last + 1 (strictly sequential, no gaps).
    /// This prevents nonce-gap attacks and ensures transaction ordering is deterministic.
    pub fn check_nonce(&mut self, agent_id: &AgentId, nonce: u128) -> Result<(), String> {
        if nonce == 0 {
            return Err("Nonce must be >= 1".into());
        }
        let last = self.agent_nonces.get(agent_id).copied().unwrap_or(0);
        let expected = last + 1;
        if nonce != expected {
            return Err(format!(
                "Nonce must be sequential: expected {}, got {} for agent {}",
                expected,
                nonce,
                hex::encode(agent_id)
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

/// Commit the chain-bound consensus parameters into the reserved system namespace.
pub fn commit_consensus_params(state: &mut ManagedWorldState) {
    state.apply_delta(&StateDelta {
        writes: vec![sccgub_types::transition::StateWrite {
            address: ConsensusParams::TRIE_KEY.to_vec(),
            value: state.consensus_params.to_canonical_bytes(),
        }],
        deletes: vec![],
    });
}

/// Load consensus parameters from trie storage when present.
pub fn consensus_params_from_trie(
    state: &ManagedWorldState,
) -> Result<Option<ConsensusParams>, String> {
    match state.get(&ConsensusParams::TRIE_KEY.to_vec()) {
        Some(bytes) => ConsensusParams::from_canonical_bytes(bytes).map(Some),
        None => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::SledStateStore;
    use sccgub_types::transition::{StateDelta, StateWrite};
    use std::sync::Arc;

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

    #[test]
    fn test_apply_delta_respects_consensus_param_max_state_entry_size() {
        let mut ws = ManagedWorldState::with_consensus_params(ConsensusParams {
            max_state_entry_size: 4,
            ..ConsensusParams::default()
        });
        let delta = StateDelta {
            writes: vec![StateWrite {
                address: b"oversized".to_vec(),
                value: b"ok".to_vec(),
            }],
            deletes: vec![],
        };

        let rejected = ws.apply_delta(&delta);

        assert_eq!(rejected, vec![b"oversized".to_vec()]);
        assert!(ws.get(&b"oversized".to_vec()).is_none());
        assert_eq!(ws.state_root(), ZERO_HASH);
    }

    #[test]
    fn test_commit_and_load_consensus_params_from_trie() {
        let params = ConsensusParams {
            default_tx_gas_limit: 1234,
            ..ConsensusParams::default()
        };
        let mut ws = ManagedWorldState::with_consensus_params(params.clone());

        commit_consensus_params(&mut ws);
        let loaded = consensus_params_from_trie(&ws)
            .expect("consensus params load should succeed")
            .expect("consensus params should be present");

        assert_eq!(loaded, params);
        assert_eq!(
            ws.get(&ConsensusParams::TRIE_KEY.to_vec()),
            Some(&params.to_canonical_bytes())
        );
        assert_ne!(ws.state_root(), ZERO_HASH);
    }

    #[test]
    fn test_bind_store_roundtrip() {
        let dir = std::env::temp_dir().join(format!("sccgub_state_bind_{}", std::process::id()));
        let store = Arc::new(SledStateStore::open(&dir).expect("store open"));

        let mut ws = ManagedWorldState::new();
        ws.apply_delta(&StateDelta {
            writes: vec![
                StateWrite {
                    address: b"alpha".to_vec(),
                    value: b"one".to_vec(),
                },
                StateWrite {
                    address: b"beta".to_vec(),
                    value: b"two".to_vec(),
                },
            ],
            deletes: vec![],
        });
        let root_before = ws.state_root();

        ws.bind_store(store.clone()).expect("bind store");
        let root_after = ws.state_root();
        assert_eq!(root_before, root_after);

        let restored = StateTrie::with_store(store).expect("reload store");
        assert_eq!(restored.root_readonly(), root_before);

        let _ = std::fs::remove_dir_all(&dir);
    }
}
