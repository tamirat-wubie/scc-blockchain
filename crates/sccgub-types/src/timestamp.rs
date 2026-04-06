use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use crate::{Hash, NodeId, ZERO_HASH};

/// Causal timestamp — ordering by causal dependency, not wall-clock.
/// Per v2.1 FIX-1: uses `parent_timestamp_hash` (Hash) instead of recursive embedding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CausalTimestamp {
    /// Lamport logical clock counter.
    pub lamport_counter: u64,
    /// Bounded vector clock tracking active nodes.
    pub vector_clock: BoundedVectorClock,
    /// Causal depth (longest causal chain length to this point).
    pub causal_depth: u32,
    /// Advisory wall-clock hint (not authoritative for ordering).
    pub wall_hint: u64,
    /// Hash of the parent block's CausalTimestamp (not recursive embedding).
    pub parent_timestamp_hash: Hash,
}

impl CausalTimestamp {
    /// Create genesis timestamp.
    pub fn genesis() -> Self {
        Self {
            lamport_counter: 0,
            vector_clock: BoundedVectorClock::new(256),
            causal_depth: 0,
            wall_hint: 0,
            parent_timestamp_hash: ZERO_HASH,
        }
    }

    /// Create a successor timestamp from a parent.
    pub fn successor(&self, node_id: NodeId, parent_hash: Hash) -> Self {
        let mut vc = self.vector_clock.clone();
        vc.increment(node_id);
        Self {
            lamport_counter: self.lamport_counter + 1,
            vector_clock: vc,
            causal_depth: self.causal_depth + 1,
            wall_hint: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            parent_timestamp_hash: parent_hash,
        }
    }
}

/// Bounded vector clock per v2.1 FIX-1.
/// Only tracks nodes active within recent epochs; prunes inactive entries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BoundedVectorClock {
    /// Sorted entries: NodeId → (counter, last_active_epoch).
    pub entries: BTreeMap<NodeId, VectorClockEntry>,
    /// Maximum number of tracked nodes.
    pub max_size: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VectorClockEntry {
    pub counter: u64,
    pub last_active_epoch: u64,
}

impl BoundedVectorClock {
    pub fn new(max_size: u32) -> Self {
        Self {
            entries: BTreeMap::new(),
            max_size,
        }
    }

    /// Increment counter for a node, marking it active.
    pub fn increment(&mut self, node_id: NodeId) {
        let entry = self.entries.entry(node_id).or_insert(VectorClockEntry {
            counter: 0,
            last_active_epoch: 0,
        });
        entry.counter += 1;
        // Prune if over capacity: remove least recently active.
        if self.entries.len() as u32 > self.max_size {
            self.prune();
        }
    }

    /// Remove least recently active entries to stay within max_size.
    fn prune(&mut self) {
        while self.entries.len() as u32 > self.max_size {
            // Find the entry with the lowest last_active_epoch.
            if let Some((&oldest_id, _)) = self
                .entries
                .iter()
                .min_by_key(|(_, e)| e.last_active_epoch)
            {
                self.entries.remove(&oldest_id);
            } else {
                break;
            }
        }
    }

    /// Merge with another vector clock (component-wise max).
    pub fn merge(&mut self, other: &BoundedVectorClock) {
        for (&node_id, other_entry) in &other.entries {
            let entry = self.entries.entry(node_id).or_insert(VectorClockEntry {
                counter: 0,
                last_active_epoch: 0,
            });
            entry.counter = entry.counter.max(other_entry.counter);
            entry.last_active_epoch = entry.last_active_epoch.max(other_entry.last_active_epoch);
        }
        while self.entries.len() as u32 > self.max_size {
            self.prune();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_genesis_timestamp() {
        let ts = CausalTimestamp::genesis();
        assert_eq!(ts.lamport_counter, 0);
        assert_eq!(ts.causal_depth, 0);
        assert_eq!(ts.parent_timestamp_hash, ZERO_HASH);
    }

    #[test]
    fn test_successor() {
        let genesis = CausalTimestamp::genesis();
        let node_id = [1u8; 32];
        let parent_hash = [2u8; 32];
        let next = genesis.successor(node_id, parent_hash);
        assert_eq!(next.lamport_counter, 1);
        assert_eq!(next.causal_depth, 1);
        assert_eq!(next.parent_timestamp_hash, parent_hash);
    }

    #[test]
    fn test_bounded_vector_clock_prune() {
        let mut vc = BoundedVectorClock::new(2);
        vc.increment([1u8; 32]);
        vc.increment([2u8; 32]);
        vc.increment([3u8; 32]);
        assert!(vc.entries.len() <= 2);
    }
}
