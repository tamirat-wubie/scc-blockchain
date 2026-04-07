use std::collections::{HashMap, HashSet, VecDeque};

use sccgub_execution::validate::validate_transition;
use sccgub_governance::containment::ContainmentState;
use sccgub_state::world::ManagedWorldState;
use sccgub_types::tension::TensionValue;
use sccgub_types::transition::SymbolicTransition;
use sccgub_types::Hash;

/// Transaction mempool with admission, dedup, validation, and containment.
pub struct Mempool {
    pending: VecDeque<SymbolicTransition>,
    seen_ids: HashSet<Hash>,
    confirmed_ids: HashSet<Hash>,
    max_size: usize,
    pub containment: ContainmentState,
}

impl Mempool {
    pub fn new(max_size: usize) -> Self {
        Self {
            pending: VecDeque::new(),
            seen_ids: HashSet::new(),
            confirmed_ids: HashSet::new(),
            max_size,
            containment: ContainmentState::default(),
        }
    }

    pub fn mark_confirmed(&mut self, ids: &[Hash]) {
        for id in ids {
            self.confirmed_ids.insert(*id);
        }
    }

    pub fn add(&mut self, tx: SymbolicTransition) -> Result<(), String> {
        let node_id = tx.actor.agent_id;
        if !self.containment.is_allowed(&node_id) {
            return Err("Agent is quarantined".into());
        }
        if self.seen_ids.contains(&tx.tx_id) {
            return Err("Duplicate transaction ID".into());
        }
        if self.confirmed_ids.contains(&tx.tx_id) {
            return Err("Transaction already included in a block".into());
        }
        if self.pending.len() >= self.max_size {
            if let Some(evicted) = self.pending.pop_front() {
                self.seen_ids.remove(&evicted.tx_id);
            }
        }
        self.seen_ids.insert(tx.tx_id);
        self.pending.push_back(tx);
        Ok(())
    }

    /// Drain validated transitions. Tracks nonces locally during drain to prevent
    /// same-agent duplicate nonces within a single block (fail-closed).
    pub fn drain_validated(&mut self, state: &ManagedWorldState) -> Vec<SymbolicTransition> {
        let mut validated = Vec::new();
        let mut to_remove: Vec<Hash> = Vec::new();
        // Track nonces locally during this drain to catch same-block duplicates.
        let mut local_nonces: HashMap<Hash, u128> = HashMap::new();

        for tx in &self.pending {
            let node_id = tx.actor.agent_id;

            // Check nonce against both committed state AND local tracking.
            let committed = state.agent_nonces.get(&node_id).copied().unwrap_or(0);
            let local = local_nonces.get(&node_id).copied().unwrap_or(committed);
            if tx.nonce == 0 || tx.nonce <= local {
                // Nonce replay — reject and remove.
                to_remove.push(tx.tx_id);
                self.containment
                    .record_invalid(node_id, TensionValue::from_integer(1));
                continue;
            }

            match validate_transition(tx, state) {
                Ok(()) => {
                    // Update local nonce tracker.
                    local_nonces.insert(node_id, tx.nonce);
                    validated.push(tx.clone());
                    self.containment
                        .record_valid(node_id, TensionValue::from_integer(1));
                }
                Err(_) => {
                    self.containment
                        .record_invalid(node_id, TensionValue::from_integer(1));
                }
            }
            to_remove.push(tx.tx_id);
        }

        let remove_set: HashSet<Hash> = to_remove.into_iter().collect();
        self.pending.retain(|tx| !remove_set.contains(&tx.tx_id));
        for id in &remove_set {
            self.seen_ids.remove(id);
        }

        self.containment.evaluate();
        validated
    }

    pub fn len(&self) -> usize {
        self.pending.len()
    }

    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.pending.is_empty()
    }
}
