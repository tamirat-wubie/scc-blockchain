use std::collections::{HashSet, VecDeque};

use sccgub_execution::validate::validate_transition;
use sccgub_governance::containment::ContainmentState;
use sccgub_state::world::ManagedWorldState;
use sccgub_types::tension::TensionValue;
use sccgub_types::transition::SymbolicTransition;
use sccgub_types::Hash;

/// Transaction mempool with admission, dedup, validation, and containment.
/// Per v2.1 FIX B-14: explicit mempool specification.
pub struct Mempool {
    pending: VecDeque<SymbolicTransition>,
    seen_ids: HashSet<Hash>,
    /// IDs of transactions already included in blocks — prevents re-submission.
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

    /// Mark transaction IDs as confirmed (included in a block).
    pub fn mark_confirmed(&mut self, ids: &[Hash]) {
        for id in ids {
            self.confirmed_ids.insert(*id);
        }
    }

    /// Add a transition to the mempool.
    /// Rejects duplicates and quarantined agents.
    pub fn add(&mut self, tx: SymbolicTransition) -> Result<(), String> {
        let node_id = tx.actor.agent_id;

        // Check containment.
        if !self.containment.is_allowed(&node_id) {
            return Err(format!(
                "Agent {} is quarantined",
                hex::encode(node_id)
            ));
        }

        // Reject duplicate tx_id.
        if self.seen_ids.contains(&tx.tx_id) {
            return Err("Duplicate transaction ID".into());
        }

        // Reject already-confirmed (included in block) transactions.
        if self.confirmed_ids.contains(&tx.tx_id) {
            return Err("Transaction already included in a block".into());
        }

        // Evict oldest if at capacity (O(1) with VecDeque).
        if self.pending.len() >= self.max_size {
            if let Some(evicted) = self.pending.pop_front() {
                self.seen_ids.remove(&evicted.tx_id);
            }
        }

        self.seen_ids.insert(tx.tx_id);
        self.pending.push_back(tx);
        Ok(())
    }

    /// Drain validated transitions from the mempool.
    /// Removes both valid and invalid transactions. Updates containment.
    pub fn drain_validated(&mut self, state: &ManagedWorldState) -> Vec<SymbolicTransition> {
        let mut validated = Vec::new();
        let mut to_remove: Vec<Hash> = Vec::new();

        for tx in &self.pending {
            let node_id = tx.actor.agent_id;
            match validate_transition(tx, state) {
                Ok(()) => {
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

        // Remove all processed transactions (both valid and invalid).
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
