use sccgub_execution::validate::validate_transition;
use sccgub_governance::containment::ContainmentState;
use sccgub_state::world::ManagedWorldState;
use sccgub_types::tension::TensionValue;
use sccgub_types::transition::SymbolicTransition;

/// Transaction mempool with admission, validation, and containment checking.
/// Per v2.1 FIX B-14: explicit mempool specification.
pub struct Mempool {
    pending: Vec<SymbolicTransition>,
    max_size: usize,
    pub containment: ContainmentState,
}

impl Mempool {
    pub fn new(max_size: usize) -> Self {
        Self {
            pending: Vec::new(),
            max_size,
            containment: ContainmentState::default(),
        }
    }

    /// Add a transition to the mempool.
    /// Checks containment — quarantined nodes cannot submit.
    pub fn add(&mut self, tx: SymbolicTransition) -> Result<(), String> {
        let node_id = tx.actor.agent_id;

        // Check containment status.
        if !self.containment.is_allowed(&node_id) {
            return Err(format!(
                "Agent {} is quarantined — transaction rejected at mempool admission",
                hex::encode(node_id)
            ));
        }

        if self.pending.len() >= self.max_size {
            // Evict oldest.
            self.pending.remove(0);
        }
        self.pending.push(tx);
        Ok(())
    }

    /// Drain validated transitions from the mempool.
    /// Updates containment state based on validation results.
    pub fn drain_validated(&mut self, state: &ManagedWorldState) -> Vec<SymbolicTransition> {
        let mut validated = Vec::new();

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
        }

        // Remove drained transactions.
        let validated_ids: std::collections::HashSet<_> =
            validated.iter().map(|tx| tx.tx_id).collect();
        self.pending
            .retain(|tx| !validated_ids.contains(&tx.tx_id));

        // Evaluate containment after processing.
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
