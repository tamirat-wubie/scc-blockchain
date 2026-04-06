use sccgub_execution::validate::validate_transition;
use sccgub_state::world::ManagedWorldState;
use sccgub_types::transition::SymbolicTransition;

/// Transaction mempool with admission and eviction.
/// Per v2.1 FIX B-14: explicit mempool specification.
pub struct Mempool {
    pending: Vec<SymbolicTransition>,
    max_size: usize,
}

impl Mempool {
    pub fn new(max_size: usize) -> Self {
        Self {
            pending: Vec::new(),
            max_size,
        }
    }

    /// Add a transition to the mempool.
    pub fn add(&mut self, tx: SymbolicTransition) {
        if self.pending.len() >= self.max_size {
            // Evict oldest.
            self.pending.remove(0);
        }
        self.pending.push(tx);
    }

    /// Drain validated transitions from the mempool.
    pub fn drain_validated(&mut self, state: &ManagedWorldState) -> Vec<SymbolicTransition> {
        let mut validated = Vec::new();
        let mut rejected_indices = Vec::new();

        for (i, tx) in self.pending.iter().enumerate() {
            match validate_transition(tx, state) {
                Ok(()) => validated.push(tx.clone()),
                Err(_) => rejected_indices.push(i),
            }
        }

        // Remove all drained transactions (validated ones).
        let validated_ids: std::collections::HashSet<_> =
            validated.iter().map(|tx| tx.tx_id).collect();
        self.pending
            .retain(|tx| !validated_ids.contains(&tx.tx_id));

        validated
    }

    pub fn len(&self) -> usize {
        self.pending.len()
    }

    pub fn is_empty(&self) -> bool {
        self.pending.is_empty()
    }
}
