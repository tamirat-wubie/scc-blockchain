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

#[cfg(test)]
mod tests {
    use super::*;
    use sccgub_types::agent::{AgentIdentity, ResponsibilityState};
    use sccgub_types::governance::PrecedenceLevel;
    use sccgub_types::mfidel::MfidelAtomicSeal;
    use sccgub_types::timestamp::CausalTimestamp;
    use sccgub_types::transition::*;
    use std::collections::HashSet;

    fn test_tx(agent_id: [u8; 32], nonce: u128) -> SymbolicTransition {
        SymbolicTransition {
            tx_id: {
                let mut id = [0u8; 32];
                id[0] = nonce as u8;
                id[1..5].copy_from_slice(&agent_id[..4]);
                id
            },
            actor: AgentIdentity {
                agent_id,
                public_key: [0u8; 32],
                mfidel_seal: MfidelAtomicSeal::from_height(1),
                registration_block: 0,
                governance_level: PrecedenceLevel::Meaning,
                norm_set: HashSet::new(),
                responsibility: ResponsibilityState::default(),
            },
            intent: TransitionIntent {
                kind: TransitionKind::StateWrite,
                target: b"test".to_vec(),
                declared_purpose: "test".into(),
            },
            preconditions: vec![],
            postconditions: vec![],
            payload: OperationPayload::Noop,
            causal_chain: vec![],
            wh_binding_intent: WHBindingIntent {
                who: agent_id,
                when: CausalTimestamp::genesis(),
                r#where: b"test".to_vec(),
                why: CausalJustification {
                    invoking_rule: [1u8; 32],
                    precedence_level: PrecedenceLevel::Meaning,
                    causal_ancestors: vec![],
                    constraint_proof: vec![],
                },
                how: TransitionMechanism::DirectStateWrite,
                which: HashSet::new(),
                what_declared: "test".into(),
            },
            nonce,
            signature: vec![0u8; 64],
        }
    }

    #[test]
    fn test_duplicate_rejected() {
        let mut mempool = Mempool::new(100);
        let tx = test_tx([1u8; 32], 1);
        assert!(mempool.add(tx.clone()).is_ok());
        assert!(mempool.add(tx).is_err()); // Duplicate tx_id.
    }

    #[test]
    fn test_confirmed_tx_rejected() {
        let mut mempool = Mempool::new(100);
        let tx = test_tx([1u8; 32], 1);
        mempool.mark_confirmed(&[tx.tx_id]);
        assert!(mempool.add(tx).is_err()); // Already confirmed.
    }

    #[test]
    fn test_capacity_eviction() {
        let mut mempool = Mempool::new(2);
        let tx1 = test_tx([1u8; 32], 1);
        let tx2 = test_tx([2u8; 32], 2);
        let tx3 = test_tx([3u8; 32], 3);

        mempool.add(tx1.clone()).unwrap();
        mempool.add(tx2).unwrap();
        assert_eq!(mempool.len(), 2);

        mempool.add(tx3).unwrap(); // Should evict tx1 (oldest).
        assert_eq!(mempool.len(), 2);

        // tx1 was evicted, so re-adding should succeed.
        assert!(mempool.add(tx1).is_ok());
    }

    #[test]
    fn test_quarantined_agent_rejected() {
        let mut mempool = Mempool::new(100);
        let agent = [99u8; 32];

        // Quarantine the agent.
        mempool.containment.nodes.insert(
            agent,
            sccgub_governance::containment::NodeBehaviorProfile {
                node_id: agent,
                positive_delta: TensionValue::ZERO,
                negative_delta: TensionValue::from_integer(1000),
                containment: sccgub_governance::containment::ContainmentLevel::Quarantine {
                    blocks_remaining: 50,
                },
                invalid_count: 100,
                valid_count: 0,
            },
        );

        let tx = test_tx(agent, 1);
        assert!(mempool.add(tx).is_err()); // Quarantined.
    }
}
