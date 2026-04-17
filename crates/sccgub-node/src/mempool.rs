use std::collections::{HashMap, HashSet, VecDeque};

use sccgub_execution::validate::admit_check_structural;
use sccgub_governance::containment::ContainmentState;
use sccgub_state::world::ManagedWorldState;
use sccgub_types::tension::TensionValue;
use sccgub_types::transition::SymbolicTransition;
use sccgub_types::Hash;

/// Maximum number of confirmed transaction IDs to retain for replay
/// protection. Once exceeded, oldest entries are pruned. 100k entries ≈ 7 MB.
const MAX_CONFIRMED_IDS: usize = 100_000;

/// Transaction mempool with admission, dedup, validation, and containment.
#[derive(Clone)]
pub struct Mempool {
    pending: VecDeque<SymbolicTransition>,
    seen_ids: HashSet<Hash>,
    confirmed_ids: HashSet<Hash>,
    /// Insertion-ordered queue for LRU eviction of confirmed_ids.
    confirmed_order: VecDeque<Hash>,
    max_size: usize,
    pub containment: ContainmentState,
}

impl Mempool {
    pub fn new(max_size: usize) -> Self {
        Self {
            pending: VecDeque::new(),
            seen_ids: HashSet::new(),
            confirmed_ids: HashSet::new(),
            confirmed_order: VecDeque::new(),
            max_size,
            containment: ContainmentState::default(),
        }
    }

    pub fn mark_confirmed(&mut self, ids: &[Hash]) {
        for id in ids {
            if self.confirmed_ids.insert(*id) {
                self.confirmed_order.push_back(*id);
            }
        }
        // M-3: Prune oldest confirmed IDs to prevent unbounded growth.
        while self.confirmed_ids.len() > MAX_CONFIRMED_IDS {
            if let Some(oldest) = self.confirmed_order.pop_front() {
                self.confirmed_ids.remove(&oldest);
            } else {
                break;
            }
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

    /// Drain admitted transitions. Lightweight structural checks only.
    ///
    /// Runs `admit_check` (signature length, nonce, size limits, WHBinding structure)
    /// but NOT Phi traversal, Ed25519 verification, or SCCE constraint propagation.
    /// Those expensive checks run in the gas loop inside `produce_block`, where every
    /// rejection produces a receipt (closing N-3-mempool).
    ///
    /// Tracks nonces locally during drain to prevent same-agent duplicate nonces
    /// within a single block (fail-closed).
    pub fn drain_validated(&mut self, state: &ManagedWorldState) -> Vec<SymbolicTransition> {
        let mut validated = Vec::new();
        let mut to_remove: Vec<Hash> = Vec::new();
        // Track nonces locally during this drain to catch same-block duplicates.
        let mut local_nonces: HashMap<Hash, u128> = HashMap::new();

        for tx in &self.pending {
            let node_id = tx.actor.agent_id;

            // Check nonce with local tracking (catches same-block duplicates).
            // This is more precise than admit_check's nonce check because it
            // tracks nonces assigned to earlier txs in this same drain batch.
            let committed = state.agent_nonces.get(&node_id).copied().unwrap_or(0);
            let local = local_nonces.get(&node_id).copied().unwrap_or(committed);
            let expected_nonce = local.saturating_add(1);
            if tx.nonce == 0 || tx.nonce != expected_nonce {
                // Nonce violation — reject and remove.
                to_remove.push(tx.tx_id);
                self.containment
                    .record_invalid(node_id, TensionValue::from_integer(1));
                continue;
            }

            // Lightweight structural checks (no nonce — already checked above with
            // local tracking that allows sequential nonces within the same batch).
            match admit_check_structural(tx, state) {
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

        // Deterministic fair ordering: sort by (nonce, tx_id hash).
        // This prevents MEV/front-running by making transaction ordering
        // deterministic and verifiable — no priority gas auctions.
        // All validators produce the same block given the same mempool.
        validated.sort_by(|a, b| a.nonce.cmp(&b.nonce).then_with(|| a.tx_id.cmp(&b.tx_id)));

        validated
    }

    pub fn len(&self) -> usize {
        self.pending.len()
    }

    pub fn pending_snapshot(&self) -> Vec<SymbolicTransition> {
        self.pending.iter().cloned().collect()
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
    use std::collections::BTreeSet;

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
                norm_set: BTreeSet::new(),
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
                which: BTreeSet::new(),
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

    // ── drain_validated tests (M-1) ──────────────────────────────

    fn test_state_with_nonce(agent: Hash, committed_nonce: u128) -> ManagedWorldState {
        let mut state = ManagedWorldState::new();
        if committed_nonce > 0 {
            state.agent_nonces.insert(agent, committed_nonce);
        }
        state
    }

    #[test]
    fn test_drain_validated_empty_mempool() {
        let mut mempool = Mempool::new(100);
        let state = ManagedWorldState::new();
        let result = mempool.drain_validated(&state);
        assert!(result.is_empty());
    }

    #[test]
    fn test_drain_validated_single_valid_tx() {
        let mut mempool = Mempool::new(100);
        let agent = [1u8; 32];
        let tx = test_tx(agent, 1);
        mempool.add(tx.clone()).unwrap();

        let state = test_state_with_nonce(agent, 0);
        let result = mempool.drain_validated(&state);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].tx_id, tx.tx_id);
        assert_eq!(mempool.len(), 0, "pending should be drained");
    }

    #[test]
    fn test_drain_validated_nonce_zero_rejected() {
        let mut mempool = Mempool::new(100);
        let agent = [1u8; 32];
        let tx = test_tx(agent, 0); // Nonce zero is always rejected.
        mempool.add(tx).unwrap();

        let state = ManagedWorldState::new();
        let result = mempool.drain_validated(&state);
        assert!(result.is_empty(), "nonce=0 should be rejected");
        assert_eq!(mempool.len(), 0, "rejected tx still drained from pending");
    }

    #[test]
    fn test_drain_validated_sequential_nonces_same_agent() {
        let mut mempool = Mempool::new(100);
        let agent = [1u8; 32];
        // Three sequential nonces from the same agent (committed=0).
        let tx1 = test_tx(agent, 1);
        let tx2 = test_tx(agent, 2);
        let tx3 = test_tx(agent, 3);
        mempool.add(tx1).unwrap();
        mempool.add(tx2).unwrap();
        mempool.add(tx3).unwrap();

        let state = test_state_with_nonce(agent, 0);
        let result = mempool.drain_validated(&state);
        assert_eq!(result.len(), 3, "all sequential nonces should pass");
    }

    #[test]
    fn test_drain_validated_nonce_gap_rejects_later() {
        let mut mempool = Mempool::new(100);
        let agent = [1u8; 32];
        // Nonces 1 and 3 but not 2 — gap means 3 is rejected.
        let tx1 = test_tx(agent, 1);
        let tx3 = test_tx(agent, 3);
        mempool.add(tx1).unwrap();
        mempool.add(tx3).unwrap();

        let state = test_state_with_nonce(agent, 0);
        let result = mempool.drain_validated(&state);
        assert_eq!(result.len(), 1, "only nonce=1 should pass, 3 has a gap");
        assert_eq!(result[0].nonce, 1);
    }

    #[test]
    fn test_drain_validated_all_invalid() {
        let mut mempool = Mempool::new(100);
        let agent = [1u8; 32];
        // Nonce=5 when committed=0 → expected=1 → mismatch.
        let tx = test_tx(agent, 5);
        mempool.add(tx).unwrap();

        let state = test_state_with_nonce(agent, 0);
        let result = mempool.drain_validated(&state);
        assert!(result.is_empty());
        assert_eq!(mempool.len(), 0, "invalid tx still removed from pending");
    }

    #[test]
    fn test_drain_validated_deterministic_ordering() {
        let mut mempool = Mempool::new(100);
        let agent_a = [1u8; 32];
        let agent_b = [2u8; 32];
        // Agent B submitted first, then Agent A.
        let tx_b = test_tx(agent_b, 1);
        let tx_a = test_tx(agent_a, 1);
        mempool.add(tx_b.clone()).unwrap();
        mempool.add(tx_a.clone()).unwrap();

        let state = ManagedWorldState::new();
        let result = mempool.drain_validated(&state);
        assert_eq!(result.len(), 2);
        // Both have nonce=1, so tiebreak by tx_id.
        assert!(
            result[0].tx_id < result[1].tx_id,
            "should be sorted by (nonce, tx_id)"
        );
    }

    // ── confirmed_ids pruning test (M-3) ─────────────────────────

    #[test]
    fn test_confirmed_ids_pruned_at_max() {
        let mut mempool = Mempool::new(100);
        // Fill confirmed_ids to MAX_CONFIRMED_IDS + 10.
        let overflow = 10;
        let total = MAX_CONFIRMED_IDS + overflow;
        let ids: Vec<Hash> = (0..total)
            .map(|i| {
                let mut h = [0u8; 32];
                h[..8].copy_from_slice(&(i as u64).to_le_bytes());
                h
            })
            .collect();
        mempool.mark_confirmed(&ids);
        assert_eq!(
            mempool.confirmed_ids.len(),
            MAX_CONFIRMED_IDS,
            "should be pruned to MAX_CONFIRMED_IDS"
        );
        // The first `overflow` IDs should have been evicted.
        for (i, id) in ids.iter().enumerate().take(overflow) {
            assert!(
                !mempool.confirmed_ids.contains(id),
                "oldest ID {} should be evicted",
                i
            );
        }
        // The newest IDs should still be present.
        assert!(mempool.confirmed_ids.contains(&ids[total - 1]));
    }
}
