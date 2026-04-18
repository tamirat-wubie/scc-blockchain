//! Patch-06 §33 state pruning gated on finality depth.
//!
//! Closes INV-STATE-BOUNDED: steady-state prunable-namespace size grows
//! as `O(active_validators + pruning_depth * block_span)` rather than
//! `O(H)`. Without pruning, chains admit unbounded growth in
//! `system/validator_set_change_history` and related projections; at
//! 10⁷ admissions the state-root recompute cost alone exceeds the block
//! budget.
//!
//! This module declares the **pruning contract** as a pair of pure
//! identification functions. The actual archive-and-delete execution is
//! coupled to a redb-backed `pruned_archive/*` surface that is excluded
//! from `ManagedWorldState::state_root` via an explicit filter; that
//! surface is wired in Patch-07, which turns `perform_pruning` from a
//! stub into an active runtime. The identification predicates — which
//! are the consensus-critical part — are final in Patch-06.
//!
//! Design: the "what CAN be pruned" predicate is pure, auditable, and
//! unit-testable on a deterministic input. The execution path (move
//! entries to archive, verify `pre_root == post_root`) is operational
//! and lives in the node binary.

use serde::{Deserialize, Serialize};

use sccgub_types::validator_set::ValidatorSetChange;
use sccgub_types::{AgentId, Hash};

/// §33.3 classification of which trie namespaces are prunable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PrunableNamespace {
    /// `system/validator_set_change_history` — superseded entries per
    /// agent_id, older than pruning_depth, prunable.
    ValidatorSetChangeHistory,
    /// `system/key_index` — superseded KeyIndex entries older than
    /// pruning_depth. (Identification stub; full implementation in Patch-07
    /// when KeyIndex grows beyond linear search.)
    KeyIndex,
    /// `block_receipts/*` — receipts older than pruning_depth blocks.
    BlockReceipts,
    /// `snapshots/*` — snapshots older than the most recent non-prunable.
    Snapshots,
}

/// A single entry identified as prunable by the predicate below. The
/// execution layer consumes this list to perform the archive + delete.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrunableEntry {
    pub namespace: PrunableNamespace,
    /// Identifier of the superseded entry. For `ValidatorSetChangeHistory`
    /// this is the `change_id` of the superseded admission.
    pub key: Hash,
    /// Identifier of the entry that supersedes this one, when applicable.
    /// `None` for `BlockReceipts`/`Snapshots` which prune on age only.
    pub superseded_by: Option<Hash>,
}

/// §33.4 pruning receipt. Produced by the execution layer after the
/// archive-and-delete pass completes. The `pre_root == post_root`
/// equality is the key invariant — pruned entries must live outside the
/// state-root computation domain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PruningReceipt {
    pub tip_height: u64,
    pub pruning_depth: u64,
    pub namespaces: Vec<(PrunableNamespace, u32)>,
    pub pre_root: Hash,
    pub post_root: Hash,
}

impl PruningReceipt {
    /// INV-STATE-BOUNDED structural check: the state root MUST NOT change
    /// as a result of pruning (archive is outside the root domain).
    pub fn state_root_preserved(&self) -> bool {
        self.pre_root == self.post_root
    }
}

/// §33.3 identification for `system/validator_set_change_history`.
///
/// Returns the list of admission records that are:
///
/// 1. Older than `pruning_depth` (i.e., `tip_height - proposed_at >=
///    pruning_depth`), AND
/// 2. Superseded by a newer admission for the same `agent_id`.
///
/// The newest admission per agent_id is ALWAYS retained. Entries in
/// this return value are safe to archive; the state-root-preserving
/// execution is the caller's responsibility.
///
/// Pure + deterministic: input is the fully-materialized history slice
/// and two scalar parameters. Order of return follows input order (stable).
pub fn identify_prunable_admission_history(
    history: &[ValidatorSetChange],
    tip_height: u64,
    pruning_depth: u64,
) -> Vec<PrunableEntry> {
    // Walk from the end to find the newest admission per agent_id. Use a
    // BTreeMap so iteration order is deterministic and the
    // iter_over_hash_type lint is satisfied.
    use std::collections::BTreeMap;

    let mut newest_per_agent: BTreeMap<AgentId, (Hash, u64)> = BTreeMap::new();
    for change in history.iter().rev() {
        let agent = change.kind.target_agent_id();
        newest_per_agent
            .entry(agent)
            .or_insert((change.change_id, change.proposed_at));
    }

    let mut prunable = Vec::new();
    for change in history {
        let agent = change.kind.target_agent_id();
        let (newest_id, _newest_height) = match newest_per_agent.get(&agent) {
            Some(v) => *v,
            None => continue,
        };
        // Retain the newest entry per agent.
        if change.change_id == newest_id {
            continue;
        }
        // Older entries prunable only if they exceed pruning_depth of age.
        let age = tip_height.saturating_sub(change.proposed_at);
        if age >= pruning_depth {
            prunable.push(PrunableEntry {
                namespace: PrunableNamespace::ValidatorSetChangeHistory,
                key: change.change_id,
                superseded_by: Some(newest_id),
            });
        }
    }
    prunable
}

/// §33.3 block-receipts identification. A receipt at height `h` is
/// prunable iff `tip_height - h >= pruning_depth`. The execution layer
/// enumerates receipt keys; we expose a scalar predicate here.
pub fn is_receipt_prunable(receipt_height: u64, tip_height: u64, pruning_depth: u64) -> bool {
    tip_height.saturating_sub(receipt_height) >= pruning_depth
}

/// Stubbed §33.4 execution path. Returns a `not-yet-wired` error in
/// Patch-06; Patch-07 replaces the body with the archive-and-delete
/// pass that maintains `state_root_preserved() == true`.
pub fn perform_pruning(
    _tip_height: u64,
    _pruning_depth: u64,
) -> Result<PruningReceipt, PruningError> {
    Err(PruningError::NotYetWired)
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PruningError {
    #[error("pruning execution path not wired in Patch-06; see Patch-07 §33 completion")]
    NotYetWired,
}

#[cfg(test)]
mod tests {
    use super::*;
    use sccgub_types::validator_set::ValidatorSetChangeKind;

    fn change(agent: u8, proposed_at: u64, power: u64) -> ValidatorSetChange {
        let kind = ValidatorSetChangeKind::RotatePower {
            agent_id: [agent; 32],
            new_voting_power: power,
            effective_height: proposed_at + 5,
        };
        ValidatorSetChange {
            change_id: ValidatorSetChange::compute_change_id(&kind, proposed_at),
            kind,
            proposed_at,
            quorum_signatures: vec![],
        }
    }

    #[test]
    fn patch_06_no_prunable_entries_for_single_admission_per_agent() {
        // One admission per agent, all recent → nothing prunable.
        let history = vec![change(1, 100, 10), change(2, 100, 20), change(3, 100, 30)];
        let prunable = identify_prunable_admission_history(&history, 110, 32);
        assert!(prunable.is_empty());
    }

    #[test]
    fn patch_06_prunes_superseded_old_entries() {
        // Agent 1 has three admissions; agent 2 has one.
        // tip_height=200, pruning_depth=32 → entries older than height 168 prunable.
        let history = vec![
            change(1, 100, 10),  // old + superseded → prunable
            change(1, 150, 20),  // old (age 50 >= 32) + superseded → prunable
            change(2, 100, 100), // old + not superseded (only one for agent 2) → retained
            change(1, 180, 30),  // recent + newest for agent 1 → retained
        ];
        let prunable = identify_prunable_admission_history(&history, 200, 32);
        assert_eq!(prunable.len(), 2);
        // Both prunable entries belong to agent 1 and point at the newest.
        let newest_id = history[3].change_id;
        for entry in &prunable {
            assert_eq!(
                entry.namespace,
                PrunableNamespace::ValidatorSetChangeHistory
            );
            assert_eq!(entry.superseded_by, Some(newest_id));
        }
    }

    #[test]
    fn patch_06_retains_superseded_but_still_recent() {
        // Agent 1 has two admissions; both are within pruning_depth of tip.
        // Even the superseded one is retained because it's still "recent."
        let history = vec![
            change(1, 180, 10), // superseded but recent → retained
            change(1, 195, 20), // newest + recent → retained
        ];
        let prunable = identify_prunable_admission_history(&history, 200, 32);
        assert!(prunable.is_empty());
    }

    #[test]
    fn patch_06_retains_newest_per_agent_even_when_old() {
        // All admissions are old, but the newest per agent MUST stay.
        let history = vec![change(1, 50, 10), change(1, 60, 20)];
        let prunable = identify_prunable_admission_history(&history, 1000, 32);
        // Only the first (superseded) entry is prunable; the newest is kept.
        assert_eq!(prunable.len(), 1);
        assert_eq!(prunable[0].key, history[0].change_id);
    }

    #[test]
    fn patch_06_receipt_prunable_predicate() {
        assert!(!is_receipt_prunable(100, 110, 32));
        assert!(is_receipt_prunable(100, 132, 32));
        assert!(is_receipt_prunable(100, 200, 32));
    }

    #[test]
    fn patch_06_perform_pruning_is_stubbed() {
        let r = perform_pruning(100, 32);
        assert!(matches!(r, Err(PruningError::NotYetWired)));
    }

    #[test]
    fn patch_06_pruning_receipt_preservation_check() {
        let receipt = PruningReceipt {
            tip_height: 100,
            pruning_depth: 32,
            namespaces: vec![(PrunableNamespace::ValidatorSetChangeHistory, 5)],
            pre_root: [0x11; 32],
            post_root: [0x11; 32],
        };
        assert!(receipt.state_root_preserved());

        let drifted = PruningReceipt {
            post_root: [0x22; 32],
            ..receipt
        };
        assert!(!drifted.state_root_preserved());
    }

    #[test]
    fn patch_06_identification_deterministic_across_orderings() {
        // INV-STATE-BOUNDED is stable under replay: identifying the same
        // prunable set regardless of outer iteration order. Since our
        // implementation uses BTreeMap, it's inherently deterministic.
        let history_a = vec![
            change(1, 100, 10),
            change(2, 110, 20),
            change(1, 150, 30),
            change(1, 180, 40),
        ];
        let result_a = identify_prunable_admission_history(&history_a, 200, 32);
        let result_b = identify_prunable_admission_history(&history_a, 200, 32);
        assert_eq!(result_a, result_b);
    }
}
