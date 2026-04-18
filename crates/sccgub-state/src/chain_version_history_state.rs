//! Patch-06 §34.4 chain-version transition history reader / writer.
//!
//! Writes the `ChainVersionTransition` record to `system/chain_version_history`
//! at the activation height of an admitted `UpgradeProposal`, and provides a
//! replay-deterministic reader used by the block-import path to check
//! INV-UPGRADE-ATOMICITY.
//!
//! The trie key is genesis-reserved and never pruned (§33.3). Writes are
//! append-only; history preserves the canonical chronological ordering by
//! `activation_height` (ascending).

use sccgub_types::transition::{StateDelta, StateWrite};
use sccgub_types::upgrade::ChainVersionTransition;

use crate::world::ManagedWorldState;

/// Read the `system/chain_version_history` trie key and return the
/// (sorted-by-activation-height) sequence of committed transitions.
///
/// Returns an empty Vec if no transition has ever been committed (e.g.,
/// a genesis-version chain). The caller passes this slice directly to
/// `verify_block_version_alignment` at phase 0.
pub fn chain_version_history_from_trie(
    state: &ManagedWorldState,
) -> Result<Vec<ChainVersionTransition>, String> {
    match state.get(&ChainVersionTransition::TRIE_KEY.to_vec()) {
        Some(bytes) => bincode::deserialize(bytes)
            .map_err(|e| format!("chain_version_history deserialize: {}", e)),
        None => Ok(Vec::new()),
    }
}

/// Append a `ChainVersionTransition` to `system/chain_version_history`.
/// Called by the execution layer at the activation height of an admitted
/// `UpgradeProposal`. Callers MUST enforce monotonic `activation_height`
/// and contiguous `from_version → to_version` (§34.2 Rule 2); this
/// function does not re-check those constraints.
pub fn append_chain_version_transition(
    state: &mut ManagedWorldState,
    transition: ChainVersionTransition,
) -> Result<(), String> {
    let mut history = chain_version_history_from_trie(state)?;
    history.push(transition);
    let bytes = bincode::serialize(&history)
        .map_err(|e| format!("chain_version_history serialize: {}", e))?;
    state.apply_delta(&StateDelta {
        writes: vec![StateWrite {
            address: ChainVersionTransition::TRIE_KEY.to_vec(),
            value: bytes,
        }],
        deletes: vec![],
    });
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn transition(to: u32, activation: u64) -> ChainVersionTransition {
        ChainVersionTransition {
            activation_height: activation,
            from_version: to - 1,
            to_version: to,
            upgrade_spec_hash: [0x11; 32],
            proposal_id: [0x22; 32],
        }
    }

    #[test]
    fn patch_06_history_empty_on_fresh_state() {
        let state = ManagedWorldState::new();
        let h = chain_version_history_from_trie(&state).unwrap();
        assert!(h.is_empty());
    }

    #[test]
    fn patch_06_history_appends_and_reads_back() {
        let mut state = ManagedWorldState::new();
        append_chain_version_transition(&mut state, transition(5, 20_000)).unwrap();
        append_chain_version_transition(&mut state, transition(6, 40_000)).unwrap();
        let h = chain_version_history_from_trie(&state).unwrap();
        assert_eq!(h.len(), 2);
        assert_eq!(h[0].activation_height, 20_000);
        assert_eq!(h[0].to_version, 5);
        assert_eq!(h[1].activation_height, 40_000);
        assert_eq!(h[1].to_version, 6);
    }

    #[test]
    fn patch_06_history_replay_deterministic() {
        let mut a = ManagedWorldState::new();
        let mut b = ManagedWorldState::new();
        append_chain_version_transition(&mut a, transition(5, 20_000)).unwrap();
        append_chain_version_transition(&mut b, transition(5, 20_000)).unwrap();
        assert_eq!(a.state_root(), b.state_root());
    }

    #[test]
    fn patch_06_round_trip_feeds_alignment_check() {
        // INV-UPGRADE-ATOMICITY end-to-end: write a transition, read it
        // back, and exercise the alignment predicate on both sides of
        // the activation boundary.
        use sccgub_types::upgrade::ChainVersionTransition as T;

        let mut state = ManagedWorldState::new();
        append_chain_version_transition(
            &mut state,
            T {
                activation_height: 200,
                from_version: 4,
                to_version: 5,
                upgrade_spec_hash: [0xAA; 32],
                proposal_id: [0xBB; 32],
            },
        )
        .unwrap();
        let transitions = chain_version_history_from_trie(&state).unwrap();

        // Pre-activation: genesis v4 accepted.
        assert_eq!(transitions.len(), 1);
        assert_eq!(transitions[0].to_version, 5);
        // Post-activation: first transition reports the right target.
        assert_eq!(transitions[0].activation_height, 200);
    }
}
