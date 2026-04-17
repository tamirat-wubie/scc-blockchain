//! Validator-set state management for Patch-04 v3 (§15).
//!
//! Two state entries back the validator-set model:
//!
//! - `system/validator_set` stores the current canonical `ValidatorSet`.
//!   Records flip between active and inactive via `active_from` /
//!   `active_until`. `RotatePower` / `RotateKey` update fields in place
//!   when the deferred activation height is reached.
//!
//! - `system/pending_validator_set_changes` stores admitted-but-not-yet-
//!   effective `ValidatorSetChange` events, canonically ordered by
//!   `(effective_height, change_id)`. At the start of each block, the
//!   execution layer calls `advance_validator_set_to_height` to drain
//!   every pending change whose `effective_height == current_height`.
//!
//! All functions here are pure state transitions. Signature verification
//! and quorum-checking live in the execution layer (Commit 4). This
//! module assumes the admission-layer predicates of §15.5 have already
//! been enforced by the caller.

use sccgub_types::transition::{StateDelta, StateWrite};
use sccgub_types::validator_set::{
    ValidatorRecord, ValidatorSet, ValidatorSetChange, ValidatorSetChangeKind,
    VALIDATOR_SET_TRIE_KEY,
};

use crate::world::ManagedWorldState;

/// Canonical trie key for pending (admitted but not yet effective)
/// `ValidatorSetChange` events. Separate from `system/validator_set` so
/// deferred activations do not mutate the active-set projection early.
pub const PENDING_VALIDATOR_SET_CHANGES_TRIE_KEY: &[u8] = b"system/pending_validator_set_changes";

/// Write the current `ValidatorSet` to the canonical trie key.
/// Used at genesis to seed `system/validator_set`, and by
/// `advance_validator_set_to_height` to commit post-activation state.
pub fn commit_validator_set(state: &mut ManagedWorldState, set: &ValidatorSet) {
    state.apply_delta(&StateDelta {
        writes: vec![StateWrite {
            address: VALIDATOR_SET_TRIE_KEY.to_vec(),
            value: set.to_canonical_bytes(),
        }],
        deletes: vec![],
    });
}

/// Read the current `ValidatorSet` from trie storage, if present.
/// Returns `Ok(None)` when no set has been committed (pre-v3 chains).
pub fn validator_set_from_trie(state: &ManagedWorldState) -> Result<Option<ValidatorSet>, String> {
    match state.get(&VALIDATOR_SET_TRIE_KEY.to_vec()) {
        Some(bytes) => ValidatorSet::from_canonical_bytes(bytes).map(Some),
        None => Ok(None),
    }
}

/// Pending `ValidatorSetChange` queue, canonically ordered by
/// `(effective_height, change_id)`.
pub fn pending_changes_from_trie(
    state: &ManagedWorldState,
) -> Result<Vec<ValidatorSetChange>, String> {
    match state.get(&PENDING_VALIDATOR_SET_CHANGES_TRIE_KEY.to_vec()) {
        Some(bytes) => bincode::deserialize(bytes)
            .map_err(|e| format!("pending_validator_set_changes deserialize: {}", e)),
        None => Ok(Vec::new()),
    }
}

fn commit_pending_changes(state: &mut ManagedWorldState, pending: &[ValidatorSetChange]) {
    let bytes =
        bincode::serialize(pending).expect("Vec<ValidatorSetChange> serialization is infallible");
    state.apply_delta(&StateDelta {
        writes: vec![StateWrite {
            address: PENDING_VALIDATOR_SET_CHANGES_TRIE_KEY.to_vec(),
            value: bytes,
        }],
        deletes: vec![],
    });
}

/// Admit a validated `ValidatorSetChange` into the pending queue.
///
/// This is a pure state transition: the caller (execution layer) is
/// responsible for §15.5 admission predicates (quorum signatures,
/// `change_id` consistency, variant-specific predicates). This function
/// only enforces the invariants that matter for replay determinism:
///
/// 1. `change.change_id` must match `compute_change_id(kind, proposed_at)`.
/// 2. The `change_id` must not already be present in the pending queue
///    (prevents duplicate admission of the same change).
/// 3. The pending queue remains canonically sorted after insertion.
pub fn apply_validator_set_change_admission(
    state: &mut ManagedWorldState,
    change: ValidatorSetChange,
) -> Result<(), ValidatorSetStateError> {
    if !change.change_id_is_consistent() {
        return Err(ValidatorSetStateError::ChangeIdMismatch);
    }
    let mut pending = pending_changes_from_trie(state).map_err(ValidatorSetStateError::Storage)?;
    if pending.iter().any(|c| c.change_id == change.change_id) {
        return Err(ValidatorSetStateError::DuplicateChangeId);
    }
    pending.push(change);
    pending.sort_by_key(|c| (c.kind.effective_height(), c.change_id));
    commit_pending_changes(state, &pending);
    Ok(())
}

/// Activation sweep: drain all pending changes whose
/// `kind.effective_height == height` and apply them to the stored
/// `ValidatorSet` in canonical `(effective_height, change_id)` order.
///
/// Returns the list of drained changes (for event emission in the
/// execution layer). If there is no committed `ValidatorSet` yet this
/// is a no-op (pre-v3 chains).
pub fn advance_validator_set_to_height(
    state: &mut ManagedWorldState,
    height: u64,
) -> Result<Vec<ValidatorSetChange>, ValidatorSetStateError> {
    let pending = pending_changes_from_trie(state).map_err(ValidatorSetStateError::Storage)?;
    if pending.is_empty() {
        return Ok(Vec::new());
    }
    let mut set = match validator_set_from_trie(state).map_err(ValidatorSetStateError::Storage)? {
        Some(s) => s,
        None => return Err(ValidatorSetStateError::SetNotInitialized),
    };

    let (to_apply, to_keep): (Vec<_>, Vec<_>) = pending
        .into_iter()
        .partition(|c| c.kind.effective_height() == height);

    for change in &to_apply {
        apply_kind_to_set(&mut set, &change.kind)?;
    }

    commit_validator_set(state, &set);
    commit_pending_changes(state, &to_keep);
    Ok(to_apply)
}

fn apply_kind_to_set(
    set: &mut ValidatorSet,
    kind: &ValidatorSetChangeKind,
) -> Result<(), ValidatorSetStateError> {
    // `ValidatorSet` internally stores records; we reconstruct an owned
    // Vec, mutate, and rebuild to keep canonical ordering and uniqueness
    // invariants enforced at the ValidatorSet constructor.
    let mut records: Vec<ValidatorRecord> = set.records().to_vec();
    match kind {
        ValidatorSetChangeKind::Add(new_record) => {
            if records.iter().any(|r| r.agent_id == new_record.agent_id) {
                return Err(ValidatorSetStateError::AgentAlreadyPresent);
            }
            if records
                .iter()
                .any(|r| r.validator_id == new_record.validator_id)
            {
                return Err(ValidatorSetStateError::ValidatorIdAlreadyInUse);
            }
            records.push(new_record.clone());
        }
        ValidatorSetChangeKind::Remove {
            agent_id,
            effective_height,
            ..
        } => {
            let record = records
                .iter_mut()
                .find(|r| r.agent_id == *agent_id)
                .ok_or(ValidatorSetStateError::AgentNotPresent)?;
            // `active_until = effective_height - 1`: record ceases to be
            // active at `effective_height` itself.
            record.active_until = Some(effective_height.saturating_sub(1));
        }
        ValidatorSetChangeKind::RotatePower {
            agent_id,
            new_voting_power,
            ..
        } => {
            if *new_voting_power == 0 {
                return Err(ValidatorSetStateError::ZeroVotingPower);
            }
            let record = records
                .iter_mut()
                .find(|r| r.agent_id == *agent_id)
                .ok_or(ValidatorSetStateError::AgentNotPresent)?;
            record.voting_power = *new_voting_power;
        }
        ValidatorSetChangeKind::RotateKey {
            agent_id,
            old_validator_id,
            new_validator_id,
            ..
        } => {
            if old_validator_id == new_validator_id {
                return Err(ValidatorSetStateError::KeyRotationNoOp);
            }
            if records
                .iter()
                .any(|r| r.validator_id == *new_validator_id && r.agent_id != *agent_id)
            {
                return Err(ValidatorSetStateError::ValidatorIdAlreadyInUse);
            }
            let record = records
                .iter_mut()
                .find(|r| r.agent_id == *agent_id)
                .ok_or(ValidatorSetStateError::AgentNotPresent)?;
            if record.validator_id != *old_validator_id {
                return Err(ValidatorSetStateError::OldKeyMismatch);
            }
            record.validator_id = *new_validator_id;
        }
    }
    *set = ValidatorSet::new(records)
        .map_err(|e| ValidatorSetStateError::SetRebuildFailed(e.to_string()))?;
    Ok(())
}

#[derive(Debug, thiserror::Error)]
pub enum ValidatorSetStateError {
    #[error("change_id does not match canonical hash of (kind, proposed_at)")]
    ChangeIdMismatch,
    #[error("duplicate change_id in pending queue")]
    DuplicateChangeId,
    #[error("attempted activation sweep before system/validator_set was initialized")]
    SetNotInitialized,
    #[error("Add: agent_id already present in set")]
    AgentAlreadyPresent,
    #[error("Add/RotateKey: validator_id already in use by another record")]
    ValidatorIdAlreadyInUse,
    #[error("Remove/RotatePower/RotateKey: agent_id not present in set")]
    AgentNotPresent,
    #[error("RotatePower: new_voting_power must be > 0 (use Remove to deactivate)")]
    ZeroVotingPower,
    #[error("RotateKey: old and new validator_id are identical")]
    KeyRotationNoOp,
    #[error("RotateKey: old_validator_id does not match stored validator_id")]
    OldKeyMismatch,
    #[error("ValidatorSet rebuild after apply failed: {0}")]
    SetRebuildFailed(String),
    #[error("state storage: {0}")]
    Storage(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use sccgub_types::mfidel::MfidelAtomicSeal;
    use sccgub_types::validator_set::RemovalReason;

    fn record(agent: u8, validator: u8, power: u64, from: u64) -> ValidatorRecord {
        ValidatorRecord {
            agent_id: [agent; 32],
            validator_id: [validator; 32],
            mfidel_seal: MfidelAtomicSeal::from_height(from),
            voting_power: power,
            active_from: from,
            active_until: None,
        }
    }

    fn signed_change(kind: ValidatorSetChangeKind, proposed_at: u64) -> ValidatorSetChange {
        let change_id = ValidatorSetChange::compute_change_id(&kind, proposed_at);
        ValidatorSetChange {
            change_id,
            kind,
            proposed_at,
            quorum_signatures: vec![],
        }
    }

    fn seed_state_with_set(records: Vec<ValidatorRecord>) -> ManagedWorldState {
        let set = ValidatorSet::new(records).unwrap();
        let mut state = ManagedWorldState::new();
        commit_validator_set(&mut state, &set);
        state
    }

    #[test]
    fn patch_04_commit_and_read_validator_set() {
        let set = ValidatorSet::new(vec![record(1, 10, 30, 0), record(2, 20, 40, 0)]).unwrap();
        let mut state = ManagedWorldState::new();
        commit_validator_set(&mut state, &set);
        let loaded = validator_set_from_trie(&state).unwrap().unwrap();
        assert_eq!(loaded, set);
    }

    #[test]
    fn patch_04_validator_set_trie_key_in_system_namespace() {
        assert!(VALIDATOR_SET_TRIE_KEY.starts_with(b"system/"));
        assert!(PENDING_VALIDATOR_SET_CHANGES_TRIE_KEY.starts_with(b"system/"));
    }

    #[test]
    fn patch_04_admission_rejects_inconsistent_change_id() {
        let mut state = seed_state_with_set(vec![record(1, 10, 30, 0)]);
        let kind = ValidatorSetChangeKind::RotatePower {
            agent_id: [1; 32],
            new_voting_power: 50,
            effective_height: 10,
        };
        let mut change = signed_change(kind, 5);
        change.change_id = [0xFF; 32]; // tamper
        let err = apply_validator_set_change_admission(&mut state, change);
        assert!(matches!(err, Err(ValidatorSetStateError::ChangeIdMismatch)));
    }

    #[test]
    fn patch_04_admission_rejects_duplicate_change_id() {
        let mut state = seed_state_with_set(vec![record(1, 10, 30, 0)]);
        let kind = ValidatorSetChangeKind::RotatePower {
            agent_id: [1; 32],
            new_voting_power: 50,
            effective_height: 10,
        };
        let change = signed_change(kind, 5);
        apply_validator_set_change_admission(&mut state, change.clone()).unwrap();
        let err = apply_validator_set_change_admission(&mut state, change);
        assert!(matches!(
            err,
            Err(ValidatorSetStateError::DuplicateChangeId)
        ));
    }

    #[test]
    fn patch_04_pending_queue_canonically_ordered() {
        let mut state = seed_state_with_set(vec![record(1, 10, 30, 0), record(2, 20, 30, 0)]);
        let change_high = signed_change(
            ValidatorSetChangeKind::Remove {
                agent_id: [1; 32],
                reason: RemovalReason::Voluntary,
                effective_height: 20,
            },
            5,
        );
        let change_low = signed_change(
            ValidatorSetChangeKind::Remove {
                agent_id: [2; 32],
                reason: RemovalReason::Voluntary,
                effective_height: 10,
            },
            6,
        );
        apply_validator_set_change_admission(&mut state, change_high).unwrap();
        apply_validator_set_change_admission(&mut state, change_low).unwrap();
        let pending = pending_changes_from_trie(&state).unwrap();
        assert_eq!(pending[0].kind.effective_height(), 10);
        assert_eq!(pending[1].kind.effective_height(), 20);
    }

    #[test]
    fn patch_04_advance_applies_add_at_effective_height() {
        let mut state = seed_state_with_set(vec![record(1, 10, 30, 0)]);
        let new_record = record(2, 20, 25, 7);
        let kind = ValidatorSetChangeKind::Add(new_record.clone());
        let change = signed_change(kind, 5);
        apply_validator_set_change_admission(&mut state, change).unwrap();

        // Before effective height: set unchanged.
        let drained = advance_validator_set_to_height(&mut state, 6).unwrap();
        assert!(drained.is_empty());
        let set = validator_set_from_trie(&state).unwrap().unwrap();
        assert_eq!(set.records().len(), 1);

        // At effective height: set grows.
        let drained = advance_validator_set_to_height(&mut state, 7).unwrap();
        assert_eq!(drained.len(), 1);
        let set = validator_set_from_trie(&state).unwrap().unwrap();
        assert_eq!(set.records().len(), 2);
        assert!(set.find_by_agent(&new_record.agent_id).is_some());
    }

    #[test]
    fn patch_04_advance_applies_remove_as_active_until() {
        let mut state = seed_state_with_set(vec![record(1, 10, 30, 0), record(2, 20, 30, 0)]);
        let kind = ValidatorSetChangeKind::Remove {
            agent_id: [2; 32],
            reason: RemovalReason::Governance,
            effective_height: 12,
        };
        let change = signed_change(kind, 5);
        apply_validator_set_change_admission(&mut state, change).unwrap();
        advance_validator_set_to_height(&mut state, 12).unwrap();

        let set = validator_set_from_trie(&state).unwrap().unwrap();
        let agent2 = set.find_by_agent(&[2; 32]).unwrap();
        assert_eq!(agent2.active_until, Some(11));
        assert!(!agent2.is_active_at(12));
        assert!(agent2.is_active_at(11));
    }

    #[test]
    fn patch_04_advance_applies_rotate_power() {
        let mut state = seed_state_with_set(vec![record(1, 10, 30, 0)]);
        let kind = ValidatorSetChangeKind::RotatePower {
            agent_id: [1; 32],
            new_voting_power: 75,
            effective_height: 10,
        };
        apply_validator_set_change_admission(&mut state, signed_change(kind, 5)).unwrap();
        advance_validator_set_to_height(&mut state, 10).unwrap();
        let set = validator_set_from_trie(&state).unwrap().unwrap();
        assert_eq!(set.find_by_agent(&[1; 32]).unwrap().voting_power, 75);
    }

    #[test]
    fn patch_04_advance_applies_rotate_key() {
        let mut state = seed_state_with_set(vec![record(1, 10, 30, 0)]);
        let kind = ValidatorSetChangeKind::RotateKey {
            agent_id: [1; 32],
            old_validator_id: [10; 32],
            new_validator_id: [11; 32],
            effective_height: 8,
        };
        apply_validator_set_change_admission(&mut state, signed_change(kind, 4)).unwrap();
        advance_validator_set_to_height(&mut state, 8).unwrap();
        let set = validator_set_from_trie(&state).unwrap().unwrap();
        let r = set.find_by_agent(&[1; 32]).unwrap();
        assert_eq!(r.validator_id, [11; 32]);
    }

    #[test]
    fn patch_04_rotate_key_rejects_mismatched_old_key() {
        let mut state = seed_state_with_set(vec![record(1, 10, 30, 0)]);
        let kind = ValidatorSetChangeKind::RotateKey {
            agent_id: [1; 32],
            old_validator_id: [99; 32], // wrong
            new_validator_id: [11; 32],
            effective_height: 8,
        };
        apply_validator_set_change_admission(&mut state, signed_change(kind, 4)).unwrap();
        let err = advance_validator_set_to_height(&mut state, 8);
        assert!(matches!(err, Err(ValidatorSetStateError::OldKeyMismatch)));
    }

    #[test]
    fn patch_04_rotate_key_rejects_reused_key() {
        let mut state = seed_state_with_set(vec![record(1, 10, 30, 0), record(2, 20, 30, 0)]);
        let kind = ValidatorSetChangeKind::RotateKey {
            agent_id: [1; 32],
            old_validator_id: [10; 32],
            new_validator_id: [20; 32], // already used by agent 2
            effective_height: 8,
        };
        apply_validator_set_change_admission(&mut state, signed_change(kind, 4)).unwrap();
        let err = advance_validator_set_to_height(&mut state, 8);
        assert!(matches!(
            err,
            Err(ValidatorSetStateError::ValidatorIdAlreadyInUse)
        ));
    }

    #[test]
    fn patch_04_rotate_power_rejects_zero_power() {
        let mut state = seed_state_with_set(vec![record(1, 10, 30, 0)]);
        let kind = ValidatorSetChangeKind::RotatePower {
            agent_id: [1; 32],
            new_voting_power: 0,
            effective_height: 5,
        };
        apply_validator_set_change_admission(&mut state, signed_change(kind, 3)).unwrap();
        let err = advance_validator_set_to_height(&mut state, 5);
        assert!(matches!(err, Err(ValidatorSetStateError::ZeroVotingPower)));
    }

    #[test]
    fn patch_04_add_rejects_duplicate_agent_id() {
        let mut state = seed_state_with_set(vec![record(1, 10, 30, 0)]);
        let kind = ValidatorSetChangeKind::Add(record(1, 99, 50, 5));
        apply_validator_set_change_admission(&mut state, signed_change(kind, 2)).unwrap();
        let err = advance_validator_set_to_height(&mut state, 5);
        assert!(matches!(
            err,
            Err(ValidatorSetStateError::AgentAlreadyPresent)
        ));
    }

    #[test]
    fn patch_04_add_rejects_reused_validator_id() {
        let mut state = seed_state_with_set(vec![record(1, 10, 30, 0)]);
        let kind = ValidatorSetChangeKind::Add(record(2, 10, 50, 5));
        apply_validator_set_change_admission(&mut state, signed_change(kind, 2)).unwrap();
        let err = advance_validator_set_to_height(&mut state, 5);
        assert!(matches!(
            err,
            Err(ValidatorSetStateError::ValidatorIdAlreadyInUse)
        ));
    }

    #[test]
    fn patch_04_validator_set_replay_determinism() {
        // Build a deterministic 100+ event scenario: 30 Adds, 30 RotatePower,
        // 20 RotateKey, 20 Remove. Apply all and compare state roots of
        // two independent applications.

        fn build_and_run() -> (ValidatorSet, sccgub_types::Hash) {
            let mut state = seed_state_with_set(vec![record(0, 0, 10, 0)]);

            let mut next_effective = 1u64;
            let mut next_agent: u8 = 1;
            let mut next_validator: u8 = 128;

            // 30 Adds
            for _ in 0..30 {
                let kind = ValidatorSetChangeKind::Add(record(
                    next_agent,
                    next_validator,
                    10,
                    next_effective,
                ));
                apply_validator_set_change_admission(
                    &mut state,
                    signed_change(kind, next_effective.saturating_sub(1)),
                )
                .unwrap();
                advance_validator_set_to_height(&mut state, next_effective).unwrap();
                next_effective += 1;
                next_agent = next_agent.wrapping_add(1);
                next_validator = next_validator.wrapping_add(1);
            }

            // 30 RotatePower on existing agents 1..=30
            for i in 1..=30u8 {
                let kind = ValidatorSetChangeKind::RotatePower {
                    agent_id: [i; 32],
                    new_voting_power: 20 + i as u64,
                    effective_height: next_effective,
                };
                apply_validator_set_change_admission(
                    &mut state,
                    signed_change(kind, next_effective.saturating_sub(1)),
                )
                .unwrap();
                advance_validator_set_to_height(&mut state, next_effective).unwrap();
                next_effective += 1;
            }

            // 20 RotateKey
            for i in 1..=20u8 {
                let old_id = 128u8.wrapping_add(i - 1);
                let new_id = next_validator;
                let kind = ValidatorSetChangeKind::RotateKey {
                    agent_id: [i; 32],
                    old_validator_id: [old_id; 32],
                    new_validator_id: [new_id; 32],
                    effective_height: next_effective,
                };
                apply_validator_set_change_admission(
                    &mut state,
                    signed_change(kind, next_effective.saturating_sub(1)),
                )
                .unwrap();
                advance_validator_set_to_height(&mut state, next_effective).unwrap();
                next_effective += 1;
                next_validator = next_validator.wrapping_add(1);
            }

            // 20 Removes (on agents 11..=30)
            for i in 11..=30u8 {
                let kind = ValidatorSetChangeKind::Remove {
                    agent_id: [i; 32],
                    reason: RemovalReason::Voluntary,
                    effective_height: next_effective,
                };
                apply_validator_set_change_admission(
                    &mut state,
                    signed_change(kind, next_effective.saturating_sub(1)),
                )
                .unwrap();
                advance_validator_set_to_height(&mut state, next_effective).unwrap();
                next_effective += 1;
            }

            let set = validator_set_from_trie(&state).unwrap().unwrap();
            let root = state.state_root();
            (set, root)
        }

        let (set_a, root_a) = build_and_run();
        let (set_b, root_b) = build_and_run();
        assert_eq!(set_a, set_b, "ValidatorSet diverges between replays");
        assert_eq!(root_a, root_b, "state_root diverges between replays");
        // Spot-check cardinality: started with 1 record, added 30, removed 20 → 11 records remain.
        assert_eq!(set_a.records().len(), 31); // 1 genesis + 30 added; Remove sets active_until but keeps record.
    }

    #[test]
    fn patch_04_pending_change_stays_when_effective_height_in_future() {
        let mut state = seed_state_with_set(vec![record(1, 10, 30, 0)]);
        let kind = ValidatorSetChangeKind::Remove {
            agent_id: [1; 32],
            reason: RemovalReason::Voluntary,
            effective_height: 100,
        };
        apply_validator_set_change_admission(&mut state, signed_change(kind, 5)).unwrap();
        // Advance to heights < 100 several times; pending must still contain the change.
        advance_validator_set_to_height(&mut state, 10).unwrap();
        advance_validator_set_to_height(&mut state, 50).unwrap();
        advance_validator_set_to_height(&mut state, 99).unwrap();
        assert_eq!(pending_changes_from_trie(&state).unwrap().len(), 1);
        advance_validator_set_to_height(&mut state, 100).unwrap();
        assert!(pending_changes_from_trie(&state).unwrap().is_empty());
    }
}
