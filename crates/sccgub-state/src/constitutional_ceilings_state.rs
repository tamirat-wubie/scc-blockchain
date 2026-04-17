//! Constitutional-ceilings state management for Patch-04 v3 (§17).
//!
//! `ConstitutionalCeilings` is written exactly once at genesis. Any
//! subsequent write attempt is a phase-6 (Organization) violation; this
//! module enforces the write-once rule via `commit_constitutional_ceilings_at_genesis`.
//!
//! The read helper `constitutional_ceilings_from_trie` returns `Ok(None)`
//! for pre-v3 chains so callers can conditionally skip the §17.4
//! phase-10 ceiling-validity check when replaying a v2 chain.

use sccgub_types::constitutional_ceilings::ConstitutionalCeilings;
use sccgub_types::transition::{StateDelta, StateWrite};

use crate::world::ManagedWorldState;

/// Canonical trie key: `system/constitutional_ceilings`.
pub use sccgub_types::constitutional_ceilings::ConstitutionalCeilings as _Ceilings;

/// Write the genesis `ConstitutionalCeilings` record. Fails closed if the
/// key is already present — §17.7 declares the write-once rule. Callers
/// MUST only invoke this during v3 genesis construction; subsequent
/// writes are prohibited (re-writing attempts at non-genesis heights
/// are rejected by phase 6 in the execution layer).
pub fn commit_constitutional_ceilings_at_genesis(
    state: &mut ManagedWorldState,
    ceilings: &ConstitutionalCeilings,
) -> Result<(), CeilingsStateError> {
    if state
        .get(&ConstitutionalCeilings::TRIE_KEY.to_vec())
        .is_some()
    {
        return Err(CeilingsStateError::AlreadyCommitted);
    }
    state.apply_delta(&StateDelta {
        writes: vec![StateWrite {
            address: ConstitutionalCeilings::TRIE_KEY.to_vec(),
            value: ceilings.to_canonical_bytes(),
        }],
        deletes: vec![],
    });
    Ok(())
}

/// Read the genesis-committed `ConstitutionalCeilings`. Returns
/// `Ok(None)` for v2 chains and for v3 chains before genesis replay has
/// committed the record. The execution layer treats `None` as "no v3
/// ceiling enforcement" when replaying a v2 genesis.
pub fn constitutional_ceilings_from_trie(
    state: &ManagedWorldState,
) -> Result<Option<ConstitutionalCeilings>, String> {
    match state.get(&ConstitutionalCeilings::TRIE_KEY.to_vec()) {
        Some(bytes) => ConstitutionalCeilings::from_canonical_bytes(bytes).map(Some),
        None => Ok(None),
    }
}

#[derive(Debug, thiserror::Error)]
pub enum CeilingsStateError {
    #[error("ConstitutionalCeilings already committed — write-once at genesis only")]
    AlreadyCommitted,
}

#[cfg(test)]
mod tests {
    use super::*;
    use sccgub_types::consensus_params::ConsensusParams;

    #[test]
    fn patch_04_commit_then_read_ceilings() {
        let mut state = ManagedWorldState::new();
        let ceilings = ConstitutionalCeilings::default();
        commit_constitutional_ceilings_at_genesis(&mut state, &ceilings).unwrap();
        let loaded = constitutional_ceilings_from_trie(&state).unwrap().unwrap();
        assert_eq!(loaded, ceilings);
    }

    #[test]
    fn patch_04_ceilings_write_once_at_genesis() {
        let mut state = ManagedWorldState::new();
        let ceilings = ConstitutionalCeilings::default();
        commit_constitutional_ceilings_at_genesis(&mut state, &ceilings).unwrap();
        let err = commit_constitutional_ceilings_at_genesis(&mut state, &ceilings);
        assert!(matches!(err, Err(CeilingsStateError::AlreadyCommitted)));
    }

    #[test]
    fn patch_04_ceilings_none_before_commit() {
        let state = ManagedWorldState::new();
        let loaded = constitutional_ceilings_from_trie(&state).unwrap();
        assert!(loaded.is_none());
    }

    #[test]
    fn patch_04_genesis_ceilings_validate_default_params() {
        // Sanity check: the default ceilings + default params must agree
        // so v3 default-constructed genesis is ceiling-valid.
        let ceilings = ConstitutionalCeilings::default();
        let params = ConsensusParams::default();
        ceilings.validate(&params).unwrap();
    }

    #[test]
    fn patch_04_ceilings_trie_key_in_system_namespace() {
        assert!(ConstitutionalCeilings::TRIE_KEY.starts_with(b"system/"));
    }
}
