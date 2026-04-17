//! Phase-10 constitutional-ceiling enforcement (Patch-04 §17.4).
//!
//! At phase 10 (Architecture) on v3 blocks, the active `ConsensusParams`
//! is checked against the genesis-committed `ConstitutionalCeilings`.
//! Any field that would violate a ceiling rejects the block.
//!
//! Pre-v3 chains have no `system/constitutional_ceilings` entry; the
//! validator short-circuits to `CeilingCheck::NotV3` in that case so
//! legacy chains continue to replay unchanged.

use sccgub_state::constitutional_ceilings_state::constitutional_ceilings_from_trie;
use sccgub_state::world::ManagedWorldState;
use sccgub_types::block::{BlockHeader, PATCH_04_BLOCK_VERSION};
use sccgub_types::constitutional_ceilings::CeilingViolation;

/// Outcome of the phase-10 ceiling check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CeilingCheck {
    /// Block is v3 and every (param, ceiling) pair is in range.
    Valid,
    /// Block is v2 or earlier — no v3 ceiling enforcement applies.
    NotV3,
    /// v3 block but no `system/constitutional_ceilings` entry present.
    /// Should not occur in a well-formed v3 chain (§19.1 requires it at
    /// genesis) — surfaced as a distinct variant so the upstream phase
    /// reports it explicitly rather than masking it as Valid.
    CeilingsMissing,
    /// A `ConsensusParams` field exceeds its constitutional ceiling.
    Violation(CeilingViolation),
    /// Ceilings bytes exist but deserialize or storage failed.
    Error(String),
}

impl CeilingCheck {
    pub fn is_pass(&self) -> bool {
        matches!(self, Self::Valid | Self::NotV3)
    }
}

/// Phase-10 ceiling validator. Returns `CeilingCheck::NotV3` for
/// non-v3 blocks (phase 10 skips ceiling enforcement then). For v3
/// blocks, loads `ConstitutionalCeilings` from the trie and validates
/// `state.consensus_params` against it.
pub fn validate_ceilings_for_block(
    state: &ManagedWorldState,
    header: &BlockHeader,
) -> CeilingCheck {
    if header.version < PATCH_04_BLOCK_VERSION {
        return CeilingCheck::NotV3;
    }
    let ceilings = match constitutional_ceilings_from_trie(state) {
        Ok(Some(c)) => c,
        Ok(None) => return CeilingCheck::CeilingsMissing,
        Err(e) => return CeilingCheck::Error(e),
    };
    match ceilings.validate(&state.consensus_params) {
        Ok(()) => CeilingCheck::Valid,
        Err(v) => CeilingCheck::Violation(v),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sccgub_state::constitutional_ceilings_state::commit_constitutional_ceilings_at_genesis;
    use sccgub_types::block::{CANONICAL_AGENT_BLOCK_VERSION, LEGACY_BLOCK_VERSION};
    use sccgub_types::consensus_params::ConsensusParams;
    use sccgub_types::constitutional_ceilings::ConstitutionalCeilings;
    use sccgub_types::mfidel::MfidelAtomicSeal;
    use sccgub_types::tension::TensionValue;
    use sccgub_types::timestamp::CausalTimestamp;
    use sccgub_types::ZERO_HASH;

    fn header_with_version(version: u32) -> BlockHeader {
        BlockHeader {
            chain_id: ZERO_HASH,
            block_id: ZERO_HASH,
            parent_id: ZERO_HASH,
            height: 0,
            timestamp: CausalTimestamp::genesis(),
            state_root: ZERO_HASH,
            transition_root: ZERO_HASH,
            receipt_root: ZERO_HASH,
            causal_root: ZERO_HASH,
            proof_root: ZERO_HASH,
            governance_hash: ZERO_HASH,
            tension_before: TensionValue::ZERO,
            tension_after: TensionValue::ZERO,
            mfidel_seal: MfidelAtomicSeal::from_height(0),
            balance_root: ZERO_HASH,
            validator_id: [1; 32],
            version,
            round_history_root: ZERO_HASH,
        }
    }

    #[test]
    fn patch_04_legacy_blocks_skip_ceiling_check() {
        let state = ManagedWorldState::new();
        let header = header_with_version(LEGACY_BLOCK_VERSION);
        assert!(matches!(
            validate_ceilings_for_block(&state, &header),
            CeilingCheck::NotV3
        ));
    }

    #[test]
    fn patch_04_v2_blocks_skip_ceiling_check() {
        let state = ManagedWorldState::new();
        let header = header_with_version(CANONICAL_AGENT_BLOCK_VERSION);
        assert!(matches!(
            validate_ceilings_for_block(&state, &header),
            CeilingCheck::NotV3
        ));
    }

    #[test]
    fn patch_04_v3_block_with_ceilings_and_default_params_passes() {
        let mut state = ManagedWorldState::new();
        commit_constitutional_ceilings_at_genesis(
            &mut state,
            &ConstitutionalCeilings::default(),
        )
        .unwrap();
        let header = header_with_version(PATCH_04_BLOCK_VERSION);
        assert_eq!(
            validate_ceilings_for_block(&state, &header),
            CeilingCheck::Valid
        );
    }

    #[test]
    fn patch_04_phase_10_rejects_ceiling_violation() {
        // Hand-craft ConsensusParams with default_tx_gas_limit exceeding
        // the ceiling, confirm the validator reports MaxTxGas.
        let mut state = ManagedWorldState::new();
        let ceilings = ConstitutionalCeilings::default();
        commit_constitutional_ceilings_at_genesis(&mut state, &ceilings).unwrap();

        let over_limit = ceilings.max_tx_gas_ceiling + 1;
        state.consensus_params = ConsensusParams {
            default_tx_gas_limit: over_limit,
            default_block_gas_limit: over_limit + 1,
            ..ConsensusParams::default()
        };

        let header = header_with_version(PATCH_04_BLOCK_VERSION);
        let result = validate_ceilings_for_block(&state, &header);
        assert!(matches!(
            result,
            CeilingCheck::Violation(CeilingViolation::MaxTxGas { .. })
        ));
    }

    #[test]
    fn patch_04_v3_block_without_committed_ceilings_flagged() {
        let state = ManagedWorldState::new();
        let header = header_with_version(PATCH_04_BLOCK_VERSION);
        assert!(matches!(
            validate_ceilings_for_block(&state, &header),
            CeilingCheck::CeilingsMissing
        ));
    }

    #[test]
    fn patch_04_ceiling_check_is_pass_semantics() {
        assert!(CeilingCheck::Valid.is_pass());
        assert!(CeilingCheck::NotV3.is_pass());
        assert!(!CeilingCheck::CeilingsMissing.is_pass());
        assert!(!CeilingCheck::Violation(CeilingViolation::MaxProofDepth {
            value: 0,
            ceiling: 0
        })
        .is_pass());
    }
}
