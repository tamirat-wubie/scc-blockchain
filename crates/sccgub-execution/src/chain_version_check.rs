//! Patch-06 §34.6 chain-version alignment check (phase 0 / pre-Phi).
//!
//! INV-UPGRADE-ATOMICITY: a block's declared version MUST match the
//! chain-version rule active at its height. A block is rejected if:
//!
//! - It claims a version >= v_next but sits at height `h < activation_height`, OR
//! - It claims a version < v_next but sits at height `h >= activation_height`.
//!
//! The check is pure; the caller looks up the relevant
//! `ChainVersionTransition` from `system/chain_version_history` and
//! hands the record(s) to this module.

use sccgub_types::upgrade::ChainVersionTransition;

/// Outcome of a phase-0 version alignment check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChainVersionCheck {
    /// Block's version matches the active rule at its height.
    Aligned,
    /// Block declares a version that does not match the active rule.
    Misaligned(ChainVersionRejection),
}

impl ChainVersionCheck {
    pub fn is_aligned(&self) -> bool {
        matches!(self, Self::Aligned)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ChainVersionRejection {
    #[error(
        "block at height {block_height} declares version {block_version}, but active rule \
         at this height is version {active_version} (transition at {activation_height})"
    )]
    VersionOutOfAlignment {
        block_height: u64,
        block_version: u32,
        active_version: u32,
        activation_height: u64,
    },
}

/// §34.6 predicate. Returns `Aligned` iff `block_version` matches the
/// rule that is active at `block_height`, given the sorted history of
/// `ChainVersionTransition` records.
///
/// `transitions` MUST be sorted ascending by `activation_height`. The
/// caller supplies the initial chain version (from genesis) so the
/// check can decide the correct version when no transitions have fired
/// yet.
pub fn verify_block_version_alignment(
    block_height: u64,
    block_version: u32,
    genesis_chain_version: u32,
    transitions: &[ChainVersionTransition],
) -> ChainVersionCheck {
    let mut active_version = genesis_chain_version;
    let mut effective_activation = 0u64;
    for t in transitions {
        if t.activation_height <= block_height {
            active_version = t.to_version;
            effective_activation = t.activation_height;
        } else {
            break;
        }
    }
    if active_version == block_version {
        ChainVersionCheck::Aligned
    } else {
        ChainVersionCheck::Misaligned(ChainVersionRejection::VersionOutOfAlignment {
            block_height,
            block_version,
            active_version,
            activation_height: effective_activation,
        })
    }
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
    fn patch_06_aligns_when_no_transitions() {
        let r = verify_block_version_alignment(100, 4, 4, &[]);
        assert!(r.is_aligned());
    }

    #[test]
    fn patch_06_misaligned_when_no_transitions_and_version_wrong() {
        let r = verify_block_version_alignment(100, 5, 4, &[]);
        assert!(matches!(
            r,
            ChainVersionCheck::Misaligned(ChainVersionRejection::VersionOutOfAlignment { .. })
        ));
    }

    #[test]
    fn patch_06_pre_activation_uses_genesis_version() {
        // Transition at height 200; block at 100 still uses genesis v4.
        let ts = vec![transition(5, 200)];
        let ok = verify_block_version_alignment(100, 4, 4, &ts);
        assert!(ok.is_aligned());
        let bad = verify_block_version_alignment(100, 5, 4, &ts);
        assert!(matches!(
            bad,
            ChainVersionCheck::Misaligned(ChainVersionRejection::VersionOutOfAlignment {
                active_version: 4,
                ..
            })
        ));
    }

    #[test]
    fn patch_06_post_activation_uses_target_version() {
        let ts = vec![transition(5, 200)];
        let ok = verify_block_version_alignment(250, 5, 4, &ts);
        assert!(ok.is_aligned());
        let bad = verify_block_version_alignment(250, 4, 4, &ts);
        assert!(matches!(
            bad,
            ChainVersionCheck::Misaligned(ChainVersionRejection::VersionOutOfAlignment {
                active_version: 5,
                ..
            })
        ));
    }

    #[test]
    fn patch_06_transition_at_exact_activation_height() {
        // §34.4: activation is atomic AT the height (>= activation_height).
        let ts = vec![transition(5, 200)];
        let ok = verify_block_version_alignment(200, 5, 4, &ts);
        assert!(ok.is_aligned());
    }

    #[test]
    fn patch_06_multiple_transitions_apply_in_order() {
        // v4 → v5 at 200, v5 → v6 at 400.
        let ts = vec![transition(5, 200), transition(6, 400)];
        // Before first: v4.
        assert!(verify_block_version_alignment(100, 4, 4, &ts).is_aligned());
        // Between: v5.
        assert!(verify_block_version_alignment(300, 5, 4, &ts).is_aligned());
        // After second: v6.
        assert!(verify_block_version_alignment(500, 6, 4, &ts).is_aligned());
    }

    #[test]
    fn patch_06_rejects_v_next_block_before_activation() {
        // Attacker submits a v5 block at height 150 when activation is at 200.
        let ts = vec![transition(5, 200)];
        let r = verify_block_version_alignment(150, 5, 4, &ts);
        assert!(matches!(
            r,
            ChainVersionCheck::Misaligned(ChainVersionRejection::VersionOutOfAlignment {
                active_version: 4,
                ..
            })
        ));
    }

    #[test]
    fn patch_06_rejects_v_current_block_after_activation() {
        // Stale v4 block submitted at height 300 when v5 has been active since 200.
        let ts = vec![transition(5, 200)];
        let r = verify_block_version_alignment(300, 4, 4, &ts);
        assert!(matches!(
            r,
            ChainVersionCheck::Misaligned(ChainVersionRejection::VersionOutOfAlignment {
                active_version: 5,
                ..
            })
        ));
    }
}
