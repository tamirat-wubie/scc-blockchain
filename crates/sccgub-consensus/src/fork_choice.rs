//! Patch-06 §32 fork-choice rule.
//!
//! Before Patch-06, honest nodes had no declared rule for selecting among
//! candidate tips on a partition recovery. The implicit "first-seen" rule
//! is dependent on message-arrival order — not deterministic across the
//! active set. §32 closes the gap with a declared lexicographic rule:
//!
//! ```text
//! score(tip) = (finalized_depth, cumulative_voting_power, tie_break_hash)
//! ```
//!
//! Higher is preferred. Comparison is lexicographic, so a chain with more
//! finalized blocks wins regardless of how much raw work its competitor
//! carries; ties break on cumulative voting power (more signed work
//! wins), then on the tip hash as a final total-order settlement.
//!
//! Reorg safety: a reorg that would revert any block whose finalized
//! depth `>= confirmation_depth` is rejected as a **consensus fault**
//! and does NOT apply, regardless of the score comparison.
//!
//! Pure + deterministic: `select_canonical_tip` is a function of the
//! candidate list only. No wall-clock, no randomness, no iteration over
//! hash-ordered containers. Exercised by replay determinism tests.

use sccgub_types::Hash;
use std::cmp::Ordering;

/// Canonical tip summary fed to the fork-choice rule. Built by the caller
/// from a candidate chain's local view; all three components MUST be
/// deterministic functions of the chain's block/vote history.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChainTip {
    /// Tip block hash; the §32.2 tie-break value.
    pub block_id: Hash,
    /// Tip block height.
    pub height: u64,
    /// Number of ancestors of `tip` (inclusive) that have reached finality
    /// (signed by `>= 2/3` of the active set at their height).
    pub finalized_depth: u64,
    /// Saturating sum across every ancestor block `b` of
    /// `sum(voting_power)` over precommit signers on `b`, mod 2^64.
    pub cumulative_voting_power: u64,
}

impl ChainTip {
    /// §32.2 lexicographic score ordering. Returns the standard `Ordering`:
    /// `Greater` means "this tip is preferred over `other`."
    pub fn score_cmp(&self, other: &Self) -> Ordering {
        match self.finalized_depth.cmp(&other.finalized_depth) {
            Ordering::Equal => {}
            ne => return ne,
        }
        match self
            .cumulative_voting_power
            .cmp(&other.cumulative_voting_power)
        {
            Ordering::Equal => {}
            ne => return ne,
        }
        // Final tie-break: tip hash as unsigned big-endian integer.
        // Arrays of equal length compare lexicographically, which
        // matches big-endian integer order for fixed-width Hash.
        self.block_id.cmp(&other.block_id)
    }
}

/// Outcome of selecting a canonical tip from a candidate list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ForkChoiceOutcome {
    /// Exactly one tip wins. Returns its index in the input slice.
    Selected(usize),
    /// No candidates supplied.
    Empty,
}

/// §32.2 canonical tip selection. Given `candidates`, returns the index of
/// the highest-scoring tip under the §32.2 lexicographic rule.
///
/// Determinism: ties cannot occur because `tie_break_hash` is a total
/// order over 32-byte hashes, and distinct blocks have distinct ids.
/// Two honest nodes seeing the same candidate list therefore return the
/// same winner — the core of INV-FORK-CHOICE-DETERMINISM.
pub fn select_canonical_tip(candidates: &[ChainTip]) -> ForkChoiceOutcome {
    if candidates.is_empty() {
        return ForkChoiceOutcome::Empty;
    }
    let mut best = 0usize;
    for (i, tip) in candidates.iter().enumerate().skip(1) {
        if tip.score_cmp(&candidates[best]) == Ordering::Greater {
            best = i;
        }
    }
    ForkChoiceOutcome::Selected(best)
}

/// §32.3 reorg-safety predicate.
///
/// Returns `Ok(())` if switching from `current` to `alternative` is safe
/// — i.e., the alternative does not attempt to revert any block whose
/// finalized depth `>= confirmation_depth`. Returns `Err` otherwise.
///
/// Parameters:
///
/// - `current`: the tip the node currently considers canonical.
/// - `alternative`: the proposed new tip.
/// - `common_ancestor_height`: height of the latest block both chains
///   share. Blocks above this height on `current` would be reverted.
/// - `current_deepest_finalized_above_fork`: the greatest
///   `finalized_depth` among blocks on `current` with height
///   `> common_ancestor_height`. If no such finalized block exists,
///   the caller passes `0`.
/// - `confirmation_depth`: the active `ConsensusParams::confirmation_depth`.
pub fn is_safe_reorg(
    current: &ChainTip,
    alternative: &ChainTip,
    common_ancestor_height: u64,
    current_deepest_finalized_above_fork: u64,
    confirmation_depth: u64,
) -> Result<(), ReorgRejection> {
    // The alternative must actually outscore the current tip. A lower or
    // equal score is not a reorg; the caller shouldn't ask.
    if alternative.score_cmp(current) != Ordering::Greater {
        return Err(ReorgRejection::AlternativeDoesNotOutscore);
    }
    // §32.3 safety: do not revert any finalized block.
    if current_deepest_finalized_above_fork >= confirmation_depth {
        return Err(ReorgRejection::RevertPastFinality {
            common_ancestor_height,
            deepest_finalized_depth: current_deepest_finalized_above_fork,
            confirmation_depth,
        });
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ReorgRejection {
    #[error("alternative tip does not outscore the current canonical tip")]
    AlternativeDoesNotOutscore,
    #[error(
        "reorg would revert a finalized block: above fork height {common_ancestor_height} \
         a block is finalized at depth {deepest_finalized_depth} (>= \
         confirmation_depth {confirmation_depth})"
    )]
    RevertPastFinality {
        common_ancestor_height: u64,
        deepest_finalized_depth: u64,
        confirmation_depth: u64,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tip(height: u64, finalized: u64, power: u64, id_byte: u8) -> ChainTip {
        ChainTip {
            block_id: [id_byte; 32],
            height,
            finalized_depth: finalized,
            cumulative_voting_power: power,
        }
    }

    #[test]
    fn patch_06_select_empty_returns_empty() {
        assert_eq!(select_canonical_tip(&[]), ForkChoiceOutcome::Empty);
    }

    #[test]
    fn patch_06_select_single_candidate_wins() {
        let only = tip(10, 2, 100, 0x11);
        assert_eq!(
            select_canonical_tip(&[only]),
            ForkChoiceOutcome::Selected(0)
        );
    }

    #[test]
    fn patch_06_higher_finalized_depth_wins() {
        // Chain A: fewer finalized blocks but huge cumulative power.
        let a = tip(10, 1, 1_000_000, 0xAA);
        // Chain B: more finalized blocks, less power.
        let b = tip(10, 3, 100, 0xBB);
        let r = select_canonical_tip(&[a, b]);
        // §32.2: finalized_depth is the primary component. B wins.
        assert_eq!(r, ForkChoiceOutcome::Selected(1));
    }

    #[test]
    fn patch_06_equal_finalized_depth_power_wins() {
        // Tied finalized depth; higher cumulative power wins.
        let a = tip(10, 2, 500, 0xAA);
        let b = tip(10, 2, 1000, 0xBB);
        let r = select_canonical_tip(&[a, b]);
        assert_eq!(r, ForkChoiceOutcome::Selected(1));
    }

    #[test]
    fn patch_06_tie_break_on_hash_deterministic() {
        // Identical on the first two components — tie-break on block_id.
        let a = tip(10, 2, 1000, 0x01);
        let b = tip(10, 2, 1000, 0x02);
        let r = select_canonical_tip(&[a, b]);
        // b's block_id [0x02; 32] > a's [0x01; 32] → b wins.
        assert_eq!(r, ForkChoiceOutcome::Selected(1));
    }

    #[test]
    fn patch_06_select_is_order_independent() {
        // INV-FORK-CHOICE-DETERMINISM: two honest nodes seeing the same
        // candidates in different orders MUST select the same tip.
        let a = tip(10, 1, 1000, 0x01);
        let b = tip(10, 2, 500, 0xBB);
        let c = tip(10, 2, 500, 0xCC);
        // Best should be c (highest finalized tied with b, higher hash).
        let r1 = select_canonical_tip(&[a, b, c]);
        let r2 = select_canonical_tip(&[c, b, a]);
        let r3 = select_canonical_tip(&[b, a, c]);
        // The winning tip has id 0xCC regardless of input order.
        match (r1, r2, r3) {
            (
                ForkChoiceOutcome::Selected(i1),
                ForkChoiceOutcome::Selected(i2),
                ForkChoiceOutcome::Selected(i3),
            ) => {
                let cands = [&[a, b, c][..], &[c, b, a][..], &[b, a, c][..]];
                assert_eq!(cands[0][i1].block_id, [0xCC; 32]);
                assert_eq!(cands[1][i2].block_id, [0xCC; 32]);
                assert_eq!(cands[2][i3].block_id, [0xCC; 32]);
            }
            other => panic!("expected three Selected outcomes, got {:?}", other),
        }
    }

    #[test]
    fn patch_06_reorg_rejected_past_finality() {
        let current = tip(20, 5, 500, 0xAA);
        let alternative = tip(22, 6, 600, 0xBB);
        let result = is_safe_reorg(&current, &alternative, 10, 5, 2);
        assert!(matches!(
            result,
            Err(ReorgRejection::RevertPastFinality { .. })
        ));
    }

    #[test]
    fn patch_06_reorg_allowed_when_no_finalized_blocks_above_fork() {
        let current = tip(20, 5, 500, 0xAA);
        let alternative = tip(22, 6, 600, 0xBB);
        // 0 finalized blocks above fork means nothing gets reverted that
        // was finalized. Reorg is safe.
        let result = is_safe_reorg(&current, &alternative, 10, 0, 2);
        assert!(result.is_ok());
    }

    #[test]
    fn patch_06_reorg_rejected_when_alternative_does_not_outscore() {
        let current = tip(20, 5, 1000, 0xAA);
        let alternative = tip(20, 5, 500, 0xBB); // lower power
        let result = is_safe_reorg(&current, &alternative, 10, 0, 2);
        // Even without finality concerns, a non-outscoring alternative is
        // rejected.
        assert!(matches!(
            result,
            Err(ReorgRejection::AlternativeDoesNotOutscore)
        ));
    }

    #[test]
    fn patch_06_score_cmp_transitive() {
        // score_cmp must impose a total order; test transitivity over a
        // small sample.
        let a = tip(10, 1, 100, 0x01);
        let b = tip(10, 2, 100, 0x02);
        let c = tip(10, 3, 100, 0x03);
        assert_eq!(a.score_cmp(&b), Ordering::Less);
        assert_eq!(b.score_cmp(&c), Ordering::Less);
        assert_eq!(a.score_cmp(&c), Ordering::Less);
    }
}
