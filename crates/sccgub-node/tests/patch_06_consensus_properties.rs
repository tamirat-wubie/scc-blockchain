//! Property-based tests for Patch-06 consensus invariants.
//!
//! Strengthens HELD status for the two pure-function consensus
//! invariants from Patch-06 that are unit-tested but not property-
//! tested in v0.7.1:
//!
//! - **INV-FORK-CHOICE-DETERMINISM (§32)**: `select_canonical_tip`
//!   and `score_cmp` form a total order over `ChainTip`. Random tip
//!   sets must yield: (a) the same winner regardless of input order,
//!   (b) the score_cmp relation is anti-symmetric and transitive,
//!   (c) the winner has the lex-maximum (finalized_depth,
//!   cumulative_voting_power, block_id) over the input.
//!
//! - **INV-UPGRADE-ATOMICITY (§34.6)**:
//!   `verify_block_version_alignment` enforces monotonic version
//!   selection: at any block height H, the active version is the
//!   `to_version` of the latest transition with `activation_height <= H`,
//!   or genesis_version if none. Random transition sequences must
//!   yield consistent active-version queries across all heights.
//!
//! Same deterministic xorshift PRNG pattern as
//! `tests/property_test.rs` — no new dependency.

use sccgub_consensus::fork_choice::{select_canonical_tip, ChainTip, ForkChoiceOutcome};
use sccgub_execution::chain_version_check::{verify_block_version_alignment, ChainVersionCheck};
use sccgub_types::upgrade::ChainVersionTransition;
use sccgub_types::Hash;
use std::cmp::Ordering;

/// Deterministic xorshift PRNG — matches tests/property_test.rs style.
fn prng(seed: &mut u64) -> u64 {
    *seed ^= *seed << 13;
    *seed ^= *seed >> 7;
    *seed ^= *seed << 17;
    *seed
}

fn random_hash(seed: &mut u64) -> Hash {
    let mut h = [0u8; 32];
    for chunk in h.chunks_mut(8) {
        let v = prng(seed).to_le_bytes();
        chunk.copy_from_slice(&v[..chunk.len()]);
    }
    h
}

fn random_tip(seed: &mut u64) -> ChainTip {
    ChainTip {
        block_id: random_hash(seed),
        // Bound height/finality/power to keep things interesting (lots
        // of ties at the primary components, forcing tiebreak paths).
        height: prng(seed) % 100,
        finalized_depth: prng(seed) % 8,
        cumulative_voting_power: prng(seed) % 1000,
    }
}

// ── INV-FORK-CHOICE-DETERMINISM ──────────────────────────────────────

#[test]
fn prop_fork_choice_select_is_order_independent_random() {
    // Generate a random candidate set; permute it in three different
    // ways; the selected winner's block_id must be identical across
    // all permutations.
    let mut seed = 0x1111_2222_3333_4444u64;
    for _ in 0..40 {
        let n = (prng(&mut seed) % 6) + 2; // 2..=7 candidates
        let original: Vec<ChainTip> = (0..n).map(|_| random_tip(&mut seed)).collect();

        // Three orderings of the same set.
        let mut rev = original.clone();
        rev.reverse();
        let mut shuffled = original.clone();
        if shuffled.len() >= 3 {
            shuffled.swap(0, 2);
        }

        let w0 = match select_canonical_tip(&original) {
            ForkChoiceOutcome::Selected(i) => original[i].block_id,
            _ => panic!("expected Selected for non-empty input"),
        };
        let w1 = match select_canonical_tip(&rev) {
            ForkChoiceOutcome::Selected(i) => rev[i].block_id,
            _ => panic!("expected Selected for non-empty input"),
        };
        let w2 = match select_canonical_tip(&shuffled) {
            ForkChoiceOutcome::Selected(i) => shuffled[i].block_id,
            _ => panic!("expected Selected for non-empty input"),
        };

        assert_eq!(w0, w1, "forward vs reverse order yielded different winners");
        assert_eq!(w1, w2, "reverse vs shuffled yielded different winners");
    }
}

#[test]
fn prop_fork_choice_winner_is_score_maximum() {
    // The winner must have score_cmp >= every other input.
    let mut seed = 0x5555_6666_7777_8888u64;
    for _ in 0..40 {
        let n = (prng(&mut seed) % 8) + 2;
        let candidates: Vec<ChainTip> = (0..n).map(|_| random_tip(&mut seed)).collect();
        let winner_idx = match select_canonical_tip(&candidates) {
            ForkChoiceOutcome::Selected(i) => i,
            _ => panic!("expected Selected"),
        };
        let winner = &candidates[winner_idx];
        for other in &candidates {
            assert!(
                winner.score_cmp(other) != Ordering::Less,
                "winner score must be >= every input score"
            );
        }
    }
}

#[test]
fn prop_fork_choice_score_cmp_is_antisymmetric() {
    // For any two tips A, B: score_cmp(A,B) == reverse(score_cmp(B,A)).
    let mut seed = 0x9999_aaaa_bbbb_ccccu64;
    for _ in 0..200 {
        let a = random_tip(&mut seed);
        let b = random_tip(&mut seed);
        let ab = a.score_cmp(&b);
        let ba = b.score_cmp(&a);
        assert_eq!(
            ab,
            ba.reverse(),
            "score_cmp must be antisymmetric: {:?} vs {:?}",
            ab,
            ba
        );
    }
}

#[test]
fn prop_fork_choice_score_cmp_is_transitive() {
    // For any three tips A, B, C: if A >= B and B >= C, then A >= C.
    let mut seed = 0xdddd_eeee_ffff_0000u64;
    for _ in 0..150 {
        let a = random_tip(&mut seed);
        let b = random_tip(&mut seed);
        let c = random_tip(&mut seed);
        let ab = a.score_cmp(&b);
        let bc = b.score_cmp(&c);
        let ac = a.score_cmp(&c);
        if ab != Ordering::Less && bc != Ordering::Less {
            assert!(
                ac != Ordering::Less,
                "transitivity violated: A>=B and B>=C should imply A>=C, got A<C"
            );
        }
    }
}

#[test]
fn prop_fork_choice_score_cmp_reflexive() {
    // score_cmp(A, A) == Equal for any tip A.
    let mut seed = 0x1234_5678_u64;
    for _ in 0..50 {
        let a = random_tip(&mut seed);
        assert_eq!(a.score_cmp(&a), Ordering::Equal);
    }
}

#[test]
fn prop_fork_choice_finalized_depth_dominates() {
    // INV-FORK-CHOICE-DETERMINISM primary-component property: a tip
    // with strictly-higher finalized_depth always beats a tip with
    // any (height, power, hash) combination.
    let mut seed = 0xfeed_beef_cafe_u64;
    for _ in 0..80 {
        let lower = ChainTip {
            block_id: random_hash(&mut seed),
            height: prng(&mut seed) % 1_000_000,
            finalized_depth: prng(&mut seed) % 5,
            cumulative_voting_power: prng(&mut seed),
        };
        let higher = ChainTip {
            block_id: random_hash(&mut seed),
            height: prng(&mut seed) % 1_000_000,
            finalized_depth: lower.finalized_depth + 1, // strictly higher
            cumulative_voting_power: prng(&mut seed),
        };
        assert_eq!(
            higher.score_cmp(&lower),
            Ordering::Greater,
            "higher finalized_depth must beat lower regardless of other components"
        );
    }
}

// ── INV-UPGRADE-ATOMICITY ────────────────────────────────────────────

fn random_transition_sequence(seed: &mut u64, n: u32) -> Vec<ChainVersionTransition> {
    // Generate `n` transitions with monotonically increasing
    // activation_height and to_version.
    let mut transitions = Vec::new();
    let mut last_height = 100u64;
    let mut last_version = 4u32;
    for _ in 0..n {
        last_height = last_height.saturating_add(prng(seed) % 1000 + 1);
        last_version = last_version.saturating_add(1);
        transitions.push(ChainVersionTransition {
            activation_height: last_height,
            from_version: last_version - 1,
            to_version: last_version,
            upgrade_spec_hash: random_hash(seed),
            proposal_id: random_hash(seed),
        });
    }
    transitions
}

#[test]
fn prop_upgrade_atomicity_active_version_monotone_in_height() {
    // For any height sequence, the active version is monotonically
    // non-decreasing.
    let mut seed = 0xface_b00cu64;
    for _ in 0..30 {
        let n = (prng(&mut seed) % 4) as u32 + 1;
        let transitions = random_transition_sequence(&mut seed, n);
        let max_h = transitions
            .last()
            .map(|t| t.activation_height + 1000)
            .unwrap_or(1000);
        let mut last_active: Option<u32> = None;
        for h in (0..max_h).step_by(123) {
            // Find what the alignment check reports as active by
            // probing every plausible version.
            let mut found_active = None;
            for v in 4..=20u32 {
                if matches!(
                    verify_block_version_alignment(h, v, 4, &transitions),
                    ChainVersionCheck::Aligned
                ) {
                    found_active = Some(v);
                    break;
                }
            }
            if let (Some(prev), Some(curr)) = (last_active, found_active) {
                assert!(
                    curr >= prev,
                    "active version went down at height {}: {} → {}",
                    h,
                    prev,
                    curr
                );
            }
            if found_active.is_some() {
                last_active = found_active;
            }
        }
    }
}

#[test]
fn prop_upgrade_atomicity_genesis_version_pre_activation() {
    // Before the earliest activation_height, only genesis_version is
    // accepted. After the latest, only the final to_version.
    let mut seed = 0x0bad_f00d_u64;
    for _ in 0..30 {
        let n = (prng(&mut seed) % 4) as u32 + 1;
        let transitions = random_transition_sequence(&mut seed, n);
        let earliest = transitions[0].activation_height;
        let latest = transitions.last().unwrap().activation_height;
        let final_v = transitions.last().unwrap().to_version;

        // Before earliest: genesis_version (4) is aligned, anything
        // else is misaligned.
        if earliest > 0 {
            assert!(matches!(
                verify_block_version_alignment(earliest - 1, 4, 4, &transitions),
                ChainVersionCheck::Aligned
            ));
            assert!(matches!(
                verify_block_version_alignment(earliest - 1, 5, 4, &transitions),
                ChainVersionCheck::Misaligned(_)
            ));
        }

        // At/after latest: final_v aligned, genesis misaligned.
        assert!(matches!(
            verify_block_version_alignment(latest + 100, final_v, 4, &transitions),
            ChainVersionCheck::Aligned
        ));
        if final_v != 4 {
            assert!(matches!(
                verify_block_version_alignment(latest + 100, 4, 4, &transitions),
                ChainVersionCheck::Misaligned(_)
            ));
        }
    }
}

#[test]
fn prop_upgrade_atomicity_exactly_one_version_aligned_per_height() {
    // At any height with a non-empty transition history, exactly
    // one block_version yields Aligned. All others yield Misaligned.
    let mut seed = 0xabba_cafe_u64;
    for _ in 0..30 {
        let n = (prng(&mut seed) % 4) as u32 + 1;
        let transitions = random_transition_sequence(&mut seed, n);
        let max_h = transitions.last().unwrap().activation_height + 1000;

        for h in [
            0u64,
            transitions[0].activation_height,
            transitions[0].activation_height.saturating_sub(1),
            transitions.last().unwrap().activation_height + 50,
            max_h - 1,
        ] {
            let mut aligned_versions = Vec::new();
            for v in 0..30u32 {
                if matches!(
                    verify_block_version_alignment(h, v, 4, &transitions),
                    ChainVersionCheck::Aligned
                ) {
                    aligned_versions.push(v);
                }
            }
            assert_eq!(
                aligned_versions.len(),
                1,
                "height {} should have exactly one aligned version, got {:?}",
                h,
                aligned_versions
            );
        }
    }
}

#[test]
fn prop_upgrade_atomicity_empty_history_uses_genesis_version() {
    // No transitions → genesis_version is the only aligned version
    // at every height.
    let mut seed = 0xb0a7_d00d_u64;
    for _ in 0..40 {
        let h = prng(&mut seed) % 1_000_000;
        let g = (prng(&mut seed) % 10) as u32; // arbitrary genesis version
        assert!(matches!(
            verify_block_version_alignment(h, g, g, &[]),
            ChainVersionCheck::Aligned
        ));
        // Any other version is misaligned.
        let other = g.wrapping_add(1);
        assert!(matches!(
            verify_block_version_alignment(h, other, g, &[]),
            ChainVersionCheck::Misaligned(_)
        ));
    }
}
