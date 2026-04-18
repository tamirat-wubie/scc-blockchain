//! `verify_ceilings_unchanged_since_genesis` — the moat-defining
//! verifier per PATCH_08.md §B.5.
//!
//! Pure function over its input (no wall-clock, no env, no I/O outside
//! `ChainStateView` method calls, no caches, no global state). Two
//! reviewers running this against the same `ChainStateView` produce
//! byte-identical output. That is the property that makes external
//! auditability meaningful.

use crate::chain_state::{ChainStateError, ChainStateView};
use crate::field::{field_value, CeilingFieldId};
use crate::violation::CeilingViolation;

/// Verify that no `ConstitutionalCeilings` field has been raised
/// (or otherwise changed) since genesis.
///
/// Returns `Ok(())` iff every `ChainVersionTransition` from genesis
/// to current tip preserved every `ConstitutionalCeilings` field at
/// exactly its genesis value. Returns the **first** `CeilingViolation`
/// encountered on failure (short-circuit per PATCH_08 §B.2).
///
/// # Algorithm (per PATCH_08 §B.5)
///
/// ```text
/// genesis_ceilings = chain.genesis_constitutional_ceilings()
/// history = chain.chain_version_history()
/// reject if history not monotonic by activation_height
/// for each transition in history (ascending):
///     pre  = chain.ceilings_at_height(transition.activation_height - 1)
///         (skipped when activation_height == 0)
///     post = chain.ceilings_at_height(transition.activation_height)
///     for each field in CeilingFieldId::ALL:
///         if pre  != genesis at field: return FieldValueChanged
///         if post != genesis at field: return FieldValueChanged
/// return Ok(())
/// ```
///
/// # Edge cases
///
/// - **Empty history** (genesis-only chain): trivially `Ok(())`.
/// - **`activation_height = 0`**: forbidden by PATCH_06 §34's
///   lead-time discipline; verifier defensively handles by checking
///   only `post` (no `pre` exists at height -1).
/// - **Non-monotonic history**: rejected with
///   `HistoryStructurallyInvalid`.
pub fn verify_ceilings_unchanged_since_genesis<V: ChainStateView>(
    chain: &V,
) -> Result<(), CeilingViolation> {
    // 1. Read the moat-defining baseline — the genesis ceilings.
    let genesis = match chain.genesis_constitutional_ceilings() {
        Ok(c) => c,
        Err(e) => {
            return Err(CeilingViolation::GenesisCeilingsUnreadable {
                reason: format_chain_state_error(&e),
            });
        }
    };

    // 2. Read the full chain-version history.
    let history = match chain.chain_version_history() {
        Ok(h) => h,
        Err(e) => {
            return Err(CeilingViolation::HistoryStructurallyInvalid {
                reason: format_chain_state_error(&e),
            });
        }
    };

    // 3. Validate history is monotonically non-decreasing in
    //    activation_height. PATCH_06 §34 admission rules guarantee
    //    monotonicity in production; the verifier checks defensively
    //    in case of a corrupted snapshot.
    for w in history.windows(2) {
        if w[0].activation_height > w[1].activation_height {
            return Err(CeilingViolation::HistoryStructurallyInvalid {
                reason: format!(
                    "transition activation_height {} precedes preceding transition's {}",
                    w[1].activation_height, w[0].activation_height,
                ),
            });
        }
    }

    // 4. Empty history: nothing to check, moat trivially holds.
    if history.is_empty() {
        return Ok(());
    }

    // 5. Walk every transition; for each, check pre and post
    //    ceilings against genesis baseline across every field.
    for transition in &history {
        let h = transition.activation_height;

        // Check pre-transition ceilings (if pre-height exists).
        if h > 0 {
            let pre = match chain.ceilings_at_height(h - 1) {
                Ok(c) => c,
                Err(e) => {
                    return Err(CeilingViolation::CeilingsUnreadableAtTransition {
                        transition_height: h,
                        reason: format_chain_state_error(&e),
                    });
                }
            };
            for field in CeilingFieldId::ALL {
                let baseline = field_value(&genesis, *field);
                let observed = field_value(&pre, *field);
                if baseline != observed {
                    return Err(CeilingViolation::FieldValueChanged {
                        transition_height: h,
                        ceiling_field: *field,
                        before_value: baseline,
                        after_value: observed,
                    });
                }
            }
        }

        // Check post-transition ceilings.
        let post = match chain.ceilings_at_height(h) {
            Ok(c) => c,
            Err(e) => {
                return Err(CeilingViolation::CeilingsUnreadableAtTransition {
                    transition_height: h,
                    reason: format_chain_state_error(&e),
                });
            }
        };
        for field in CeilingFieldId::ALL {
            let baseline = field_value(&genesis, *field);
            let observed = field_value(&post, *field);
            if baseline != observed {
                return Err(CeilingViolation::FieldValueChanged {
                    transition_height: h,
                    ceiling_field: *field,
                    before_value: baseline,
                    after_value: observed,
                });
            }
        }
    }

    Ok(())
}

fn format_chain_state_error(e: &ChainStateError) -> String {
    format!("{}", e)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain_state::JsonChainStateFixture;
    use sccgub_types::constitutional_ceilings::ConstitutionalCeilings;
    use sccgub_types::upgrade::ChainVersionTransition;

    fn t(activation: u64, to_v: u32) -> ChainVersionTransition {
        ChainVersionTransition {
            activation_height: activation,
            from_version: to_v - 1,
            to_version: to_v,
            upgrade_spec_hash: [0xAA; 32],
            proposal_id: [0xBB; 32],
        }
    }

    // ─── Mandatory case 1: empty history → Ok(()) ─────────────────

    #[test]
    fn patch_08_empty_history_returns_ok() {
        let f = JsonChainStateFixture::genesis_preserved(
            [0; 32],
            ConstitutionalCeilings::default(),
            vec![],
        );
        verify_ceilings_unchanged_since_genesis(&f).unwrap();
    }

    // ─── Mandatory case 2: every field preserved across single transition ───

    #[test]
    fn patch_08_single_transition_preserved_returns_ok() {
        let c = ConstitutionalCeilings::default();
        let f = JsonChainStateFixture::genesis_preserved([0; 32], c, vec![t(100, 5)]);
        verify_ceilings_unchanged_since_genesis(&f).unwrap();
    }

    // ─── Mandatory case 3: every field preserved across multiple transitions ─

    #[test]
    fn patch_08_multiple_transitions_preserved_returns_ok() {
        let c = ConstitutionalCeilings::default();
        let f = JsonChainStateFixture::genesis_preserved(
            [0; 32],
            c,
            vec![t(100, 5), t(200, 6), t(300, 7)],
        );
        verify_ceilings_unchanged_since_genesis(&f).unwrap();
    }

    // ─── Helper: a fixture with a single drifted post-transition field ──

    fn fixture_with_drifted_field(
        history: Vec<ChainVersionTransition>,
        drift_at_height: u64,
        mutate: impl Fn(&mut ConstitutionalCeilings),
    ) -> JsonChainStateFixture {
        let genesis = ConstitutionalCeilings::default();
        let mut by_height = Vec::new();
        for tr in &history {
            if tr.activation_height > 0 {
                by_height.push((tr.activation_height - 1, genesis.clone()));
            }
            let mut here = genesis.clone();
            if tr.activation_height == drift_at_height {
                mutate(&mut here);
            }
            by_height.push((tr.activation_height, here));
        }
        JsonChainStateFixture {
            genesis_block_hash: [0; 32],
            genesis_ceilings: genesis,
            chain_version_history: history,
            ceilings_by_height: by_height,
        }
    }

    // ─── Mandatory case 4: per CeilingFieldId variant, drift detected ──

    #[test]
    fn patch_08_drift_in_max_proof_depth_detected() {
        let f = fixture_with_drifted_field(vec![t(100, 5)], 100, |c| {
            c.max_proof_depth_ceiling += 1;
        });
        let r = verify_ceilings_unchanged_since_genesis(&f);
        assert!(matches!(
            r,
            Err(CeilingViolation::FieldValueChanged {
                ceiling_field: CeilingFieldId::MaxProofDepth,
                ..
            })
        ));
    }

    #[test]
    fn patch_08_drift_in_max_tx_gas_detected() {
        let f = fixture_with_drifted_field(vec![t(100, 5)], 100, |c| {
            c.max_tx_gas_ceiling += 1;
        });
        let r = verify_ceilings_unchanged_since_genesis(&f);
        assert!(matches!(
            r,
            Err(CeilingViolation::FieldValueChanged {
                ceiling_field: CeilingFieldId::MaxTxGas,
                ..
            })
        ));
    }

    #[test]
    fn patch_08_drift_in_min_effective_fee_floor_detected() {
        // Even a DECREASE counts as drift — the moat is "unchanged",
        // not "not-raised."
        let f = fixture_with_drifted_field(vec![t(100, 5)], 100, |c| {
            c.min_effective_fee_floor -= 1;
        });
        let r = verify_ceilings_unchanged_since_genesis(&f);
        assert!(matches!(
            r,
            Err(CeilingViolation::FieldValueChanged {
                ceiling_field: CeilingFieldId::MinEffectiveFeeFloor,
                ..
            })
        ));
    }

    // ─── Mandatory case 5: short-circuit on first violation ──

    #[test]
    fn patch_08_short_circuits_on_first_violation() {
        // Two drift points: at height 100 (max_proof_depth) and 200
        // (max_tx_gas). Verifier MUST return the height-100 violation.
        let history = vec![t(100, 5), t(200, 6)];
        let genesis = ConstitutionalCeilings::default();
        let mut by_height = Vec::new();
        // Height 99: clean.
        by_height.push((99, genesis.clone()));
        // Height 100: max_proof_depth drift.
        let mut h100 = genesis.clone();
        h100.max_proof_depth_ceiling += 10;
        by_height.push((100, h100));
        // Height 199: clean (NOT drifted at this point).
        by_height.push((199, genesis.clone()));
        // Height 200: max_tx_gas drift.
        let mut h200 = genesis.clone();
        h200.max_tx_gas_ceiling += 999;
        by_height.push((200, h200));

        let f = JsonChainStateFixture {
            genesis_block_hash: [0; 32],
            genesis_ceilings: genesis,
            chain_version_history: history,
            ceilings_by_height: by_height,
        };
        let r = verify_ceilings_unchanged_since_genesis(&f);
        match r {
            Err(CeilingViolation::FieldValueChanged {
                transition_height,
                ceiling_field,
                ..
            }) => {
                assert_eq!(transition_height, 100);
                assert_eq!(ceiling_field, CeilingFieldId::MaxProofDepth);
            }
            other => panic!(
                "expected first-violation FieldValueChanged at h=100, got {:?}",
                other
            ),
        }
    }

    // ─── Mandatory case 6: degenerate activation_height = 0 ──

    #[test]
    fn patch_08_degenerate_activation_height_zero_handled() {
        // Height 0 is forbidden by PATCH_06 §34 lead-time but
        // verifier handles defensively (only checks post; no
        // height -1 to read).
        let genesis = ConstitutionalCeilings::default();
        let f = JsonChainStateFixture {
            genesis_block_hash: [0; 32],
            genesis_ceilings: genesis.clone(),
            chain_version_history: vec![t(0, 1)],
            ceilings_by_height: vec![(0, genesis)],
        };
        verify_ceilings_unchanged_since_genesis(&f).unwrap();
    }

    // ─── Mandatory case 7: HistoryStructurallyInvalid on out-of-order ──

    #[test]
    fn patch_08_non_monotonic_history_rejected() {
        let genesis = ConstitutionalCeilings::default();
        let f = JsonChainStateFixture {
            genesis_block_hash: [0; 32],
            genesis_ceilings: genesis.clone(),
            chain_version_history: vec![t(200, 6), t(100, 5)], // out of order
            ceilings_by_height: vec![
                (99, genesis.clone()),
                (100, genesis.clone()),
                (199, genesis.clone()),
                (200, genesis),
            ],
        };
        let r = verify_ceilings_unchanged_since_genesis(&f);
        assert!(matches!(
            r,
            Err(CeilingViolation::HistoryStructurallyInvalid { .. })
        ));
    }

    // ─── Mandatory case 8: GenesisCeilingsUnreadable propagation ──

    struct UnreadableGenesisFixture;
    impl ChainStateView for UnreadableGenesisFixture {
        fn genesis_block_hash(&self) -> sccgub_types::Hash {
            [0; 32]
        }
        fn genesis_constitutional_ceilings(
            &self,
        ) -> Result<ConstitutionalCeilings, ChainStateError> {
            Err(ChainStateError::GenesisCeilingsMissing(
                "synthetic missing".into(),
            ))
        }
        fn chain_version_history(&self) -> Result<Vec<ChainVersionTransition>, ChainStateError> {
            Ok(vec![])
        }
        fn ceilings_at_height(&self, _h: u64) -> Result<ConstitutionalCeilings, ChainStateError> {
            Err(ChainStateError::Io("never reached".into()))
        }
    }

    #[test]
    fn patch_08_genesis_ceilings_unreadable_returns_genesis_unreadable() {
        let f = UnreadableGenesisFixture;
        let r = verify_ceilings_unchanged_since_genesis(&f);
        assert!(matches!(
            r,
            Err(CeilingViolation::GenesisCeilingsUnreadable { .. })
        ));
    }

    // ─── Mandatory case 9: CeilingsUnreadableAtTransition propagation ──

    #[test]
    fn patch_08_missing_ceilings_at_transition_returns_unreadable_at_transition() {
        let genesis = ConstitutionalCeilings::default();
        let f = JsonChainStateFixture {
            genesis_block_hash: [0; 32],
            genesis_ceilings: genesis.clone(),
            chain_version_history: vec![t(100, 5)],
            // Intentionally missing height 99 and 100 → read fails.
            ceilings_by_height: vec![],
        };
        let r = verify_ceilings_unchanged_since_genesis(&f);
        assert!(matches!(
            r,
            Err(CeilingViolation::CeilingsUnreadableAtTransition {
                transition_height: 100,
                ..
            })
        ));
    }

    // ─── Adversarial case 1: pre-transition height drift (not just post) ──

    #[test]
    fn patch_08_pre_transition_drift_detected() {
        // A subtler attack: the ceilings record at activation_height-1
        // (i.e., the block JUST BEFORE the chain version change) is
        // tampered, but the activation_height record itself is clean.
        // The verifier must catch this.
        let genesis = ConstitutionalCeilings::default();
        let history = vec![t(100, 5)];
        let mut tampered = genesis.clone();
        tampered.max_block_gas_ceiling += 1000;
        let f = JsonChainStateFixture {
            genesis_block_hash: [0; 32],
            genesis_ceilings: genesis.clone(),
            chain_version_history: history,
            ceilings_by_height: vec![
                (99, tampered), // drift at PRE-transition height
                (100, genesis), // clean at activation height
            ],
        };
        let r = verify_ceilings_unchanged_since_genesis(&f);
        assert!(matches!(
            r,
            Err(CeilingViolation::FieldValueChanged {
                ceiling_field: CeilingFieldId::MaxBlockGas,
                transition_height: 100,
                ..
            })
        ));
    }

    // ─── Adversarial case 2: encoding-portability sanity ──

    #[test]
    fn patch_08_value_comparison_uses_partialeq_not_bytes() {
        // The verifier compares CeilingValue via PartialEq, which is
        // value-based. This test confirms that genesis ceilings
        // serialized + deserialized produce identical PartialEq
        // outcomes — so encoding endianness or padding cannot trick
        // the comparison.
        let g = ConstitutionalCeilings::default();
        let bytes = bincode::serialize(&g).unwrap();
        let g2: ConstitutionalCeilings = bincode::deserialize(&bytes).unwrap();
        // Both fixtures should pass with a single transition.
        let f1 = JsonChainStateFixture::genesis_preserved([0; 32], g.clone(), vec![t(50, 5)]);
        let f2 = JsonChainStateFixture::genesis_preserved([0; 32], g2, vec![t(50, 5)]);
        verify_ceilings_unchanged_since_genesis(&f1).unwrap();
        verify_ceilings_unchanged_since_genesis(&f2).unwrap();
    }

    // ─── Adversarial case 3: many transitions, drift in middle ──

    #[test]
    fn patch_08_drift_in_middle_of_long_history() {
        let genesis = ConstitutionalCeilings::default();
        let history = vec![
            t(100, 5),
            t(200, 6),
            t(300, 7), // drift here
            t(400, 8),
            t(500, 9),
        ];
        let mut by_height = Vec::new();
        for tr in &history {
            by_height.push((tr.activation_height - 1, genesis.clone()));
            let mut here = genesis.clone();
            if tr.activation_height == 300 {
                here.max_validator_set_size_ceiling += 1;
            }
            by_height.push((tr.activation_height, here));
        }
        let f = JsonChainStateFixture {
            genesis_block_hash: [0; 32],
            genesis_ceilings: genesis,
            chain_version_history: history,
            ceilings_by_height: by_height,
        };
        let r = verify_ceilings_unchanged_since_genesis(&f);
        match r {
            Err(CeilingViolation::FieldValueChanged {
                transition_height,
                ceiling_field,
                ..
            }) => {
                assert_eq!(transition_height, 300);
                assert_eq!(ceiling_field, CeilingFieldId::MaxValidatorSetSize);
            }
            other => panic!("expected drift at h=300, got {:?}", other),
        }
    }

    // ─── Pure-function property: verifier output is deterministic ──

    #[test]
    fn patch_08_verifier_is_pure_over_input() {
        let f = JsonChainStateFixture::genesis_preserved(
            [0xAB; 32],
            ConstitutionalCeilings::default(),
            vec![t(100, 5), t(200, 6)],
        );
        // Run twice; outputs identical (no caches, no global state,
        // no wall-clock). Use Result PartialEq.
        let r1 = verify_ceilings_unchanged_since_genesis(&f);
        let r2 = verify_ceilings_unchanged_since_genesis(&f);
        assert_eq!(r1, r2);
    }
}
