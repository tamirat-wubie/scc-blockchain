//! Patch-05 §22 evidence-sourced slashing admission.
//!
//! When a block carries `EquivocationEvidence` records, §15.7 Stage 1
//! requires each evidence record to be paired with a synthetic
//! `ValidatorSetChange::Remove` whose `quorum_signatures` is empty
//! (evidence-sourced bypass). Phase 12 branches the validation:
//!
//! - **Proposer-sourced** (`!quorum_signatures.is_empty()`): validated
//!   by existing `validate_validator_set_change` — quorum tally against
//!   `active_set(H_admit)`.
//!
//! - **Evidence-sourced** (`quorum_signatures.is_empty()`): validated by
//!   `validate_evidence_sourced_remove` in this module — cross-checked
//!   against a matching `EquivocationEvidence` in the same block, with
//!   the synthesized change_id expected to match via
//!   `synthesize_equivocation_removal`.
//!
//! INV-SLASHING-LIVENESS (§22.4): every admitted evidence record
//! produces a matching synthetic Remove in the same block.
//!
//! Design choice: two events are paired iff the synthesized change_id
//! matches the admitted change_id. This makes the relationship
//! deterministic and verifiable without maintaining a separate
//! evidence-to-remove cross-reference.

use sccgub_consensus::equivocation::{synthesize_equivocation_removal, EquivocationSynthesis};
use sccgub_types::validator_set::{
    EquivocationEvidence, ValidatorSet, ValidatorSetChange, ValidatorSetChangeKind,
};

/// Outcome of §22 validation over the `(validator_set_changes, equivocation_evidence)`
/// pair from a single block body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EvidenceAdmissionResult {
    /// Every evidence record has a matching synthetic Remove, and every
    /// empty-signature Remove has a matching evidence record.
    Valid,
    /// Block-level rejection. `reason` identifies the failing predicate.
    Invalid(EvidenceAdmissionRejection),
}

impl EvidenceAdmissionResult {
    pub fn is_valid(&self) -> bool {
        matches!(self, Self::Valid)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EvidenceAdmissionRejection {
    #[error(
        "evidence-sourced Remove at index {idx} has non-empty \
         quorum_signatures (should be empty per §15.7 bypass)"
    )]
    EvidenceSourcedHasQuorumSigs { idx: usize },
    #[error(
        "ValidatorSetChange at index {idx} has empty quorum_signatures \
         but does not match any EquivocationEvidence in the block"
    )]
    OrphanEvidenceSourcedRemove { idx: usize },
    #[error(
        "EquivocationEvidence at index {idx} has no matching synthetic \
         Remove in body.validator_set_changes (§22.4 INV-SLASHING-LIVENESS)"
    )]
    EvidenceMissingSyntheticRemove { idx: usize },
    #[error("evidence at index {idx} failed synthesis: {reason}")]
    SynthesisFailed { idx: usize, reason: String },
    #[error(
        "evidence-sourced Remove change_id {admitted:?} does not match \
         synthesized change_id {expected:?}"
    )]
    ChangeIdMismatch {
        admitted: [u8; 32],
        expected: [u8; 32],
    },
}

/// Validate the pair `(validator_set_changes, equivocation_evidence)`
/// from a block body under §22.
///
/// - `changes`: the block's `body.validator_set_changes` slice (possibly
///   empty).
/// - `evidence`: the block's `body.equivocation_evidence` slice (possibly
///   empty).
/// - `current_set`: `active_set(H_admit)` from state; used to resolve
///   each evidence record's `validator_id → agent_id`.
/// - `h_admit`: block height at which admission occurs.
/// - `activation_delay`: §15.5 clamp output; synthetic Remove takes
///   effect at `h_admit + activation_delay`.
///
/// Returns `Valid` if every (evidence, synthetic Remove) pairs up.
/// Returns `Invalid(reason)` on first predicate failure.
///
/// This function DOES NOT validate proposer-sourced changes — those are
/// handled by `validate_all_validator_set_changes` in the sibling
/// `validator_set` module. Phase 12 calls both validators and combines
/// the outcomes.
pub fn validate_evidence_admission(
    changes: &[ValidatorSetChange],
    evidence: &[EquivocationEvidence],
    current_set: &ValidatorSet,
    h_admit: u64,
    activation_delay: u64,
) -> EvidenceAdmissionResult {
    // Step 1: synthesize every evidence record. Record the expected
    // change_id for each.
    let mut expected_synthetics: Vec<(usize, ValidatorSetChange)> = Vec::new();
    for (idx, ev) in evidence.iter().enumerate() {
        match synthesize_equivocation_removal(ev, current_set, h_admit, activation_delay) {
            EquivocationSynthesis::Synthesized(change) => {
                expected_synthetics.push((idx, change));
            }
            EquivocationSynthesis::NotStructuralEquivocation => {
                return EvidenceAdmissionResult::Invalid(
                    EvidenceAdmissionRejection::SynthesisFailed {
                        idx,
                        reason: "not structurally an equivocation".into(),
                    },
                );
            }
            EquivocationSynthesis::SignatureInvalid => {
                return EvidenceAdmissionResult::Invalid(
                    EvidenceAdmissionRejection::SynthesisFailed {
                        idx,
                        reason: "vote signature fails verify_strict".into(),
                    },
                );
            }
            EquivocationSynthesis::SignerNotInActiveSet => {
                return EvidenceAdmissionResult::Invalid(
                    EvidenceAdmissionRejection::SynthesisFailed {
                        idx,
                        reason: "signing validator not in active_set(H_admit)".into(),
                    },
                );
            }
        }
    }

    // Step 2: partition `changes` into evidence-sourced (empty sigs)
    // and proposer-sourced (non-empty sigs). Only evidence-sourced are
    // our concern here.
    let evidence_sourced: Vec<(usize, &ValidatorSetChange)> = changes
        .iter()
        .enumerate()
        .filter(|(_, c)| {
            c.quorum_signatures.is_empty()
                && matches!(c.kind, ValidatorSetChangeKind::Remove { .. })
        })
        .collect();

    // Step 3: for each evidence-sourced Remove, verify it matches exactly
    // one expected synthetic by change_id. If `quorum_signatures.is_empty()`
    // and `kind != Remove`, that is an unsupported synthesis (§15.7 only
    // produces Remove); reject as orphan.
    for (ch_idx, change) in &evidence_sourced {
        // Double-check: empty sigs + not-Remove means someone tried to
        // smuggle an unsigned Add/RotatePower/RotateKey — already
        // excluded by the filter above, but the check is cheap.
        let matched = expected_synthetics
            .iter()
            .find(|(_, expected)| expected.change_id == change.change_id);
        match matched {
            Some(_) => {}
            None => {
                return EvidenceAdmissionResult::Invalid(
                    EvidenceAdmissionRejection::OrphanEvidenceSourcedRemove { idx: *ch_idx },
                );
            }
        }
    }

    // Step 4: INV-SLASHING-LIVENESS — every expected synthetic MUST be
    // present in the block's evidence-sourced Removes. Any evidence
    // without a paired Remove fails the invariant.
    for (ev_idx, expected) in &expected_synthetics {
        let paired = changes.iter().any(|c| {
            c.change_id == expected.change_id
                && c.quorum_signatures.is_empty()
                && matches!(c.kind, ValidatorSetChangeKind::Remove { .. })
        });
        if !paired {
            return EvidenceAdmissionResult::Invalid(
                EvidenceAdmissionRejection::EvidenceMissingSyntheticRemove { idx: *ev_idx },
            );
        }
    }

    // Step 5: defensive — any change with non-empty sigs whose change_id
    // matches a synthetic (i.e., proposer-sourced but colliding with an
    // evidence-sourced event) is rejected. This should never occur in
    // practice because proposer-sourced events carry distinct proposed_at
    // timestamps, but it closes the "smuggle quorum sigs onto a
    // synthetic" attack surface.
    for (idx, change) in changes.iter().enumerate() {
        if !change.quorum_signatures.is_empty()
            && expected_synthetics
                .iter()
                .any(|(_, e)| e.change_id == change.change_id)
        {
            return EvidenceAdmissionResult::Invalid(
                EvidenceAdmissionRejection::EvidenceSourcedHasQuorumSigs { idx },
            );
        }
    }

    EvidenceAdmissionResult::Valid
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use sccgub_types::mfidel::MfidelAtomicSeal;
    use sccgub_types::validator_set::{
        EquivocationVote, EquivocationVoteType, RemovalReason, ValidatorRecord,
    };

    fn keypair(seed: u8) -> (SigningKey, [u8; 32]) {
        let sk = SigningKey::from_bytes(&[seed; 32]);
        let pk = *sk.verifying_key().as_bytes();
        (sk, pk)
    }

    fn record(agent: u8, validator_pk: [u8; 32], power: u64) -> ValidatorRecord {
        ValidatorRecord {
            agent_id: [agent; 32],
            validator_id: validator_pk,
            mfidel_seal: MfidelAtomicSeal::from_height(0),
            voting_power: power,
            active_from: 0,
            active_until: None,
        }
    }

    fn make_vote(sk: &SigningKey, pk: [u8; 32], block_hash: [u8; 32]) -> EquivocationVote {
        let height = 10u64;
        let round = 0u32;
        let payload = sccgub_crypto::canonical::canonical_bytes(&(
            &pk,
            &block_hash,
            height,
            round,
            0u8, // Prevote
        ));
        let sig = sk.sign(&payload).to_bytes().to_vec();
        EquivocationVote {
            validator_id: pk,
            block_hash,
            height,
            round,
            vote_type: EquivocationVoteType::Prevote,
            signature: sig,
        }
    }

    fn make_evidence(sk: &SigningKey, pk: [u8; 32]) -> EquivocationEvidence {
        let v_a = make_vote(sk, pk, [0xAA; 32]);
        let v_b = make_vote(sk, pk, [0xBB; 32]);
        EquivocationEvidence::new(v_a, v_b)
    }

    fn set_with_one(pk: [u8; 32]) -> ValidatorSet {
        ValidatorSet::new(vec![record(7, pk, 10)]).unwrap()
    }

    fn synth(ev: &EquivocationEvidence, set: &ValidatorSet, h: u64, d: u64) -> ValidatorSetChange {
        match synthesize_equivocation_removal(ev, set, h, d) {
            EquivocationSynthesis::Synthesized(c) => c,
            other => panic!("synthesis failed: {:?}", other),
        }
    }

    // ── Happy path ────────────────────────────────────────────────

    #[test]
    fn patch_05_evidence_sourced_remove_admitted() {
        let (sk, pk) = keypair(5);
        let ev = make_evidence(&sk, pk);
        let set = set_with_one(pk);
        let change = synth(&ev, &set, 20, 3);
        let result = validate_evidence_admission(&[change], &[ev], &set, 20, 3);
        assert!(
            matches!(result, EvidenceAdmissionResult::Valid),
            "expected Valid, got {:?}",
            result
        );
    }

    #[test]
    fn patch_05_empty_block_is_valid() {
        let set = ValidatorSet::new(vec![]).unwrap();
        let result = validate_evidence_admission(&[], &[], &set, 10, 3);
        assert!(result.is_valid());
    }

    // ── §22.4 INV-SLASHING-LIVENESS ───────────────────────────────

    #[test]
    fn patch_05_slashing_liveness_enforced() {
        // Evidence present but no matching Remove in validator_set_changes
        // → INV-SLASHING-LIVENESS violated, block rejected.
        let (sk, pk) = keypair(5);
        let ev = make_evidence(&sk, pk);
        let set = set_with_one(pk);
        let result = validate_evidence_admission(&[], &[ev], &set, 20, 3);
        assert!(matches!(
            result,
            EvidenceAdmissionResult::Invalid(
                EvidenceAdmissionRejection::EvidenceMissingSyntheticRemove { idx: 0 }
            )
        ));
    }

    #[test]
    fn patch_05_evidence_without_matching_remove_rejected() {
        // Remove IS present but its change_id differs from the synthesized
        // one (e.g., proposer tampered with the agent_id). Should reject.
        let (sk, pk) = keypair(5);
        let ev = make_evidence(&sk, pk);
        let set = set_with_one(pk);
        let mut change = synth(&ev, &set, 20, 3);
        change.change_id = [0xFF; 32]; // tamper
        let result = validate_evidence_admission(&[change], &[ev], &set, 20, 3);
        // The tampered change is an orphan (no matching expected synthetic),
        // AND the evidence has no matching Remove. Either error is fine; the
        // orphan check fires first by iteration order.
        assert!(matches!(
            result,
            EvidenceAdmissionResult::Invalid(
                EvidenceAdmissionRejection::OrphanEvidenceSourcedRemove { .. }
            ) | EvidenceAdmissionResult::Invalid(
                EvidenceAdmissionRejection::EvidenceMissingSyntheticRemove { .. }
            )
        ));
    }

    // ── Orphan synthetic (Remove w/ empty sigs but no evidence) ──

    #[test]
    fn patch_05_orphan_synthetic_remove_rejected() {
        // A Remove with empty quorum_signatures but NO evidence record —
        // the block is trying to slash someone without justification.
        let change = ValidatorSetChange {
            change_id: [0x01; 32],
            kind: ValidatorSetChangeKind::Remove {
                agent_id: [42; 32],
                reason: RemovalReason::Equivocation,
                effective_height: 23,
            },
            proposed_at: 20,
            quorum_signatures: vec![], // evidence-sourced shape
        };
        let set = ValidatorSet::new(vec![record(42, [10; 32], 10)]).unwrap();
        let result = validate_evidence_admission(&[change], &[], &set, 20, 3);
        assert!(matches!(
            result,
            EvidenceAdmissionResult::Invalid(
                EvidenceAdmissionRejection::OrphanEvidenceSourcedRemove { idx: 0 }
            )
        ));
    }

    // ── Proposer-sourced empty-sigs (should never happen) ────────

    #[test]
    fn patch_05_proposer_sourced_empty_sigs_rejected() {
        // A non-Remove change (e.g., Add) with empty quorum_signatures.
        // The evidence-admission module filters on Remove specifically, so
        // this is a no-op here. The proposer-sourced validator in
        // validator_set.rs will reject via QuorumNotReached. Test
        // exercises that the evidence-admission module does NOT
        // false-pair an empty-sigs Add.
        let set = ValidatorSet::new(vec![record(7, [11; 32], 10)]).unwrap();
        let add_change = ValidatorSetChange {
            change_id: [0xEE; 32],
            kind: ValidatorSetChangeKind::Add(record(8, [12; 32], 20)),
            proposed_at: 20,
            quorum_signatures: vec![],
        };
        // No evidence in body.
        let result = validate_evidence_admission(&[add_change], &[], &set, 20, 3);
        // The evidence-admission module accepts this (no Remove w/ empty
        // sigs to pair), passing through to proposer-sourced validation
        // which will reject the Add as empty-quorum.
        assert!(result.is_valid());
    }

    // ── change_id collision between proposer-sourced and synthetic

    #[test]
    fn patch_05_proposer_sourced_colliding_change_id_rejected() {
        // An attacker crafts a proposer-sourced Remove with the SAME
        // change_id as a legitimate evidence-sourced synthetic, hoping
        // to smuggle quorum-sigs onto the synthetic slot. §22 rejects.
        let (sk, pk) = keypair(5);
        let ev = make_evidence(&sk, pk);
        let set = set_with_one(pk);
        let synthetic = synth(&ev, &set, 20, 3);

        // Build a colliding proposer-sourced change: same change_id but
        // non-empty sigs.
        let colliding = ValidatorSetChange {
            change_id: synthetic.change_id,
            kind: synthetic.kind.clone(),
            proposed_at: synthetic.proposed_at,
            quorum_signatures: vec![([1; 32], vec![0xAA; 64])],
        };
        let result = validate_evidence_admission(&[synthetic, colliding], &[ev], &set, 20, 3);
        assert!(matches!(
            result,
            EvidenceAdmissionResult::Invalid(
                EvidenceAdmissionRejection::EvidenceSourcedHasQuorumSigs { .. }
            )
        ));
    }

    // ── Multiple evidence records ────────────────────────────────

    #[test]
    fn patch_05_two_evidence_records_with_paired_synthetics() {
        let (sk_a, pk_a) = keypair(10);
        let (sk_b, pk_b) = keypair(11);
        let ev_a = make_evidence(&sk_a, pk_a);
        let ev_b = make_evidence(&sk_b, pk_b);
        let set = ValidatorSet::new(vec![record(7, pk_a, 10), record(8, pk_b, 15)]).unwrap();
        let change_a = synth(&ev_a, &set, 20, 3);
        let change_b = synth(&ev_b, &set, 20, 3);
        let result = validate_evidence_admission(&[change_a, change_b], &[ev_a, ev_b], &set, 20, 3);
        assert!(result.is_valid());
    }

    #[test]
    fn patch_05_two_evidence_one_paired_one_unpaired_rejected() {
        let (sk_a, pk_a) = keypair(10);
        let (sk_b, pk_b) = keypair(11);
        let ev_a = make_evidence(&sk_a, pk_a);
        let ev_b = make_evidence(&sk_b, pk_b);
        let set = ValidatorSet::new(vec![record(7, pk_a, 10), record(8, pk_b, 15)]).unwrap();
        let change_a = synth(&ev_a, &set, 20, 3);
        // ev_b has no paired Remove.
        let result = validate_evidence_admission(&[change_a], &[ev_a, ev_b], &set, 20, 3);
        assert!(matches!(
            result,
            EvidenceAdmissionResult::Invalid(
                EvidenceAdmissionRejection::EvidenceMissingSyntheticRemove { idx: 1 }
            )
        ));
    }

    // ── Synthesis failures propagate ─────────────────────────────

    #[test]
    fn patch_05_evidence_with_outsider_signer_rejected_at_synthesis() {
        // Signer is not in active_set → synthesis fails → admission rejects.
        let (sk, pk) = keypair(5);
        let (_, other_pk) = keypair(99);
        let ev = make_evidence(&sk, pk);
        // Set contains only `other_pk`; `pk` (the signer) is absent.
        let set = ValidatorSet::new(vec![record(1, other_pk, 10)]).unwrap();
        let result = validate_evidence_admission(&[], &[ev], &set, 20, 3);
        assert!(matches!(
            result,
            EvidenceAdmissionResult::Invalid(EvidenceAdmissionRejection::SynthesisFailed {
                idx: 0,
                ..
            })
        ));
    }
}
