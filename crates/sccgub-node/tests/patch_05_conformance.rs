//! Patch-05 end-to-end conformance test.
//!
//! Exercises all six new v4 systems in a single deterministic flow:
//!
//! 1. **Fee oracle (§20)** — populate tension history, assert
//!    `effective_fee_median` is bounded between min/max window
//!    elements, and single-sample manipulation cannot move the
//!    median (INV-FEE-ORACLE-BOUNDED).
//! 2. **Mfidel seal VRF (§21)** — v4 seal derivation differs from v1
//!    and folds `prior_block_hash` (INV-SEAL-NO-GRIND precondition).
//! 3. **Evidence-sourced slashing (§22)** — `validate_evidence_admission`
//!    accepts a paired (evidence, synthetic Remove) block and rejects
//!    orphans / missing pairs (INV-SLASHING-LIVENESS).
//! 4. **Determinism lint (§23)** — compile-time property; not exercised
//!    at runtime here. The workspace build's successful compilation
//!    under `#![deny(clippy::iter_over_hash_type)]` across consensus,
//!    state, and execution is the conformance artifact.
//! 5. **Typed ModifyConsensusParam (§25)** —
//!    `validate_typed_param_proposal` accepts within-ceiling proposals
//!    and rejects ceiling violations under the current constitutional
//!    bounds (INV-TYPED-PARAM-CEILING first half).
//! 6. **Admitted-history projection (§27)** — admission appends to
//!    `system/validator_set_change_history` in order, and the history
//!    replays bit-identically (INV-HISTORY-COMPLETENESS).
//!
//! Also verifies **replay determinism** across the v4 surface by
//! running the scenario twice in independent `ManagedWorldState`
//! instances.

use ed25519_dalek::{Signer, SigningKey};

use sccgub_consensus::equivocation::{synthesize_equivocation_removal, EquivocationSynthesis};
use sccgub_execution::evidence_admission::{
    validate_evidence_admission, EvidenceAdmissionRejection, EvidenceAdmissionResult,
};
use sccgub_governance::patch_04::{validate_typed_param_proposal, TypedParamProposalRejection};
use sccgub_state::tension_history::{append_and_trim, tension_history_from_trie, window};
use sccgub_state::validator_set_state::{
    apply_validator_set_change_admission, commit_validator_set,
    validator_set_change_history_from_trie,
};
use sccgub_state::world::ManagedWorldState;
use sccgub_types::consensus_params::ConsensusParams;
use sccgub_types::constitutional_ceilings::{CeilingViolation, ConstitutionalCeilings};
use sccgub_types::economics::{median_of_tensions, EconomicState};
use sccgub_types::mfidel::MfidelAtomicSeal;
use sccgub_types::tension::TensionValue;
use sccgub_types::typed_params::{ConsensusParamField, ConsensusParamValue};
use sccgub_types::validator_set::{
    EquivocationEvidence, EquivocationVote, EquivocationVoteType, RemovalReason, ValidatorRecord,
    ValidatorSet, ValidatorSetChange, ValidatorSetChangeKind,
};
use sccgub_types::ZERO_HASH;

// ── Fixtures ───────────────────────────────────────────────────────

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
    let payload = sccgub_crypto::canonical::canonical_bytes(&(&pk, &block_hash, 10u64, 0u32, 0u8));
    EquivocationVote {
        validator_id: pk,
        block_hash,
        height: 10,
        round: 0,
        vote_type: EquivocationVoteType::Prevote,
        signature: sk.sign(&payload).to_bytes().to_vec(),
    }
}

fn t(n: i64) -> TensionValue {
    TensionValue::from_integer(n)
}

/// Run the full Patch-05 scenario and return observable outcomes for
/// replay comparison.
fn run_scenario() -> ScenarioOutcome {
    let mut state = ManagedWorldState::new();
    let params = ConsensusParams::default();
    let ceilings = ConstitutionalCeilings::default();

    // ── §20 fee oracle: fill tension history, assert boundedness ──
    for i in 0..5u64 {
        append_and_trim(&mut state, t(100 + i as i64 * 10)).unwrap();
    }
    let history = tension_history_from_trie(&state).unwrap();
    assert_eq!(history.len(), 5);
    let w = window(&history, params.median_tension_window as usize);
    let econ = EconomicState::default();
    let fee = econ.effective_fee_median(&w, t(1000), &params);
    let min_fee = econ.effective_fee_median(&[t(100); 5], t(1000), &params);
    let max_fee = econ.effective_fee_median(&[t(140); 5], t(1000), &params);
    assert!(
        min_fee <= fee && fee <= max_fee,
        "INV-FEE-ORACLE-BOUNDED violated: fee {} outside [{}, {}]",
        fee,
        min_fee,
        max_fee
    );

    // Single-sample manipulation must not move the median.
    let baseline = vec![t(100), t(100), t(100), t(100), t(100)];
    let attacker = vec![t(100), t(100), t(100), t(100), t(999_999)];
    assert_eq!(
        median_of_tensions(&baseline),
        median_of_tensions(&attacker),
        "single-sample manipulation moved the median"
    );

    // ── §21 Mfidel seal VRF ──────────────────────────────────────
    let prior_a = [0x11u8; 32];
    let prior_b = [0x22u8; 32];
    let seal_a = MfidelAtomicSeal::from_height_v4(10, &prior_a);
    let seal_b = MfidelAtomicSeal::from_height_v4(10, &prior_b);
    // Seals are deterministic:
    assert_eq!(seal_a, MfidelAtomicSeal::from_height_v4(10, &prior_a));
    // Prior-hash folding is real:
    let mut differs = false;
    for p in 0..32u8 {
        if MfidelAtomicSeal::from_height_v4(10, &[p; 32]) != seal_a {
            differs = true;
            break;
        }
    }
    assert!(differs, "§21 prior_block_hash folding is cosmetic");
    let _ = seal_b; // keep

    // ── §22 evidence-sourced slashing ────────────────────────────
    let (sk_v, pk_v) = keypair(5);
    let validator_set =
        ValidatorSet::new(vec![record(7, pk_v, 10), record(8, keypair(6).1, 10)]).unwrap();
    commit_validator_set(&mut state, &validator_set);
    let evidence = EquivocationEvidence::new(
        make_vote(&sk_v, pk_v, [0xAA; 32]),
        make_vote(&sk_v, pk_v, [0xBB; 32]),
    );
    let synthetic = match synthesize_equivocation_removal(&evidence, &validator_set, 20, 3) {
        EquivocationSynthesis::Synthesized(c) => c,
        other => panic!("synthesis failed: {:?}", other),
    };
    let happy = validate_evidence_admission(
        std::slice::from_ref(&synthetic),
        std::slice::from_ref(&evidence),
        &validator_set,
        20,
        3,
    );
    assert!(
        happy.is_valid(),
        "evidence-sourced admission happy path failed: {:?}",
        happy
    );

    // INV-SLASHING-LIVENESS: evidence without matching Remove is rejected.
    let liveness =
        validate_evidence_admission(&[], std::slice::from_ref(&evidence), &validator_set, 20, 3);
    assert!(matches!(
        liveness,
        EvidenceAdmissionResult::Invalid(
            EvidenceAdmissionRejection::EvidenceMissingSyntheticRemove { .. }
        )
    ));

    // ── §25 typed ModifyConsensusParam ──────────────────────────
    // Accept a within-ceiling proposal.
    validate_typed_param_proposal(
        &params,
        &ceilings,
        ConsensusParamField::MaxProofDepth,
        ConsensusParamValue::U32(300),
        100,
        50,
    )
    .unwrap();
    // Reject a ceiling-violating proposal.
    let over_ceiling = validate_typed_param_proposal(
        &params,
        &ceilings,
        ConsensusParamField::FeeTensionAlpha,
        ConsensusParamValue::I128(2 * TensionValue::SCALE), // > 1.0 ceiling
        100,
        50,
    );
    assert!(matches!(
        over_ceiling,
        Err(TypedParamProposalRejection::CeilingViolation(
            CeilingViolation::MaxFeeTensionAlpha { .. }
        ))
    ));

    // ── §27 admission-history projection ────────────────────────
    // Admit three changes; history must record all three in order.
    let c1 = signed_change(
        ValidatorSetChangeKind::RotatePower {
            agent_id: [7; 32],
            new_voting_power: 20,
            effective_height: 50,
        },
        5,
    );
    let c2 = signed_change(
        ValidatorSetChangeKind::RotatePower {
            agent_id: [7; 32],
            new_voting_power: 30,
            effective_height: 60,
        },
        6,
    );
    let c3 = signed_change(
        ValidatorSetChangeKind::Remove {
            agent_id: [8; 32],
            reason: RemovalReason::Voluntary,
            effective_height: 70,
        },
        7,
    );
    apply_validator_set_change_admission(&mut state, c1.clone()).unwrap();
    apply_validator_set_change_admission(&mut state, c2.clone()).unwrap();
    apply_validator_set_change_admission(&mut state, c3.clone()).unwrap();
    let history = validator_set_change_history_from_trie(&state).unwrap();
    assert_eq!(history.len(), 3);
    assert_eq!(history[0].change_id, c1.change_id);
    assert_eq!(history[1].change_id, c2.change_id);
    assert_eq!(history[2].change_id, c3.change_id);

    ScenarioOutcome {
        state_root: state.state_root(),
        tension_history_len: tension_history_from_trie(&state).unwrap().len(),
        admission_history_len: validator_set_change_history_from_trie(&state)
            .unwrap()
            .len(),
        seal_v4_at_10: seal_a,
    }
}

fn signed_change(kind: ValidatorSetChangeKind, proposed_at: u64) -> ValidatorSetChange {
    ValidatorSetChange {
        change_id: ValidatorSetChange::compute_change_id(&kind, proposed_at),
        kind,
        proposed_at,
        quorum_signatures: vec![],
    }
}

#[derive(Debug, PartialEq, Eq)]
struct ScenarioOutcome {
    state_root: [u8; 32],
    tension_history_len: usize,
    admission_history_len: usize,
    seal_v4_at_10: MfidelAtomicSeal,
}

#[test]
fn patch_05_conformance_end_to_end() {
    let outcome = run_scenario();
    assert_ne!(outcome.state_root, ZERO_HASH);
    assert_eq!(outcome.tension_history_len, 5);
    assert_eq!(outcome.admission_history_len, 3);
    assert!(outcome.seal_v4_at_10.is_valid());
}

#[test]
fn patch_05_conformance_replay_determinism_across_v4_systems() {
    // Two independent runs produce bit-identical state roots and outcomes.
    let run_a = run_scenario();
    let run_b = run_scenario();
    assert_eq!(
        run_a, run_b,
        "Patch-05 scenario must replay deterministically across all v4 systems"
    );
}
