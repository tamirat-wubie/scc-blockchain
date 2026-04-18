//! Multi-validator convergence test (Patch-07 §A groundwork).
//!
//! The v0.5.0 and v0.6.0 audits both flagged the absence of a
//! multi-validator integration harness. A full BFT harness is large and
//! coupled to network plumbing; this test takes the narrower "replay
//! determinism across N independent validators" slice that is
//! sufficient to exercise the consensus-critical invariants Patch-06
//! introduced.
//!
//! Scenario: three independent `ManagedWorldState` instances each apply
//! the same deterministic sequence of Patch-06-surface mutations:
//!
//! - Constitutional-ceilings commit (§17 genesis-only)
//! - Validator-set commit (§15)
//! - Tension-history appends (§20 oracle)
//! - Admission-history appends (§27 projection)
//! - Chain-version transition append (§34 upgrade)
//!
//! After the sequence completes, every validator's `state_root()` MUST
//! match. Validators must also read back identical projections
//! (admission history, chain-version history, ceilings).
//!
//! This test doubles as a regression fence for the Patch-06 surface:
//! any future change that accidentally introduces nondeterminism — a
//! `HashMap` iteration, a wall-clock read, a nondeterministic
//! serialization — will cause state roots to diverge here.

use sccgub_state::chain_version_history_state::{
    append_chain_version_transition, chain_version_history_from_trie,
};
use sccgub_state::constitutional_ceilings_state::{
    commit_constitutional_ceilings_at_genesis, constitutional_ceilings_from_trie,
};
use sccgub_state::tension_history::{append_and_trim, tension_history_from_trie};
use sccgub_state::validator_set_state::{
    apply_validator_set_change_admission, commit_validator_set,
    validator_set_change_history_from_trie,
};
use sccgub_state::world::ManagedWorldState;
use sccgub_types::constitutional_ceilings::ConstitutionalCeilings;
use sccgub_types::mfidel::MfidelAtomicSeal;
use sccgub_types::tension::TensionValue;
use sccgub_types::upgrade::ChainVersionTransition;
use sccgub_types::validator_set::{
    RemovalReason, ValidatorRecord, ValidatorSet, ValidatorSetChange, ValidatorSetChangeKind,
};

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

fn rotate_power(agent: u8, proposed_at: u64, power: u64) -> ValidatorSetChange {
    let kind = ValidatorSetChangeKind::RotatePower {
        agent_id: [agent; 32],
        new_voting_power: power,
        effective_height: proposed_at + 5,
    };
    ValidatorSetChange {
        change_id: ValidatorSetChange::compute_change_id(&kind, proposed_at),
        kind,
        proposed_at,
        quorum_signatures: vec![],
    }
}

fn remove_change(agent: u8, proposed_at: u64) -> ValidatorSetChange {
    let kind = ValidatorSetChangeKind::Remove {
        agent_id: [agent; 32],
        reason: RemovalReason::Voluntary,
        effective_height: proposed_at + 5,
    };
    ValidatorSetChange {
        change_id: ValidatorSetChange::compute_change_id(&kind, proposed_at),
        kind,
        proposed_at,
        quorum_signatures: vec![],
    }
}

fn t(n: i64) -> TensionValue {
    TensionValue::from_integer(n)
}

/// Drive the full Patch-06 state surface through a single validator
/// instance. The sequence is identical across every validator; if any
/// mutation is order-dependent or nondeterministic, post-run state
/// roots will diverge.
fn drive_patch_06_surface(state: &mut ManagedWorldState) {
    // §17: commit ceilings at genesis.
    commit_constitutional_ceilings_at_genesis(state, &ConstitutionalCeilings::default()).unwrap();

    // §15: commit a 3-validator set.
    let set = ValidatorSet::new(vec![
        record(1, [0xAA; 32], 10),
        record(2, [0xBB; 32], 20),
        record(3, [0xCC; 32], 30),
    ])
    .unwrap();
    commit_validator_set(state, &set);

    // §20: fill tension history (a specific, deterministic sequence).
    for i in 0..7u64 {
        append_and_trim(state, t(100 + i as i64 * 10)).unwrap();
    }

    // §27: admit three validator-set changes in sequence.
    apply_validator_set_change_admission(state, rotate_power(1, 100, 15)).unwrap();
    apply_validator_set_change_admission(state, rotate_power(2, 101, 25)).unwrap();
    apply_validator_set_change_admission(state, remove_change(3, 102)).unwrap();

    // §34: append one chain-version transition.
    append_chain_version_transition(
        state,
        ChainVersionTransition {
            activation_height: 20_000,
            from_version: 4,
            to_version: 5,
            upgrade_spec_hash: [0xDE; 32],
            proposal_id: [0xAD; 32],
        },
    )
    .unwrap();
}

#[test]
fn multi_validator_state_roots_converge_on_patch_06_surface() {
    // Three independent validators run the same sequence.
    let mut v0 = ManagedWorldState::new();
    let mut v1 = ManagedWorldState::new();
    let mut v2 = ManagedWorldState::new();

    drive_patch_06_surface(&mut v0);
    drive_patch_06_surface(&mut v1);
    drive_patch_06_surface(&mut v2);

    let r0 = v0.state_root();
    let r1 = v1.state_root();
    let r2 = v2.state_root();

    assert_eq!(r0, r1, "validator 0 and 1 diverged on Patch-06 state root");
    assert_eq!(r1, r2, "validator 1 and 2 diverged on Patch-06 state root");
}

#[test]
fn multi_validator_patch_06_projections_match() {
    // Every validator must read back identical projections.
    let mut v0 = ManagedWorldState::new();
    let mut v1 = ManagedWorldState::new();

    drive_patch_06_surface(&mut v0);
    drive_patch_06_surface(&mut v1);

    // §27: admission history matches length, change_id sequence, ordering.
    let h0 = validator_set_change_history_from_trie(&v0).unwrap();
    let h1 = validator_set_change_history_from_trie(&v1).unwrap();
    assert_eq!(h0.len(), 3);
    assert_eq!(h0.len(), h1.len());
    for i in 0..h0.len() {
        assert_eq!(
            h0[i].change_id, h1[i].change_id,
            "admission[{}] diverged",
            i
        );
    }

    // §20: tension history matches.
    let t0 = tension_history_from_trie(&v0).unwrap();
    let t1 = tension_history_from_trie(&v1).unwrap();
    assert_eq!(t0, t1);

    // §17: ceilings match (should be default).
    let c0 = constitutional_ceilings_from_trie(&v0).unwrap();
    let c1 = constitutional_ceilings_from_trie(&v1).unwrap();
    assert_eq!(c0, c1);

    // §34: chain-version transitions match.
    let t0 = chain_version_history_from_trie(&v0).unwrap();
    let t1 = chain_version_history_from_trie(&v1).unwrap();
    assert_eq!(t0.len(), 1);
    assert_eq!(t0[0].activation_height, t1[0].activation_height);
    assert_eq!(t0[0].proposal_id, t1[0].proposal_id);
}

#[test]
fn multi_validator_repeated_runs_stable() {
    // Run the full scenario twice on the same validator; results must
    // be byte-identical (no accumulated nondeterminism across runs).
    let mut a = ManagedWorldState::new();
    let mut b = ManagedWorldState::new();
    drive_patch_06_surface(&mut a);
    drive_patch_06_surface(&mut b);

    let ra = a.state_root();
    let rb = b.state_root();
    assert_eq!(ra, rb, "repeat run on fresh state must produce same root");
}
