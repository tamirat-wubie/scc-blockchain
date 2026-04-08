//! Production Gate 1: Adversarial consensus certification.
//! Tests that prove the chain stays safe under hostile conditions.
//!
//! Covers: Byzantine votes, double-signing, partition recovery,
//! validator churn, replay determinism, and conservation invariants.

use std::collections::HashMap;

use sccgub_consensus::finality::{FinalityConfig, FinalityTracker};
use sccgub_consensus::partition::PartitionConfig;
use sccgub_consensus::protocol::*;
use sccgub_consensus::safety::*;
use sccgub_consensus::slashing::{SlashingConfig, SlashingEngine};
use sccgub_crypto::keys::generate_keypair;
use sccgub_types::tension::TensionValue;

// === Helpers ===

fn make_validators(
    n: u8,
) -> (
    HashMap<[u8; 32], [u8; 32]>,
    Vec<([u8; 32], ed25519_dalek::SigningKey)>,
) {
    let mut set = HashMap::new();
    let mut keys = Vec::new();
    for i in 1..=n {
        let key = generate_keypair();
        let pk = *key.verifying_key().as_bytes();
        let id = [i; 32];
        set.insert(id, pk);
        keys.push((id, key));
    }
    (set, keys)
}

const TEST_CHAIN_ID: [u8; 32] = [0xCC; 32];
const TEST_EPOCH: u64 = 1;

fn signed_vote(
    id: [u8; 32],
    key: &ed25519_dalek::SigningKey,
    block: [u8; 32],
    height: u64,
    round: u32,
    vtype: VoteType,
) -> Vote {
    let data = sccgub_consensus::protocol::vote_sign_data(
        &TEST_CHAIN_ID,
        TEST_EPOCH,
        &block,
        height,
        round,
        vtype,
    );
    let sig = sccgub_crypto::signature::sign(key, &data);
    Vote {
        validator_id: id,
        block_hash: block,
        height,
        round,
        vote_type: vtype,
        signature: sig,
    }
}

fn test_round(
    block: [u8; 32],
    height: u64,
    round: u32,
    vs: HashMap<[u8; 32], [u8; 32]>,
) -> ConsensusRound {
    ConsensusRound::new(TEST_CHAIN_ID, TEST_EPOCH, block, height, round, vs, 10)
}

// === Gate 1: Byzantine consensus tests ===

#[test]
fn test_byzantine_minority_cannot_finalize() {
    let block = [0xAAu8; 32];
    let bad_block = [0xBBu8; 32];
    let (vs, keys) = make_validators(7);
    let mut round = test_round(block, 1, 0, vs);

    for i in 0..5 {
        round
            .add_prevote(signed_vote(
                keys[i].0,
                &keys[i].1,
                block,
                1,
                0,
                VoteType::Prevote,
            ))
            .unwrap();
    }
    for i in 5..7 {
        round
            .add_prevote(signed_vote(
                keys[i].0,
                &keys[i].1,
                bad_block,
                1,
                0,
                VoteType::Prevote,
            ))
            .unwrap();
    }

    assert!(round.has_prevote_quorum());
    assert_eq!(round.prevote_count(), 5);
}

#[test]
fn test_one_third_byzantine_blocks_quorum() {
    let block = [0xAAu8; 32];
    let bad_block = [0xBBu8; 32];
    let (vs, keys) = make_validators(6);
    let mut round = test_round(block, 1, 0, vs);

    for i in 0..4 {
        round
            .add_prevote(signed_vote(
                keys[i].0,
                &keys[i].1,
                block,
                1,
                0,
                VoteType::Prevote,
            ))
            .unwrap();
    }
    for i in 4..6 {
        round
            .add_prevote(signed_vote(
                keys[i].0,
                &keys[i].1,
                bad_block,
                1,
                0,
                VoteType::Prevote,
            ))
            .unwrap();
    }

    assert!(
        !round.has_prevote_quorum(),
        "4/6 should not reach quorum of 5"
    );
}

#[test]
fn test_forged_vote_from_non_member_rejected() {
    let block = [0xAAu8; 32];
    let (vs, _) = make_validators(4);
    let mut round = test_round(block, 1, 0, vs);

    let outsider = generate_keypair();
    let vote = signed_vote([99u8; 32], &outsider, block, 1, 0, VoteType::Prevote);
    assert!(round.add_prevote(vote).is_err());
}

#[test]
fn test_vote_with_wrong_height_rejected() {
    let block = [0xAAu8; 32];
    let (vs, keys) = make_validators(4);
    let mut round = ConsensusRound::new(TEST_CHAIN_ID, TEST_EPOCH, block, 5, 0, vs, 10);

    let vote = signed_vote(keys[0].0, &keys[0].1, block, 999, 0, VoteType::Prevote);
    assert!(round.add_prevote(vote).is_err());
}

#[test]
fn test_vote_with_wrong_round_rejected() {
    let block = [0xAAu8; 32];
    let (vs, keys) = make_validators(4);
    let mut round = test_round(block, 1, 0, vs);

    let vote = signed_vote(keys[0].0, &keys[0].1, block, 1, 5, VoteType::Prevote);
    assert!(round.add_prevote(vote).is_err());
}

#[test]
fn test_empty_signature_rejected() {
    let block = [0xAAu8; 32];
    let (vs, keys) = make_validators(4);
    let mut round = test_round(block, 1, 0, vs);

    let vote = Vote {
        validator_id: keys[0].0,
        block_hash: block,
        height: 1,
        round: 0,
        vote_type: VoteType::Prevote,
        signature: vec![],
    };
    assert!(round.add_prevote(vote).is_err());
}

#[test]
fn test_corrupted_signature_rejected() {
    let block = [0xAAu8; 32];
    let (vs, keys) = make_validators(4);
    let mut round = test_round(block, 1, 0, vs);

    let mut vote = signed_vote(keys[0].0, &keys[0].1, block, 1, 0, VoteType::Prevote);
    vote.signature[0] ^= 0xFF;
    assert!(round.add_prevote(vote).is_err());
}

// === Equivocation detection and slashing ===

#[test]
fn test_double_signing_produces_evidence_and_slashing() {
    let key = generate_keypair();
    let pk = *key.verifying_key().as_bytes();
    let id = [1u8; 32];
    let height = 10u64;

    let block_a = [0xAAu8; 32];
    let block_b = [0xBBu8; 32];

    let data_a = sccgub_crypto::canonical::canonical_bytes(&(&block_a, height, 0u32, 2u8));
    let data_b = sccgub_crypto::canonical::canonical_bytes(&(&block_b, height, 0u32, 2u8));

    let evidence = EquivocationEvidence {
        validator_id: id,
        height,
        round_a: 0,
        round_b: 0,
        block_hash_a: block_a,
        block_hash_b: block_b,
        signature_a: sccgub_crypto::signature::sign(&key, &data_a),
        signature_b: sccgub_crypto::signature::sign(&key, &data_b),
    };
    assert!(evidence.verify(&pk).is_ok());

    let mut store = EquivocationStore::new();
    assert!(store.submit_evidence(evidence, &pk).unwrap());
    assert!(store.is_equivocator(&id));

    // Slashing via protocol-level EquivocationProof.
    let mut engine = SlashingEngine::new(SlashingConfig::default());
    engine.set_stake(id, TensionValue::from_integer(100_000));

    let proof = EquivocationProof {
        validator_id: id,
        height,
        round: 0,
        vote_type: VoteType::Prevote,
        block_hash_a: block_a,
        block_hash_b: block_b,
    };
    engine.slash_double_sign(proof, 10).unwrap();

    let stake = engine.stakes.get(&id).unwrap();
    assert!(stake.raw() < TensionValue::from_integer(100_000).raw());
}

// === Safety certificate verification ===

#[test]
fn test_safety_cert_cryptographic_verification() {
    let block = [42u8; 32];
    let height = 5u64;
    let round = 0u32;
    let (vs, keys) = make_validators(4);

    let mut precommit_sigs = Vec::new();
    for (id, key) in &keys[..3] {
        let data = sccgub_crypto::canonical::canonical_bytes(&(&block, height, round, 2u8));
        let sig = sccgub_crypto::signature::sign(key, &data);
        precommit_sigs.push((*id, sig));
    }

    let cert = SafetyCertificate {
        height,
        block_hash: block,
        round,
        precommit_signatures: precommit_sigs,
        quorum: 3,
        validator_count: 4,
    };

    assert!(cert.verify_cryptographic(&vs).is_ok());
}

#[test]
fn test_safety_cert_rejects_non_member_signer() {
    let block = [42u8; 32];
    let (vs, _) = make_validators(4);
    let outsider = generate_keypair();

    let data = sccgub_crypto::canonical::canonical_bytes(&(&block, 5u64, 0u32, 2u8));
    let sig = sccgub_crypto::signature::sign(&outsider, &data);

    let cert = SafetyCertificate {
        height: 5,
        block_hash: block,
        round: 0,
        precommit_signatures: vec![
            ([99u8; 32], sig),
            ([1; 32], vec![0; 64]),
            ([2; 32], vec![0; 64]),
        ],
        quorum: 3,
        validator_count: 4,
    };

    assert!(cert.verify_cryptographic(&vs).is_err());
}

// === Fork proof ===

#[test]
fn test_conflicting_certs_detect_equivocators() {
    let (_vs, keys) = make_validators(7);
    let height = 10u64;
    let block_a = [0xAAu8; 32];
    let block_b = [0xBBu8; 32];

    let mut sigs_a = Vec::new();
    for i in 0..5 {
        let data = sccgub_crypto::canonical::canonical_bytes(&(&block_a, height, 0u32, 2u8));
        let sig = sccgub_crypto::signature::sign(&keys[i].1, &data);
        sigs_a.push((keys[i].0, sig));
    }

    let mut sigs_b = Vec::new();
    for i in 3..7 {
        let data = sccgub_crypto::canonical::canonical_bytes(&(&block_b, height, 0u32, 2u8));
        let sig = sccgub_crypto::signature::sign(&keys[i].1, &data);
        sigs_b.push((keys[i].0, sig));
    }

    let cert_a = SafetyCertificate {
        height,
        block_hash: block_a,
        round: 0,
        precommit_signatures: sigs_a,
        quorum: 5,
        validator_count: 7,
    };
    let cert_b = SafetyCertificate {
        height,
        block_hash: block_b,
        round: 0,
        precommit_signatures: sigs_b,
        quorum: 5,
        validator_count: 7,
    };

    assert!(cert_a.verify_structure().is_ok());

    let evidence = EquivocationStore::extract_from_fork(&cert_a, &cert_b);
    assert_eq!(evidence.len(), 2, "Validators 3 and 4 signed both certs");
}

// === Partition detection and recovery ===

#[test]
fn test_partition_detection_and_recovery_plan() {
    let mut detector = sccgub_consensus::partition::PartitionDetector::default();
    let config = PartitionConfig::default();

    detector.report_height([1u8; 32], 100);
    detector.report_height([2u8; 32], 100);
    detector.report_height([3u8; 32], 100);
    detector.report_height([4u8; 32], 80);

    let status = detector.detect(&config);
    assert!(
        matches!(
            status,
            sccgub_consensus::partition::PartitionStatus::Partitioned { .. }
        ),
        "Should detect partition"
    );

    let recovery = sccgub_consensus::partition::plan_recovery(&status, &config, 95);
    assert!(
        matches!(
            recovery,
            sccgub_consensus::partition::RecoveryAction::Rollback { .. }
        ),
        "Should plan rollback recovery"
    );
}

// === Finality behavior ===

#[test]
fn test_finality_progresses_monotonically() {
    let config = FinalityConfig {
        confirmation_depth: 2,
        ..Default::default()
    };
    let mut tracker = FinalityTracker::default();

    let mut finalized_heights = Vec::new();
    for h in 1..=20 {
        tracker.on_new_block(h);
        tracker.check_finality(&config, |height| Some([height as u8; 32]));
        finalized_heights.push(tracker.finalized_height);
    }

    for w in finalized_heights.windows(2) {
        assert!(
            w[1] >= w[0],
            "Finality must not regress: {} < {}",
            w[1],
            w[0]
        );
    }
    // With depth=2, tip=20: finalized_height advances while finalized+depth <= tip.
    let final_h = *finalized_heights.last().unwrap();
    assert!(
        final_h >= 18,
        "Should finalize at least height 18, got {}",
        final_h
    );
}

#[test]
fn test_finality_gap_bounded() {
    let config = FinalityConfig {
        confirmation_depth: 3,
        ..Default::default()
    };
    let mut tracker = FinalityTracker::default();

    for h in 1..=100 {
        tracker.on_new_block(h);
        tracker.check_finality(&config, |height| Some([height as u8; 32]));
        assert!(
            tracker.finality_gap() <= config.confirmation_depth,
            "Finality gap {} exceeds depth {} at height {}",
            tracker.finality_gap(),
            config.confirmation_depth,
            h
        );
    }
}

// === Slashing persistence ===

#[test]
fn test_slashing_state_survives_serialization() {
    let mut engine = SlashingEngine::new(SlashingConfig::default());
    let id = [1u8; 32];
    engine.set_stake(id, TensionValue::from_integer(100_000));

    let proof = EquivocationProof {
        validator_id: id,
        height: 1,
        round: 0,
        vote_type: VoteType::Prevote,
        block_hash_a: [0xAA; 32],
        block_hash_b: [0xBB; 32],
    };
    engine.slash_double_sign(proof, 1).unwrap();

    let json = serde_json::to_string(&engine.events).unwrap();
    let recovered: Vec<sccgub_consensus::slashing::SlashingEvent> =
        serde_json::from_str(&json).unwrap();

    assert_eq!(recovered.len(), 1);
    assert!(engine.stakes.get(&id).unwrap().raw() < TensionValue::from_integer(100_000).raw());
}

// === Gate 2: Replay determinism ===

#[test]
fn test_replay_produces_identical_state() {
    use sccgub_state::apply::apply_genesis_mint;
    use sccgub_state::balances::BalanceLedger;
    use sccgub_state::world::ManagedWorldState;
    use sccgub_types::transition::{StateDelta, StateWrite};

    let validator = [1u8; 32];

    let mut state1 = ManagedWorldState::new();
    let mut bal1 = BalanceLedger::new();
    apply_genesis_mint(&mut state1, &mut bal1, &validator);
    state1.apply_delta(&StateDelta {
        writes: vec![
            StateWrite {
                address: b"key/a".to_vec(),
                value: b"val_a".to_vec(),
            },
            StateWrite {
                address: b"key/b".to_vec(),
                value: b"val_b".to_vec(),
            },
        ],
        deletes: vec![],
    });

    let mut state2 = ManagedWorldState::new();
    let mut bal2 = BalanceLedger::new();
    apply_genesis_mint(&mut state2, &mut bal2, &validator);
    state2.apply_delta(&StateDelta {
        writes: vec![
            StateWrite {
                address: b"key/a".to_vec(),
                value: b"val_a".to_vec(),
            },
            StateWrite {
                address: b"key/b".to_vec(),
                value: b"val_b".to_vec(),
            },
        ],
        deletes: vec![],
    });

    assert_eq!(state1.state_root(), state2.state_root());
    assert_eq!(bal1.total_supply(), bal2.total_supply());
}

// === Gate 3: Financial conservation proofs ===

#[test]
fn test_conservation_transfer_preserves_supply() {
    use sccgub_state::balances::BalanceLedger;

    let mut ledger = BalanceLedger::new();
    let alice = [1u8; 32];
    let bob = [2u8; 32];
    let carol = [3u8; 32];

    ledger.credit(&alice, TensionValue::from_integer(10_000));
    let initial = ledger.total_supply();

    ledger
        .transfer(&alice, &bob, TensionValue::from_integer(3_000))
        .unwrap();
    ledger
        .transfer(&bob, &carol, TensionValue::from_integer(1_500))
        .unwrap();
    ledger
        .transfer(&carol, &alice, TensionValue::from_integer(500))
        .unwrap();

    assert_eq!(ledger.total_supply(), initial);
}

#[test]
fn test_conservation_treasury_lifecycle() {
    use sccgub_state::treasury::Treasury;

    let mut treasury = Treasury::new();
    let fee_total = TensionValue::from_integer(1000);
    treasury.collect_fee(fee_total);

    let distributed = treasury.distribute_reward(TensionValue::from_integer(300));
    treasury.burn(TensionValue::from_integer(200)).unwrap();

    let sum =
        TensionValue(distributed.raw() + treasury.total_burned.raw() + treasury.pending_fees.raw());
    assert_eq!(sum, fee_total);
}

#[test]
fn test_conservation_escrow_lifecycle() {
    use sccgub_state::balances::BalanceLedger;
    use sccgub_state::escrow::{EscrowCondition, EscrowRegistry};

    let mut bal = BalanceLedger::new();
    let alice = [1u8; 32];
    let bob = [2u8; 32];
    bal.credit(&alice, TensionValue::from_integer(1000));
    let initial = bal.total_supply();

    let mut escrow = EscrowRegistry::new();
    let id = escrow
        .create(
            alice,
            bob,
            TensionValue::from_integer(400),
            EscrowCondition::ArbiterApproval { arbiter: [3u8; 32] },
            1,
            100,
            &mut bal,
        )
        .unwrap();

    assert_eq!(
        TensionValue(bal.total_supply().raw() + escrow.total_locked().raw()),
        initial,
    );

    escrow.release(&id, &mut bal).unwrap();
    assert_eq!(bal.total_supply(), initial);
}

#[test]
fn test_conservation_escrow_refund_path() {
    use sccgub_state::balances::BalanceLedger;
    use sccgub_state::escrow::{EscrowCondition, EscrowRegistry};

    let mut bal = BalanceLedger::new();
    let alice = [1u8; 32];
    let bob = [2u8; 32];
    bal.credit(&alice, TensionValue::from_integer(1000));
    let initial = bal.total_supply();

    let mut escrow = EscrowRegistry::new();
    let id = escrow
        .create(
            alice,
            bob,
            TensionValue::from_integer(600),
            EscrowCondition::TimeLocked { release_at: 500 },
            1,
            10,
            &mut bal,
        )
        .unwrap();

    escrow.refund(&id, 11, &mut bal).unwrap();
    assert_eq!(bal.total_supply(), initial);
    assert_eq!(bal.balance_of(&alice), TensionValue::from_integer(1000));
}

#[test]
fn test_failed_transfer_does_not_mutate_state() {
    use sccgub_state::balances::BalanceLedger;

    let mut ledger = BalanceLedger::new();
    let alice = [1u8; 32];
    let bob = [2u8; 32];
    ledger.credit(&alice, TensionValue::from_integer(100));

    let before_alice = ledger.balance_of(&alice);
    let before_bob = ledger.balance_of(&bob);
    let before_supply = ledger.total_supply();

    let result = ledger.transfer(&alice, &bob, TensionValue::from_integer(500));
    assert!(result.is_err());

    assert_eq!(ledger.balance_of(&alice), before_alice);
    assert_eq!(ledger.balance_of(&bob), before_bob);
    assert_eq!(ledger.total_supply(), before_supply);
}

#[test]
fn test_no_supply_creation_without_explicit_credit() {
    use sccgub_state::balances::BalanceLedger;

    let mut ledger = BalanceLedger::new();
    assert_eq!(ledger.total_supply(), TensionValue::ZERO);

    let result = ledger.transfer(&[1u8; 32], &[2u8; 32], TensionValue::from_integer(1));
    assert!(result.is_err());
    assert_eq!(ledger.total_supply(), TensionValue::ZERO);
}

#[test]
fn test_gas_fee_conservation() {
    use sccgub_execution::gas::GasMeter;
    use sccgub_state::treasury::Treasury;

    let mut treasury = Treasury::new();
    let gas_price = TensionValue::from_integer(1);
    let mut total_gas = 0u64;

    for i in 1..=10u64 {
        let mut meter = GasMeter::default_tx();
        meter.charge_compute(i * 100).unwrap();
        meter.charge_state_write().unwrap();

        let fee = meter.compute_fee(gas_price);
        treasury.collect_fee(fee);
        total_gas += meter.used;
    }

    let expected = TensionValue((total_gas as i128).saturating_mul(gas_price.raw()));
    assert_eq!(treasury.total_fees_collected, expected);
}

// === Adversarial escrow tests ===

#[test]
fn test_escrow_double_release_rejected() {
    use sccgub_state::balances::BalanceLedger;
    use sccgub_state::escrow::{EscrowCondition, EscrowRegistry};

    let mut bal = BalanceLedger::new();
    bal.credit(&[1u8; 32], TensionValue::from_integer(1000));
    let initial = bal.total_supply();

    let mut escrow = EscrowRegistry::new();
    let id = escrow
        .create(
            [1u8; 32],
            [2u8; 32],
            TensionValue::from_integer(500),
            EscrowCondition::ArbiterApproval { arbiter: [3u8; 32] },
            1,
            100,
            &mut bal,
        )
        .unwrap();

    escrow.release(&id, &mut bal).unwrap();

    // Second release must fail — funds already released.
    let result = escrow.release(&id, &mut bal);
    assert!(result.is_err(), "Double release must be rejected");
    assert_eq!(bal.total_supply(), initial, "Supply must be conserved");
}

#[test]
fn test_escrow_refund_after_release_rejected() {
    use sccgub_state::balances::BalanceLedger;
    use sccgub_state::escrow::{EscrowCondition, EscrowRegistry};

    let mut bal = BalanceLedger::new();
    bal.credit(&[1u8; 32], TensionValue::from_integer(1000));

    let mut escrow = EscrowRegistry::new();
    let id = escrow
        .create(
            [1u8; 32],
            [2u8; 32],
            TensionValue::from_integer(500),
            EscrowCondition::TimeLocked { release_at: 50 },
            1,
            100,
            &mut bal,
        )
        .unwrap();

    escrow.release(&id, &mut bal).unwrap();

    // Refund after release must fail.
    let result = escrow.refund(&id, 200, &mut bal);
    assert!(result.is_err(), "Refund after release must be rejected");
}

#[test]
fn test_escrow_premature_refund_rejected() {
    use sccgub_state::balances::BalanceLedger;
    use sccgub_state::escrow::{EscrowCondition, EscrowRegistry};

    let mut bal = BalanceLedger::new();
    bal.credit(&[1u8; 32], TensionValue::from_integer(1000));

    let mut escrow = EscrowRegistry::new();
    let id = escrow
        .create(
            [1u8; 32],
            [2u8; 32],
            TensionValue::from_integer(300),
            EscrowCondition::ArbiterApproval { arbiter: [3u8; 32] },
            1,
            100, // timeout at block 101.
            &mut bal,
        )
        .unwrap();

    // Refund at block 50 (before timeout 101).
    let result = escrow.refund(&id, 50, &mut bal);
    assert!(result.is_err(), "Premature refund must be rejected");
}

#[test]
fn test_escrow_zero_amount_rejected() {
    use sccgub_state::balances::BalanceLedger;
    use sccgub_state::escrow::{EscrowCondition, EscrowRegistry};

    let mut bal = BalanceLedger::new();
    bal.credit(&[1u8; 32], TensionValue::from_integer(1000));

    let mut escrow = EscrowRegistry::new();
    let result = escrow.create(
        [1u8; 32],
        [2u8; 32],
        TensionValue::ZERO,
        EscrowCondition::TimeLocked { release_at: 50 },
        1,
        100,
        &mut bal,
    );
    assert!(result.is_err(), "Zero-amount escrow must be rejected");
}

#[test]
fn test_escrow_self_escrow_rejected() {
    use sccgub_state::balances::BalanceLedger;
    use sccgub_state::escrow::{EscrowCondition, EscrowRegistry};

    let mut bal = BalanceLedger::new();
    bal.credit(&[1u8; 32], TensionValue::from_integer(1000));

    let mut escrow = EscrowRegistry::new();
    let result = escrow.create(
        [1u8; 32],
        [1u8; 32], // Same sender and recipient.
        TensionValue::from_integer(100),
        EscrowCondition::TimeLocked { release_at: 50 },
        1,
        100,
        &mut bal,
    );
    assert!(result.is_err(), "Self-escrow must be rejected");
}

// === Adversarial receipt / validation tests ===

#[test]
fn test_metered_validation_rejects_invalid_tx() {
    use sccgub_execution::validate::validate_transition_metered;
    use sccgub_state::world::ManagedWorldState;
    use sccgub_types::agent::{AgentIdentity, ResponsibilityState};
    use sccgub_types::governance::PrecedenceLevel;
    use sccgub_types::mfidel::MfidelAtomicSeal;
    use sccgub_types::timestamp::CausalTimestamp;
    use sccgub_types::transition::*;
    use std::collections::HashSet;

    let state = ManagedWorldState::new();

    // Create a tx with empty signature (invalid).
    let tx = SymbolicTransition {
        tx_id: [0u8; 32],
        actor: AgentIdentity {
            agent_id: [1u8; 32],
            public_key: [0u8; 32],
            mfidel_seal: MfidelAtomicSeal::from_height(1),
            registration_block: 0,
            governance_level: PrecedenceLevel::Meaning,
            norm_set: HashSet::new(),
            responsibility: ResponsibilityState::default(),
        },
        intent: TransitionIntent {
            kind: TransitionKind::StateWrite,
            target: b"test".to_vec(),
            declared_purpose: "test".into(),
        },
        preconditions: vec![],
        postconditions: vec![],
        payload: OperationPayload::Write {
            key: b"test".to_vec(),
            value: b"val".to_vec(),
        },
        causal_chain: vec![],
        wh_binding_intent: WHBindingIntent {
            who: [1u8; 32],
            when: CausalTimestamp::genesis(),
            r#where: b"test".to_vec(),
            why: CausalJustification {
                invoking_rule: [2u8; 32],
                precedence_level: PrecedenceLevel::Meaning,
                causal_ancestors: vec![],
                constraint_proof: vec![],
            },
            how: TransitionMechanism::DirectStateWrite,
            which: HashSet::new(),
            what_declared: "test".into(),
        },
        nonce: 1,
        signature: vec![], // Empty — invalid.
    };

    let (receipt, gas_used) =
        validate_transition_metered(&tx, &state, sccgub_execution::gas::costs::DEFAULT_TX_LIMIT);

    assert!(
        !receipt.verdict.is_accepted(),
        "Invalid tx must be rejected"
    );
    assert!(gas_used > 0, "Gas must be consumed even for rejected txs");
    assert_eq!(
        receipt.pre_state_root, receipt.post_state_root,
        "Rejected tx must not change state"
    );
}

// === Restart / replay convergence tests ===

#[test]
fn test_chain_init_replay_convergence() {
    // Two independent chain inits produce different keys but identical genesis structure.
    use sccgub_state::apply::apply_genesis_mint;
    use sccgub_state::balances::BalanceLedger;
    use sccgub_state::world::ManagedWorldState;

    let validator = [42u8; 32];

    let mut s1 = ManagedWorldState::new();
    let mut b1 = BalanceLedger::new();
    apply_genesis_mint(&mut s1, &mut b1, &validator);

    let mut s2 = ManagedWorldState::new();
    let mut b2 = BalanceLedger::new();
    apply_genesis_mint(&mut s2, &mut b2, &validator);

    assert_eq!(
        s1.state_root(),
        s2.state_root(),
        "Genesis mint must be deterministic"
    );
    assert_eq!(b1.total_supply(), b2.total_supply());
    assert_eq!(b1.balance_of(&validator), b2.balance_of(&validator));
}

#[test]
fn test_keystore_roundtrip_argon2_chacha() {
    use sccgub_crypto::keystore::{decrypt_key, encrypt_key};

    let key = sccgub_crypto::keys::generate_keypair();
    let passphrase = "production-grade-passphrase-2024!";

    let bundle = encrypt_key(&key, passphrase).unwrap();
    assert_eq!(bundle.kdf, "argon2id");
    assert_eq!(bundle.cipher, "chacha20-poly1305");

    let recovered = decrypt_key(&bundle, passphrase).unwrap();
    assert_eq!(key.as_bytes(), recovered.as_bytes());

    // Wrong passphrase must fail with AEAD rejection.
    assert!(decrypt_key(&bundle, "wrong").is_err());
}

#[test]
fn test_keystore_tampered_ciphertext_detected() {
    use sccgub_crypto::keystore::{decrypt_key, encrypt_key};

    let key = sccgub_crypto::keys::generate_keypair();
    let mut bundle = encrypt_key(&key, "pass").unwrap();
    bundle.ciphertext[5] ^= 0xFF; // Tamper.
    assert!(
        decrypt_key(&bundle, "pass").is_err(),
        "AEAD must detect tampering"
    );
}

// === Role-based custody tests ===

#[test]
fn test_custody_role_separation() {
    use sccgub_crypto::roles::*;

    let mut keyring = OperatorKeyring::new();
    let val_pk = [1u8; 32];
    let treasury_pk = [2u8; 32];

    keyring.register(KeyRole::Validator, val_pk, 0);
    keyring.register(KeyRole::Treasury, treasury_pk, 0);

    // Validator key can sign blocks but not mint.
    assert!(keyring
        .authorize(&val_pk, &AuthorizedAction::SignBlock, 10)
        .is_ok());
    assert!(keyring
        .authorize(&val_pk, &AuthorizedAction::AuthorizeMint, 10)
        .is_err());

    // Treasury key can mint but not sign blocks.
    assert!(keyring
        .authorize(&treasury_pk, &AuthorizedAction::AuthorizeMint, 10)
        .is_ok());
    assert!(keyring
        .authorize(&treasury_pk, &AuthorizedAction::SignBlock, 10)
        .is_err());
}

#[test]
fn test_custody_revoked_key_blocked() {
    use sccgub_crypto::roles::*;

    let mut keyring = OperatorKeyring::new();
    let pk = [1u8; 32];
    keyring.register(KeyRole::Validator, pk, 0);

    keyring.revoke(KeyRole::Validator).unwrap();
    assert!(
        keyring
            .authorize(&pk, &AuthorizedAction::SignBlock, 10)
            .is_err(),
        "Revoked key must be blocked"
    );
}

// === Snapshot roundtrip verification ===

#[test]
fn test_snapshot_roundtrip_preserves_state() {
    use sccgub_state::apply::apply_genesis_mint;
    use sccgub_state::balances::BalanceLedger;
    use sccgub_state::world::ManagedWorldState;
    use sccgub_types::transition::{StateDelta, StateWrite};

    let validator = [42u8; 32];

    // Build state with genesis + writes.
    let mut state = ManagedWorldState::new();
    let mut balances = BalanceLedger::new();
    apply_genesis_mint(&mut state, &mut balances, &validator);

    state.apply_delta(&StateDelta {
        writes: vec![
            StateWrite {
                address: b"doc/title".to_vec(),
                value: b"hello world".to_vec(),
            },
            StateWrite {
                address: b"doc/author".to_vec(),
                value: b"alice".to_vec(),
            },
        ],
        deletes: vec![],
    });
    state.set_height(5);

    let root_before = state.state_root();
    let supply_before = balances.total_supply();
    let entries_before = state.trie.len();

    // Export snapshot (simulate by collecting trie entries).
    let snapshot_entries: Vec<(Vec<u8>, Vec<u8>)> = state
        .trie
        .iter()
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    let snapshot_nonces: Vec<([u8; 32], u128)> =
        state.agent_nonces.iter().map(|(k, v)| (*k, *v)).collect();
    let snapshot_balances: Vec<([u8; 32], i128)> = balances
        .balances
        .iter()
        .map(|(k, v)| (*k, v.raw()))
        .collect();

    // Import into fresh state.
    let mut restored = ManagedWorldState::new();
    for (k, v) in &snapshot_entries {
        restored.trie.insert(k.clone(), v.clone());
    }
    for (agent, nonce) in &snapshot_nonces {
        restored.agent_nonces.insert(*agent, *nonce);
    }
    restored.set_height(5);

    let mut restored_bal = BalanceLedger::new();
    for (agent, raw) in &snapshot_balances {
        restored_bal.credit(agent, TensionValue(*raw));
    }

    // Verify: roots, supply, entry count must be identical.
    assert_eq!(
        restored.state_root(),
        root_before,
        "State root must survive snapshot roundtrip"
    );
    assert_eq!(
        restored_bal.total_supply(),
        supply_before,
        "Supply must survive snapshot roundtrip"
    );
    assert_eq!(
        restored.trie.len(),
        entries_before,
        "Entry count must match"
    );
}

#[test]
fn test_nonce_state_survives_replay() {
    use sccgub_state::world::ManagedWorldState;

    let mut state = ManagedWorldState::new();
    let agent = [1u8; 32];

    // Simulate nonce progression.
    for nonce in 1..=10u128 {
        assert!(state.check_nonce(&agent, nonce).is_ok());
    }

    // Nonce 10 should be the last committed.
    assert!(
        state.check_nonce(&agent, 10).is_err(),
        "Nonce 10 already used"
    );
    assert!(
        state.check_nonce(&agent, 11).is_ok(),
        "Nonce 11 should be valid"
    );
}

// === Nonce gap rejection test ===

#[test]
fn test_nonce_gap_rejected() {
    use sccgub_state::world::ManagedWorldState;

    let mut state = ManagedWorldState::new();
    let agent = [1u8; 32];

    // First nonce must be 1.
    assert!(state.check_nonce(&agent, 1).is_ok());

    // Next must be 2, not 5 (gap).
    assert!(
        state.check_nonce(&agent, 5).is_err(),
        "Nonce gap (1 -> 5) must be rejected"
    );

    // Correct next nonce.
    assert!(state.check_nonce(&agent, 2).is_ok());
    assert!(state.check_nonce(&agent, 3).is_ok());

    // Replay of used nonce rejected.
    assert!(state.check_nonce(&agent, 2).is_err());
}

// === Full chain lifecycle test ===

#[test]
fn test_chain_init_produce_verify_roundtrip() {
    use sccgub_state::apply::{apply_block_transitions, apply_genesis_mint, balances_from_trie};
    use sccgub_state::balances::BalanceLedger;
    use sccgub_state::world::ManagedWorldState;
    use sccgub_types::transition::{OperationPayload, StateDelta, StateWrite};

    let validator = [1u8; 32];

    // Phase 1: Init — genesis mint.
    let mut state = ManagedWorldState::new();
    let mut balances = BalanceLedger::new();
    apply_genesis_mint(&mut state, &mut balances, &validator);

    let genesis_supply = balances.total_supply();
    let genesis_root = state.state_root();
    assert!(genesis_supply.raw() > 0, "Genesis must mint supply");

    // Phase 2: Produce — apply some writes.
    let transitions = vec![];
    apply_block_transitions(&mut state, &mut balances, &transitions);

    // Supply unchanged with no transactions.
    assert_eq!(balances.total_supply(), genesis_supply);

    // Phase 3: State writes.
    state.apply_delta(&StateDelta {
        writes: vec![
            StateWrite {
                address: b"doc/1".to_vec(),
                value: b"hello".to_vec(),
            },
            StateWrite {
                address: b"doc/2".to_vec(),
                value: b"world".to_vec(),
            },
        ],
        deletes: vec![],
    });

    let post_write_root = state.state_root();
    assert_ne!(
        post_write_root, genesis_root,
        "Writes must change state root"
    );

    // Phase 4: Verify — replay from scratch produces identical root.
    let mut replay_state = ManagedWorldState::new();
    let mut replay_bal = BalanceLedger::new();
    apply_genesis_mint(&mut replay_state, &mut replay_bal, &validator);
    replay_state.apply_delta(&StateDelta {
        writes: vec![
            StateWrite {
                address: b"doc/1".to_vec(),
                value: b"hello".to_vec(),
            },
            StateWrite {
                address: b"doc/2".to_vec(),
                value: b"world".to_vec(),
            },
        ],
        deletes: vec![],
    });
    assert_eq!(
        replay_state.state_root(),
        post_write_root,
        "Replay must produce identical root"
    );

    // Phase 5: Export/Import — trie entries roundtrip.
    let exported: Vec<(Vec<u8>, Vec<u8>)> = state
        .trie
        .iter()
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();

    let mut imported_state = ManagedWorldState::new();
    for (k, v) in &exported {
        imported_state.trie.insert(k.clone(), v.clone());
    }
    assert_eq!(
        imported_state.state_root(),
        post_write_root,
        "Import must produce identical root"
    );

    // Phase 6: Balance reconstruction from trie.
    let recovered = balances_from_trie(&state).expect("balance trie should be well-formed");
    assert_eq!(
        recovered.total_supply(),
        genesis_supply,
        "Balance reconstruction must match"
    );
    assert_eq!(
        recovered.balance_of(&validator),
        balances.balance_of(&validator)
    );
}

// === Escrow condition spoofing test ===

#[test]
fn test_escrow_wrong_value_does_not_release() {
    use sccgub_state::balances::BalanceLedger;
    use sccgub_state::escrow::{EscrowCondition, EscrowRegistry};
    use sccgub_state::world::ManagedWorldState;

    let mut bal = BalanceLedger::new();
    let alice = [1u8; 32];
    let bob = [2u8; 32];
    bal.credit(&alice, TensionValue::from_integer(1000));

    let mut escrow = EscrowRegistry::new();
    let mut state = ManagedWorldState::new();

    escrow
        .create(
            alice,
            bob,
            TensionValue::from_integer(500),
            EscrowCondition::StateProof {
                key: b"delivery/proof".to_vec(),
                expected_value: b"confirmed".to_vec(),
                required_authority: None,
            },
            1,
            100,
            &mut bal,
        )
        .unwrap();

    // Write WRONG value to the key.
    state.apply_delta(&sccgub_types::transition::StateDelta {
        writes: vec![sccgub_types::transition::StateWrite {
            address: b"delivery/proof".to_vec(),
            value: b"WRONG_VALUE".to_vec(),
        }],
        deletes: vec![],
    });

    // Escrow must NOT release — value doesn't match.
    let released = escrow.check_and_release(&state, 50, &mut bal);
    assert!(
        released.is_empty(),
        "Escrow must not release on wrong value"
    );
    assert_eq!(
        bal.balance_of(&bob),
        TensionValue::ZERO,
        "Bob must not receive funds"
    );
}
