//! Full-pipeline integration tests.
//!
//! Exercises the complete system: chain lifecycle → treasury → escrow →
//! events → artifact types → delegation → snapshot.
//! These tests prove the modules work together, not just in isolation.

use sccgub_state::balances::BalanceLedger;
use sccgub_state::escrow::{EscrowCondition, EscrowRegistry};
use sccgub_state::treasury::Treasury;
use sccgub_types::artifact::{ArtifactKind, ArtifactRef, SchemaEntry, SchemaStatus, StorageScheme};
use sccgub_types::attestation::{ArtifactAttestation, AttestationKind};
use sccgub_types::delegation::{
    AutonomyBudget, CapabilityLease, CapabilityScope, MissionState, OperationType, SafetyMode,
};
use sccgub_types::dispute::{DisputeClaim, DisputeState};
use sccgub_types::events::{BlockEventLog, ChainEvent};
use sccgub_types::future::{AgentCircuitBreaker, CircuitBreakerState, SessionKey};
use sccgub_types::lineage::{LineageEdge, TransformType};
use sccgub_types::rights::{AccessGrant, ArtifactAction, PolicyVerdict, PolicyVerdictReceipt};
use sccgub_types::session::{EpochCommit, SessionCommit, SessionState};
use sccgub_types::tension::TensionValue;

// ============================================================================
// 1. Treasury → Escrow → Balance conservation pipeline
// ============================================================================

#[test]
fn test_treasury_escrow_balance_conservation_pipeline() {
    let mut balances = BalanceLedger::new();
    let mut treasury = Treasury::new();
    let mut escrow = EscrowRegistry::new();

    let alice = [1u8; 32];
    let bob = [2u8; 32];
    let validator = [3u8; 32];

    // Genesis: mint 10,000 to alice.
    balances.credit(&alice, TensionValue::from_integer(10_000));
    let total_supply = balances.total_supply();

    // Simulate 5 blocks of fees.
    for _ in 0..5 {
        let fee = TensionValue::from_integer(100);
        // Alice pays fee (debit from balance, credit to treasury).
        balances.debit(&alice, fee).unwrap();
        treasury.collect_fee(fee);
    }

    // Distribute reward to validator from treasury.
    let reward = treasury.distribute_reward(TensionValue::from_integer(200));
    balances.credit(&validator, reward);

    // Create escrow: alice → bob, 1000 tokens.
    let escrow_id = escrow
        .create(
            alice,
            bob,
            TensionValue::from_integer(1000),
            EscrowCondition::TimeLocked { release_at: 100 },
            1,
            200,
            &mut balances,
        )
        .unwrap();

    // INVARIANT: total_supply = balances + escrow_locked + treasury_pending.
    let accounted = TensionValue(
        balances.total_supply().raw() + escrow.total_locked().raw() + treasury.pending_fees.raw(),
    );
    assert_eq!(
        accounted, total_supply,
        "Conservation: balances + escrow + treasury must equal total supply"
    );

    // Release escrow.
    escrow.release(&escrow_id, &mut balances).unwrap();

    // After release: escrow_locked = 0, balance supply includes bob's funds.
    let accounted_after = TensionValue(
        balances.total_supply().raw() + escrow.total_locked().raw() + treasury.pending_fees.raw(),
    );
    assert_eq!(accounted_after, total_supply);
}

// ============================================================================
// 2. Artifact → Attestation → Lineage → Rights → Dispute pipeline
// ============================================================================

#[test]
fn test_artifact_provenance_pipeline() {
    // Phase 1: Register artifact.
    let artifact = ArtifactRef {
        artifact_id: [10u8; 32],
        kind: ArtifactKind::CaptureSession,
        schema_name: "vrc-media-core".into(),
        schema_version: "1.1".into(),
        content_hash: [11u8; 32],
        manifest_hash: [12u8; 32],
        signature_hash: Some([13u8; 32]),
        storage_scheme: StorageScheme::Vrc,
        locator: "s3://bucket/capture.vrc".into(),
        byte_length: 500_000,
        created_by: [1u8; 32],
        created_at_block: 100,
    };
    assert!(artifact.validate().is_ok());

    // Phase 2: Attest capture.
    let attestation = ArtifactAttestation {
        attestation_id: [20u8; 32],
        kind: AttestationKind::Capture,
        artifact_id: artifact.artifact_id,
        subject: [1u8; 32],   // Operator.
        authority: [2u8; 32], // Device authority.
        software_version: "virecai-capture/2.0".into(),
        environment_hash: Some([21u8; 32]),
        claims_hash: [22u8; 32],
        valid_from_block: 100,
        valid_to_block: Some(500),
        signature: vec![0u8; 64],
    };
    assert!(attestation.validate().is_ok());

    // Phase 3: Derive a reconstruction output.
    let derived_artifact = ArtifactRef {
        artifact_id: [30u8; 32],
        kind: ArtifactKind::ReconstructionOutput,
        schema_name: "reconstruction-v1".into(),
        schema_version: "1.0".into(),
        content_hash: [31u8; 32],
        manifest_hash: [32u8; 32],
        signature_hash: None,
        storage_scheme: StorageScheme::ObjectStore,
        locator: "s3://bucket/reconstruction.bin".into(),
        byte_length: 2_000_000,
        created_by: [3u8; 32],
        created_at_block: 150,
    };
    assert!(derived_artifact.validate().is_ok());

    // Phase 4: Record lineage edge.
    let edge = LineageEdge {
        edge_id: [40u8; 32],
        parent: artifact.artifact_id,
        child: derived_artifact.artifact_id,
        transform: TransformType::Reconstruct,
        actor: [3u8; 32],
        proof_hash: Some([41u8; 32]),
        created_at_block: 150,
    };
    assert!(edge.validate().is_ok());

    // Phase 5: Grant access.
    let grant = AccessGrant {
        grant_id: [50u8; 32],
        artifact_id: derived_artifact.artifact_id,
        grantee: [4u8; 32],
        actions: vec![ArtifactAction::View, ArtifactAction::Export],
        purpose_hash: Some([51u8; 32]),
        valid_from_block: 150,
        valid_to_block: Some(1000),
        revocable: true,
        revoked: false,
        granted_by: [3u8; 32],
    };
    assert!(grant.validate().is_ok());
    assert!(grant.is_active(200));

    // Phase 6: Policy verdict.
    let verdict = PolicyVerdictReceipt {
        receipt_id: [60u8; 32],
        artifact_id: derived_artifact.artifact_id,
        verdict: PolicyVerdict::Allow,
        policy_set_id: [61u8; 32],
        reason_codes: vec!["compliant".into()],
        evidence_root: [62u8; 32],
        issued_by: [5u8; 32],
        supersedes: None,
        block_height: 160,
        signature: vec![0u8; 64],
    };
    assert!(verdict.validate().is_ok());

    // Phase 7: Dispute the derived artifact.
    let dispute = DisputeClaim {
        dispute_id: [70u8; 32],
        target_artifact: derived_artifact.artifact_id,
        claimant: [6u8; 32],
        reason_code: "unauthorized_reconstruction".into(),
        evidence_hash: [71u8; 32],
        filed_at_block: 200,
        state: DisputeState::Open,
        challenge_window_end: 300,
    };
    assert!(dispute.validate().is_ok());
    assert!(dispute.is_open());
}

// ============================================================================
// 3. Session → Epoch → Checkpoint pipeline
// ============================================================================

#[test]
fn test_session_epoch_pipeline() {
    let mut session = SessionCommit {
        session_id: [80u8; 32],
        root_artifact: [81u8; 32],
        state: SessionState::Open,
        start_block: 100,
        end_block: None,
        latest_epoch: 0,
        latest_commitment_root: [0u8; 32],
    };
    assert!(session.validate().is_ok());

    // Commit 3 epochs.
    for i in 1..=3u64 {
        let epoch = EpochCommit {
            epoch_id: [80 + i as u8; 32],
            session_id: session.session_id,
            epoch_index: i,
            artifact_root: [90 + i as u8; 32],
            lineage_root: [100 + i as u8; 32],
            policy_root: [110 + i as u8; 32],
            event_count: i * 100,
            closed_at_block: 100 + i * 10,
        };
        assert!(epoch.validate(session.latest_epoch).is_ok());
        session.latest_epoch = i;
        session.latest_commitment_root = epoch.artifact_root;
    }

    // Close session.
    session.state = SessionState::Closed;
    session.end_block = Some(200);
    assert_eq!(session.latest_epoch, 3);
}

// ============================================================================
// 4. Delegation → Autonomy → Circuit Breaker pipeline
// ============================================================================

#[test]
fn test_delegation_autonomy_circuit_breaker_pipeline() {
    let robot_id = [7u8; 32];
    let operator_id = [8u8; 32];

    // Phase 1: Create capability lease.
    let mut lease = CapabilityLease {
        lease_id: [90u8; 32],
        delegator: operator_id,
        delegate: robot_id,
        scope: CapabilityScope {
            write_prefixes: vec![b"robot/zone-a/".to_vec()],
            read_prefixes: vec![b"sensor/".to_vec()],
            allowed_operations: vec![OperationType::StateWrite, OperationType::EvidenceCommit],
            zone_constraints: vec![b"zone-a".to_vec()],
        },
        valid_from: 100,
        valid_until: 500,
        budget: TensionValue::from_integer(5000),
        spent: TensionValue::ZERO,
        max_actions: 100,
        actions_taken: 0,
        revoked: false,
        require_cosign: false,
    };

    assert!(lease.is_valid(200));
    assert!(lease.allows_write(b"robot/zone-a/data"));
    assert!(!lease.allows_write(b"robot/zone-b/data")); // Out of scope.
    assert!(lease.allows_operation(OperationType::StateWrite));
    assert!(!lease.allows_operation(OperationType::AssetTransfer)); // Not allowed.

    // Phase 2: Robot acts within budget.
    assert!(lease
        .record_spend(200, TensionValue::from_integer(100))
        .is_ok());
    assert_eq!(lease.actions_taken, 1);

    // Phase 3: Autonomy budget for off-chain decisions.
    let mut autonomy = AutonomyBudget {
        agent_id: robot_id,
        max_unconfirmed_spend: TensionValue::from_integer(500),
        max_unconfirmed_actions: 10,
        pending_spend: TensionValue::ZERO,
        pending_actions: 0,
        last_settled_height: 200,
    };

    // Robot acts locally without chain confirmation.
    autonomy
        .record_local_action(TensionValue::from_integer(100))
        .unwrap();
    autonomy
        .record_local_action(TensionValue::from_integer(200))
        .unwrap();
    assert!(autonomy.can_act_locally(TensionValue::from_integer(100)));
    assert!(!autonomy.can_act_locally(TensionValue::from_integer(300))); // Would exceed.

    // Settle on-chain.
    autonomy.settle(250);
    assert_eq!(autonomy.pending_spend, TensionValue::ZERO);

    // Phase 4: Circuit breaker detects anomaly.
    let mut breaker = AgentCircuitBreaker {
        agent_id: robot_id,
        state: CircuitBreakerState::Closed,
        failure_threshold: 3,
        failure_count: 0,
        max_spend_rate: TensionValue::from_integer(1000),
        current_block_spend: TensionValue::ZERO,
        cooldown_blocks: 10,
        test_blocks: 3,
    };

    // Normal operation.
    assert!(breaker.can_act());
    breaker.record_success();

    // Anomaly: 3 consecutive failures.
    breaker.record_failure(300);
    breaker.record_failure(300);
    breaker.record_failure(300);
    assert!(!breaker.can_act()); // Tripped.

    // Recovery after cooldown.
    breaker.try_recover(310);
    assert!(breaker.can_act()); // Half-open.

    // Successful tests → fully recovered.
    breaker.record_success();
    breaker.record_success();
    breaker.record_success();
    assert!(matches!(breaker.state, CircuitBreakerState::Closed));
}

// ============================================================================
// 5. Safety mode pipeline
// ============================================================================

#[test]
fn test_safety_mode_enforcement() {
    // Normal mode — full capabilities.
    assert!(SafetyMode::Normal.can_write());
    assert!(SafetyMode::Normal.can_spend());
    assert!(SafetyMode::Normal.commits_state());
    assert!(!SafetyMode::Normal.requires_operator());

    // ReadOnly — observe only.
    assert!(!SafetyMode::ReadOnly.can_write());
    assert!(!SafetyMode::ReadOnly.can_spend());

    // NoSpend — write but no transfers.
    assert!(SafetyMode::NoSpend.can_write());
    assert!(!SafetyMode::NoSpend.can_spend());

    // Shadow — recorded but not committed.
    assert!(!SafetyMode::Shadow.commits_state());

    // OperatorOnly — requires human co-sign.
    assert!(SafetyMode::OperatorOnly.requires_operator());

    // Quarantine — nothing permitted.
    assert!(!SafetyMode::Quarantine.can_write());
    assert!(!SafetyMode::Quarantine.can_spend());
    assert!(!SafetyMode::Quarantine.commits_state());
}

// ============================================================================
// 6. Event log pipeline
// ============================================================================

#[test]
fn test_event_log_multi_type() {
    let mut log = BlockEventLog::new();

    // Emit diverse events.
    log.emit(ChainEvent::StateWrite {
        tx_id: [1u8; 32],
        key: b"doc/1".to_vec(),
        actor: [2u8; 32],
    });
    log.emit(ChainEvent::Transfer {
        tx_id: [3u8; 32],
        from: [4u8; 32],
        to: [5u8; 32],
        amount: TensionValue::from_integer(500),
        purpose: "payment".into(),
    });
    log.emit(ChainEvent::FeeCharged {
        tx_id: [0u8; 32],
        payer: [4u8; 32],
        amount: TensionValue::from_integer(10),
        gas_used: 5000,
    });
    log.emit(ChainEvent::ArtifactRegistered {
        artifact_id: [10u8; 32],
        created_by: [1u8; 32],
        content_hash: [11u8; 32],
        schema_name: "vrc-v1".into(),
    });
    log.emit(ChainEvent::DisputeLifecycle {
        dispute_id: [20u8; 32],
        target_artifact: [10u8; 32],
        action: "filed".into(),
        block_height: 100,
    });

    assert_eq!(log.event_count(), 5);
    assert_eq!(log.transfers().len(), 1);
    assert_eq!(log.fees().len(), 1);
}

// ============================================================================
// 7. Schema registry pipeline
// ============================================================================

#[test]
fn test_schema_lifecycle() {
    let schema = SchemaEntry {
        schema_name: "vrc-media-core".into(),
        schema_version: "1.1".into(),
        spec_hash: [1u8; 32],
        status: SchemaStatus::Active,
        compatibility_parent: Some(("vrc-media-core".into(), "1.0".into())),
        registered_at_block: 50,
    };
    assert!(schema.validate().is_ok());

    // Deprecate.
    let mut deprecated = schema.clone();
    deprecated.status = SchemaStatus::Deprecated;
    assert!(deprecated.validate().is_ok());

    // New version.
    let v2 = SchemaEntry {
        schema_name: "vrc-media-core".into(),
        schema_version: "2.0".into(),
        spec_hash: [2u8; 32],
        status: SchemaStatus::Active,
        compatibility_parent: Some(("vrc-media-core".into(), "1.1".into())),
        registered_at_block: 200,
    };
    assert!(v2.validate().is_ok());
}

// ============================================================================
// 8. Mission state machine pipeline
// ============================================================================

#[test]
fn test_mission_lifecycle_complete() {
    // Full happy path.
    assert!(MissionState::Proposed.can_transition_to(MissionState::Accepted));
    assert!(MissionState::Accepted.can_transition_to(MissionState::Executing));
    assert!(MissionState::Executing.can_transition_to(MissionState::Completed));
    assert!(MissionState::Completed.can_transition_to(MissionState::Settled));

    // Degraded path.
    assert!(MissionState::Executing.can_transition_to(MissionState::Degraded));
    assert!(MissionState::Degraded.can_transition_to(MissionState::Recovered));
    assert!(MissionState::Recovered.can_transition_to(MissionState::Executing));

    // Dispute path.
    assert!(MissionState::Completed.can_transition_to(MissionState::Disputed));
    assert!(MissionState::Disputed.can_transition_to(MissionState::Settled));

    // Cancellation path.
    assert!(MissionState::Proposed.can_transition_to(MissionState::Cancelled));
    assert!(MissionState::Paused.can_transition_to(MissionState::Cancelled));

    // Invalid transitions (terminal states).
    assert!(!MissionState::Settled.can_transition_to(MissionState::Executing));
    assert!(!MissionState::Cancelled.can_transition_to(MissionState::Accepted));
}

// ============================================================================
// 9. Session key + spend tracking pipeline
// ============================================================================

#[test]
fn test_session_key_full_lifecycle() {
    let mut sk = SessionKey {
        session_id: [1u8; 32],
        master_account: [2u8; 32],
        session_public_key: [3u8; 32],
        allowed_operations: vec!["transfer".into(), "write".into()],
        max_spend_per_tx: TensionValue::from_integer(100),
        max_total_spend: TensionValue::from_integer(500),
        spent: TensionValue::ZERO,
        max_transactions: 10,
        transactions_used: 0,
        expires_at_block: 1000,
        revoked: false,
    };

    // Valid and can spend.
    assert!(sk.is_valid(100));
    assert!(sk.can_spend(TensionValue::from_integer(50)));

    // Use 5 times.
    for _ in 0..5 {
        assert!(sk.record_use(TensionValue::from_integer(80)).is_ok());
    }
    assert_eq!(sk.transactions_used, 5);
    assert_eq!(sk.spent, TensionValue::from_integer(400));

    // 6th use would exceed total budget.
    assert!(sk.record_use(TensionValue::from_integer(200)).is_err());

    // Revoke.
    sk.revoked = true;
    assert!(!sk.is_valid(500));
}
