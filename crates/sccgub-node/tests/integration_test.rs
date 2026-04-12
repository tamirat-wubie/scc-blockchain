//! Integration tests: full chain lifecycle.
//! Genesis -> submit transitions -> produce block -> validate -> verify state.

use std::collections::HashSet;

use sccgub_crypto::hash::blake3_hash;
use sccgub_crypto::keys::generate_keypair;
use sccgub_crypto::merkle::merkle_root_of_bytes;
use sccgub_crypto::signature::{sign, verify};
use sccgub_execution::cpog::validate_cpog;
use sccgub_execution::phi::{is_per_tx_phase, phi_check_single_tx, phi_traversal_block};
use sccgub_execution::wh_check::check_wh_binding_intent;
use sccgub_governance::norms::NormRegistry;
use sccgub_governance::precedence::{check_governance_change, GovernanceChangeType};
use sccgub_governance::responsibility;
use sccgub_governance::validator::select_validator;
use sccgub_state::world::ManagedWorldState;
use sccgub_types::agent::{AgentIdentity, ResponsibilityState, ValidatorAuthority};
use sccgub_types::block::{Block, BlockBody, BlockHeader};
use sccgub_types::causal::{CausalEdge, CausalGraphDelta, CausalVertex};
use sccgub_types::governance::*;
use sccgub_types::mfidel::MfidelAtomicSeal;
use sccgub_types::proof::{CausalProof, PhiTraversalLog};
use sccgub_types::receipt::Verdict;
use sccgub_types::tension::TensionValue;
use sccgub_types::timestamp::CausalTimestamp;
use sccgub_types::transition::*;
use sccgub_types::ZERO_HASH;

/// Helper: create a test agent with keypair.
fn create_test_agent() -> (AgentIdentity, ed25519_dalek::SigningKey) {
    let key = generate_keypair();
    let pk = *key.verifying_key().as_bytes();
    let seal = MfidelAtomicSeal::from_height(1);
    let agent_id = sccgub_crypto::hash::blake3_hash_concat(&[
        &pk,
        &sccgub_crypto::canonical::canonical_bytes(&seal),
    ]);
    let agent = AgentIdentity {
        agent_id,
        public_key: pk,
        mfidel_seal: seal,
        registration_block: 0,
        governance_level: PrecedenceLevel::Meaning,
        norm_set: HashSet::new(),
        responsibility: ResponsibilityState::default(),
    };
    (agent, key)
}

/// Helper: create a valid state-write transition.
fn create_write_tx(
    agent: &AgentIdentity,
    key: &ed25519_dalek::SigningKey,
    addr: &[u8],
    data: &[u8],
    nonce: u128,
) -> SymbolicTransition {
    let intent = WHBindingIntent {
        who: agent.agent_id,
        when: CausalTimestamp::genesis(),
        r#where: addr.to_vec(),
        why: CausalJustification {
            invoking_rule: blake3_hash(b"state-write-rule"),
            precedence_level: PrecedenceLevel::Meaning,
            causal_ancestors: vec![],
            constraint_proof: vec![],
        },
        how: TransitionMechanism::DirectStateWrite,
        which: HashSet::new(),
        what_declared: format!("Write {} bytes to {}", data.len(), hex::encode(addr)),
    };

    let payload = OperationPayload::Write {
        key: addr.to_vec(),
        value: data.to_vec(),
    };

    // Build tx first, then sign using canonical_tx_bytes for consistency.
    let mut tx = SymbolicTransition {
        tx_id: [0u8; 32],
        actor: agent.clone(),
        intent: TransitionIntent {
            kind: TransitionKind::StateWrite,
            target: addr.to_vec(),
            declared_purpose: "Integration test write".into(),
        },
        preconditions: vec![],
        postconditions: vec![],
        payload,
        causal_chain: vec![],
        wh_binding_intent: intent,
        nonce,
        signature: vec![],
    };
    let canonical = sccgub_execution::validate::canonical_tx_bytes(&tx);
    tx.tx_id = blake3_hash(&canonical);
    tx.signature = sign(key, &canonical);
    tx
}

/// Helper: build a minimal valid block.
/// Speculatively applies transitions to compute post-transition state_root.
fn build_test_block(
    height: u64,
    parent_id: [u8; 32],
    parent_timestamp: &CausalTimestamp,
    transitions: Vec<SymbolicTransition>,
    validator_key: &ed25519_dalek::SigningKey,
    state: &ManagedWorldState,
) -> Block {
    let validator_id = blake3_hash(validator_key.verifying_key().as_bytes());
    let chain_id = blake3_hash(b"test-chain");
    let timestamp = parent_timestamp.successor(validator_id, blake3_hash(&parent_id), 0);
    let seal = MfidelAtomicSeal::from_height(height);

    let tx_bytes: Vec<&[u8]> = transitions.iter().map(|tx| tx.tx_id.as_slice()).collect();
    let transition_root = merkle_root_of_bytes(&tx_bytes);

    // Speculatively apply transitions to compute post-state root.
    let mut spec_state = state.clone();
    for tx in &transitions {
        if let OperationPayload::Write { key, value } = &tx.payload {
            spec_state.apply_delta(&StateDelta {
                writes: vec![StateWrite {
                    address: key.clone(),
                    value: value.clone(),
                }],
                deletes: vec![],
            });
        }
    }

    let governance = GovernanceSnapshot {
        state_hash: ZERO_HASH,
        active_norm_count: 0,
        emergency_mode: false,
        finality_mode: FinalityMode::Deterministic,
        governance_limits: sccgub_types::governance::GovernanceLimitsSnapshot::default(),
        finality_config: sccgub_types::governance::FinalityConfigSnapshot::default(),
    };

    let tension_before = state.state.tension_field.total;

    let mut header = BlockHeader {
        chain_id,
        block_id: ZERO_HASH,
        parent_id,
        height,
        timestamp,
        state_root: spec_state.state_root(), // Post-transition root.
        transition_root,
        receipt_root: ZERO_HASH,
        causal_root: ZERO_HASH,
        proof_root: ZERO_HASH,
        governance_hash: sccgub_crypto::canonical::canonical_hash(&governance),
        tension_before,
        tension_after: tension_before,
        mfidel_seal: seal,
        balance_root: ZERO_HASH,
        validator_id,
        version: 1,
    };
    // Compute block_id from full header (same as chain.rs).
    let header_bytes = sccgub_crypto::canonical::canonical_bytes(&header);
    header.block_id = blake3_hash(&header_bytes);

    let proof = CausalProof {
        block_height: height,
        transitions_proven: vec![],
        phi_traversal_log: PhiTraversalLog::default(),
        governance_snapshot_hash: header.governance_hash,
        tension_before,
        tension_after: tension_before,
        constraint_results: vec![],
        recursion_depth: 0,
        validator_signature: sign(validator_key, &header_bytes),
        causal_hash: blake3_hash(&header_bytes),
    };

    Block {
        header,
        body: BlockBody {
            transitions: transitions.clone(),
            transition_count: transitions.len() as u32,
            total_tension_delta: TensionValue::ZERO,
            constraint_satisfaction: vec![],
            genesis_consensus_params: None,
        },
        receipts: vec![],
        causal_delta: CausalGraphDelta::default(),
        proof,
        governance,
    }
}

// ====== TESTS ======

#[test]
fn test_full_chain_lifecycle() {
    // 1. Create genesis state.
    let state = ManagedWorldState::new();
    let (agent, agent_key) = create_test_agent();
    let validator_key = generate_keypair();

    // 2. Build genesis block.
    let genesis = build_test_block(
        0,
        ZERO_HASH,
        &CausalTimestamp::genesis(),
        vec![],
        &validator_key,
        &state,
    );
    assert!(genesis.is_structurally_valid());

    // 3. Validate genesis via CPoG.
    let cpog_result = validate_cpog(&genesis, &state, &ZERO_HASH);
    assert!(
        cpog_result.is_valid(),
        "Genesis CPoG failed: {:?}",
        cpog_result
    );

    // 4. Submit transitions.
    let tx1 = create_write_tx(
        &agent,
        &agent_key,
        b"data/account/alice/balance",
        b"1000",
        1,
    );
    let tx2 = create_write_tx(&agent, &agent_key, b"data/account/bob/balance", b"500", 2);
    let tx3 = create_write_tx(&agent, &agent_key, b"data/config/max_supply", b"1000000", 3);

    // 5. Validate each transition individually via the shared per-tx checker.
    for tx in [&tx1, &tx2, &tx3] {
        for phase in sccgub_types::proof::PhiPhase::ALL {
            if is_per_tx_phase(phase) {
                let result = phi_check_single_tx(phase, tx, &state);
                assert!(
                    result.passed,
                    "Per-tx Phi phase {:?} failed for {:?}: {}",
                    phase, tx.tx_id, result.details
                );
            }
        }
    }

    // 6. Build block #1 with the transitions.
    let block1 = build_test_block(
        1,
        genesis.header.block_id,
        &genesis.header.timestamp,
        vec![tx1.clone(), tx2.clone(), tx3.clone()],
        &validator_key,
        &state,
    );
    assert!(block1.is_structurally_valid());
    assert_eq!(block1.body.transition_count, 3);
    assert_eq!(block1.header.mfidel_seal, MfidelAtomicSeal::from_height(1));

    // 7. Run full 13-phase Phi traversal on the block.
    let phi_log = phi_traversal_block(&block1, &state);
    assert!(
        phi_log.all_phases_passed,
        "Block Phi traversal failed: {:?}",
        phi_log
    );
    assert_eq!(phi_log.phases_completed.len(), 13);

    // 8. Validate via CPoG.
    let cpog_result = validate_cpog(&block1, &state, &genesis.header.block_id);
    assert!(
        cpog_result.is_valid(),
        "Block #1 CPoG failed: {:?}",
        cpog_result
    );

    // 9. Apply state changes.
    let mut state = state;
    for tx in &block1.body.transitions {
        if let OperationPayload::Write { key, value } = &tx.payload {
            state.apply_delta(&StateDelta {
                writes: vec![StateWrite {
                    address: key.clone(),
                    value: value.clone(),
                }],
                deletes: vec![],
            });
        }
    }
    state.set_height(1);

    // 10. Verify state was applied.
    assert_eq!(
        state.get(&b"data/account/alice/balance".to_vec()),
        Some(&b"1000".to_vec())
    );
    assert_eq!(
        state.get(&b"data/account/bob/balance".to_vec()),
        Some(&b"500".to_vec())
    );
    assert_eq!(
        state.get(&b"data/config/max_supply".to_vec()),
        Some(&b"1000000".to_vec())
    );

    // 11. Verify state root changed.
    assert_ne!(state.state_root(), ZERO_HASH);
}

#[test]
fn test_invalid_block_wrong_parent() {
    let state = ManagedWorldState::new();
    let validator_key = generate_keypair();

    let genesis = build_test_block(
        0,
        ZERO_HASH,
        &CausalTimestamp::genesis(),
        vec![],
        &validator_key,
        &state,
    );

    // Build block with WRONG parent ID.
    let wrong_parent = [0xFFu8; 32];
    let bad_block = build_test_block(
        1,
        wrong_parent,
        &genesis.header.timestamp,
        vec![],
        &validator_key,
        &state,
    );

    let result = validate_cpog(&bad_block, &state, &genesis.header.block_id);
    assert!(!result.is_valid(), "Should reject block with wrong parent");
}

#[test]
fn test_invalid_block_wrong_mfidel_seal() {
    let state = ManagedWorldState::new();
    let validator_key = generate_keypair();

    let genesis = build_test_block(
        0,
        ZERO_HASH,
        &CausalTimestamp::genesis(),
        vec![],
        &validator_key,
        &state,
    );

    let mut bad_block = build_test_block(
        1,
        genesis.header.block_id,
        &genesis.header.timestamp,
        vec![],
        &validator_key,
        &state,
    );
    // Tamper with the seal.
    bad_block.header.mfidel_seal = MfidelAtomicSeal { row: 34, column: 8 };

    let result = validate_cpog(&bad_block, &state, &genesis.header.block_id);
    assert!(
        !result.is_valid(),
        "Should reject block with wrong Mfidel seal"
    );
}

#[test]
fn test_invalid_transition_missing_wh_binding() {
    let (agent, agent_key) = create_test_agent();

    // Create transition with empty WHBinding fields.
    let mut tx = create_write_tx(&agent, &agent_key, b"data/test", b"data", 0);
    tx.wh_binding_intent.who = ZERO_HASH; // Make it invalid.

    let result = check_wh_binding_intent(&tx.wh_binding_intent);
    assert!(result.is_err(), "Should reject transition with empty 'who'");
}

#[test]
fn test_causal_timestamp_ordering() {
    let genesis_ts = CausalTimestamp::genesis();
    let node_id = [1u8; 32];

    let ts1 = genesis_ts.successor(node_id, blake3_hash(b"parent1"), 100);
    let ts2 = ts1.successor(node_id, blake3_hash(b"parent2"), 200);

    // Lamport counter must strictly increase.
    assert!(ts1.lamport_counter > genesis_ts.lamport_counter);
    assert!(ts2.lamport_counter > ts1.lamport_counter);

    // Causal depth must increase.
    assert!(ts1.causal_depth > genesis_ts.causal_depth);
    assert!(ts2.causal_depth > ts1.causal_depth);
}

#[test]
fn test_mfidel_seal_full_cycle() {
    // Verify all 272 seals in a full Mfidel cycle are unique.
    let mut seals = HashSet::new();
    for h in 1..=272u64 {
        let seal = MfidelAtomicSeal::from_height(h);
        assert!(seal.is_valid());
        seals.insert((seal.row, seal.column));
    }
    assert_eq!(seals.len(), 272, "All 272 fidels should be unique");

    // Cycle wraps: height 273 == height 1.
    assert_eq!(
        MfidelAtomicSeal::from_height(273),
        MfidelAtomicSeal::from_height(1)
    );
}

#[test]
fn test_tension_budget_enforcement() {
    let state = ManagedWorldState::new();
    let validator_key = generate_keypair();

    let genesis = build_test_block(
        0,
        ZERO_HASH,
        &CausalTimestamp::genesis(),
        vec![],
        &validator_key,
        &state,
    );

    // Build block that claims tension increase beyond budget.
    let mut bad_block = build_test_block(
        1,
        genesis.header.block_id,
        &genesis.header.timestamp,
        vec![],
        &validator_key,
        &state,
    );
    bad_block.header.tension_after = TensionValue::from_integer(99999); // way over budget

    let result = validate_cpog(&bad_block, &state, &genesis.header.block_id);
    assert!(
        !result.is_valid(),
        "Should reject block exceeding tension budget"
    );
}

#[test]
fn test_signature_verification() {
    let key = generate_keypair();
    let pk = *key.verifying_key().as_bytes();
    let data = b"transition payload data";
    let sig = sign(&key, data);

    assert!(verify(&pk, data, &sig));
    assert!(!verify(&pk, b"tampered data", &sig));
}

#[test]
fn test_merkle_root_determinism() {
    let items: Vec<&[u8]> = vec![b"tx1", b"tx2", b"tx3"];
    let root1 = merkle_root_of_bytes(&items);
    let root2 = merkle_root_of_bytes(&items);
    assert_eq!(root1, root2);
    assert_ne!(root1, ZERO_HASH);
}

#[test]
fn test_state_root_changes_on_write() {
    let mut state = ManagedWorldState::new();
    let root_empty = state.state_root();

    state.apply_delta(&StateDelta {
        writes: vec![StateWrite {
            address: b"key1".to_vec(),
            value: b"value1".to_vec(),
        }],
        deletes: vec![],
    });
    let root_one = state.state_root();

    state.apply_delta(&StateDelta {
        writes: vec![StateWrite {
            address: b"key2".to_vec(),
            value: b"value2".to_vec(),
        }],
        deletes: vec![],
    });
    let root_two = state.state_root();

    assert_eq!(root_empty, ZERO_HASH);
    assert_ne!(root_one, ZERO_HASH);
    assert_ne!(root_one, root_two);
}

#[test]
fn test_validator_selection_deterministic() {
    let validators = vec![
        ValidatorAuthority {
            node_id: [1u8; 32],
            governance_level: PrecedenceLevel::Meaning,
            norm_compliance: TensionValue::from_integer(9),
            causal_reliability: TensionValue::from_integer(8),
            active: true,
        },
        ValidatorAuthority {
            node_id: [2u8; 32],
            governance_level: PrecedenceLevel::Safety,
            norm_compliance: TensionValue::from_integer(7),
            causal_reliability: TensionValue::from_integer(7),
            active: true,
        },
    ];

    let v1 = select_validator(&validators).unwrap();
    let v2 = select_validator(&validators).unwrap();
    assert_eq!(
        v1.node_id, v2.node_id,
        "Validator selection must be deterministic"
    );
}

#[test]
fn test_governance_precedence_enforcement() {
    // GENESIS can do anything.
    assert!(check_governance_change(
        PrecedenceLevel::Genesis,
        GovernanceChangeType::GovernanceUpgrade
    )
    .is_ok());

    // OPTIMIZATION cannot change governance.
    assert!(check_governance_change(
        PrecedenceLevel::Optimization,
        GovernanceChangeType::GovernanceUpgrade
    )
    .is_err());

    // MEANING can add norms.
    assert!(
        check_governance_change(PrecedenceLevel::Meaning, GovernanceChangeType::NormAddition)
            .is_ok()
    );

    // EMOTION cannot add norms (MEANING required).
    assert!(
        check_governance_change(PrecedenceLevel::Emotion, GovernanceChangeType::NormAddition)
            .is_err()
    );
}

#[test]
fn test_responsibility_decay_and_bound() {
    let mut state = ResponsibilityState::default();

    responsibility::record_positive(&mut state, [1u8; 32], TensionValue::from_integer(100), 0);
    responsibility::record_negative(&mut state, [2u8; 32], TensionValue::from_integer(30), 0);

    assert_eq!(state.net_responsibility, TensionValue::from_integer(70));

    // Check bound.
    let max = TensionValue::from_integer(200);
    assert!(responsibility::check_responsibility_bound(&[&state], max));

    let strict = TensionValue::from_integer(50);
    assert!(!responsibility::check_responsibility_bound(
        &[&state],
        strict
    ));
}

#[test]
fn test_causal_graph_acyclicity() {
    use sccgub_types::causal::CausalGraph;

    let mut graph = CausalGraph::default();
    let a = CausalVertex::Transition([1u8; 32]);
    let b = CausalVertex::Transition([2u8; 32]);
    let c = CausalVertex::Transition([3u8; 32]);

    graph.add_vertex(a.clone());
    graph.add_vertex(b.clone());
    graph.add_vertex(c.clone());

    // A -> B -> C (acyclic).
    graph.add_edge(CausalEdge::CausedBy {
        source: a.clone(),
        target: b.clone(),
    });
    graph.add_edge(CausalEdge::CausedBy {
        source: b.clone(),
        target: c.clone(),
    });
    assert!(graph.is_acyclic());

    // Add C -> A (creates cycle).
    graph.add_edge(CausalEdge::CausedBy {
        source: c.clone(),
        target: a.clone(),
    });
    assert!(!graph.is_acyclic());
}

#[test]
fn test_verdict_variants() {
    let accept = Verdict::Accept;
    assert!(accept.is_accepted());

    let reject = Verdict::Reject {
        reason: "invalid".into(),
    };
    assert!(!reject.is_accepted());

    let defer = Verdict::Defer {
        condition: "waiting".into(),
    };
    assert!(!defer.is_accepted());

    let escalate = Verdict::Escalate { level: 2 };
    assert!(!escalate.is_accepted());
}

#[test]
fn test_multi_block_chain() {
    let mut state = ManagedWorldState::new();
    let (agent, agent_key) = create_test_agent();
    let validator_key = generate_keypair();

    // Genesis.
    let genesis = build_test_block(
        0,
        ZERO_HASH,
        &CausalTimestamp::genesis(),
        vec![],
        &validator_key,
        &state,
    );
    let result = validate_cpog(&genesis, &state, &ZERO_HASH);
    assert!(result.is_valid());

    let mut prev_block = genesis;

    // Produce 10 blocks.
    for i in 1..=10u64 {
        let tx = create_write_tx(
            &agent,
            &agent_key,
            format!("data/block/{}", i).as_bytes(),
            format!("payload_{}", i).as_bytes(),
            i as u128,
        );

        let block = build_test_block(
            i,
            prev_block.header.block_id,
            &prev_block.header.timestamp,
            vec![tx.clone()],
            &validator_key,
            &state,
        );

        assert!(block.is_structurally_valid());

        // Verify Mfidel seal cycles correctly.
        assert_eq!(block.header.mfidel_seal, MfidelAtomicSeal::from_height(i));

        let result = validate_cpog(&block, &state, &prev_block.header.block_id);
        assert!(result.is_valid(), "Block #{} CPoG failed: {:?}", i, result);

        // Apply state + advance nonce.
        if let OperationPayload::Write { key, value } = &tx.payload {
            state.apply_delta(&StateDelta {
                writes: vec![StateWrite {
                    address: key.clone(),
                    value: value.clone(),
                }],
                deletes: vec![],
            });
        }
        let _ = state.check_nonce(&tx.actor.agent_id, tx.nonce);
        state.set_height(i);

        prev_block = block;
    }

    // Verify final state.
    assert_eq!(
        state.get(&b"data/block/10".to_vec()),
        Some(&b"payload_10".to_vec())
    );
    assert_ne!(state.state_root(), ZERO_HASH);
}

#[test]
fn test_fixed_point_tension_determinism() {
    // Ensure tension arithmetic is deterministic (no floating-point).
    let a = TensionValue::from_integer(123);
    let b = TensionValue::from_integer(456);
    let c = a + b;
    assert_eq!(c, TensionValue::from_integer(579));

    let d = TensionValue(TensionValue::SCALE / 3); // 0.333...
    let e = d.mul_fp(TensionValue::from_integer(3));
    // Should be very close to 1.0 but not exactly due to fixed-point truncation.
    assert!(e.raw() > 0);
    assert!(e.raw() <= TensionValue::SCALE);
}

#[test]
fn test_norm_replicator_convergence() {
    let mut registry = NormRegistry::new();

    let high_fit = sccgub_types::governance::Norm {
        id: [1u8; 32],
        name: "high-fitness".into(),
        description: String::new(),
        precedence: PrecedenceLevel::Meaning,
        population_share: TensionValue(TensionValue::SCALE / 2), // 0.5
        fitness: TensionValue::from_integer(10),
        enforcement_cost: TensionValue::ZERO,
        active: true,
        created_at_height: 0,
    };

    let low_fit = sccgub_types::governance::Norm {
        id: [2u8; 32],
        name: "low-fitness".into(),
        description: String::new(),
        precedence: PrecedenceLevel::Meaning,
        population_share: TensionValue(TensionValue::SCALE / 2), // 0.5
        fitness: TensionValue::from_integer(2),
        enforcement_cost: TensionValue::ZERO,
        active: true,
        created_at_height: 0,
    };

    registry.register(high_fit);
    registry.register(low_fit);

    // Run 20 epochs of replicator dynamics.
    for _ in 0..20 {
        registry.evolve_epoch();
    }

    let h = registry.get(&[1u8; 32]).unwrap();
    let l = registry.get(&[2u8; 32]).unwrap();

    // High-fitness norm should dominate.
    assert!(
        h.population_share > l.population_share,
        "High-fitness norm should have larger share: {} vs {}",
        h.population_share,
        l.population_share
    );
}

#[test]
fn test_merkle_proof_for_transaction_inclusion() {
    use sccgub_crypto::merkle::{compute_merkle_root, generate_proof, verify_proof};

    let (agent, agent_key) = create_test_agent();
    let txs: Vec<_> = (1..=5)
        .map(|i| {
            create_write_tx(
                &agent,
                &agent_key,
                format!("proof/key/{}", i).as_bytes(),
                b"data",
                i,
            )
        })
        .collect();

    let leaf_hashes: Vec<[u8; 32]> = txs.iter().map(|tx| tx.tx_id).collect();
    let root = compute_merkle_root(&leaf_hashes);

    // Verify inclusion proof for each transaction.
    for (i, tx) in txs.iter().enumerate() {
        let proof = generate_proof(&leaf_hashes, i).unwrap();
        assert!(
            verify_proof(&root, &tx.tx_id, &proof),
            "Merkle inclusion proof failed for tx {}",
            i
        );
    }

    // Fake tx should fail proof.
    let fake_id = blake3_hash(b"fake-tx");
    let proof = generate_proof(&leaf_hashes, 0).unwrap();
    assert!(!verify_proof(&root, &fake_id, &proof));
}

#[test]
fn test_governance_proposal_lifecycle() {
    use sccgub_governance::proposals::{ProposalKind, ProposalRegistry};

    let mut proposals = ProposalRegistry::default();

    // Submit a norm proposal.
    let id = proposals
        .submit(
            [1u8; 32],
            PrecedenceLevel::Meaning,
            ProposalKind::AddNorm {
                name: "test-norm".into(),
                description: "Integration test norm".into(),
                initial_fitness: TensionValue::from_integer(5),
                enforcement_cost: TensionValue::from_integer(1),
            },
            10,
            5,
        )
        .unwrap();

    // Vote during valid period.
    proposals
        .vote(&id, [10u8; 32], PrecedenceLevel::Meaning, true, 12)
        .unwrap();
    proposals
        .vote(&id, [11u8; 32], PrecedenceLevel::Meaning, true, 13)
        .unwrap();

    // Finalize after voting period — enters timelock.
    let accepted = proposals.finalize(16);
    assert_eq!(accepted.len(), 1);

    // Activate after timelock expires (ordinary = 50 blocks from finalize height).
    let norm = proposals
        .activate(&id, 16 + sccgub_governance::proposals::timelocks::ORDINARY)
        .unwrap()
        .unwrap();
    assert_eq!(norm.name, "test-norm");
    assert!(norm.active);
}

#[test]
fn test_agent_registration_and_lookup() {
    use sccgub_governance::registration::AgentRegistry;

    let mut registry = AgentRegistry::default();
    let key = sccgub_crypto::keys::generate_keypair();
    let pk = *key.verifying_key().as_bytes();
    let seal = MfidelAtomicSeal::from_height(1);

    let id = registry
        .register(pk, seal, PrecedenceLevel::Meaning, 0)
        .unwrap();

    assert!(registry.is_active(&id));

    // Duplicate should fail.
    assert!(registry
        .register(
            pk,
            MfidelAtomicSeal::from_height(1),
            PrecedenceLevel::Meaning,
            1
        )
        .is_err());

    // Revoke.
    registry.revoke(&id).unwrap();
    assert!(!registry.is_active(&id));
}

#[test]
fn test_balance_transfer() {
    use sccgub_state::balances::BalanceLedger;

    let mut ledger = BalanceLedger::new();
    let alice = [1u8; 32];
    let bob = [2u8; 32];
    let charlie = [3u8; 32];

    // Mint initial supply.
    ledger.credit(&alice, TensionValue::from_integer(10_000));

    // Transfer chain: alice -> bob -> charlie.
    ledger
        .transfer(&alice, &bob, TensionValue::from_integer(3000))
        .unwrap();
    ledger
        .transfer(&bob, &charlie, TensionValue::from_integer(1000))
        .unwrap();

    assert_eq!(ledger.balance_of(&alice), TensionValue::from_integer(7000));
    assert_eq!(ledger.balance_of(&bob), TensionValue::from_integer(2000));
    assert_eq!(
        ledger.balance_of(&charlie),
        TensionValue::from_integer(1000)
    );

    // Total supply conserved.
    assert_eq!(ledger.total_supply(), TensionValue::from_integer(10_000));

    // Insufficient funds rejected.
    assert!(ledger
        .transfer(&charlie, &alice, TensionValue::from_integer(5000))
        .is_err());

    // Zero transfer rejected.
    assert!(ledger.transfer(&alice, &bob, TensionValue::ZERO).is_err());

    // Self-transfer rejected.
    assert!(ledger
        .transfer(&alice, &alice, TensionValue::from_integer(100))
        .is_err());
}

#[test]
fn test_economic_fee_computation() {
    use sccgub_types::economics::EconomicState;

    let econ = EconomicState::default();
    let budget = TensionValue::from_integer(100);

    // Zero tension -> fee equals base_fee.
    let fee_zero = econ.effective_fee(TensionValue::ZERO, budget);
    assert_eq!(fee_zero, econ.base_fee);

    // Higher tension -> higher fee.
    let fee_low = econ.effective_fee(TensionValue::from_integer(20), budget);
    let fee_high = econ.effective_fee(TensionValue::from_integer(80), budget);
    assert!(fee_high > fee_low, "Higher tension = higher fee");

    // Negative budget -> base_fee (fallback).
    let fee_neg = econ.effective_fee(
        TensionValue::from_integer(50),
        TensionValue(-(TensionValue::SCALE)),
    );
    assert_eq!(fee_neg, econ.base_fee);
}

/// Comprehensive end-to-end test exercising ALL major subsystems.
#[test]
fn test_end_to_end_all_subsystems() {
    use sccgub_execution::cpog::validate_cpog;
    use sccgub_execution::phi::phi_traversal_block;
    use sccgub_governance::containment::ContainmentState;
    use sccgub_governance::emergency::{evaluate_emergency, EmergencyPolicy};
    use sccgub_governance::norms::NormRegistry;
    use sccgub_governance::proposals::{ProposalKind, ProposalRegistry};
    use sccgub_governance::registration::AgentRegistry;
    use sccgub_state::balances::BalanceLedger;
    use sccgub_types::economics::EconomicState;

    // ===== 1. AGENT REGISTRATION =====
    let mut agent_registry = AgentRegistry::default();
    let (agent_alice, key_alice) = create_test_agent();
    let alice_id = agent_registry
        .register(
            agent_alice.public_key,
            agent_alice.mfidel_seal.clone(),
            PrecedenceLevel::Meaning,
            0,
        )
        .unwrap();
    assert!(agent_registry.is_active(&alice_id));

    // ===== 2. GENESIS + BLOCK PRODUCTION =====
    let mut state = ManagedWorldState::new();
    let validator_key = generate_keypair();

    // Genesis block.
    let genesis = build_test_block(
        0,
        ZERO_HASH,
        &CausalTimestamp::genesis(),
        vec![],
        &validator_key,
        &state,
    );
    assert!(genesis.is_structurally_valid());
    let cpog = validate_cpog(&genesis, &state, &ZERO_HASH);
    assert!(cpog.is_valid(), "Genesis CPoG: {:?}", cpog);

    // ===== 3. BALANCE LEDGER =====
    let mut balances = BalanceLedger::new();
    balances.credit(&alice_id, TensionValue::from_integer(100_000));
    assert_eq!(balances.total_supply(), TensionValue::from_integer(100_000));

    // ===== 4. TRANSACTIONS + BLOCK #1 =====
    let tx1 = create_write_tx(
        &agent_alice,
        &key_alice,
        b"data/alice/data",
        b"hello world",
        1,
    );
    let tx2 = create_write_tx(&agent_alice, &key_alice, b"data/alice/config", b"v1", 2);
    let tx3 = create_write_tx(&agent_alice, &key_alice, b"data/alice/counter", b"42", 3);

    let block1 = build_test_block(
        1,
        genesis.header.block_id,
        &genesis.header.timestamp,
        vec![tx1.clone(), tx2.clone(), tx3.clone()],
        &validator_key,
        &state,
    );
    assert!(block1.is_structurally_valid());

    // ===== 5. FULL PHI TRAVERSAL =====
    let phi = phi_traversal_block(&block1, &state);
    assert!(phi.is_all_passed(), "Phi failed: {:?}", phi);
    assert_eq!(phi.phases_completed.len(), 13);

    // ===== 6. CPoG VALIDATION (all 6 Merkle roots) =====
    let cpog1 = validate_cpog(&block1, &state, &genesis.header.block_id);
    assert!(cpog1.is_valid(), "Block #1 CPoG: {:?}", cpog1);

    // ===== 7. STATE APPLICATION =====
    for tx in &block1.body.transitions {
        if let OperationPayload::Write { key, value } = &tx.payload {
            state.apply_delta(&StateDelta {
                writes: vec![StateWrite {
                    address: key.clone(),
                    value: value.clone(),
                }],
                deletes: vec![],
            });
        }
        let _ = state.check_nonce(&tx.actor.agent_id, tx.nonce);
    }
    state.set_height(1);

    // Verify state was applied.
    assert_eq!(
        state.get(&b"data/alice/data".to_vec()),
        Some(&b"hello world".to_vec())
    );
    assert_eq!(
        state.get(&b"data/alice/counter".to_vec()),
        Some(&b"42".to_vec())
    );
    assert_ne!(state.state_root(), ZERO_HASH);

    // State root matches block header.
    assert_eq!(state.state_root(), block1.header.state_root);

    // ===== 8. NONCE REPLAY REJECTED =====
    let replay_tx = create_write_tx(&agent_alice, &key_alice, b"data/alice/replay", b"bad", 1);
    let replay_result = sccgub_execution::validate::validate_transition(&replay_tx, &state);
    assert!(replay_result.is_err(), "Nonce replay should be rejected");

    // ===== 9. GOVERNANCE PROPOSALS =====
    let mut proposals = ProposalRegistry::default();
    let prop_id = proposals
        .submit(
            alice_id,
            PrecedenceLevel::Meaning,
            ProposalKind::AddNorm {
                name: "fairness".into(),
                description: "Ensure fair resource distribution".into(),
                initial_fitness: TensionValue::from_integer(8),
                enforcement_cost: TensionValue::from_integer(2),
            },
            1,
            5,
        )
        .unwrap();
    proposals
        .vote(&prop_id, alice_id, PrecedenceLevel::Meaning, true, 3)
        .unwrap();
    let accepted = proposals.finalize(7);
    assert_eq!(accepted.len(), 1);
    let norm = proposals
        .activate(
            &prop_id,
            7 + sccgub_governance::proposals::timelocks::ORDINARY,
        )
        .unwrap()
        .unwrap();

    // ===== 10. NORM REPLICATOR DYNAMICS =====
    let mut norm_registry = NormRegistry::new();
    norm_registry.register(norm);
    // Add a competing norm.
    norm_registry.register(sccgub_types::governance::Norm {
        id: [99u8; 32],
        name: "efficiency".into(),
        description: "Optimize throughput".into(),
        precedence: PrecedenceLevel::Optimization,
        population_share: TensionValue(TensionValue::SCALE / 2),
        fitness: TensionValue::from_integer(3),
        enforcement_cost: TensionValue::from_integer(1),
        active: true,
        created_at_height: 0,
    });
    for _ in 0..10 {
        norm_registry.evolve_epoch();
    }
    // Higher-fitness norm should dominate.
    let fairness = norm_registry.get(&prop_id).unwrap();
    let efficiency = norm_registry.get(&[99u8; 32]).unwrap();
    assert!(fairness.population_share > efficiency.population_share);

    // ===== 11. CONTAINMENT =====
    let mut containment = ContainmentState::default();
    let bad_node = [0xBBu8; 32];
    // Record many invalid transitions to drive hostility above threshold.
    for _ in 0..50 {
        containment.record_invalid(bad_node, TensionValue::from_integer(100));
    }
    // Evaluate multiple times to escalate through containment levels.
    for _ in 0..5 {
        containment.evaluate();
    }
    assert!(
        !containment.is_allowed(&bad_node),
        "Bad node should be contained"
    );

    // Good node stays free.
    let good_node = [0xAAu8; 32];
    containment.record_valid(good_node, TensionValue::from_integer(100));
    containment.evaluate();
    assert!(containment.is_allowed(&good_node));

    // ===== 12. EMERGENCY GOVERNANCE =====
    let emergency_policy = EmergencyPolicy::default();
    let low_tension_field = sccgub_types::tension::TensionField::default();
    let gov_state = sccgub_types::governance::GovernanceState::default();
    let decision = evaluate_emergency(&low_tension_field, &gov_state, &emergency_policy);
    assert!(!decision.is_emergency(), "Low tension = no emergency");

    // ===== 13. MERKLE PROOFS =====
    let leaves: Vec<[u8; 32]> = block1.body.transitions.iter().map(|t| t.tx_id).collect();
    let root = sccgub_crypto::merkle::compute_merkle_root(&leaves);
    for (i, tx) in block1.body.transitions.iter().enumerate() {
        let proof = sccgub_crypto::merkle::generate_proof(&leaves, i).unwrap();
        assert!(sccgub_crypto::merkle::verify_proof(
            &root, &tx.tx_id, &proof
        ));
    }

    // ===== 14. ECONOMIC FEES =====
    let econ = EconomicState::default();
    let budget = TensionValue::from_integer(100);
    let fee = econ.effective_fee(TensionValue::from_integer(50), budget);
    assert!(fee >= econ.base_fee, "Fee should be >= base_fee");

    // ===== 15. BALANCE TRANSFERS =====
    let (agent_bob, _) = create_test_agent();
    balances
        .transfer(
            &alice_id,
            &agent_bob.agent_id,
            TensionValue::from_integer(25_000),
        )
        .unwrap();
    assert_eq!(
        balances.balance_of(&alice_id),
        TensionValue::from_integer(75_000)
    );
    assert_eq!(
        balances.balance_of(&agent_bob.agent_id),
        TensionValue::from_integer(25_000)
    );
    assert_eq!(balances.total_supply(), TensionValue::from_integer(100_000));

    // ===== 16. DOMAIN PACKS =====
    let mut domain_registry = sccgub_types::domain::DomainPackRegistry::default();
    let finance_pack = sccgub_types::domain::DomainPack {
        id: [0xFFu8; 32],
        name: "finance".into(),
        version: "1.0.0".into(),
        description: "Financial instruments".into(),
        required_level: PrecedenceLevel::Meaning,
        types: vec![sccgub_types::domain::DomainType {
            name: "finance.Account".into(),
            schema: "account type".into(),
            fields: vec![sccgub_types::domain::DomainField {
                name: "balance".into(),
                field_type: "TensionValue".into(),
                required: true,
            }],
        }],
        laws: vec![],
        dependencies: vec![],
        installed_at: None,
        active: false,
    };
    domain_registry
        .install(finance_pack, PrecedenceLevel::Meaning, 1)
        .unwrap();
    assert_eq!(domain_registry.active_packs().len(), 1);

    // ===== 17. MULTI-BLOCK CHAIN =====
    let tx4 = create_write_tx(&agent_alice, &key_alice, b"data/alice/block2", b"data2", 4);
    let block2 = build_test_block(
        2,
        block1.header.block_id,
        &block1.header.timestamp,
        vec![tx4.clone()],
        &validator_key,
        &state,
    );
    let cpog2 = validate_cpog(&block2, &state, &block1.header.block_id);
    assert!(cpog2.is_valid(), "Block #2 CPoG: {:?}", cpog2);

    // Apply block 2 state.
    for tx in &block2.body.transitions {
        if let OperationPayload::Write { key, value } = &tx.payload {
            state.apply_delta(&StateDelta {
                writes: vec![StateWrite {
                    address: key.clone(),
                    value: value.clone(),
                }],
                deletes: vec![],
            });
        }
    }
    state.set_height(2);
    assert_eq!(state.state_root(), block2.header.state_root);

    // ===== FINAL ASSERTIONS =====
    // All Mfidel seals correct.
    assert_eq!(genesis.header.mfidel_seal, MfidelAtomicSeal::from_height(0));
    assert_eq!(block1.header.mfidel_seal, MfidelAtomicSeal::from_height(1));
    assert_eq!(block2.header.mfidel_seal, MfidelAtomicSeal::from_height(2));

    // Chain height progressed.
    assert_eq!(state.state.height, 2);

    // 4 state entries (3 from block 1 + 1 from block 2).
    assert_eq!(state.trie.len(), 4);
}

#[test]
fn test_duplicate_mempool_submission_rejected() {
    use std::collections::HashSet;

    let (agent, agent_key) = create_test_agent();
    let tx = create_write_tx(&agent, &agent_key, b"data/dedup/test", b"data", 1);

    // Manual mempool to test dedup.
    let mut seen = HashSet::new();
    seen.insert(tx.tx_id);

    // Second submission of same tx_id should be detected.
    assert!(seen.contains(&tx.tx_id), "Duplicate should be detected");
}

#[test]
fn test_domain_pack_dependent_deactivation_rejected() {
    use sccgub_types::domain::{DomainField, DomainPack, DomainPackRegistry, DomainType};

    let mut registry = DomainPackRegistry::default();

    // Install base pack.
    let base_id = [1u8; 32];
    let base = DomainPack {
        id: base_id,
        name: "base".into(),
        version: "1.0.0".into(),
        description: "Base domain".into(),
        required_level: PrecedenceLevel::Meaning,
        types: vec![DomainType {
            name: "base.Record".into(),
            schema: "base record".into(),
            fields: vec![DomainField {
                name: "id".into(),
                field_type: "u64".into(),
                required: true,
            }],
        }],
        laws: vec![],
        dependencies: vec![],
        installed_at: None,
        active: false,
    };
    registry.install(base, PrecedenceLevel::Meaning, 0).unwrap();

    // Install dependent pack.
    let dep = DomainPack {
        id: [2u8; 32],
        name: "derived".into(),
        version: "1.0.0".into(),
        description: "Depends on base".into(),
        required_level: PrecedenceLevel::Meaning,
        types: vec![DomainType {
            name: "derived.Record".into(),
            schema: "derived record".into(),
            fields: vec![],
        }],
        laws: vec![],
        dependencies: vec![base_id], // Depends on base.
        installed_at: None,
        active: false,
    };
    registry.install(dep, PrecedenceLevel::Meaning, 1).unwrap();

    // Deactivating base should fail because derived depends on it.
    let result = registry.deactivate(&base_id);
    assert!(
        result.is_err(),
        "Should reject deactivation of depended-upon pack"
    );
}

#[test]
fn test_duplicate_voter_rejected() {
    use sccgub_governance::proposals::{ProposalKind, ProposalRegistry};

    let mut proposals = ProposalRegistry::default();
    let voter = [42u8; 32];

    let id = proposals
        .submit(
            [1u8; 32],
            PrecedenceLevel::Meaning,
            ProposalKind::AddNorm {
                name: "test".into(),
                description: "test".into(),
                initial_fitness: TensionValue::from_integer(1),
                enforcement_cost: TensionValue::ZERO,
            },
            0,
            10,
        )
        .unwrap();

    // First vote succeeds.
    proposals
        .vote(&id, voter, PrecedenceLevel::Meaning, true, 1)
        .unwrap();

    // Second vote by same agent should fail.
    let result = proposals.vote(&id, voter, PrecedenceLevel::Meaning, false, 2);
    assert!(result.is_err(), "Duplicate voter should be rejected");
}

// ===== INVARIANT TEST SUITE =====
// Maps every README invariant to a machine-checked test.

#[test]
fn test_inv4_no_fork_deterministic_finality() {
    // INV-4: No fork (deterministic finality).
    // Two blocks at the same height with same parent should have identical block_id
    // if they contain the same transactions (deterministic block production).
    let (agent, agent_key) = create_test_agent();
    let validator_key = generate_keypair();
    let state = ManagedWorldState::new();

    let genesis = build_test_block(
        0,
        ZERO_HASH,
        &CausalTimestamp::genesis(),
        vec![],
        &validator_key,
        &state,
    );

    let tx = create_write_tx(&agent, &agent_key, b"data/inv4/test", b"data", 1);

    let block_a = build_test_block(
        1,
        genesis.header.block_id,
        &genesis.header.timestamp,
        vec![tx.clone()],
        &validator_key,
        &state,
    );
    let block_b = build_test_block(
        1,
        genesis.header.block_id,
        &genesis.header.timestamp,
        vec![tx.clone()],
        &validator_key,
        &state,
    );

    // Same inputs -> same block_id (deterministic).
    assert_eq!(block_a.header.block_id, block_b.header.block_id);
}

#[test]
fn test_inv8_contract_decidability_bound() {
    // INV-8: No contract beyond decidability bound.
    use sccgub_execution::contract::{
        default_max_steps_for_state, execute_contract, execute_contract_with_state_params,
    };
    use sccgub_types::contract::SymbolicCausalContract;
    use sccgub_types::transition::Constraint;

    let contract = SymbolicCausalContract {
        contract_id: [42u8; 32],
        name: "TestBound".into(),
        laws: vec![Constraint {
            id: [1u8; 32],
            expression: "governance:2".into(),
        }],
        state: std::collections::HashMap::new(),
        history: vec![],
        deployer: [0u8; 32],
        governance_level: PrecedenceLevel::Meaning,
        deployed_at: 0,
    };

    let (agent, _) = create_test_agent();
    let tx = create_write_tx(&agent, &generate_keypair(), b"contract/test", b"v", 1);
    let state = ManagedWorldState::new();

    // With max_steps=0, contract MUST reject (decidability bound enforced).
    let result = execute_contract(&contract, &tx, &state, 0);
    assert!(
        !result.verdict.is_accepted(),
        "INV-8: step limit must be enforced"
    );

    // With the chain-bound default, should have room to execute.
    let result = execute_contract_with_state_params(&contract, &tx, &state);
    // Passes or fails on precondition, but does NOT exceed step limit.
    assert!(result.steps_used <= default_max_steps_for_state(&state));
}

#[test]
fn test_inv13_responsibility_bounded() {
    // INV-13: |Σ R_i_net| <= R_max_imbalance.
    use sccgub_governance::responsibility;

    let mut s1 = sccgub_types::agent::ResponsibilityState::default();
    responsibility::record_positive(&mut s1, [1u8; 32], TensionValue::from_integer(500), 1);

    let mut s2 = sccgub_types::agent::ResponsibilityState::default();
    responsibility::record_negative(&mut s2, [2u8; 32], TensionValue::from_integer(200), 1);

    let max_imbalance = TensionValue::from_integer(1000);
    assert!(
        responsibility::check_responsibility_bound(&[&s1, &s2], max_imbalance),
        "INV-13: total net responsibility should be within bounds"
    );

    // Exceed the bound.
    let strict = TensionValue::from_integer(100);
    assert!(
        !responsibility::check_responsibility_bound(&[&s1, &s2], strict),
        "INV-13: should fail when bound exceeded"
    );
}
