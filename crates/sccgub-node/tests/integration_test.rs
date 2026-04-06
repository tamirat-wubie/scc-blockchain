//! Integration tests: full chain lifecycle.
//! Genesis -> submit transitions -> produce block -> validate -> verify state.

use std::collections::{HashMap, HashSet};

use sccgub_crypto::hash::blake3_hash;
use sccgub_crypto::keys::generate_keypair;
use sccgub_crypto::merkle::{compute_merkle_root, merkle_root_of_bytes};
use sccgub_crypto::signature::{sign, verify};
use sccgub_execution::cpog::{validate_cpog, CpogResult};
use sccgub_execution::phi::{phi_traversal_block, phi_traversal_tx};
use sccgub_execution::wh_check::check_wh_binding_intent;
use sccgub_governance::norms::NormRegistry;
use sccgub_governance::precedence::{check_governance_change, GovernanceChangeType};
use sccgub_governance::responsibility;
use sccgub_governance::validator::{round_robin_proposer, select_validator};
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
    let agent_id = blake3_hash(&pk);
    let agent = AgentIdentity {
        agent_id,
        public_key: pk,
        mfidel_seal: MfidelAtomicSeal::from_height(1),
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

    let tx_data = serde_json::to_vec(&(&agent.agent_id, addr, data, nonce)).unwrap();
    let tx_id = blake3_hash(&tx_data);
    let signature = sign(key, &tx_data);

    SymbolicTransition {
        tx_id,
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
        signature,
    }
}

/// Helper: build a minimal valid block.
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
    let timestamp = parent_timestamp.successor(validator_id, blake3_hash(&parent_id));
    let seal = MfidelAtomicSeal::from_height(height);

    let tx_bytes: Vec<&[u8]> = transitions.iter().map(|tx| tx.tx_id.as_slice()).collect();
    let transition_root = merkle_root_of_bytes(&tx_bytes);

    let governance = GovernanceSnapshot {
        state_hash: ZERO_HASH,
        active_norm_count: 0,
        emergency_mode: false,
        finality_mode: FinalityMode::Deterministic,
    };

    let tension_before = state.state.tension_field.total;
    let header_data = serde_json::to_vec(&(chain_id, height, &parent_id)).unwrap();
    let block_id = blake3_hash(&header_data);

    let header = BlockHeader {
        chain_id,
        block_id,
        parent_id,
        height,
        timestamp,
        state_root: state.state_root(),
        transition_root,
        receipt_root: ZERO_HASH,
        causal_root: ZERO_HASH,
        proof_root: ZERO_HASH,
        governance_hash: blake3_hash(&serde_json::to_vec(&governance).unwrap()),
        tension_before,
        tension_after: tension_before,
        mfidel_seal: seal,
        validator_id,
        version: 1,
    };

    let proof = CausalProof {
        block_height: height,
        transitions_proven: vec![],
        phi_traversal_log: PhiTraversalLog::default(),
        governance_snapshot_hash: header.governance_hash,
        tension_before,
        tension_after: tension_before,
        constraint_results: vec![],
        recursion_depth: 0,
        validator_signature: sign(validator_key, &header_data),
        causal_hash: blake3_hash(&header_data),
    };

    Block {
        header,
        body: BlockBody {
            transitions: transitions.clone(),
            transition_count: transitions.len() as u32,
            total_tension_delta: TensionValue::ZERO,
            constraint_satisfaction: vec![],
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
    assert!(cpog_result.is_valid(), "Genesis CPoG failed: {:?}", cpog_result);

    // 4. Submit transitions.
    let tx1 = create_write_tx(&agent, &agent_key, b"account/alice/balance", b"1000", 0);
    let tx2 = create_write_tx(&agent, &agent_key, b"account/bob/balance", b"500", 1);
    let tx3 = create_write_tx(&agent, &agent_key, b"config/max_supply", b"1000000", 2);

    // 5. Validate each transition individually.
    for tx in [&tx1, &tx2, &tx3] {
        let phi_log = phi_traversal_tx(tx, &state);
        assert!(phi_log.all_phases_passed, "Per-tx Phi failed for {:?}", tx.tx_id);
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
    assert!(phi_log.all_phases_passed, "Block Phi traversal failed: {:?}", phi_log);
    assert_eq!(phi_log.phases_completed.len(), 13);

    // 8. Validate via CPoG.
    let cpog_result = validate_cpog(&block1, &state, &genesis.header.block_id);
    assert!(cpog_result.is_valid(), "Block #1 CPoG failed: {:?}", cpog_result);

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
        state.get(&b"account/alice/balance".to_vec()),
        Some(&b"1000".to_vec())
    );
    assert_eq!(
        state.get(&b"account/bob/balance".to_vec()),
        Some(&b"500".to_vec())
    );
    assert_eq!(
        state.get(&b"config/max_supply".to_vec()),
        Some(&b"1000000".to_vec())
    );

    // 11. Verify state root changed.
    assert_ne!(state.state_root(), ZERO_HASH);
}

#[test]
fn test_invalid_block_wrong_parent() {
    let state = ManagedWorldState::new();
    let validator_key = generate_keypair();

    let genesis = build_test_block(0, ZERO_HASH, &CausalTimestamp::genesis(), vec![], &validator_key, &state);

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

    let genesis = build_test_block(0, ZERO_HASH, &CausalTimestamp::genesis(), vec![], &validator_key, &state);

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
    assert!(!result.is_valid(), "Should reject block with wrong Mfidel seal");
}

#[test]
fn test_invalid_transition_missing_wh_binding() {
    let (agent, agent_key) = create_test_agent();

    // Create transition with empty WHBinding fields.
    let mut tx = create_write_tx(&agent, &agent_key, b"test", b"data", 0);
    tx.wh_binding_intent.who = ZERO_HASH; // Make it invalid.

    let result = check_wh_binding_intent(&tx.wh_binding_intent);
    assert!(result.is_err(), "Should reject transition with empty 'who'");
}

#[test]
fn test_causal_timestamp_ordering() {
    let genesis_ts = CausalTimestamp::genesis();
    let node_id = [1u8; 32];

    let ts1 = genesis_ts.successor(node_id, blake3_hash(b"parent1"));
    let ts2 = ts1.successor(node_id, blake3_hash(b"parent2"));

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

    let genesis = build_test_block(0, ZERO_HASH, &CausalTimestamp::genesis(), vec![], &validator_key, &state);

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
    assert!(!result.is_valid(), "Should reject block exceeding tension budget");
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
    assert_eq!(v1.node_id, v2.node_id, "Validator selection must be deterministic");
}

#[test]
fn test_governance_precedence_enforcement() {
    // GENESIS can do anything.
    assert!(check_governance_change(PrecedenceLevel::Genesis, GovernanceChangeType::GovernanceUpgrade).is_ok());

    // OPTIMIZATION cannot change governance.
    assert!(check_governance_change(PrecedenceLevel::Optimization, GovernanceChangeType::GovernanceUpgrade).is_err());

    // MEANING can add norms.
    assert!(check_governance_change(PrecedenceLevel::Meaning, GovernanceChangeType::NormAddition).is_ok());

    // EMOTION cannot add norms (MEANING required).
    assert!(check_governance_change(PrecedenceLevel::Emotion, GovernanceChangeType::NormAddition).is_err());
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
    assert!(!responsibility::check_responsibility_bound(&[&state], strict));
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
    let genesis = build_test_block(0, ZERO_HASH, &CausalTimestamp::genesis(), vec![], &validator_key, &state);
    let result = validate_cpog(&genesis, &state, &ZERO_HASH);
    assert!(result.is_valid());

    let mut prev_block = genesis;

    // Produce 10 blocks.
    for i in 1..=10u64 {
        let tx = create_write_tx(
            &agent,
            &agent_key,
            format!("block/{}/data", i).as_bytes(),
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

        // Apply state.
        if let OperationPayload::Write { key, value } = &tx.payload {
            state.apply_delta(&StateDelta {
                writes: vec![StateWrite {
                    address: key.clone(),
                    value: value.clone(),
                }],
                deletes: vec![],
            });
        }
        state.set_height(i);

        prev_block = block;
    }

    // Verify final state.
    assert_eq!(
        state.get(&b"block/10/data".to_vec()),
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
