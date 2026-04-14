use std::collections::BTreeSet;
use std::time::Instant;

use sccgub_crypto::hash::blake3_hash;
use sccgub_crypto::keys::generate_keypair;
use sccgub_crypto::signature::sign;
use sccgub_execution::validate::canonical_tx_bytes;
use sccgub_node::chain::Chain;
use sccgub_state::world::ManagedWorldState;
use sccgub_types::agent::{AgentIdentity, ResponsibilityState};
use sccgub_types::governance::PrecedenceLevel;
use sccgub_types::mfidel::MfidelAtomicSeal;
use sccgub_types::tension::TensionValue;
use sccgub_types::timestamp::CausalTimestamp;
use sccgub_types::transition::*;

fn create_bench_tx(
    agent: &AgentIdentity,
    key: &ed25519_dalek::SigningKey,
    nonce: u128,
) -> SymbolicTransition {
    let target = format!("data/bench/tx/{}", nonce).into_bytes();
    let payload = OperationPayload::Write {
        key: target.clone(),
        value: format!("data_{}", nonce).into_bytes(),
    };

    let intent = WHBindingIntent {
        who: agent.agent_id,
        when: CausalTimestamp::genesis(),
        r#where: target.clone(),
        why: CausalJustification {
            invoking_rule: blake3_hash(b"bench-rule"),
            precedence_level: PrecedenceLevel::Meaning,
            causal_ancestors: vec![],
            constraint_proof: vec![],
        },
        how: TransitionMechanism::DirectStateWrite,
        which: BTreeSet::new(),
        what_declared: format!("Bench write #{}", nonce),
    };

    let mut tx = SymbolicTransition {
        tx_id: [0u8; 32],
        actor: agent.clone(),
        intent: TransitionIntent {
            kind: TransitionKind::StateWrite,
            target,
            declared_purpose: format!("Bench #{}", nonce),
        },
        preconditions: vec![],
        postconditions: vec![],
        payload,
        causal_chain: vec![],
        wh_binding_intent: intent,
        nonce,
        signature: vec![],
    };

    let canonical = canonical_tx_bytes(&tx);
    tx.tx_id = blake3_hash(&canonical);
    tx.signature = sign(key, &canonical);
    tx
}

fn main() {
    let agent_key = generate_keypair();
    let pk = *agent_key.verifying_key().as_bytes();
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
        norm_set: BTreeSet::new(),
        responsibility: ResponsibilityState::default(),
    };

    println!("=== SCCGUB Block Production Benchmark ===\n");

    // ---------------------------------------------------------------
    // 1. Transaction creation + signing throughput
    // ---------------------------------------------------------------
    println!("--- Transaction Creation + Signing ---");
    let counts = [10, 100, 500, 1000];
    for &count in &counts {
        let start = Instant::now();
        let txs: Vec<_> = (1..=count)
            .map(|i| create_bench_tx(&agent, &agent_key, i as u128))
            .collect();
        let elapsed = start.elapsed();
        println!(
            "Create+sign {:>5} txs: {:>8.2?}  ({:>8.0} tx/s)",
            count,
            elapsed,
            count as f64 / elapsed.as_secs_f64()
        );
        let _ = txs;
    }
    println!();

    // ---------------------------------------------------------------
    // 2. Standalone validation throughput
    // ---------------------------------------------------------------
    println!("--- Transaction Validation (standalone) ---");
    for &count in &counts {
        let txs: Vec<_> = (1..=count)
            .map(|i| create_bench_tx(&agent, &agent_key, i as u128))
            .collect();
        let state = ManagedWorldState::new();
        let start = Instant::now();
        let mut valid = 0u32;
        for tx in &txs {
            if sccgub_execution::validate::validate_transition(tx, &state).is_ok() {
                valid += 1;
            }
        }
        let elapsed = start.elapsed();
        println!(
            "Validate    {:>5} txs: {:>8.2?}  ({:>8.0} tx/s, {} valid)",
            count,
            elapsed,
            count as f64 / elapsed.as_secs_f64(),
            valid
        );
    }
    println!();

    // ---------------------------------------------------------------
    // 3. Merkle root computation
    // ---------------------------------------------------------------
    println!("--- Merkle Root Computation ---");
    for &count in &counts {
        let leaves: Vec<[u8; 32]> = (0..count)
            .map(|i| blake3_hash(&(i as u64).to_le_bytes()))
            .collect();
        let start = Instant::now();
        let _root = sccgub_crypto::merkle::compute_merkle_root(&leaves);
        let elapsed = start.elapsed();
        println!("Merkle root {:>5} leaves: {:>8.2?}", count, elapsed);
    }
    println!();

    // ---------------------------------------------------------------
    // 4. End-to-end block production through Chain
    // ---------------------------------------------------------------
    println!("--- End-to-End Block Production (Chain) ---");

    // Build a chain whose validator key matches the agent identity,
    // so submitted transactions pass Phi phase signature checks.
    let mut chain = Chain::init();
    chain.governance_limits.max_consecutive_proposals = 10_000;
    chain.mempool.containment.hostility_threshold = TensionValue::from_integer(1_000_000);

    let chain_key = chain.validator_key.clone();
    let chain_pk = *chain_key.verifying_key().as_bytes();
    let chain_seal = MfidelAtomicSeal::from_height(0);
    let chain_agent_id =
        sccgub_state::apply::validator_spend_account(chain.block_version, &chain_pk);
    let chain_agent = AgentIdentity {
        agent_id: chain_agent_id,
        public_key: chain_pk,
        mfidel_seal: chain_seal,
        registration_block: 0,
        governance_level: PrecedenceLevel::Meaning,
        norm_set: BTreeSet::new(),
        responsibility: ResponsibilityState::default(),
    };

    // 4a. Single-tx blocks: measure per-block overhead.
    let single_tx_count = 100;
    let start = Instant::now();
    for i in 1..=single_tx_count {
        let tx = create_bench_tx(&chain_agent, &chain_key, i as u128);
        chain
            .submit_transition(tx)
            .unwrap_or_else(|e| panic!("submit #{} failed: {}", i, e));
        chain
            .produce_block()
            .unwrap_or_else(|e| panic!("block #{} failed: {}", i, e));
    }
    let elapsed = start.elapsed();
    println!(
        "Single-tx blocks: {:>5} blocks in {:>8.2?}  ({:>6.0} blocks/s, {:>6.0} tx/s)",
        single_tx_count,
        elapsed,
        single_tx_count as f64 / elapsed.as_secs_f64(),
        single_tx_count as f64 / elapsed.as_secs_f64(),
    );

    // 4b. Sustained throughput: submit+produce N blocks with 1 tx each.
    //     Tests throughput over a longer chain (state growth effects).
    let sustained_counts = [500, 1000];
    for &count in &sustained_counts {
        let mut chain2 = Chain::init();
        chain2.governance_limits.max_consecutive_proposals = count as u32 + 100;
        chain2.mempool.containment.hostility_threshold = TensionValue::from_integer(1_000_000);

        let key2 = chain2.validator_key.clone();
        let pk2 = *key2.verifying_key().as_bytes();
        let agent_id2 = sccgub_state::apply::validator_spend_account(chain2.block_version, &pk2);
        let agent2 = AgentIdentity {
            agent_id: agent_id2,
            public_key: pk2,
            mfidel_seal: MfidelAtomicSeal::from_height(0),
            registration_block: 0,
            governance_level: PrecedenceLevel::Meaning,
            norm_set: BTreeSet::new(),
            responsibility: ResponsibilityState::default(),
        };

        let start = Instant::now();
        for i in 1..=count {
            let tx = create_bench_tx(&agent2, &key2, i as u128);
            chain2.submit_transition(tx).unwrap_or_else(|e| {
                panic!("submit #{} failed at height {}: {}", i, chain2.height(), e)
            });
            chain2
                .produce_block()
                .unwrap_or_else(|e| panic!("block #{} failed: {}", i, e));
        }
        let elapsed = start.elapsed();
        println!(
            "Sustained   {:>5} blocks:           {:>8.2?}  ({:>6.0} blocks/s, {:>6.0} tx/s)",
            count,
            elapsed,
            count as f64 / elapsed.as_secs_f64(),
            count as f64 / elapsed.as_secs_f64(),
        );
    }


    // 4c. Batched blocks: submit N txs from one agent, produce 1 block.
    //     Tests multi-tx block packing (requires batch nonce fix).
    let batch_sizes = [10, 50, 100];
    for &batch in &batch_sizes {
        let mut chain3 = Chain::init();
        chain3.governance_limits.max_consecutive_proposals = 10_000;
        chain3.mempool.containment.hostility_threshold = TensionValue::from_integer(1_000_000);

        let key3 = chain3.validator_key.clone();
        let pk3 = *key3.verifying_key().as_bytes();
        let agent_id3 = sccgub_state::apply::validator_spend_account(chain3.block_version, &pk3);
        let agent3 = AgentIdentity {
            agent_id: agent_id3,
            public_key: pk3,
            mfidel_seal: MfidelAtomicSeal::from_height(0),
            registration_block: 0,
            governance_level: PrecedenceLevel::Meaning,
            norm_set: BTreeSet::new(),
            responsibility: ResponsibilityState::default(),
        };

        for i in 1..=batch {
            let tx = create_bench_tx(&agent3, &key3, i as u128);
            chain3
                .submit_transition(tx)
                .unwrap_or_else(|e| panic!("submit #{} failed: {}", i, e));
        }

        let start = Instant::now();
        let block = chain3
            .produce_block()
            .unwrap_or_else(|e| panic!("batch block failed: {}", e))
            .clone();
        let elapsed = start.elapsed();

        let included = block.body.transitions.len();
        println!(
            "Batch block {:>5} txs, {:>5} included: {:>8.2?}  ({:>8.0} tx/s effective)",
            batch,
            included,
            elapsed,
            included as f64 / elapsed.as_secs_f64(),
        );
    }
    println!();

    // ---------------------------------------------------------------
    // 5. Chain replay (from_blocks) throughput
    // ---------------------------------------------------------------
    println!("--- Chain Replay (from_blocks) ---");
    {
        let mut source = Chain::init();
        source.governance_limits.max_consecutive_proposals = 10_000;
        source.mempool.containment.hostility_threshold = TensionValue::from_integer(1_000_000);

        let skey = source.validator_key.clone();
        let spk = *skey.verifying_key().as_bytes();
        let sagent_id = sccgub_state::apply::validator_spend_account(source.block_version, &spk);
        let sagent = AgentIdentity {
            agent_id: sagent_id,
            public_key: spk,
            mfidel_seal: MfidelAtomicSeal::from_height(0),
            registration_block: 0,
            governance_level: PrecedenceLevel::Meaning,
            norm_set: BTreeSet::new(),
            responsibility: ResponsibilityState::default(),
        };

        let replay_blocks = 200;
        for i in 1..=replay_blocks {
            let tx = create_bench_tx(&sagent, &skey, i as u128);
            source
                .submit_transition(tx)
                .unwrap_or_else(|e| panic!("submit #{} failed: {}", i, e));
            source
                .produce_block()
                .unwrap_or_else(|e| panic!("block #{} failed: {}", i, e));
        }

        let blocks = source.blocks.clone();
        let block_count = blocks.len();

        let start = Instant::now();
        let replayed = Chain::from_blocks(blocks).expect("replay should succeed");
        let elapsed = start.elapsed();

        assert_eq!(replayed.height(), source.height());
        println!(
            "Replay {:>5} blocks (1 tx each): {:>8.2?}  ({:>6.0} blocks/s)",
            block_count,
            elapsed,
            block_count as f64 / elapsed.as_secs_f64(),
        );
    }
    println!();

    // ---------------------------------------------------------------
    // 6. Snapshot create + restore
    // ---------------------------------------------------------------
    println!("--- Snapshot Create + Restore ---");
    {
        let start = Instant::now();
        let snapshot = chain.create_snapshot();
        let create_elapsed = start.elapsed();

        let start = Instant::now();
        let mut restored = Chain::init();
        restored.restore_from_snapshot(&snapshot);
        let restore_elapsed = start.elapsed();

        println!(
            "Snapshot create: {:>8.2?}  (chain height {})",
            create_elapsed,
            chain.height()
        );
        println!("Snapshot restore: {:>8.2?}", restore_elapsed);
    }

    println!("\n=== Benchmark complete ===");
}
