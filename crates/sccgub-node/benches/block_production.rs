use std::collections::HashSet;
use std::time::Instant;

use sccgub_crypto::hash::blake3_hash;
use sccgub_crypto::keys::generate_keypair;
use sccgub_crypto::signature::sign;
use sccgub_execution::validate::canonical_tx_bytes;
use sccgub_state::world::ManagedWorldState;
use sccgub_types::agent::{AgentIdentity, ResponsibilityState};
use sccgub_types::governance::PrecedenceLevel;
use sccgub_types::mfidel::MfidelAtomicSeal;
use sccgub_types::timestamp::CausalTimestamp;
use sccgub_types::transition::*;

fn create_bench_tx(
    agent: &AgentIdentity,
    key: &ed25519_dalek::SigningKey,
    nonce: u128,
) -> SymbolicTransition {
    let target = format!("bench/tx/{}", nonce).into_bytes();
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
        which: HashSet::new(),
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
        &serde_json::to_vec(&seal).unwrap(),
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

    // Benchmark: transaction creation + signing.
    let counts = [10, 100, 500, 1000];
    for &count in &counts {
        let start = Instant::now();
        let txs: Vec<_> = (1..=count)
            .map(|i| create_bench_tx(&agent, &agent_key, i as u128))
            .collect();
        let elapsed = start.elapsed();
        println!(
            "Create+sign {} txs: {:?} ({:.0} tx/s)",
            count,
            elapsed,
            count as f64 / elapsed.as_secs_f64()
        );

        // Benchmark: transaction validation.
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
            "Validate    {} txs: {:?} ({:.0} tx/s, {} valid)",
            count,
            elapsed,
            count as f64 / elapsed.as_secs_f64(),
            valid
        );
        println!();
    }

    // Benchmark: Merkle root computation.
    for &count in &counts {
        let leaves: Vec<[u8; 32]> = (0..count).map(|i| blake3_hash(&(i as u64).to_le_bytes())).collect();
        let start = Instant::now();
        let _root = sccgub_crypto::merkle::compute_merkle_root(&leaves);
        let elapsed = start.elapsed();
        println!("Merkle root {} leaves: {:?}", count, elapsed);
    }
}
