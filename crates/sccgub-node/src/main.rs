mod chain;
mod mempool;
mod persistence;

use clap::{Parser, Subcommand};
use std::collections::HashSet;

use sccgub_crypto::hash::blake3_hash;
use sccgub_crypto::keys::generate_keypair;
use sccgub_crypto::signature::sign;
use sccgub_types::governance::PrecedenceLevel;
use sccgub_types::mfidel::MfidelAtomicSeal;
use sccgub_types::timestamp::CausalTimestamp;
use sccgub_types::transition::*;
use sccgub_types::agent::{AgentIdentity, ResponsibilityState};

use chain::Chain;

#[derive(Parser)]
#[command(name = "sccgub")]
#[command(about = "Symbolic Causal Chain General Universal Blockchain — Node CLI")]
#[command(version = "0.1.0")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize a new chain with genesis block.
    Init,
    /// Run a demo: create genesis, submit transactions, produce blocks.
    Demo,
    /// Show information about the chain/spec.
    Info,
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Init => cmd_init(),
        Commands::Demo => cmd_demo(),
        Commands::Info => cmd_info(),
    }
}

fn cmd_init() {
    let chain = Chain::init();
    let genesis = chain.latest_block().unwrap();
    println!("Chain initialized.");
    println!("  Chain ID:      {}", hex::encode(chain.chain_id));
    println!("  Genesis block: {}", hex::encode(genesis.header.block_id));
    println!(
        "  Mfidel seal:   f[{}][{}]",
        genesis.header.mfidel_seal.row, genesis.header.mfidel_seal.column
    );
    println!("  State root:    {}", hex::encode(genesis.header.state_root));
    println!("  Height:        {}", genesis.header.height);
}

fn cmd_demo() {
    println!("=== SCCGUB Demo ===\n");

    // 1. Initialize chain.
    let mut chain = Chain::init();
    let genesis = chain.latest_block().unwrap();
    println!("[Genesis] Block #{}", genesis.header.height);
    println!("  ID:         {}", hex::encode(genesis.header.block_id));
    println!(
        "  Mfidel:     f[{}][{}]",
        genesis.header.mfidel_seal.row, genesis.header.mfidel_seal.column
    );
    println!();

    // 2. Create an agent and submit transitions.
    let agent_key = generate_keypair();
    let agent_pk = *agent_key.verifying_key().as_bytes();
    let agent_id = blake3_hash(&agent_pk);

    let agent = AgentIdentity {
        agent_id,
        public_key: agent_pk,
        mfidel_seal: MfidelAtomicSeal::from_height(1),
        registration_block: 0,
        governance_level: PrecedenceLevel::Meaning,
        norm_set: HashSet::new(),
        responsibility: ResponsibilityState::default(),
    };

    // Submit 3 transitions.
    for i in 0..3 {
        let tx = create_test_transition(&agent, &agent_key, i);
        println!("[Submit] Transition #{}: {}", i, hex::encode(tx.tx_id));
        chain.submit_transition(tx);
    }
    println!();

    // 3. Produce a block.
    match chain.produce_block() {
        Ok(block) => {
            println!("[Block #{}] Produced!", block.header.height);
            println!("  ID:         {}", hex::encode(block.header.block_id));
            println!("  Parent:     {}", hex::encode(block.header.parent_id));
            println!("  Txs:        {}", block.body.transition_count);
            println!(
                "  Mfidel:     f[{}][{}]",
                block.header.mfidel_seal.row, block.header.mfidel_seal.column
            );
            println!("  State root: {}", hex::encode(block.header.state_root));
            println!("  Tension:    {} -> {}", block.header.tension_before, block.header.tension_after);
        }
        Err(e) => {
            println!("[Error] Failed to produce block: {}", e);
        }
    }
    println!();

    // 4. Show chain summary.
    println!("=== Chain Summary ===");
    println!("  Height:       {}", chain.height());
    println!("  Total blocks: {}", chain.blocks.len());
    println!("  Mempool:      {} pending", chain.mempool.len());
    for (i, block) in chain.blocks.iter().enumerate() {
        println!(
            "  Block #{}: {} (txs: {}, seal: f[{}][{}])",
            i,
            hex::encode(block.header.block_id),
            block.body.transition_count,
            block.header.mfidel_seal.row,
            block.header.mfidel_seal.column
        );
    }
}

fn cmd_info() {
    println!("Symbolic Causal Chain General Universal Blockchain (SCCGUB)");
    println!("Version: 0.1.0 (MVP — v2.1 spec)");
    println!();
    println!("Architecture:");
    println!("  Consensus:   Causal Proof-of-Governance (CPoG)");
    println!("  Finality:    Deterministic (immediate, no forks)");
    println!("  Validation:  13-phase Phi traversal");
    println!("  Contracts:   Symbolic Causal Contracts (decidable)");
    println!("  State:       Tension-governed symbol mesh");
    println!("  Identity:    Mfidel 34x8 Ge'ez atomic seal");
    println!("  Governance:  Phi^2-enforced precedence order");
    println!("  Arithmetic:  Fixed-point (i128, 18 decimals)");
    println!();
    println!("Precedence Order:");
    println!("  0 GENESIS      (immutable chain axioms)");
    println!("  1 SAFETY       (chain survival)");
    println!("  2 MEANING      (semantic integrity)");
    println!("  3 EMOTION      (value alignment)");
    println!("  4 OPTIMIZATION (performance tuning)");
    println!();
    println!("Invariants enforced:");
    println!("  INV-1:  No block without valid CPoG");
    println!("  INV-2:  No state change without Phi traversal");
    println!("  INV-3:  No governance change below MEANING precedence");
    println!("  INV-4:  No fork (deterministic finality)");
    println!("  INV-5:  No unbounded tension growth");
    println!("  INV-6:  No identity mutation post-genesis");
    println!("  INV-7:  No transition without complete WHBinding");
    println!("  INV-8:  No contract beyond decidability bound");
    println!("  INV-13: |Sigma R_i_net| <= R_max_imbalance");
    println!("  INV-17: Causal graph acyclicity");
}

fn create_test_transition(
    agent: &AgentIdentity,
    agent_key: &ed25519_dalek::SigningKey,
    index: u8,
) -> SymbolicTransition {
    let key = format!("test/key/{}", index).into_bytes();
    let value = format!("value_{}", index).into_bytes();

    let intent = WHBindingIntent {
        who: agent.agent_id,
        when: CausalTimestamp::genesis(),
        r#where: key.clone(),
        why: CausalJustification {
            invoking_rule: blake3_hash(b"test-rule"),
            precedence_level: PrecedenceLevel::Meaning,
            causal_ancestors: vec![],
            constraint_proof: vec![],
        },
        how: TransitionMechanism::DirectStateWrite,
        which: HashSet::new(),
        what_declared: format!("Write test data #{}", index),
    };

    let payload = OperationPayload::Write {
        key: key.clone(),
        value: value.clone(),
    };

    let tx_data = serde_json::to_vec(&(&agent.agent_id, &key, &value, index)).unwrap_or_default();
    let tx_id = blake3_hash(&tx_data);
    let signature = sign(agent_key, &tx_data);

    SymbolicTransition {
        tx_id,
        actor: agent.clone(),
        intent: TransitionIntent {
            kind: TransitionKind::StateWrite,
            target: key,
            declared_purpose: format!("Test write #{}", index),
        },
        preconditions: vec![],
        postconditions: vec![],
        payload,
        causal_chain: vec![],
        wh_binding_intent: intent,
        nonce: index as u128,
        signature,
    }
}
