mod chain;
mod mempool;
mod persistence;

use std::collections::HashSet;
use std::path::PathBuf;

use clap::{Parser, Subcommand};

use sccgub_crypto::hash::blake3_hash;
use sccgub_crypto::keys::generate_keypair;
use sccgub_crypto::signature::sign;
use sccgub_types::agent::{AgentIdentity, ResponsibilityState};
use sccgub_types::governance::PrecedenceLevel;
use sccgub_types::mfidel::MfidelAtomicSeal;
use sccgub_types::timestamp::CausalTimestamp;
use sccgub_types::transition::*;

use chain::Chain;
use persistence::ChainStore;

const DEFAULT_DATA_DIR: &str = ".sccgub";

#[derive(Parser)]
#[command(name = "sccgub")]
#[command(about = "Symbolic Causal Chain General Universal Blockchain — Node CLI")]
#[command(version = "0.1.0")]
struct Cli {
    /// Data directory for chain storage.
    #[arg(long, default_value = DEFAULT_DATA_DIR)]
    data_dir: PathBuf,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize a new chain with genesis block and save to disk.
    Init,
    /// Load chain from disk, submit test transactions, produce a block, and save.
    Produce {
        /// Number of test transactions to include.
        #[arg(short, long, default_value = "3")]
        txs: u32,
    },
    /// Show a specific block by height.
    ShowBlock {
        /// Block height to display.
        height: u64,
    },
    /// Show the current chain summary.
    Status,
    /// Show the current world state entries.
    ShowState,
    /// Verify the entire chain by replaying and re-validating all blocks.
    Verify,
    /// Run the full demo (init + produce + status) in-memory.
    Demo,
    /// Show information about the chain/spec.
    Info,
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Init => cmd_init(&cli.data_dir),
        Commands::Produce { txs } => cmd_produce(&cli.data_dir, txs),
        Commands::ShowBlock { height } => cmd_show_block(&cli.data_dir, height),
        Commands::Status => cmd_status(&cli.data_dir),
        Commands::ShowState => cmd_show_state(&cli.data_dir),
        Commands::Verify => cmd_verify(&cli.data_dir),
        Commands::Demo => cmd_demo(),
        Commands::Info => cmd_info(),
    }
}

fn cmd_init(data_dir: &std::path::Path) {
    let store = match ChainStore::new(data_dir) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Failed to create data directory: {}", e);
            std::process::exit(1);
        }
    };

    // Check if chain already exists.
    if store.load_block(0).is_ok() {
        eprintln!("Chain already initialized at {:?}. Delete the directory to reinitialize.", data_dir);
        std::process::exit(1);
    }

    let chain = Chain::init();
    let genesis = chain.latest_block().unwrap();

    store.save_block(genesis).expect("Failed to save genesis block");
    store.save_metadata(&chain.chain_id).expect("Failed to save metadata");

    println!("Chain initialized at {:?}", data_dir);
    println!("  Chain ID:      {}", hex::encode(chain.chain_id));
    println!("  Genesis block: {}", hex::encode(genesis.header.block_id));
    println!(
        "  Mfidel seal:   f[{}][{}] (vowel origin)",
        genesis.header.mfidel_seal.row, genesis.header.mfidel_seal.column
    );
    println!("  State root:    {}", hex::encode(genesis.header.state_root));
}

fn cmd_produce(data_dir: &std::path::Path, num_txs: u32) {
    let store = match ChainStore::new(data_dir) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Failed to open data directory: {}", e);
            std::process::exit(1);
        }
    };

    // Load existing chain.
    let blocks = match store.load_all_blocks() {
        Ok(b) if !b.is_empty() => b,
        _ => {
            eprintln!("No chain found. Run `sccgub init` first.");
            std::process::exit(1);
        }
    };

    let mut chain = Chain::from_blocks(blocks);

    // Create a test agent with correctly derived agent_id.
    let agent_key = generate_keypair();
    let agent_pk = *agent_key.verifying_key().as_bytes();
    let seal = MfidelAtomicSeal::from_height(chain.height() + 1);
    let agent_id = sccgub_crypto::hash::blake3_hash_concat(&[
        &agent_pk,
        &serde_json::to_vec(&seal).unwrap(),
    ]);

    let agent = AgentIdentity {
        agent_id,
        public_key: agent_pk,
        mfidel_seal: seal,
        registration_block: chain.height(),
        governance_level: PrecedenceLevel::Meaning,
        norm_set: HashSet::new(),
        responsibility: ResponsibilityState::default(),
    };

    let current_height = chain.height();
    for i in 0..num_txs {
        let tx = create_test_transition(&agent, &agent_key, i, current_height);
        chain.submit_transition(tx);
    }
    println!("Submitted {} transitions to mempool.", num_txs);

    match chain.produce_block() {
        Ok(block) => {
            store.save_block(block).expect("Failed to save block");
            println!("Block #{} produced and saved.", block.header.height);
            print_block_summary(block);
        }
        Err(e) => {
            eprintln!("Failed to produce block: {}", e);
            std::process::exit(1);
        }
    }
}

fn cmd_show_block(data_dir: &std::path::Path, height: u64) {
    let store = match ChainStore::new(data_dir) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Failed to open data directory: {}", e);
            std::process::exit(1);
        }
    };

    match store.load_block(height) {
        Ok(block) => {
            println!("Block #{}", block.header.height);
            println!("  Block ID:       {}", hex::encode(block.header.block_id));
            println!("  Parent ID:      {}", hex::encode(block.header.parent_id));
            println!("  Chain ID:       {}", hex::encode(block.header.chain_id));
            println!(
                "  Mfidel seal:    f[{}][{}]",
                block.header.mfidel_seal.row, block.header.mfidel_seal.column
            );
            println!("  State root:     {}", hex::encode(block.header.state_root));
            println!("  Transition root:{}", hex::encode(block.header.transition_root));
            println!("  Tension:        {} -> {}", block.header.tension_before, block.header.tension_after);
            println!("  Validator:      {}", hex::encode(block.header.validator_id));
            println!("  Version:        {}", block.header.version);
            println!("  Lamport clock:  {}", block.header.timestamp.lamport_counter);
            println!("  Causal depth:   {}", block.header.timestamp.causal_depth);
            println!("  Transitions:    {}", block.body.transition_count);
            for (i, tx) in block.body.transitions.iter().enumerate() {
                println!("    [{}] {} (kind: {:?})", i, hex::encode(tx.tx_id), tx.intent.kind);
                println!("        target: {}", String::from_utf8_lossy(&tx.intent.target));
                println!("        purpose: {}", tx.intent.declared_purpose);
            }
            println!("  Receipts:       {}", block.receipts.len());
            println!("  Governance:     emergency={}, norms={}", block.governance.emergency_mode, block.governance.active_norm_count);
            println!("  Proof depth:    {}", block.proof.recursion_depth);
        }
        Err(e) => {
            eprintln!("Block #{} not found: {}", height, e);
            std::process::exit(1);
        }
    }
}

fn cmd_status(data_dir: &std::path::Path) {
    let store = match ChainStore::new(data_dir) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Failed to open data directory: {}", e);
            std::process::exit(1);
        }
    };

    let blocks = match store.load_all_blocks() {
        Ok(b) => b,
        Err(e) => {
            eprintln!("Failed to load chain: {}", e);
            std::process::exit(1);
        }
    };

    if blocks.is_empty() {
        println!("No chain found. Run `sccgub init` first.");
        return;
    }

    let latest = blocks.last().unwrap();
    let total_txs: u64 = blocks.iter().map(|b| b.body.transition_count as u64).sum();

    println!("=== SCCGUB Chain Status ===");
    println!("  Data dir:       {:?}", data_dir);
    println!("  Chain ID:       {}", hex::encode(latest.header.chain_id));
    println!("  Height:         {}", latest.header.height);
    println!("  Total blocks:   {}", blocks.len());
    println!("  Total txs:      {}", total_txs);
    println!("  Latest block:   {}", hex::encode(latest.header.block_id));
    println!("  State root:     {}", hex::encode(latest.header.state_root));
    println!("  Tension:        {}", latest.header.tension_after);
    println!(
        "  Mfidel seal:    f[{}][{}] (cycle {})",
        latest.header.mfidel_seal.row,
        latest.header.mfidel_seal.column,
        MfidelAtomicSeal::cycle_number(latest.header.height)
    );
    println!("  Finality:       {:?}", latest.governance.finality_mode);
    println!("  Emergency mode: {}", latest.governance.emergency_mode);
    println!();
    println!("  Block history:");
    for block in &blocks {
        println!(
            "    #{:>4}  {}  txs:{:<3}  seal:f[{:>2}][{}]  tension:{}",
            block.header.height,
            &hex::encode(block.header.block_id)[..16],
            block.body.transition_count,
            block.header.mfidel_seal.row,
            block.header.mfidel_seal.column,
            block.header.tension_after,
        );
    }
}

fn cmd_show_state(data_dir: &std::path::Path) {
    let store = match ChainStore::new(data_dir) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Failed to open data directory: {}", e);
            std::process::exit(1);
        }
    };

    let blocks = match store.load_all_blocks() {
        Ok(b) => b,
        Err(e) => {
            eprintln!("Failed to load chain: {}", e);
            std::process::exit(1);
        }
    };

    if blocks.is_empty() {
        println!("No chain found. Run `sccgub init` first.");
        return;
    }

    // Replay all blocks to reconstruct state.
    let mut state = sccgub_state::world::ManagedWorldState::new();
    for block in &blocks {
        for tx in &block.body.transitions {
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
    }

    println!("=== World State (height {}) ===", blocks.last().unwrap().header.height);
    println!("  State root: {}", hex::encode(state.state_root()));
    println!("  Entries:    {}", state.trie.len());
    println!();

    for (key, value) in state.trie.iter() {
        let key_str = String::from_utf8_lossy(key);
        let value_str = String::from_utf8_lossy(value);
        println!("  {} = {}", key_str, value_str);
    }
}

fn cmd_verify(data_dir: &std::path::Path) {
    let store = match ChainStore::new(data_dir) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Failed to open data directory: {}", e);
            std::process::exit(1);
        }
    };

    let blocks = match store.load_all_blocks() {
        Ok(b) if !b.is_empty() => b,
        _ => {
            eprintln!("No chain found. Run `sccgub init` first.");
            std::process::exit(1);
        }
    };

    println!("=== Chain Verification ===");
    println!("  Verifying {} blocks...\n", blocks.len());

    let mut state = sccgub_state::world::ManagedWorldState::new();
    state.state.governance_state = sccgub_types::governance::GovernanceState {
        finality_mode: sccgub_types::governance::FinalityMode::Deterministic,
        ..Default::default()
    };

    let mut errors = 0u32;

    for (i, block) in blocks.iter().enumerate() {
        let parent_id = if i == 0 {
            sccgub_types::ZERO_HASH
        } else {
            blocks[i - 1].header.block_id
        };

        // Check structural validity.
        if !block.is_structurally_valid() {
            println!("  [FAIL] Block #{}: structural validation failed", block.header.height);
            errors += 1;
            continue;
        }

        // Run full CPoG validation.
        let result = sccgub_execution::cpog::validate_cpog(block, &state, &parent_id);
        match result {
            sccgub_execution::cpog::CpogResult::Valid => {
                let seal = &block.header.mfidel_seal;
                println!(
                    "  [OK]   Block #{:>4}  txs:{:<3}  seal:f[{:>2}][{}]  receipts:{}",
                    block.header.height,
                    block.body.transition_count,
                    seal.row,
                    seal.column,
                    block.receipts.len(),
                );
            }
            sccgub_execution::cpog::CpogResult::Invalid { errors: errs } => {
                println!(
                    "  [FAIL] Block #{}: CPoG validation failed",
                    block.header.height
                );
                for err in &errs {
                    println!("         - {}", err);
                }
                errors += 1;
            }
        }

        // Replay state.
        for tx in &block.body.transitions {
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
        state.set_height(block.header.height);
    }

    println!();
    if errors == 0 {
        println!("  Verification PASSED: all {} blocks valid.", blocks.len());
        println!("  Final state root: {}", hex::encode(state.state_root()));
        println!("  Final height:     {}", state.state.height);
    } else {
        println!("  Verification FAILED: {} block(s) invalid.", errors);
        std::process::exit(1);
    }
}

fn cmd_demo() {
    println!("=== SCCGUB Demo ===\n");

    let mut chain = Chain::init();
    let genesis = chain.latest_block().unwrap();
    println!("[Genesis] Block #{}", genesis.header.height);
    println!("  ID:     {}", hex::encode(genesis.header.block_id));
    println!(
        "  Mfidel: f[{}][{}]",
        genesis.header.mfidel_seal.row, genesis.header.mfidel_seal.column
    );
    println!();

    let agent_key = generate_keypair();
    let agent_pk = *agent_key.verifying_key().as_bytes();
    let seal = MfidelAtomicSeal::from_height(1);
    let agent_id = sccgub_crypto::hash::blake3_hash_concat(&[
        &agent_pk,
        &serde_json::to_vec(&seal).unwrap(),
    ]);
    let agent = AgentIdentity {
        agent_id,
        public_key: agent_pk,
        mfidel_seal: seal,
        registration_block: 0,
        governance_level: PrecedenceLevel::Meaning,
        norm_set: HashSet::new(),
        responsibility: ResponsibilityState::default(),
    };

    for i in 0..3 {
        let tx = create_test_transition(&agent, &agent_key, i, 0);
        println!("[Submit] Tx #{}: {}", i, hex::encode(tx.tx_id));
        chain.submit_transition(tx);
    }
    println!();

    match chain.produce_block() {
        Ok(block) => {
            print_block_summary(block);
        }
        Err(e) => {
            eprintln!("[Error] {}", e);
        }
    }
    println!();

    println!("=== Chain Summary ===");
    println!("  Height: {}, Blocks: {}, Mempool: {}", chain.height(), chain.blocks.len(), chain.mempool.len());
    for block in &chain.blocks {
        println!(
            "  #{}: {} (txs:{}, seal:f[{}][{}])",
            block.header.height,
            &hex::encode(block.header.block_id)[..16],
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
    println!("Security Invariants:");
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

fn print_block_summary(block: &sccgub_types::block::Block) {
    println!("[Block #{}]", block.header.height);
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

fn create_test_transition(
    agent: &AgentIdentity,
    agent_key: &ed25519_dalek::SigningKey,
    index: u32,
    base_height: u64,
) -> SymbolicTransition {
    let key = format!("data/h{}/entry/{}", base_height + 1, index).into_bytes();
    let value = format!("value_{}", index).into_bytes();

    let intent = WHBindingIntent {
        who: agent.agent_id,
        when: CausalTimestamp::genesis(),
        r#where: key.clone(),
        why: CausalJustification {
            invoking_rule: blake3_hash(b"state-write-rule"),
            precedence_level: PrecedenceLevel::Meaning,
            causal_ancestors: vec![],
            constraint_proof: vec![],
        },
        how: TransitionMechanism::DirectStateWrite,
        which: HashSet::new(),
        what_declared: format!("Write entry #{}", index),
    };

    let payload = OperationPayload::Write {
        key: key.clone(),
        value: value.clone(),
    };

    let nonce = (base_height * 1000 + index as u64) as u128 + 1; // Unique, monotonically increasing.

    // Build tx first (without signature), then compute canonical bytes and sign.
    let mut tx = SymbolicTransition {
        tx_id: [0u8; 32],
        actor: agent.clone(),
        intent: TransitionIntent {
            kind: TransitionKind::StateWrite,
            target: key,
            declared_purpose: format!("Write entry #{}", index),
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
    tx.signature = sign(agent_key, &canonical);
    tx
}
