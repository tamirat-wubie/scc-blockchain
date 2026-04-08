mod chain;
pub mod config;
mod mempool;
mod observability;
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
#[command(version = "0.2.0")]
struct Cli {
    /// Data directory for chain storage.
    #[arg(long, default_value = DEFAULT_DATA_DIR)]
    data_dir: PathBuf,

    /// Validator key passphrase (or set SCCGUB_PASSPHRASE env var).
    #[arg(long, env = "SCCGUB_PASSPHRASE", default_value = "")]
    passphrase: String,

    /// Path to TOML configuration file.
    #[arg(long, default_value = "sccgub.toml")]
    config: PathBuf,

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
    /// Search for a transaction by its ID (hex prefix).
    SearchTx {
        /// Transaction ID prefix (hex).
        prefix: String,
    },
    /// Export the entire chain to a single JSON file.
    Export {
        /// Output file path.
        output: std::path::PathBuf,
    },
    /// Import a chain from an exported JSON file.
    Import {
        /// Input file path.
        input: std::path::PathBuf,
    },
    /// Transfer tokens from the validator to a new agent and produce a block.
    Transfer {
        /// Amount to transfer (integer tokens).
        amount: u64,
    },
    /// Show chain economics: total supply, accounts, fees.
    Stats,
    /// Show the balance of a specific agent (by hex ID prefix).
    Balance {
        /// Agent ID (hex, can be prefix).
        agent: String,
    },
    /// Show chain health report (metrics, performance, security).
    Health,
    /// Start the REST API server.
    Serve {
        /// Port to listen on.
        #[arg(short, long, default_value = "3000")]
        port: u16,
    },
    /// Run the full demo (init + produce + status) in-memory.
    Demo,
    /// Show information about the chain/spec.
    Info,
    /// Show treasury status (fees collected, rewards distributed, pending).
    Treasury,
    /// Show escrow registry summary.
    Escrow,
}

#[tokio::main]
async fn main() {
    // Initialize structured logging.
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("sccgub=info".parse().unwrap()),
        )
        .init();

    let cli = Cli::parse();

    let passphrase = &cli.passphrase;

    match cli.command {
        Commands::Init => cmd_init(&cli.data_dir, passphrase),
        Commands::Produce { txs } => cmd_produce(&cli.data_dir, txs, passphrase),
        Commands::ShowBlock { height } => cmd_show_block(&cli.data_dir, height),
        Commands::Status => cmd_status(&cli.data_dir),
        Commands::ShowState => cmd_show_state(&cli.data_dir),
        Commands::Verify => cmd_verify(&cli.data_dir),
        Commands::SearchTx { prefix } => cmd_search_tx(&cli.data_dir, &prefix),
        Commands::Export { output } => cmd_export(&cli.data_dir, &output),
        Commands::Import { input } => cmd_import(&cli.data_dir, &input),
        Commands::Transfer { amount } => cmd_transfer(&cli.data_dir, amount, passphrase),
        Commands::Stats => cmd_stats(&cli.data_dir),
        Commands::Balance { agent } => cmd_balance(&cli.data_dir, &agent),
        Commands::Health => cmd_health(&cli.data_dir),
        Commands::Serve { port } => cmd_serve(&cli.data_dir, port).await,
        Commands::Demo => cmd_demo(),
        Commands::Info => cmd_info(),
        Commands::Treasury => cmd_treasury(&cli.data_dir),
        Commands::Escrow => cmd_escrow(&cli.data_dir),
    }
}

/// Replay blocks to reconstruct full state (single source of truth).
/// Used by: cmd_verify, cmd_stats, cmd_health, cmd_serve, cmd_balance.
fn replay_chain_state(
    blocks: &[sccgub_types::block::Block],
) -> (
    sccgub_state::world::ManagedWorldState,
    sccgub_state::balances::BalanceLedger,
) {
    let mut state = sccgub_state::world::ManagedWorldState::new();
    let mut balances = sccgub_state::balances::BalanceLedger::new();
    if let Some(genesis) = blocks.first() {
        sccgub_state::apply::apply_genesis_mint(
            &mut state,
            &mut balances,
            &genesis.header.validator_id,
        );
    }
    for block in blocks {
        sccgub_state::apply::apply_block_transitions(
            &mut state,
            &mut balances,
            &block.body.transitions,
        );
        for tx in &block.body.transitions {
            if let Err(e) = state.check_nonce(&tx.actor.agent_id, tx.nonce) {
                tracing::warn!("Nonce error during replay: {}", e);
            }
        }
        state.set_height(block.header.height);
    }
    (state, balances)
}

fn cmd_init(data_dir: &std::path::Path, passphrase: &str) {
    let store = match ChainStore::new(data_dir) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Failed to create data directory: {}", e);
            std::process::exit(1);
        }
    };

    // Check if chain already exists.
    if store.load_block(0).is_ok() {
        eprintln!(
            "Chain already initialized at {:?}. Delete the directory to reinitialize.",
            data_dir
        );
        std::process::exit(1);
    }

    let chain = Chain::init();
    let genesis = chain.latest_block().unwrap();

    store
        .save_block(genesis)
        .expect("Failed to save genesis block");
    store
        .save_metadata(&chain.chain_id)
        .expect("Failed to save metadata");
    store
        .save_validator_key(&chain.validator_key, passphrase)
        .expect("Failed to save validator key");

    println!("Chain initialized at {:?}", data_dir);
    println!("  Chain ID:      {}", hex::encode(chain.chain_id));
    println!("  Genesis block: {}", hex::encode(genesis.header.block_id));
    println!(
        "  Mfidel seal:   f[{}][{}] (vowel origin)",
        genesis.header.mfidel_seal.row, genesis.header.mfidel_seal.column
    );
    println!(
        "  State root:    {}",
        hex::encode(genesis.header.state_root)
    );
}

fn cmd_produce(data_dir: &std::path::Path, num_txs: u32, passphrase: &str) {
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

    // Try to restore from snapshot for faster loading.
    if let Ok(Some(snapshot)) = store.load_latest_snapshot() {
        if snapshot.height == chain.height() {
            chain.restore_from_snapshot(&snapshot);
        }
    }

    // Load persisted validator key if available.
    if store.has_validator_key() {
        match store.load_validator_key(passphrase) {
            Ok(key) => chain.set_validator_key(key),
            Err(e) => eprintln!("Warning: could not load validator key: {}", e),
        }
    }

    // Create a test agent with correctly derived agent_id.
    let agent_key = generate_keypair();
    let agent_pk = *agent_key.verifying_key().as_bytes();
    let seal = MfidelAtomicSeal::from_height(chain.height() + 1);
    let agent_id = sccgub_crypto::hash::blake3_hash_concat(&[
        &agent_pk,
        &sccgub_crypto::canonical::canonical_bytes(&seal),
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
        if let Err(e) = chain.submit_transition(tx) {
            tracing::warn!("Transaction rejected: {}", e);
        }
    }
    println!("Submitted {} transitions to mempool.", num_txs);

    let produced_height = match chain.produce_block() {
        Ok(block) => {
            store.save_block(block).expect("Failed to save block");
            println!("Block #{} produced and saved.", block.header.height);
            print_block_summary(block);
            block.header.height
        }
        Err(e) => {
            eprintln!("Failed to produce block: {}", e);
            std::process::exit(1);
        }
    };

    // Save state snapshot every 10 blocks for fast reload.
    if produced_height % 10 == 0 && produced_height > 0 {
        let snapshot = chain.create_snapshot();
        store
            .save_snapshot(&snapshot)
            .expect("Failed to save snapshot");
        println!("  Snapshot saved at height {}.", produced_height);
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
            println!(
                "  Transition root:{}",
                hex::encode(block.header.transition_root)
            );
            println!(
                "  Tension:        {} -> {}",
                block.header.tension_before, block.header.tension_after
            );
            println!(
                "  Validator:      {}",
                hex::encode(block.header.validator_id)
            );
            println!("  Version:        {}", block.header.version);
            println!(
                "  Lamport clock:  {}",
                block.header.timestamp.lamport_counter
            );
            println!("  Causal depth:   {}", block.header.timestamp.causal_depth);
            println!("  Transitions:    {}", block.body.transition_count);
            for (i, tx) in block.body.transitions.iter().enumerate() {
                println!(
                    "    [{}] {} (kind: {:?})",
                    i,
                    hex::encode(tx.tx_id),
                    tx.intent.kind
                );
                println!(
                    "        target: {}",
                    String::from_utf8_lossy(&tx.intent.target)
                );
                println!("        purpose: {}", tx.intent.declared_purpose);
            }
            println!("  Receipts:       {}", block.receipts.len());
            println!(
                "  Governance:     emergency={}, norms={}",
                block.governance.emergency_mode, block.governance.active_norm_count
            );
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
    println!(
        "  State root:     {}",
        hex::encode(latest.header.state_root)
    );
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

    // Replay all blocks using shared apply function (single source of truth).
    let mut state = sccgub_state::world::ManagedWorldState::new();
    let mut balances = sccgub_state::balances::BalanceLedger::new();
    if let Some(genesis) = blocks.first() {
        sccgub_state::apply::apply_genesis_mint(
            &mut state,
            &mut balances,
            &genesis.header.validator_id,
        );
    }
    for block in &blocks {
        sccgub_state::apply::apply_block_transitions(
            &mut state,
            &mut balances,
            &block.body.transitions,
        );
    }

    println!(
        "=== World State (height {}) ===",
        blocks.last().unwrap().header.height
    );
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

    // Write genesis balance into trie (mirrors chain.rs init).
    if let Some(genesis) = blocks.first() {
        let balance_key =
            format!("balance/{}", hex::encode(genesis.header.validator_id)).into_bytes();
        state.apply_delta(&sccgub_types::transition::StateDelta {
            writes: vec![sccgub_types::transition::StateWrite {
                address: balance_key,
                value: sccgub_types::tension::TensionValue::from_integer(1_000_000)
                    .raw()
                    .to_le_bytes()
                    .to_vec(),
            }],
            deletes: vec![],
        });
    }

    let mut errors = 0u32;

    for (i, block) in blocks.iter().enumerate() {
        let parent_id = if i == 0 {
            sccgub_types::ZERO_HASH
        } else {
            blocks[i - 1].header.block_id
        };

        // Check structural validity.
        if !block.is_structurally_valid() {
            println!(
                "  [FAIL] Block #{}: structural validation failed",
                block.header.height
            );
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

        // Replay state + nonces + balance trie writes.
        let mut replay_balances = sccgub_state::balances::BalanceLedger::new();
        // Reconstruct balances from trie.
        for (key, value) in state.trie.iter() {
            if key.starts_with(b"balance/") && value.len() == 16 {
                if let Ok(agent_bytes) = hex::decode(&key[8..]) {
                    if agent_bytes.len() == 32 {
                        let mut id = [0u8; 32];
                        id.copy_from_slice(&agent_bytes);
                        let mut raw = [0u8; 16];
                        raw.copy_from_slice(value);
                        replay_balances.credit(
                            &id,
                            sccgub_types::tension::TensionValue(i128::from_le_bytes(raw)),
                        );
                    }
                }
            }
        }

        for tx in &block.body.transitions {
            match &tx.payload {
                OperationPayload::Write { key, value } => {
                    state.apply_delta(&StateDelta {
                        writes: vec![StateWrite {
                            address: key.clone(),
                            value: value.clone(),
                        }],
                        deletes: vec![],
                    });
                }
                OperationPayload::AssetTransfer { from, to, amount } => {
                    if let Err(e) = replay_balances.transfer(
                        from,
                        to,
                        sccgub_types::tension::TensionValue(*amount),
                    ) {
                        tracing::warn!("Transfer failed during stats replay: {}", e);
                    }
                }
                _ => {}
            }
            if let Err(e) = state.check_nonce(&tx.actor.agent_id, tx.nonce) {
                println!(
                    "  [FAIL] Block #{}: nonce error for tx {}: {}",
                    block.header.height,
                    hex::encode(tx.tx_id),
                    e
                );
                errors += 1;
            }
        }

        // Write updated balances into trie (mirrors chain.rs produce_block).
        for (agent_id, balance) in &replay_balances.balances {
            let key = format!("balance/{}", hex::encode(agent_id)).into_bytes();
            state.apply_delta(&StateDelta {
                writes: vec![StateWrite {
                    address: key,
                    value: balance.raw().to_le_bytes().to_vec(),
                }],
                deletes: vec![],
            });
        }

        state.set_height(block.header.height);

        // Verify state root matches block header (skip genesis which has no transactions).
        if block.header.height > 0 {
            let computed_root = state.state_root();
            if block.header.state_root != computed_root {
                println!(
                    "  [FAIL] Block #{}: state root mismatch (header: {}, computed: {})",
                    block.header.height,
                    hex::encode(block.header.state_root),
                    hex::encode(computed_root),
                );
                errors += 1;
            }
        }

        // Check block height continuity.
        if block.header.height != i as u64 {
            println!(
                "  [FAIL] Block #{}: height gap (expected {}, got {})",
                block.header.height, i, block.header.height
            );
            errors += 1;
        }
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

fn cmd_export(data_dir: &std::path::Path, output: &std::path::Path) {
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
            eprintln!("No chain found.");
            std::process::exit(1);
        }
    };

    let snapshot = serde_json::json!({
        "format": "sccgub-chain-export",
        "version": "1.0",
        "chain_id": hex::encode(blocks[0].header.chain_id),
        "height": blocks.last().unwrap().header.height,
        "block_count": blocks.len(),
        "blocks": blocks,
    });

    let json = serde_json::to_string_pretty(&snapshot).expect("Serialization failed");

    // Write atomically.
    let tmp = output.with_extension("tmp");
    std::fs::write(&tmp, &json).expect("Failed to write export file");
    std::fs::rename(&tmp, output).expect("Failed to finalize export file");

    println!(
        "Exported {} blocks (height {}) to {:?} ({:.1} KB)",
        blocks.len(),
        blocks.last().unwrap().header.height,
        output,
        json.len() as f64 / 1024.0
    );
}

fn cmd_import(data_dir: &std::path::Path, input: &std::path::Path) {
    let store = match ChainStore::new(data_dir) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Failed to open data directory: {}", e);
            std::process::exit(1);
        }
    };

    // Check if chain already exists.
    if store.load_block(0).is_ok() {
        eprintln!(
            "Chain already exists at {:?}. Delete it first to import.",
            data_dir
        );
        std::process::exit(1);
    }

    let json = std::fs::read_to_string(input).expect("Failed to read import file");
    let snapshot: serde_json::Value = serde_json::from_str(&json).expect("Invalid JSON");

    let format = snapshot
        .get("format")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if format != "sccgub-chain-export" {
        eprintln!(
            "Invalid export format: expected 'sccgub-chain-export', got '{}'",
            format
        );
        std::process::exit(1);
    }

    let blocks: Vec<sccgub_types::block::Block> =
        serde_json::from_value(snapshot.get("blocks").cloned().unwrap_or_default())
            .expect("Failed to parse blocks from export");

    // Verify and save each block.
    let mut state = sccgub_state::world::ManagedWorldState::new();
    state.state.governance_state = sccgub_types::governance::GovernanceState {
        finality_mode: sccgub_types::governance::FinalityMode::Deterministic,
        ..Default::default()
    };

    for (i, block) in blocks.iter().enumerate() {
        if !block.is_structurally_valid() {
            eprintln!(
                "Block #{} failed structural validation",
                block.header.height
            );
            std::process::exit(1);
        }

        let parent_id = if i == 0 {
            sccgub_types::ZERO_HASH
        } else {
            blocks[i - 1].header.block_id
        };

        let result = sccgub_execution::cpog::validate_cpog(block, &state, &parent_id);
        if !result.is_valid() {
            eprintln!(
                "Block #{} failed CPoG validation: {:?}",
                block.header.height, result
            );
            std::process::exit(1);
        }

        store.save_block(block).expect("Failed to save block");

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
            if let Err(e) = state.check_nonce(&tx.actor.agent_id, tx.nonce) {
                eprintln!(
                    "Import failed: block #{} nonce error: {}",
                    block.header.height, e
                );
                std::process::exit(1);
            }
        }
        state.set_height(block.header.height);
    }

    if let Some(chain_id) = blocks.first().map(|b| b.header.chain_id) {
        store
            .save_metadata(&chain_id)
            .expect("Failed to save metadata");
    }

    println!(
        "Imported {} blocks (height {}) from {:?}",
        blocks.len(),
        blocks.last().map_or(0, |b| b.header.height),
        input
    );
}

fn cmd_search_tx(data_dir: &std::path::Path, prefix: &str) {
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

    let prefix_lower = prefix.to_lowercase();
    let mut found = false;

    for block in &blocks {
        for (i, tx) in block.body.transitions.iter().enumerate() {
            let tx_hex = hex::encode(tx.tx_id);
            if tx_hex.starts_with(&prefix_lower) {
                found = true;
                println!("Transaction found in Block #{}:", block.header.height);
                println!("  Tx ID:     {}", tx_hex);
                println!("  Index:     {}", i);
                println!("  Kind:      {:?}", tx.intent.kind);
                println!(
                    "  Target:    {}",
                    String::from_utf8_lossy(&tx.intent.target)
                );
                println!("  Purpose:   {}", tx.intent.declared_purpose);
                println!("  Actor:     {}", hex::encode(tx.actor.agent_id));
                println!("  Nonce:     {}", tx.nonce);
                println!(
                    "  Mfidel:    f[{}][{}]",
                    block.header.mfidel_seal.row, block.header.mfidel_seal.column
                );
                // Show receipt if available.
                if let Some(receipt) = block.receipts.get(i) {
                    println!("  Verdict:   {:?}", receipt.verdict);
                    println!("  Phi phase: {}/13", receipt.phi_phase_reached);
                }
                println!();
            }
        }
    }

    if !found {
        println!("No transaction found with prefix '{}'", prefix);
    }
}

fn cmd_transfer(data_dir: &std::path::Path, amount: u64, passphrase: &str) {
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

    let mut chain = Chain::from_blocks(blocks);

    // Load validator key (sender).
    if store.has_validator_key() {
        match store.load_validator_key(passphrase) {
            Ok(key) => chain.set_validator_key(key),
            Err(e) => {
                eprintln!("Failed to load validator key: {}", e);
                std::process::exit(1);
            }
        }
    }

    // Sender: the validator (who has the genesis mint).
    let sender_pk = *chain.validator_key.verifying_key().as_bytes();
    let sender_seal = MfidelAtomicSeal::from_height(0);
    let sender_id = sccgub_crypto::hash::blake3_hash_concat(&[
        &sender_pk,
        &sccgub_crypto::canonical::canonical_bytes(&sender_seal),
    ]);
    let sender = AgentIdentity {
        agent_id: sender_id,
        public_key: sender_pk,
        mfidel_seal: sender_seal,
        registration_block: 0,
        governance_level: PrecedenceLevel::Meaning,
        norm_set: HashSet::new(),
        responsibility: ResponsibilityState::default(),
    };

    // Recipient: generate a new agent.
    let recipient_key = generate_keypair();
    let recipient_pk = *recipient_key.verifying_key().as_bytes();
    let recipient_seal = MfidelAtomicSeal::from_height(chain.height() + 1);
    let recipient_id = sccgub_crypto::hash::blake3_hash_concat(&[
        &recipient_pk,
        &sccgub_crypto::canonical::canonical_bytes(&recipient_seal),
    ]);

    let current_height = chain.height();
    let nonce = (current_height + 1) * 1000 + 1;
    let transfer_amount = sccgub_types::tension::TensionValue::from_integer(amount as i64);

    // Build transfer transaction.
    let intent = WHBindingIntent {
        who: sender_id,
        when: CausalTimestamp::genesis(),
        r#where: b"ledger/transfer".to_vec(),
        why: CausalJustification {
            invoking_rule: blake3_hash(b"asset-transfer-rule"),
            precedence_level: PrecedenceLevel::Meaning,
            causal_ancestors: vec![],
            constraint_proof: vec![],
        },
        how: TransitionMechanism::DirectStateWrite,
        which: HashSet::new(),
        what_declared: format!("Transfer {} tokens", amount),
    };

    let mut tx = SymbolicTransition {
        tx_id: [0u8; 32],
        actor: sender.clone(),
        intent: TransitionIntent {
            kind: TransitionKind::AssetTransfer,
            target: b"ledger/transfer".to_vec(),
            declared_purpose: format!(
                "Transfer {} tokens to {}",
                amount,
                &hex::encode(recipient_id)[..16]
            ),
        },
        preconditions: vec![],
        postconditions: vec![],
        payload: OperationPayload::AssetTransfer {
            from: sender_id,
            to: recipient_id,
            amount: transfer_amount.raw(),
        },
        causal_chain: vec![],
        wh_binding_intent: intent,
        nonce: nonce as u128,
        signature: vec![],
    };

    let canonical = sccgub_execution::validate::canonical_tx_bytes(&tx);
    tx.tx_id = blake3_hash(&canonical);
    tx.signature = sccgub_crypto::signature::sign(&chain.validator_key, &canonical);

    if let Err(e) = chain.submit_transition(tx) {
        tracing::warn!("Transaction rejected: {}", e);
    }

    let produced_height = match chain.produce_block() {
        Ok(block) => {
            store.save_block(block).expect("Failed to save block");
            block.header.height
        }
        Err(e) => {
            eprintln!("Failed to produce block: {}", e);
            std::process::exit(1);
        }
    };

    println!("Transfer complete in Block #{}:", produced_height);
    println!("  From:   {} (validator)", &hex::encode(sender_id)[..16]);
    println!("  To:     {}", hex::encode(recipient_id));
    println!("  Amount: {} tokens", amount);
    println!();

    // Show updated balances.
    println!("Balances after transfer:");
    println!("  Sender:    {}", chain.balances.balance_of(&sender_id));
    println!("  Recipient: {}", chain.balances.balance_of(&recipient_id));
    println!("  Supply:    {}", chain.balances.total_supply());
}

fn cmd_balance(data_dir: &std::path::Path, agent_prefix: &str) {
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
            eprintln!("No chain found.");
            std::process::exit(1);
        }
    };

    // Replay to reconstruct balances.
    let mut balances = sccgub_state::balances::BalanceLedger::new();

    // Genesis mint: validator of block 0 gets initial supply.
    balances.credit(
        &blocks[0].header.validator_id,
        sccgub_types::tension::TensionValue::from_integer(1_000_000),
    );

    for block in &blocks {
        for tx in &block.body.transitions {
            if let sccgub_types::transition::OperationPayload::AssetTransfer { from, to, amount } =
                &tx.payload
            {
                if let Err(e) =
                    balances.transfer(from, to, sccgub_types::tension::TensionValue(*amount))
                {
                    tracing::warn!("Transfer failed during balance replay: {}", e);
                }
            }
        }
    }

    let prefix_lower = agent_prefix.to_lowercase();

    // Show all balances matching prefix, or all if prefix is empty.
    let mut found = false;
    for (agent_id, balance) in &balances.balances {
        let hex_id = hex::encode(agent_id);
        if (prefix_lower.is_empty() || hex_id.starts_with(&prefix_lower)) && balance.raw() > 0 {
            found = true;
            println!("Agent: {}", hex_id);
            println!("  Balance: {}", balance);
            println!();
        }
    }

    if !found {
        if prefix_lower.is_empty() {
            println!("No accounts with positive balance.");
        } else {
            println!("No agent found with prefix '{}'", agent_prefix);
        }
    }

    println!("Total supply: {}", balances.total_supply());
    println!("Accounts:     {}", balances.account_count());
}

fn cmd_stats(data_dir: &std::path::Path) {
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
            eprintln!("No chain found.");
            std::process::exit(1);
        }
    };

    let total_txs: u64 = blocks.iter().map(|b| b.body.transition_count as u64).sum();
    let total_receipts: u64 = blocks.iter().map(|b| b.receipts.len() as u64).sum();
    let total_causal_edges: u64 = blocks
        .iter()
        .map(|b| b.causal_delta.new_edges.len() as u64)
        .sum();
    let total_causal_vertices: u64 = blocks
        .iter()
        .map(|b| b.causal_delta.new_vertices.len() as u64)
        .sum();

    // Count unique agents.
    let mut agents = std::collections::HashSet::new();
    for block in &blocks {
        for tx in &block.body.transitions {
            agents.insert(tx.actor.agent_id);
        }
    }

    let (state, _balances) = replay_chain_state(&blocks);

    let latest = blocks.last().unwrap();
    let mfidel_cycle = sccgub_types::mfidel::MfidelAtomicSeal::cycle_number(latest.header.height);

    println!("=== SCCGUB Chain Statistics ===");
    println!();
    println!("  Chain");
    println!("    Height:            {}", latest.header.height);
    println!("    Blocks:            {}", blocks.len());
    println!("    Mfidel cycle:      {}", mfidel_cycle);
    println!();
    println!("  Transactions");
    println!("    Total:             {}", total_txs);
    println!("    Receipts:          {}", total_receipts);
    println!(
        "    Avg per block:     {:.1}",
        if blocks.len() > 1 {
            total_txs as f64 / (blocks.len() - 1) as f64
        } else {
            0.0
        }
    );
    println!();
    println!("  Causal Graph");
    println!("    Vertices:          {}", total_causal_vertices);
    println!("    Edges:             {}", total_causal_edges);
    println!();
    println!("  State");
    println!("    Entries:           {}", state.trie.len());
    println!("    State root:        {}", hex::encode(state.state_root()));
    println!("    Unique agents:     {}", agents.len());
    println!();
    println!("  Governance");
    println!(
        "    Finality:          {:?}",
        latest.governance.finality_mode
    );
    println!(
        "    Emergency:         {}",
        latest.governance.emergency_mode
    );
    println!(
        "    Active norms:      {}",
        latest.governance.active_norm_count
    );
    println!();
    println!("  Tension");
    println!("    Current:           {}", latest.header.tension_after);
}

fn cmd_health(data_dir: &std::path::Path) {
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
            eprintln!("No chain found.");
            std::process::exit(1);
        }
    };

    let mut metrics = observability::ChainMetrics::default();

    let mut total_causal_edges = 0u64;
    let mut state = sccgub_state::world::ManagedWorldState::new();

    for block in &blocks {
        metrics.record_block(block.body.transition_count, 0);
        total_causal_edges += block.causal_delta.new_edges.len() as u64;

        for tx in &block.body.transitions {
            if let sccgub_types::transition::OperationPayload::Write { key, value } = &tx.payload {
                state.apply_delta(&sccgub_types::transition::StateDelta {
                    writes: vec![sccgub_types::transition::StateWrite {
                        address: key.clone(),
                        value: value.clone(),
                    }],
                    deletes: vec![],
                });
            }
        }
    }

    metrics.state_entries = state.trie.len() as u64;
    metrics.causal_edges = total_causal_edges;

    // Compute finality.
    let finality_config = sccgub_consensus::finality::FinalityConfig::default();
    let mut finality = sccgub_consensus::finality::FinalityTracker::default();
    if let Some(last) = blocks.last() {
        for h in 1..=last.header.height {
            finality.on_new_block(h);
        }
        finality.check_finality(&finality_config, |h| {
            blocks.get(h as usize).map(|b| b.header.block_id)
        });
    }

    let latest = blocks.last().unwrap();

    println!("{}", metrics.report());
    println!("  Finality");
    println!("    Finalized height:   {}", finality.finalized_height);
    println!("    Tip height:         {}", latest.header.height);
    println!("    Finality gap:       {}", finality.finality_gap());
    println!(
        "    Confirmation depth: {}",
        finality_config.confirmation_depth
    );
    println!(
        "    Expected latency:   {} ms",
        finality_config.expected_finality_ms()
    );
    println!(
        "    SLA met:            {}",
        if finality_config.meets_sla() {
            "YES"
        } else {
            "NO"
        }
    );
    println!();
    println!("  Mfidel");
    println!(
        "    Current seal:       f[{}][{}]",
        latest.header.mfidel_seal.row, latest.header.mfidel_seal.column
    );
    println!(
        "    Cycle:              {}",
        sccgub_types::mfidel::MfidelAtomicSeal::cycle_number(latest.header.height)
    );
    println!("    Fidels completed:   {}", latest.header.height % 272);
}

async fn cmd_serve(data_dir: &std::path::Path, port: u16) {
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

    // Rebuild state from blocks.
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

    // Compute finality.
    let mut finality = sccgub_consensus::finality::FinalityTracker::default();
    let finality_config = sccgub_consensus::finality::FinalityConfig::default();
    if let Some(last) = blocks.last() {
        for h in 1..=last.header.height {
            finality.on_new_block(h);
        }
        finality.check_finality(&finality_config, |h| {
            blocks.get(h as usize).map(|b| b.header.block_id)
        });
    }

    let chain_id = blocks[0].header.chain_id;

    let app_state = sccgub_api::handlers::SharedState::from(std::sync::Arc::new(
        tokio::sync::RwLock::new(sccgub_api::handlers::AppState {
            blocks,
            state,
            chain_id,
            finalized_height: finality.finalized_height,
            pending_txs: Vec::new(),
            seen_tx_ids: std::collections::HashSet::new(),
        }),
    ));

    let app = sccgub_api::router::build_router(app_state);

    let addr = format!("0.0.0.0:{}", port);
    println!("SCCGUB API server starting on http://{}", addr);
    println!("Endpoints (v1):");
    println!("  GET  /api/v1/status          — chain summary");
    println!("  GET  /api/v1/health          — system health + finality");
    println!("  GET  /api/v1/block/:height   — block detail with transactions");
    println!("  GET  /api/v1/state           — paginated world state (?offset=&limit=)");
    println!("  GET  /api/v1/tx/:tx_id       — transaction detail by ID");
    println!("  POST /api/v1/tx/submit       — submit signed transaction (hex)");
    println!("Legacy routes (/api/*) also available.");
    println!();

    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
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
        &sccgub_crypto::canonical::canonical_bytes(&seal),
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
        if let Err(e) = chain.submit_transition(tx) {
            tracing::warn!("Transaction rejected: {}", e);
        }
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
    println!(
        "  Height: {}, Blocks: {}, Mempool: {}",
        chain.height(),
        chain.blocks.len(),
        chain.mempool.len()
    );
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
    println!(
        "  Tension:    {} -> {}",
        block.header.tension_before, block.header.tension_after
    );
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

fn cmd_treasury(data_dir: &std::path::Path) {
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

    let chain = Chain::from_blocks(blocks);

    println!("=== Treasury Status ===\n");
    println!("  Epoch:              {}", chain.treasury.epoch);
    println!("  Pending fees:       {}", chain.treasury.pending_fees);
    println!(
        "  Total collected:    {}",
        chain.treasury.total_fees_collected
    );
    println!(
        "  Total distributed:  {}",
        chain.treasury.total_rewards_distributed
    );
    println!("  Total burned:       {}", chain.treasury.total_burned);
    println!("  Epoch fees:         {}", chain.treasury.epoch_fees);
    println!("  Epoch rewards:      {}", chain.treasury.epoch_rewards);
    println!();

    // Conservation check.
    let sum = sccgub_types::tension::TensionValue(
        chain.treasury.total_rewards_distributed.raw()
            + chain.treasury.total_burned.raw()
            + chain.treasury.pending_fees.raw(),
    );
    let conserved = sum == chain.treasury.total_fees_collected;
    println!(
        "  Conservation:       {} (collected = distributed + burned + pending)",
        if conserved { "OK" } else { "VIOLATION" }
    );
}

fn cmd_escrow(data_dir: &std::path::Path) {
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

    let chain = Chain::from_blocks(blocks);

    println!("=== Escrow Status ===\n");
    println!("  Chain height:       {}", chain.height());
    println!("  Total supply:       {}", chain.balances.total_supply());
    println!("  Active accounts:    {}", chain.balances.account_count());
    println!();
    println!("  (Escrow registry is initialized per-session;");
    println!("   persistent escrow state requires state trie integration.)");
}
