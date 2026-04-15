//! Purpose: SCCGUB node CLI entry point and command routing.
//! Governance scope: operator-facing commands and parameter proposal flows.
//! Dependencies: clap, sccgub-node modules, sccgub-types.
//! Invariants: explicit error paths, deterministic command outputs.

use sccgub_node::config;
use sccgub_node::network;

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::time::Duration;

use clap::{Parser, Subcommand};

use sccgub_crypto::hash::blake3_hash;
use sccgub_crypto::keys::generate_keypair;
use sccgub_crypto::signature::sign;
use sccgub_types::agent::{AgentIdentity, ResponsibilityState};
use sccgub_types::block::CURRENT_BLOCK_VERSION;
use sccgub_types::governance::PrecedenceLevel;
use sccgub_types::mfidel::MfidelAtomicSeal;
use sccgub_types::timestamp::CausalTimestamp;
use sccgub_types::transition::*;

use sccgub_node::chain::Chain;
use sccgub_node::persistence::ChainStore;

const DEFAULT_DATA_DIR: &str = ".sccgub";
const GOVERNED_PARAMETER_KEYS: [&str; 10] = [
    "governance.max_consecutive_proposals",
    "governance.max_actions_per_agent_pct",
    "governance.safety_change_min_signers",
    "governance.genesis_change_min_signers",
    "governance.max_authority_term_epochs",
    "governance.authority_cooldown_epochs",
    "finality.confirmation_depth",
    "finality.max_finality_ms",
    "finality.target_block_time_ms",
    "finality.mode",
];

#[derive(Parser)]
#[command(name = "sccgub")]
#[command(about = "Symbolic Causal Chain General Universal Blockchain -- Node CLI")]
#[command(version = env!("CARGO_PKG_VERSION"))]
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
    Status {
        /// Emit JSON schema instead of values.
        #[arg(long, default_value_t = false)]
        schema: bool,
    },
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
        /// Enable p2p networking (uses config network section).
        #[arg(long, default_value_t = false)]
        p2p: bool,
    },
    /// Start the REST API server and print live metrics.
    Observe {
        /// Port to listen on.
        #[arg(short, long, default_value = "3000")]
        port: u16,
        /// Enable p2p networking (uses config network section).
        #[arg(long, default_value_t = false)]
        p2p: bool,
        /// Metrics print interval in seconds.
        #[arg(long, default_value = "5")]
        interval: u64,
        /// Emit JSON lines instead of plain text.
        #[arg(long, default_value_t = false)]
        json: bool,
    },
    /// Run the full demo (init + produce + status) in-memory.
    Demo,
    /// Show information about the chain/spec.
    Info,
    /// Show current governed parameter values.
    Governed {
        /// Emit JSON output.
        #[arg(long, default_value_t = false)]
        json: bool,
        /// Emit JSON schema instead of values.
        #[arg(long, default_value_t = false)]
        schema: bool,
    },
    /// Propose a governed parameter update (writes a governance proposal tx).
    GovernedPropose {
        /// Governed parameter key.
        key: String,
        /// Proposed value (string).
        value: String,
    },
    /// Vote for a governance proposal by id (hex).
    GovernedVote {
        /// Proposal id (32-byte hex).
        proposal_id: String,
    },
    /// Show governance proposal registry summary.
    GovernedStatus,
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
        Commands::Init => cmd_init(&cli.data_dir, &cli.config, passphrase),
        Commands::Produce { txs } => cmd_produce(&cli.data_dir, txs, &cli.config, passphrase),
        Commands::ShowBlock { height } => cmd_show_block(&cli.data_dir, height),
        Commands::Status { schema } => cmd_status(&cli.data_dir, schema),
        Commands::ShowState => cmd_show_state(&cli.data_dir),
        Commands::Verify => cmd_verify(&cli.data_dir),
        Commands::SearchTx { prefix } => cmd_search_tx(&cli.data_dir, &prefix),
        Commands::Export { output } => cmd_export(&cli.data_dir, &output),
        Commands::Import { input } => cmd_import(&cli.data_dir, &input),
        Commands::Transfer { amount } => cmd_transfer(&cli.data_dir, amount, passphrase),
        Commands::Stats => cmd_stats(&cli.data_dir),
        Commands::Balance { agent } => cmd_balance(&cli.data_dir, &agent),
        Commands::Health => cmd_health(&cli.data_dir),
        Commands::Serve { port, p2p } => {
            cmd_serve(&cli.data_dir, port, p2p, &cli.config, passphrase, None).await
        }
        Commands::Observe {
            port,
            p2p,
            interval,
            json,
        } => {
            cmd_serve(
                &cli.data_dir,
                port,
                p2p,
                &cli.config,
                passphrase,
                Some((interval, json)),
            )
            .await
        }
        Commands::Demo => cmd_demo(),
        Commands::Info => cmd_info(),
        Commands::Governed { json, schema } => cmd_governed(&cli.data_dir, json, schema),
        Commands::GovernedPropose { key, value } => {
            cmd_governed_propose(&cli.data_dir, passphrase, &key, &value)
        }
        Commands::GovernedVote { proposal_id } => {
            cmd_governed_vote(&cli.data_dir, passphrase, &proposal_id)
        }
        Commands::GovernedStatus => cmd_governed_status(&cli.data_dir),
        Commands::Treasury => cmd_treasury(&cli.data_dir),
        Commands::Escrow => cmd_escrow(&cli.data_dir),
    }
}

/// Replay blocks to reconstruct full state (single source of truth).
/// Used by: cmd_verify, cmd_stats, cmd_health, cmd_serve, cmd_balance.
fn replay_chain_state(
    blocks: &[sccgub_types::block::Block],
) -> Result<
    (
        sccgub_state::world::ManagedWorldState,
        sccgub_state::balances::BalanceLedger,
    ),
    String,
> {
    let replayed = Chain::from_blocks(blocks.to_vec()).map_err(|e| e.to_string())?;
    Ok((replayed.state, replayed.balances))
}

fn restore_snapshot_if_available(
    store: &ChainStore,
    chain: &mut Chain,
    allow_restore: bool,
    durable_store: Option<std::sync::Arc<dyn sccgub_state::store::StateStore>>,
) -> bool {
    if !allow_restore {
        return false;
    }

    let snapshot = match store.load_latest_snapshot() {
        Ok(Some(snapshot)) => snapshot,
        Ok(None) => return false,
        Err(e) => {
            eprintln!("Warning: snapshot load failed: {}", e);
            return false;
        }
    };

    if snapshot.height != chain.height() {
        eprintln!(
            "Warning: snapshot height {} does not match chain height {}; skipping restore.",
            snapshot.height,
            chain.height()
        );
        return false;
    }

    let Some(block) = chain.blocks.get(snapshot.height as usize) else {
        eprintln!(
            "Warning: snapshot height {} is out of range; skipping restore.",
            snapshot.height
        );
        return false;
    };

    if snapshot.state_root != block.header.state_root {
        eprintln!(
            "Warning: snapshot state root mismatch at height {}; skipping restore.",
            snapshot.height
        );
        return false;
    }

    let mut balances = sccgub_state::balances::BalanceLedger::new();
    for (agent_id, raw_balance) in &snapshot.balances {
        balances.import_balance(*agent_id, sccgub_types::tension::TensionValue(*raw_balance));
    }
    let balance_root = balances.balance_root();
    if balance_root != block.header.balance_root {
        eprintln!(
            "Warning: snapshot balance root mismatch at height {}; skipping restore.",
            snapshot.height
        );
        return false;
    }

    if let Some(store) = durable_store {
        if let Err(e) = chain.restore_from_snapshot_with_store(&snapshot, store) {
            eprintln!("Warning: snapshot restore with store failed: {}", e);
            return false;
        }
    } else {
        chain.restore_from_snapshot(&snapshot);
    }

    true
}

fn restore_safety_certificates_if_available(store: &ChainStore, chain: &mut Chain) {
    let certs = match store.load_safety_certificates() {
        Ok(certs) => certs,
        Err(e) => {
            eprintln!("Warning: safety certificate load failed: {}", e);
            return;
        }
    };
    if certs.is_empty() {
        return;
    }
    chain.restore_safety_certificates(certs);
}

fn bind_state_store_if_enabled(
    store: &ChainStore,
    chain: &mut Chain,
    config: &config::NodeConfig,
) -> Option<std::sync::Arc<dyn sccgub_state::store::StateStore>> {
    if !config.storage.state_store_enabled {
        return None;
    }

    let state_store = match store.open_state_store(&config.storage) {
        Ok(store) => {
            std::sync::Arc::new(store) as std::sync::Arc<dyn sccgub_state::store::StateStore>
        }
        Err(e) => {
            eprintln!("Warning: state store open failed: {}", e);
            return None;
        }
    };

    match state_store.is_empty() {
        Ok(true) => {
            if let Err(e) = chain.state.bind_store(state_store.clone()) {
                eprintln!("Warning: state store bind failed: {}", e);
            }
        }
        Ok(false) => {
            let durable_trie = match sccgub_state::trie::StateTrie::with_store(state_store.clone())
            {
                Ok(trie) => trie,
                Err(e) => {
                    eprintln!("Warning: state store load failed: {}", e);
                    return Some(state_store);
                }
            };
            let durable_root = durable_trie.root_readonly();
            let expected_root = chain.state.state_root();
            if durable_root == expected_root {
                chain.state.trie = durable_trie;
            } else if let Err(e) = chain.state.bind_store(state_store.clone()) {
                eprintln!(
                    "Warning: state store root mismatch (durable={} expected={}); rebinding failed: {}",
                    hex::encode(durable_root),
                    hex::encode(expected_root),
                    e
                );
            }
        }
        Err(e) => {
            eprintln!("Warning: state store status check failed: {}", e);
        }
    }

    Some(state_store)
}

fn bind_state_store_for_snapshot(
    store: &ChainStore,
    config: &config::NodeConfig,
) -> Option<std::sync::Arc<dyn sccgub_state::store::StateStore>> {
    if !config.storage.state_store_enabled {
        return None;
    }

    match store.open_state_store(&config.storage) {
        Ok(store) => {
            Some(std::sync::Arc::new(store) as std::sync::Arc<dyn sccgub_state::store::StateStore>)
        }
        Err(e) => {
            eprintln!("Warning: state store open failed: {}", e);
            None
        }
    }
}

fn cmd_init(data_dir: &std::path::Path, config_path: &std::path::Path, passphrase: &str) {
    let config = config::NodeConfig::load(config_path);
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

    if config.chain.initial_finality_mode.is_none()
        && config.network.enable
        && config.network.validators.len() > 1
    {
        eprintln!(
            "Warning: multiple validators configured but initial_finality_mode is not set. \
            Set chain.initial_finality_mode = \"bft:<quorum>\" in config for multi-validator BFT."
        );
    }

    let mut chain = match config.chain.initial_finality_mode.as_deref() {
        Some(mode) => match sccgub_node::chain::parse_finality_mode(mode) {
            Ok(parsed) => Chain::init_with_finality_mode(parsed),
            Err(e) => {
                eprintln!("Invalid chain.initial_finality_mode: {}", e);
                std::process::exit(1);
            }
        },
        None => Chain::init(),
    };
    if !config.network.validators.is_empty() {
        match network::NetworkRuntime::validators_from_config(&config.network) {
            Ok(validators) => chain.set_validator_set(validators),
            Err(e) => eprintln!("Warning: validator set config ignored: {}", e),
        }
    }
    let _ = bind_state_store_if_enabled(&store, &mut chain, &config);
    let genesis = chain
        .latest_block()
        .expect("Chain::init must produce genesis");

    if let Err(e) = store.save_block(genesis) {
        eprintln!("Failed to save genesis block: {}", e);
        std::process::exit(1);
    }
    if let Err(e) = store.save_metadata(&chain.chain_id) {
        eprintln!("Failed to save metadata: {}", e);
        std::process::exit(1);
    }
    if let Err(e) = store.save_validator_key(&chain.validator_key, passphrase) {
        eprintln!("Failed to save validator key: {}", e);
        std::process::exit(1);
    }

    println!("Chain initialized at {:?}", data_dir);
    println!("  Chain ID:      {}", hex::encode(chain.chain_id));
    println!("  Genesis block: {}", hex::encode(genesis.header.block_id));
    println!("  Block version: {}", genesis.header.version);
    println!(
        "  Mfidel seal:   f[{}][{}] (vowel origin)",
        genesis.header.mfidel_seal.row, genesis.header.mfidel_seal.column
    );
    println!(
        "  State root:    {}",
        hex::encode(genesis.header.state_root)
    );
}

fn cmd_produce(
    data_dir: &std::path::Path,
    num_txs: u32,
    config_path: &std::path::Path,
    passphrase: &str,
) {
    let config = config::NodeConfig::load(config_path);
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

    let mut chain = Chain::from_blocks(blocks).unwrap_or_else(|e| {
        eprintln!("Chain import failed: {}", e);
        std::process::exit(1);
    });
    if !config.network.validators.is_empty() {
        match network::NetworkRuntime::validators_from_config(&config.network) {
            Ok(validators) => chain.set_validator_set(validators),
            Err(e) => eprintln!("Warning: validator set config ignored: {}", e),
        }
    }

    let durable_store = bind_state_store_for_snapshot(&store, &config);
    let restored = restore_snapshot_if_available(&store, &mut chain, true, durable_store.clone());
    if !restored {
        let _ = bind_state_store_if_enabled(&store, &mut chain, &config);
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
    let seal = MfidelAtomicSeal::from_height(chain.height().saturating_add(1));
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
        norm_set: BTreeSet::new(),
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
            if let Err(e) = store.save_block(block) {
                eprintln!("Failed to save block: {}", e);
                std::process::exit(1);
            }
            println!("Block #{} produced and saved.", block.header.height);
            print_block_summary(block);
            block.header.height
        }
        Err(e) => {
            eprintln!("Failed to produce block: {}", e);
            std::process::exit(1);
        }
    };

    if let Err(e) = chain.state.flush_store() {
        eprintln!("Warning: state store flush failed: {}", e);
    }

    // Save state snapshot periodically for fast reload.
    let snap_interval = config.chain.snapshot_interval.max(1);
    if produced_height % snap_interval == 0 && produced_height > 0 {
        let snapshot = chain.create_snapshot();
        if let Err(e) = store.save_snapshot(&snapshot) {
            eprintln!("Warning: failed to save snapshot: {}", e);
        } else {
            println!("  Snapshot saved at height {}.", produced_height);
        }
        // Keep only the 3 most recent snapshots to avoid unbounded disk growth.
        if let Ok(removed) = store.rotate_snapshots(3) {
            if removed > 0 {
                println!("  Rotated {} old snapshot(s).", removed);
            }
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

fn cmd_status(data_dir: &std::path::Path, schema: bool) {
    if schema {
        println!("{}", include_str!("../../../specs/STATUS_JSON_SCHEMA.json"));
        return;
    }

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

    let Some(latest) = blocks.last() else {
        println!("No chain found. Run `sccgub init` first.");
        return;
    };
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

    let Some(tip) = blocks.last() else {
        println!("No chain found. Run `sccgub init` first.");
        return;
    };
    let tip_height = tip.header.height;

    let (state, _balances) = match replay_chain_state(&blocks) {
        Ok(replayed) => replayed,
        Err(e) => {
            eprintln!("Failed to replay chain state: {}", e);
            std::process::exit(1);
        }
    };

    println!("=== World State (height {}) ===", tip_height);
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
    let mut balances = sccgub_state::balances::BalanceLedger::new();
    let mut treasury = sccgub_state::treasury::Treasury::new();

    // Apply genesis funding exactly as the runtime does.
    if let Some(genesis) = blocks.first() {
        let genesis_spend_account = sccgub_state::apply::validator_spend_account(
            genesis.header.version,
            &genesis.header.validator_id,
        );
        sccgub_state::apply::apply_genesis_mint(&mut state, &mut balances, &genesis_spend_account);
        state.set_height(0);
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

        // Replay state via the shared economics + apply path.
        if block.header.height > 0 {
            let gas_price = sccgub_types::economics::EconomicState::default().effective_fee(
                state.state.tension_field.total,
                state.state.tension_field.budget.current_budget,
            );
            if let Err(e) = sccgub_state::apply::apply_block_economics(
                &mut state,
                &mut balances,
                &mut treasury,
                &block.body.transitions,
                &block.receipts,
                block.header.version,
                &block.header.validator_id,
                gas_price,
                sccgub_state::treasury::default_block_reward(),
            ) {
                println!(
                    "  [FAIL] Block #{}: economics replay failed: {}",
                    block.header.height, e
                );
                errors += 1;
            }
        }

        sccgub_state::apply::apply_block_transitions(
            &mut state,
            &mut balances,
            &block.body.transitions,
        );

        for tx in &block.body.transitions {
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

    // Safe: blocks guaranteed non-empty by load guard above.
    let tip_height = blocks[blocks.len() - 1].header.height;
    let snapshot = serde_json::json!({
        "format": "sccgub-chain-export",
        "version": "1.0",
        "chain_id": hex::encode(blocks[0].header.chain_id),
        "height": tip_height,
        "block_count": blocks.len(),
        "blocks": blocks,
    });

    let json = match serde_json::to_string_pretty(&snapshot) {
        Ok(j) => j,
        Err(e) => {
            eprintln!("Serialization failed: {}", e);
            std::process::exit(1);
        }
    };

    // Write atomically.
    let tmp = output.with_extension("tmp");
    if let Err(e) = std::fs::write(&tmp, &json) {
        eprintln!("Failed to write export file: {}", e);
        std::process::exit(1);
    }
    if let Err(e) = std::fs::rename(&tmp, output) {
        eprintln!("Failed to finalize export file: {}", e);
        std::process::exit(1);
    }

    println!(
        "Exported {} blocks (height {}) to {:?} ({:.1} KB)",
        blocks.len(),
        tip_height,
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

    let json = match std::fs::read_to_string(input) {
        Ok(j) => j,
        Err(e) => {
            eprintln!("Failed to read import file {:?}: {}", input, e);
            std::process::exit(1);
        }
    };
    let snapshot: serde_json::Value = match serde_json::from_str(&json) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Invalid JSON in import file: {}", e);
            std::process::exit(1);
        }
    };

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
        match serde_json::from_value(snapshot.get("blocks").cloned().unwrap_or_default()) {
            Ok(b) => b,
            Err(e) => {
                eprintln!("Failed to parse blocks from export: {}", e);
                std::process::exit(1);
            }
        };

    let replayed = Chain::from_blocks(blocks.clone()).unwrap_or_else(|e| {
        eprintln!("Import verification failed: {}", e);
        std::process::exit(1);
    });

    for block in &blocks {
        if let Err(e) = store.save_block(block) {
            eprintln!(
                "Failed to save block at height {}: {}",
                block.header.height, e
            );
            std::process::exit(1);
        }
    }

    if let Some(chain_id) = blocks.first().map(|b| b.header.chain_id) {
        if let Err(e) = store.save_metadata(&chain_id) {
            eprintln!("Failed to save metadata: {}", e);
            std::process::exit(1);
        }
    }
    if let Err(e) = store.save_snapshot(&replayed.create_snapshot()) {
        eprintln!("Failed to save imported snapshot: {}", e);
        std::process::exit(1);
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

    let mut chain = Chain::from_blocks(blocks).unwrap_or_else(|e| {
        eprintln!("Chain import failed: {}", e);
        std::process::exit(1);
    });

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

    // Sender: the validator signer. Spend-account resolution follows the
    // chain's block version so legacy v1 chains keep replaying correctly while
    // v2 chains spend from the canonical validator agent account.
    let sender_pk = *chain.validator_key.verifying_key().as_bytes();
    let sender_seal = MfidelAtomicSeal::from_height(0);
    let sender_id = sccgub_crypto::hash::blake3_hash_concat(&[
        &sender_pk,
        &sccgub_crypto::canonical::canonical_bytes(&sender_seal),
    ]);
    let sender_spend_account =
        sccgub_state::apply::validator_spend_account(chain.block_version, &sender_pk);
    let sender = AgentIdentity {
        agent_id: sender_id,
        public_key: sender_pk,
        mfidel_seal: sender_seal,
        registration_block: 0,
        governance_level: PrecedenceLevel::Meaning,
        norm_set: BTreeSet::new(),
        responsibility: ResponsibilityState::default(),
    };

    // Recipient: generate a new agent.
    let recipient_key = generate_keypair();
    let recipient_pk = *recipient_key.verifying_key().as_bytes();
    let recipient_seal = MfidelAtomicSeal::from_height(chain.height().saturating_add(1));
    let recipient_id = sccgub_crypto::hash::blake3_hash_concat(&[
        &recipient_pk,
        &sccgub_crypto::canonical::canonical_bytes(&recipient_seal),
    ]);

    let nonce = chain
        .state
        .agent_nonces
        .get(&sender_id)
        .copied()
        .unwrap_or(0)
        + 1;
    let transfer_amount = sccgub_types::tension::TensionValue::from_integer(amount as i64);

    // Build transfer transaction.
    let transfer_target = sccgub_types::namespace::balance_key(&sender_spend_account);
    let intent = WHBindingIntent {
        who: sender_id,
        when: CausalTimestamp::genesis(),
        r#where: transfer_target.clone(),
        why: CausalJustification {
            invoking_rule: blake3_hash(b"asset-transfer-rule"),
            precedence_level: PrecedenceLevel::Meaning,
            causal_ancestors: vec![],
            constraint_proof: vec![],
        },
        how: TransitionMechanism::DirectStateWrite,
        which: BTreeSet::new(),
        what_declared: format!("Transfer {} tokens", amount),
    };

    let mut tx = SymbolicTransition {
        tx_id: [0u8; 32],
        actor: sender.clone(),
        intent: TransitionIntent {
            kind: TransitionKind::AssetTransfer,
            target: transfer_target.clone(),
            declared_purpose: format!(
                "Transfer {} tokens to {}",
                amount,
                &hex::encode(recipient_id)[..16]
            ),
        },
        preconditions: vec![],
        postconditions: vec![],
        payload: OperationPayload::AssetTransfer {
            from: sender_spend_account,
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

    let produced_block = match chain.produce_block() {
        Ok(block) => {
            let cloned = block.clone();
            if let Err(e) = store.save_block(block) {
                eprintln!("Failed to save block: {}", e);
                std::process::exit(1);
            }
            cloned
        }
        Err(e) => {
            eprintln!("Failed to produce block: {}", e);
            std::process::exit(1);
        }
    };
    let produced_height = produced_block.header.height;

    let included = produced_block.body.transitions.iter().any(|candidate| {
        matches!(
            &candidate.payload,
            OperationPayload::AssetTransfer { from, to, amount: raw }
                if *from == sender_spend_account
                    && *to == recipient_id
                    && *raw == transfer_amount.raw()
        )
    });
    if !included {
        eprintln!(
            "Transfer transaction was not included in Block #{}.",
            produced_height
        );
        if !chain.latest_rejected_receipts.is_empty() {
            eprintln!("Latest reject receipts:");
            for receipt in &chain.latest_rejected_receipts {
                eprintln!("  {} -> {}", hex::encode(receipt.tx_id), receipt.verdict);
            }
        }
        std::process::exit(1);
    }

    println!("Transfer complete in Block #{}:", produced_height);
    println!("  From:   {} (validator)", &hex::encode(sender_id)[..16]);
    println!("  To:     {}", hex::encode(recipient_id));
    println!("  Amount: {} tokens", amount);
    println!();

    // Show updated balances.
    println!("Balances after transfer:");
    println!(
        "  Sender:    {}",
        chain.balances.balance_of(&sender_spend_account)
    );
    println!("  Recipient: {}", chain.balances.balance_of(&recipient_id));
    println!("  Liquid:    {}", chain.balances.total_supply());
    println!("  Treasury:  {}", chain.treasury.pending_fees);
    println!(
        "  Accounted: {}",
        sccgub_types::tension::TensionValue(
            chain.balances.total_supply().raw() + chain.treasury.pending_fees.raw()
        )
    );
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

    let chain = Chain::from_blocks(blocks).unwrap_or_else(|e| {
        eprintln!("Failed to replay balances: {}", e);
        std::process::exit(1);
    });
    let balances = &chain.balances;

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

    println!("Liquid balances: {}", balances.total_supply());
    println!("Treasury pending: {}", chain.treasury.pending_fees);
    println!(
        "Accounted supply: {}",
        sccgub_types::tension::TensionValue(
            balances.total_supply().raw() + chain.treasury.pending_fees.raw()
        )
    );
    println!("Accounts:         {}", balances.account_count());
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

    let (state, _balances) = match replay_chain_state(&blocks) {
        Ok(replayed) => replayed,
        Err(e) => {
            eprintln!("Failed to replay chain state: {}", e);
            std::process::exit(1);
        }
    };

    let latest = &blocks[blocks.len() - 1];
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

    let mut metrics = sccgub_node::observability::ChainMetrics::default();

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

    let latest = &blocks[blocks.len() - 1];
    // Compute finality using the on-chain configuration snapshot.
    let finality_config = sccgub_consensus::finality::FinalityConfig {
        confirmation_depth: latest.governance.finality_config.confirmation_depth,
        max_finality_ms: latest.governance.finality_config.max_finality_ms,
        target_block_time_ms: latest.governance.finality_config.target_block_time_ms,
    };
    let mut finality = sccgub_consensus::finality::FinalityTracker::default();
    for h in 1..=latest.header.height {
        finality.on_new_block(h);
    }
    match latest.governance.finality_mode {
        sccgub_types::governance::FinalityMode::Deterministic => {
            finality.check_finality(&finality_config, |h| {
                blocks.get(h as usize).map(|b| b.header.block_id)
            });
        }
        sccgub_types::governance::FinalityMode::BftCertified { .. } => {
            if let Ok(certs) = store.load_safety_certificates() {
                if let Some(max_height) = certs.iter().map(|c| c.height).max() {
                    finality.finalized_height = max_height;
                }
            }
        }
    }

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

async fn cmd_serve(
    data_dir: &std::path::Path,
    port: u16,
    p2p: bool,
    config_path: &std::path::Path,
    passphrase: &str,
    observe_interval: Option<(u64, bool)>,
) {
    let config = config::NodeConfig::load(config_path);
    let store = match ChainStore::new(data_dir) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Failed to open data directory: {}", e);
            std::process::exit(1);
        }
    };
    let store = std::sync::Arc::new(store);

    let blocks = match store.load_all_blocks() {
        Ok(b) if !b.is_empty() => b,
        _ => {
            eprintln!("No chain found. Run `sccgub init` first.");
            std::process::exit(1);
        }
    };

    let mut chain = match Chain::from_blocks(blocks) {
        Ok(chain) => chain,
        Err(e) => {
            eprintln!("Failed to rebuild chain: {}", e);
            std::process::exit(1);
        }
    };
    let durable_store = bind_state_store_for_snapshot(store.as_ref(), &config);
    let restored = restore_snapshot_if_available(
        store.as_ref(),
        &mut chain,
        config.storage.snapshot_restore_enabled,
        durable_store.clone(),
    );
    restore_safety_certificates_if_available(store.as_ref(), &mut chain);
    if !restored {
        let _ = bind_state_store_if_enabled(store.as_ref(), &mut chain, &config);
    }
    if store.has_validator_key() {
        if let Ok(key) = store.load_validator_key(passphrase) {
            chain.set_validator_key(key);
        }
    }
    if config.network.enable || p2p {
        match network::NetworkRuntime::validators_from_config(&config.network) {
            Ok(validators) => chain.set_validator_set(validators),
            Err(e) => tracing::warn!("Validator set config ignored: {}", e),
        }
    }
    let chain_id = chain.chain_id;
    let chain_ref = std::sync::Arc::new(tokio::sync::RwLock::new(chain));

    let chain_snapshot = chain_ref.read().await;
    let finalized_height = chain_snapshot.finalized_height();
    let state = chain_snapshot.state.clone();
    let blocks = chain_snapshot.blocks.clone();
    let slashing_events = chain_snapshot.slashing.events.clone();
    let slashing_stakes = chain_snapshot
        .slashing
        .stakes
        .iter()
        .map(|(k, v)| (*k, v.raw()))
        .collect();
    let slashing_removed = chain_snapshot.slashing.removed.clone();
    let equivocation_records = chain_snapshot.equivocation_records.clone();
    let safety_certificates = chain_snapshot.safety_certificates.clone();
    let governance_limits = chain_snapshot.governance_limits.clone();
    let finality_config = chain_snapshot.finality_config.clone();
    let proposals = chain_snapshot.proposals.proposals.clone();
    drop(chain_snapshot);

    let app_state = sccgub_api::handlers::SharedState::from(std::sync::Arc::new(
        tokio::sync::RwLock::new(sccgub_api::handlers::AppState {
            blocks,
            state,
            chain_id,
            finalized_height,
            proposals,
            governance_limits,
            finality_config,
            slashing_events,
            slashing_stakes,
            slashing_removed,
            equivocation_records,
            safety_certificates,
            bandwidth_inbound_bytes: 0,
            bandwidth_outbound_bytes: 0,
            peer_stats: std::collections::HashMap::new(),
            pending_txs: Vec::new(),
            seen_tx_ids: std::collections::HashSet::new(),
        }),
    ));

    let bridge = sccgub_node::api_bridge::ApiBridge::new(app_state.clone())
        .with_min_interval_ms(config.api_sync.min_interval_ms);
    {
        let chain = chain_ref.read().await;
        let _ = bridge.sync_from_chain(&chain).await;
    }
    {
        let mut chain = chain_ref.write().await;
        chain.set_api_bridge(bridge.clone());
    }

    if config.network.enable || p2p {
        let runtime =
            match network::NetworkRuntime::new(chain_ref.clone(), config.network.clone()).await {
                Ok(rt) => rt
                    .with_api_bridge(bridge.clone())
                    .with_persistence(store.clone(), config.chain.snapshot_interval),
                Err(e) => {
                    eprintln!("Failed to start p2p runtime: {}", e);
                    std::process::exit(1);
                }
            };
        let runtime = std::sync::Arc::new(runtime);
        let _ = runtime.run().await;
    }

    if !(config.network.enable || p2p) {
        let _ = bridge.sync_from_chain_arc(&chain_ref).await;
    }

    if let Some((interval_secs, json_output)) = observe_interval {
        let metrics = bridge.metrics();
        let chain_for_observe = chain_ref.clone();
        let interval_secs = interval_secs.max(1);
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(Duration::from_secs(interval_secs));
            loop {
                ticker.tick().await;
                let chain = chain_for_observe.read().await;
                let api_sync_events = metrics.lock().map(|m| m.api_sync_events).unwrap_or(0);
                if json_output {
                    let payload = serde_json::json!({
                        "height": chain.height(),
                        "finalized_height": chain.finality.finalized_height,
                        "mempool": chain.mempool.len(),
                        "slashing_events": chain.slashing.events.len(),
                        "api_sync_events": api_sync_events,
                    });
                    println!("{}", payload);
                } else {
                    println!(
                        "Observe: height={} finalized={} mempool={} slashing_events={} api_sync_events={}",
                        chain.height(),
                        chain.finality.finalized_height,
                        chain.mempool.len(),
                        chain.slashing.events.len(),
                        api_sync_events
                    );
                }
            }
        });
    }

    let app = sccgub_api::router::build_router(app_state);

    let addr = format!("{}:{}", config.api.bind, port);
    println!("SCCGUB API server starting on http://{}", addr);
    println!("Endpoints (v1):");
    println!("  GET  /api/v1/status                  - chain summary");
    println!("  GET  /api/v1/health                  - system health + finality");
    println!("  GET  /api/v1/finality/certificates   - finality safety certificates");
    println!("  GET  /api/v1/slashing                - slashing summary");
    println!("  GET  /api/v1/slashing/{{validator_id}} - validator slashing detail");
    println!("  GET  /api/v1/slashing/evidence       - equivocation evidence list");
    println!("  GET  /api/v1/slashing/evidence/{{validator_id}} - validator evidence list");
    println!("  GET  /api/v1/block/{{height}}           - block detail with transactions");
    println!("  GET  /api/v1/block/{{height}}/receipts  - block receipts with gas breakdown");
    println!("  GET  /api/v1/state                   - paginated world state (?offset=&limit=)");
    println!("  GET  /api/v1/tx/{{tx_id}}               - transaction detail by ID");
    println!("  GET  /api/v1/receipt/{{tx_id}}          - receipt with verdict + resource usage");
    println!("  POST /api/v1/tx/submit               - submit signed transaction (hex)");
    println!("  POST /api/v1/governance/params/propose - submit signed param proposal (hex)");
    println!("  POST /api/v1/governance/proposals/vote - submit signed proposal vote (hex)");
    println!("Legacy routes (/api/*) also available.");
    println!();

    let listener = match tokio::net::TcpListener::bind(&addr).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("Failed to bind to {}: {}", addr, e);
            std::process::exit(1);
        }
    };
    if let Err(e) = axum::serve(listener, app).await {
        eprintln!("Server error: {}", e);
        std::process::exit(1);
    }
}

fn cmd_demo() {
    println!("=== SCCGUB Demo ===\n");

    let mut chain = Chain::init();
    chain.governance_limits.max_consecutive_proposals = 200;
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
        norm_set: BTreeSet::new(),
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

    println!();
    println!("=== Governance Demo ===");
    let proposer = *chain.validator_key.verifying_key().as_bytes();
    let proposal_height = chain.height();
    let proposal_id = chain
        .proposals
        .submit(
            proposer,
            PrecedenceLevel::Meaning,
            sccgub_governance::proposals::ProposalKind::AddNorm {
                name: "DemoNorm".into(),
                description: "Governance demo norm".into(),
                initial_fitness: sccgub_types::tension::TensionValue::from_integer(1),
                enforcement_cost: sccgub_types::tension::TensionValue::from_integer(1),
            },
            proposal_height,
            3,
        )
        .expect("proposal submission must succeed");

    chain
        .proposals
        .vote(
            &proposal_id,
            proposer,
            PrecedenceLevel::Meaning,
            true,
            proposal_height + 1,
        )
        .expect("proposal vote must succeed");

    let target_height = proposal_height + 3 + sccgub_governance::proposals::timelocks::ORDINARY + 2;
    while chain.height() < target_height {
        let _ = chain.produce_block();
    }

    let status = chain
        .proposals
        .proposals
        .iter()
        .find(|p| p.id == proposal_id)
        .map(|p| p.status)
        .unwrap_or(sccgub_governance::proposals::ProposalStatus::Expired);
    println!("  Proposal status: {:?}", status);
    println!(
        "  Active norm present: {}",
        chain
            .state
            .state
            .governance_state
            .active_norms
            .contains_key(&proposal_id)
    );

    println!();
    println!("=== Escrow Demo ===");
    let mut balances = sccgub_state::balances::BalanceLedger::new();
    let mut registry = sccgub_state::escrow::EscrowRegistry::new();
    let sender = [7u8; 32];
    let recipient = [8u8; 32];
    balances.credit(
        &sender,
        sccgub_types::tension::TensionValue::from_integer(1_000),
    );

    let escrow_id = registry
        .create(
            sender,
            recipient,
            sccgub_types::tension::TensionValue::from_integer(250),
            sccgub_state::escrow::EscrowCondition::TimeLocked { release_at: 5 },
            1,
            10,
            &mut balances,
        )
        .expect("escrow create must succeed");

    let state = sccgub_state::world::ManagedWorldState::new();
    let released_before =
        registry.check_and_release(&state, 4, &mut balances, &std::collections::HashMap::new());
    println!("  Released before timelock: {}", released_before.len());
    let released_after =
        registry.check_and_release(&state, 5, &mut balances, &std::collections::HashMap::new());
    println!("  Released at timelock: {}", released_after.len());
    println!(
        "  Escrow status: {:?}",
        registry.get(&escrow_id).map(|e| e.status)
    );
    println!("  Sender balance: {}", balances.balance_of(&sender).raw());
    println!(
        "  Recipient balance: {}",
        balances.balance_of(&recipient).raw()
    );
}

fn cmd_info() {
    println!("Symbolic Causal Chain General Universal Blockchain (SCCGUB)");
    println!(
        "Version: {} (hardening-stage single-node reference runtime)",
        env!("CARGO_PKG_VERSION")
    );
    println!();
    println!("Architecture:");
    println!("  Consensus:   Causal Proof-of-Governance (CPoG)");
    println!(
        "  Protocol:    Block v{} default, v1 replay-compatible",
        CURRENT_BLOCK_VERSION
    );
    println!("  Finality:    Deterministic runtime (p2p proposer rotation optional)");
    println!("  Validation:  13-phase Phi traversal");
    println!("  Contracts:   Symbolic Causal Contracts (decidable)");
    println!("  State:       Replay-authoritative world state with block log + snapshots");
    println!("  Identity:    Mfidel 34x8 Ge'ez atomic seal");
    println!("  Governance:  Live proposal timelocks + precedence order");
    println!("  Governed parameters:");
    println!("    governance.max_consecutive_proposals");
    println!("    governance.max_actions_per_agent_pct");
    println!("    governance.safety_change_min_signers");
    println!("    governance.genesis_change_min_signers");
    println!("    governance.max_authority_term_epochs");
    println!("    governance.authority_cooldown_epochs");
    println!("    finality.confirmation_depth");
    println!("    finality.max_finality_ms");
    println!("    finality.target_block_time_ms");
    println!("    finality.mode");
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

fn cmd_governed(data_dir: &std::path::Path, json: bool, schema: bool) {
    if schema {
        println!(
            "{}",
            include_str!("../../../specs/GOVERNED_JSON_SCHEMA.json")
        );
        return;
    }
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

    let chain = Chain::from_blocks(blocks).unwrap_or_else(|e| {
        eprintln!("Chain import failed: {}", e);
        std::process::exit(1);
    });

    if json {
        let payload = serde_json::json!({
            "governance": {
                "max_consecutive_proposals": chain.governance_limits.max_consecutive_proposals,
                "max_actions_per_agent_pct": chain.governance_limits.max_actions_per_agent_pct,
                "safety_change_min_signers": chain.governance_limits.safety_change_min_signers,
                "genesis_change_min_signers": chain.governance_limits.genesis_change_min_signers,
                "max_authority_term_epochs": chain.governance_limits.max_authority_term_epochs,
                "authority_cooldown_epochs": chain.governance_limits.authority_cooldown_epochs,
            },
            "finality": {
                "confirmation_depth": chain.finality_config.confirmation_depth,
                "max_finality_ms": chain.finality_config.max_finality_ms,
                "target_block_time_ms": chain.finality_config.target_block_time_ms,
            }
        });
        println!("{}", payload);
        return;
    }

    println!("Governed Parameter Values");
    println!(
        "  governance.max_consecutive_proposals = {}",
        chain.governance_limits.max_consecutive_proposals
    );
    println!(
        "  governance.max_actions_per_agent_pct = {}",
        chain.governance_limits.max_actions_per_agent_pct
    );
    println!(
        "  governance.safety_change_min_signers = {}",
        chain.governance_limits.safety_change_min_signers
    );
    println!(
        "  governance.genesis_change_min_signers = {}",
        chain.governance_limits.genesis_change_min_signers
    );
    println!(
        "  governance.max_authority_term_epochs = {}",
        chain.governance_limits.max_authority_term_epochs
    );
    println!(
        "  governance.authority_cooldown_epochs = {}",
        chain.governance_limits.authority_cooldown_epochs
    );
    println!(
        "  finality.confirmation_depth = {}",
        chain.finality_config.confirmation_depth
    );
    println!(
        "  finality.max_finality_ms = {}",
        chain.finality_config.max_finality_ms
    );
    println!(
        "  finality.target_block_time_ms = {}",
        chain.finality_config.target_block_time_ms
    );
}

fn cmd_governed_propose(data_dir: &std::path::Path, passphrase: &str, key: &str, value: &str) {
    let (mut chain, store) = load_chain_with_key(data_dir, passphrase);
    if !GOVERNED_PARAMETER_KEYS.contains(&key) {
        eprintln!("Unknown governed parameter key: {}", key);
        std::process::exit(1);
    }
    let actor_key = chain.validator_key.clone();
    let actor_pk = *actor_key.verifying_key().as_bytes();
    let actor_id = sccgub_state::apply::validator_spend_account(chain.block_version, &actor_pk);
    let last_nonce = chain
        .state
        .agent_nonces
        .get(&actor_id)
        .copied()
        .unwrap_or(0);
    let nonce = last_nonce + 1;

    let target = b"norms/governance/params/propose".to_vec();
    let payload_value = format!("{}={}", key, value).into_bytes();
    let mut tx = SymbolicTransition {
        tx_id: [0u8; 32],
        actor: AgentIdentity {
            agent_id: actor_id,
            public_key: actor_pk,
            mfidel_seal: MfidelAtomicSeal::from_height(0),
            registration_block: 0,
            governance_level: PrecedenceLevel::Safety,
            norm_set: BTreeSet::new(),
            responsibility: ResponsibilityState::default(),
        },
        intent: TransitionIntent {
            kind: TransitionKind::GovernanceUpdate,
            target: target.clone(),
            declared_purpose: "governed parameter proposal".into(),
        },
        preconditions: vec![],
        postconditions: vec![],
        payload: OperationPayload::Write {
            key: target.clone(),
            value: payload_value,
        },
        causal_chain: vec![],
        wh_binding_intent: WHBindingIntent {
            who: actor_id,
            when: CausalTimestamp::genesis(),
            r#where: target.clone(),
            why: CausalJustification {
                invoking_rule: [1u8; 32],
                precedence_level: PrecedenceLevel::Safety,
                causal_ancestors: vec![],
                constraint_proof: vec![],
            },
            how: TransitionMechanism::DirectStateWrite,
            which: BTreeSet::new(),
            what_declared: "governed parameter proposal".into(),
        },
        nonce,
        signature: vec![],
    };

    let canonical = sccgub_execution::validate::canonical_tx_bytes(&tx);
    tx.tx_id = blake3_hash(&canonical);
    tx.signature = sign(&actor_key, &canonical);

    chain.submit_transition(tx).unwrap_or_else(|e| {
        eprintln!("Proposal submission rejected: {}", e);
        std::process::exit(1);
    });

    let block = chain.produce_block().unwrap_or_else(|e| {
        eprintln!("Block production failed: {}", e);
        std::process::exit(1);
    });

    store.save_block(block).unwrap_or_else(|e| {
        eprintln!("Failed to persist block: {}", e);
        std::process::exit(1);
    });

    println!(
        "Governed parameter proposal submitted in block #{}",
        block.header.height
    );
}

fn cmd_governed_vote(data_dir: &std::path::Path, passphrase: &str, proposal_id: &str) {
    let (mut chain, store) = load_chain_with_key(data_dir, passphrase);
    let actor_key = chain.validator_key.clone();
    let actor_pk = *actor_key.verifying_key().as_bytes();
    let actor_id = sccgub_state::apply::validator_spend_account(chain.block_version, &actor_pk);
    let last_nonce = chain
        .state
        .agent_nonces
        .get(&actor_id)
        .copied()
        .unwrap_or(0);
    let nonce = last_nonce + 1;

    let proposal_bytes = parse_hex_32(proposal_id).unwrap_or_else(|e| {
        eprintln!("Invalid proposal id: {}", e);
        std::process::exit(1);
    });

    let target = b"norms/governance/proposals/vote".to_vec();
    let mut tx = SymbolicTransition {
        tx_id: [0u8; 32],
        actor: AgentIdentity {
            agent_id: actor_id,
            public_key: actor_pk,
            mfidel_seal: MfidelAtomicSeal::from_height(0),
            registration_block: 0,
            governance_level: PrecedenceLevel::Safety,
            norm_set: BTreeSet::new(),
            responsibility: ResponsibilityState::default(),
        },
        intent: TransitionIntent {
            kind: TransitionKind::GovernanceUpdate,
            target: target.clone(),
            declared_purpose: "governance proposal vote".into(),
        },
        preconditions: vec![],
        postconditions: vec![],
        payload: OperationPayload::Write {
            key: target.clone(),
            value: proposal_bytes.to_vec(),
        },
        causal_chain: vec![],
        wh_binding_intent: WHBindingIntent {
            who: actor_id,
            when: CausalTimestamp::genesis(),
            r#where: target.clone(),
            why: CausalJustification {
                invoking_rule: [1u8; 32],
                precedence_level: PrecedenceLevel::Safety,
                causal_ancestors: vec![],
                constraint_proof: vec![],
            },
            how: TransitionMechanism::DirectStateWrite,
            which: BTreeSet::new(),
            what_declared: "governance proposal vote".into(),
        },
        nonce,
        signature: vec![],
    };

    let canonical = sccgub_execution::validate::canonical_tx_bytes(&tx);
    tx.tx_id = blake3_hash(&canonical);
    tx.signature = sign(&actor_key, &canonical);

    chain.submit_transition(tx).unwrap_or_else(|e| {
        eprintln!("Vote submission rejected: {}", e);
        std::process::exit(1);
    });

    let block = chain.produce_block().unwrap_or_else(|e| {
        eprintln!("Block production failed: {}", e);
        std::process::exit(1);
    });

    store.save_block(block).unwrap_or_else(|e| {
        eprintln!("Failed to persist block: {}", e);
        std::process::exit(1);
    });

    println!(
        "Governance vote submitted in block #{}",
        block.header.height
    );
}

fn cmd_governed_status(data_dir: &std::path::Path) {
    let store = ChainStore::new(data_dir).unwrap_or_else(|e| {
        eprintln!("Failed to open data directory: {}", e);
        std::process::exit(1);
    });

    let blocks = store.load_all_blocks().unwrap_or_else(|_| {
        eprintln!("No chain found. Run `sccgub init` first.");
        std::process::exit(1);
    });

    let chain = Chain::from_blocks(blocks).unwrap_or_else(|e| {
        eprintln!("Chain import failed: {}", e);
        std::process::exit(1);
    });

    println!("Governance Proposal Registry");
    println!("  Total proposals: {}", chain.proposals.proposals.len());
    for proposal in &chain.proposals.proposals {
        println!(
            "  - id={} status={:?} votes_for={} votes_against={} timelock_until={} submitted_at={}",
            hex::encode(proposal.id),
            proposal.status,
            proposal.votes_for,
            proposal.votes_against,
            proposal.timelock_until,
            proposal.submitted_at
        );
    }
}

fn load_chain_with_key(data_dir: &std::path::Path, passphrase: &str) -> (Chain, ChainStore) {
    let store = ChainStore::new(data_dir).unwrap_or_else(|e| {
        eprintln!("Failed to open data directory: {}", e);
        std::process::exit(1);
    });

    let blocks = store.load_all_blocks().unwrap_or_else(|_| {
        eprintln!("No chain found. Run `sccgub init` first.");
        std::process::exit(1);
    });

    let mut chain = Chain::from_blocks(blocks).unwrap_or_else(|e| {
        eprintln!("Chain import failed: {}", e);
        std::process::exit(1);
    });
    restore_safety_certificates_if_available(&store, &mut chain);

    if !store.has_validator_key() {
        eprintln!("Validator key not found. Run `sccgub init` first.");
        std::process::exit(1);
    }

    let key = store.load_validator_key(passphrase).unwrap_or_else(|e| {
        eprintln!("Failed to load validator key: {}", e);
        std::process::exit(1);
    });
    chain.validator_key = key;

    (chain, store)
}

fn parse_hex_32(value: &str) -> Result<[u8; 32], String> {
    let bytes = hex::decode(value).map_err(|e| format!("hex decode failed: {}", e))?;
    if bytes.len() != 32 {
        return Err(format!("expected 32 bytes, got {}", bytes.len()));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
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
    let key = sccgub_types::namespace::data_key(
        format!("h{}/entry/{}", base_height + 1, index).as_bytes(),
    );
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
        which: BTreeSet::new(),
        what_declared: format!("Write entry #{}", index),
    };

    let payload = OperationPayload::Write {
        key: key.clone(),
        value: value.clone(),
    };

    let nonce = index as u128 + 1; // Sequential for the fresh agent created in cmd_produce.

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

    let chain = Chain::from_blocks(blocks).unwrap_or_else(|e| {
        eprintln!("Chain import failed: {}", e);
        std::process::exit(1);
    });

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

    let chain = Chain::from_blocks(blocks).unwrap_or_else(|e| {
        eprintln!("Chain import failed: {}", e);
        std::process::exit(1);
    });

    println!("=== Escrow Status ===\n");
    println!("  Chain height:       {}", chain.height());
    println!("  Total supply:       {}", chain.balances.total_supply());
    println!("  Active accounts:    {}", chain.balances.account_count());
    println!();
    println!("  (Escrow registry is initialized per-session;");
    println!("   persistent escrow state requires state trie integration.)");
}
