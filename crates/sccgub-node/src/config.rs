use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Node configuration — loaded from TOML file or defaults.
/// This replaces all hardcoded values with operator-configurable parameters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeConfig {
    /// Chain parameters.
    pub chain: ChainConfig,
    /// API server parameters.
    pub api: ApiConfig,
    /// API sync parameters.
    pub api_sync: ApiSyncConfig,
    /// Network (p2p) parameters.
    pub network: NetworkConfig,
    /// Storage parameters.
    pub storage: StorageConfig,
    /// Validator parameters.
    pub validator: ValidatorConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainConfig {
    /// Initial token supply at genesis.
    pub genesis_supply: i64,
    /// Maximum transactions per block.
    pub max_txs_per_block: u32,
    /// Block snapshot interval (every N blocks).
    pub snapshot_interval: u64,
    /// Finality confirmation depth.
    pub finality_depth: u64,
    /// Initial finality mode for genesis (e.g. "deterministic" or "bft:2").
    #[serde(default)]
    pub initial_finality_mode: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiConfig {
    /// Port for the REST API server.
    pub port: u16,
    /// Bind address.
    pub bind: String,
    /// Maximum state entries per page.
    pub page_size: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiSyncConfig {
    /// Minimum milliseconds between API state syncs.
    pub min_interval_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    /// Whether p2p networking is enabled.
    pub enable: bool,
    /// Bind address for the p2p listener.
    pub bind: String,
    /// Port for the p2p listener.
    pub port: u16,
    /// Known peer addresses (host:port).
    pub peers: Vec<String>,
    /// Optional allowlist for inbound peers (host or host:port).
    pub allowed_peers: Vec<String>,
    /// Validator public keys (hex) for proposer rotation.
    pub validators: Vec<String>,
    /// Target block interval (ms) for proposer loop.
    pub block_interval_ms: u64,
    /// Whether to run the proposer loop (auto-proposal).
    #[serde(default = "default_true")]
    pub proposer_loop_enabled: bool,
    /// Consensus round timeout (ms) before advancing to next round.
    pub round_timeout_ms: u64,
    /// Maximum rounds before aborting a height.
    pub max_rounds: u32,
    /// Validator set epoch (binds vote signatures).
    pub epoch: u64,
    /// Protocol version advertised in Hello.
    pub protocol_version: u32,
    /// Inbound message rate window (ms).
    pub inbound_msg_window_ms: u64,
    /// Maximum inbound messages per window per peer.
    pub inbound_msg_limit: u32,
    /// Initial peer score on first handshake.
    pub peer_score_initial: i32,
    /// Score penalty per violation.
    pub peer_score_penalty: i32,
    /// Score threshold at or below which a peer is banned.
    pub peer_score_ban_threshold: i32,
    /// Maximum recorded violations before banning a peer.
    pub peer_max_violations: u32,
    /// Score decay interval for connected peers (ms).
    pub peer_score_decay_interval_ms: u64,
    /// Score increment applied during decay.
    pub peer_score_decay_amount: i32,
    /// Violation forgiveness interval (ms).
    pub peer_violation_forgive_interval_ms: u64,
    /// Bandwidth accounting window (ms).
    pub bandwidth_window_ms: u64,
    /// Maximum inbound bytes per window per peer.
    pub inbound_bytes_limit: u64,
    /// Maximum outbound bytes per window per peer.
    pub outbound_bytes_limit: u64,
    /// Minimum number of distinct connected peers required for finality.
    pub min_connected_peers: usize,
    /// Maximum percent of connected peers allowed from the same /16 subnet.
    pub max_same_subnet_pct: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageConfig {
    /// Data directory path.
    pub data_dir: PathBuf,
    /// Whether to restore chain state from snapshots on boot.
    pub snapshot_restore_enabled: bool,
    /// Whether to enable the durable state store (sled-backed).
    #[serde(default)]
    pub state_store_enabled: bool,
    /// Directory for the durable state store (relative to data dir if not absolute).
    #[serde(default)]
    pub state_store_dir: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorConfig {
    /// Key passphrase (overridden by --passphrase CLI arg or SCCGUB_PASSPHRASE env var).
    ///
    /// SECURITY: prefer the SCCGUB_PASSPHRASE environment variable over this field.
    /// Config files may be world-readable; storing passphrases in plaintext on disk
    /// is a key-exposure risk. This field exists for development convenience only.
    pub key_passphrase: String,
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            chain: ChainConfig {
                genesis_supply: 1_000_000,
                max_txs_per_block: 1000,
                snapshot_interval: 10,
                finality_depth: 2,
                initial_finality_mode: None,
            },
            api: ApiConfig {
                port: 3000,
                bind: "127.0.0.1".into(),
                page_size: 100,
            },
            api_sync: ApiSyncConfig {
                min_interval_ms: 250,
            },
            network: NetworkConfig {
                enable: false,
                bind: "0.0.0.0".into(),
                port: 9000,
                peers: Vec::new(),
                allowed_peers: Vec::new(),
                validators: Vec::new(),
                block_interval_ms: 5_000,
                proposer_loop_enabled: true,
                round_timeout_ms: 4_000,
                max_rounds: 3,
                epoch: 0,
                protocol_version: 1,
                inbound_msg_window_ms: 1_000,
                inbound_msg_limit: 50,
                peer_score_initial: 100,
                peer_score_penalty: 10,
                peer_score_ban_threshold: 0,
                peer_max_violations: 5,
                peer_score_decay_interval_ms: 10_000,
                peer_score_decay_amount: 1,
                peer_violation_forgive_interval_ms: 30_000,
                bandwidth_window_ms: 1_000,
                inbound_bytes_limit: 64 * 1024,
                outbound_bytes_limit: 64 * 1024,
                min_connected_peers: 3,
                max_same_subnet_pct: 50,
            },
            storage: StorageConfig {
                data_dir: PathBuf::from(".sccgub"),
                snapshot_restore_enabled: true,
                state_store_enabled: false,
                state_store_dir: PathBuf::from("state_db"),
            },
            validator: ValidatorConfig {
                key_passphrase: String::new(), // Must be set by operator.
            },
        }
    }
}

fn default_true() -> bool {
    true
}

impl NodeConfig {
    /// Load config from a TOML file, falling back to defaults.
    pub fn load(path: &Path) -> Self {
        match std::fs::read_to_string(path) {
            Ok(content) => match toml::from_str(&content) {
                Ok(config) => config,
                Err(e) => {
                    eprintln!("Warning: config parse error: {}. Using defaults.", e);
                    Self::default()
                }
            },
            Err(_) => Self::default(),
        }
    }

    /// Get the effective passphrase (env var > config file > empty).
    pub fn effective_passphrase(&self) -> String {
        std::env::var("SCCGUB_PASSPHRASE").unwrap_or_else(|_| self.validator.key_passphrase.clone())
    }

    /// Write default config to a file.
    pub fn write_default(path: &Path) -> std::io::Result<()> {
        let config = Self::default();
        let content =
            toml::to_string_pretty(&config).unwrap_or_else(|_| "# Failed to serialize".into());
        std::fs::write(path, content)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = NodeConfig::default();
        assert_eq!(config.chain.genesis_supply, 1_000_000);
        assert_eq!(config.api.port, 3000);
        assert_eq!(config.api.bind, "127.0.0.1");
        assert_eq!(config.api_sync.min_interval_ms, 250);
        assert!(config.chain.initial_finality_mode.is_none());
        assert!(config.storage.snapshot_restore_enabled);
        assert!(!config.storage.state_store_enabled);
        assert_eq!(config.storage.state_store_dir, PathBuf::from("state_db"));
        assert_eq!(config.network.port, 9000);
        assert_eq!(config.network.bind, "0.0.0.0");
        assert!(config.network.allowed_peers.is_empty());
        assert!(config.network.proposer_loop_enabled);
        assert_eq!(config.network.min_connected_peers, 3);
        assert_eq!(config.network.max_same_subnet_pct, 50);
        assert!(config.validator.key_passphrase.is_empty());
    }

    #[test]
    fn test_config_roundtrip() {
        let config = NodeConfig::default();
        let toml_str = toml::to_string_pretty(&config).unwrap();
        let parsed: NodeConfig = toml::from_str(&toml_str).unwrap();
        assert_eq!(parsed.chain.genesis_supply, config.chain.genesis_supply);
        assert_eq!(parsed.api.port, config.api.port);
        assert_eq!(
            parsed.api_sync.min_interval_ms,
            config.api_sync.min_interval_ms
        );
    }
}
