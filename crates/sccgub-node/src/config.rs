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
pub struct StorageConfig {
    /// Data directory path.
    pub data_dir: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorConfig {
    /// Key passphrase (overridden by --passphrase CLI arg or SCCGUB_PASSPHRASE env var).
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
            },
            api: ApiConfig {
                port: 3000,
                bind: "127.0.0.1".into(),
                page_size: 100,
            },
            storage: StorageConfig {
                data_dir: PathBuf::from(".sccgub"),
            },
            validator: ValidatorConfig {
                key_passphrase: String::new(), // Must be set by operator.
            },
        }
    }
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
        assert!(config.validator.key_passphrase.is_empty());
    }

    #[test]
    fn test_config_roundtrip() {
        let config = NodeConfig::default();
        let toml_str = toml::to_string_pretty(&config).unwrap();
        let parsed: NodeConfig = toml::from_str(&toml_str).unwrap();
        assert_eq!(parsed.chain.genesis_supply, config.chain.genesis_supply);
        assert_eq!(parsed.api.port, config.api.port);
    }
}
