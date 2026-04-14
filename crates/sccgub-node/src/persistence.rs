use std::fs;
use std::path::{Path, PathBuf};

use crate::config::StorageConfig;
use sccgub_consensus::safety::SafetyCertificate;
use sccgub_state::store::SledStateStore;
use sccgub_types::block::Block;

const STORAGE_VERSION: &str = env!("CARGO_PKG_VERSION");
const VALIDATOR_KEY_FILE: &str = "validator.key";

/// Chain persistence - save and load blocks, metadata, validator keys, and snapshots.
#[allow(dead_code)]
pub struct ChainStore {
    base_dir: PathBuf,
}

#[allow(dead_code)]
impl ChainStore {
    /// Create a new chain store at the given directory.
    /// Cleans up any stale .tmp files from interrupted writes.
    pub fn new(base_dir: &Path) -> std::io::Result<Self> {
        fs::create_dir_all(base_dir.join("blocks"))?;
        fs::create_dir_all(base_dir.join("state"))?;
        // Clean up stale .tmp files from interrupted atomic writes.
        if let Ok(entries) = fs::read_dir(base_dir.join("blocks")) {
            for entry in entries.flatten() {
                if entry.file_name().to_string_lossy().ends_with(".tmp") {
                    let _ = fs::remove_file(entry.path());
                }
            }
        }
        Ok(Self {
            base_dir: base_dir.to_path_buf(),
        })
    }

    /// Save a block to disk as JSON using atomic write (write-then-rename).
    pub fn save_block(&self, block: &Block) -> std::io::Result<()> {
        let filename = format!("block_{:010}.json", block.header.height);
        let path = self.base_dir.join("blocks").join(&filename);
        let tmp_path = self
            .base_dir
            .join("blocks")
            .join(format!("{}.tmp", filename));
        let json = serde_json::to_string_pretty(block).map_err(std::io::Error::other)?;
        // Write to temp file first, then rename for atomicity.
        fs::write(&tmp_path, &json)?;
        fs::rename(&tmp_path, &path)?;
        Ok(())
    }

    /// Load a block from disk by height. Verifies structural integrity after load.
    pub fn load_block(&self, height: u64) -> std::io::Result<Block> {
        let filename = format!("block_{:010}.json", height);
        let path = self.base_dir.join("blocks").join(filename);
        let json = fs::read_to_string(path)?;
        let block: Block = serde_json::from_str(&json).map_err(std::io::Error::other)?;
        // Verify structural integrity on load.
        if !block.is_structurally_valid() {
            return Err(std::io::Error::other(format!(
                "Block #{} failed structural validation after load",
                height
            )));
        }
        Ok(block)
    }

    /// Load all blocks from disk in order. Filters to valid block files only.
    pub fn load_all_blocks(&self) -> std::io::Result<Vec<Block>> {
        let blocks_dir = self.base_dir.join("blocks");
        let mut entries: Vec<_> = fs::read_dir(&blocks_dir)?
            .filter_map(|e| e.ok())
            .filter(|e| {
                let name = e.file_name();
                let s = name.to_string_lossy();
                s.starts_with("block_") && s.ends_with(".json") && !s.ends_with(".tmp")
            })
            .collect();

        entries.sort_by_key(|e| e.file_name());

        let mut blocks = Vec::new();
        for entry in entries {
            let json = fs::read_to_string(entry.path())?;
            let block: Block = serde_json::from_str(&json).map_err(std::io::Error::other)?;
            if !block.is_structurally_valid() {
                return Err(std::io::Error::other(format!(
                    "Block #{} failed structural validation",
                    block.header.height
                )));
            }
            // Verify height continuity and parent chain linkage.
            let expected_height = blocks.len() as u64;
            if block.header.height != expected_height {
                return Err(std::io::Error::other(format!(
                    "Block height gap: expected {}, got {}",
                    expected_height, block.header.height
                )));
            }
            if expected_height > 0 {
                let prev: &Block = &blocks[blocks.len() - 1];
                if block.header.parent_id != prev.header.block_id {
                    return Err(std::io::Error::other(format!(
                        "Parent chain broken at height {}: parent {} != prev block {}",
                        block.header.height,
                        hex::encode(block.header.parent_id),
                        hex::encode(prev.header.block_id),
                    )));
                }
            }
            blocks.push(block);
        }
        Ok(blocks)
    }

    /// Get the latest block height on disk (reads only the last file).
    pub fn latest_height(&self) -> std::io::Result<Option<u64>> {
        let blocks_dir = self.base_dir.join("blocks");
        let mut entries: Vec<_> = fs::read_dir(&blocks_dir)?
            .filter_map(|e| e.ok())
            .filter(|e| {
                let name = e.file_name();
                let s = name.to_string_lossy();
                s.starts_with("block_") && s.ends_with(".json") && !s.ends_with(".tmp")
            })
            .collect();
        entries.sort_by_key(|e| e.file_name());
        match entries.last() {
            None => Ok(None),
            Some(entry) => {
                let json = fs::read_to_string(entry.path())?;
                let block: Block = serde_json::from_str(&json).map_err(std::io::Error::other)?;
                Ok(Some(block.header.height))
            }
        }
    }

    /// Save chain metadata (atomic write).
    pub fn save_metadata(&self, chain_id: &[u8; 32]) -> std::io::Result<()> {
        let path = self.base_dir.join("chain_meta.json");
        let tmp_path = self.base_dir.join("chain_meta.json.tmp");
        let json = serde_json::json!({
            "chain_id": hex::encode(chain_id),
            "version": STORAGE_VERSION,
            "spec": "SCCGUB v2.1"
        });
        fs::write(
            &tmp_path,
            serde_json::to_string_pretty(&json).map_err(std::io::Error::other)?,
        )?;
        fs::rename(&tmp_path, &path)
    }

    pub fn base_dir(&self) -> &Path {
        &self.base_dir
    }

    pub fn open_state_store(&self, config: &StorageConfig) -> Result<SledStateStore, String> {
        let path = if config.state_store_dir.is_absolute() {
            config.state_store_dir.clone()
        } else {
            self.base_dir.join(&config.state_store_dir)
        };
        if let Err(err) = fs::create_dir_all(&path) {
            return Err(format!("state store dir create failed: {}", err));
        }
        SledStateStore::open(&path)
    }

    fn validator_key_path(&self) -> PathBuf {
        self.base_dir.join(VALIDATOR_KEY_FILE)
    }

    /// Save validator key to disk using the shared finance-grade keystore bundle.
    pub fn save_validator_key(
        &self,
        key: &ed25519_dalek::SigningKey,
        passphrase: &str,
    ) -> std::io::Result<()> {
        let path = self.validator_key_path();
        let tmp_path = self.base_dir.join(format!("{}.tmp", VALIDATOR_KEY_FILE));
        let bundle =
            sccgub_crypto::keystore::encrypt_key(key, passphrase).map_err(std::io::Error::other)?;
        let json = serde_json::to_string_pretty(&bundle).map_err(std::io::Error::other)?;
        fs::write(&tmp_path, json)?;
        fs::rename(&tmp_path, &path)
    }

    /// Load validator key from disk.
    ///
    /// New keystore files are JSON bundles produced by `sccgub_crypto::keystore`.
    /// Legacy Blake3-XOR files are still accepted for backward-compatible reads.
    pub fn load_validator_key(
        &self,
        passphrase: &str,
    ) -> std::io::Result<ed25519_dalek::SigningKey> {
        let path = self.validator_key_path();
        let content = fs::read_to_string(path)?;
        if content.trim_start().starts_with('{') {
            let bundle: sccgub_crypto::keystore::EncryptedKeyBundle =
                serde_json::from_str(&content).map_err(std::io::Error::other)?;
            return sccgub_crypto::keystore::decrypt_key(&bundle, passphrase)
                .map_err(std::io::Error::other);
        }

        let encrypted = hex::decode(content.trim())
            .map_err(|e| std::io::Error::other(format!("Invalid legacy key hex: {}", e)))?;
        if encrypted.len() != 32 {
            return Err(std::io::Error::other(
                "Legacy encrypted key must be 32 bytes",
            ));
        }

        let mut enc_bytes = [0u8; 32];
        enc_bytes.copy_from_slice(&encrypted);
        let raw = decrypt_key_legacy(&enc_bytes, passphrase);
        Ok(ed25519_dalek::SigningKey::from_bytes(&raw))
    }

    /// Check if a validator key exists on disk.
    pub fn has_validator_key(&self) -> bool {
        self.validator_key_path().exists()
    }

    /// Save consensus round state for crash recovery.
    /// Persisted after each vote or round advancement so a restarted
    /// validator can rejoin the current round without re-voting.
    pub fn save_consensus_state(
        &self,
        rounds: &std::collections::HashMap<u64, serde_json::Value>,
    ) -> std::io::Result<()> {
        let path = self.base_dir.join("consensus_rounds.json");
        let tmp_path = self.base_dir.join("consensus_rounds.json.tmp");
        let serializable: std::collections::HashMap<String, serde_json::Value> = rounds
            .iter()
            .map(|(k, v)| (k.to_string(), v.clone()))
            .collect();
        let json = serde_json::to_string(&serializable).map_err(std::io::Error::other)?;
        fs::write(&tmp_path, json)?;
        fs::rename(&tmp_path, &path)
    }

    pub fn save_safety_certificates(
        &self,
        certificates: &[SafetyCertificate],
    ) -> std::io::Result<()> {
        let path = self.base_dir.join("safety_certs.json");
        let tmp_path = self.base_dir.join("safety_certs.json.tmp");
        let json = serde_json::to_string_pretty(certificates).map_err(std::io::Error::other)?;
        fs::write(&tmp_path, &json)?;
        fs::rename(&tmp_path, &path)
    }

    /// Load persisted consensus round state on restart.
    /// Returns empty map if no state exists (clean start).
    pub fn load_consensus_state(
        &self,
    ) -> std::io::Result<std::collections::HashMap<u64, serde_json::Value>> {
        let path = self.base_dir.join("consensus_rounds.json");
        if !path.exists() {
            return Ok(std::collections::HashMap::new());
        }
        let data = fs::read_to_string(&path)?;
        let raw: std::collections::HashMap<String, serde_json::Value> =
            serde_json::from_str(&data).map_err(std::io::Error::other)?;
        let mut parsed = std::collections::HashMap::new();
        for (key, value) in raw {
            let height = key.parse::<u64>().map_err(|e| {
                std::io::Error::other(format!("Invalid consensus height {}: {}", key, e))
            })?;
            parsed.insert(height, value);
        }
        Ok(parsed)
    }

    pub fn load_safety_certificates(&self) -> std::io::Result<Vec<SafetyCertificate>> {
        let path = self.base_dir.join("safety_certs.json");
        if !path.exists() {
            return Ok(Vec::new());
        }
        let data = fs::read_to_string(&path)?;
        let certs: Vec<SafetyCertificate> =
            serde_json::from_str(&data).map_err(std::io::Error::other)?;
        Ok(certs)
    }

    /// Clear persisted consensus state (after successful finalization).
    pub fn clear_consensus_state(&self) -> std::io::Result<()> {
        let path = self.base_dir.join("consensus_rounds.json");
        if path.exists() {
            fs::remove_file(&path)?;
        }
        Ok(())
    }

    pub fn clear_safety_certificates(&self) -> std::io::Result<()> {
        let path = self.base_dir.join("safety_certs.json");
        if path.exists() {
            fs::remove_file(&path)?;
        }
        Ok(())
    }

    /// Save a state snapshot at a given height.
    /// Snapshots contain the full state trie + nonces + balances, enabling
    /// fast chain load without replaying all blocks from genesis.
    pub fn save_snapshot(&self, snapshot: &StateSnapshot) -> std::io::Result<()> {
        let filename = format!("snapshot_{:010}.json", snapshot.height);
        let path = self.base_dir.join("state").join(&filename);
        let tmp_path = self
            .base_dir
            .join("state")
            .join(format!("{}.tmp", filename));
        let json = serde_json::to_string(snapshot).map_err(std::io::Error::other)?;
        fs::write(&tmp_path, &json)?;
        fs::rename(&tmp_path, &path)
    }

    /// Load the latest state snapshot.
    pub fn load_latest_snapshot(&self) -> std::io::Result<Option<StateSnapshot>> {
        let state_dir = self.base_dir.join("state");
        let mut entries: Vec<_> = fs::read_dir(&state_dir)?
            .filter_map(|e| e.ok())
            .filter(|e| {
                let name = e.file_name();
                let s = name.to_string_lossy();
                s.starts_with("snapshot_") && s.ends_with(".json") && !s.ends_with(".tmp")
            })
            .collect();

        if entries.is_empty() {
            return Ok(None);
        }

        entries.sort_by_key(|e| e.file_name());
        let Some(latest) = entries.last() else {
            return Ok(None);
        };
        let json = fs::read_to_string(latest.path())?;
        let snapshot: StateSnapshot = serde_json::from_str(&json).map_err(std::io::Error::other)?;
        Ok(Some(snapshot))
    }
}

/// Legacy validator-key masking retained only for backward-compatible reads.
/// New writes use Argon2id + ChaCha20-Poly1305 in `sccgub_crypto::keystore`.
fn encrypt_key_legacy(key: &[u8; 32], passphrase: &str) -> [u8; 32] {
    let mask = sccgub_crypto::hash::blake3_hash(passphrase.as_bytes());
    let mut encrypted = [0u8; 32];
    for i in 0..32 {
        encrypted[i] = key[i] ^ mask[i];
    }
    encrypted
}

/// Legacy validator-key decrypt (XOR is its own inverse).
fn decrypt_key_legacy(encrypted: &[u8; 32], passphrase: &str) -> [u8; 32] {
    encrypt_key_legacy(encrypted, passphrase)
}

/// State snapshot for fast chain loading.
/// Captures all consensus-critical state needed to resume without replay.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct StateSnapshot {
    pub height: u64,
    pub state_root: sccgub_types::MerkleRoot,
    /// Full state trie entries.
    pub trie_entries: Vec<(Vec<u8>, Vec<u8>)>,
    /// Per-agent nonces.
    pub agent_nonces: Vec<(sccgub_types::AgentId, u128)>,
    /// Balance ledger entries.
    pub balances: Vec<(sccgub_types::AgentId, i128)>,
    /// Treasury pending fees (raw i128).
    pub treasury_pending_raw: i128,
    /// Treasury total fees collected (raw i128).
    pub treasury_collected_raw: i128,
    /// Treasury total rewards distributed (raw i128).
    pub treasury_distributed_raw: i128,
    /// Treasury total burned (raw i128).
    pub treasury_burned_raw: i128,
    /// Treasury epoch number.
    pub treasury_epoch: u64,
    /// Finalized block height.
    pub finalized_height: u64,
    /// Slashing events recorded so far.
    #[serde(default)]
    pub slashing_events: Vec<sccgub_consensus::slashing::SlashingEvent>,
    /// Slashing stakes (validator_id -> raw stake).
    #[serde(default)]
    pub slashing_stakes: Vec<(sccgub_types::Hash, i128)>,
    /// Slashing removed validators.
    #[serde(default)]
    pub slashing_removed: Vec<sccgub_types::Hash>,
    /// Slashing absence counters (validator_id -> consecutive absent epochs).
    #[serde(default)]
    pub slashing_absence: Vec<(sccgub_types::Hash, u32)>,
    /// Equivocation evidence records (proof + epoch).
    #[serde(default)]
    pub equivocation_records: Vec<(sccgub_consensus::protocol::EquivocationProof, u64)>,
    /// Safety certificates from BFT finality (consensus proofs).
    #[serde(default)]
    pub safety_certificates: Vec<sccgub_consensus::safety::SafetyCertificate>,
    /// Active validator set snapshot (for proposer rotation).
    #[serde(default)]
    pub validator_set: Vec<sccgub_types::agent::ValidatorAuthority>,
    /// Governance limits snapshot (for restart-safe parameters).
    #[serde(default)]
    pub governance_limits: sccgub_governance::anti_concentration::GovernanceLimits,
    /// Finality config snapshot (for restart-safe parameters).
    #[serde(default)]
    pub finality_config: sccgub_consensus::finality::FinalityConfig,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::Chain;
    use sccgub_crypto::hash::blake3_hash;
    use sccgub_crypto::keys::generate_keypair;
    use sccgub_types::block::{Block, BlockBody, BlockHeader};
    use sccgub_types::causal::CausalGraphDelta;
    use sccgub_types::governance::{FinalityMode, GovernanceSnapshot};
    use sccgub_types::mfidel::MfidelAtomicSeal;
    use sccgub_types::proof::{CausalProof, PhiTraversalLog};
    use sccgub_types::tension::TensionValue;
    use sccgub_types::timestamp::CausalTimestamp;
    use sccgub_types::transition::*;
    use sccgub_types::ZERO_HASH;
    use std::collections::BTreeSet;

    fn test_block(height: u64) -> Block {
        Block {
            header: BlockHeader {
                chain_id: [1u8; 32], // Non-zero for non-genesis validity.
                // block_id uses height+1 so block 0 is non-zero.
                block_id: [(height + 1) as u8; 32],
                parent_id: if height == 0 {
                    ZERO_HASH
                } else {
                    // Must match prev block_id: [height as u8; 32].
                    [height as u8; 32]
                },
                height,
                timestamp: CausalTimestamp::genesis(),
                state_root: ZERO_HASH,
                transition_root: ZERO_HASH,
                receipt_root: ZERO_HASH,
                causal_root: ZERO_HASH,
                proof_root: ZERO_HASH,
                governance_hash: ZERO_HASH,
                tension_before: TensionValue::ZERO,
                tension_after: TensionValue::ZERO,
                mfidel_seal: MfidelAtomicSeal::from_height(height),
                balance_root: ZERO_HASH,
                validator_id: ZERO_HASH,
                version: 1,
            },
            body: BlockBody {
                transitions: vec![],
                transition_count: 0,
                total_tension_delta: TensionValue::ZERO,
                constraint_satisfaction: vec![],
                genesis_consensus_params: None,
            },
            receipts: vec![],
            causal_delta: CausalGraphDelta::default(),
            proof: CausalProof {
                block_height: height,
                transitions_proven: vec![],
                phi_traversal_log: PhiTraversalLog::default(),
                governance_snapshot_hash: ZERO_HASH,
                tension_before: TensionValue::ZERO,
                tension_after: TensionValue::ZERO,
                constraint_results: vec![],
                recursion_depth: 0,
                validator_signature: vec![],
                causal_hash: ZERO_HASH,
            },
            governance: GovernanceSnapshot {
                state_hash: ZERO_HASH,
                active_norm_count: 0,
                emergency_mode: false,
                finality_mode: FinalityMode::Deterministic,
                governance_limits: sccgub_types::governance::GovernanceLimitsSnapshot::default(),
                finality_config: sccgub_types::governance::FinalityConfigSnapshot::default(),
            },
        }
    }

    #[test]
    fn test_save_and_load_block() {
        let dir = std::env::temp_dir().join(format!("sccgub_test_{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let store = ChainStore::new(&dir).unwrap();

        let block = test_block(0);
        store.save_block(&block).unwrap();

        let loaded = store.load_block(0).unwrap();
        assert_eq!(loaded.header.height, 0);
        assert_eq!(loaded.header.block_id, block.header.block_id);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_load_all_blocks() {
        let dir = std::env::temp_dir().join(format!("sccgub_test_all_{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let store = ChainStore::new(&dir).unwrap();

        for h in 0..5 {
            store.save_block(&test_block(h)).unwrap();
        }

        let blocks = store.load_all_blocks().unwrap();
        assert_eq!(blocks.len(), 5);
        for (i, block) in blocks.iter().enumerate() {
            assert_eq!(block.header.height, i as u64);
        }

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_save_and_load_validator_key_roundtrip() {
        let dir = std::env::temp_dir().join(format!("sccgub_key_test_{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let store = ChainStore::new(&dir).unwrap();
        let key = generate_keypair();

        store
            .save_validator_key(&key, "node-passphrase")
            .expect("validator keystore should save");

        let loaded = store
            .load_validator_key("node-passphrase")
            .expect("validator keystore should load");
        assert_eq!(loaded.as_bytes(), key.as_bytes());
        assert!(
            fs::read_to_string(dir.join(VALIDATOR_KEY_FILE))
                .unwrap()
                .trim_start()
                .starts_with('{'),
            "new validator keystore format must be JSON"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_load_legacy_validator_key_roundtrip() {
        let dir = std::env::temp_dir().join(format!("sccgub_key_legacy_{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let store = ChainStore::new(&dir).unwrap();
        let key = generate_keypair();
        let encrypted = encrypt_key_legacy(&key.to_bytes(), "legacy-passphrase");
        fs::write(dir.join(VALIDATOR_KEY_FILE), hex::encode(encrypted)).unwrap();

        let loaded = store
            .load_validator_key("legacy-passphrase")
            .expect("legacy validator key should still load");
        assert_eq!(loaded.as_bytes(), key.as_bytes());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_save_and_load_safety_certificates() {
        let dir = std::env::temp_dir().join(format!("sccgub_safety_{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let store = ChainStore::new(&dir).unwrap();

        let cert = SafetyCertificate {
            chain_id: [1u8; 32],
            epoch: 7,
            height: 12,
            block_hash: [2u8; 32],
            round: 1,
            precommit_signatures: vec![([3u8; 32], vec![0u8; 64])],
            quorum: 1,
            validator_count: 1,
        };

        store
            .save_safety_certificates(&[cert.clone()])
            .expect("safety certs should save");
        let loaded = store
            .load_safety_certificates()
            .expect("safety certs should load");
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].height, cert.height);
        assert_eq!(loaded[0].block_hash, cert.block_hash);
        assert_eq!(loaded[0].round, cert.round);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_snapshot_restore_matches_block_replay() {
        let dir =
            std::env::temp_dir().join(format!("sccgub_snapshot_restore_{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let store = ChainStore::new(&dir).unwrap();

        let mut chain = Chain::init();
        chain.governance_limits.max_consecutive_proposals = 100;
        let genesis = chain.latest_block().unwrap().clone();
        store.save_block(&genesis).unwrap();

        for _ in 0..5 {
            chain.produce_block().unwrap();
            let block = chain.latest_block().unwrap().clone();
            store.save_block(&block).unwrap();
        }

        let snapshot = chain.create_snapshot();
        store.save_snapshot(&snapshot).unwrap();

        let blocks = store.load_all_blocks().unwrap();
        let mut replayed = Chain::from_blocks(blocks).unwrap();

        assert_eq!(snapshot.height, replayed.height());
        assert_eq!(snapshot.state_root, replayed.state.state_root());

        replayed.restore_from_snapshot(&snapshot);

        assert_eq!(
            replayed.state.state_root(),
            chain.state.state_root(),
            "Snapshot restore must match replayed state root"
        );
        assert_eq!(
            replayed.balances.total_supply(),
            chain.balances.total_supply(),
            "Snapshot restore must preserve total supply"
        );
        assert_eq!(
            replayed.governance_limits.max_consecutive_proposals,
            chain.governance_limits.max_consecutive_proposals
        );
        assert_eq!(
            replayed.finality_config.confirmation_depth,
            chain.finality_config.confirmation_depth
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_persisted_finality_config_replays() {
        let dir =
            std::env::temp_dir().join(format!("sccgub_finality_persist_{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let store = ChainStore::new(&dir).unwrap();

        let mut chain = Chain::init();
        chain.governance_limits.max_consecutive_proposals = 400;
        chain.finality_config.confirmation_depth = 7;

        let genesis = chain.latest_block().unwrap().clone();
        store.save_block(&genesis).unwrap();

        for _ in 0..3 {
            chain.produce_block().unwrap();
            let block = chain.latest_block().unwrap().clone();
            store.save_block(&block).unwrap();
        }

        assert_eq!(chain.finality_config.confirmation_depth, 7);

        let snapshot = chain.create_snapshot();
        store.save_snapshot(&snapshot).unwrap();

        let blocks = store.load_all_blocks().unwrap();
        let mut replayed = Chain::from_blocks(blocks).unwrap();
        assert_eq!(replayed.finality_config.confirmation_depth, 7);

        replayed.restore_from_snapshot(&snapshot);
        assert_eq!(replayed.finality_config.confirmation_depth, 7);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_persisted_norm_proposal_replays() {
        let dir = std::env::temp_dir().join(format!("sccgub_norm_persist_{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let store = ChainStore::new(&dir).unwrap();

        let mut chain = Chain::init();
        chain.governance_limits.max_consecutive_proposals = 200;
        let actor_key = chain.validator_key.clone();
        let actor_pk = *actor_key.verifying_key().as_bytes();
        let actor_seal = MfidelAtomicSeal::from_height(0);
        let actor_id = sccgub_state::apply::validator_spend_account(chain.block_version, &actor_pk);

        let genesis = chain.latest_block().unwrap().clone();
        store.save_block(&genesis).unwrap();

        let proposal_target = b"norms/persisted_norm".to_vec();
        let mut propose_tx = SymbolicTransition {
            tx_id: [0u8; 32],
            actor: sccgub_types::agent::AgentIdentity {
                agent_id: actor_id,
                public_key: actor_pk,
                mfidel_seal: actor_seal.clone(),
                registration_block: 0,
                governance_level: sccgub_types::governance::PrecedenceLevel::Meaning,
                norm_set: BTreeSet::new(),
                responsibility: sccgub_types::agent::ResponsibilityState::default(),
            },
            intent: TransitionIntent {
                kind: TransitionKind::NormProposal,
                target: proposal_target.clone(),
                declared_purpose: "persisted norm proposal".into(),
            },
            preconditions: vec![],
            postconditions: vec![],
            payload: OperationPayload::ProposeNorm {
                name: "persisted-norm".into(),
                description: "norm proposal persisted across replay".into(),
            },
            causal_chain: vec![],
            wh_binding_intent: WHBindingIntent {
                who: actor_id,
                when: CausalTimestamp::genesis(),
                r#where: proposal_target.clone(),
                why: CausalJustification {
                    invoking_rule: [1u8; 32],
                    precedence_level: sccgub_types::governance::PrecedenceLevel::Meaning,
                    causal_ancestors: vec![],
                    constraint_proof: vec![],
                },
                how: TransitionMechanism::GovernanceAction,
                which: BTreeSet::new(),
                what_declared: "persisted norm proposal".into(),
            },
            nonce: 1,
            signature: vec![],
        };
        let canonical = sccgub_execution::validate::canonical_tx_bytes(&propose_tx);
        propose_tx.tx_id = blake3_hash(&canonical);
        propose_tx.signature = sccgub_crypto::signature::sign(&actor_key, &canonical);

        chain
            .submit_transition(propose_tx)
            .expect("submit should succeed");
        let block = chain.produce_block().unwrap().clone();
        if block.body.transitions.len() != 1 {
            let reason = chain
                .latest_rejected_receipts
                .get(0)
                .map(|r| r.verdict.to_string())
                .unwrap_or_else(|| "no rejection receipt".into());
            panic!("proposal tx rejected: {}", reason);
        }
        assert!(block.receipts[0].verdict.is_accepted());
        store.save_block(&block).unwrap();

        let proposal_id = chain
            .proposals
            .proposals
            .iter()
            .find(|p| p.proposer == actor_id)
            .map(|p| p.id)
            .expect("proposal should be registered");

        let vote_target = b"norms/governance/proposals/vote".to_vec();
        let mut vote_tx = SymbolicTransition {
            tx_id: [0u8; 32],
            actor: sccgub_types::agent::AgentIdentity {
                agent_id: actor_id,
                public_key: actor_pk,
                mfidel_seal: actor_seal.clone(),
                registration_block: 0,
                governance_level: sccgub_types::governance::PrecedenceLevel::Meaning,
                norm_set: BTreeSet::new(),
                responsibility: sccgub_types::agent::ResponsibilityState::default(),
            },
            intent: TransitionIntent {
                kind: TransitionKind::GovernanceUpdate,
                target: vote_target.clone(),
                declared_purpose: "vote for norm proposal".into(),
            },
            preconditions: vec![],
            postconditions: vec![],
            payload: OperationPayload::Write {
                key: vote_target.clone(),
                value: proposal_id.to_vec(),
            },
            causal_chain: vec![block.body.transitions[0].tx_id],
            wh_binding_intent: WHBindingIntent {
                who: actor_id,
                when: CausalTimestamp::genesis(),
                r#where: vote_target.clone(),
                why: CausalJustification {
                    invoking_rule: [1u8; 32],
                    precedence_level: sccgub_types::governance::PrecedenceLevel::Meaning,
                    causal_ancestors: vec![],
                    constraint_proof: vec![],
                },
                how: TransitionMechanism::DirectStateWrite,
                which: BTreeSet::new(),
                what_declared: "vote for norm proposal".into(),
            },
            nonce: 2,
            signature: vec![],
        };
        let canonical_vote = sccgub_execution::validate::canonical_tx_bytes(&vote_tx);
        vote_tx.tx_id = blake3_hash(&canonical_vote);
        vote_tx.signature = sccgub_crypto::signature::sign(&actor_key, &canonical_vote);

        chain
            .submit_transition(vote_tx)
            .expect("vote submit should succeed");
        let vote_block = chain.produce_block().unwrap().clone();
        if vote_block.body.transitions.len() != 1 {
            let reason = chain
                .latest_rejected_receipts
                .get(0)
                .map(|r| r.verdict.to_string())
                .unwrap_or_else(|| "no rejection receipt".into());
            panic!("vote tx rejected: {}", reason);
        }
        assert!(vote_block.receipts[0].verdict.is_accepted());
        store.save_block(&vote_block).unwrap();

        for _ in 0..60 {
            chain.produce_block().unwrap();
            let block = chain.latest_block().unwrap().clone();
            store.save_block(&block).unwrap();
        }

        assert!(
            chain
                .state
                .state
                .governance_state
                .active_norms
                .contains_key(&proposal_id),
            "norm should be activated in live chain"
        );

        let snapshot = chain.create_snapshot();
        store.save_snapshot(&snapshot).unwrap();

        let blocks = store.load_all_blocks().unwrap();
        let replayed = Chain::from_blocks(blocks).unwrap();
        assert!(
            replayed
                .state
                .state
                .governance_state
                .active_norms
                .contains_key(&proposal_id),
            "norm should be activated after replay"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_persisted_param_proposal_replays() {
        let dir = std::env::temp_dir().join(format!("sccgub_param_persist_{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let store = ChainStore::new(&dir).unwrap();

        let mut chain = Chain::init();
        chain.governance_limits.max_consecutive_proposals = 300;
        let actor_key = chain.validator_key.clone();
        let actor_pk = *actor_key.verifying_key().as_bytes();
        let actor_seal = MfidelAtomicSeal::from_height(0);
        let actor_id = sccgub_state::apply::validator_spend_account(chain.block_version, &actor_pk);

        let genesis = chain.latest_block().unwrap().clone();
        store.save_block(&genesis).unwrap();

        let propose_target = b"norms/governance/params/propose".to_vec();
        let mut propose_tx = SymbolicTransition {
            tx_id: [0u8; 32],
            actor: sccgub_types::agent::AgentIdentity {
                agent_id: actor_id,
                public_key: actor_pk,
                mfidel_seal: actor_seal.clone(),
                registration_block: 0,
                governance_level: sccgub_types::governance::PrecedenceLevel::Safety,
                norm_set: BTreeSet::new(),
                responsibility: sccgub_types::agent::ResponsibilityState::default(),
            },
            intent: TransitionIntent {
                kind: TransitionKind::GovernanceUpdate,
                target: propose_target.clone(),
                declared_purpose: "propose finality update".into(),
            },
            preconditions: vec![],
            postconditions: vec![],
            payload: OperationPayload::Write {
                key: propose_target.clone(),
                value: b"finality.confirmation_depth=5".to_vec(),
            },
            causal_chain: vec![],
            wh_binding_intent: WHBindingIntent {
                who: actor_id,
                when: CausalTimestamp::genesis(),
                r#where: propose_target.clone(),
                why: CausalJustification {
                    invoking_rule: [1u8; 32],
                    precedence_level: sccgub_types::governance::PrecedenceLevel::Safety,
                    causal_ancestors: vec![],
                    constraint_proof: vec![],
                },
                how: TransitionMechanism::DirectStateWrite,
                which: BTreeSet::new(),
                what_declared: "propose finality update".into(),
            },
            nonce: 1,
            signature: vec![],
        };
        let canonical = sccgub_execution::validate::canonical_tx_bytes(&propose_tx);
        propose_tx.tx_id = blake3_hash(&canonical);
        propose_tx.signature = sccgub_crypto::signature::sign(&actor_key, &canonical);

        chain
            .submit_transition(propose_tx)
            .expect("param proposal submit should succeed");
        let proposal_block = chain.produce_block().unwrap().clone();
        if proposal_block.body.transitions.len() != 1 {
            let reason = chain
                .latest_rejected_receipts
                .get(0)
                .map(|r| r.verdict.to_string())
                .unwrap_or_else(|| "no rejection receipt".into());
            panic!("param proposal tx rejected: {}", reason);
        }
        store.save_block(&proposal_block).unwrap();

        let proposal_id = chain
            .proposals
            .proposals
            .iter()
            .find(|p| p.proposer == actor_id)
            .map(|p| p.id)
            .expect("parameter proposal should be registered");

        let vote_target = b"norms/governance/proposals/vote".to_vec();
        let mut vote_tx = SymbolicTransition {
            tx_id: [0u8; 32],
            actor: sccgub_types::agent::AgentIdentity {
                agent_id: actor_id,
                public_key: actor_pk,
                mfidel_seal: actor_seal.clone(),
                registration_block: 0,
                governance_level: sccgub_types::governance::PrecedenceLevel::Safety,
                norm_set: BTreeSet::new(),
                responsibility: sccgub_types::agent::ResponsibilityState::default(),
            },
            intent: TransitionIntent {
                kind: TransitionKind::GovernanceUpdate,
                target: vote_target.clone(),
                declared_purpose: "vote for param proposal".into(),
            },
            preconditions: vec![],
            postconditions: vec![],
            payload: OperationPayload::Write {
                key: vote_target.clone(),
                value: proposal_id.to_vec(),
            },
            causal_chain: vec![proposal_block.body.transitions[0].tx_id],
            wh_binding_intent: WHBindingIntent {
                who: actor_id,
                when: CausalTimestamp::genesis(),
                r#where: vote_target.clone(),
                why: CausalJustification {
                    invoking_rule: [1u8; 32],
                    precedence_level: sccgub_types::governance::PrecedenceLevel::Safety,
                    causal_ancestors: vec![],
                    constraint_proof: vec![],
                },
                how: TransitionMechanism::DirectStateWrite,
                which: BTreeSet::new(),
                what_declared: "vote for param proposal".into(),
            },
            nonce: 2,
            signature: vec![],
        };
        let canonical_vote = sccgub_execution::validate::canonical_tx_bytes(&vote_tx);
        vote_tx.tx_id = blake3_hash(&canonical_vote);
        vote_tx.signature = sccgub_crypto::signature::sign(&actor_key, &canonical_vote);

        chain
            .submit_transition(vote_tx)
            .expect("param vote submit should succeed");
        let vote_block = chain.produce_block().unwrap().clone();
        if vote_block.body.transitions.len() != 1 {
            let reason = chain
                .latest_rejected_receipts
                .get(0)
                .map(|r| r.verdict.to_string())
                .unwrap_or_else(|| "no rejection receipt".into());
            panic!("param vote tx rejected: {}", reason);
        }
        store.save_block(&vote_block).unwrap();

        for _ in 0..210 {
            chain.produce_block().unwrap();
            let block = chain.latest_block().unwrap().clone();
            store.save_block(&block).unwrap();
        }

        assert_eq!(chain.finality_config.confirmation_depth, 5);

        let snapshot = chain.create_snapshot();
        store.save_snapshot(&snapshot).unwrap();

        let blocks = store.load_all_blocks().unwrap();
        let replayed = Chain::from_blocks(blocks).unwrap();
        assert_eq!(replayed.finality_config.confirmation_depth, 5);

        let _ = fs::remove_dir_all(&dir);
    }
}
