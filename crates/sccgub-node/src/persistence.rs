use std::fs;
use std::path::{Path, PathBuf};

use sccgub_types::block::Block;

/// Chain persistence — save and load chain state from disk.
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
            "version": "0.1.0",
            "spec": "SCCGUB v2.1"
        });
        fs::write(&tmp_path, serde_json::to_string_pretty(&json).unwrap())?;
        fs::rename(&tmp_path, &path)
    }

    pub fn base_dir(&self) -> &Path {
        &self.base_dir
    }

    /// Save validator key to disk (raw Ed25519 secret key bytes).
    /// WARNING: This stores the key unencrypted. For production, use encrypted storage.
    pub fn save_validator_key(&self, key: &ed25519_dalek::SigningKey) -> std::io::Result<()> {
        let path = self.base_dir.join("validator.key");
        let tmp_path = self.base_dir.join("validator.key.tmp");
        fs::write(&tmp_path, hex::encode(key.to_bytes()))?;
        fs::rename(&tmp_path, &path)
    }

    /// Load validator key from disk.
    pub fn load_validator_key(&self) -> std::io::Result<ed25519_dalek::SigningKey> {
        let path = self.base_dir.join("validator.key");
        let hex_str = fs::read_to_string(path)?;
        let bytes = hex::decode(hex_str.trim())
            .map_err(|e| std::io::Error::other(format!("Invalid key hex: {}", e)))?;
        if bytes.len() != 32 {
            return Err(std::io::Error::other("Validator key must be 32 bytes"));
        }
        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(&bytes);
        Ok(ed25519_dalek::SigningKey::from_bytes(&key_bytes))
    }

    /// Check if a validator key exists on disk.
    pub fn has_validator_key(&self) -> bool {
        self.base_dir.join("validator.key").exists()
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
        let latest = entries.last().unwrap();
        let json = fs::read_to_string(latest.path())?;
        let snapshot: StateSnapshot = serde_json::from_str(&json).map_err(std::io::Error::other)?;
        Ok(Some(snapshot))
    }
}

/// State snapshot for fast chain loading.
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use sccgub_types::block::{Block, BlockBody, BlockHeader};
    use sccgub_types::causal::CausalGraphDelta;
    use sccgub_types::governance::{FinalityMode, GovernanceSnapshot};
    use sccgub_types::mfidel::MfidelAtomicSeal;
    use sccgub_types::proof::{CausalProof, PhiTraversalLog};
    use sccgub_types::tension::TensionValue;
    use sccgub_types::timestamp::CausalTimestamp;
    use sccgub_types::ZERO_HASH;

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
}
