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
    pub fn new(base_dir: &Path) -> std::io::Result<Self> {
        fs::create_dir_all(base_dir.join("blocks"))?;
        fs::create_dir_all(base_dir.join("state"))?;
        Ok(Self {
            base_dir: base_dir.to_path_buf(),
        })
    }

    /// Save a block to disk as JSON.
    pub fn save_block(&self, block: &Block) -> std::io::Result<()> {
        let filename = format!("block_{:010}.json", block.header.height);
        let path = self.base_dir.join("blocks").join(filename);
        let json = serde_json::to_string_pretty(block)
            .map_err(std::io::Error::other)?;
        fs::write(path, json)
    }

    /// Load a block from disk by height.
    pub fn load_block(&self, height: u64) -> std::io::Result<Block> {
        let filename = format!("block_{:010}.json", height);
        let path = self.base_dir.join("blocks").join(filename);
        let json = fs::read_to_string(path)?;
        serde_json::from_str(&json)
            .map_err(std::io::Error::other)
    }

    /// Load all blocks from disk in order.
    pub fn load_all_blocks(&self) -> std::io::Result<Vec<Block>> {
        let blocks_dir = self.base_dir.join("blocks");
        let mut entries: Vec<_> = fs::read_dir(&blocks_dir)?
            .filter_map(|e| e.ok())
            .filter(|e| {
                e.path()
                    .extension()
                    .is_some_and(|ext| ext == "json")
            })
            .collect();

        entries.sort_by_key(|e| e.file_name());

        let mut blocks = Vec::new();
        for entry in entries {
            let json = fs::read_to_string(entry.path())?;
            let block: Block = serde_json::from_str(&json)
                .map_err(std::io::Error::other)?;
            blocks.push(block);
        }
        Ok(blocks)
    }

    /// Get the latest block height on disk.
    pub fn latest_height(&self) -> std::io::Result<Option<u64>> {
        let blocks = self.load_all_blocks()?;
        Ok(blocks.last().map(|b| b.header.height))
    }

    /// Save chain metadata (chain_id, etc.).
    pub fn save_metadata(&self, chain_id: &[u8; 32]) -> std::io::Result<()> {
        let path = self.base_dir.join("chain_meta.json");
        let json = serde_json::json!({
            "chain_id": hex::encode(chain_id),
            "version": "0.1.0",
            "spec": "SCCGUB v2.1"
        });
        fs::write(path, serde_json::to_string_pretty(&json).unwrap())
    }

    /// Get the data directory path.
    pub fn base_dir(&self) -> &Path {
        &self.base_dir
    }
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
    use std::collections::HashMap;

    fn test_block(height: u64) -> Block {
        Block {
            header: BlockHeader {
                chain_id: ZERO_HASH,
                block_id: [height as u8; 32],
                parent_id: ZERO_HASH,
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
                validator_id: ZERO_HASH,
                version: 1,
            },
            body: BlockBody {
                transitions: vec![],
                transition_count: 0,
                total_tension_delta: TensionValue::ZERO,
                constraint_satisfaction_map: HashMap::new(),
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
                constraint_map: HashMap::new(),
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
        let dir = std::env::temp_dir().join("sccgub_test_persistence");
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
        let dir = std::env::temp_dir().join("sccgub_test_persistence_all");
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
