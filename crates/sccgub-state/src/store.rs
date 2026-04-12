//! Purpose: Durable state storage interface and sled-backed implementation.
//! Governance scope: Persistence substrate for consensus-critical state entries.
//! Dependencies: sled, standard filesystem paths.
//! Invariants: fail-closed on IO errors, explicit errors for all operations.

use std::path::Path;
use std::sync::Arc;

use sled::Db;

pub trait StateStore: Send + Sync {
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, String>;
    fn put(&self, key: &[u8], value: &[u8]) -> Result<(), String>;
    fn delete(&self, key: &[u8]) -> Result<(), String>;
    fn iter_prefix(&self, prefix: &[u8]) -> Result<Vec<(Vec<u8>, Vec<u8>)>, String>;
    fn iter_all(&self) -> Result<Vec<(Vec<u8>, Vec<u8>)>, String>;
    fn flush(&self) -> Result<(), String>;
}

#[derive(Clone)]
pub struct SledStateStore {
    db: Arc<Db>,
}

impl SledStateStore {
    pub fn open(path: &Path) -> Result<Self, String> {
        let db = sled::open(path).map_err(|e| format!("sled open failed: {}", e))?;
        Ok(Self { db: Arc::new(db) })
    }
}

impl StateStore for SledStateStore {
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, String> {
        self.db
            .get(key)
            .map(|opt| opt.map(|v| v.to_vec()))
            .map_err(|e| format!("sled get failed: {}", e))
    }

    fn put(&self, key: &[u8], value: &[u8]) -> Result<(), String> {
        self.db
            .insert(key, value)
            .map_err(|e| format!("sled insert failed: {}", e))?;
        Ok(())
    }

    fn delete(&self, key: &[u8]) -> Result<(), String> {
        self.db
            .remove(key)
            .map_err(|e| format!("sled remove failed: {}", e))?;
        Ok(())
    }

    fn iter_prefix(&self, prefix: &[u8]) -> Result<Vec<(Vec<u8>, Vec<u8>)>, String> {
        let mut entries = Vec::new();
        for item in self.db.scan_prefix(prefix) {
            let (key, value) = item.map_err(|e| format!("sled scan failed: {}", e))?;
            entries.push((key.to_vec(), value.to_vec()));
        }
        Ok(entries)
    }

    fn iter_all(&self) -> Result<Vec<(Vec<u8>, Vec<u8>)>, String> {
        let mut entries = Vec::new();
        for item in self.db.iter() {
            let (key, value) = item.map_err(|e| format!("sled iter failed: {}", e))?;
            entries.push((key.to_vec(), value.to_vec()));
        }
        Ok(entries)
    }

    fn flush(&self) -> Result<(), String> {
        self.db
            .flush()
            .map(|_| ())
            .map_err(|e| format!("sled flush failed: {}", e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sled_state_store_roundtrip() {
        let dir = std::env::temp_dir().join(format!("sccgub_state_store_{}", std::process::id()));
        let store = SledStateStore::open(&dir).expect("store open");
        let key = b"alpha";
        let value = b"beta";
        store.put(key, value).expect("put");
        let loaded = store.get(key).expect("get").expect("value");
        assert_eq!(loaded, value);
        store.delete(key).expect("delete");
        let missing = store.get(key).expect("get");
        assert!(missing.is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_sled_state_store_prefix_iter() {
        let dir = std::env::temp_dir().join(format!("sccgub_state_prefix_{}", std::process::id()));
        let store = SledStateStore::open(&dir).expect("store open");
        store.put(b"abc/1", b"v1").expect("put");
        store.put(b"abc/2", b"v2").expect("put");
        store.put(b"zzz/1", b"v3").expect("put");
        let entries = store.iter_prefix(b"abc/").expect("scan");
        assert_eq!(entries.len(), 2);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
