//! Purpose: Durable state storage interface and redb-backed implementation.
//! Governance scope: Persistence substrate for consensus-critical state entries.
//! Dependencies: redb, standard filesystem paths.
//! Invariants: fail-closed on IO errors, explicit errors for all operations.

use std::path::Path;
use std::sync::Arc;

use redb::{Database, ReadableDatabase, ReadableTable, ReadableTableMetadata, TableDefinition};

pub type StateEntry = (Vec<u8>, Vec<u8>);
pub type StateEntries = Vec<StateEntry>;

const STATE_TABLE: TableDefinition<&[u8], &[u8]> = TableDefinition::new("state");

pub trait StateStore: Send + Sync {
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, String>;
    fn put(&self, key: &[u8], value: &[u8]) -> Result<(), String>;
    fn delete(&self, key: &[u8]) -> Result<(), String>;
    fn iter_prefix(&self, prefix: &[u8]) -> Result<StateEntries, String>;
    fn iter_all(&self) -> Result<StateEntries, String>;
    fn is_empty(&self) -> Result<bool, String>;
    fn flush(&self) -> Result<(), String>;
}

#[derive(Clone)]
pub struct RedbStateStore {
    db: Arc<Database>,
}

impl RedbStateStore {
    pub fn open(dir: &Path) -> Result<Self, String> {
        std::fs::create_dir_all(dir).map_err(|e| format!("state dir create failed: {}", e))?;
        let db_path = dir.join("state.redb");
        let db = Database::create(&db_path).map_err(|e| format!("redb open failed: {}", e))?;
        Ok(Self { db: Arc::new(db) })
    }
}

impl StateStore for RedbStateStore {
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, String> {
        let rtxn = self
            .db
            .begin_read()
            .map_err(|e| format!("redb read failed: {}", e))?;
        let table = match rtxn.open_table(STATE_TABLE) {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(None),
            Err(e) => return Err(format!("redb table open failed: {}", e)),
        };
        match table.get(key) {
            Ok(Some(guard)) => Ok(Some(guard.value().to_vec())),
            Ok(None) => Ok(None),
            Err(e) => Err(format!("redb get failed: {}", e)),
        }
    }

    fn put(&self, key: &[u8], value: &[u8]) -> Result<(), String> {
        let wtxn = self
            .db
            .begin_write()
            .map_err(|e| format!("redb write failed: {}", e))?;
        {
            let mut table = wtxn
                .open_table(STATE_TABLE)
                .map_err(|e| format!("redb table open failed: {}", e))?;
            table
                .insert(key, value)
                .map_err(|e| format!("redb insert failed: {}", e))?;
        }
        wtxn.commit()
            .map_err(|e| format!("redb commit failed: {}", e))?;
        Ok(())
    }

    fn delete(&self, key: &[u8]) -> Result<(), String> {
        let wtxn = self
            .db
            .begin_write()
            .map_err(|e| format!("redb write failed: {}", e))?;
        {
            let mut table = wtxn
                .open_table(STATE_TABLE)
                .map_err(|e| format!("redb table open failed: {}", e))?;
            table
                .remove(key)
                .map_err(|e| format!("redb remove failed: {}", e))?;
        }
        wtxn.commit()
            .map_err(|e| format!("redb commit failed: {}", e))?;
        Ok(())
    }

    fn iter_prefix(&self, prefix: &[u8]) -> Result<StateEntries, String> {
        let rtxn = self
            .db
            .begin_read()
            .map_err(|e| format!("redb read failed: {}", e))?;
        let table = match rtxn.open_table(STATE_TABLE) {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(Vec::new()),
            Err(e) => return Err(format!("redb table open failed: {}", e)),
        };
        let mut entries = Vec::new();
        let iter = table
            .range(prefix..)
            .map_err(|e| format!("redb range failed: {}", e))?;
        for item in iter {
            let (k, v) = item.map_err(|e| format!("redb iter failed: {}", e))?;
            let key_bytes = k.value();
            if !key_bytes.starts_with(prefix) {
                break;
            }
            entries.push((key_bytes.to_vec(), v.value().to_vec()));
        }
        Ok(entries)
    }

    fn iter_all(&self) -> Result<StateEntries, String> {
        let rtxn = self
            .db
            .begin_read()
            .map_err(|e| format!("redb read failed: {}", e))?;
        let table = match rtxn.open_table(STATE_TABLE) {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(Vec::new()),
            Err(e) => return Err(format!("redb table open failed: {}", e)),
        };
        let mut entries = Vec::new();
        let iter = table
            .iter()
            .map_err(|e| format!("redb iter failed: {}", e))?;
        for item in iter {
            let (k, v) = item.map_err(|e| format!("redb iter failed: {}", e))?;
            entries.push((k.value().to_vec(), v.value().to_vec()));
        }
        Ok(entries)
    }

    fn is_empty(&self) -> Result<bool, String> {
        let rtxn = self
            .db
            .begin_read()
            .map_err(|e| format!("redb read failed: {}", e))?;
        let table = match rtxn.open_table(STATE_TABLE) {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(true),
            Err(e) => return Err(format!("redb table open failed: {}", e)),
        };
        table
            .len()
            .map(|n| n == 0)
            .map_err(|e| format!("redb len failed: {}", e))
    }

    fn flush(&self) -> Result<(), String> {
        // redb write transactions are durable on commit; no separate flush needed.
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_redb_state_store_roundtrip() {
        let dir = std::env::temp_dir().join(format!("sccgub_state_store_{}", std::process::id()));
        let store = RedbStateStore::open(&dir).expect("store open");
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
    fn test_redb_state_store_prefix_iter() {
        let dir = std::env::temp_dir().join(format!("sccgub_state_prefix_{}", std::process::id()));
        let store = RedbStateStore::open(&dir).expect("store open");
        store.put(b"abc/1", b"v1").expect("put");
        store.put(b"abc/2", b"v2").expect("put");
        store.put(b"zzz/1", b"v3").expect("put");
        let entries = store.iter_prefix(b"abc/").expect("scan");
        assert_eq!(entries.len(), 2);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
