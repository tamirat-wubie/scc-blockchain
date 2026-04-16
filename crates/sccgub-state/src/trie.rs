use std::collections::BTreeMap;
use std::sync::Arc;

use sccgub_crypto::hash::blake3_hash_concat;
use sccgub_crypto::merkle::compute_merkle_root;
use sccgub_types::{Hash, MerkleRoot, SymbolAddress, ZERO_HASH};

use crate::store::StateStore;

/// Simplified Merkle Patricia Trie backed by a BTreeMap.
/// Features lazy root caching — root is recomputed only when the trie is dirty.
#[derive(Clone)]
pub struct StateTrie {
    store: BTreeMap<SymbolAddress, Vec<u8>>,
    /// Cached Merkle root. `None` means dirty (needs recomputation).
    cached_root: Option<MerkleRoot>,
    durable: Option<Arc<dyn StateStore>>,
    durable_error: Option<String>,
}

impl std::fmt::Debug for StateTrie {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StateTrie")
            .field("entries", &self.store.len())
            .field("cached_root", &self.cached_root)
            .field("durable", &self.durable.is_some())
            .field("durable_error", &self.durable_error)
            .finish()
    }
}

impl StateTrie {
    pub fn new() -> Self {
        Self {
            store: BTreeMap::new(),
            cached_root: Some(ZERO_HASH),
            durable: None,
            durable_error: None,
        }
    }

    pub fn with_store(store: Arc<dyn StateStore>) -> Result<Self, String> {
        let entries = store.iter_all()?;
        let mut map = BTreeMap::new();
        for (key, value) in entries {
            map.insert(key, value);
        }
        Ok(Self {
            store: map,
            cached_root: None,
            durable: Some(store),
            durable_error: None,
        })
    }

    pub fn durable_error(&self) -> Option<&str> {
        self.durable_error.as_deref()
    }

    pub fn take_durable_error(&mut self) -> Option<String> {
        self.durable_error.take()
    }

    pub fn flush_durable(&mut self) -> Result<(), String> {
        if let Some(store) = &self.durable {
            if let Err(err) = store.flush() {
                self.durable_error = Some(err.clone());
                return Err(err);
            }
        }
        Ok(())
    }

    pub fn get(&self, key: &SymbolAddress) -> Option<&Vec<u8>> {
        self.store.get(key)
    }

    pub fn insert(&mut self, key: SymbolAddress, value: Vec<u8>) {
        self.store.insert(key.clone(), value.clone());
        self.cached_root = None; // Invalidate cache.
        if let Some(store) = &self.durable {
            if let Err(err) = store.put(&key, &value) {
                self.durable_error = Some(err.clone());
                tracing::error!("State trie durable insert failed: {}", err);
            }
        }
    }

    pub fn remove(&mut self, key: &SymbolAddress) -> Option<Vec<u8>> {
        let result = self.store.remove(key);
        if result.is_some() {
            self.cached_root = None; // Invalidate cache.
            if let Some(store) = &self.durable {
                if let Err(err) = store.delete(key) {
                    self.durable_error = Some(err.clone());
                    tracing::error!("State trie durable delete failed: {}", err);
                }
            }
        }
        result
    }

    pub fn contains(&self, key: &SymbolAddress) -> bool {
        self.store.contains_key(key)
    }

    pub fn len(&self) -> usize {
        self.store.len()
    }

    pub fn is_empty(&self) -> bool {
        self.store.is_empty()
    }

    /// Compute the Merkle root of the entire trie state.
    /// Uses lazy caching — only recomputes when the trie has been modified.
    pub fn root(&mut self) -> MerkleRoot {
        if let Some(cached) = self.cached_root {
            return cached;
        }
        let computed = self.compute_root();
        self.cached_root = Some(computed);
        computed
    }

    /// Force recompute (for immutable contexts where &self is needed).
    pub fn root_readonly(&self) -> MerkleRoot {
        if let Some(cached) = self.cached_root {
            return cached;
        }
        self.compute_root()
    }

    fn compute_root(&self) -> MerkleRoot {
        if self.store.is_empty() {
            return ZERO_HASH;
        }
        // Domain-separated hashing: hash(len(key) || key || len(value) || value)
        let leaves: Vec<Hash> = self
            .store
            .iter()
            .map(|(k, v)| blake3_hash_concat(&[k.as_slice(), v.as_slice()]))
            .collect();
        compute_merkle_root(&leaves)
    }

    /// Iterate over all entries.
    pub fn iter(&self) -> impl Iterator<Item = (&SymbolAddress, &Vec<u8>)> {
        self.store.iter()
    }

    /// Iterate entries with a given prefix (efficient range scan on BTreeMap).
    pub fn prefix_iter<'a>(
        &'a self,
        prefix: &'a [u8],
    ) -> impl Iterator<Item = (&'a SymbolAddress, &'a Vec<u8>)> {
        let start = prefix.to_vec();
        self.store
            .range(start..)
            .take_while(move |(k, _)| k.starts_with(prefix))
    }

    /// Count entries matching a prefix (efficient).
    pub fn count_prefix(&self, prefix: &[u8]) -> usize {
        self.prefix_iter(prefix).count()
    }
}

impl Default for StateTrie {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_trie() {
        let mut trie = StateTrie::new();
        assert_eq!(trie.root(), ZERO_HASH);
        assert!(trie.is_empty());
    }

    #[test]
    fn test_insert_and_get() {
        let mut trie = StateTrie::new();
        trie.insert(b"key1".to_vec(), b"value1".to_vec());
        assert_eq!(trie.get(&b"key1".to_vec()), Some(&b"value1".to_vec()));
        assert_ne!(trie.root(), ZERO_HASH);
    }

    #[test]
    fn test_deterministic_root() {
        let mut t1 = StateTrie::new();
        t1.insert(b"a".to_vec(), b"1".to_vec());
        t1.insert(b"b".to_vec(), b"2".to_vec());

        let mut t2 = StateTrie::new();
        t2.insert(b"a".to_vec(), b"1".to_vec());
        t2.insert(b"b".to_vec(), b"2".to_vec());

        assert_eq!(t1.root(), t2.root());
    }

    #[test]
    fn test_different_state_different_root() {
        let mut t1 = StateTrie::new();
        t1.insert(b"a".to_vec(), b"1".to_vec());

        let mut t2 = StateTrie::new();
        t2.insert(b"a".to_vec(), b"2".to_vec());

        assert_ne!(t1.root(), t2.root());
    }

    #[test]
    fn test_cache_invalidation() {
        let mut trie = StateTrie::new();
        trie.insert(b"key".to_vec(), b"val1".to_vec());
        let root1 = trie.root();

        trie.insert(b"key".to_vec(), b"val2".to_vec());
        let root2 = trie.root();

        assert_ne!(root1, root2, "Root should change after mutation");
    }

    #[test]
    fn test_cache_hit() {
        let mut trie = StateTrie::new();
        trie.insert(b"key".to_vec(), b"val".to_vec());
        let root1 = trie.root();
        let root2 = trie.root(); // Should be a cache hit.
        assert_eq!(root1, root2);
    }

    #[test]
    fn test_remove_existing_key() {
        let mut trie = StateTrie::new();
        trie.insert(b"key".to_vec(), b"val".to_vec());
        assert!(!trie.is_empty());

        let removed = trie.remove(&b"key".to_vec());
        assert_eq!(removed, Some(b"val".to_vec()));
        assert!(trie.is_empty());
        assert_eq!(trie.root(), ZERO_HASH);
    }

    #[test]
    fn test_remove_nonexistent_key() {
        let mut trie = StateTrie::new();
        trie.insert(b"exists".to_vec(), b"val".to_vec());
        let root_before = trie.root();

        let removed = trie.remove(&b"nope".to_vec());
        assert_eq!(removed, None);
        // Root should not have been invalidated.
        assert_eq!(trie.root(), root_before);
    }

    #[test]
    fn test_remove_invalidates_cache() {
        let mut trie = StateTrie::new();
        trie.insert(b"a".to_vec(), b"1".to_vec());
        trie.insert(b"b".to_vec(), b"2".to_vec());
        let root_with_both = trie.root();

        trie.remove(&b"b".to_vec());
        let root_after_remove = trie.root();
        assert_ne!(
            root_with_both, root_after_remove,
            "Removing a key must change the root"
        );
    }

    #[test]
    fn test_prefix_iter_matching() {
        let mut trie = StateTrie::new();
        trie.insert(b"data/a".to_vec(), b"1".to_vec());
        trie.insert(b"data/b".to_vec(), b"2".to_vec());
        trie.insert(b"meta/x".to_vec(), b"3".to_vec());
        trie.insert(b"data/c".to_vec(), b"4".to_vec());

        let data_entries: Vec<_> = trie.prefix_iter(b"data/").collect();
        assert_eq!(data_entries.len(), 3);
        // BTreeMap preserves order.
        assert_eq!(data_entries[0].0, &b"data/a".to_vec());
        assert_eq!(data_entries[1].0, &b"data/b".to_vec());
        assert_eq!(data_entries[2].0, &b"data/c".to_vec());
    }

    #[test]
    fn test_prefix_iter_no_match() {
        let mut trie = StateTrie::new();
        trie.insert(b"data/a".to_vec(), b"1".to_vec());

        let results: Vec<_> = trie.prefix_iter(b"nope/").collect();
        assert!(results.is_empty());
    }

    #[test]
    fn test_count_prefix() {
        let mut trie = StateTrie::new();
        trie.insert(b"balance/aaa".to_vec(), b"100".to_vec());
        trie.insert(b"balance/bbb".to_vec(), b"200".to_vec());
        trie.insert(b"balance/ccc".to_vec(), b"300".to_vec());
        trie.insert(b"nonce/aaa".to_vec(), b"1".to_vec());

        assert_eq!(trie.count_prefix(b"balance/"), 3);
        assert_eq!(trie.count_prefix(b"nonce/"), 1);
        assert_eq!(trie.count_prefix(b"nothing/"), 0);
    }

    #[test]
    fn test_contains_and_len() {
        let mut trie = StateTrie::new();
        assert_eq!(trie.len(), 0);
        assert!(!trie.contains(&b"key".to_vec()));

        trie.insert(b"key".to_vec(), b"val".to_vec());
        assert_eq!(trie.len(), 1);
        assert!(trie.contains(&b"key".to_vec()));

        trie.remove(&b"key".to_vec());
        assert_eq!(trie.len(), 0);
        assert!(!trie.contains(&b"key".to_vec()));
    }

    #[test]
    fn test_root_readonly_consistent() {
        let mut trie = StateTrie::new();
        trie.insert(b"x".to_vec(), b"y".to_vec());
        let mutable_root = trie.root();
        let readonly_root = trie.root_readonly();
        assert_eq!(mutable_root, readonly_root);
    }

    // --- Durable store tests using in-memory mock ---

    use std::collections::BTreeMap as StdBTreeMap;
    use std::sync::Mutex;

    /// In-memory StateStore mock for testing durable trie operations.
    struct MockStore {
        data: Mutex<StdBTreeMap<Vec<u8>, Vec<u8>>>,
        flush_error: Mutex<Option<String>>,
    }

    impl MockStore {
        fn new() -> Self {
            Self {
                data: Mutex::new(StdBTreeMap::new()),
                flush_error: Mutex::new(None),
            }
        }

        fn with_flush_error(err: &str) -> Self {
            Self {
                data: Mutex::new(StdBTreeMap::new()),
                flush_error: Mutex::new(Some(err.to_string())),
            }
        }

        fn snapshot(&self) -> StdBTreeMap<Vec<u8>, Vec<u8>> {
            self.data.lock().unwrap().clone()
        }
    }

    impl crate::store::StateStore for MockStore {
        fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, String> {
            Ok(self.data.lock().unwrap().get(key).cloned())
        }
        fn put(&self, key: &[u8], value: &[u8]) -> Result<(), String> {
            self.data
                .lock()
                .unwrap()
                .insert(key.to_vec(), value.to_vec());
            Ok(())
        }
        fn delete(&self, key: &[u8]) -> Result<(), String> {
            self.data.lock().unwrap().remove(key);
            Ok(())
        }
        fn iter_prefix(&self, prefix: &[u8]) -> Result<crate::store::StateEntries, String> {
            let map = self.data.lock().unwrap();
            Ok(map
                .range(prefix.to_vec()..)
                .take_while(|(k, _)| k.starts_with(prefix))
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect())
        }
        fn iter_all(&self) -> Result<crate::store::StateEntries, String> {
            Ok(self
                .data
                .lock()
                .unwrap()
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect())
        }
        fn is_empty(&self) -> Result<bool, String> {
            Ok(self.data.lock().unwrap().is_empty())
        }
        fn flush(&self) -> Result<(), String> {
            let guard = self.flush_error.lock().unwrap();
            if let Some(err) = &*guard {
                return Err(err.clone());
            }
            Ok(())
        }
    }

    #[test]
    fn test_with_store_loads_existing_data() {
        let mock = Arc::new(MockStore::new());
        mock.put(b"key1", b"val1").unwrap();
        mock.put(b"key2", b"val2").unwrap();

        let trie = StateTrie::with_store(mock).unwrap();
        assert_eq!(trie.get(&b"key1".to_vec()), Some(&b"val1".to_vec()));
        assert_eq!(trie.get(&b"key2".to_vec()), Some(&b"val2".to_vec()));
        assert_eq!(trie.len(), 2);
    }

    #[test]
    fn test_insert_propagates_to_durable_store() {
        let mock = Arc::new(MockStore::new());
        let mut trie = StateTrie::with_store(mock.clone()).unwrap();
        trie.insert(b"abc".to_vec(), b"123".to_vec());

        // Check the mock store received the write.
        let snap = mock.snapshot();
        assert_eq!(snap.get(b"abc".as_slice()), Some(&b"123".to_vec()));
    }

    #[test]
    fn test_remove_propagates_to_durable_store() {
        let mock = Arc::new(MockStore::new());
        mock.put(b"key", b"val").unwrap();
        let mut trie = StateTrie::with_store(mock.clone()).unwrap();
        assert_eq!(trie.len(), 1);

        trie.remove(&b"key".to_vec());
        assert!(trie.is_empty());
        // Durable store should also have the key removed.
        assert!(mock.snapshot().is_empty());
    }

    #[test]
    fn test_flush_durable_success() {
        let mock = Arc::new(MockStore::new());
        let mut trie = StateTrie::with_store(mock).unwrap();
        assert!(trie.flush_durable().is_ok());
        assert!(trie.durable_error().is_none());
    }

    #[test]
    fn test_flush_durable_error_captured() {
        let mock = Arc::new(MockStore::with_flush_error("disk full"));
        let mut trie = StateTrie::with_store(mock).unwrap();
        let err = trie.flush_durable().unwrap_err();
        assert!(err.contains("disk full"));
        assert_eq!(trie.durable_error(), Some("disk full"));
    }

    #[test]
    fn test_take_durable_error_clears() {
        let mock = Arc::new(MockStore::with_flush_error("io error"));
        let mut trie = StateTrie::with_store(mock).unwrap();
        let _ = trie.flush_durable(); // Triggers error.
        assert!(trie.durable_error().is_some());

        let taken = trie.take_durable_error();
        assert_eq!(taken, Some("io error".to_string()));
        assert!(trie.durable_error().is_none()); // Cleared.
    }

    #[test]
    fn test_flush_durable_without_store_is_noop() {
        let mut trie = StateTrie::new(); // No durable store.
        assert!(trie.flush_durable().is_ok());
    }
}
