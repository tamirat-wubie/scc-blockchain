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
}
