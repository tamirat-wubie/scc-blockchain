use std::collections::BTreeMap;

use sccgub_crypto::hash::blake3_hash_concat;
use sccgub_crypto::merkle::compute_merkle_root;
use sccgub_types::{Hash, MerkleRoot, SymbolAddress, ZERO_HASH};

/// Simplified Merkle Patricia Trie backed by a BTreeMap.
/// MVP implementation: HashMap storage with on-demand Merkle root computation.
/// A full Patricia trie is a later optimization.
#[derive(Debug, Clone)]
pub struct StateTrie {
    store: BTreeMap<SymbolAddress, Vec<u8>>,
}

impl StateTrie {
    pub fn new() -> Self {
        Self {
            store: BTreeMap::new(),
        }
    }

    pub fn get(&self, key: &SymbolAddress) -> Option<&Vec<u8>> {
        self.store.get(key)
    }

    pub fn insert(&mut self, key: SymbolAddress, value: Vec<u8>) {
        self.store.insert(key, value);
    }

    pub fn remove(&mut self, key: &SymbolAddress) -> Option<Vec<u8>> {
        self.store.remove(key)
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
    /// Hashes each (key, value) pair, then builds a Merkle tree.
    pub fn root(&self) -> MerkleRoot {
        if self.store.is_empty() {
            return ZERO_HASH;
        }
        // Domain-separated hashing: hash(len(key) || key || len(value) || value)
        // Prevents key/value boundary confusion attacks.
        let leaves: Vec<Hash> = self
            .store
            .iter()
            .map(|(k, v)| {
                blake3_hash_concat(&[k.as_slice(), v.as_slice()])
            })
            .collect();
        compute_merkle_root(&leaves)
    }

    /// Iterate over all entries.
    pub fn iter(&self) -> impl Iterator<Item = (&SymbolAddress, &Vec<u8>)> {
        self.store.iter()
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
        let trie = StateTrie::new();
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
}
