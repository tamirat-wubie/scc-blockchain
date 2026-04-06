use crate::hash::blake3_hash_concat;

const ZERO_HASH: [u8; 32] = [0u8; 32];

/// Compute a Merkle root from a list of leaf hashes.
/// Uses a simple binary Merkle tree construction.
pub fn compute_merkle_root(leaves: &[[u8; 32]]) -> [u8; 32] {
    if leaves.is_empty() {
        return ZERO_HASH;
    }
    if leaves.len() == 1 {
        return leaves[0];
    }

    let mut current_level: Vec<[u8; 32]> = leaves.to_vec();

    while current_level.len() > 1 {
        let mut next_level = Vec::new();
        let mut i = 0;
        while i < current_level.len() {
            if i + 1 < current_level.len() {
                next_level.push(blake3_hash_concat(&[&current_level[i], &current_level[i + 1]]));
            } else {
                next_level.push(blake3_hash_concat(&[&current_level[i], &current_level[i]]));
            }
            i += 2;
        }
        current_level = next_level;
    }

    current_level[0]
}

/// Compute Merkle root from serializable items by hashing each one first.
pub fn merkle_root_of_bytes(items: &[&[u8]]) -> [u8; 32] {
    let leaves: Vec<[u8; 32]> = items
        .iter()
        .map(|item| crate::hash::blake3_hash(item))
        .collect();
    compute_merkle_root(&leaves)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::blake3_hash;

    #[test]
    fn test_empty_merkle_root() {
        assert_eq!(compute_merkle_root(&[]), ZERO_HASH);
    }

    #[test]
    fn test_single_leaf() {
        let leaf = blake3_hash(b"leaf");
        assert_eq!(compute_merkle_root(&[leaf]), leaf);
    }

    #[test]
    fn test_two_leaves() {
        let a = blake3_hash(b"a");
        let b = blake3_hash(b"b");
        let root = compute_merkle_root(&[a, b]);
        assert_ne!(root, ZERO_HASH);
        assert_ne!(root, a);
        assert_ne!(root, b);
    }

    #[test]
    fn test_merkle_deterministic() {
        let leaves: Vec<[u8; 32]> = (0..5).map(|i| blake3_hash(&[i])).collect();
        let r1 = compute_merkle_root(&leaves);
        let r2 = compute_merkle_root(&leaves);
        assert_eq!(r1, r2);
    }
}
