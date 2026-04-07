use crate::hash::blake3_hash_concat;

const ZERO_HASH: [u8; 32] = [0u8; 32];

/// Domain tags for Merkle tree security.
/// Prevents second-preimage attacks by distinguishing leaf from internal nodes.
const LEAF_DOMAIN: &[u8] = &[0x00];
const INTERNAL_DOMAIN: &[u8] = &[0x01];

/// Hash a leaf with domain separation.
fn hash_leaf(data: &[u8; 32]) -> [u8; 32] {
    blake3_hash_concat(&[LEAF_DOMAIN, data])
}

/// Hash two children into an internal node with domain separation.
fn hash_internal(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    blake3_hash_concat(&[INTERNAL_DOMAIN, left, right])
}

/// Compute a Merkle root from a list of leaf hashes.
/// Uses domain-separated hashing to prevent second-preimage attacks.
/// Odd leaves are promoted (hashed alone), not duplicated.
pub fn compute_merkle_root(leaves: &[[u8; 32]]) -> [u8; 32] {
    if leaves.is_empty() {
        return ZERO_HASH;
    }
    if leaves.len() == 1 {
        return hash_leaf(&leaves[0]);
    }

    // Hash all leaves with leaf domain tag.
    let mut current_level: Vec<[u8; 32]> = leaves.iter().map(hash_leaf).collect();

    while current_level.len() > 1 {
        let mut next_level = Vec::new();
        let mut i = 0;
        while i < current_level.len() {
            if i + 1 < current_level.len() {
                next_level.push(hash_internal(&current_level[i], &current_level[i + 1]));
            } else {
                // Odd leaf: promote without duplication (prevents second-preimage).
                next_level.push(current_level[i]);
            }
            i += 2;
        }
        current_level = next_level;
    }

    current_level[0]
}

/// Compute Merkle root from serializable items.
/// Each item is hashed with length-prefixed domain separation to prevent
/// ambiguous concatenation attacks.
pub fn merkle_root_of_bytes(items: &[&[u8]]) -> [u8; 32] {
    let leaves: Vec<[u8; 32]> = items
        .iter()
        .map(|item| {
            // Length-prefix each item to prevent boundary confusion.
            let len_bytes = (item.len() as u64).to_le_bytes();
            blake3_hash_concat(&[&len_bytes, item])
        })
        .collect();
    compute_merkle_root(&leaves)
}

/// Merkle inclusion proof: a list of sibling hashes and their positions.
#[derive(Debug, Clone)]
pub struct MerkleProof {
    /// Sibling hashes from leaf to root. Each entry is (hash, is_right_sibling).
    pub siblings: Vec<([u8; 32], bool)>,
}

/// Generate a Merkle inclusion proof for a leaf at the given index.
#[allow(clippy::manual_is_multiple_of)]
pub fn generate_proof(leaves: &[[u8; 32]], index: usize) -> Option<MerkleProof> {
    if index >= leaves.len() || leaves.is_empty() {
        return None;
    }

    let mut current_level: Vec<[u8; 32]> = leaves.iter().map(hash_leaf).collect();
    let mut proof_index = index;
    let mut siblings = Vec::new();

    while current_level.len() > 1 {
        let sibling_index = if proof_index % 2 == 0 {
            proof_index + 1
        } else {
            proof_index - 1
        };

        if sibling_index < current_level.len() {
            siblings.push((current_level[sibling_index], proof_index % 2 == 0));
        }
        // else: odd leaf, no sibling — promoted

        // Build next level.
        let mut next_level = Vec::new();
        let mut i = 0;
        while i < current_level.len() {
            if i + 1 < current_level.len() {
                next_level.push(hash_internal(&current_level[i], &current_level[i + 1]));
            } else {
                next_level.push(current_level[i]); // Odd promote.
            }
            i += 2;
        }

        proof_index /= 2;
        current_level = next_level;
    }

    Some(MerkleProof { siblings })
}

/// Verify a Merkle inclusion proof.
pub fn verify_proof(root: &[u8; 32], leaf: &[u8; 32], proof: &MerkleProof) -> bool {
    let mut current = hash_leaf(leaf);

    for (sibling, is_right) in &proof.siblings {
        if *is_right {
            current = hash_internal(&current, sibling);
        } else {
            current = hash_internal(sibling, &current);
        }
    }

    current == *root
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
        let root = compute_merkle_root(&[leaf]);
        assert_ne!(root, ZERO_HASH);
        // Single leaf should be domain-hashed, not returned raw.
        assert_ne!(root, leaf);
    }

    #[test]
    fn test_two_leaves() {
        let a = blake3_hash(b"a");
        let b = blake3_hash(b"b");
        let root = compute_merkle_root(&[a, b]);
        assert_ne!(root, ZERO_HASH);
    }

    #[test]
    fn test_odd_leaf_not_duplicated() {
        // [A, B, C] should NOT equal [A, B, C, C]
        let a = blake3_hash(b"a");
        let b = blake3_hash(b"b");
        let c = blake3_hash(b"c");
        let root_3 = compute_merkle_root(&[a, b, c]);
        let root_4 = compute_merkle_root(&[a, b, c, c]);
        assert_ne!(root_3, root_4, "Odd leaf should not be duplicated");
    }

    #[test]
    fn test_merkle_deterministic() {
        let leaves: Vec<[u8; 32]> = (0..5).map(|i| blake3_hash(&[i])).collect();
        let r1 = compute_merkle_root(&leaves);
        let r2 = compute_merkle_root(&leaves);
        assert_eq!(r1, r2);
    }

    #[test]
    fn test_length_prefix_prevents_ambiguity() {
        let r1 = merkle_root_of_bytes(&[b"ab", b"cd"]);
        let r2 = merkle_root_of_bytes(&[b"a", b"bcd"]);
        assert_ne!(r1, r2, "Length-prefixed hashing should prevent ambiguity");
    }

    #[test]
    fn test_merkle_proof_verification() {
        let leaves: Vec<[u8; 32]> = (0..8).map(|i| blake3_hash(&[i])).collect();
        let root = compute_merkle_root(&leaves);

        // Generate and verify proof for each leaf.
        for i in 0..leaves.len() {
            let proof = generate_proof(&leaves, i).unwrap();
            assert!(
                verify_proof(&root, &leaves[i], &proof),
                "Proof failed for leaf {}",
                i
            );
        }
    }

    #[test]
    fn test_merkle_proof_odd_leaves() {
        let leaves: Vec<[u8; 32]> = (0..5).map(|i| blake3_hash(&[i])).collect();
        let root = compute_merkle_root(&leaves);

        for i in 0..leaves.len() {
            let proof = generate_proof(&leaves, i).unwrap();
            assert!(verify_proof(&root, &leaves[i], &proof));
        }
    }

    #[test]
    fn test_merkle_proof_invalid_leaf() {
        let leaves: Vec<[u8; 32]> = (0..4).map(|i| blake3_hash(&[i])).collect();
        let root = compute_merkle_root(&leaves);
        let proof = generate_proof(&leaves, 0).unwrap();

        // Wrong leaf should fail.
        let fake_leaf = blake3_hash(b"fake");
        assert!(!verify_proof(&root, &fake_leaf, &proof));
    }

    #[test]
    fn test_merkle_proof_out_of_bounds() {
        let leaves: Vec<[u8; 32]> = (0..4).map(|i| blake3_hash(&[i])).collect();
        assert!(generate_proof(&leaves, 10).is_none());
        assert!(generate_proof(&[], 0).is_none());
    }
}
