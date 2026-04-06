/// Compute Blake3 hash of arbitrary data.
pub fn blake3_hash(data: &[u8]) -> [u8; 32] {
    *blake3::hash(data).as_bytes()
}

/// Compute hash of multiple byte slices with length-prefix domain separation.
/// Each part is prefixed with its length to prevent ambiguous concatenation.
pub fn blake3_hash_concat(parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    for part in parts {
        hasher.update(&(part.len() as u64).to_le_bytes());
        hasher.update(part);
    }
    *hasher.finalize().as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_deterministic() {
        let a = blake3_hash(b"hello");
        let b = blake3_hash(b"hello");
        assert_eq!(a, b);
    }

    #[test]
    fn test_hash_different_inputs() {
        let a = blake3_hash(b"hello");
        let b = blake3_hash(b"world");
        assert_ne!(a, b);
    }

    #[test]
    fn test_hash_concat_domain_separated() {
        // "ab" + "cd" should differ from "a" + "bcd" due to length prefixing.
        let h1 = blake3_hash_concat(&[b"ab", b"cd"]);
        let h2 = blake3_hash_concat(&[b"a", b"bcd"]);
        assert_ne!(h1, h2, "Length-prefixed concat should prevent ambiguity");
    }
}
