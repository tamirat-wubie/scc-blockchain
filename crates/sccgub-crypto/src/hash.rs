/// Compute Blake3 hash of arbitrary data.
pub fn blake3_hash(data: &[u8]) -> [u8; 32] {
    *blake3::hash(data).as_bytes()
}

/// Compute hash of multiple byte slices concatenated.
pub fn blake3_hash_concat(parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    for part in parts {
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
    fn test_hash_concat() {
        let h = blake3_hash_concat(&[b"hello", b"world"]);
        assert_ne!(h, [0u8; 32]);
    }
}
