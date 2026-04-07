use crate::hash::blake3_hash;

// Deterministic binary serialization for consensus-critical hashing.
// Replaces JSON with bincode: deterministic, compact, ~10x faster.

/// Compute a canonical hash of any serializable value using bincode.
pub fn canonical_hash<T: serde::Serialize>(value: &T) -> [u8; 32] {
    let bytes = bincode::serialize(value).expect("bincode serialization cannot fail for Serialize types");
    blake3_hash(&bytes)
}

/// Serialize a value to canonical binary bytes.
pub fn canonical_bytes<T: serde::Serialize>(value: &T) -> Vec<u8> {
    bincode::serialize(value).expect("bincode serialization cannot fail for Serialize types")
}

/// Deserialize from canonical binary bytes.
pub fn from_canonical_bytes<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T, String> {
    bincode::deserialize(bytes).map_err(|e| format!("bincode deserialization failed: {}", e))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug)]
    struct TestStruct {
        a: u64,
        b: [u8; 32],
        c: Vec<u8>,
    }

    #[test]
    fn test_canonical_hash_deterministic() {
        let val = TestStruct {
            a: 42,
            b: [1u8; 32],
            c: vec![1, 2, 3],
        };
        let h1 = canonical_hash(&val);
        let h2 = canonical_hash(&val);
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_canonical_bytes_roundtrip() {
        let val = TestStruct {
            a: 99,
            b: [5u8; 32],
            c: vec![10, 20, 30],
        };
        let bytes = canonical_bytes(&val);
        let restored: TestStruct = from_canonical_bytes(&bytes).unwrap();
        assert_eq!(val, restored);
    }

    #[test]
    fn test_canonical_is_compact() {
        let val = TestStruct {
            a: 42,
            b: [0u8; 32],
            c: vec![0; 100],
        };
        let bincode_bytes = canonical_bytes(&val);
        let json_bytes = serde_json::to_vec(&val).unwrap();
        // Bincode should be significantly smaller than JSON.
        assert!(
            bincode_bytes.len() < json_bytes.len(),
            "bincode {} vs json {} bytes",
            bincode_bytes.len(),
            json_bytes.len()
        );
    }

    #[test]
    fn test_different_values_different_hashes() {
        let a = TestStruct {
            a: 1,
            b: [0u8; 32],
            c: vec![],
        };
        let b = TestStruct {
            a: 2,
            b: [0u8; 32],
            c: vec![],
        };
        assert_ne!(canonical_hash(&a), canonical_hash(&b));
    }
}
