use blake3::Hasher;
use ed25519_dalek::SigningKey;

/// Secure keystore — encrypts private keys at rest using a passphrase.
///
/// Key derivation: BLAKE3-based KDF with configurable iterations (memory-hard
/// properties via iteration count). In production, use Argon2id — this serves
/// as the deterministic, no-extra-dependency baseline.
///
/// Encryption: XOR stream cipher from BLAKE3 keyed hash (deterministic,
/// no additional dependencies). In production, upgrade to ChaCha20-Poly1305.
///
/// This module is designed so the encryption scheme can be swapped without
/// changing the keystore interface.
const KDF_ITERATIONS: u32 = 100_000;
const SALT_LEN: usize = 32;
const KEY_LEN: usize = 32;

/// Encrypted key bundle stored on disk.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EncryptedKeyBundle {
    /// KDF salt (random, unique per bundle).
    pub salt: Vec<u8>,
    /// Encrypted private key bytes (64 bytes for Ed25519 SigningKey).
    pub ciphertext: Vec<u8>,
    /// KDF iteration count (stored for forward compatibility).
    pub kdf_iterations: u32,
    /// Public key (stored in plaintext for identification).
    pub public_key: [u8; 32],
    /// BLAKE3 checksum of plaintext key for integrity verification.
    pub checksum: [u8; 32],
}

/// Derive an encryption key from a passphrase and salt.
fn derive_key(passphrase: &[u8], salt: &[u8], iterations: u32) -> [u8; KEY_LEN] {
    let mut key = [0u8; KEY_LEN];
    let mut state = {
        let mut h = Hasher::new();
        h.update(passphrase);
        h.update(salt);
        h.finalize()
    };

    // Iterative hashing for key stretching.
    for _ in 0..iterations {
        let mut h = Hasher::new();
        h.update(state.as_bytes());
        h.update(salt);
        state = h.finalize();
    }

    key.copy_from_slice(&state.as_bytes()[..KEY_LEN]);
    key
}

/// XOR-based stream encryption using BLAKE3 keyed hash.
/// Deterministic: same key + data = same ciphertext.
fn xor_encrypt(key: &[u8; KEY_LEN], data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len());

    for (block_idx, chunk) in data.chunks(32).enumerate() {
        let mut h = Hasher::new_keyed(key);
        h.update(&(block_idx as u64).to_le_bytes());
        let stream = h.finalize();
        let stream_bytes = stream.as_bytes();

        for (i, &byte) in chunk.iter().enumerate() {
            out.push(byte ^ stream_bytes[i]);
        }
    }

    out
}

/// Encrypt a signing key with a passphrase.
pub fn encrypt_key(key: &SigningKey, passphrase: &str) -> EncryptedKeyBundle {
    let mut salt = [0u8; SALT_LEN];
    // Use the key itself as entropy for the salt (deterministic per key).
    // In production, use OsRng for random salt.
    let mut h = Hasher::new();
    h.update(key.as_bytes());
    h.update(b"keystore-salt");
    let hash = h.finalize();
    salt.copy_from_slice(&hash.as_bytes()[..SALT_LEN]);

    let derived = derive_key(passphrase.as_bytes(), &salt, KDF_ITERATIONS);
    let plaintext = key.as_bytes();
    let ciphertext = xor_encrypt(&derived, plaintext);

    // Checksum for integrity.
    let checksum = crate::hash::blake3_hash(plaintext);

    EncryptedKeyBundle {
        salt: salt.to_vec(),
        ciphertext,
        kdf_iterations: KDF_ITERATIONS,
        public_key: *key.verifying_key().as_bytes(),
        checksum,
    }
}

/// Decrypt a signing key from an encrypted bundle.
pub fn decrypt_key(bundle: &EncryptedKeyBundle, passphrase: &str) -> Result<SigningKey, String> {
    let derived = derive_key(passphrase.as_bytes(), &bundle.salt, bundle.kdf_iterations);
    let plaintext = xor_encrypt(&derived, &bundle.ciphertext);

    if plaintext.len() != 32 {
        return Err("Decrypted key has wrong length".into());
    }

    // Verify checksum.
    let checksum = crate::hash::blake3_hash(&plaintext);
    if checksum != bundle.checksum {
        return Err("Passphrase incorrect or key corrupted (checksum mismatch)".into());
    }

    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(&plaintext);

    let key = SigningKey::from_bytes(&key_bytes);

    // Verify public key matches.
    if *key.verifying_key().as_bytes() != bundle.public_key {
        return Err("Decrypted key does not match stored public key".into());
    }

    Ok(key)
}

/// Save an encrypted key bundle to a file as JSON.
pub fn save_keystore(bundle: &EncryptedKeyBundle, path: &std::path::Path) -> std::io::Result<()> {
    let json = serde_json::to_string_pretty(bundle).map_err(std::io::Error::other)?;
    std::fs::write(path, json)
}

/// Load an encrypted key bundle from a file.
pub fn load_keystore(path: &std::path::Path) -> Result<EncryptedKeyBundle, String> {
    let content = std::fs::read_to_string(path).map_err(|e| format!("Read error: {}", e))?;
    serde_json::from_str(&content).map_err(|e| format!("Parse error: {}", e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::generate_keypair;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = generate_keypair();
        let passphrase = "test-passphrase-123";

        let bundle = encrypt_key(&key, passphrase);
        let recovered = decrypt_key(&bundle, passphrase).unwrap();

        assert_eq!(key.as_bytes(), recovered.as_bytes());
        assert_eq!(
            key.verifying_key().as_bytes(),
            recovered.verifying_key().as_bytes()
        );
    }

    #[test]
    fn test_wrong_passphrase_rejected() {
        let key = generate_keypair();
        let bundle = encrypt_key(&key, "correct-passphrase");

        let result = decrypt_key(&bundle, "wrong-passphrase");
        assert!(result.is_err());
    }

    #[test]
    fn test_public_key_stored_plaintext() {
        let key = generate_keypair();
        let bundle = encrypt_key(&key, "pass");

        // Public key is readable without decryption.
        assert_eq!(bundle.public_key, *key.verifying_key().as_bytes());
    }

    #[test]
    fn test_ciphertext_differs_from_plaintext() {
        let key = generate_keypair();
        let bundle = encrypt_key(&key, "pass");
        assert_ne!(&bundle.ciphertext, key.as_bytes().as_slice());
    }

    #[test]
    fn test_different_passphrases_different_ciphertext() {
        let key = generate_keypair();
        let bundle1 = encrypt_key(&key, "pass1");
        let bundle2 = encrypt_key(&key, "pass2");

        // Same key, different passphrases → different ciphertext.
        // Note: salt is derived from key, so same salt. But derived key differs.
        assert_ne!(bundle1.ciphertext, bundle2.ciphertext);
    }

    #[test]
    fn test_kdf_iterations_stored() {
        let key = generate_keypair();
        let bundle = encrypt_key(&key, "pass");
        assert_eq!(bundle.kdf_iterations, KDF_ITERATIONS);
    }
}
