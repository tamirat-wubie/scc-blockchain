use argon2::Argon2;
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use ed25519_dalek::SigningKey;
use rand::RngCore;
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

/// Finance-grade keystore — encrypts private keys at rest.
///
/// Key derivation: Argon2id (memory-hard, resistant to GPU/ASIC attacks).
/// Encryption: ChaCha20-Poly1305 AEAD (authenticated encryption).
///
/// Security properties:
/// - Passphrase -> Argon2id -> 32-byte encryption key.
/// - Random 32-byte salt (unique per bundle, stored alongside ciphertext).
/// - Random 12-byte nonce (unique per encryption, stored alongside ciphertext).
/// - AEAD authentication tag prevents tampered ciphertext from decrypting.
/// - BLAKE3 checksum of plaintext for defense-in-depth integrity check.
/// - Public key stored in cleartext for identification without decryption.
const SALT_LEN: usize = 32;
const NONCE_LEN: usize = 12;

/// Encrypted key bundle stored on disk.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EncryptedKeyBundle {
    /// Argon2id salt (random, unique per bundle).
    pub salt: Vec<u8>,
    /// ChaCha20-Poly1305 nonce (random, unique per encryption).
    pub nonce: Vec<u8>,
    /// AEAD-encrypted private key bytes (32 bytes + 16-byte auth tag).
    pub ciphertext: Vec<u8>,
    /// Public key (stored in plaintext for identification).
    pub public_key: [u8; 32],
    /// BLAKE3 checksum of plaintext key for integrity verification.
    pub checksum: [u8; 32],
    /// KDF algorithm identifier for forward compatibility.
    pub kdf: String,
    /// Encryption algorithm identifier.
    pub cipher: String,
}

/// Derive a 32-byte encryption key from passphrase + salt using Argon2id.
fn derive_key(passphrase: &[u8], salt: &[u8]) -> Result<[u8; 32], String> {
    let mut key = [0u8; 32];
    Argon2::default()
        .hash_password_into(passphrase, salt, &mut key)
        .map_err(|e| format!("Argon2id KDF failed: {}", e))?;
    Ok(key)
}

/// Encrypt a signing key with a passphrase using Argon2id + ChaCha20-Poly1305.
pub fn encrypt_key(key: &SigningKey, passphrase: &str) -> Result<EncryptedKeyBundle, String> {
    // Generate random salt and nonce.
    let mut salt = vec![0u8; SALT_LEN];
    let mut nonce_bytes = vec![0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut salt);
    rand::thread_rng().fill_bytes(&mut nonce_bytes);

    // Derive encryption key (zeroized after use).
    let mut derived = derive_key(passphrase.as_bytes(), &salt)?;

    // Encrypt with ChaCha20-Poly1305.
    let cipher =
        ChaCha20Poly1305::new_from_slice(&derived).map_err(|e| format!("Cipher init: {}", e))?;
    derived.zeroize(); // Wipe derived key from memory.
    let nonce = Nonce::from_slice(&nonce_bytes);
    let plaintext = key.as_bytes();
    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_slice())
        .map_err(|e| format!("Encryption failed: {}", e))?;

    let checksum = crate::hash::blake3_hash(plaintext);

    Ok(EncryptedKeyBundle {
        salt,
        nonce: nonce_bytes,
        ciphertext,
        public_key: *key.verifying_key().as_bytes(),
        checksum,
        kdf: "argon2id".into(),
        cipher: "chacha20-poly1305".into(),
    })
}

/// Decrypt a signing key from an encrypted bundle.
pub fn decrypt_key(bundle: &EncryptedKeyBundle, passphrase: &str) -> Result<SigningKey, String> {
    // Derive the same encryption key (zeroized after use).
    let mut derived = derive_key(passphrase.as_bytes(), &bundle.salt)?;

    // Decrypt with ChaCha20-Poly1305.
    let cipher =
        ChaCha20Poly1305::new_from_slice(&derived).map_err(|e| format!("Cipher init: {}", e))?;
    derived.zeroize(); // Wipe derived key from memory.

    if bundle.nonce.len() != NONCE_LEN {
        return Err("Invalid nonce length".into());
    }
    let nonce = Nonce::from_slice(&bundle.nonce);

    let mut plaintext = cipher
        .decrypt(nonce, bundle.ciphertext.as_slice())
        .map_err(|_| "Decryption failed: wrong passphrase or corrupted data".to_string())?;

    if plaintext.len() != 32 {
        plaintext.zeroize();
        return Err("Decrypted key has wrong length".into());
    }

    // Verify BLAKE3 checksum (constant-time to prevent timing side-channels).
    let checksum = crate::hash::blake3_hash(&plaintext);
    if checksum.ct_eq(&bundle.checksum).unwrap_u8() != 1 {
        plaintext.zeroize();
        return Err("Integrity check failed: checksum mismatch".into());
    }

    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(&plaintext);
    plaintext.zeroize(); // Wipe decrypted plaintext from memory.
    let key = SigningKey::from_bytes(&key_bytes);
    key_bytes.zeroize(); // Wipe key bytes copy.

    // Verify public key matches (constant-time comparison).
    if key
        .verifying_key()
        .as_bytes()
        .ct_eq(&bundle.public_key)
        .unwrap_u8()
        != 1
    {
        return Err("Decrypted key does not match stored public key".into());
    }

    Ok(key)
}

/// Save an encrypted key bundle to a file as JSON.
/// Uses atomic write-then-rename to prevent key loss on crash.
pub fn save_keystore(bundle: &EncryptedKeyBundle, path: &std::path::Path) -> std::io::Result<()> {
    let json = serde_json::to_string_pretty(bundle).map_err(std::io::Error::other)?;
    // Write to a temporary file first, then rename atomically.
    let tmp_path = path.with_extension("tmp");
    std::fs::write(&tmp_path, &json)?;
    std::fs::rename(&tmp_path, path)?;
    Ok(())
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

        let bundle = encrypt_key(&key, passphrase).unwrap();
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
        let bundle = encrypt_key(&key, "correct-passphrase").unwrap();

        let result = decrypt_key(&bundle, "wrong-passphrase");
        assert!(result.is_err());
    }

    #[test]
    fn test_public_key_stored_plaintext() {
        let key = generate_keypair();
        let bundle = encrypt_key(&key, "pass").unwrap();
        assert_eq!(bundle.public_key, *key.verifying_key().as_bytes());
    }

    #[test]
    fn test_ciphertext_differs_from_plaintext() {
        let key = generate_keypair();
        let bundle = encrypt_key(&key, "pass").unwrap();
        // Ciphertext is 32 bytes + 16 byte auth tag = 48 bytes.
        assert_eq!(bundle.ciphertext.len(), 48);
        assert_ne!(&bundle.ciphertext[..32], key.as_bytes().as_slice());
    }

    #[test]
    fn test_tampered_ciphertext_rejected() {
        let key = generate_keypair();
        let mut bundle = encrypt_key(&key, "pass").unwrap();
        bundle.ciphertext[0] ^= 0xFF; // Tamper one byte.
        let result = decrypt_key(&bundle, "pass");
        assert!(result.is_err(), "AEAD must reject tampered ciphertext");
    }

    #[test]
    fn test_kdf_and_cipher_recorded() {
        let key = generate_keypair();
        let bundle = encrypt_key(&key, "pass").unwrap();
        assert_eq!(bundle.kdf, "argon2id");
        assert_eq!(bundle.cipher, "chacha20-poly1305");
    }

    #[test]
    fn test_random_salt_unique_per_encryption() {
        let key = generate_keypair();
        let b1 = encrypt_key(&key, "pass").unwrap();
        let b2 = encrypt_key(&key, "pass").unwrap();
        assert_ne!(b1.salt, b2.salt, "Each encryption must use a unique salt");
        assert_ne!(
            b1.nonce, b2.nonce,
            "Each encryption must use a unique nonce"
        );
    }

    // ── N-49 coverage: keystore file I/O ─────────────────────────────

    #[test]
    fn test_save_and_load_keystore_roundtrip() {
        let key = generate_keypair();
        let bundle = encrypt_key(&key, "test-pass").unwrap();

        let dir = std::env::temp_dir().join(format!("sccgub_keytest_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("test.keystore");

        save_keystore(&bundle, &path).unwrap();
        let loaded = load_keystore(&path).unwrap();

        assert_eq!(loaded.public_key, bundle.public_key);
        assert_eq!(loaded.ciphertext, bundle.ciphertext);
        assert_eq!(loaded.salt, bundle.salt);
        assert_eq!(loaded.nonce, bundle.nonce);

        // Decrypt the loaded bundle to verify full roundtrip.
        let recovered = decrypt_key(&loaded, "test-pass").unwrap();
        assert_eq!(key.as_bytes(), recovered.as_bytes());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_load_keystore_missing_file_fails() {
        let result = load_keystore(std::path::Path::new("/nonexistent/path/keystore.json"));
        assert!(result.is_err());
    }

    #[test]
    fn test_load_keystore_corrupt_json_fails() {
        let dir = std::env::temp_dir().join(format!("sccgub_corrupt_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("corrupt.keystore");
        std::fs::write(&path, "not valid json {{{").unwrap();

        let result = load_keystore(&path);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Parse error"));

        let _ = std::fs::remove_dir_all(&dir);
    }
}
