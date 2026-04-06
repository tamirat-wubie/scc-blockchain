use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;

/// Generate a new Ed25519 keypair.
pub fn generate_keypair() -> SigningKey {
    SigningKey::generate(&mut OsRng)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_keypair() {
        let key = generate_keypair();
        let pk = key.verifying_key();
        assert_ne!(pk.as_bytes(), &[0u8; 32]);
    }
}
