use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

/// Sign data with an Ed25519 signing key.
pub fn sign(key: &SigningKey, data: &[u8]) -> Vec<u8> {
    let sig = key.sign(data);
    sig.to_bytes().to_vec()
}

/// Verify an Ed25519 signature.
pub fn verify(public_key: &[u8; 32], data: &[u8], signature: &[u8]) -> bool {
    let Ok(vk) = VerifyingKey::from_bytes(public_key) else {
        return false;
    };
    let Ok(sig) = Signature::from_slice(signature) else {
        return false;
    };
    vk.verify(data, &sig).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::generate_keypair;

    #[test]
    fn test_sign_and_verify() {
        let key = generate_keypair();
        let data = b"test message";
        let sig = sign(&key, data);
        assert!(verify(key.verifying_key().as_bytes(), data, &sig));
    }

    #[test]
    fn test_invalid_signature() {
        let key = generate_keypair();
        let data = b"test message";
        let sig = sign(&key, data);
        assert!(!verify(key.verifying_key().as_bytes(), b"wrong data", &sig));
    }
}
