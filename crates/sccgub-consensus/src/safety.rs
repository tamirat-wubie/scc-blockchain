use std::collections::{HashMap, HashSet};

use sccgub_types::Hash;

// Formal BFT safety proof framework.
// Safety theorem: If f < n/3 validators are Byzantine, no conflicting blocks
// can both achieve supermajority. Proof: two supermajorities require > 2n/3
// votes each, totaling > 4n/3 votes — but only n validators exist, so at
// least n/3 + 1 validators must appear in BOTH quorums. Those are equivocators.

/// A formal safety certificate proving a block was finalized.
/// Contains cryptographic proof: each precommit signature is verified against
/// the validator set before the certificate is considered valid.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SafetyCertificate {
    /// Chain identifier for vote domain separation.
    #[serde(default)]
    pub chain_id: Hash,
    /// Validator set epoch used when signing votes.
    #[serde(default)]
    pub epoch: u64,
    pub height: u64,
    pub block_hash: Hash,
    /// Round in which consensus was achieved.
    pub round: u32,
    /// The set of precommit signatures (at least quorum).
    pub precommit_signatures: Vec<(Hash, Vec<u8>)>, // (validator_id, signature)
    /// Quorum size used.
    pub quorum: u32,
    /// Total validator count.
    pub validator_count: u32,
}

impl SafetyCertificate {
    /// Verify that the certificate is structurally valid (quorum size, no duplicates).
    pub fn verify_structure(&self) -> Result<(), String> {
        let expected_quorum = (2u64 * self.validator_count as u64) / 3 + 1;
        if self.quorum as u64 != expected_quorum {
            return Err(format!(
                "Quorum mismatch: claimed {} but expected {} for n={}",
                self.quorum, expected_quorum, self.validator_count
            ));
        }
        if (self.precommit_signatures.len().min(u32::MAX as usize) as u32) < self.quorum {
            return Err(format!(
                "Insufficient signatures: {} < quorum {}",
                self.precommit_signatures.len(),
                self.quorum
            ));
        }
        // Check for duplicate signers.
        let unique_signers: HashSet<Hash> = self
            .precommit_signatures
            .iter()
            .map(|(id, _)| *id)
            .collect();
        if unique_signers.len() != self.precommit_signatures.len() {
            return Err("Duplicate signer detected in safety certificate".into());
        }
        Ok(())
    }

    /// Full cryptographic verification: structure + every signature verified
    /// against the validator set and the committed block data.
    ///
    /// This is the method that MUST be called when accepting a certificate from
    /// an external source (peer, checkpoint import, bridge relay).
    pub fn verify_cryptographic(
        &self,
        validator_set: &HashMap<Hash, [u8; 32]>,
    ) -> Result<(), String> {
        self.verify_structure()?;

        // Every signer must be in the authorized validator set.
        for (validator_id, signature) in &self.precommit_signatures {
            let public_key = validator_set.get(validator_id).ok_or_else(|| {
                format!("Signer {} not in validator set", hex::encode(validator_id))
            })?;

            if signature.len() < 64 {
                return Err(format!(
                    "Signature too short ({} bytes) from validator {}",
                    signature.len(),
                    hex::encode(validator_id)
                ));
            }

            // Reconstruct the signed message using consensus domain separation.
            let vote_data = crate::protocol::vote_sign_data(
                &self.chain_id,
                self.epoch,
                &self.block_hash,
                self.height,
                self.round,
                crate::protocol::VoteType::Precommit,
            );

            if !sccgub_crypto::signature::verify(public_key, &vote_data, signature) {
                return Err(format!(
                    "Invalid signature from validator {}",
                    hex::encode(validator_id)
                ));
            }
        }

        Ok(())
    }

    /// Build a certificate from a finalized ConsensusRound.
    pub fn from_round(
        chain_id: Hash,
        epoch: u64,
        block_hash: Hash,
        height: u64,
        round: u32,
        precommits: &HashMap<Hash, crate::protocol::Vote>,
        validator_count: u32,
    ) -> Self {
        let quorum = ((2u64 * validator_count as u64) / 3 + 1).min(u32::MAX as u64) as u32;
        let precommit_signatures: Vec<(Hash, Vec<u8>)> = precommits
            .values()
            .filter(|v| v.block_hash == block_hash)
            .map(|v| (v.validator_id, v.signature.clone()))
            .collect();

        Self {
            chain_id,
            epoch,
            height,
            block_hash,
            round,
            precommit_signatures,
            quorum,
            validator_count,
        }
    }
}

/// Persistent equivocation evidence store.
/// Accumulates evidence across rounds, heights, and peers.
/// Evidence is irrefutable: two signed messages from the same validator
/// for different blocks at the same height.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct EquivocationStore {
    /// All collected evidence, keyed by validator ID.
    evidence: HashMap<Hash, Vec<EquivocationEvidence>>,
    /// Validators with confirmed equivocation (slashable).
    pub confirmed_equivocators: HashSet<Hash>,
}

/// Cryptographic proof of equivocation: two conflicting signed votes.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EquivocationEvidence {
    pub validator_id: Hash,
    pub height: u64,
    pub round_a: u32,
    pub round_b: u32,
    pub block_hash_a: Hash,
    pub block_hash_b: Hash,
    /// Signature over (block_hash_a, height, round_a, vote_type).
    pub signature_a: Vec<u8>,
    /// Signature over (block_hash_b, height, round_b, vote_type).
    pub signature_b: Vec<u8>,
}

impl EquivocationEvidence {
    /// Verify that this evidence is cryptographically valid.
    /// Both signatures must verify against the validator's public key,
    /// and the block hashes must differ.
    pub fn verify(&self, public_key: &[u8; 32]) -> Result<(), String> {
        if self.block_hash_a == self.block_hash_b {
            return Err("Not equivocation: same block hash".into());
        }

        // Verify signature A.
        let data_a = sccgub_crypto::canonical::canonical_bytes(&(
            &self.block_hash_a,
            self.height,
            self.round_a,
            2u8,
        ));
        if !sccgub_crypto::signature::verify(public_key, &data_a, &self.signature_a) {
            return Err("Signature A verification failed".into());
        }

        // Verify signature B.
        let data_b = sccgub_crypto::canonical::canonical_bytes(&(
            &self.block_hash_b,
            self.height,
            self.round_b,
            2u8,
        ));
        if !sccgub_crypto::signature::verify(public_key, &data_b, &self.signature_b) {
            return Err("Signature B verification failed".into());
        }

        Ok(())
    }
}

impl EquivocationStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Submit evidence of equivocation. Verifies signatures before accepting.
    /// Returns true if this is new evidence (not already known).
    pub fn submit_evidence(
        &mut self,
        evidence: EquivocationEvidence,
        public_key: &[u8; 32],
    ) -> Result<bool, String> {
        evidence.verify(public_key)?;

        let validator = evidence.validator_id;
        let entries = self.evidence.entry(validator).or_default();

        // Check if we already have evidence at this height from this validator.
        let duplicate = entries.iter().any(|e| {
            e.height == evidence.height
                && e.block_hash_a == evidence.block_hash_a
                && e.block_hash_b == evidence.block_hash_b
        });

        if duplicate {
            return Ok(false);
        }

        entries.push(evidence);
        self.confirmed_equivocators.insert(validator);
        Ok(true)
    }

    /// Check if a validator has confirmed equivocation evidence.
    pub fn is_equivocator(&self, validator_id: &Hash) -> bool {
        self.confirmed_equivocators.contains(validator_id)
    }

    /// Get all evidence against a specific validator.
    pub fn evidence_for(&self, validator_id: &Hash) -> &[EquivocationEvidence] {
        self.evidence
            .get(validator_id)
            .map_or(&[], |v| v.as_slice())
    }

    /// Total number of confirmed equivocators.
    pub fn equivocator_count(&self) -> usize {
        self.confirmed_equivocators.len()
    }

    /// Extract equivocation evidence from two conflicting safety certificates.
    pub fn extract_from_fork(
        cert_a: &SafetyCertificate,
        cert_b: &SafetyCertificate,
    ) -> Vec<EquivocationEvidence> {
        if cert_a.height != cert_b.height || cert_a.block_hash == cert_b.block_hash {
            return Vec::new();
        }

        let sigs_a: HashMap<Hash, &Vec<u8>> = cert_a
            .precommit_signatures
            .iter()
            .map(|(id, sig)| (*id, sig))
            .collect();

        let mut evidence = Vec::new();
        for (id, sig_b) in &cert_b.precommit_signatures {
            if let Some(sig_a) = sigs_a.get(id) {
                evidence.push(EquivocationEvidence {
                    validator_id: *id,
                    height: cert_a.height,
                    round_a: cert_a.round,
                    round_b: cert_b.round,
                    block_hash_a: cert_a.block_hash,
                    block_hash_b: cert_b.block_hash,
                    signature_a: (*sig_a).clone(),
                    signature_b: sig_b.clone(),
                });
            }
        }

        evidence
    }
}

/// Prove that two conflicting blocks cannot both be finalized.
pub fn prove_no_fork(cert_a: &SafetyCertificate, cert_b: &SafetyCertificate) -> ForkProofResult {
    if cert_a.height != cert_b.height {
        return ForkProofResult::DifferentHeights;
    }
    if cert_a.validator_count != cert_b.validator_count {
        return ForkProofResult::ImpossibleFork {
            reason: "Certificates reference different validator set sizes".into(),
        };
    }
    if cert_a.block_hash == cert_b.block_hash {
        return ForkProofResult::SameBlock;
    }

    let signers_a: HashSet<Hash> = cert_a
        .precommit_signatures
        .iter()
        .map(|(id, _)| *id)
        .collect();
    let signers_b: HashSet<Hash> = cert_b
        .precommit_signatures
        .iter()
        .map(|(id, _)| *id)
        .collect();

    let equivocators: Vec<Hash> = signers_a.intersection(&signers_b).copied().collect();

    if equivocators.is_empty() {
        ForkProofResult::ImpossibleFork {
            reason: format!(
                "No equivocators found but {} + {} > {} total validators",
                signers_a.len(),
                signers_b.len(),
                cert_a.validator_count
            ),
        }
    } else {
        ForkProofResult::EquivocatorsFound {
            equivocators,
            height: cert_a.height,
            block_a: cert_a.block_hash,
            block_b: cert_b.block_hash,
        }
    }
}

/// Maximum Byzantine validators tolerated for a given validator set size.
pub fn max_byzantine(validator_count: u32) -> u32 {
    if validator_count < 4 {
        return 0;
    }
    (validator_count - 1) / 3
}

/// Check if a validator set size provides the desired Byzantine tolerance.
pub fn check_byzantine_tolerance(
    validator_count: u32,
    desired_tolerance: u32,
) -> Result<(), String> {
    let max_f = max_byzantine(validator_count);
    if desired_tolerance > max_f {
        Err(format!(
            "Cannot tolerate f={} with n={} validators (max f={}). Need n >= {}",
            desired_tolerance,
            validator_count,
            max_f,
            desired_tolerance.saturating_mul(3).saturating_add(1)
        ))
    } else {
        Ok(())
    }
}

/// Result of a fork proof analysis.
#[derive(Debug, Clone)]
pub enum ForkProofResult {
    DifferentHeights,
    SameBlock,
    EquivocatorsFound {
        equivocators: Vec<Hash>,
        height: u64,
        block_a: Hash,
        block_b: Hash,
    },
    ImpossibleFork {
        reason: String,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol;
    use sccgub_crypto::keys::generate_keypair;

    const TEST_CHAIN_ID: Hash = [0xCC; 32];
    const TEST_EPOCH: u64 = 1;

    fn make_cert(height: u64, block: Hash, signers: &[u8], n: u32) -> SafetyCertificate {
        SafetyCertificate {
            chain_id: TEST_CHAIN_ID,
            epoch: TEST_EPOCH,
            height,
            block_hash: block,
            round: 0,
            precommit_signatures: signers.iter().map(|&s| ([s; 32], vec![0u8; 64])).collect(),
            quorum: (2 * n) / 3 + 1,
            validator_count: n,
        }
    }

    #[test]
    fn test_safety_certificate_valid() {
        let cert = make_cert(10, [1u8; 32], &[1, 2, 3], 4);
        assert!(cert.verify_structure().is_ok());
    }

    #[test]
    fn test_insufficient_signatures() {
        let cert = make_cert(10, [1u8; 32], &[1, 2], 4);
        assert!(cert.verify_structure().is_err());
    }

    #[test]
    fn test_duplicate_signer_detected() {
        let mut cert = make_cert(10, [1u8; 32], &[1, 2, 3], 4);
        cert.precommit_signatures[2].0 = [1; 32];
        assert!(cert.verify_structure().is_err());
    }

    #[test]
    fn test_cryptographic_verification() {
        let block = [42u8; 32];
        let height = 5u64;
        let round = 0u32;

        // Create validator keypairs.
        let mut validator_set = HashMap::new();
        let mut signers = Vec::new();
        for i in 1..=4u8 {
            let key = generate_keypair();
            let pk = *key.verifying_key().as_bytes();
            let id = [i; 32];
            validator_set.insert(id, pk);
            signers.push((id, key));
        }

        // Create properly signed precommits.
        let mut precommit_signatures = Vec::new();
        for (id, key) in &signers[..3] {
            let data = protocol::vote_sign_data(
                &TEST_CHAIN_ID,
                TEST_EPOCH,
                &block,
                height,
                round,
                crate::protocol::VoteType::Precommit,
            );
            let sig = sccgub_crypto::signature::sign(key, &data);
            precommit_signatures.push((*id, sig));
        }

        let cert = SafetyCertificate {
            chain_id: TEST_CHAIN_ID,
            epoch: TEST_EPOCH,
            height,
            block_hash: block,
            round,
            precommit_signatures,
            quorum: 3,
            validator_count: 4,
        };

        assert!(cert.verify_cryptographic(&validator_set).is_ok());
    }

    #[test]
    fn test_cryptographic_verification_bad_sig() {
        let block = [42u8; 32];
        let height = 5u64;
        let round = 0u32;

        let mut validator_set = HashMap::new();
        for i in 1..=4u8 {
            let key = generate_keypair();
            let pk = *key.verifying_key().as_bytes();
            validator_set.insert([i; 32], pk);
        }

        // Use garbage signatures.
        let cert = SafetyCertificate {
            chain_id: TEST_CHAIN_ID,
            epoch: TEST_EPOCH,
            height,
            block_hash: block,
            round,
            precommit_signatures: vec![
                ([1; 32], vec![0u8; 64]), // Invalid signature.
                ([2; 32], vec![0u8; 64]),
                ([3; 32], vec![0u8; 64]),
            ],
            quorum: 3,
            validator_count: 4,
        };

        assert!(cert.verify_cryptographic(&validator_set).is_err());
    }

    #[test]
    fn test_equivocation_evidence_verified() {
        let key = generate_keypair();
        let pk = *key.verifying_key().as_bytes();
        let id = [1u8; 32];
        let height = 10u64;

        let block_a = [0xAAu8; 32];
        let block_b = [0xBBu8; 32];

        let data_a = sccgub_crypto::canonical::canonical_bytes(&(&block_a, height, 0u32, 2u8));
        let data_b = sccgub_crypto::canonical::canonical_bytes(&(&block_b, height, 0u32, 2u8));

        let evidence = EquivocationEvidence {
            validator_id: id,
            height,
            round_a: 0,
            round_b: 0,
            block_hash_a: block_a,
            block_hash_b: block_b,
            signature_a: sccgub_crypto::signature::sign(&key, &data_a),
            signature_b: sccgub_crypto::signature::sign(&key, &data_b),
        };

        assert!(evidence.verify(&pk).is_ok());
    }

    #[test]
    fn test_equivocation_store_submit_and_query() {
        let key = generate_keypair();
        let pk = *key.verifying_key().as_bytes();
        let id = [1u8; 32];

        let block_a = [0xAAu8; 32];
        let block_b = [0xBBu8; 32];
        let height = 10u64;

        let data_a = sccgub_crypto::canonical::canonical_bytes(&(&block_a, height, 0u32, 2u8));
        let data_b = sccgub_crypto::canonical::canonical_bytes(&(&block_b, height, 0u32, 2u8));

        let evidence = EquivocationEvidence {
            validator_id: id,
            height,
            round_a: 0,
            round_b: 0,
            block_hash_a: block_a,
            block_hash_b: block_b,
            signature_a: sccgub_crypto::signature::sign(&key, &data_a),
            signature_b: sccgub_crypto::signature::sign(&key, &data_b),
        };

        let mut store = EquivocationStore::new();
        assert!(!store.is_equivocator(&id));

        let is_new = store.submit_evidence(evidence, &pk).unwrap();
        assert!(is_new);
        assert!(store.is_equivocator(&id));
        assert_eq!(store.equivocator_count(), 1);
        assert_eq!(store.evidence_for(&id).len(), 1);
    }

    #[test]
    fn test_equivocation_duplicate_rejected() {
        let key = generate_keypair();
        let pk = *key.verifying_key().as_bytes();
        let id = [1u8; 32];
        let block_a = [0xAAu8; 32];
        let block_b = [0xBBu8; 32];
        let height = 10u64;

        let data_a = sccgub_crypto::canonical::canonical_bytes(&(&block_a, height, 0u32, 2u8));
        let data_b = sccgub_crypto::canonical::canonical_bytes(&(&block_b, height, 0u32, 2u8));

        let evidence = EquivocationEvidence {
            validator_id: id,
            height,
            round_a: 0,
            round_b: 0,
            block_hash_a: block_a,
            block_hash_b: block_b,
            signature_a: sccgub_crypto::signature::sign(&key, &data_a),
            signature_b: sccgub_crypto::signature::sign(&key, &data_b),
        };

        let mut store = EquivocationStore::new();
        assert!(store.submit_evidence(evidence.clone(), &pk).unwrap());
        assert!(!store.submit_evidence(evidence, &pk).unwrap()); // Duplicate.
    }

    #[test]
    fn test_prove_no_fork_finds_equivocators() {
        let cert_a = make_cert(10, [1u8; 32], &[1, 2, 3], 4);
        let cert_b = make_cert(10, [2u8; 32], &[3, 4, 5], 4);

        match prove_no_fork(&cert_a, &cert_b) {
            ForkProofResult::EquivocatorsFound { equivocators, .. } => {
                assert_eq!(equivocators.len(), 1);
                assert_eq!(equivocators[0], [3u8; 32]);
            }
            other => panic!("Expected EquivocatorsFound, got {:?}", other),
        }
    }

    #[test]
    fn test_same_block_not_fork() {
        let cert_a = make_cert(10, [1u8; 32], &[1, 2, 3], 4);
        let cert_b = make_cert(10, [1u8; 32], &[2, 3, 4], 4);
        assert!(matches!(
            prove_no_fork(&cert_a, &cert_b),
            ForkProofResult::SameBlock
        ));
    }

    #[test]
    fn test_max_byzantine() {
        assert_eq!(max_byzantine(3), 0);
        assert_eq!(max_byzantine(4), 1);
        assert_eq!(max_byzantine(7), 2);
        assert_eq!(max_byzantine(21), 6);
        assert_eq!(max_byzantine(100), 33);
    }

    #[test]
    fn test_byzantine_tolerance_check() {
        assert!(check_byzantine_tolerance(21, 6).is_ok());
        assert!(check_byzantine_tolerance(21, 7).is_err());
        assert!(check_byzantine_tolerance(4, 1).is_ok());
        assert!(check_byzantine_tolerance(3, 1).is_err());
    }

    #[test]
    fn test_extract_from_fork() {
        let cert_a = make_cert(10, [1u8; 32], &[1, 2, 3], 4);
        let cert_b = make_cert(10, [2u8; 32], &[3, 4, 5], 4);

        let evidence = EquivocationStore::extract_from_fork(&cert_a, &cert_b);
        assert_eq!(evidence.len(), 1);
        assert_eq!(evidence[0].validator_id, [3u8; 32]);
    }

    #[test]
    fn test_from_round_builds_certificate() {
        use crate::protocol::{vote_sign_data, Vote, VoteType};
        use sccgub_crypto::keys::generate_keypair;

        let chain_id = [0xCC; 32];
        let epoch = 1u64;
        let block_hash = [0xAA; 32];
        let height = 5u64;
        let round = 0u32;

        let keys: Vec<_> = (0..4).map(|_| generate_keypair()).collect();
        let mut precommits = std::collections::HashMap::new();
        for (i, key) in keys.iter().enumerate() {
            let id = [i as u8 + 1; 32];
            let pk = *key.verifying_key().as_bytes();
            let data = vote_sign_data(
                &chain_id,
                epoch,
                &block_hash,
                height,
                round,
                VoteType::Precommit,
            );
            let sig = sccgub_crypto::signature::sign(key, &data);
            precommits.insert(
                id,
                Vote {
                    validator_id: id,
                    block_hash,
                    height,
                    round,
                    vote_type: VoteType::Precommit,
                    signature: sig,
                },
            );
            // Store pk for later verification.
            let _ = pk;
        }

        let cert = SafetyCertificate::from_round(
            chain_id,
            epoch,
            block_hash,
            height,
            round,
            &precommits,
            4,
        );

        assert_eq!(cert.height, height);
        assert_eq!(cert.block_hash, block_hash);
        assert_eq!(cert.validator_count, 4);
        assert_eq!(cert.quorum, 3); // floor(2*4/3) + 1 = 3
        assert_eq!(cert.precommit_signatures.len(), 4);
    }

    // ── N-48 coverage: safety certificate edge cases ─────────────────

    #[test]
    fn test_safety_cert_quorum_mismatch_fails() {
        let mut cert = make_cert(10, [1u8; 32], &[1, 2, 3], 4);
        // Manually set quorum to wrong value (should be 3 for n=4).
        cert.quorum = 2;
        let err = cert.verify_structure().unwrap_err();
        assert!(err.contains("Quorum mismatch"), "got: {}", err);
    }

    #[test]
    fn test_safety_cert_short_signer_sig_fails() {
        let block = [42u8; 32];
        let height = 5u64;
        let round = 0u32;

        let mut validator_set = HashMap::new();
        let mut signers = Vec::new();
        for i in 1..=4u8 {
            let key = generate_keypair();
            let pk = *key.verifying_key().as_bytes();
            let id = [i; 32];
            validator_set.insert(id, pk);
            signers.push((id, key));
        }

        // Two valid sigs, one short sig.
        let mut precommit_signatures = Vec::new();
        for (id, key) in &signers[..2] {
            let data = protocol::vote_sign_data(
                &TEST_CHAIN_ID,
                TEST_EPOCH,
                &block,
                height,
                round,
                crate::protocol::VoteType::Precommit,
            );
            let sig = sccgub_crypto::signature::sign(key, &data);
            precommit_signatures.push((*id, sig));
        }
        // Third sig: only 32 bytes (too short).
        precommit_signatures.push((signers[2].0, vec![0u8; 32]));

        let cert = SafetyCertificate {
            chain_id: TEST_CHAIN_ID,
            epoch: TEST_EPOCH,
            height,
            block_hash: block,
            round,
            precommit_signatures,
            quorum: 3,
            validator_count: 4,
        };

        let err = cert.verify_cryptographic(&validator_set).unwrap_err();
        assert!(
            err.contains("Signature too short"),
            "Expected short sig error, got: {}",
            err
        );
    }

    #[test]
    fn test_equivocation_evidence_same_block_rejected() {
        let key = generate_keypair();
        let pk = *key.verifying_key().as_bytes();
        let id = [1u8; 32];
        let height = 10u64;
        let block = [0xAAu8; 32];

        let data = sccgub_crypto::canonical::canonical_bytes(&(&block, height, 0u32, 2u8));

        let evidence = EquivocationEvidence {
            validator_id: id,
            height,
            round_a: 0,
            round_b: 0,
            block_hash_a: block,
            block_hash_b: block, // Same block — not real equivocation
            signature_a: sccgub_crypto::signature::sign(&key, &data),
            signature_b: sccgub_crypto::signature::sign(&key, &data),
        };

        let err = evidence.verify(&pk).unwrap_err();
        assert!(err.contains("same block hash"), "got: {}", err);
    }

    #[test]
    fn test_extract_from_fork_different_heights_returns_empty() {
        let cert_a = make_cert(10, [1u8; 32], &[1, 2, 3], 4);
        let cert_b = make_cert(11, [2u8; 32], &[3, 4, 5], 4);
        let evidence = EquivocationStore::extract_from_fork(&cert_a, &cert_b);
        assert!(
            evidence.is_empty(),
            "Different heights should yield no equivocation evidence"
        );
    }

    #[test]
    fn test_extract_from_fork_same_block_returns_empty() {
        let cert_a = make_cert(10, [1u8; 32], &[1, 2, 3], 4);
        let cert_b = make_cert(10, [1u8; 32], &[3, 4, 5], 4);
        let evidence = EquivocationStore::extract_from_fork(&cert_a, &cert_b);
        assert!(
            evidence.is_empty(),
            "Same block hash should yield no equivocation evidence"
        );
    }

    #[test]
    fn test_check_byzantine_tolerance_display_overflow_safe() {
        // Ensure the error message uses saturating arithmetic (N-48 fix).
        let err = check_byzantine_tolerance(3, u32::MAX).unwrap_err();
        // Just verify it doesn't panic and produces a valid error message.
        assert!(err.contains("Cannot tolerate"), "got: {}", err);
    }
}
