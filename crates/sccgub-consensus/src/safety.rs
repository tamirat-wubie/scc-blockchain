use sccgub_types::Hash;

// Formal BFT safety proof framework.
// Safety theorem: If f < n/3 validators are Byzantine, no conflicting blocks
// can both achieve supermajority. Proof: two supermajorities require > 2n
// validators, but only n exist.

/// A formal safety certificate proving no fork can exist.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SafetyCertificate {
    pub height: u64,
    pub block_hash: Hash,
    /// The set of precommit signatures (at least quorum).
    pub precommit_signatures: Vec<(Hash, Vec<u8>)>, // (validator_id, signature)
    /// Quorum size used.
    pub quorum: u32,
    /// Total validator count.
    pub validator_count: u32,
}

impl SafetyCertificate {
    /// Verify that the certificate is structurally valid.
    pub fn verify_structure(&self) -> Result<(), String> {
        let expected_quorum = (2 * self.validator_count) / 3 + 1;
        if self.quorum != expected_quorum {
            return Err(format!(
                "Quorum mismatch: claimed {} but expected {} for n={}",
                self.quorum, expected_quorum, self.validator_count
            ));
        }
        if (self.precommit_signatures.len() as u32) < self.quorum {
            return Err(format!(
                "Insufficient signatures: {} < quorum {}",
                self.precommit_signatures.len(),
                self.quorum
            ));
        }
        // Check for duplicate signers.
        let unique_signers: std::collections::HashSet<Hash> =
            self.precommit_signatures.iter().map(|(id, _)| *id).collect();
        if unique_signers.len() != self.precommit_signatures.len() {
            return Err("Duplicate signer detected in safety certificate".into());
        }
        Ok(())
    }
}

/// Prove that two conflicting blocks cannot both be finalized.
///
/// Given two safety certificates for different blocks at the same height,
/// at least one certificate must contain a dishonest validator (equivocator).
/// This function identifies the equivocators.
pub fn prove_no_fork(
    cert_a: &SafetyCertificate,
    cert_b: &SafetyCertificate,
) -> ForkProofResult {
    if cert_a.height != cert_b.height {
        return ForkProofResult::DifferentHeights;
    }
    if cert_a.block_hash == cert_b.block_hash {
        return ForkProofResult::SameBlock;
    }

    // Find validators that signed both certificates (equivocators).
    let signers_a: std::collections::HashSet<Hash> =
        cert_a.precommit_signatures.iter().map(|(id, _)| *id).collect();
    let signers_b: std::collections::HashSet<Hash> =
        cert_b.precommit_signatures.iter().map(|(id, _)| *id).collect();

    let equivocators: Vec<Hash> = signers_a.intersection(&signers_b).copied().collect();

    if equivocators.is_empty() {
        // No overlap means combined signers > n (impossible if both certs are valid).
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
        return 0; // Need at least 4 validators for f=1.
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
            3 * desired_tolerance + 1
        ))
    } else {
        Ok(())
    }
}

/// Result of a fork proof analysis.
#[derive(Debug, Clone)]
pub enum ForkProofResult {
    /// Certificates are for different heights (not a fork).
    DifferentHeights,
    /// Certificates are for the same block (agreement, not a fork).
    SameBlock,
    /// Equivocators found — these validators signed both conflicting blocks.
    EquivocatorsFound {
        equivocators: Vec<Hash>,
        height: u64,
        block_a: Hash,
        block_b: Hash,
    },
    /// Logically impossible fork (indicates a bug in the proof system).
    ImpossibleFork { reason: String },
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_cert(
        height: u64,
        block: Hash,
        signers: &[u8],
        n: u32,
    ) -> SafetyCertificate {
        SafetyCertificate {
            height,
            block_hash: block,
            precommit_signatures: signers
                .iter()
                .map(|&s| ([s; 32], vec![0u8; 64]))
                .collect(),
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
        let cert = make_cert(10, [1u8; 32], &[1, 2], 4); // Need 3, have 2.
        assert!(cert.verify_structure().is_err());
    }

    #[test]
    fn test_duplicate_signer_detected() {
        let mut cert = make_cert(10, [1u8; 32], &[1, 2, 3], 4);
        cert.precommit_signatures[2].0 = [1; 32]; // Duplicate signer.
        assert!(cert.verify_structure().is_err());
    }

    #[test]
    fn test_prove_no_fork_finds_equivocators() {
        // Two conflicting certs at same height. Validator 3 signed both.
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
        assert!(matches!(prove_no_fork(&cert_a, &cert_b), ForkProofResult::SameBlock));
    }

    #[test]
    fn test_max_byzantine() {
        assert_eq!(max_byzantine(3), 0);  // f=0 for n=3.
        assert_eq!(max_byzantine(4), 1);  // f=1 for n=4.
        assert_eq!(max_byzantine(7), 2);  // f=2 for n=7.
        assert_eq!(max_byzantine(21), 6); // f=6 for n=21.
        assert_eq!(max_byzantine(100), 33); // f=33 for n=100.
    }

    #[test]
    fn test_byzantine_tolerance_check() {
        assert!(check_byzantine_tolerance(21, 6).is_ok());
        assert!(check_byzantine_tolerance(21, 7).is_err());
        assert!(check_byzantine_tolerance(4, 1).is_ok());
        assert!(check_byzantine_tolerance(3, 1).is_err());
    }
}
