use serde::{Deserialize, Serialize};

use crate::{AgentId, Hash};

// GDPR-compliant data lifecycle management.
//
// Resolves the fundamental conflict: GDPR Article 17 (right to erasure)
// vs blockchain immutability. Solution: personal data stays off-chain,
// chain records existence proofs + deletion events.
//
// EU AI Act (Aug 2025) simultaneously requires 10-year audit trails.
// This module satisfies both by recording the *fact* of data operations
// without storing the data itself.

/// Off-chain data reference stored on-chain.
/// The actual data lives in external storage; the chain holds a hash commitment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OffChainRef {
    /// Hash of the off-chain content (integrity proof).
    pub content_hash: Hash,
    /// URI where the data can be retrieved (IPFS, S3, local store, etc.).
    pub storage_uri: String,
    /// Data classification for regulatory routing.
    pub classification: DataClassification,
    /// Whether this data has been deleted.
    pub deleted: bool,
}

/// Data classification levels for regulatory compliance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DataClassification {
    /// Public data (no restrictions).
    Public,
    /// Internal/operational data.
    Internal,
    /// Personal data subject to GDPR/privacy laws.
    Personal,
    /// Sensitive personal data (health, biometric, financial).
    Sensitive,
    /// Regulated data (requires specific compliance).
    Regulated,
}

/// GDPR deletion request and proof.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeletionProof {
    /// Hash of the data that was deleted.
    pub data_hash: Hash,
    /// Agent who requested the deletion.
    pub requested_by: AgentId,
    /// Regulatory basis (e.g., "GDPR Art. 17", "HIPAA", "Ethiopian Data Protection").
    pub regulatory_basis: String,
    /// Block height at which deletion was recorded.
    pub deleted_at_height: u64,
    /// Hash of the original creation event (causal link).
    pub creation_event_hash: Hash,
}

/// Data lifecycle tracker.
#[derive(Debug, Clone, Default)]
pub struct DataLifecycleTracker {
    /// Off-chain data references indexed by content hash.
    pub references: std::collections::HashMap<Hash, OffChainRef>,
    /// Deletion proofs indexed by data hash.
    pub deletions: Vec<DeletionProof>,
}

impl DataLifecycleTracker {
    /// Register an off-chain data reference.
    pub fn register_data(
        &mut self,
        content_hash: Hash,
        storage_uri: String,
        classification: DataClassification,
    ) -> Result<(), String> {
        if self.references.contains_key(&content_hash) {
            return Err("Data reference already registered".into());
        }
        self.references.insert(
            content_hash,
            OffChainRef {
                content_hash,
                storage_uri,
                classification,
                deleted: false,
            },
        );
        Ok(())
    }

    /// Record a GDPR-compliant deletion.
    /// Marks the on-chain reference as deleted and records the proof.
    pub fn record_deletion(
        &mut self,
        data_hash: Hash,
        requested_by: AgentId,
        regulatory_basis: String,
        height: u64,
        creation_event_hash: Hash,
    ) -> Result<DeletionProof, String> {
        let reference = self
            .references
            .get_mut(&data_hash)
            .ok_or("Data reference not found")?;

        if reference.deleted {
            return Err("Data already deleted".into());
        }

        reference.deleted = true;

        let proof = DeletionProof {
            data_hash,
            requested_by,
            regulatory_basis,
            deleted_at_height: height,
            creation_event_hash,
        };

        self.deletions.push(proof.clone());
        Ok(proof)
    }

    /// Verify that all references to a data hash have been deleted.
    /// This proves GDPR compliance for a specific data subject.
    pub fn verify_erasure(&self, data_hash: &Hash) -> ErasureVerification {
        match self.references.get(data_hash) {
            None => ErasureVerification::NeverExisted,
            Some(r) if r.deleted => {
                let proof = self.deletions.iter().find(|d| d.data_hash == *data_hash);
                ErasureVerification::Deleted {
                    proof: proof.cloned(),
                }
            }
            Some(_) => ErasureVerification::StillExists,
        }
    }

    /// Count of active (non-deleted) personal data references.
    pub fn active_personal_data_count(&self) -> usize {
        self.references
            .values()
            .filter(|r| {
                !r.deleted
                    && matches!(
                        r.classification,
                        DataClassification::Personal | DataClassification::Sensitive
                    )
            })
            .count()
    }
}

/// Result of an erasure verification.
#[derive(Debug, Clone)]
pub enum ErasureVerification {
    /// Data was never recorded on this chain.
    NeverExisted,
    /// Data exists and has been deleted, with proof.
    Deleted { proof: Option<DeletionProof> },
    /// Data exists and has NOT been deleted.
    StillExists,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_register_and_delete() {
        let mut tracker = DataLifecycleTracker::default();
        let hash = [1u8; 32];

        tracker
            .register_data(hash, "ipfs://Qm...".into(), DataClassification::Personal)
            .unwrap();

        assert_eq!(tracker.active_personal_data_count(), 1);

        let proof = tracker
            .record_deletion(hash, [2u8; 32], "GDPR Art. 17".into(), 100, [3u8; 32])
            .unwrap();

        assert_eq!(proof.regulatory_basis, "GDPR Art. 17");
        assert_eq!(tracker.active_personal_data_count(), 0);
    }

    #[test]
    fn test_verify_erasure() {
        let mut tracker = DataLifecycleTracker::default();
        let hash = [1u8; 32];

        // Never existed.
        assert!(matches!(
            tracker.verify_erasure(&hash),
            ErasureVerification::NeverExisted
        ));

        // Register.
        tracker
            .register_data(
                hash,
                "s3://bucket/key".into(),
                DataClassification::Sensitive,
            )
            .unwrap();

        // Still exists.
        assert!(matches!(
            tracker.verify_erasure(&hash),
            ErasureVerification::StillExists
        ));

        // Delete.
        tracker
            .record_deletion(hash, [2u8; 32], "HIPAA".into(), 50, [3u8; 32])
            .unwrap();

        // Verified deleted with proof.
        match tracker.verify_erasure(&hash) {
            ErasureVerification::Deleted { proof } => {
                assert!(proof.is_some());
                assert_eq!(proof.unwrap().regulatory_basis, "HIPAA");
            }
            _ => panic!("Expected Deleted"),
        }
    }

    #[test]
    fn test_double_deletion_rejected() {
        let mut tracker = DataLifecycleTracker::default();
        let hash = [1u8; 32];
        tracker
            .register_data(hash, "uri".into(), DataClassification::Personal)
            .unwrap();
        tracker
            .record_deletion(hash, [2u8; 32], "GDPR".into(), 10, [3u8; 32])
            .unwrap();

        // Second deletion should fail.
        assert!(tracker
            .record_deletion(hash, [2u8; 32], "GDPR".into(), 20, [3u8; 32])
            .is_err());
    }

    #[test]
    fn test_duplicate_registration_rejected() {
        let mut tracker = DataLifecycleTracker::default();
        let hash = [1u8; 32];
        tracker
            .register_data(hash, "uri".into(), DataClassification::Public)
            .unwrap();
        assert!(tracker
            .register_data(hash, "uri2".into(), DataClassification::Public)
            .is_err());
    }
}
