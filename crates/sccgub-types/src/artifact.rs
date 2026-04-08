use serde::{Deserialize, Serialize};

use crate::{AgentId, Hash};

/// External artifact commitment — the chain stores only identity, commitment,
/// authority, lineage, and settlement. Never raw media or large payloads.
///
/// Design rule: content_hash is primary, locator is secondary.
/// An artifact remains validatable even if the storage locator changes.
///
/// Unique artifact identifier (BLAKE3 hash of canonical content commitment).
pub type ArtifactId = Hash;

/// What kind of external artifact this represents.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ArtifactKind {
    CaptureSession,
    VrcFile,
    MlvffFile,
    ReconstructionOutput,
    IntelligenceOutput,
    DeliveryBundle,
    PolicyBundle,
    Dataset,
    Model,
    Custom(String),
}

/// Where the artifact's full content lives (off-chain).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum StorageScheme {
    Uri,
    Ipfs,
    ObjectStore,
    LocalFile,
    Vrc,
    Mlvff,
    Custom(String),
}

/// On-chain reference to an external artifact.
/// Stores only hashes, metadata, and locator — never raw content.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactRef {
    /// Unique identifier (derived from content commitment).
    pub artifact_id: ArtifactId,
    /// Classification of the artifact.
    pub kind: ArtifactKind,
    /// Schema this artifact conforms to.
    pub schema_name: String,
    /// Version of the schema.
    pub schema_version: String,
    /// BLAKE3 hash of the full artifact content.
    pub content_hash: Hash,
    /// BLAKE3 hash of the artifact's manifest/header.
    pub manifest_hash: Hash,
    /// Optional BLAKE3 hash of the artifact's cryptographic signature block.
    pub signature_hash: Option<Hash>,
    /// How the artifact is stored off-chain.
    pub storage_scheme: StorageScheme,
    /// Off-chain locator (URI, CID, path, etc.). Secondary to content_hash.
    pub locator: String,
    /// Size of the artifact in bytes.
    pub byte_length: u64,
    /// Who registered this artifact on-chain.
    pub created_by: AgentId,
    /// Block height at which this was registered.
    pub created_at_block: u64,
}

impl ArtifactRef {
    /// Compute the canonical bytes used for artifact ID derivation.
    /// Callers should hash this with BLAKE3 to produce the artifact_id.
    /// Formula: artifact_id = BLAKE3(content_hash || manifest_hash || schema_name || schema_version)
    pub fn canonical_id_preimage(
        content_hash: &[u8; 32],
        manifest_hash: &[u8; 32],
        schema_name: &str,
        schema_version: &str,
    ) -> Vec<u8> {
        let mut data = Vec::with_capacity(64 + schema_name.len() + schema_version.len());
        data.extend_from_slice(content_hash);
        data.extend_from_slice(manifest_hash);
        data.extend_from_slice(schema_name.as_bytes());
        data.extend_from_slice(schema_version.as_bytes());
        data
    }

    /// Validate that required fields are present (fail-closed).
    pub fn validate(&self) -> Result<(), String> {
        if self.artifact_id == [0u8; 32] {
            return Err("artifact_id is required".into());
        }
        if self.content_hash == [0u8; 32] {
            return Err("content_hash is required".into());
        }
        if self.manifest_hash == [0u8; 32] {
            return Err("manifest_hash is required".into());
        }
        if self.schema_name.is_empty() {
            return Err("schema_name is required".into());
        }
        if self.schema_version.is_empty() {
            return Err("schema_version is required".into());
        }
        if self.created_by == [0u8; 32] {
            return Err("created_by (producer identity) is required".into());
        }
        if self.locator.is_empty() {
            return Err("locator is required".into());
        }
        if self.byte_length == 0 {
            return Err("byte_length must be > 0".into());
        }
        Ok(())
    }
}

/// Schema registry entry — versioned external schema binding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SchemaEntry {
    pub schema_name: String,
    pub schema_version: String,
    /// Hash of the full schema specification document (off-chain).
    pub spec_hash: Hash,
    /// Current lifecycle status.
    pub status: SchemaStatus,
    /// Parent schema for compatibility chain.
    pub compatibility_parent: Option<(String, String)>,
    /// Block height at which this entry was registered.
    pub registered_at_block: u64,
}

impl SchemaEntry {
    pub fn validate(&self) -> Result<(), String> {
        if self.schema_name.is_empty() {
            return Err("schema_name is required".into());
        }
        if self.schema_version.is_empty() {
            return Err("schema_version is required".into());
        }
        if self.spec_hash == [0u8; 32] {
            return Err("spec_hash is required".into());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SchemaStatus {
    Active,
    Deprecated,
    Frozen,
    Retired,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_artifact() -> ArtifactRef {
        ArtifactRef {
            artifact_id: [1u8; 32],
            kind: ArtifactKind::VrcFile,
            schema_name: "vrc-media-core".into(),
            schema_version: "1.1".into(),
            content_hash: [2u8; 32],
            manifest_hash: [3u8; 32],
            signature_hash: Some([4u8; 32]),
            storage_scheme: StorageScheme::Vrc,
            locator: "s3://bucket/artifact.vrc".into(),
            byte_length: 1_000_000,
            created_by: [5u8; 32],
            created_at_block: 100,
        }
    }

    #[test]
    fn test_valid_artifact_passes() {
        assert!(valid_artifact().validate().is_ok());
    }

    #[test]
    fn test_missing_content_hash_rejected() {
        let mut a = valid_artifact();
        a.content_hash = [0u8; 32];
        assert!(a.validate().is_err());
    }

    #[test]
    fn test_missing_manifest_hash_rejected() {
        let mut a = valid_artifact();
        a.manifest_hash = [0u8; 32];
        assert!(a.validate().is_err());
    }

    #[test]
    fn test_missing_schema_rejected() {
        let mut a = valid_artifact();
        a.schema_name = String::new();
        assert!(a.validate().is_err());
    }

    #[test]
    fn test_missing_producer_rejected() {
        let mut a = valid_artifact();
        a.created_by = [0u8; 32];
        assert!(a.validate().is_err());
    }

    #[test]
    fn test_serialization_roundtrip() {
        let a = valid_artifact();
        let bytes = serde_json::to_vec(&a).unwrap();
        let recovered: ArtifactRef = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(recovered.artifact_id, a.artifact_id);
        assert_eq!(recovered.content_hash, a.content_hash);
    }
}
