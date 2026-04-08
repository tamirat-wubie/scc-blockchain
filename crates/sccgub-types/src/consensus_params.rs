//! Consensus-critical parameters that affect block validation.
//!
//! Patch 03: every value in this struct affects the chain state root or block
//! validation outcome. Two nodes built from different commits MUST agree on
//! these values, or they will silently produce divergent blocks.
//!
//! Enforcement strategy: at genesis, the canonical bincode encoding of
//! `ConsensusParams` is written to the trie under the key `system/consensus_params`.
//! Any node importing the chain re-reads the entry, deserializes it, and uses
//! THOSE values for validation — not the local binary's compile-time constants.
//! If a peer's params disagree with the local binary's defaults, the peer's
//! state root will not match and CPoG validation will reject the chain.
//!
//! New parameters MUST be added with explicit defaults that match the values
//! they replace, or every existing chain will fail to import after the upgrade.

use serde::{Deserialize, Serialize};

/// Consensus-critical parameters. Stored in the genesis state root.
///
/// Every field affects either:
/// - Whether a block is accepted (gas limits, size caps, recursion bounds)
/// - The deterministic execution of contracts (step limit)
/// - The SCCE constraint walker bounds
///
/// Modifying any field requires a chain hard fork.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsensusParams {
    // ── CPoG validation ────────────────────────────────────────────────
    /// Maximum allowed proof recursion depth.
    pub max_proof_depth: u32,

    // ── SCCE walker bounds ─────────────────────────────────────────────
    /// Maximum number of symbols the SCCE walker may activate per transition.
    pub max_activated_symbols: u32,
    /// Maximum number of trie scans per activated symbol.
    pub max_scan_per_symbol: u64,
    /// Maximum constraints evaluated per symbol before forced termination.
    pub max_constraints_per_symbol: u64,

    // ── Contract execution ─────────────────────────────────────────────
    /// Default step bound for contract execution.
    pub default_max_steps: u64,

    // ── Gas limits ─────────────────────────────────────────────────────
    /// Maximum gas a single transaction may consume.
    pub default_tx_gas_limit: u64,
    /// Maximum gas a block may consume across all transactions.
    pub default_block_gas_limit: u64,

    // ── Gas costs (per operation) ──────────────────────────────────────
    pub gas_tx_base: u64,
    pub gas_compute_step: u64,
    pub gas_state_read: u64,
    pub gas_state_write: u64,
    pub gas_sig_verify: u64,
    pub gas_hash_op: u64,
    pub gas_proof_byte: u64,
    pub gas_payload_byte: u64,

    // ── Size caps ──────────────────────────────────────────────────────
    /// Maximum length of a symbol address (in bytes).
    pub max_symbol_address_len: u32,
    /// Maximum size of a single state entry key or value (in bytes).
    pub max_state_entry_size: u32,
}

impl Default for ConsensusParams {
    /// Default parameters match the current hard-coded constants.
    fn default() -> Self {
        Self {
            max_proof_depth: 256,
            max_activated_symbols: 16,
            max_scan_per_symbol: 1000,
            max_constraints_per_symbol: 64,
            default_max_steps: 10_000,
            default_tx_gas_limit: 1_000_000,
            default_block_gas_limit: 50_000_000,
            gas_tx_base: 1_000,
            gas_compute_step: 10,
            gas_state_read: 100,
            gas_state_write: 500,
            gas_sig_verify: 3_000,
            gas_hash_op: 50,
            gas_proof_byte: 5,
            gas_payload_byte: 2,
            max_symbol_address_len: 4096,
            max_state_entry_size: 1_048_576,
        }
    }
}

impl ConsensusParams {
    /// Canonical key under which `ConsensusParams` is stored in the trie.
    /// The `system/` prefix is writable by no transition kind (per ontology table),
    /// so this entry can only be set at genesis.
    pub const TRIE_KEY: &'static [u8] = b"system/consensus_params";

    /// Serialize to canonical bincode for storage in the trie.
    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        bincode::serialize(self).expect("ConsensusParams serialization is infallible")
    }

    /// Deserialize from canonical bincode read out of the trie.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, String> {
        bincode::deserialize(bytes).map_err(|e| format!("ConsensusParams deserialization: {}", e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_matches_legacy_constants() {
        let p = ConsensusParams::default();
        assert_eq!(p.max_proof_depth, 256);
        assert_eq!(p.max_activated_symbols, 16);
        assert_eq!(p.max_scan_per_symbol, 1000);
        assert_eq!(p.max_constraints_per_symbol, 64);
        assert_eq!(p.default_max_steps, 10_000);
        assert_eq!(p.default_tx_gas_limit, 1_000_000);
        assert_eq!(p.default_block_gas_limit, 50_000_000);
        assert_eq!(p.gas_tx_base, 1_000);
        assert_eq!(p.gas_compute_step, 10);
        assert_eq!(p.gas_state_read, 100);
        assert_eq!(p.gas_state_write, 500);
        assert_eq!(p.gas_sig_verify, 3_000);
        assert_eq!(p.gas_hash_op, 50);
        assert_eq!(p.gas_proof_byte, 5);
        assert_eq!(p.gas_payload_byte, 2);
        assert_eq!(p.max_symbol_address_len, 4096);
        assert_eq!(p.max_state_entry_size, 1_048_576);
    }

    #[test]
    fn roundtrip_canonical_bytes() {
        let p = ConsensusParams::default();
        let bytes = p.to_canonical_bytes();
        let parsed = ConsensusParams::from_canonical_bytes(&bytes).unwrap();
        assert_eq!(p, parsed);
    }

    #[test]
    fn from_canonical_bytes_rejects_garbage() {
        let result = ConsensusParams::from_canonical_bytes(b"not valid bincode");
        assert!(result.is_err());
    }

    #[test]
    fn trie_key_is_in_system_namespace() {
        assert!(ConsensusParams::TRIE_KEY.starts_with(b"system/"));
    }
}
