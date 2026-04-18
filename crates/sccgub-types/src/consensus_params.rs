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
    /// Maximum propagation depth for SCCE mesh traversal.
    pub max_constraint_propagation_depth: u32,
    /// Maximum SCCE propagation steps before forced termination.
    pub max_constraint_propagation_steps: u64,
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
    /// Maximum allowed absolute swing between tension_before and tension_after.
    pub max_tension_swing: i64,

    // ── v3 additions (Patch-04) ────────────────────────────────────────
    // The six fields below are introduced in `header.version = 3`.
    // v2 chains deserialize via `LegacyConsensusParamsV2` and receive
    // the defaults declared in `Default` below.
    /// View-change base timeout, milliseconds (§16.1).
    pub view_change_base_timeout_ms: u32,
    /// View-change maximum timeout (exponential-backoff cap), milliseconds (§16.1).
    pub view_change_max_timeout_ms: u32,
    /// Maximum canonical-encoded block size in bytes (§17.5).
    pub max_block_bytes: u32,
    /// Maximum concurrently-active governance proposals (§17.6).
    pub max_active_proposals: u32,
    /// Default active validator-set size (capped by `ConstitutionalCeilings`).
    pub max_validator_set_size: u32,
    /// Default maximum `ValidatorSetChange` events per block.
    pub max_validator_set_changes_per_block_param: u32,

    // ── v4 additions (Patch-05) ────────────────────────────────────────
    // v3 chains deserialize via `LegacyConsensusParamsV3` and receive
    // the defaults declared in `Default` below.
    /// Patch-05 §20.1: window size for median-over-window fee oracle.
    /// Must be odd (so the median is a single sample, not an averaged
    /// pair — keeps the oracle response less vulnerable to a single
    /// manipulator). Default 7 blocks.
    pub median_tension_window: u32,
    /// Patch-05 §20.1: tension multiplier α, fixed-point (raw i128).
    /// Default `SCALE/2 = 0.5`.
    pub fee_tension_alpha: i128,
    /// Patch-05 §24: confirmation depth (`k`) used to derive
    /// §15.5 activation_delay. Default 2.
    pub confirmation_depth: u64,
    /// Patch-05 §29: maximum `EquivocationEvidence` records per block.
    /// Default 4.
    pub max_equivocation_evidence_per_block_param: u32,
}

impl Default for ConsensusParams {
    /// Default parameters match the current hard-coded constants.
    fn default() -> Self {
        Self {
            max_proof_depth: 256,
            max_constraint_propagation_depth: 32,
            max_constraint_propagation_steps: 10_000,
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
            max_tension_swing: 2_000_000,
            // v3 (Patch-04) defaults — see PATCH_04.md §17.3.
            view_change_base_timeout_ms: 1_000,
            view_change_max_timeout_ms: 60_000,
            max_block_bytes: 2_097_152,
            max_active_proposals: 128,
            max_validator_set_size: 64,
            max_validator_set_changes_per_block_param: 4,
            // v4 (Patch-05) defaults — see PATCH_05.md §20.1, §24, §29.
            median_tension_window: 7,
            fee_tension_alpha: crate::tension::TensionValue::SCALE / 2, // 0.5
            confirmation_depth: 2,
            max_equivocation_evidence_per_block_param: 4,
        }
    }
}

impl ConsensusParams {
    /// Patch-06 §33.2: pruning depth derived from `confirmation_depth`.
    /// A trie entry is prunable only if the youngest block that touched
    /// it has finality depth `>= pruning_depth`. Derived rather than
    /// added as a separate field to avoid yet another schema migration;
    /// defaults to `confirmation_depth * 16 = 32` blocks.
    pub fn pruning_depth(&self) -> u64 {
        self.confirmation_depth.saturating_mul(16)
    }

    /// Canonical key under which `ConsensusParams` is stored in the trie.
    /// The `system/` prefix is writable by no transition kind (per ontology table),
    /// so this entry can only be set at genesis.
    pub const TRIE_KEY: &'static [u8] = b"system/consensus_params";

    /// Serialize to canonical bincode for storage in the trie.
    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        bincode::serialize(self).expect("ConsensusParams serialization is infallible")
    }

    /// Deserialize from canonical bincode read out of the trie.
    /// Runs bounds validation after deserialization (defense-in-depth).
    ///
    /// Fallback cascade: current struct → `LegacyConsensusParamsV3`
    /// (Patch-04 / v0.4.0 schema, no v4 fields) → `LegacyConsensusParamsV2`
    /// (v0.3.0 schema, no v3 fields) → `LegacyConsensusParamsV1`
    /// (pre-v0.3.0 schema). Fallback paths inject defaults for any
    /// fields missing in the older encoding, so v2 and v3 chains
    /// continue to replay under Patch-05 code.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, String> {
        let params: Self = bincode::deserialize(bytes)
            .or_else(|_| {
                bincode::deserialize::<LegacyConsensusParamsV3>(bytes).map(ConsensusParams::from)
            })
            .or_else(|_| {
                bincode::deserialize::<LegacyConsensusParamsV2>(bytes).map(ConsensusParams::from)
            })
            .or_else(|_| {
                bincode::deserialize::<LegacyConsensusParamsV1>(bytes).map(ConsensusParams::from)
            })
            .map_err(|e| format!("ConsensusParams deserialization: {}", e))?;
        params.validate()?;
        Ok(params)
    }

    /// Bounds validation for deserialized consensus params.
    ///
    /// Rejects values that would make the chain unusable or create
    /// resource-exhaustion vectors. State-root replay already protects
    /// against tampered params from untrusted sources, but bounds
    /// validation catches bugs in genesis construction or migration.
    pub fn validate(&self) -> Result<(), String> {
        if self.max_proof_depth == 0 || self.max_proof_depth > 100_000 {
            return Err(format!(
                "max_proof_depth {} out of bounds (1..100000)",
                self.max_proof_depth
            ));
        }
        if self.default_tx_gas_limit == 0 || self.default_tx_gas_limit > 1_000_000_000 {
            return Err(format!(
                "default_tx_gas_limit {} out of bounds (1..1000000000)",
                self.default_tx_gas_limit
            ));
        }
        if self.default_block_gas_limit == 0 || self.default_block_gas_limit > 10_000_000_000 {
            return Err(format!(
                "default_block_gas_limit {} out of bounds (1..10000000000)",
                self.default_block_gas_limit
            ));
        }
        if self.default_block_gas_limit < self.default_tx_gas_limit {
            return Err(format!(
                "default_block_gas_limit {} < default_tx_gas_limit {}",
                self.default_block_gas_limit, self.default_tx_gas_limit
            ));
        }
        if self.max_state_entry_size == 0 || self.max_state_entry_size > 16 * 1024 * 1024 {
            return Err(format!(
                "max_state_entry_size {} out of bounds (1..16777216)",
                self.max_state_entry_size
            ));
        }
        if self.max_symbol_address_len == 0 || self.max_symbol_address_len > 1_048_576 {
            return Err(format!(
                "max_symbol_address_len {} out of bounds (1..1048576)",
                self.max_symbol_address_len
            ));
        }
        if self.max_tension_swing <= 0 || self.max_tension_swing > 1_000_000_000 {
            return Err(format!(
                "max_tension_swing {} out of bounds (1..1000000000)",
                self.max_tension_swing
            ));
        }
        // Propagation bounds — prevent OOM from unbounded walker expansion.
        if self.max_constraint_propagation_depth == 0
            || self.max_constraint_propagation_depth > 1_000
        {
            return Err(format!(
                "max_constraint_propagation_depth {} out of bounds (1..1000)",
                self.max_constraint_propagation_depth
            ));
        }
        if self.max_constraint_propagation_steps == 0
            || self.max_constraint_propagation_steps > 10_000_000
        {
            return Err(format!(
                "max_constraint_propagation_steps {} out of bounds (1..10000000)",
                self.max_constraint_propagation_steps
            ));
        }
        if self.max_activated_symbols == 0 {
            return Err("max_activated_symbols must be > 0".into());
        }
        if self.max_scan_per_symbol == 0 {
            return Err("max_scan_per_symbol must be > 0".into());
        }
        if self.max_constraints_per_symbol == 0 {
            return Err("max_constraints_per_symbol must be > 0".into());
        }
        if self.default_max_steps == 0 || self.default_max_steps > 10_000_000 {
            return Err(format!(
                "default_max_steps {} out of bounds (1..10000000)",
                self.default_max_steps
            ));
        }
        for (label, value) in [
            ("gas_tx_base", self.gas_tx_base),
            ("gas_compute_step", self.gas_compute_step),
            ("gas_state_read", self.gas_state_read),
            ("gas_state_write", self.gas_state_write),
            ("gas_sig_verify", self.gas_sig_verify),
            ("gas_hash_op", self.gas_hash_op),
            ("gas_proof_byte", self.gas_proof_byte),
            ("gas_payload_byte", self.gas_payload_byte),
        ] {
            if value == 0 || value > 1_000_000 {
                return Err(format!("{} {} out of bounds (1..1000000)", label, value));
            }
        }

        // ── Patch-04 v3 additions ─────────────────────────────────────
        if self.view_change_base_timeout_ms == 0 {
            return Err("view_change_base_timeout_ms must be > 0".into());
        }
        if self.view_change_max_timeout_ms < self.view_change_base_timeout_ms {
            return Err(format!(
                "view_change_max_timeout_ms {} < view_change_base_timeout_ms {}",
                self.view_change_max_timeout_ms, self.view_change_base_timeout_ms
            ));
        }
        if self.max_block_bytes < 1024 {
            return Err(format!(
                "max_block_bytes {} below sane floor (1024)",
                self.max_block_bytes
            ));
        }
        if self.max_active_proposals == 0 {
            return Err("max_active_proposals must be > 0".into());
        }
        if self.max_validator_set_size == 0 {
            return Err("max_validator_set_size must be > 0".into());
        }
        if self.max_validator_set_changes_per_block_param == 0 {
            return Err("max_validator_set_changes_per_block_param must be > 0".into());
        }

        // ── Patch-05 v4 additions ─────────────────────────────────────
        if self.median_tension_window == 0 {
            return Err("median_tension_window must be > 0".into());
        }
        if self.median_tension_window.is_multiple_of(2) {
            return Err(format!(
                "median_tension_window {} must be odd (single-sample median)",
                self.median_tension_window
            ));
        }
        if self.fee_tension_alpha < 0 {
            return Err(format!(
                "fee_tension_alpha {} must be non-negative",
                self.fee_tension_alpha
            ));
        }
        if self.confirmation_depth == 0 {
            return Err("confirmation_depth must be > 0".into());
        }
        if self.max_equivocation_evidence_per_block_param == 0 {
            return Err("max_equivocation_evidence_per_block_param must be > 0".into());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct LegacyConsensusParamsV1 {
    max_proof_depth: u32,
    max_activated_symbols: u32,
    max_scan_per_symbol: u64,
    max_constraints_per_symbol: u64,
    default_max_steps: u64,
    default_tx_gas_limit: u64,
    default_block_gas_limit: u64,
    gas_tx_base: u64,
    gas_compute_step: u64,
    gas_state_read: u64,
    gas_state_write: u64,
    gas_sig_verify: u64,
    gas_hash_op: u64,
    gas_proof_byte: u64,
    gas_payload_byte: u64,
    max_symbol_address_len: u32,
    max_state_entry_size: u32,
}

impl From<LegacyConsensusParamsV1> for ConsensusParams {
    fn from(value: LegacyConsensusParamsV1) -> Self {
        let defaults = Self::default();
        Self {
            max_proof_depth: value.max_proof_depth,
            max_constraint_propagation_depth: 32,
            max_constraint_propagation_steps: 10_000,
            max_activated_symbols: value.max_activated_symbols,
            max_scan_per_symbol: value.max_scan_per_symbol,
            max_constraints_per_symbol: value.max_constraints_per_symbol,
            default_max_steps: value.default_max_steps,
            default_tx_gas_limit: value.default_tx_gas_limit,
            default_block_gas_limit: value.default_block_gas_limit,
            gas_tx_base: value.gas_tx_base,
            gas_compute_step: value.gas_compute_step,
            gas_state_read: value.gas_state_read,
            gas_state_write: value.gas_state_write,
            gas_sig_verify: value.gas_sig_verify,
            gas_hash_op: value.gas_hash_op,
            gas_proof_byte: value.gas_proof_byte,
            gas_payload_byte: value.gas_payload_byte,
            max_symbol_address_len: value.max_symbol_address_len,
            max_state_entry_size: value.max_state_entry_size,
            max_tension_swing: 2_000_000,
            // v3 fields get Patch-04 defaults when migrating from V1.
            view_change_base_timeout_ms: defaults.view_change_base_timeout_ms,
            view_change_max_timeout_ms: defaults.view_change_max_timeout_ms,
            max_block_bytes: defaults.max_block_bytes,
            max_active_proposals: defaults.max_active_proposals,
            max_validator_set_size: defaults.max_validator_set_size,
            max_validator_set_changes_per_block_param: defaults
                .max_validator_set_changes_per_block_param,
            // v4 fields get Patch-05 defaults.
            median_tension_window: defaults.median_tension_window,
            fee_tension_alpha: defaults.fee_tension_alpha,
            confirmation_depth: defaults.confirmation_depth,
            max_equivocation_evidence_per_block_param: defaults
                .max_equivocation_evidence_per_block_param,
        }
    }
}

/// v0.3.0 schema of `ConsensusParams` (pre-Patch-04). Retained as a
/// deserialization fallback so v2 chains replay under Patch-04 code without
/// re-encoding the genesis `consensus_params` payload. The six v3 fields are
/// filled with `ConsensusParams::default()` values on migration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct LegacyConsensusParamsV2 {
    max_proof_depth: u32,
    max_constraint_propagation_depth: u32,
    max_constraint_propagation_steps: u64,
    max_activated_symbols: u32,
    max_scan_per_symbol: u64,
    max_constraints_per_symbol: u64,
    default_max_steps: u64,
    default_tx_gas_limit: u64,
    default_block_gas_limit: u64,
    gas_tx_base: u64,
    gas_compute_step: u64,
    gas_state_read: u64,
    gas_state_write: u64,
    gas_sig_verify: u64,
    gas_hash_op: u64,
    gas_proof_byte: u64,
    gas_payload_byte: u64,
    max_symbol_address_len: u32,
    max_state_entry_size: u32,
    max_tension_swing: i64,
}

impl From<LegacyConsensusParamsV2> for ConsensusParams {
    fn from(value: LegacyConsensusParamsV2) -> Self {
        let defaults = Self::default();
        Self {
            max_proof_depth: value.max_proof_depth,
            max_constraint_propagation_depth: value.max_constraint_propagation_depth,
            max_constraint_propagation_steps: value.max_constraint_propagation_steps,
            max_activated_symbols: value.max_activated_symbols,
            max_scan_per_symbol: value.max_scan_per_symbol,
            max_constraints_per_symbol: value.max_constraints_per_symbol,
            default_max_steps: value.default_max_steps,
            default_tx_gas_limit: value.default_tx_gas_limit,
            default_block_gas_limit: value.default_block_gas_limit,
            gas_tx_base: value.gas_tx_base,
            gas_compute_step: value.gas_compute_step,
            gas_state_read: value.gas_state_read,
            gas_state_write: value.gas_state_write,
            gas_sig_verify: value.gas_sig_verify,
            gas_hash_op: value.gas_hash_op,
            gas_proof_byte: value.gas_proof_byte,
            gas_payload_byte: value.gas_payload_byte,
            max_symbol_address_len: value.max_symbol_address_len,
            max_state_entry_size: value.max_state_entry_size,
            max_tension_swing: value.max_tension_swing,
            view_change_base_timeout_ms: defaults.view_change_base_timeout_ms,
            view_change_max_timeout_ms: defaults.view_change_max_timeout_ms,
            max_block_bytes: defaults.max_block_bytes,
            max_active_proposals: defaults.max_active_proposals,
            max_validator_set_size: defaults.max_validator_set_size,
            max_validator_set_changes_per_block_param: defaults
                .max_validator_set_changes_per_block_param,
            median_tension_window: defaults.median_tension_window,
            fee_tension_alpha: defaults.fee_tension_alpha,
            confirmation_depth: defaults.confirmation_depth,
            max_equivocation_evidence_per_block_param: defaults
                .max_equivocation_evidence_per_block_param,
        }
    }
}

/// v0.4.0 schema of `ConsensusParams` (pre-Patch-05). Retained as a
/// deserialization fallback so v3 chains replay under Patch-05 code
/// without re-encoding the genesis `consensus_params` payload. The four
/// v4 fields are filled with `ConsensusParams::default()` values on
/// migration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct LegacyConsensusParamsV3 {
    max_proof_depth: u32,
    max_constraint_propagation_depth: u32,
    max_constraint_propagation_steps: u64,
    max_activated_symbols: u32,
    max_scan_per_symbol: u64,
    max_constraints_per_symbol: u64,
    default_max_steps: u64,
    default_tx_gas_limit: u64,
    default_block_gas_limit: u64,
    gas_tx_base: u64,
    gas_compute_step: u64,
    gas_state_read: u64,
    gas_state_write: u64,
    gas_sig_verify: u64,
    gas_hash_op: u64,
    gas_proof_byte: u64,
    gas_payload_byte: u64,
    max_symbol_address_len: u32,
    max_state_entry_size: u32,
    max_tension_swing: i64,
    view_change_base_timeout_ms: u32,
    view_change_max_timeout_ms: u32,
    max_block_bytes: u32,
    max_active_proposals: u32,
    max_validator_set_size: u32,
    max_validator_set_changes_per_block_param: u32,
}

impl From<LegacyConsensusParamsV3> for ConsensusParams {
    fn from(value: LegacyConsensusParamsV3) -> Self {
        let defaults = Self::default();
        Self {
            max_proof_depth: value.max_proof_depth,
            max_constraint_propagation_depth: value.max_constraint_propagation_depth,
            max_constraint_propagation_steps: value.max_constraint_propagation_steps,
            max_activated_symbols: value.max_activated_symbols,
            max_scan_per_symbol: value.max_scan_per_symbol,
            max_constraints_per_symbol: value.max_constraints_per_symbol,
            default_max_steps: value.default_max_steps,
            default_tx_gas_limit: value.default_tx_gas_limit,
            default_block_gas_limit: value.default_block_gas_limit,
            gas_tx_base: value.gas_tx_base,
            gas_compute_step: value.gas_compute_step,
            gas_state_read: value.gas_state_read,
            gas_state_write: value.gas_state_write,
            gas_sig_verify: value.gas_sig_verify,
            gas_hash_op: value.gas_hash_op,
            gas_proof_byte: value.gas_proof_byte,
            gas_payload_byte: value.gas_payload_byte,
            max_symbol_address_len: value.max_symbol_address_len,
            max_state_entry_size: value.max_state_entry_size,
            max_tension_swing: value.max_tension_swing,
            view_change_base_timeout_ms: value.view_change_base_timeout_ms,
            view_change_max_timeout_ms: value.view_change_max_timeout_ms,
            max_block_bytes: value.max_block_bytes,
            max_active_proposals: value.max_active_proposals,
            max_validator_set_size: value.max_validator_set_size,
            max_validator_set_changes_per_block_param: value
                .max_validator_set_changes_per_block_param,
            median_tension_window: defaults.median_tension_window,
            fee_tension_alpha: defaults.fee_tension_alpha,
            confirmation_depth: defaults.confirmation_depth,
            max_equivocation_evidence_per_block_param: defaults
                .max_equivocation_evidence_per_block_param,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_matches_legacy_constants() {
        let p = ConsensusParams::default();
        assert_eq!(p.max_proof_depth, 256);
        assert_eq!(p.max_constraint_propagation_depth, 32);
        assert_eq!(p.max_constraint_propagation_steps, 10_000);
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
        assert_eq!(p.max_tension_swing, 2_000_000);
        // v3 (Patch-04) defaults.
        assert_eq!(p.view_change_base_timeout_ms, 1_000);
        assert_eq!(p.view_change_max_timeout_ms, 60_000);
        assert_eq!(p.max_block_bytes, 2_097_152);
        assert_eq!(p.max_active_proposals, 128);
        assert_eq!(p.max_validator_set_size, 64);
        assert_eq!(p.max_validator_set_changes_per_block_param, 4);
        // v4 (Patch-05) defaults.
        assert_eq!(p.median_tension_window, 7);
        assert_eq!(p.fee_tension_alpha, crate::tension::TensionValue::SCALE / 2);
        assert_eq!(p.confirmation_depth, 2);
        assert_eq!(p.max_equivocation_evidence_per_block_param, 4);
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

    #[test]
    fn from_canonical_bytes_accepts_legacy_patch03_encoding() {
        let legacy = LegacyConsensusParamsV1 {
            max_proof_depth: 512,
            max_activated_symbols: 9,
            max_scan_per_symbol: 77,
            max_constraints_per_symbol: 12,
            default_max_steps: 333,
            default_tx_gas_limit: 444,
            default_block_gas_limit: 555,
            gas_tx_base: 11,
            gas_compute_step: 22,
            gas_state_read: 33,
            gas_state_write: 44,
            gas_sig_verify: 55,
            gas_hash_op: 66,
            gas_proof_byte: 77,
            gas_payload_byte: 88,
            max_symbol_address_len: 99,
            max_state_entry_size: 1234,
        };

        let bytes = bincode::serialize(&legacy).expect("legacy serialization must succeed");
        let parsed = ConsensusParams::from_canonical_bytes(&bytes)
            .expect("legacy consensus params must still deserialize");

        assert_eq!(parsed.max_proof_depth, 512);
        assert_eq!(parsed.max_constraint_propagation_depth, 32);
        assert_eq!(parsed.max_constraint_propagation_steps, 10_000);
        assert_eq!(parsed.max_activated_symbols, 9);
        assert_eq!(parsed.default_tx_gas_limit, 444);
        assert_eq!(parsed.max_state_entry_size, 1234);
        assert_eq!(parsed.max_tension_swing, 2_000_000);
    }

    #[test]
    fn default_passes_validation() {
        assert!(ConsensusParams::default().validate().is_ok());
    }

    #[test]
    fn zero_proof_depth_rejected() {
        let p = ConsensusParams {
            max_proof_depth: 0,
            ..Default::default()
        };
        assert!(p.validate().is_err());
    }

    #[test]
    fn extreme_proof_depth_rejected() {
        let p = ConsensusParams {
            max_proof_depth: 999_999,
            ..Default::default()
        };
        assert!(p.validate().is_err());
    }

    #[test]
    fn block_gas_below_tx_gas_rejected() {
        let p = ConsensusParams {
            default_block_gas_limit: 100,
            default_tx_gas_limit: 1_000,
            ..Default::default()
        };
        assert!(p.validate().is_err());
    }

    #[test]
    fn zero_state_entry_size_rejected() {
        let p = ConsensusParams {
            max_state_entry_size: 0,
            ..Default::default()
        };
        assert!(p.validate().is_err());
    }

    #[test]
    fn zero_gas_cost_rejected() {
        let p = ConsensusParams {
            gas_state_write: 0,
            ..Default::default()
        };
        assert!(p.validate().is_err());
    }

    #[test]
    fn excessive_symbol_address_len_rejected() {
        let p = ConsensusParams {
            max_symbol_address_len: 1_048_577,
            ..Default::default()
        };
        assert!(p.validate().is_err());
    }

    #[test]
    fn excessive_default_max_steps_rejected() {
        let p = ConsensusParams {
            default_max_steps: 10_000_001,
            ..Default::default()
        };
        assert!(p.validate().is_err());
    }

    // ── N-48 coverage: boundary values ───────────────────────────────

    #[test]
    fn block_gas_equal_to_tx_gas_accepted() {
        let p = ConsensusParams {
            default_block_gas_limit: 1_000,
            default_tx_gas_limit: 1_000,
            ..Default::default()
        };
        assert!(p.validate().is_ok());
    }

    #[test]
    fn zero_tension_swing_rejected() {
        let p = ConsensusParams {
            max_tension_swing: 0,
            ..Default::default()
        };
        assert!(p.validate().is_err());
    }

    #[test]
    fn negative_tension_swing_rejected() {
        let p = ConsensusParams {
            max_tension_swing: -1,
            ..Default::default()
        };
        assert!(p.validate().is_err());
    }

    #[test]
    fn excessive_tension_swing_rejected() {
        let p = ConsensusParams {
            max_tension_swing: 1_000_000_001,
            ..Default::default()
        };
        assert!(p.validate().is_err());
    }

    #[test]
    fn zero_constraint_propagation_depth_rejected() {
        let p = ConsensusParams {
            max_constraint_propagation_depth: 0,
            ..Default::default()
        };
        assert!(p.validate().is_err());
    }

    #[test]
    fn excessive_constraint_propagation_depth_rejected() {
        let p = ConsensusParams {
            max_constraint_propagation_depth: 1_001,
            ..Default::default()
        };
        assert!(p.validate().is_err());
    }

    #[test]
    fn zero_constraint_propagation_steps_rejected() {
        let p = ConsensusParams {
            max_constraint_propagation_steps: 0,
            ..Default::default()
        };
        assert!(p.validate().is_err());
    }

    // ── Patch-04 v3 field coverage ───────────────────────────────────

    #[test]
    fn patch_04_view_change_max_below_base_rejected() {
        let p = ConsensusParams {
            view_change_base_timeout_ms: 10_000,
            view_change_max_timeout_ms: 1_000,
            ..Default::default()
        };
        assert!(p.validate().is_err());
    }

    #[test]
    fn patch_04_zero_view_change_base_rejected() {
        let p = ConsensusParams {
            view_change_base_timeout_ms: 0,
            ..Default::default()
        };
        assert!(p.validate().is_err());
    }

    #[test]
    fn patch_04_tiny_max_block_bytes_rejected() {
        let p = ConsensusParams {
            max_block_bytes: 512,
            ..Default::default()
        };
        assert!(p.validate().is_err());
    }

    #[test]
    fn patch_04_zero_max_active_proposals_rejected() {
        let p = ConsensusParams {
            max_active_proposals: 0,
            ..Default::default()
        };
        assert!(p.validate().is_err());
    }

    #[test]
    fn patch_04_zero_max_validator_set_size_rejected() {
        let p = ConsensusParams {
            max_validator_set_size: 0,
            ..Default::default()
        };
        assert!(p.validate().is_err());
    }

    #[test]
    fn patch_04_legacy_v2_deserializes_with_v3_defaults() {
        // Simulate a v0.3.0 genesis consensus_params payload. V2 schema has
        // no v3 fields; fallback must inject defaults and yield a valid
        // v3 ConsensusParams.
        let v2 = LegacyConsensusParamsV2 {
            max_proof_depth: 256,
            max_constraint_propagation_depth: 32,
            max_constraint_propagation_steps: 10_000,
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
            max_tension_swing: 2_000_000,
        };
        let bytes = bincode::serialize(&v2).unwrap();
        let parsed = ConsensusParams::from_canonical_bytes(&bytes)
            .expect("V2 legacy bytes must decode into v3 ConsensusParams");
        let defaults = ConsensusParams::default();
        assert_eq!(
            parsed.view_change_base_timeout_ms,
            defaults.view_change_base_timeout_ms
        );
        assert_eq!(parsed.max_block_bytes, defaults.max_block_bytes);
        assert_eq!(parsed.max_active_proposals, defaults.max_active_proposals);
        assert_eq!(
            parsed.max_validator_set_size,
            defaults.max_validator_set_size
        );
    }

    #[test]
    fn patch_04_current_bytes_preserve_v3_fields() {
        // v3 encoding roundtrips without loss. Regression guard against a
        // fallback cascade silently truncating v3 fields.
        let p = ConsensusParams {
            view_change_base_timeout_ms: 2_500,
            max_active_proposals: 200,
            ..Default::default()
        };
        let bytes = p.to_canonical_bytes();
        let back = ConsensusParams::from_canonical_bytes(&bytes).unwrap();
        assert_eq!(back.view_change_base_timeout_ms, 2_500);
        assert_eq!(back.max_active_proposals, 200);
    }

    // ── Patch-05 v4 field coverage ───────────────────────────────────

    #[test]
    fn patch_05_even_median_window_rejected() {
        let p = ConsensusParams {
            median_tension_window: 8,
            ..Default::default()
        };
        let err = p.validate().expect_err("even window must reject");
        assert!(
            err.contains("odd"),
            "error should name the oddness rule: {}",
            err
        );
    }

    #[test]
    fn patch_05_zero_median_window_rejected() {
        let p = ConsensusParams {
            median_tension_window: 0,
            ..Default::default()
        };
        assert!(p.validate().is_err());
    }

    #[test]
    fn patch_05_odd_median_window_accepted() {
        for w in [1u32, 3, 5, 7, 9, 15, 31] {
            let p = ConsensusParams {
                median_tension_window: w,
                ..Default::default()
            };
            p.validate()
                .unwrap_or_else(|e| panic!("w={} rejected: {}", w, e));
        }
    }

    #[test]
    fn patch_05_negative_fee_alpha_rejected() {
        let p = ConsensusParams {
            fee_tension_alpha: -1,
            ..Default::default()
        };
        assert!(p.validate().is_err());
    }

    #[test]
    fn patch_05_zero_confirmation_depth_rejected() {
        let p = ConsensusParams {
            confirmation_depth: 0,
            ..Default::default()
        };
        assert!(p.validate().is_err());
    }

    #[test]
    fn patch_05_zero_equivocation_evidence_cap_rejected() {
        let p = ConsensusParams {
            max_equivocation_evidence_per_block_param: 0,
            ..Default::default()
        };
        assert!(p.validate().is_err());
    }

    #[test]
    fn patch_05_legacy_v3_deserializes_with_v4_defaults() {
        // v0.4.0 genesis consensus_params payload. V3 schema has no v4
        // fields; fallback must inject defaults.
        let v3 = LegacyConsensusParamsV3 {
            max_proof_depth: 256,
            max_constraint_propagation_depth: 32,
            max_constraint_propagation_steps: 10_000,
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
            max_tension_swing: 2_000_000,
            view_change_base_timeout_ms: 1_000,
            view_change_max_timeout_ms: 60_000,
            max_block_bytes: 2_097_152,
            max_active_proposals: 128,
            max_validator_set_size: 64,
            max_validator_set_changes_per_block_param: 4,
        };
        let bytes = bincode::serialize(&v3).unwrap();
        let parsed = ConsensusParams::from_canonical_bytes(&bytes)
            .expect("V3 legacy bytes must decode into v4 ConsensusParams");
        let defaults = ConsensusParams::default();
        // v4 fields come from defaults.
        assert_eq!(parsed.median_tension_window, defaults.median_tension_window);
        assert_eq!(parsed.fee_tension_alpha, defaults.fee_tension_alpha);
        assert_eq!(parsed.confirmation_depth, defaults.confirmation_depth);
        // v3 fields preserved.
        assert_eq!(parsed.max_validator_set_size, 64);
    }

    #[test]
    fn patch_05_current_bytes_preserve_v4_fields() {
        let p = ConsensusParams {
            median_tension_window: 11,
            fee_tension_alpha: crate::tension::TensionValue::SCALE / 4, // 0.25
            confirmation_depth: 6,
            max_equivocation_evidence_per_block_param: 12,
            ..Default::default()
        };
        let bytes = p.to_canonical_bytes();
        let back = ConsensusParams::from_canonical_bytes(&bytes).unwrap();
        assert_eq!(back.median_tension_window, 11);
        assert_eq!(
            back.fee_tension_alpha,
            crate::tension::TensionValue::SCALE / 4
        );
        assert_eq!(back.confirmation_depth, 6);
        assert_eq!(back.max_equivocation_evidence_per_block_param, 12);
    }
}
