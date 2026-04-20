//! Constitutional ceilings (Patch-04 §17).
//!
//! Before Patch-04, any `ConsensusParams` value could be raised by a
//! Safety-level governance proposal. §17 introduces a parallel struct whose
//! values are bound at genesis and CANNOT be raised by any governance path.
//! This closes the recursive-governance expansion fracture (F3).
//!
//! Ceiling values in `Default` use the risk-profiled headroom table from
//! PATCH_04.md §17.2: safety-adjacent params get ×1–×2 headroom over their
//! `ConsensusParams` default; throughput/economic params get ×4–×16.
//!
//! Enforcement lives in `sccgub-execution` phase 10 (§17.4) and
//! `sccgub-governance` submission-time checks (§17.8).

use serde::{Deserialize, Serialize};

use crate::consensus_params::ConsensusParams;

/// Parallel struct to `ConsensusParams` declaring constitutional upper bounds
/// on every tunable parameter that could, if raised, drift the chain outside
/// its originally-safe regime.
///
/// Canonical bincode field order matches the declaration below. No field may
/// be added, removed, or reordered without a chain hard fork.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConstitutionalCeilings {
    // ── §11 CPoG bounds ───────────────────────────────────────────────
    pub max_proof_depth_ceiling: u32,

    // ── Gas bounds ────────────────────────────────────────────────────
    pub max_tx_gas_ceiling: u64,
    pub max_block_gas_ceiling: u64,

    // ── Contract execution ────────────────────────────────────────────
    pub max_contract_steps_ceiling: u64,

    // ── Address / state size ──────────────────────────────────────────
    pub max_address_length_ceiling: u32,
    pub max_state_entry_size_ceiling: u32,

    // ── Tension ───────────────────────────────────────────────────────
    pub max_tension_swing_ceiling: i64,

    // ── Block size ────────────────────────────────────────────────────
    pub max_block_bytes_ceiling: u32,

    // ── Governance queue ──────────────────────────────────────────────
    pub max_active_proposals_ceiling: u32,

    // ── View-change (§16) ─────────────────────────────────────────────
    pub max_view_change_base_timeout_ms: u32,
    pub max_view_change_max_timeout_ms: u32,

    // ── Validator set (§15) ───────────────────────────────────────────
    pub max_validator_set_size_ceiling: u32,
    pub max_validator_set_changes_per_block: u32,

    // ── v4 additions (Patch-05 §29) ───────────────────────────────────
    /// Upper bound on `fee_tension_alpha`. Default `SCALE` (= 1.0).
    /// Above unit, a single high-tension window can more than double the
    /// base fee — an economic capture vector even with median smoothing.
    pub max_fee_tension_alpha_ceiling: i128,
    /// Upper bound on `median_tension_window`. Default 64 blocks.
    /// Caps governance-driven stalling of the fee signal.
    pub max_median_tension_window_ceiling: u32,
    /// Upper bound on `confirmation_depth`. Default 8.
    /// Since §15.5 `activation_delay` scales with `k`, an arbitrarily
    /// large `confirmation_depth` would freeze validator-set changes.
    pub max_confirmation_depth_ceiling: u64,
    /// Upper bound on `max_equivocation_evidence_per_block_param`.
    /// Default 16. Caps slashing-admission DoS surface.
    pub max_equivocation_evidence_per_block: u32,

    // ── v5 additions (Patch-06 §31) ───────────────────────────────────
    /// Lower bound on the composed `effective_fee_median` output. After
    /// the median-over-window multiplier is applied, the returned fee is
    /// clamped to `max(computed, min_effective_fee_floor)`. Closes the
    /// fee-collapse attack where coordinated low-tension blocks drive
    /// the effective fee below a viable spam-resistance threshold.
    /// Default `TensionValue::SCALE / 100` (= 0.01 fee units).
    pub min_effective_fee_floor: i128,

    // ── PATCH_10 §39.4 additions ──────────────────────────────────────
    /// Upper bound on `max_forgery_vetoes_per_block` param. Default 8.
    /// Caps per-block admission of phase-12 `ForgeryVeto` records per
    /// PATCH_10 §39.4. Headroom ×2 over default param (4). Raising this
    /// ceiling is a governance operation bounded by §17.8-symmetric
    /// (PATCH_10 §38). The rate is a trade-off between veto-admission
    /// latency and mass-forgery-attack DoS surface; see PATCH_10 §39.4
    /// rationale and tracking issue #64.
    pub max_forgery_vetoes_per_block_ceiling: u32,
}

impl Default for ConstitutionalCeilings {
    /// Default v3 ceilings — PATCH_04.md §17.2 headroom-profiled values.
    /// Every pair `(param, ceiling)` satisfies `default_param_value <=
    /// ceiling_value` so a default-constructed v3 genesis is ceiling-valid.
    fn default() -> Self {
        Self {
            // Safety: ×2 over default (256)
            max_proof_depth_ceiling: 512,
            // Economic: ×16 over default (1M)
            max_tx_gas_ceiling: 16_000_000,
            // Economic: ×16 over default (50M)
            max_block_gas_ceiling: 800_000_000,
            // Decidability: ×4 over default (10K)
            max_contract_steps_ceiling: 40_000,
            // Pinned at default (4096) — no legitimate growth reason
            max_address_length_ceiling: 4_096,
            // Throughput: ×4 over default (1 MiB)
            max_state_entry_size_ceiling: 4_194_304,
            // Safety: ×2 over default (2M)
            max_tension_swing_ceiling: 4_000_000,
            // Network: ×4 over v3 default (2 MiB)
            max_block_bytes_ceiling: 8_388_608,
            // Governance DoS: ×2 over v3 default (128)
            max_active_proposals_ceiling: 256,
            // View-change: wide upper bounds for exotic-partition tolerance
            max_view_change_base_timeout_ms: 60_000,
            max_view_change_max_timeout_ms: 3_600_000,
            // Validator set: 128 cap (see PATCH_04 resolved decision #10)
            max_validator_set_size_ceiling: 128,
            // Up to 8 validator-set changes per block
            max_validator_set_changes_per_block: 8,
            // Patch-05 §29 v4 additions
            // Fee alpha: ×2 over default (0.5), capped at 1.0
            max_fee_tension_alpha_ceiling: crate::tension::TensionValue::SCALE,
            // Median window: ×~9 over default (7), capped at 64
            max_median_tension_window_ceiling: 64,
            // Confirmation depth: ×4 over default (2), capped at 8
            max_confirmation_depth_ceiling: 8,
            // Equivocation evidence per block: ×4 over default (4), capped at 16
            max_equivocation_evidence_per_block: 16,
            // Patch-06 §31: default floor 0.01 fee units. Small enough to
            // be a no-op on healthy chains (default base_fee = 1.0), large
            // enough to block a multi-block collapse to near-zero.
            min_effective_fee_floor: crate::tension::TensionValue::SCALE / 100,
            // PATCH_10 §39.4: default 8 (×2 over default param 4).
            max_forgery_vetoes_per_block_ceiling: 8,
        }
    }
}

/// Error type for ceiling violations. Reported back to callers that attempt
/// to propose `ConsensusParams` exceeding the active constitutional bound.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CeilingViolation {
    #[error("max_proof_depth {value} exceeds ceiling {ceiling}")]
    MaxProofDepth { value: u32, ceiling: u32 },
    #[error("default_tx_gas_limit {value} exceeds max_tx_gas_ceiling {ceiling}")]
    MaxTxGas { value: u64, ceiling: u64 },
    #[error("default_block_gas_limit {value} exceeds max_block_gas_ceiling {ceiling}")]
    MaxBlockGas { value: u64, ceiling: u64 },
    #[error("default_max_steps {value} exceeds max_contract_steps_ceiling {ceiling}")]
    MaxContractSteps { value: u64, ceiling: u64 },
    #[error("max_symbol_address_len {value} exceeds max_address_length_ceiling {ceiling}")]
    MaxAddressLength { value: u32, ceiling: u32 },
    #[error("max_state_entry_size {value} exceeds max_state_entry_size_ceiling {ceiling}")]
    MaxStateEntrySize { value: u32, ceiling: u32 },
    #[error("max_tension_swing {value} exceeds max_tension_swing_ceiling {ceiling}")]
    MaxTensionSwing { value: i64, ceiling: i64 },
    #[error("max_block_bytes {value} exceeds max_block_bytes_ceiling {ceiling}")]
    MaxBlockBytes { value: u32, ceiling: u32 },
    #[error("max_active_proposals {value} exceeds max_active_proposals_ceiling {ceiling}")]
    MaxActiveProposals { value: u32, ceiling: u32 },
    #[error("view_change_base_timeout_ms {value} exceeds ceiling {ceiling}")]
    ViewChangeBaseTimeout { value: u32, ceiling: u32 },
    #[error("view_change_max_timeout_ms {value} exceeds ceiling {ceiling}")]
    ViewChangeMaxTimeout { value: u32, ceiling: u32 },
    #[error("max_validator_set_size {value} exceeds max_validator_set_size_ceiling {ceiling}")]
    MaxValidatorSetSize { value: u32, ceiling: u32 },
    #[error(
        "max_validator_set_changes_per_block_param {value} exceeds \
         max_validator_set_changes_per_block {ceiling}"
    )]
    MaxValidatorSetChangesPerBlock { value: u32, ceiling: u32 },

    // ── v4 additions (Patch-05 §29) ───────────────────────────────────
    #[error("fee_tension_alpha {value} exceeds max_fee_tension_alpha_ceiling {ceiling}")]
    MaxFeeTensionAlpha { value: i128, ceiling: i128 },
    #[error("median_tension_window {value} exceeds max_median_tension_window_ceiling {ceiling}")]
    MaxMedianTensionWindow { value: u32, ceiling: u32 },
    #[error("confirmation_depth {value} exceeds max_confirmation_depth_ceiling {ceiling}")]
    MaxConfirmationDepth { value: u64, ceiling: u64 },
    #[error(
        "max_equivocation_evidence_per_block_param {value} exceeds \
         max_equivocation_evidence_per_block {ceiling}"
    )]
    MaxEquivocationEvidencePerBlock { value: u32, ceiling: u32 },

    // ── PATCH_10 §39.4 additions ──────────────────────────────────────
    #[error(
        "max_forgery_vetoes_per_block_param {value} exceeds \
         max_forgery_vetoes_per_block_ceiling {ceiling}"
    )]
    MaxForgeryVetoesPerBlock { value: u32, ceiling: u32 },
}

impl ConstitutionalCeilings {
    /// Canonical trie key: `system/constitutional_ceilings`.
    pub const TRIE_KEY: &'static [u8] = b"system/constitutional_ceilings";

    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        bincode::serialize(self).expect("ConstitutionalCeilings serialization is infallible")
    }

    /// Fallback cascade: current struct → `LegacyConstitutionalCeilingsV2`
    /// (pre-PATCH_10 schema) → `LegacyConstitutionalCeilingsV1` (pre-Patch-06
    /// schema). A successful legacy parse promotes to the current struct by
    /// filling newer fields with defaults. This lets a v3/v4 genesis (V1
    /// shape) and a v5-pre-PATCH_10 genesis (V2 shape) both continue to
    /// load under post-PATCH_10 code; the new forgery-veto-rate ceiling
    /// default (8) is a no-op for any chain where
    /// `max_forgery_vetoes_per_block_param <= 8`, which includes every
    /// chain using default `ConsensusParams` (param = 4).
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, String> {
        if let Ok(current) = bincode::deserialize::<ConstitutionalCeilings>(bytes) {
            return Ok(current);
        }
        if let Ok(v2) = bincode::deserialize::<LegacyConstitutionalCeilingsV2>(bytes) {
            return Ok(ConstitutionalCeilings::from(v2));
        }
        bincode::deserialize::<LegacyConstitutionalCeilingsV1>(bytes)
            .map(ConstitutionalCeilings::from)
            .map_err(|e| format!("ConstitutionalCeilings deserialize: {}", e))
    }

    /// Verify every §17.2 companion field of `params` is `<=` its ceiling.
    /// Returns the first violation encountered (in declaration order).
    ///
    /// Called at phase 10 against the active params (§17.4) and at
    /// governance submission time against the proposed params (§17.8).
    pub fn validate(&self, params: &ConsensusParams) -> Result<(), CeilingViolation> {
        if params.max_proof_depth > self.max_proof_depth_ceiling {
            return Err(CeilingViolation::MaxProofDepth {
                value: params.max_proof_depth,
                ceiling: self.max_proof_depth_ceiling,
            });
        }
        if params.default_tx_gas_limit > self.max_tx_gas_ceiling {
            return Err(CeilingViolation::MaxTxGas {
                value: params.default_tx_gas_limit,
                ceiling: self.max_tx_gas_ceiling,
            });
        }
        if params.default_block_gas_limit > self.max_block_gas_ceiling {
            return Err(CeilingViolation::MaxBlockGas {
                value: params.default_block_gas_limit,
                ceiling: self.max_block_gas_ceiling,
            });
        }
        if params.default_max_steps > self.max_contract_steps_ceiling {
            return Err(CeilingViolation::MaxContractSteps {
                value: params.default_max_steps,
                ceiling: self.max_contract_steps_ceiling,
            });
        }
        if params.max_symbol_address_len > self.max_address_length_ceiling {
            return Err(CeilingViolation::MaxAddressLength {
                value: params.max_symbol_address_len,
                ceiling: self.max_address_length_ceiling,
            });
        }
        if params.max_state_entry_size > self.max_state_entry_size_ceiling {
            return Err(CeilingViolation::MaxStateEntrySize {
                value: params.max_state_entry_size,
                ceiling: self.max_state_entry_size_ceiling,
            });
        }
        if params.max_tension_swing > self.max_tension_swing_ceiling {
            return Err(CeilingViolation::MaxTensionSwing {
                value: params.max_tension_swing,
                ceiling: self.max_tension_swing_ceiling,
            });
        }
        if params.max_block_bytes > self.max_block_bytes_ceiling {
            return Err(CeilingViolation::MaxBlockBytes {
                value: params.max_block_bytes,
                ceiling: self.max_block_bytes_ceiling,
            });
        }
        if params.max_active_proposals > self.max_active_proposals_ceiling {
            return Err(CeilingViolation::MaxActiveProposals {
                value: params.max_active_proposals,
                ceiling: self.max_active_proposals_ceiling,
            });
        }
        if params.view_change_base_timeout_ms > self.max_view_change_base_timeout_ms {
            return Err(CeilingViolation::ViewChangeBaseTimeout {
                value: params.view_change_base_timeout_ms,
                ceiling: self.max_view_change_base_timeout_ms,
            });
        }
        if params.view_change_max_timeout_ms > self.max_view_change_max_timeout_ms {
            return Err(CeilingViolation::ViewChangeMaxTimeout {
                value: params.view_change_max_timeout_ms,
                ceiling: self.max_view_change_max_timeout_ms,
            });
        }
        if params.max_validator_set_size > self.max_validator_set_size_ceiling {
            return Err(CeilingViolation::MaxValidatorSetSize {
                value: params.max_validator_set_size,
                ceiling: self.max_validator_set_size_ceiling,
            });
        }
        if params.max_validator_set_changes_per_block_param
            > self.max_validator_set_changes_per_block
        {
            return Err(CeilingViolation::MaxValidatorSetChangesPerBlock {
                value: params.max_validator_set_changes_per_block_param,
                ceiling: self.max_validator_set_changes_per_block,
            });
        }
        // v4 additions (Patch-05 §29).
        if params.fee_tension_alpha > self.max_fee_tension_alpha_ceiling {
            return Err(CeilingViolation::MaxFeeTensionAlpha {
                value: params.fee_tension_alpha,
                ceiling: self.max_fee_tension_alpha_ceiling,
            });
        }
        if params.median_tension_window > self.max_median_tension_window_ceiling {
            return Err(CeilingViolation::MaxMedianTensionWindow {
                value: params.median_tension_window,
                ceiling: self.max_median_tension_window_ceiling,
            });
        }
        if params.confirmation_depth > self.max_confirmation_depth_ceiling {
            return Err(CeilingViolation::MaxConfirmationDepth {
                value: params.confirmation_depth,
                ceiling: self.max_confirmation_depth_ceiling,
            });
        }
        if params.max_equivocation_evidence_per_block_param
            > self.max_equivocation_evidence_per_block
        {
            return Err(CeilingViolation::MaxEquivocationEvidencePerBlock {
                value: params.max_equivocation_evidence_per_block_param,
                ceiling: self.max_equivocation_evidence_per_block,
            });
        }
        // PATCH_10 §39.4: forgery-veto-per-block ceiling check.
        if params.max_forgery_vetoes_per_block_param > self.max_forgery_vetoes_per_block_ceiling {
            return Err(CeilingViolation::MaxForgeryVetoesPerBlock {
                value: params.max_forgery_vetoes_per_block_param,
                ceiling: self.max_forgery_vetoes_per_block_ceiling,
            });
        }
        Ok(())
    }
}

/// Pre-Patch-06 `ConstitutionalCeilings` layout. Retained verbatim so a v3/v4
/// genesis's serialized ceilings continue to deserialize under v5 code. New
/// fields are filled from `ConstitutionalCeilings::default()` in the `From`
/// conversion, so no chain sees a silent ceiling change on replay.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct LegacyConstitutionalCeilingsV1 {
    max_proof_depth_ceiling: u32,
    max_tx_gas_ceiling: u64,
    max_block_gas_ceiling: u64,
    max_contract_steps_ceiling: u64,
    max_address_length_ceiling: u32,
    max_state_entry_size_ceiling: u32,
    max_tension_swing_ceiling: i64,
    max_block_bytes_ceiling: u32,
    max_active_proposals_ceiling: u32,
    max_view_change_base_timeout_ms: u32,
    max_view_change_max_timeout_ms: u32,
    max_validator_set_size_ceiling: u32,
    max_validator_set_changes_per_block: u32,
    max_fee_tension_alpha_ceiling: i128,
    max_median_tension_window_ceiling: u32,
    max_confirmation_depth_ceiling: u64,
    max_equivocation_evidence_per_block: u32,
}

impl From<LegacyConstitutionalCeilingsV1> for ConstitutionalCeilings {
    fn from(v: LegacyConstitutionalCeilingsV1) -> Self {
        let defaults = ConstitutionalCeilings::default();
        Self {
            max_proof_depth_ceiling: v.max_proof_depth_ceiling,
            max_tx_gas_ceiling: v.max_tx_gas_ceiling,
            max_block_gas_ceiling: v.max_block_gas_ceiling,
            max_contract_steps_ceiling: v.max_contract_steps_ceiling,
            max_address_length_ceiling: v.max_address_length_ceiling,
            max_state_entry_size_ceiling: v.max_state_entry_size_ceiling,
            max_tension_swing_ceiling: v.max_tension_swing_ceiling,
            max_block_bytes_ceiling: v.max_block_bytes_ceiling,
            max_active_proposals_ceiling: v.max_active_proposals_ceiling,
            max_view_change_base_timeout_ms: v.max_view_change_base_timeout_ms,
            max_view_change_max_timeout_ms: v.max_view_change_max_timeout_ms,
            max_validator_set_size_ceiling: v.max_validator_set_size_ceiling,
            max_validator_set_changes_per_block: v.max_validator_set_changes_per_block,
            max_fee_tension_alpha_ceiling: v.max_fee_tension_alpha_ceiling,
            max_median_tension_window_ceiling: v.max_median_tension_window_ceiling,
            max_confirmation_depth_ceiling: v.max_confirmation_depth_ceiling,
            max_equivocation_evidence_per_block: v.max_equivocation_evidence_per_block,
            min_effective_fee_floor: defaults.min_effective_fee_floor,
            max_forgery_vetoes_per_block_ceiling: defaults.max_forgery_vetoes_per_block_ceiling,
        }
    }
}

/// Pre-PATCH_10 `ConstitutionalCeilings` layout (v5 schema with Patch-06
/// fee-floor but without PATCH_10 §39 forgery-veto-rate ceiling). Retained
/// so a v5 genesis serialized before PATCH_10 activation continues to
/// deserialize under post-PATCH_10 code. The new field is filled from
/// `ConstitutionalCeilings::default()`, identical discipline to V1.
///
/// `from_canonical_bytes` tries current → V2 → V1 in that order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct LegacyConstitutionalCeilingsV2 {
    max_proof_depth_ceiling: u32,
    max_tx_gas_ceiling: u64,
    max_block_gas_ceiling: u64,
    max_contract_steps_ceiling: u64,
    max_address_length_ceiling: u32,
    max_state_entry_size_ceiling: u32,
    max_tension_swing_ceiling: i64,
    max_block_bytes_ceiling: u32,
    max_active_proposals_ceiling: u32,
    max_view_change_base_timeout_ms: u32,
    max_view_change_max_timeout_ms: u32,
    max_validator_set_size_ceiling: u32,
    max_validator_set_changes_per_block: u32,
    max_fee_tension_alpha_ceiling: i128,
    max_median_tension_window_ceiling: u32,
    max_confirmation_depth_ceiling: u64,
    max_equivocation_evidence_per_block: u32,
    min_effective_fee_floor: i128,
}

impl From<LegacyConstitutionalCeilingsV2> for ConstitutionalCeilings {
    fn from(v: LegacyConstitutionalCeilingsV2) -> Self {
        let defaults = ConstitutionalCeilings::default();
        Self {
            max_proof_depth_ceiling: v.max_proof_depth_ceiling,
            max_tx_gas_ceiling: v.max_tx_gas_ceiling,
            max_block_gas_ceiling: v.max_block_gas_ceiling,
            max_contract_steps_ceiling: v.max_contract_steps_ceiling,
            max_address_length_ceiling: v.max_address_length_ceiling,
            max_state_entry_size_ceiling: v.max_state_entry_size_ceiling,
            max_tension_swing_ceiling: v.max_tension_swing_ceiling,
            max_block_bytes_ceiling: v.max_block_bytes_ceiling,
            max_active_proposals_ceiling: v.max_active_proposals_ceiling,
            max_view_change_base_timeout_ms: v.max_view_change_base_timeout_ms,
            max_view_change_max_timeout_ms: v.max_view_change_max_timeout_ms,
            max_validator_set_size_ceiling: v.max_validator_set_size_ceiling,
            max_validator_set_changes_per_block: v.max_validator_set_changes_per_block,
            max_fee_tension_alpha_ceiling: v.max_fee_tension_alpha_ceiling,
            max_median_tension_window_ceiling: v.max_median_tension_window_ceiling,
            max_confirmation_depth_ceiling: v.max_confirmation_depth_ceiling,
            max_equivocation_evidence_per_block: v.max_equivocation_evidence_per_block,
            min_effective_fee_floor: v.min_effective_fee_floor,
            max_forgery_vetoes_per_block_ceiling: defaults.max_forgery_vetoes_per_block_ceiling,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn patch_04_ceilings_canonical_bytes() {
        let c = ConstitutionalCeilings::default();
        let bytes = c.to_canonical_bytes();
        let back = ConstitutionalCeilings::from_canonical_bytes(&bytes).unwrap();
        assert_eq!(c, back);
    }

    #[test]
    fn patch_04_default_params_below_all_ceilings() {
        let ceilings = ConstitutionalCeilings::default();
        let params = ConsensusParams::default();
        ceilings
            .validate(&params)
            .expect("default ConsensusParams must satisfy default ConstitutionalCeilings");
    }

    #[test]
    fn patch_04_trie_key_in_system_namespace() {
        assert!(ConstitutionalCeilings::TRIE_KEY.starts_with(b"system/"));
    }

    #[test]
    fn patch_04_reject_proof_depth_over_ceiling() {
        let c = ConstitutionalCeilings::default();
        let p = ConsensusParams {
            max_proof_depth: c.max_proof_depth_ceiling + 1,
            ..Default::default()
        };
        assert!(matches!(
            c.validate(&p),
            Err(CeilingViolation::MaxProofDepth { .. })
        ));
    }

    #[test]
    fn patch_04_reject_tx_gas_over_ceiling() {
        let c = ConstitutionalCeilings::default();
        let tx_gas = c.max_tx_gas_ceiling + 1;
        // Must also bump block gas so we hit tx-gas check first in declaration order
        // (and so `default_block_gas_limit >= default_tx_gas_limit` sanity passes).
        let p = ConsensusParams {
            default_tx_gas_limit: tx_gas,
            default_block_gas_limit: tx_gas + 1,
            ..Default::default()
        };
        assert!(matches!(
            c.validate(&p),
            Err(CeilingViolation::MaxTxGas { .. })
        ));
    }

    #[test]
    fn patch_04_reject_block_gas_over_ceiling() {
        let c = ConstitutionalCeilings::default();
        let p = ConsensusParams {
            default_block_gas_limit: c.max_block_gas_ceiling + 1,
            ..Default::default()
        };
        assert!(matches!(
            c.validate(&p),
            Err(CeilingViolation::MaxBlockGas { .. })
        ));
    }

    #[test]
    fn patch_04_reject_contract_steps_over_ceiling() {
        let c = ConstitutionalCeilings::default();
        let p = ConsensusParams {
            default_max_steps: c.max_contract_steps_ceiling + 1,
            ..Default::default()
        };
        assert!(matches!(
            c.validate(&p),
            Err(CeilingViolation::MaxContractSteps { .. })
        ));
    }

    #[test]
    fn patch_04_reject_address_length_over_ceiling() {
        let c = ConstitutionalCeilings::default();
        let p = ConsensusParams {
            max_symbol_address_len: c.max_address_length_ceiling + 1,
            ..Default::default()
        };
        assert!(matches!(
            c.validate(&p),
            Err(CeilingViolation::MaxAddressLength { .. })
        ));
    }

    #[test]
    fn patch_04_reject_state_entry_size_over_ceiling() {
        let c = ConstitutionalCeilings::default();
        let p = ConsensusParams {
            max_state_entry_size: c.max_state_entry_size_ceiling + 1,
            ..Default::default()
        };
        assert!(matches!(
            c.validate(&p),
            Err(CeilingViolation::MaxStateEntrySize { .. })
        ));
    }

    #[test]
    fn patch_04_reject_tension_swing_over_ceiling() {
        let c = ConstitutionalCeilings::default();
        let p = ConsensusParams {
            max_tension_swing: c.max_tension_swing_ceiling + 1,
            ..Default::default()
        };
        assert!(matches!(
            c.validate(&p),
            Err(CeilingViolation::MaxTensionSwing { .. })
        ));
    }

    #[test]
    fn patch_04_reject_block_bytes_over_ceiling() {
        let c = ConstitutionalCeilings::default();
        let p = ConsensusParams {
            max_block_bytes: c.max_block_bytes_ceiling + 1,
            ..Default::default()
        };
        assert!(matches!(
            c.validate(&p),
            Err(CeilingViolation::MaxBlockBytes { .. })
        ));
    }

    #[test]
    fn patch_04_reject_active_proposals_over_ceiling() {
        let c = ConstitutionalCeilings::default();
        let p = ConsensusParams {
            max_active_proposals: c.max_active_proposals_ceiling + 1,
            ..Default::default()
        };
        assert!(matches!(
            c.validate(&p),
            Err(CeilingViolation::MaxActiveProposals { .. })
        ));
    }

    #[test]
    fn patch_04_reject_view_change_base_timeout_over_ceiling() {
        let c = ConstitutionalCeilings::default();
        let base = c.max_view_change_base_timeout_ms + 1;
        let defaults = ConsensusParams::default();
        // Ensure max >= base so the base-over-ceiling check triggers first.
        let p = ConsensusParams {
            view_change_base_timeout_ms: base,
            view_change_max_timeout_ms: base.max(defaults.view_change_max_timeout_ms),
            ..defaults
        };
        assert!(matches!(
            c.validate(&p),
            Err(CeilingViolation::ViewChangeBaseTimeout { .. })
        ));
    }

    #[test]
    fn patch_04_reject_view_change_max_timeout_over_ceiling() {
        let c = ConstitutionalCeilings::default();
        let p = ConsensusParams {
            view_change_max_timeout_ms: c.max_view_change_max_timeout_ms + 1,
            ..Default::default()
        };
        assert!(matches!(
            c.validate(&p),
            Err(CeilingViolation::ViewChangeMaxTimeout { .. })
        ));
    }

    #[test]
    fn patch_04_reject_validator_set_size_over_ceiling() {
        let c = ConstitutionalCeilings::default();
        let p = ConsensusParams {
            max_validator_set_size: c.max_validator_set_size_ceiling + 1,
            ..Default::default()
        };
        assert!(matches!(
            c.validate(&p),
            Err(CeilingViolation::MaxValidatorSetSize { .. })
        ));
    }

    #[test]
    fn patch_04_reject_validator_set_changes_over_ceiling() {
        let c = ConstitutionalCeilings::default();
        let p = ConsensusParams {
            max_validator_set_changes_per_block_param: c.max_validator_set_changes_per_block + 1,
            ..Default::default()
        };
        assert!(matches!(
            c.validate(&p),
            Err(CeilingViolation::MaxValidatorSetChangesPerBlock { .. })
        ));
    }

    // ── Patch-05 v4 ceiling coverage ─────────────────────────────────

    #[test]
    fn patch_05_default_params_below_all_v4_ceilings() {
        let ceilings = ConstitutionalCeilings::default();
        let params = ConsensusParams::default();
        ceilings
            .validate(&params)
            .expect("default ConsensusParams must satisfy default v4 ConstitutionalCeilings");
    }

    #[test]
    fn patch_05_reject_fee_alpha_over_ceiling() {
        let c = ConstitutionalCeilings::default();
        let p = ConsensusParams {
            fee_tension_alpha: c.max_fee_tension_alpha_ceiling + 1,
            ..Default::default()
        };
        assert!(matches!(
            c.validate(&p),
            Err(CeilingViolation::MaxFeeTensionAlpha { .. })
        ));
    }

    #[test]
    fn patch_05_reject_median_window_over_ceiling() {
        let c = ConstitutionalCeilings::default();
        // 65 is odd AND above the ceiling of 64. If 65 were above ceiling
        // BUT even, we'd hit the oddness check first in ConsensusParams::validate;
        // ceiling check runs in ConstitutionalCeilings::validate so this test
        // exercises only the ceiling path with an odd value above the cap.
        let over_ceiling = c.max_median_tension_window_ceiling + 1;
        // Ensure oddness to stay out of the oddness-error path.
        let window = if over_ceiling.is_multiple_of(2) {
            over_ceiling + 1
        } else {
            over_ceiling
        };
        let p = ConsensusParams {
            median_tension_window: window,
            ..Default::default()
        };
        assert!(matches!(
            c.validate(&p),
            Err(CeilingViolation::MaxMedianTensionWindow { .. })
        ));
    }

    #[test]
    fn patch_05_reject_confirmation_depth_over_ceiling() {
        let c = ConstitutionalCeilings::default();
        let p = ConsensusParams {
            confirmation_depth: c.max_confirmation_depth_ceiling + 1,
            ..Default::default()
        };
        assert!(matches!(
            c.validate(&p),
            Err(CeilingViolation::MaxConfirmationDepth { .. })
        ));
    }

    #[test]
    fn patch_05_reject_equivocation_evidence_per_block_over_ceiling() {
        let c = ConstitutionalCeilings::default();
        let p = ConsensusParams {
            max_equivocation_evidence_per_block_param: c.max_equivocation_evidence_per_block + 1,
            ..Default::default()
        };
        assert!(matches!(
            c.validate(&p),
            Err(CeilingViolation::MaxEquivocationEvidencePerBlock { .. })
        ));
    }

    // ── Patch-06 §31 floor ─────────────────────────────────────────────

    #[test]
    fn patch_06_default_floor_matches_spec_31_2() {
        let c = ConstitutionalCeilings::default();
        assert_eq!(
            c.min_effective_fee_floor,
            crate::tension::TensionValue::SCALE / 100
        );
    }

    #[test]
    fn patch_06_legacy_ceilings_roundtrip_with_default_floor() {
        // A pre-Patch-06 serialized ceiling (no min_effective_fee_floor field)
        // must deserialize under v5 code and receive the default floor, so
        // replay of a v3/v4 genesis does not break when the node is
        // upgraded.
        let legacy = LegacyConstitutionalCeilingsV1 {
            max_proof_depth_ceiling: 512,
            max_tx_gas_ceiling: 16_000_000,
            max_block_gas_ceiling: 800_000_000,
            max_contract_steps_ceiling: 40_000,
            max_address_length_ceiling: 4_096,
            max_state_entry_size_ceiling: 4_194_304,
            max_tension_swing_ceiling: 4_000_000,
            max_block_bytes_ceiling: 8_388_608,
            max_active_proposals_ceiling: 256,
            max_view_change_base_timeout_ms: 60_000,
            max_view_change_max_timeout_ms: 3_600_000,
            max_validator_set_size_ceiling: 128,
            max_validator_set_changes_per_block: 8,
            max_fee_tension_alpha_ceiling: crate::tension::TensionValue::SCALE,
            max_median_tension_window_ceiling: 64,
            max_confirmation_depth_ceiling: 8,
            max_equivocation_evidence_per_block: 16,
        };
        let bytes = bincode::serialize(&legacy).unwrap();
        let current = ConstitutionalCeilings::from_canonical_bytes(&bytes).unwrap();
        let defaults = ConstitutionalCeilings::default();
        assert_eq!(
            current.min_effective_fee_floor,
            defaults.min_effective_fee_floor
        );
        assert_eq!(current.max_proof_depth_ceiling, 512);
    }

    #[test]
    fn patch_06_current_ceilings_roundtrip_stable() {
        let c = ConstitutionalCeilings::default();
        let bytes = c.to_canonical_bytes();
        let back = ConstitutionalCeilings::from_canonical_bytes(&bytes).unwrap();
        assert_eq!(c, back);
    }

    #[test]
    fn patch_05_v4_ceiling_values_match_spec_29() {
        let c = ConstitutionalCeilings::default();
        assert_eq!(
            c.max_fee_tension_alpha_ceiling,
            crate::tension::TensionValue::SCALE
        );
        assert_eq!(c.max_median_tension_window_ceiling, 64);
        assert_eq!(c.max_confirmation_depth_ceiling, 8);
        assert_eq!(c.max_equivocation_evidence_per_block, 16);
    }

    #[test]
    fn patch_04_ceiling_values_match_spec_17_2() {
        // Regression guard: the spec table in PATCH_04.md §17.2 drives
        // these values. If they diverge, this test fires and the spec or
        // the code must be brought back into agreement.
        let c = ConstitutionalCeilings::default();
        assert_eq!(c.max_proof_depth_ceiling, 512);
        assert_eq!(c.max_tx_gas_ceiling, 16_000_000);
        assert_eq!(c.max_block_gas_ceiling, 800_000_000);
        assert_eq!(c.max_contract_steps_ceiling, 40_000);
        assert_eq!(c.max_address_length_ceiling, 4_096);
        assert_eq!(c.max_state_entry_size_ceiling, 4_194_304);
        assert_eq!(c.max_tension_swing_ceiling, 4_000_000);
        assert_eq!(c.max_block_bytes_ceiling, 8_388_608);
        assert_eq!(c.max_active_proposals_ceiling, 256);
        assert_eq!(c.max_view_change_base_timeout_ms, 60_000);
        assert_eq!(c.max_view_change_max_timeout_ms, 3_600_000);
        assert_eq!(c.max_validator_set_size_ceiling, 128);
        assert_eq!(c.max_validator_set_changes_per_block, 8);
    }
}
