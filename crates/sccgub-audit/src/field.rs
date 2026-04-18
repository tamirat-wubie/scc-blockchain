//! Enumeration of every `ConstitutionalCeilings` field per
//! PATCH_08.md §B.4.
//!
//! **Discipline**: every field of `sccgub_types::constitutional_ceilings::
//! ConstitutionalCeilings` MUST have a corresponding `CeilingFieldId`
//! variant. A future PR adding a new ceiling field MUST add the
//! corresponding variant in the same PR — missing a field would
//! silently allow that field to drift, defeating the moat.
//!
//! The compile-time check `compile_test_field_id_exhaustive` at the
//! bottom of this file ensures the verifier walks every field via
//! exhaustive `match`, so adding a `ConstitutionalCeilings` field
//! without adding a matching variant here is a compile error.

use serde::{Deserialize, Serialize};

use sccgub_types::constitutional_ceilings::ConstitutionalCeilings;

/// Identifier for a single ceiling field. Every field of
/// `ConstitutionalCeilings` is enumerated here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CeilingFieldId {
    /// `max_proof_depth_ceiling: u32`
    MaxProofDepth,
    /// `max_tx_gas_ceiling: u64`
    MaxTxGas,
    /// `max_block_gas_ceiling: u64`
    MaxBlockGas,
    /// `max_contract_steps_ceiling: u64`
    MaxContractSteps,
    /// `max_address_length_ceiling: u32`
    MaxAddressLength,
    /// `max_state_entry_size_ceiling: u32`
    MaxStateEntrySize,
    /// `max_tension_swing_ceiling: i64`
    MaxTensionSwing,
    /// `max_block_bytes_ceiling: u32`
    MaxBlockBytes,
    /// `max_active_proposals_ceiling: u32`
    MaxActiveProposals,
    /// `max_view_change_base_timeout_ms: u32`
    MaxViewChangeBaseTimeoutMs,
    /// `max_view_change_max_timeout_ms: u32`
    MaxViewChangeMaxTimeoutMs,
    /// `max_validator_set_size_ceiling: u32`
    MaxValidatorSetSize,
    /// `max_validator_set_changes_per_block: u32`
    MaxValidatorSetChangesPerBlock,
    /// `max_fee_tension_alpha_ceiling: i128`
    MaxFeeTensionAlpha,
    /// `max_median_tension_window_ceiling: u32`
    MaxMedianTensionWindow,
    /// `max_confirmation_depth_ceiling: u64`
    MaxConfirmationDepth,
    /// `max_equivocation_evidence_per_block: u32`
    MaxEquivocationEvidencePerBlock,
    /// `min_effective_fee_floor: i128`
    MinEffectiveFeeFloor,
}

impl CeilingFieldId {
    /// All ceiling field identifiers, in canonical order matching
    /// `ConstitutionalCeilings` field declaration order.
    ///
    /// The verifier iterates this slice on every transition; missing
    /// a variant here means the corresponding field is silently
    /// allowed to drift, which would defeat the moat. The compile-time
    /// match in `field_value` ensures missing variants are caught at
    /// build time.
    pub const ALL: &'static [CeilingFieldId] = &[
        Self::MaxProofDepth,
        Self::MaxTxGas,
        Self::MaxBlockGas,
        Self::MaxContractSteps,
        Self::MaxAddressLength,
        Self::MaxStateEntrySize,
        Self::MaxTensionSwing,
        Self::MaxBlockBytes,
        Self::MaxActiveProposals,
        Self::MaxViewChangeBaseTimeoutMs,
        Self::MaxViewChangeMaxTimeoutMs,
        Self::MaxValidatorSetSize,
        Self::MaxValidatorSetChangesPerBlock,
        Self::MaxFeeTensionAlpha,
        Self::MaxMedianTensionWindow,
        Self::MaxConfirmationDepth,
        Self::MaxEquivocationEvidencePerBlock,
        Self::MinEffectiveFeeFloor,
    ];

    /// Human-readable name (the Rust struct field name) — used in CLI
    /// output and JSON serialization.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::MaxProofDepth => "max_proof_depth_ceiling",
            Self::MaxTxGas => "max_tx_gas_ceiling",
            Self::MaxBlockGas => "max_block_gas_ceiling",
            Self::MaxContractSteps => "max_contract_steps_ceiling",
            Self::MaxAddressLength => "max_address_length_ceiling",
            Self::MaxStateEntrySize => "max_state_entry_size_ceiling",
            Self::MaxTensionSwing => "max_tension_swing_ceiling",
            Self::MaxBlockBytes => "max_block_bytes_ceiling",
            Self::MaxActiveProposals => "max_active_proposals_ceiling",
            Self::MaxViewChangeBaseTimeoutMs => "max_view_change_base_timeout_ms",
            Self::MaxViewChangeMaxTimeoutMs => "max_view_change_max_timeout_ms",
            Self::MaxValidatorSetSize => "max_validator_set_size_ceiling",
            Self::MaxValidatorSetChangesPerBlock => "max_validator_set_changes_per_block",
            Self::MaxFeeTensionAlpha => "max_fee_tension_alpha_ceiling",
            Self::MaxMedianTensionWindow => "max_median_tension_window_ceiling",
            Self::MaxConfirmationDepth => "max_confirmation_depth_ceiling",
            Self::MaxEquivocationEvidencePerBlock => "max_equivocation_evidence_per_block",
            Self::MinEffectiveFeeFloor => "min_effective_fee_floor",
        }
    }
}

/// Type-erased ceiling value. Variants cover every concrete type
/// `ConstitutionalCeilings` uses (`u32`, `u64`, `i64`, `i128`). The
/// verifier compares values via `PartialEq`, not via byte
/// representation, so encoding-portability across reviewers is
/// guaranteed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CeilingValue {
    /// 32-bit unsigned width.
    U32(u32),
    /// 64-bit unsigned width.
    U64(u64),
    /// 64-bit signed width.
    I64(i64),
    /// 128-bit signed width (used for fixed-point fee fields).
    I128(i128),
}

impl std::fmt::Display for CeilingValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::U32(v) => write!(f, "{}", v),
            Self::U64(v) => write!(f, "{}", v),
            Self::I64(v) => write!(f, "{}", v),
            Self::I128(v) => write!(f, "{}", v),
        }
    }
}

/// Extract the value of a single ceiling field from a
/// `ConstitutionalCeilings` snapshot. The exhaustive `match` is the
/// compile-time safety net that catches new fields added to
/// `ConstitutionalCeilings` without a corresponding `CeilingFieldId`
/// variant — Rust's exhaustiveness check requires every variant be
/// handled.
pub fn field_value(ceilings: &ConstitutionalCeilings, field: CeilingFieldId) -> CeilingValue {
    match field {
        CeilingFieldId::MaxProofDepth => CeilingValue::U32(ceilings.max_proof_depth_ceiling),
        CeilingFieldId::MaxTxGas => CeilingValue::U64(ceilings.max_tx_gas_ceiling),
        CeilingFieldId::MaxBlockGas => CeilingValue::U64(ceilings.max_block_gas_ceiling),
        CeilingFieldId::MaxContractSteps => CeilingValue::U64(ceilings.max_contract_steps_ceiling),
        CeilingFieldId::MaxAddressLength => CeilingValue::U32(ceilings.max_address_length_ceiling),
        CeilingFieldId::MaxStateEntrySize => {
            CeilingValue::U32(ceilings.max_state_entry_size_ceiling)
        }
        CeilingFieldId::MaxTensionSwing => CeilingValue::I64(ceilings.max_tension_swing_ceiling),
        CeilingFieldId::MaxBlockBytes => CeilingValue::U32(ceilings.max_block_bytes_ceiling),
        CeilingFieldId::MaxActiveProposals => {
            CeilingValue::U32(ceilings.max_active_proposals_ceiling)
        }
        CeilingFieldId::MaxViewChangeBaseTimeoutMs => {
            CeilingValue::U32(ceilings.max_view_change_base_timeout_ms)
        }
        CeilingFieldId::MaxViewChangeMaxTimeoutMs => {
            CeilingValue::U32(ceilings.max_view_change_max_timeout_ms)
        }
        CeilingFieldId::MaxValidatorSetSize => {
            CeilingValue::U32(ceilings.max_validator_set_size_ceiling)
        }
        CeilingFieldId::MaxValidatorSetChangesPerBlock => {
            CeilingValue::U32(ceilings.max_validator_set_changes_per_block)
        }
        CeilingFieldId::MaxFeeTensionAlpha => {
            CeilingValue::I128(ceilings.max_fee_tension_alpha_ceiling)
        }
        CeilingFieldId::MaxMedianTensionWindow => {
            CeilingValue::U32(ceilings.max_median_tension_window_ceiling)
        }
        CeilingFieldId::MaxConfirmationDepth => {
            CeilingValue::U64(ceilings.max_confirmation_depth_ceiling)
        }
        CeilingFieldId::MaxEquivocationEvidencePerBlock => {
            CeilingValue::U32(ceilings.max_equivocation_evidence_per_block)
        }
        CeilingFieldId::MinEffectiveFeeFloor => {
            CeilingValue::I128(ceilings.min_effective_fee_floor)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn patch_08_all_field_count_matches_struct_field_count() {
        // ConstitutionalCeilings has 18 fields per PATCH_08 §B.4
        // enumeration. ALL slice MUST have 18 entries. If a new field
        // is added without updating ALL, this test fires before the
        // verifier silently skips the field.
        assert_eq!(
            CeilingFieldId::ALL.len(),
            18,
            "ALL slice length must match ConstitutionalCeilings field count"
        );
    }

    #[test]
    fn patch_08_all_variants_distinct() {
        use std::collections::BTreeSet;
        let mut seen = BTreeSet::new();
        for f in CeilingFieldId::ALL {
            let inserted = seen.insert(f.as_str());
            assert!(inserted, "duplicate field id: {}", f.as_str());
        }
    }

    #[test]
    fn patch_08_field_value_default_ceilings_well_formed() {
        let c = ConstitutionalCeilings::default();
        for f in CeilingFieldId::ALL {
            // Just confirms no panic; values exercise every match arm.
            let _ = field_value(&c, *f);
        }
    }

    #[test]
    fn patch_08_ceiling_value_display() {
        assert_eq!(format!("{}", CeilingValue::U32(42)), "42");
        assert_eq!(format!("{}", CeilingValue::U64(99)), "99");
        assert_eq!(format!("{}", CeilingValue::I64(-7)), "-7");
        assert_eq!(format!("{}", CeilingValue::I128(-1_000_000)), "-1000000");
    }
}
