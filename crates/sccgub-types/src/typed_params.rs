//! Patch-05 §25 typed `ModifyConsensusParam` proposal payload.
//!
//! Before Patch-05, consensus-parameter proposals used
//! `ProposalKind::ModifyParameter { key: String, value: String }`, a
//! stringly-typed surface with no compile-time field enumeration. §25
//! introduces a typed variant (`field: ConsensusParamField`,
//! `new_value: ConsensusParamValue`) so:
//!
//! - the ceiling check in `sccgub-governance::patch_04` can run against
//!   a concrete `ConsensusParams` clone at submission time
//!   (INV-TYPED-PARAM-CEILING first half);
//! - the activation path applies the typed value atomically, not via
//!   string parsing that could misinterpret integer vs signed i128;
//! - the enum is closed: adding a new tunable field is a compiler-
//!   enforced migration.

use serde::{Deserialize, Serialize};

use crate::consensus_params::ConsensusParams;

/// Enumeration of all consensus-tunable fields that a governance
/// proposal MAY modify. Matches `ConsensusParams` struct fields
/// 1:1 for v4. New fields added in future chain versions get new
/// enum variants with explicit canonical-bincode positions.
///
/// Fields that are NOT consensus-tunable (e.g. the seal derivation,
/// the canonical bincode field order) intentionally do not appear.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConsensusParamField {
    // CPoG validation
    MaxProofDepth,

    // SCCE walker bounds
    MaxConstraintPropagationDepth,
    MaxConstraintPropagationSteps,
    MaxActivatedSymbols,
    MaxScanPerSymbol,
    MaxConstraintsPerSymbol,

    // Contract execution
    DefaultMaxSteps,

    // Gas limits
    DefaultTxGasLimit,
    DefaultBlockGasLimit,

    // Gas costs
    GasTxBase,
    GasComputeStep,
    GasStateRead,
    GasStateWrite,
    GasSigVerify,
    GasHashOp,
    GasProofByte,
    GasPayloadByte,

    // Size caps
    MaxSymbolAddressLen,
    MaxStateEntrySize,
    MaxTensionSwing,

    // v3 (Patch-04) additions
    ViewChangeBaseTimeoutMs,
    ViewChangeMaxTimeoutMs,
    MaxBlockBytes,
    MaxActiveProposals,
    MaxValidatorSetSize,
    MaxValidatorSetChangesPerBlockParam,

    // v4 (Patch-05) additions
    MedianTensionWindow,
    FeeTensionAlpha,
    ConfirmationDepth,
    MaxEquivocationEvidencePerBlockParam,

    // PATCH_10 §39.4 addition
    MaxForgeryVetoesPerBlockParam,
}

/// Typed value for a `ModifyConsensusParam` proposal. Each variant
/// corresponds to the raw type of one or more `ConsensusParams`
/// fields; the apply path rejects mismatches (e.g., `U32` supplied
/// for a `u64` field).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConsensusParamValue {
    U32(u32),
    U64(u64),
    I64(i64),
    I128(i128),
}

/// Error returned when a `(field, new_value)` pair cannot be applied.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TypedParamApplyError {
    /// The `new_value` variant does not match the field's primitive
    /// type. E.g., `U32` supplied for `default_tx_gas_limit: u64`.
    #[error("type mismatch: field {field:?} is {expected} but value is {actual}")]
    TypeMismatch {
        field: ConsensusParamField,
        expected: &'static str,
        actual: &'static str,
    },
}

impl ConsensusParamValue {
    fn type_name(&self) -> &'static str {
        match self {
            Self::U32(_) => "u32",
            Self::U64(_) => "u64",
            Self::I64(_) => "i64",
            Self::I128(_) => "i128",
        }
    }
}

/// Clone `base` and overwrite the specified field with `new_value`.
/// Called at submission time to compute the hypothetical params that
/// would exist if the proposal activated; the result is passed to
/// `validate_consensus_params_proposal` for ceiling validation.
pub fn apply_typed_param(
    base: &ConsensusParams,
    field: ConsensusParamField,
    new_value: ConsensusParamValue,
) -> Result<ConsensusParams, TypedParamApplyError> {
    let mut out = base.clone();
    macro_rules! expect_u32 {
        ($variant:ident, $assign:expr) => {
            match new_value {
                ConsensusParamValue::U32(v) => {
                    $assign = v;
                }
                other => {
                    return Err(TypedParamApplyError::TypeMismatch {
                        field,
                        expected: "u32",
                        actual: other.type_name(),
                    })
                }
            }
        };
    }
    macro_rules! expect_u64 {
        ($variant:ident, $assign:expr) => {
            match new_value {
                ConsensusParamValue::U64(v) => {
                    $assign = v;
                }
                other => {
                    return Err(TypedParamApplyError::TypeMismatch {
                        field,
                        expected: "u64",
                        actual: other.type_name(),
                    })
                }
            }
        };
    }
    macro_rules! expect_i64 {
        ($variant:ident, $assign:expr) => {
            match new_value {
                ConsensusParamValue::I64(v) => {
                    $assign = v;
                }
                other => {
                    return Err(TypedParamApplyError::TypeMismatch {
                        field,
                        expected: "i64",
                        actual: other.type_name(),
                    })
                }
            }
        };
    }
    macro_rules! expect_i128 {
        ($variant:ident, $assign:expr) => {
            match new_value {
                ConsensusParamValue::I128(v) => {
                    $assign = v;
                }
                other => {
                    return Err(TypedParamApplyError::TypeMismatch {
                        field,
                        expected: "i128",
                        actual: other.type_name(),
                    })
                }
            }
        };
    }

    match field {
        ConsensusParamField::MaxProofDepth => expect_u32!(U32, out.max_proof_depth),
        ConsensusParamField::MaxConstraintPropagationDepth => {
            expect_u32!(U32, out.max_constraint_propagation_depth)
        }
        ConsensusParamField::MaxConstraintPropagationSteps => {
            expect_u64!(U64, out.max_constraint_propagation_steps)
        }
        ConsensusParamField::MaxActivatedSymbols => expect_u32!(U32, out.max_activated_symbols),
        ConsensusParamField::MaxScanPerSymbol => expect_u64!(U64, out.max_scan_per_symbol),
        ConsensusParamField::MaxConstraintsPerSymbol => {
            expect_u64!(U64, out.max_constraints_per_symbol)
        }
        ConsensusParamField::DefaultMaxSteps => expect_u64!(U64, out.default_max_steps),
        ConsensusParamField::DefaultTxGasLimit => expect_u64!(U64, out.default_tx_gas_limit),
        ConsensusParamField::DefaultBlockGasLimit => expect_u64!(U64, out.default_block_gas_limit),
        ConsensusParamField::GasTxBase => expect_u64!(U64, out.gas_tx_base),
        ConsensusParamField::GasComputeStep => expect_u64!(U64, out.gas_compute_step),
        ConsensusParamField::GasStateRead => expect_u64!(U64, out.gas_state_read),
        ConsensusParamField::GasStateWrite => expect_u64!(U64, out.gas_state_write),
        ConsensusParamField::GasSigVerify => expect_u64!(U64, out.gas_sig_verify),
        ConsensusParamField::GasHashOp => expect_u64!(U64, out.gas_hash_op),
        ConsensusParamField::GasProofByte => expect_u64!(U64, out.gas_proof_byte),
        ConsensusParamField::GasPayloadByte => expect_u64!(U64, out.gas_payload_byte),
        ConsensusParamField::MaxSymbolAddressLen => expect_u32!(U32, out.max_symbol_address_len),
        ConsensusParamField::MaxStateEntrySize => expect_u32!(U32, out.max_state_entry_size),
        ConsensusParamField::MaxTensionSwing => expect_i64!(I64, out.max_tension_swing),
        ConsensusParamField::ViewChangeBaseTimeoutMs => {
            expect_u32!(U32, out.view_change_base_timeout_ms)
        }
        ConsensusParamField::ViewChangeMaxTimeoutMs => {
            expect_u32!(U32, out.view_change_max_timeout_ms)
        }
        ConsensusParamField::MaxBlockBytes => expect_u32!(U32, out.max_block_bytes),
        ConsensusParamField::MaxActiveProposals => expect_u32!(U32, out.max_active_proposals),
        ConsensusParamField::MaxValidatorSetSize => expect_u32!(U32, out.max_validator_set_size),
        ConsensusParamField::MaxValidatorSetChangesPerBlockParam => {
            expect_u32!(U32, out.max_validator_set_changes_per_block_param)
        }
        ConsensusParamField::MedianTensionWindow => {
            expect_u32!(U32, out.median_tension_window)
        }
        ConsensusParamField::FeeTensionAlpha => expect_i128!(I128, out.fee_tension_alpha),
        ConsensusParamField::ConfirmationDepth => expect_u64!(U64, out.confirmation_depth),
        ConsensusParamField::MaxEquivocationEvidencePerBlockParam => {
            expect_u32!(U32, out.max_equivocation_evidence_per_block_param)
        }
        ConsensusParamField::MaxForgeryVetoesPerBlockParam => {
            expect_u32!(U32, out.max_forgery_vetoes_per_block_param)
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn patch_05_typed_apply_max_proof_depth_u32() {
        let base = ConsensusParams::default();
        let out = apply_typed_param(
            &base,
            ConsensusParamField::MaxProofDepth,
            ConsensusParamValue::U32(256),
        )
        .unwrap();
        assert_eq!(out.max_proof_depth, 256);
    }

    #[test]
    fn patch_05_typed_apply_fee_alpha_i128() {
        let base = ConsensusParams::default();
        let out = apply_typed_param(
            &base,
            ConsensusParamField::FeeTensionAlpha,
            ConsensusParamValue::I128(crate::tension::TensionValue::SCALE / 4),
        )
        .unwrap();
        assert_eq!(
            out.fee_tension_alpha,
            crate::tension::TensionValue::SCALE / 4
        );
    }

    #[test]
    fn patch_05_typed_apply_confirmation_depth_u64() {
        let base = ConsensusParams::default();
        let out = apply_typed_param(
            &base,
            ConsensusParamField::ConfirmationDepth,
            ConsensusParamValue::U64(5),
        )
        .unwrap();
        assert_eq!(out.confirmation_depth, 5);
    }

    #[test]
    fn patch_05_typed_apply_preserves_other_fields() {
        // Applying one field must not perturb any other — the returned
        // ConsensusParams is a clone-and-replace, not a zero-init.
        let base = ConsensusParams {
            max_proof_depth: 777,
            default_tx_gas_limit: 999_999,
            confirmation_depth: 4,
            ..ConsensusParams::default()
        };
        let out = apply_typed_param(
            &base,
            ConsensusParamField::MaxBlockBytes,
            ConsensusParamValue::U32(3_000_000),
        )
        .unwrap();
        assert_eq!(out.max_block_bytes, 3_000_000);
        assert_eq!(out.max_proof_depth, 777);
        assert_eq!(out.default_tx_gas_limit, 999_999);
        assert_eq!(out.confirmation_depth, 4);
    }

    #[test]
    fn patch_05_typed_apply_u32_for_u64_field_rejected() {
        let base = ConsensusParams::default();
        let err = apply_typed_param(
            &base,
            ConsensusParamField::DefaultTxGasLimit,
            ConsensusParamValue::U32(100),
        );
        assert!(matches!(
            err,
            Err(TypedParamApplyError::TypeMismatch {
                expected: "u64",
                actual: "u32",
                ..
            })
        ));
    }

    #[test]
    fn patch_05_typed_apply_u64_for_u32_field_rejected() {
        let base = ConsensusParams::default();
        let err = apply_typed_param(
            &base,
            ConsensusParamField::MaxProofDepth,
            ConsensusParamValue::U64(100),
        );
        assert!(matches!(
            err,
            Err(TypedParamApplyError::TypeMismatch {
                expected: "u32",
                actual: "u64",
                ..
            })
        ));
    }

    #[test]
    fn patch_05_typed_apply_i64_for_i128_field_rejected() {
        let base = ConsensusParams::default();
        let err = apply_typed_param(
            &base,
            ConsensusParamField::FeeTensionAlpha,
            ConsensusParamValue::I64(100),
        );
        assert!(matches!(
            err,
            Err(TypedParamApplyError::TypeMismatch {
                expected: "i128",
                actual: "i64",
                ..
            })
        ));
    }

    #[test]
    fn patch_05_typed_apply_i128_for_i64_field_rejected() {
        let base = ConsensusParams::default();
        let err = apply_typed_param(
            &base,
            ConsensusParamField::MaxTensionSwing,
            ConsensusParamValue::I128(100),
        );
        assert!(matches!(
            err,
            Err(TypedParamApplyError::TypeMismatch {
                expected: "i64",
                actual: "i128",
                ..
            })
        ));
    }

    #[test]
    fn patch_05_typed_apply_canonical_bytes_roundtrip() {
        // Both ConsensusParamField and ConsensusParamValue must
        // canonical-bincode round-trip (they are stored on-chain as
        // part of ProposalKind::ModifyConsensusParam).
        let field = ConsensusParamField::FeeTensionAlpha;
        let value = ConsensusParamValue::I128(42);
        let field_bytes = bincode::serialize(&field).unwrap();
        let value_bytes = bincode::serialize(&value).unwrap();
        let field_back: ConsensusParamField = bincode::deserialize(&field_bytes).unwrap();
        let value_back: ConsensusParamValue = bincode::deserialize(&value_bytes).unwrap();
        assert_eq!(field, field_back);
        assert_eq!(value, value_back);
    }

    #[test]
    fn patch_05_typed_apply_every_field_u32_variants() {
        // Sanity: every u32 field accepts a U32 value.
        let base = ConsensusParams::default();
        for f in [
            ConsensusParamField::MaxProofDepth,
            ConsensusParamField::MaxConstraintPropagationDepth,
            ConsensusParamField::MaxActivatedSymbols,
            ConsensusParamField::MaxSymbolAddressLen,
            ConsensusParamField::MaxStateEntrySize,
            ConsensusParamField::ViewChangeBaseTimeoutMs,
            ConsensusParamField::ViewChangeMaxTimeoutMs,
            ConsensusParamField::MaxBlockBytes,
            ConsensusParamField::MaxActiveProposals,
            ConsensusParamField::MaxValidatorSetSize,
            ConsensusParamField::MaxValidatorSetChangesPerBlockParam,
            ConsensusParamField::MedianTensionWindow,
            ConsensusParamField::MaxEquivocationEvidencePerBlockParam,
            ConsensusParamField::MaxForgeryVetoesPerBlockParam,
        ] {
            // Accept a safe mid-range u32 to avoid secondary validate() bounds.
            apply_typed_param(&base, f, ConsensusParamValue::U32(7))
                .unwrap_or_else(|e| panic!("field {:?} rejected U32(7): {}", f, e));
        }
    }

    /// PATCH_10 §39.4 + DCA pre-merge FRACTURE-V083-01 closure:
    /// the new `max_forgery_vetoes_per_block_param` field has a typed-
    /// governance variant and the apply path writes through correctly.
    #[test]
    fn patch_10_typed_apply_max_forgery_vetoes_per_block_param() {
        let base = ConsensusParams::default();
        let out = apply_typed_param(
            &base,
            ConsensusParamField::MaxForgeryVetoesPerBlockParam,
            ConsensusParamValue::U32(6),
        )
        .expect("U32(6) must apply to max_forgery_vetoes_per_block_param");
        assert_eq!(out.max_forgery_vetoes_per_block_param, 6);
    }

    /// PATCH_10 §39.4 + DCA pre-merge FRACTURE-V083-01 closure:
    /// type mismatch on the new field is rejected, matching sibling
    /// u32-typed fields' behavior.
    #[test]
    fn patch_10_typed_apply_max_forgery_vetoes_rejects_u64() {
        let base = ConsensusParams::default();
        let result = apply_typed_param(
            &base,
            ConsensusParamField::MaxForgeryVetoesPerBlockParam,
            ConsensusParamValue::U64(6),
        );
        assert!(matches!(
            result,
            Err(TypedParamApplyError::TypeMismatch {
                field: ConsensusParamField::MaxForgeryVetoesPerBlockParam,
                expected: "u32",
                actual: "u64",
            })
        ));
    }
}
