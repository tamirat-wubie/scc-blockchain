//! Patch-04 v3 governance validators (§17.8 + §15.4 + §18.2 submission paths).
//!
//! This module is invoked at proposal submission time (not at timelock
//! expiry, not at activation). Three responsibilities:
//!
//! 1. §17.8 — reject any governance proposal that would modify
//!    `ConstitutionalCeilings` or that would push a `ConsensusParams`
//!    field above its ceiling. Submission-time rejection is mandatory
//!    because timelock-expiry rejection would let a known-invalid
//!    proposal occupy a queue slot for up to 200 blocks.
//!
//! 2. §15.4 — validate `ValidatorSetChange` submissions carry the
//!    precedence level required for their variant (Meaning for
//!    RotatePower, Safety for Remove+Governance reason, etc.).
//!
//! 3. §18.2 — structural checks on `KeyRotation` submissions before
//!    they reach the mempool (non-zero keys, distinct old/new keys,
//!    payload bytes consistent). Signature verification happens at
//!    admission (Commit 3 state-layer path) — this module is the
//!    submission-time gate, not the admission gate.

use sccgub_types::consensus_params::ConsensusParams;
use sccgub_types::constitutional_ceilings::{CeilingViolation, ConstitutionalCeilings};
use sccgub_types::governance::PrecedenceLevel;
use sccgub_types::key_rotation::KeyRotation;
use sccgub_types::typed_params::{
    apply_typed_param, ConsensusParamField, ConsensusParamValue, TypedParamApplyError,
};
use sccgub_types::validator_set::{ValidatorSetChange, ValidatorSetChangeKind};

// ── §17.8 ceiling enforcement ─────────────────────────────────────

/// Rejection reasons for proposals that touch ceiling-bound params.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ProposalCeilingRejection {
    /// Proposal attempts to raise a ceiling value directly. No governance
    /// path is permitted to raise ceilings (§17.8).
    #[error("proposal attempts to modify ConstitutionalCeilings field: {field}")]
    CeilingModification { field: String },
    /// Proposal would set a `ConsensusParams` field above its ceiling.
    #[error("proposed ConsensusParams violates ceiling: {0}")]
    CeilingViolation(#[from] CeilingViolation),
}

/// Validate a proposed `ConsensusParams` change at submission time.
///
/// Returns `Ok(())` if the change leaves every (param, ceiling) pair
/// in bounds. Called by governance submission before a `ModifyParameter`
/// proposal is entered into the proposal registry.
pub fn validate_consensus_params_proposal(
    proposed: &ConsensusParams,
    ceilings: &ConstitutionalCeilings,
) -> Result<(), ProposalCeilingRejection> {
    ceilings
        .validate(proposed)
        .map_err(ProposalCeilingRejection::from)
}

/// Reject any attempt to modify `ConstitutionalCeilings`. Returns an
/// error whose `field` names the first detected change — used to make
/// the rejection message actionable.
pub fn validate_ceilings_immutable(
    current: &ConstitutionalCeilings,
    proposed: &ConstitutionalCeilings,
) -> Result<(), ProposalCeilingRejection> {
    macro_rules! check_field {
        ($field:ident) => {
            if current.$field != proposed.$field {
                return Err(ProposalCeilingRejection::CeilingModification {
                    field: stringify!($field).to_string(),
                });
            }
        };
    }
    check_field!(max_proof_depth_ceiling);
    check_field!(max_tx_gas_ceiling);
    check_field!(max_block_gas_ceiling);
    check_field!(max_contract_steps_ceiling);
    check_field!(max_address_length_ceiling);
    check_field!(max_state_entry_size_ceiling);
    check_field!(max_tension_swing_ceiling);
    check_field!(max_block_bytes_ceiling);
    check_field!(max_active_proposals_ceiling);
    check_field!(max_view_change_base_timeout_ms);
    check_field!(max_view_change_max_timeout_ms);
    check_field!(max_validator_set_size_ceiling);
    check_field!(max_validator_set_changes_per_block);
    Ok(())
}

// ── §15.4 ValidatorSetChange submission ───────────────────────────

/// Rejection reasons for `ValidatorSetChange` submissions.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ValidatorSetChangeSubmissionRejection {
    #[error("submitter precedence {have:?} insufficient; {kind} requires at least {required:?}")]
    InsufficientPrecedence {
        have: PrecedenceLevel,
        required: PrecedenceLevel,
        kind: &'static str,
    },
    #[error("change_id does not match canonical hash of (kind, proposed_at)")]
    ChangeIdMismatch,
}

/// Minimum precedence required to submit each variant of
/// `ValidatorSetChange`. Per §15.4 discipline, membership changes are
/// safety-critical (Safety); RotatePower is a meaning-layer tuning
/// (Meaning); RotateKey accompanies a KeyRotation and inherits that
/// event's authorization (Meaning).
pub fn required_precedence_for_change(kind: &ValidatorSetChangeKind) -> PrecedenceLevel {
    match kind {
        ValidatorSetChangeKind::Add(_) | ValidatorSetChangeKind::Remove { .. } => {
            PrecedenceLevel::Safety
        }
        ValidatorSetChangeKind::RotatePower { .. } | ValidatorSetChangeKind::RotateKey { .. } => {
            PrecedenceLevel::Meaning
        }
    }
}

/// Validate a `ValidatorSetChange` submission. Structural predicates
/// only — quorum signatures and active-set membership are re-validated
/// at phase 12 (Commit 4) against the block-time active set.
pub fn validate_validator_set_change_submission(
    change: &ValidatorSetChange,
    submitter_level: PrecedenceLevel,
) -> Result<(), ValidatorSetChangeSubmissionRejection> {
    if !change.change_id_is_consistent() {
        return Err(ValidatorSetChangeSubmissionRejection::ChangeIdMismatch);
    }
    let required = required_precedence_for_change(&change.kind);
    if (submitter_level as u8) > (required as u8) {
        return Err(
            ValidatorSetChangeSubmissionRejection::InsufficientPrecedence {
                have: submitter_level,
                required,
                kind: match &change.kind {
                    ValidatorSetChangeKind::Add(_) => "Add",
                    ValidatorSetChangeKind::Remove { .. } => "Remove",
                    ValidatorSetChangeKind::RotatePower { .. } => "RotatePower",
                    ValidatorSetChangeKind::RotateKey { .. } => "RotateKey",
                },
            },
        );
    }
    Ok(())
}

// ── §18.2 KeyRotation submission ──────────────────────────────────

/// Rejection reasons for `KeyRotation` submissions.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum KeyRotationSubmissionRejection {
    #[error("old and new public keys are identical (no-op rotation)")]
    NoOp,
    #[error("public key is the zero vector; signing keys must be non-zero")]
    ZeroPublicKey,
    #[error("signature_by_old_key must be 64 bytes (Ed25519); got {len}")]
    OldSignatureLength { len: usize },
    #[error("signature_by_new_key must be 64 bytes (Ed25519); got {len}")]
    NewSignatureLength { len: usize },
}

// ── §25 typed ModifyConsensusParam submission ─────────────────────

/// Rejection reasons for a typed `ModifyConsensusParam` submission.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TypedParamProposalRejection {
    #[error("typed value does not match field type: {0}")]
    TypeMismatch(#[from] TypedParamApplyError),
    #[error(transparent)]
    CeilingViolation(#[from] CeilingViolation),
    #[error("activation_height {activation} < current_height {current} + 1")]
    ActivationInPast { activation: u64, current: u64 },
    /// PATCH_10 v0.8.4 addition: catches in-struct `ConsensusParams::validate()`
    /// bounds the ceiling check does not evaluate (e.g., `confirmation_depth == 0`,
    /// even `median_tension_window`, zero forgery-veto rate).
    #[error("proposed ConsensusParams fails in-struct validation: {0}")]
    ParamBounds(String),
    /// PATCH_10 v0.8.4 FRACTURE-V084-04 closure: `activation_height` too far
    /// in the future. Caps parking-attack surface where a Safety-level
    /// proposer submits `activation_height: u64::MAX` to leave a sleeper
    /// proposal that activates under unreviewable future state.
    #[error(
        "activation_height {activation} too far in future; max offset \
         {max_offset} blocks from current_height {current}"
    )]
    ActivationTooFarInFuture {
        activation: u64,
        current: u64,
        max_offset: u64,
    },
}

/// PATCH_10 v0.8.4 FRACTURE-V084-04 cap on `activation_height` offset.
///
/// A typed `ModifyConsensusParam` proposal's declared `activation_height`
/// must lie in `(current_height, current_height + MAX_ACTIVATION_HEIGHT_OFFSET]`.
/// Closes the parking-attack vector per DCA pre-merge audit
/// `docs/audits/2026-04-20-dca-pre-merge-v0.8.4-typed-modify-consensus-param.md`
/// §FRACTURE-V084-04.
///
/// Value: 10 × CONSTITUTIONAL timelock = 2000 blocks. Rationale:
/// 1. Admits the full constitutional timelock (200 blocks) with 9×
///    additional scheduling headroom — enough for legitimate operator
///    coordination across validators and clients.
/// 2. Caps the attacker's parking horizon to ~33 minutes at 1s blocks —
///    short enough that sleeper proposals are observable in normal
///    governance review cadence.
/// 3. Deterministic constant, no governance tunable (changing requires
///    a new protocol release; matches the "constitutional" register).
pub const MAX_ACTIVATION_HEIGHT_OFFSET: u64 = 10 * crate::proposals::timelocks::CONSTITUTIONAL;

/// Validate a typed `ModifyConsensusParam` proposal at submission time.
///
/// Steps per §25 + PATCH_10 v0.8.4 composition:
/// 1. `activation_height` must be strictly in the future (> current_height).
/// 2. Apply the `(field, new_value)` pair to the current chain
///    `ConsensusParams` to produce the hypothetical post-activation
///    params.
/// 3. Validate the hypothetical params against the chain's current
///    `ConstitutionalCeilings` via §17.4 (`ceilings.validate`).
/// 4. PATCH_10 v0.8.4: run `ConsensusParams::validate()` on the
///    hypothetical params to catch in-struct bounds (`confirmation_depth > 0`,
///    `median_tension_window` odd, `max_forgery_vetoes_per_block_param > 0`,
///    etc.) that a pair-only check misses.
///
/// Returns the hypothetical `ConsensusParams` on success — useful for the
/// caller to record alongside the proposal and re-validate at activation time
/// per §25.4 `INV-TYPED-PARAM-CEILING` (second half, applied in the state
/// crate when the timelock expires).
pub fn validate_typed_param_proposal(
    current: &ConsensusParams,
    ceilings: &ConstitutionalCeilings,
    field: ConsensusParamField,
    new_value: ConsensusParamValue,
    activation_height: u64,
    current_height: u64,
) -> Result<ConsensusParams, TypedParamProposalRejection> {
    if activation_height <= current_height {
        return Err(TypedParamProposalRejection::ActivationInPast {
            activation: activation_height,
            current: current_height,
        });
    }
    // FRACTURE-V084-04 cap: activation_height must be within a bounded
    // offset from current_height. Uses saturating_add so current_height
    // near u64::MAX does not wrap.
    let max_activation = current_height.saturating_add(MAX_ACTIVATION_HEIGHT_OFFSET);
    if activation_height > max_activation {
        return Err(TypedParamProposalRejection::ActivationTooFarInFuture {
            activation: activation_height,
            current: current_height,
            max_offset: MAX_ACTIVATION_HEIGHT_OFFSET,
        });
    }
    let hypothetical = apply_typed_param(current, field, new_value)?;
    ceilings.validate(&hypothetical)?;
    hypothetical
        .validate()
        .map_err(TypedParamProposalRejection::ParamBounds)?;
    Ok(hypothetical)
}

/// Structural submission-time validation for a `KeyRotation`.
/// Cryptographic verification of the two signatures happens at the
/// state-layer `apply_key_rotation` path (Commit 3) under `verify_strict`.
pub fn validate_key_rotation_submission(
    rotation: &KeyRotation,
) -> Result<(), KeyRotationSubmissionRejection> {
    if rotation.old_public_key == rotation.new_public_key {
        return Err(KeyRotationSubmissionRejection::NoOp);
    }
    if rotation.old_public_key == [0u8; 32] || rotation.new_public_key == [0u8; 32] {
        return Err(KeyRotationSubmissionRejection::ZeroPublicKey);
    }
    if rotation.signature_by_old_key.len() != 64 {
        return Err(KeyRotationSubmissionRejection::OldSignatureLength {
            len: rotation.signature_by_old_key.len(),
        });
    }
    if rotation.signature_by_new_key.len() != 64 {
        return Err(KeyRotationSubmissionRejection::NewSignatureLength {
            len: rotation.signature_by_new_key.len(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use sccgub_types::mfidel::MfidelAtomicSeal;
    use sccgub_types::validator_set::{
        RemovalReason, ValidatorRecord, ValidatorSetChange, ValidatorSetChangeKind,
    };

    fn make_change(kind: ValidatorSetChangeKind, proposed_at: u64) -> ValidatorSetChange {
        let change_id = ValidatorSetChange::compute_change_id(&kind, proposed_at);
        ValidatorSetChange {
            change_id,
            kind,
            proposed_at,
            quorum_signatures: vec![],
        }
    }

    fn sample_record() -> ValidatorRecord {
        ValidatorRecord {
            agent_id: [1; 32],
            validator_id: [2; 32],
            mfidel_seal: MfidelAtomicSeal::from_height(0),
            voting_power: 10,
            active_from: 0,
            active_until: None,
        }
    }

    // ── §17.8 ─────────────────────────────────────────────────────

    #[test]
    fn patch_04_governance_rejects_ceiling_raise() {
        let ceilings = ConstitutionalCeilings::default();
        let proposed = ConsensusParams {
            max_proof_depth: ceilings.max_proof_depth_ceiling + 1,
            ..Default::default()
        };
        let err = validate_consensus_params_proposal(&proposed, &ceilings);
        assert!(matches!(
            err,
            Err(ProposalCeilingRejection::CeilingViolation(
                CeilingViolation::MaxProofDepth { .. }
            ))
        ));
    }

    #[test]
    fn patch_04_governance_accepts_params_below_ceilings() {
        let ceilings = ConstitutionalCeilings::default();
        let proposed = ConsensusParams::default();
        validate_consensus_params_proposal(&proposed, &ceilings).unwrap();
    }

    #[test]
    fn patch_04_governance_rejects_direct_ceiling_modification() {
        let current = ConstitutionalCeilings::default();
        let proposed = ConstitutionalCeilings {
            max_proof_depth_ceiling: current.max_proof_depth_ceiling + 1,
            ..current.clone()
        };
        let err = validate_ceilings_immutable(&current, &proposed);
        assert!(matches!(
            err,
            Err(ProposalCeilingRejection::CeilingModification { field })
            if field == "max_proof_depth_ceiling"
        ));
    }

    #[test]
    fn patch_04_governance_accepts_unchanged_ceilings() {
        let c = ConstitutionalCeilings::default();
        validate_ceilings_immutable(&c, &c).unwrap();
    }

    // ── §15.4 ─────────────────────────────────────────────────────

    #[test]
    fn patch_04_validator_set_add_requires_safety() {
        assert_eq!(
            required_precedence_for_change(&ValidatorSetChangeKind::Add(sample_record())),
            PrecedenceLevel::Safety
        );
    }

    #[test]
    fn patch_04_validator_set_remove_requires_safety() {
        assert_eq!(
            required_precedence_for_change(&ValidatorSetChangeKind::Remove {
                agent_id: [1; 32],
                reason: RemovalReason::Governance,
                effective_height: 10,
            }),
            PrecedenceLevel::Safety
        );
    }

    #[test]
    fn patch_04_validator_set_rotate_power_requires_meaning() {
        assert_eq!(
            required_precedence_for_change(&ValidatorSetChangeKind::RotatePower {
                agent_id: [1; 32],
                new_voting_power: 20,
                effective_height: 10,
            }),
            PrecedenceLevel::Meaning
        );
    }

    #[test]
    fn patch_04_validator_set_change_rejects_insufficient_precedence() {
        let change = make_change(ValidatorSetChangeKind::Add(sample_record()), 5);
        let err = validate_validator_set_change_submission(
            &change,
            PrecedenceLevel::Optimization, // way below Safety
        );
        assert!(matches!(
            err,
            Err(ValidatorSetChangeSubmissionRejection::InsufficientPrecedence { .. })
        ));
    }

    #[test]
    fn patch_04_validator_set_change_accepts_safety_submitter() {
        let change = make_change(ValidatorSetChangeKind::Add(sample_record()), 5);
        validate_validator_set_change_submission(&change, PrecedenceLevel::Safety).unwrap();
    }

    #[test]
    fn patch_04_validator_set_change_rejects_tampered_change_id() {
        let kind = ValidatorSetChangeKind::RotatePower {
            agent_id: [1; 32],
            new_voting_power: 20,
            effective_height: 10,
        };
        let mut change = make_change(kind, 5);
        change.change_id = [0xFF; 32];
        let err = validate_validator_set_change_submission(&change, PrecedenceLevel::Safety);
        assert!(matches!(
            err,
            Err(ValidatorSetChangeSubmissionRejection::ChangeIdMismatch)
        ));
    }

    // ── §18.2 KeyRotation submission ──────────────────────────────

    fn make_rotation(old: [u8; 32], new: [u8; 32]) -> KeyRotation {
        KeyRotation {
            agent_id: [7; 32],
            old_public_key: old,
            new_public_key: new,
            rotation_height: 10,
            signature_by_old_key: vec![0xAA; 64],
            signature_by_new_key: vec![0xBB; 64],
        }
    }

    #[test]
    fn patch_04_key_rotation_submission_rejects_noop() {
        let r = make_rotation([1; 32], [1; 32]);
        assert!(matches!(
            validate_key_rotation_submission(&r),
            Err(KeyRotationSubmissionRejection::NoOp)
        ));
    }

    #[test]
    fn patch_04_key_rotation_submission_rejects_zero_key() {
        let r = make_rotation([0; 32], [1; 32]);
        assert!(matches!(
            validate_key_rotation_submission(&r),
            Err(KeyRotationSubmissionRejection::ZeroPublicKey)
        ));
    }

    #[test]
    fn patch_04_key_rotation_submission_rejects_short_old_sig() {
        let mut r = make_rotation([1; 32], [2; 32]);
        r.signature_by_old_key = vec![0xAA; 10];
        assert!(matches!(
            validate_key_rotation_submission(&r),
            Err(KeyRotationSubmissionRejection::OldSignatureLength { .. })
        ));
    }

    #[test]
    fn patch_04_key_rotation_submission_rejects_short_new_sig() {
        let mut r = make_rotation([1; 32], [2; 32]);
        r.signature_by_new_key = vec![0xBB; 10];
        assert!(matches!(
            validate_key_rotation_submission(&r),
            Err(KeyRotationSubmissionRejection::NewSignatureLength { .. })
        ));
    }

    #[test]
    fn patch_04_key_rotation_submission_happy_path() {
        let r = make_rotation([1; 32], [2; 32]);
        validate_key_rotation_submission(&r).unwrap();
    }

    // ── Patch-05 §25 typed ModifyConsensusParam tests ─────────────────

    #[test]
    fn patch_05_typed_param_accepts_within_ceiling() {
        let current = ConsensusParams::default();
        let ceilings = ConstitutionalCeilings::default();
        // Propose raising max_proof_depth to 300 (default 256, ceiling 512).
        validate_typed_param_proposal(
            &current,
            &ceilings,
            ConsensusParamField::MaxProofDepth,
            ConsensusParamValue::U32(300),
            100,
            50,
        )
        .unwrap();
    }

    #[test]
    fn patch_05_typed_param_rejects_ceiling_violation() {
        let current = ConsensusParams::default();
        let ceilings = ConstitutionalCeilings::default();
        // Propose max_proof_depth above ceiling (512) → ceiling rejection.
        let err = validate_typed_param_proposal(
            &current,
            &ceilings,
            ConsensusParamField::MaxProofDepth,
            ConsensusParamValue::U32(1000),
            100,
            50,
        );
        assert!(matches!(
            err,
            Err(TypedParamProposalRejection::CeilingViolation(
                CeilingViolation::MaxProofDepth { .. }
            ))
        ));
    }

    #[test]
    fn patch_05_typed_param_rejects_type_mismatch() {
        let current = ConsensusParams::default();
        let ceilings = ConstitutionalCeilings::default();
        // max_proof_depth is u32; supplying U64 must fail BEFORE ceiling check.
        let err = validate_typed_param_proposal(
            &current,
            &ceilings,
            ConsensusParamField::MaxProofDepth,
            ConsensusParamValue::U64(300),
            100,
            50,
        );
        assert!(matches!(
            err,
            Err(TypedParamProposalRejection::TypeMismatch(_))
        ));
    }

    #[test]
    fn patch_05_typed_param_rejects_past_activation_height() {
        let current = ConsensusParams::default();
        let ceilings = ConstitutionalCeilings::default();
        let err = validate_typed_param_proposal(
            &current,
            &ceilings,
            ConsensusParamField::MaxProofDepth,
            ConsensusParamValue::U32(300),
            50, // activation
            50, // current — equal, not strictly in future
        );
        assert!(matches!(
            err,
            Err(TypedParamProposalRejection::ActivationInPast { .. })
        ));
    }

    #[test]
    fn patch_05_typed_param_rejects_fee_alpha_over_ceiling() {
        // Economic capture attempt: propose α = 2.0 (ceiling is 1.0 · SCALE).
        let current = ConsensusParams::default();
        let ceilings = ConstitutionalCeilings::default();
        let err = validate_typed_param_proposal(
            &current,
            &ceilings,
            ConsensusParamField::FeeTensionAlpha,
            ConsensusParamValue::I128(2 * sccgub_types::tension::TensionValue::SCALE),
            1000,
            500,
        );
        assert!(matches!(
            err,
            Err(TypedParamProposalRejection::CeilingViolation(
                CeilingViolation::MaxFeeTensionAlpha { .. }
            ))
        ));
    }

    #[test]
    fn patch_05_typed_param_rejects_confirmation_depth_over_ceiling() {
        let current = ConsensusParams::default();
        let ceilings = ConstitutionalCeilings::default();
        let err = validate_typed_param_proposal(
            &current,
            &ceilings,
            ConsensusParamField::ConfirmationDepth,
            ConsensusParamValue::U64(100), // ceiling is 8
            1000,
            500,
        );
        assert!(matches!(
            err,
            Err(TypedParamProposalRejection::CeilingViolation(
                CeilingViolation::MaxConfirmationDepth { .. }
            ))
        ));
    }
}
