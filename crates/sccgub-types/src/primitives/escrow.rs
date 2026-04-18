//! Patch-07 §D.2 EscrowCommitment primitive — INV-ESCROW-DECIDABILITY.
//!
//! The refined thesis specified an `Escrow` primitive whose release
//! condition is an adapter-defined predicate: `condition: ConditionExpr`.
//! The Part-2 audit flagged this as undecidable by construction — an
//! adapter can supply a predicate that does not terminate or whose
//! evaluation walks unbounded history.
//!
//! This module commits to a **decidability-bounded** variant. Every
//! escrow declares the maximum predicate evaluation effort up-front
//! (steps + state reads). The kernel rejects escrows whose declared
//! bound exceeds a global ceiling, and adapter runtimes are required
//! to terminate predicate evaluation at the declared bound.
//!
//! This does not fully implement predicate evaluation (which requires
//! an adapter runtime). It declares the contract: every escrow is a
//! budget-bounded commitment, and the budget is fixed at creation.

use serde::{Deserialize, Serialize};

use crate::{AgentId, Hash};

/// Global ceiling on per-escrow predicate steps. An escrow declaring
/// more than this is structurally invalid.
///
/// Justification: at 10⁴ active escrows × 10⁴ steps = 10⁸ step-ops
/// per block if every escrow's predicate fires. The block-gas budget
/// cannot absorb more without dedicating the entire block to escrow
/// evaluation.
pub const MAX_ESCROW_PREDICATE_STEPS: u32 = 10_000;

/// Global ceiling on per-escrow state-read count within one
/// predicate evaluation. Caps I/O cost independently of compute.
pub const MAX_ESCROW_PREDICATE_READS: u32 = 256;

/// Minimum timeout (in blocks) from creation to auto-refund. An escrow
/// with a near-term timeout is effectively not-an-escrow; this floor
/// prevents degenerate bypass patterns.
pub const MIN_ESCROW_TIMEOUT_BLOCKS: u64 = 2;

/// Maximum timeout (in blocks). Equivalent to ~30 years at 2-minute
/// blocks; longer is a lockup vector, not an escrow.
pub const MAX_ESCROW_TIMEOUT_BLOCKS: u64 = 8_000_000;

/// Domain separator for escrow canonical hash. Must not collide.
pub const ESCROW_DOMAIN_SEPARATOR: &[u8] = b"sccgub-escrow-commitment-v7";

/// Decidability bounds declared at escrow creation. The runtime MUST
/// refuse to evaluate any predicate that would exceed these bounds.
///
/// Canonical bincode field order: `max_steps, max_reads`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct EscrowPredicateBounds {
    pub max_steps: u32,
    pub max_reads: u32,
}

impl Default for EscrowPredicateBounds {
    fn default() -> Self {
        Self {
            max_steps: 1_000,
            max_reads: 32,
        }
    }
}

/// The thing an escrow holds until the predicate is satisfied or
/// timeout fires. Types are distinguished for canonical hashing; each
/// variant's payload is domain-interpreted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EscrowPayload {
    /// Value commitment — holds `amount` units of `asset` until release.
    Value { asset: Hash, amount: i128 },
    /// Message commitment — holds a message (referenced by its id)
    /// until release; useful for conditional delivery.
    MessageRef { message_id: Hash },
    /// Action commitment — holds a deferred action (referenced by an
    /// action manifest hash) until release.
    ActionRef { action_manifest: Hash },
}

/// Patch-07 §D.2 escrow commitment.
///
/// Canonical bincode field order: `escrow_id, payload, predicate_hash,
/// bounds, timeout_height, beneficiary_on_success,
/// beneficiary_on_timeout, creator, creation_height`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EscrowCommitment {
    pub escrow_id: Hash,
    pub payload: EscrowPayload,
    /// Hash of the predicate source/bytecode. Runtime looks up the
    /// predicate by this hash in an adapter-scoped registry.
    pub predicate_hash: Hash,
    pub bounds: EscrowPredicateBounds,
    pub timeout_height: u64,
    pub beneficiary_on_success: AgentId,
    pub beneficiary_on_timeout: AgentId,
    pub creator: AgentId,
    pub creation_height: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EscrowValidationError {
    #[error("predicate step budget {value} exceeds ceiling {ceiling}")]
    StepsOverCeiling { value: u32, ceiling: u32 },
    #[error("predicate read budget {value} exceeds ceiling {ceiling}")]
    ReadsOverCeiling { value: u32, ceiling: u32 },
    #[error(
        "timeout height {timeout} not in valid range \
         [creation+{min}, creation+{max}]"
    )]
    TimeoutOutOfRange {
        timeout: u64,
        creation_height: u64,
        min: u64,
        max: u64,
    },
    #[error("escrow_id inconsistent with canonical payload")]
    IdInconsistent,
    #[error("escrow amount must be positive; got {0}")]
    NonPositiveAmount(i128),
}

impl EscrowCommitment {
    /// Canonical bytes folded into `escrow_id`. Excludes `escrow_id`
    /// itself.
    pub fn canonical_escrow_bytes(&self) -> Vec<u8> {
        bincode::serialize(&(
            &self.payload,
            &self.predicate_hash,
            &self.bounds,
            self.timeout_height,
            &self.beneficiary_on_success,
            &self.beneficiary_on_timeout,
            &self.creator,
            self.creation_height,
        ))
        .expect("EscrowCommitment canonical_escrow_bytes serialization is infallible")
    }

    /// Compute the canonical escrow id.
    #[allow(clippy::too_many_arguments)]
    pub fn compute_escrow_id(
        payload: &EscrowPayload,
        predicate_hash: &Hash,
        bounds: &EscrowPredicateBounds,
        timeout_height: u64,
        beneficiary_on_success: &AgentId,
        beneficiary_on_timeout: &AgentId,
        creator: &AgentId,
        creation_height: u64,
    ) -> Hash {
        let bytes = bincode::serialize(&(
            payload,
            predicate_hash,
            bounds,
            timeout_height,
            beneficiary_on_success,
            beneficiary_on_timeout,
            creator,
            creation_height,
        ))
        .expect("compute_escrow_id serialization is infallible");
        let mut hasher = blake3::Hasher::new();
        hasher.update(ESCROW_DOMAIN_SEPARATOR);
        hasher.update(&bytes);
        *hasher.finalize().as_bytes()
    }

    /// INV-ESCROW-DECIDABILITY structural check. Enforces declared
    /// bounds are within kernel ceilings and timeout is in-range.
    pub fn validate_structural(&self) -> Result<(), EscrowValidationError> {
        if self.bounds.max_steps > MAX_ESCROW_PREDICATE_STEPS {
            return Err(EscrowValidationError::StepsOverCeiling {
                value: self.bounds.max_steps,
                ceiling: MAX_ESCROW_PREDICATE_STEPS,
            });
        }
        if self.bounds.max_reads > MAX_ESCROW_PREDICATE_READS {
            return Err(EscrowValidationError::ReadsOverCeiling {
                value: self.bounds.max_reads,
                ceiling: MAX_ESCROW_PREDICATE_READS,
            });
        }
        let delta = self.timeout_height.saturating_sub(self.creation_height);
        if !(MIN_ESCROW_TIMEOUT_BLOCKS..=MAX_ESCROW_TIMEOUT_BLOCKS).contains(&delta) {
            return Err(EscrowValidationError::TimeoutOutOfRange {
                timeout: self.timeout_height,
                creation_height: self.creation_height,
                min: MIN_ESCROW_TIMEOUT_BLOCKS,
                max: MAX_ESCROW_TIMEOUT_BLOCKS,
            });
        }
        if let EscrowPayload::Value { amount, .. } = &self.payload {
            if *amount <= 0 {
                return Err(EscrowValidationError::NonPositiveAmount(*amount));
            }
        }
        let expected = Self::compute_escrow_id(
            &self.payload,
            &self.predicate_hash,
            &self.bounds,
            self.timeout_height,
            &self.beneficiary_on_success,
            &self.beneficiary_on_timeout,
            &self.creator,
            self.creation_height,
        );
        if expected != self.escrow_id {
            return Err(EscrowValidationError::IdInconsistent);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mk(timeout: u64) -> EscrowCommitment {
        let payload = EscrowPayload::Value {
            asset: [0xAA; 32],
            amount: 1_000,
        };
        let predicate_hash = [0xBB; 32];
        let bounds = EscrowPredicateBounds::default();
        let creation_height = 100;
        let success = [0xCC; 32];
        let timeout_b = [0xDD; 32];
        let creator = [0xEE; 32];
        EscrowCommitment {
            escrow_id: EscrowCommitment::compute_escrow_id(
                &payload,
                &predicate_hash,
                &bounds,
                timeout,
                &success,
                &timeout_b,
                &creator,
                creation_height,
            ),
            payload,
            predicate_hash,
            bounds,
            timeout_height: timeout,
            beneficiary_on_success: success,
            beneficiary_on_timeout: timeout_b,
            creator,
            creation_height,
        }
    }

    #[test]
    fn patch_07_valid_escrow_passes_validation() {
        let e = mk(200);
        e.validate_structural().unwrap();
    }

    #[test]
    fn patch_07_escrow_id_consistency_enforced() {
        let mut e = mk(200);
        e.escrow_id = [0xFF; 32];
        assert!(matches!(
            e.validate_structural(),
            Err(EscrowValidationError::IdInconsistent)
        ));
    }

    #[test]
    fn patch_07_timeout_too_close_rejected() {
        // Timeout exactly at creation_height → delta = 0 < MIN.
        let e = mk(100);
        assert!(matches!(
            e.validate_structural(),
            Err(EscrowValidationError::TimeoutOutOfRange { .. })
        ));
    }

    #[test]
    fn patch_07_timeout_too_far_rejected() {
        // Creation at 100, timeout at 100 + MAX + 1.
        let e = mk(100 + MAX_ESCROW_TIMEOUT_BLOCKS + 1);
        assert!(matches!(
            e.validate_structural(),
            Err(EscrowValidationError::TimeoutOutOfRange { .. })
        ));
    }

    #[test]
    fn patch_07_predicate_steps_over_ceiling_rejected() {
        let payload = EscrowPayload::Value {
            asset: [0xAA; 32],
            amount: 1_000,
        };
        let predicate_hash = [0xBB; 32];
        let bounds = EscrowPredicateBounds {
            max_steps: MAX_ESCROW_PREDICATE_STEPS + 1,
            max_reads: 32,
        };
        let creator = [0xEE; 32];
        let escrow_id = EscrowCommitment::compute_escrow_id(
            &payload,
            &predicate_hash,
            &bounds,
            200,
            &[0xCC; 32],
            &[0xDD; 32],
            &creator,
            100,
        );
        let e = EscrowCommitment {
            escrow_id,
            payload,
            predicate_hash,
            bounds,
            timeout_height: 200,
            beneficiary_on_success: [0xCC; 32],
            beneficiary_on_timeout: [0xDD; 32],
            creator,
            creation_height: 100,
        };
        assert!(matches!(
            e.validate_structural(),
            Err(EscrowValidationError::StepsOverCeiling { .. })
        ));
    }

    #[test]
    fn patch_07_non_positive_amount_rejected() {
        let payload = EscrowPayload::Value {
            asset: [0xAA; 32],
            amount: 0,
        };
        let predicate_hash = [0xBB; 32];
        let bounds = EscrowPredicateBounds::default();
        let creator = [0xEE; 32];
        let creation_height = 100;
        let escrow_id = EscrowCommitment::compute_escrow_id(
            &payload,
            &predicate_hash,
            &bounds,
            200,
            &[0xCC; 32],
            &[0xDD; 32],
            &creator,
            creation_height,
        );
        let e = EscrowCommitment {
            escrow_id,
            payload,
            predicate_hash,
            bounds,
            timeout_height: 200,
            beneficiary_on_success: [0xCC; 32],
            beneficiary_on_timeout: [0xDD; 32],
            creator,
            creation_height,
        };
        assert!(matches!(
            e.validate_structural(),
            Err(EscrowValidationError::NonPositiveAmount(0))
        ));
    }

    #[test]
    fn patch_07_escrow_default_bounds_under_ceiling() {
        // Regression: defaults must be admissible.
        let b = EscrowPredicateBounds::default();
        assert!(b.max_steps <= MAX_ESCROW_PREDICATE_STEPS);
        assert!(b.max_reads <= MAX_ESCROW_PREDICATE_READS);
    }

    #[test]
    fn patch_07_domain_separator_matches_spec() {
        assert_eq!(ESCROW_DOMAIN_SEPARATOR, b"sccgub-escrow-commitment-v7");
    }
}
