//! `CeilingViolation` enum per PATCH_08.md §B.3.
//!
//! Four variants, ordered by likelihood-of-occurrence in the verifier
//! algorithm: `FieldValueChanged` (the primary moat-violation case),
//! `GenesisCeilingsUnreadable`, `CeilingsUnreadableAtTransition`,
//! `HistoryStructurallyInvalid`.

use serde::{Deserialize, Serialize};

use crate::field::{CeilingFieldId, CeilingValue};

/// A ceiling-immutability violation. Returned by
/// `verify_ceilings_unchanged_since_genesis` on first failure
/// (short-circuit per PATCH_08 §B.2). Subsequent violations are not
/// enumerated because any single violation breaks the moat.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
pub enum CeilingViolation {
    /// A ceiling field's value at `transition_height` differed from
    /// its genesis value. **The primary moat-violation case.**
    #[error(
        "ceiling field {ceiling_field} changed at transition height {transition_height}: \
         genesis was {before_value}, observed {after_value}"
    )]
    FieldValueChanged {
        /// Block height of the `ChainVersionTransition` at which the
        /// drift was observed.
        transition_height: u64,
        /// Which ceiling field drifted.
        ceiling_field: CeilingFieldId,
        /// Genesis value of the field (the moat-defining baseline).
        before_value: CeilingValue,
        /// Observed value at `transition_height` — DIFFERS from
        /// `before_value`.
        after_value: CeilingValue,
    },
    /// The genesis ceilings record could not be read or deserialized.
    /// The chain has no genesis ceilings to compare against; the moat
    /// is undefined for this chain.
    #[error("genesis ceilings unreadable: {reason}")]
    GenesisCeilingsUnreadable {
        /// Underlying error description (typically a deserialization
        /// failure or missing-key error).
        reason: String,
    },
    /// A `ChainVersionTransition` referenced a height at which the
    /// ceilings record could not be read. Possible incomplete snapshot
    /// or corrupted state.
    #[error("ceilings unreadable at transition height {transition_height}: {reason}")]
    CeilingsUnreadableAtTransition {
        /// Block height where the read failed.
        transition_height: u64,
        /// Underlying error description.
        reason: String,
    },
    /// `chain_version_history` contained a transition whose
    /// `activation_height` predated genesis or violated monotonic
    /// ordering. Indicates corrupted history.
    #[error("chain version history structurally invalid: {reason}")]
    HistoryStructurallyInvalid {
        /// Description of the structural defect (out-of-order
        /// transitions, duplicate heights, etc.).
        reason: String,
    },
}

impl std::fmt::Display for CeilingFieldId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn patch_08_violation_serde_roundtrip() {
        let v = CeilingViolation::FieldValueChanged {
            transition_height: 42,
            ceiling_field: CeilingFieldId::MaxProofDepth,
            before_value: CeilingValue::U32(256),
            after_value: CeilingValue::U32(512),
        };
        let json = serde_json::to_string(&v).unwrap();
        let back: CeilingViolation = serde_json::from_str(&json).unwrap();
        assert_eq!(v, back);
    }

    #[test]
    fn patch_08_violation_display_includes_transition_and_field() {
        let v = CeilingViolation::FieldValueChanged {
            transition_height: 99,
            ceiling_field: CeilingFieldId::MaxTxGas,
            before_value: CeilingValue::U64(1_000_000),
            after_value: CeilingValue::U64(2_000_000),
        };
        let s = format!("{}", v);
        assert!(s.contains("max_tx_gas_ceiling"));
        assert!(s.contains("99"));
        assert!(s.contains("1000000"));
        assert!(s.contains("2000000"));
    }
}
