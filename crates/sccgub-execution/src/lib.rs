// Patch-05 §23: iteration-order determinism discipline extended to the
// execution crate. See sccgub-state/src/lib.rs for the rationale.
#![deny(clippy::iter_over_hash_type)]

pub mod ceilings;
pub mod chain_version_check;
pub mod constraints;
pub mod contract;
pub mod cpog;
pub mod evidence_admission;
pub mod forgery_veto;
pub mod gas;
pub mod invariants;
pub mod key_rotation_check;
pub mod ontology;
pub mod payload_check;
pub mod phi;
pub mod scce;
pub mod validate;
pub mod validator_set;
pub mod wh_check;
