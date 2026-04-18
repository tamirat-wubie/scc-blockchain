//! `sccgub-audit` — external moat-verifier for SCCGUB.
//!
//! Implements `verify_ceilings_unchanged_since_genesis` per
//! [`PATCH_08.md`](../../../PATCH_08.md) and [`POSITIONING.md` §11](
//! ../../../POSITIONING.md).
//!
//! # The moat this verifies
//!
//! POSITIONING §1 declares SCCGUB's only genuine technical moat:
//!
//! > Constitutional ceilings are genesis-write-once and not modifiable
//! > by any governance path, including the governance path itself.
//!
//! Today the property holds **by absence** — there is no code path in
//! the substrate that writes `system/constitutional_ceilings` after
//! genesis. That is sufficient for the property to *hold*, but not for
//! it to be *demonstrably held* to a third party. An institution
//! evaluating SCCGUB for a constitutional-court use case must
//! currently audit the substrate codebase to confirm the absence; that
//! is fragile and maintainer-dependent.
//!
//! This crate makes the property **externally auditable** — runnable
//! by any third party with read access to the chain log, without
//! source-code review and without trust in the maintainer.
//!
//! # Dependency isolation
//!
//! This crate intentionally depends ONLY on `sccgub-types` (for
//! `ConstitutionalCeilings`, `ChainVersionTransition`, and canonical
//! encodings) plus minimal external crates (`serde`, `bincode`,
//! `blake3`, `thiserror`, `clap`). It does NOT depend on
//! `sccgub-state`, `sccgub-execution`, `sccgub-consensus`,
//! `sccgub-governance`, `sccgub-network`, `sccgub-api`, or
//! `sccgub-node`. This isolation is part of the moat: the verifier
//! exists to be checked by parties who do not trust the rest of the
//! substrate.
//!
//! Per PATCH_08 §C.2: a future patch that adds an `sccgub-state`
//! dependency to this crate requires a positioning amendment under
//! POSITIONING §14 explaining why the verifier can credibly survive
//! the dependency.

#![deny(unsafe_code)]
#![deny(missing_docs)]

pub mod chain_state;
pub mod field;
pub mod verifier;
pub mod violation;

pub use chain_state::{ChainStateError, ChainStateView, JsonChainStateFixture};
pub use field::{CeilingFieldId, CeilingValue};
pub use verifier::verify_ceilings_unchanged_since_genesis;
pub use violation::CeilingViolation;
