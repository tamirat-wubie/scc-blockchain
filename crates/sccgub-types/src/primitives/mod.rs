//! Patch-07 §D Tier-2 universal primitives.
//!
//! Per docs/THESIS_AUDIT.md and docs/THESIS_AUDIT_PT2.md, the audit
//! recommends a **reduced-commitment path** vs. the "six universal
//! primitives" proposed in the refined thesis: declare `ValueTransfer`,
//! `Message`, and `Attestation` as kernel primitives (structurally
//! irreducible), and declare `Escrow`, `Reference`, and `Supersession`
//! as structured compositions over those irreducibles. This module
//! lands the three composition templates as **declared types with
//! bounded semantics**, while keeping the core primitives in their
//! existing locations:
//!
//! - `ValueTransfer` remains `sccgub_types::transition::SymbolicTransition`
//!   with kind `Transfer` (not re-homed; existing consensus discipline
//!   wraps it).
//! - `Attestation` remains `sccgub_types::attestation::ArtifactAttestation`
//!   for artifact-specific claims; future Patch-08 can generalize.
//! - `Message` is introduced here as a new, size-capped, domain-tagged
//!   envelope (the audit's INV-MESSAGE-RETENTION-PAID requirement).
//! - `EscrowCommitment`, `ReferenceLink`, and `SupersessionLink` are
//!   introduced as the three composition templates.
//!
//! **Not runtime-wired.** These are declared types with unit-testable
//! canonical-bytes, size-cap, and decidability predicates. Phase-level
//! integration into Φ is intentionally deferred to a later patch so the
//! audit can re-cover this surface before it becomes consensus-critical.
//!
//! Each type implements a shared pattern:
//!
//! 1. Canonical bincode bytes that exclude non-canonical fields
//!    (signatures, caller-supplied nonces).
//! 2. A domain-separated BLAKE3 hash bound to the primitive's type.
//! 3. A `validate()` method that enforces size caps and decidability
//!    bounds at the type boundary, not later in execution.

pub mod escrow;
pub mod message;
pub mod reference;
pub mod supersession;

pub use escrow::{EscrowCommitment, EscrowPredicateBounds, EscrowValidationError};
pub use message::{Message, MessageValidationError, MAX_MESSAGE_BODY_BYTES};
pub use reference::{ReferenceKind, ReferenceLink, ReferenceValidationError};
pub use supersession::{SupersessionLink, SupersessionValidationError};
