<!--
Purpose: Consolidated ledger of every invariant declared across the
SCCGUB specification (PROTOCOL.md v2.0, PATCH_04, PATCH_05, PATCH_06,
PATCH_07). Kept in one place so future patches can see the entire
invariant surface at a glance and tell "declared" from "held at compile
time" from "held in execution" from "held by convention."

This document is a ledger, not a design proposal. New invariants go
into the relevant patch spec first; they are mirrored here with their
enforcement locus.

Convention:

  enforcement — one of:
    type-layer      - enforced by a struct/enum constructor or validate()
    execution-layer - enforced by a phase-N validator in sccgub-execution
    consensus-layer - enforced by the BFT protocol
    state-layer     - enforced by a state accessor (set-once, etc.)
    doc-only        - declared but not mechanically enforced; TODO

  status — one of:
    HELD            - enforcement exercised by tests, integrated into phi
    UNIT-TESTED     - enforcement exists at the type or module layer,
                      unit tests exercise it, but no phase integration
    STUBBED         - declared in code, execution is a todo!() or
                      NotYetWired error
    DECLARED-ONLY   - spec text exists, no code
-->

# SCCGUB Invariant Ledger

Current as of **v0.7.0** (Patch-07 tier-2 primitives).

## Pre-Patch invariants (PROTOCOL.md v1.0–v2.0)

| ID | Short name | Enforcement | Status |
|---|---|---|---|
| INV-1 | Valid CPoG on every block | execution-layer (`cpog.rs`) | HELD |
| INV-2 | Phi-traversal before any state write | execution-layer (`phi.rs`) | HELD |
| INV-3 | Conservation of supply | state-layer (`BalanceLedger`) | HELD |
| INV-4 | Nonce monotonicity | state-layer (`validate_nonces`) | HELD |
| INV-5 | State root integrity | consensus-layer (BFT hash agreement) | HELD |
| INV-6 | Tension homeostasis | state-layer (`TensionField`) | HELD |
| INV-7 | Receipt completeness | execution-layer (`phi::phase_12`) | HELD |
| INV-8 | Causal acyclicity | execution-layer (`phi::phase_11`) | HELD |
| INV-9 | Append-only H | state-layer + convention | HELD |
| INV-10 | Identity immutability post-creation | state-layer | HELD |

## Patch-04 invariants (§15–§19)

| ID | Declared in | Enforcement | Status |
|---|---|---|---|
| INV-VALIDATOR-SET-CONTINUITY | PATCH_04 §15 | state-layer (`validator_set_state`) | HELD |
| INV-VALIDATOR-KEY-COHERENCE | PATCH_04 §18 | state-layer + crypto | HELD |
| INV-CEILING-PRESERVATION | PATCH_04 §17 | execution-layer (`ceilings.rs` phase 10) | HELD |
| INV-KEY-ROTATION | PATCH_04 §18 | state-layer (`key_rotation_state`) | HELD |
| INV-VIEW-CHANGE-LIVENESS | PATCH_04 §16 | consensus-layer (`view_change.rs`) | HELD |

## Patch-05 invariants (§20–§29)

| ID | Declared in | Enforcement | Status |
|---|---|---|---|
| INV-FEE-ORACLE-BOUNDED | PATCH_05 §20 | type-layer (`median_of_tensions`) | HELD |
| INV-SEAL-NO-GRIND | PATCH_05 §21 | type-layer (`MfidelAtomicSeal::from_height_v4`) | HELD |
| INV-SLASHING-LIVENESS | PATCH_05 §22 | execution-layer (`evidence_admission.rs`) | HELD |
| INV-TYPED-PARAM-CEILING | PATCH_05 §25 | governance-layer (`validate_typed_param_proposal`) | HELD |
| INV-HISTORY-COMPLETENESS | PATCH_05 §27 | state-layer (`validator_set_state::append_admission_to_history`) | HELD |

## Patch-06 invariants (§30–§34)

| ID | Declared in | Enforcement | Status |
|---|---|---|---|
| INV-FORGERY-VETO-AUTHORIZED | PATCH_06 §30 | execution-layer (`forgery_veto.rs`) | UNIT-TESTED (not yet in phase 12) |
| INV-FEE-FLOOR-ENFORCED | PATCH_06 §31 | type-layer + execution-layer (`effective_fee_median_floored`, wired in `cpog.rs`) | HELD |
| INV-FORK-CHOICE-DETERMINISM | PATCH_06 §32 | consensus-layer + node-layer (`fork_choice.rs`, wired in `Chain::should_switch_to` v0.6.4) | HELD |
| INV-STATE-BOUNDED | PATCH_06 §33 | state-layer (`pruning.rs`) | STUBBED (identification pure; execution is `NotYetWired`) |
| INV-UPGRADE-ATOMICITY | PATCH_06 §34 | execution-layer + node-layer (`chain_version_check.rs`, wired in `Chain::validate_candidate_block_for_round` v0.6.1) | HELD |

## Patch-07 invariants (§D Tier-2 primitives)

| ID | Declared in | Enforcement | Status |
|---|---|---|---|
| INV-MESSAGE-RETENTION-PAID | PATCH_07 §D.1 | type-layer (`Message::validate_structural`, `MAX_MESSAGE_BODY_BYTES = 1024`, `MAX_MESSAGE_CAUSAL_ANCHORS = 16`) | UNIT-TESTED |
| INV-ESCROW-DECIDABILITY | PATCH_07 §D.2 | type-layer (`EscrowPredicateBounds`, `MAX_ESCROW_PREDICATE_STEPS = 10_000`, `MAX_ESCROW_PREDICATE_READS = 256`, `MIN_ESCROW_TIMEOUT_BLOCKS = 2`, `MAX_ESCROW_TIMEOUT_BLOCKS = 8_000_000`) | UNIT-TESTED |
| INV-REFERENCE-DISCOVERABILITY | PATCH_07 §D.3 | type-layer (`ReferenceLink::validate_structural`, self-reference rejected, `MAX_REFERENCE_KEY_BYTES = 128`) | UNIT-TESTED (target-side policy deferred) |
| INV-SUPERSESSION-UNIQUENESS | PATCH_07 §D.4 | type-layer (`canonical_successor`: earliest-height-then-lexicographic-link_id) | UNIT-TESTED |

## Audit-raised invariants NOT yet declared in code

These six invariants were raised by `docs/THESIS_AUDIT.md` +
`docs/THESIS_AUDIT_PT2.md` but are NOT yet declared in any spec
section. Listed here so future patches know the surface.

| ID | Source | Enforcement (proposed) | Status |
|---|---|---|---|
| INV-DOMAIN-ISOLATION | THESIS_AUDIT pt1 §B | state-layer (namespace-scoped keyspace enforcement when `DomainAdapter` API lands) | DECLARED-ONLY |
| INV-ADAPTER-SCHEMA-STABILITY | THESIS_AUDIT pt1 §B | governance-layer (adapter upgrade must preserve external references) | DECLARED-ONLY |
| INV-SUPERSESSION-CLOSURE | THESIS_AUDIT pt1 §B | state-layer (cross-reference behaviour after supersession) | DECLARED-ONLY |
| INV-ADAPTER-AUTHORITY-CONTAINMENT | THESIS_AUDIT pt1 §B | execution-layer (adapter X auth does not imply adapter Y auth) | DECLARED-ONLY |
| INV-ASSET-REGISTRY-AUTHORITY | THESIS_AUDIT pt2 §B | execution-layer (registrations require verifiable issuer credential) | DECLARED-ONLY |
| INV-CREDENTIAL-PROVENANCE | THESIS_AUDIT pt2 §B | execution-layer (credentials carry issuer chain up to genesis root) | DECLARED-ONLY |

## Summary counts

- **HELD**: 22 invariants
- **UNIT-TESTED** (not yet phase-integrated): 5 invariants
- **STUBBED**: 1 invariant (INV-STATE-BOUNDED — pruning execution deferred to Patch-07 §B; PATCH_06 §33.4.1 explains why)
- **DECLARED-ONLY**: 6 invariants (audit-raised; spec work pending)

**Total declared surface**: 34 invariants across v2.0 + Patch-04–07.

## Reading the ledger

- **HELD** invariants can be relied on at spec-reading time; a
  property violation is a bug.
- **UNIT-TESTED** invariants are exercised by the module that declares
  the primitive but are not yet wired into the 13-phase Φ pipeline;
  they become consensus-critical when wired.
- **STUBBED** invariants have a shape but no execution path; code that
  calls them receives a `NotYetWired` error or equivalent.
- **DECLARED-ONLY** invariants are spec prose only; no enforcement
  locus exists yet. They are on the roadmap but not yet real.

The single most important number here is the ratio of HELD to
DECLARED-ONLY: at v0.7.0 it is 22:6. Every DECLARED-ONLY entry is a
structural debt the substrate will pay interest on until it becomes
HELD.
