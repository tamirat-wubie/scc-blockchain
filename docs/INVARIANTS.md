<!--
Purpose: Consolidated ledger of every invariant declared across the
SCCGUB specification (PROTOCOL.md v2.0, PATCH_04, PATCH_05, PATCH_06,
PATCH_07, plus POSITIONING.md §7.1 amendments). Kept in one place so
future patches can see the entire invariant surface at a glance and
tell "declared" from "held at compile time" from "held in execution"
from "held by convention."

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

Current as of **v0.8.0 + Patch-08 verifier shipped** (2026-04-18).
Tier-0 / Tier-1 distinction added per Audit pt3 finding that the
SCCGUB moat reduces to one property: constitutional ceilings
genesis-write-once with no governance path to raise. **Both Tier-0
ceiling-immutability invariants are now HELD** via the
`sccgub-audit` crate's externally-runnable verifier (PATCH_08 §X
implementation). The ledger now classifies invariants into the
moat-defining tier (Tier 0, both HELD) and the adapter-hygiene
tier (Tier 1, six DECLARED-ONLY). Pre-tier sections (Patch-04
through Patch-07) preserve their original organization for
historical readability; the Tier-0 / Tier-1 sections lower in the
document expose the moat structure.

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

## Tier-0 ceiling-immutability invariants (POSITIONING §7.1, moat-defining)

Added per POSITIONING.md §7.1 (PR #43, post-Audit-pt3 amendment).
These are the invariants that hold the §1 moat
(cryptographically-bound-constitutional-immutability). Without them,
§1's claim is rhetoric, not structure. They are subject to
externally-auditable verification per POSITIONING §11.

**These take precedence over Tier-1 adapter-hygiene invariants in the
adapter-work gate**: no new domain adapter shall be developed past
finance extraction until **all Tier-0 invariants are HELD**.

| ID | Declared in | Enforcement | Status |
|---|---|---|---|
| INV-CEILING-PRESERVATION | PATCH_04 §17 + POSITIONING §7.1 | execution-layer (`ceilings.rs` phase 10) — every block validator runs `ConstitutionalCeilings::validate(&params)`; any block whose `ConsensusParams` exceed any ceiling field is rejected | HELD (already shipped Patch-04; promoted to Tier-0 by POSITIONING §7.1 reorder; previously listed under Patch-04 invariants above and is the same invariant, now classified as moat-defining) |
| INV-CEILINGS-WRITE-ONCE | POSITIONING §7.1 + PATCH_08 §B | state-layer (`system/constitutional_ceilings` set at genesis; **no governance path can rewrite it**) — enforced by absence of any write code path; verifier `verify_ceilings_unchanged_since_genesis(...)` in `crates/sccgub-audit` cross-checks the property externally without trusting the maintainer | **HELD** (Patch-08; verifier shipped with 27 unit tests + 10 conformance oracle cases) |
| INV-CEILINGS-NEVER-RAISED-IN-HISTORY | POSITIONING §7.1 + PATCH_08 §B | audit-layer (`crates/sccgub-audit::verify_ceilings_unchanged_since_genesis`) — externally-auditable property: across every `ChainVersionTransition` from genesis to tip, no ceiling field ever drifted. **Verified in pure-function form by any third party with chain-log read access; runnable as standalone CLI (`sccgub-audit verify-ceilings`).** | **HELD** (Patch-08 verifier shipped; moat-defining per POSITIONING §11) |

**Important note on INV-CEILING-PRESERVATION**: this invariant
appears in **both** the Patch-04 invariants section above AND the
Tier-0 section here. It is **the same invariant** — POSITIONING §7.1
reclassified it as Tier-0 / moat-defining without changing its
declaration site. The duplication is intentional in the ledger:
readers looking at Patch-04 history see it where it shipped;
readers looking at the moat structure see it where it functions.
A future patch that consolidates the ledger should add a
cross-reference rather than removing either entry.

## Tier-1 adapter-hygiene invariants (POSITIONING §7.2, after the moat)

Renamed from "Audit-raised invariants NOT yet declared in code" per
POSITIONING.md §7.2. These six invariants are the original ones
raised by `docs/THESIS_AUDIT.md` + `docs/THESIS_AUDIT_PT2.md`.
**Adapter work past finance extraction is gated on Tier-0 HELD plus
all six of these HELD.** Listed here so future patches know the
surface.

| ID | Source | Enforcement (proposed) | Status |
|---|---|---|---|
| INV-DOMAIN-ISOLATION | THESIS_AUDIT pt1 §B | state-layer (namespace-scoped keyspace enforcement when `DomainAdapter` API lands) | DECLARED-ONLY |
| INV-ADAPTER-SCHEMA-STABILITY | THESIS_AUDIT pt1 §B | governance-layer (adapter upgrade must preserve external references) | DECLARED-ONLY |
| INV-SUPERSESSION-CLOSURE | THESIS_AUDIT pt1 §B | state-layer (cross-reference behaviour after supersession) | DECLARED-ONLY |
| INV-ADAPTER-AUTHORITY-CONTAINMENT | THESIS_AUDIT pt1 §B | execution-layer (adapter X auth does not imply adapter Y auth) | DECLARED-ONLY |
| INV-ASSET-REGISTRY-AUTHORITY | THESIS_AUDIT pt2 §B | execution-layer (registrations require verifiable issuer credential) | DECLARED-ONLY |
| INV-CREDENTIAL-PROVENANCE | THESIS_AUDIT pt2 §B | execution-layer (credentials carry issuer chain up to genesis root) | DECLARED-ONLY |

## Summary counts

- **HELD**: **24 invariants** (Patch-08 promoted INV-CEILINGS-WRITE-ONCE and INV-CEILINGS-NEVER-RAISED-IN-HISTORY from DECLARED-ONLY → HELD via the `sccgub-audit` verifier; INV-CEILING-PRESERVATION still counted once despite appearing in both Patch-04 and Tier-0 tables)
- **UNIT-TESTED** (not yet phase-integrated): 5 invariants
- **STUBBED**: 1 invariant (INV-STATE-BOUNDED — pruning execution deferred to Patch-07 §B; PATCH_06 §33.4.1 explains why)
- **DECLARED-ONLY**: 6 invariants (Tier-1 audit-raised; Patch-08 closed the two Tier-0 entries that were here previously)

**Total declared surface**: 36 invariants across v2.0 + Patch-04–08.

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

**Tier-0 vs Tier-1 distinction** (POSITIONING §7.1/§7.2): Tier-0
invariants must HOLD before Tier-1 invariants become load-bearing.
If the ceilings aren't mechanically sound, the adapter gate is
guarding nothing. Adapter work past finance extraction is gated on
Tier-0 HELD plus Tier-1 HELD. Neither tier optional.

The single most important number here is the ratio of HELD to
DECLARED-ONLY: at v0.8.0 (Patch-08 verifier shipped) it is **24:6**.
Every DECLARED-ONLY entry is structural debt the substrate will pay
interest on until it becomes HELD. **Both Tier-0 ceiling-immutability
entries are now HELD** via `crates/sccgub-audit`: the §1 moat is no
longer rhetoric — it is structurally verified by a pure-function
externally-runnable verifier (POSITIONING §11 commitment fulfilled).
