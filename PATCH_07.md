# PATCH_07 — Tier-2 Universal Primitives (honest scope)

**Chain version introduced:** no new chain version yet. The types land as
non-consensus declarations with unit-testable validation. Wiring into Φ
(admission, phases) is intentionally deferred to a later patch so the
audits can re-cover the surface before it becomes consensus-critical.

**Relationship to prior patches:** extends PROTOCOL.md v2.0 + PATCH_04
§15–§19 + PATCH_05 §20–§29 + PATCH_06 §30–§34. No existing invariant is
retracted.

**Relationship to thesis documents and audits:** this patch is the
**audit-recommended reduced-commitment path**, not the "six primitives"
proposal as written. Rationale captured below.

## §A Why this patch is smaller than the thesis asked for

Two thesis documents were submitted proposing a three-tier "governance
kernel + Tier-2 universal primitives + domain adapters" architecture.
Two audit documents responded under the Deterministic Causal Auditor
discipline (`docs/THESIS_AUDIT.md` and `docs/THESIS_AUDIT_PT2.md`). The
audits identified ten open invariants, a regulatory footprint ~10× the
current kernel, a capital model named-not-planned, and a 12-month
timeline under-scaled by 3–5×.

Rather than ship the full thesis as stated, Patch-07 **implements the
audits' reduced-commitment path**:

- **Three primitives remain kernel-irreducible**: `ValueTransfer`
  (existing: `SymbolicTransition`), `Message` (new: `primitives::Message`),
  `Attestation` (existing: `ArtifactAttestation`; a generalized variant
  is deferred).
- **Three primitives are declared as composition templates**:
  `EscrowCommitment`, `ReferenceLink`, `SupersessionLink`. They land as
  types with bounded semantics and unit tests; they are NOT promoted to
  consensus primitives in this patch.
- **No MUL token**. §A.1 of PATCH_07_AUDIT (below) defers token work
  until first adapter is live.
- **No `DomainAdapter` trait yet**. Declaring the trait without a
  runtime to host it would freeze the interface before any real
  adapter has validated it.
- **No "civilizational infrastructure" public framing**. The README
  stays on "hardening-stage governed blockchain kernel."

## §B Tier-2 primitive types

All live in `sccgub-types::primitives`. None are wired into phase
execution, admission, or the state trie in this patch. They are
declared types with canonical bytes, domain separators, and
`validate_structural()` methods that enforce the invariants below at
construction time.

### §B.1 `Message` (sccgub-types::primitives::message)

Closes **INV-MESSAGE-RETENTION-PAID**. Kernel-level messaging with
arbitrary bytes is an unbounded DoS vector against H (audit pt2 §D).
The primitive commits to hard caps:

- `MAX_MESSAGE_BODY_BYTES = 1024` — larger payloads externalize and
  reference via `ReferenceLink`.
- `MAX_ROLE_NAME_BYTES = 64` — role names are identifiers, not
  free-form strings.
- `MAX_MESSAGE_CAUSAL_ANCHORS = 16` — messages with more direct causal
  parents aggregate through References.
- Duplicate causal anchors rejected at the type layer.
- Domain separator `sccgub-message-v7` for canonical hash.
- `message_id()` excludes signature; signature malleability cannot
  affect the id.

### §B.2 `EscrowCommitment` (sccgub-types::primitives::escrow)

Closes **INV-ESCROW-DECIDABILITY**. Escrow predicates defined by
adapters must terminate (audit pt2 §B). The primitive commits to
bounds:

- `EscrowPredicateBounds { max_steps, max_reads }` fixed at creation.
- Global ceilings: `MAX_ESCROW_PREDICATE_STEPS = 10_000`,
  `MAX_ESCROW_PREDICATE_READS = 256`.
- Timeout range: `[2, 8_000_000]` blocks (floor prevents degenerate
  zero-timeout; ceiling prevents multi-century lockup).
- Payload variants: `Value`, `MessageRef`, `ActionRef` (each with its
  own canonical encoding).
- Non-positive value amounts rejected.
- Domain separator `sccgub-escrow-commitment-v7`.

### §B.3 `ReferenceLink` (sccgub-types::primitives::reference)

Closes **INV-REFERENCE-DISCOVERABILITY** (partial). Cross-domain
references without target-side policy leak target structure (audit pt2
§B). The primitive commits to:

- `ReferenceKind` enum: `DependsOn | Cites | Supersedes | Contradicts`.
- `MAX_REFERENCE_KEY_BYTES = 128`.
- Self-reference (source == target) rejected.
- `link_id` canonical consistency enforced at construction.
- Domain separator `sccgub-reference-v7`.

Target-side policy enforcement (an adapter-level read-time filter) is
not in this patch; it is deferred until the `DomainAdapter` runtime
exists.

### §B.4 `SupersessionLink` (sccgub-types::primitives::supersession)

Closes **INV-SUPERSESSION-UNIQUENESS**. The audit flagged that two
authorities racing to supersede the same fact produce ambiguous
canonical state. The primitive commits to **first-valid-wins**:

- `canonical_successor(links)` returns the link with minimum
  `(height, link_id)`. Order-independent by construction.
- Self-supersession (original == replacement) rejected.
- Domain separator `sccgub-supersession-v7`.
- `reason` is a 32-byte hash pointer to an off-chain document, not
  a free-form string.

## §C Not in this patch

- **Generalized domain-neutral Attestation**. The existing
  `ArtifactAttestation` is artifact-specific; a universal attestation
  wanting `asserter + authority + schema-typed claim` is a Patch-08
  scope item. The current primitive set intentionally does not re-home
  attestations prematurely.
- **`DomainAdapter` trait**. Declared in audit comments; implementation
  waits until a concrete adapter extraction (finance) has validated
  the shape empirically. Ship one adapter, then freeze the trait.
- **MUL token + AssetRegistry**. Deferred until the first adapter is
  live. Audit pt2 §H.7 details the regulatory and economic rationale.
- **Namespace enforcement**. State keyspace remains un-domained. The
  `source_domain` / `target_domain` fields in `ReferenceLink` are
  opaque 32-byte ids; kernel does not yet enforce them.
- **Phase-level admission for any Tier-2 primitive**. The types land
  as non-consensus declarations. A future patch with a new chain
  version can promote selected primitives into phase-12 admission.

## §D Invariants declared by Patch-07

| ID | Locus | Cap or semantic |
|---|---|---|
| INV-MESSAGE-RETENTION-PAID | `Message::validate_structural` | `body ≤ 1024 B`, `role ≤ 64 B`, `anchors ≤ 16`, anchors-unique |
| INV-ESCROW-DECIDABILITY | `EscrowCommitment::validate_structural` | `steps ≤ 10_000`, `reads ≤ 256`, timeout ∈ [2, 8_000_000] |
| INV-REFERENCE-DISCOVERABILITY | `ReferenceLink::validate_structural` | `key ≤ 128 B`, self-reference rejected |
| INV-SUPERSESSION-UNIQUENESS | `canonical_successor` | `(height, link_id)` lexicographic minimum |

All four are **UNIT-TESTED** in `docs/INVARIANTS.md` classification.
None are HELD (phase-integrated) yet.

## §E Test coverage

35 new unit tests across the four primitive modules:

- `message`: 11 tests (cap-exact, cap-exceeded, role-cap, causal-anchor
  dup, id-excludes-signature, body-change-changes-id, domain-separator).
- `escrow`: 7 tests (happy path, id consistency, timeout min/max,
  predicate steps ceiling, non-positive amount, default-under-ceiling,
  domain separator).
- `reference`: 6 tests (happy path, id consistency, self-reference,
  oversized key, same-domain different-key ok, all kinds valid,
  domain separator).
- `supersession`: 8 tests (happy path, self-supersession, id
  consistency, canonical-successor empty/single/earliest/tiebreak/
  order-independent, domain separator).

All 35 tests green. Workspace count at v0.7.0 is the v0.6.5 baseline
plus 35.

## §F What shipping this patch commits to

1. **The four invariants above become regression-fenced** — changing
   the caps requires updating the tests and the spec together.
2. **The four domain separators `sccgub-*-v7` are reserved** and
   cannot be collided by future primitives without a chain-version
   bump.
3. **The type layout of each primitive is frozen** under bincode
   canonical encoding. Field additions or reorderings require a
   legacy-cascade pattern like `LegacyConsensusParamsV1..V3`.
4. **The composition-templates frame is the official design** — Escrow,
   Reference, Supersession are templates, not primitives. If a later
   patch promotes any of them to kernel-primitive status, it must
   provide evidence the promotion meets the `≥ 3 shape-of-truth
   domains` discipline.

## §G What shipping this patch does NOT commit to

1. The full "governance kernel + adapters" thesis. That thesis has a
   live audit debt catalogued in `docs/THESIS_AUDIT.md` + pt2.
2. A universal truth-store framing, MUL token, or 12-month v1.0
   timeline.
3. Phase-level integration of any Tier-2 primitive.
4. A `DomainAdapter` trait shape (declared but intentionally unbuilt
   until first adapter extraction).
5. Any promise about which domains land next.

## §H Forward references

| Patch | Scope (not yet scheduled) |
|---|---|
| Patch-07 §B-2 | In-trie admission-history pruning resolution (PATCH_06 §33.4.1 addendum). |
| Patch-08 | Generalized `Attestation` primitive that subsumes `ArtifactAttestation` for domain-neutral use. |
| Patch-09 | Finance adapter extraction as a chain-breaking v6 or v7 upgrade (via PATCH_06 §34 live-upgrade protocol). |
| Patch-10+ | Phase integration for Tier-2 primitives that survive the adapter-extraction test. |

## §I Deferrals

The audits raised six DECLARED-ONLY invariants that are not touched in
this patch: INV-DOMAIN-ISOLATION, INV-ADAPTER-SCHEMA-STABILITY,
INV-SUPERSESSION-CLOSURE, INV-ADAPTER-AUTHORITY-CONTAINMENT,
INV-ASSET-REGISTRY-AUTHORITY, INV-CREDENTIAL-PROVENANCE. All six
require the `DomainAdapter` runtime that Patch-07 intentionally
defers. They appear in `docs/INVARIANTS.md` under "Audit-raised
invariants NOT yet declared in code" and are the structural debt
Patch-09 will begin to retire.
