<!--
Purpose: Authoritative product positioning for SCCGUB. Replaces the
implicit, drifting positioning that earlier theses ("governance kernel
+ adapters", "universal truth store") proposed but did not commit to.
Reconciles the architecture against the consolidated audit findings in
docs/THESIS_AUDIT.md (PR #33) and docs/THESIS_AUDIT_PT2.md (PR #34).

Governance scope: this document declares what SCCGUB is, what it is
not, what is open, and what is non-goal. Subsequent patches MUST
reference this document when their scope intersects positioning. A
patch that contradicts this document requires a positioning amendment
PR before the patch lands.

Dependencies: PROTOCOL.md v2.0, PATCH_04.md, PATCH_05.md, PATCH_06.md,
PATCH_07.md, docs/INVARIANTS.md, docs/THESIS_AUDIT.md,
docs/THESIS_AUDIT_PT2.md, docs/FINANCE_EXTRACTION_PLAN.md,
docs/PRUNING_RESOLUTION_DESIGN.md.

Invariants of this document:
  - Every contestable claim is anchored to an in-tree artifact (commit,
    file, audit reference) or named explicitly as open.
  - No marketing-register language. No "civilizational." No "universal."
    No "no existing chain has."
  - Open problems are named, not solved. Solved problems cite the work
    that solved them.

Date: 2026-04-18. Repo at v0.7.2, main @ b4c4daf.
-->

# SCCGUB — Positioning

## §1 What SCCGUB is

**SCCGUB is a cryptographically-bound-constitutional-immutability
substrate for institutions whose legitimacy depends on inability to
modify their own foundations.** The symbolic governance and
attestation layers are the mechanisms through which this
immutability is expressed and the substrate made auditable; the
immutability itself is the moat.

The genuine technical moat is one specific property:

> Constitutional ceilings are **genesis-write-once and not
> modifiable by any governance path, including the governance path
> itself.**

No production-tier substrate I am aware of binds its own meta-
governance at genesis with cryptographic finality. Cosmos governance
can vote-raise its own parameters. Substrate runtime can be replaced
by on-chain upgrade. Hyperledger Fabric channel admins can change
channel policy. Tezos self-amends explicitly. SCCGUB cannot do any
of these things to its constitutional ceilings; the ceilings sit
below the governance layer, and governance cannot reach above
itself. See PATCH_04.md §17 (ceilings spec) and `crates/sccgub-types/
src/constitutional_ceilings.rs` (implementation). Audit pt3
(`docs/THESIS_AUDIT_PT3.md`) walks every other claimed differentiator
and finds them at parity with the modern alternative stack
(Cosmos SDK + custom module + W3C VCs + DID + EAS + Fabric).

**Supporting disciplines** (real but not the moat — the mechanisms
through which immutability is expressed and audited):

- **Uniform 13-phase Φ traversal** at consensus level (every
  transition passes all 13 phases, no exceptions). The uniformity
  is the discipline novelty; individual phases have alternative-
  stack equivalents.
- **Append-only causal lineage H** with deterministic supersession
  via `canonical_successor` (Patch-07 §D.4).
- **Mfidel-grounded identity** as semantic category (see §5). Pure
  cultural-positioning differentiation; zero technical work. Real
  for deployments where non-Western symbol-space matters.
- **Three irreducible primitives** (ValueTransfer, Message,
  Attestation) plus three standard-library templates. Table-stakes
  for the niche, not the differentiator (see §3).

### §1.1 Niche — narrow but sharp, not pinprick-narrow

SCCGUB is built for **institutions whose legitimacy depends on
inability to modify their own foundational rules.** Six concrete
institutional targets:

1. **Constitutional courts** and supreme courts whose institutional
   guarantee is "the rules of judgment cannot be rewritten by the
   judges."
2. **Treaty enforcement bodies** whose legitimacy depends on
   unchangeable cross-state commitments.
3. **Indigenous data sovereignty councils** whose authority requires
   cryptographic finality on community-owned attestation rules.
4. **International standards bodies** whose foundational rule sets
   must outlast the body itself.
5. **Algorithmic accountability registries** under the EU AI Act and
   analogous regimes — AI model provenance and training-data
   attestation. Immutable meta-governance is exactly the property:
   "this model's training-data attestation rules cannot be
   retroactively rewritten by the model's operator."
6. **Post-settlement legal archives** — court records, land
   registries in jurisdictions with weak institutional trust,
   academic publication records after retraction windows close.
   The shape: decision-made, record-sealed, no party can change the
   archive's own rules later.

This is **narrow but sharp, not pinprick-narrow.** Each category
contains many medium-scale registries, not a handful of global
bodies. The addressable institutional surface is real and
identifiable, while remaining true to the depth-in-niche framing.

### §1.2 What SCCGUB is not

SCCGUB is **not** a general-purpose L1, **not** a DeFi platform,
**not** a smart-contract execution environment, **not** a "universal
truth store," **not** civilizational infrastructure, and **not** a
"symbolic governance + attestation substrate" as the primary
framing — that framing is retired by §10.2 in favor of the
immutable-meta-governance lead above. The symbolic layer remains
real and load-bearing for architecture; it is no longer the lead.

## §2 The kernel — what it is structurally

The kernel comprises:

| Component | Code locus |
|---|---|
| USCL algebra `𝕊 := ⟨Ι, Λ, Σ, Γ, H⟩` | `sccgub-types::*` |
| Φ_gov mutation gate (sole write path) | `sccgub-execution::phi` |
| 13-phase Φ traversal | `sccgub-execution::phi` |
| Ψ judgment kernel (proof-carrying verdicts) | `sccgub-execution::*` |
| H append-only lineage | `sccgub-state::*` |
| Precedence hierarchy | `sccgub-types::governance` |
| BFT consensus (two-round, k-block finality) | `sccgub-consensus::*` |
| Mfidel identity (34×8 atomic matrix) | `sccgub-types::mfidel` |
| Canonical encoding (bincode + BLAKE3 + Ed25519) | `sccgub-crypto::*` |
| Constitutional ceilings | `sccgub-types::constitutional_ceilings` |

Counts as of `b4c4daf`: 9 crates, 62,083 lines of Rust across
`crates/`, 1,293 tests, all CI green on Ubuntu + Windows + security
audit.

The kernel today **also owns finance-specific state** (`BalanceLedger`,
`Treasury`, escrow state, asset registry, fee composition) that
properly belongs in a domain adapter. Extraction is planned per
[`docs/FINANCE_EXTRACTION_PLAN.md`](docs/FINANCE_EXTRACTION_PLAN.md).
The plan is honest about its 6–9 month cost and its 5 hard
prerequisites; until those prerequisites resolve, the kernel
intentionally keeps finance in place rather than ship a half-extracted
intermediate state.

## §3 Tier-2 primitives — three irreducible, three templates

**Frame correction (per Audit pt3)**: ValueTransfer + Message +
Attestation are **table stakes for the niche, not the
differentiator**. Most chains support equivalent operations: EAS
provides typed attestations; EIP-712 provides typed signed messages;
ERC-20 provides typed value transfer; Hyperledger Fabric provides
all three within channels. Cosmos modules and Substrate pallets
each implement equivalent primitives.

**The uniqueness lives in how the ceilings governing the primitives
are bound at genesis.** A future patch can change the
`effective_fee` formula, but it cannot raise `min_effective_fee_floor`
past its genesis value. A future governance proposal can RotatePower
a validator, but it cannot raise `max_validator_set_size` past the
genesis ceiling. The primitives are reproducible across substrates;
the **immutability of the rules governing them is not** (see §11
for the cryptographic verification of this property).

The refined thesis proposed six universal Tier-2 primitives. The
audit identified that three of the six structurally decompose into
the other three. Patch-07 ([PATCH_07.md](PATCH_07.md)) shipped the
3+3 split:

**Irreducible kernel primitives:**

- **`ValueTransfer`** — A→B transfer of an asset under
  conservation. Existing as `SymbolicTransition` with kind `Transfer`.
- **`Message`** — domain-tagged signed envelope, body capped at
  `MAX_MESSAGE_BODY_BYTES = 1024` per INV-MESSAGE-RETENTION-PAID.
  Larger payloads externalize via §4 discipline.
- **`Attestation`** — signed claim by an authority. Today scoped to
  artifacts (`ArtifactAttestation`); a generalized
  domain-neutral variant is Patch-08 scope.

**Standard-library templates compiled from primitives:**

- **`EscrowCommitment`** — Message + ValueTransfer + bounded
  predicate. Lives in `sccgub-types::primitives::escrow`. Decidability
  bounds (`MAX_ESCROW_PREDICATE_STEPS = 10_000`,
  `MAX_ESCROW_PREDICATE_READS = 256`) declared at construction per
  INV-ESCROW-DECIDABILITY.
- **`ReferenceLink`** — pointer between domains, typed by
  `ReferenceKind`. Not a kernel primitive in the consensus-frozen
  sense; adapters can vary the template.
- **`SupersessionLink`** — first-valid-wins canonical successor
  selection, deterministic across all validators per
  INV-SUPERSESSION-UNIQUENESS.

**Discipline**: a future primitive is admissible to the kernel only
if it is genuinely irreducible (cannot be expressed as a typed
payload over the existing three) AND is needed by at least three
adapter categories. The discipline is documented; it is enforced by
review, not by a Φ_gov predicate.

**Crate placement and consensus-layer-zero-knowledge property**: the
standard-library templates live outside the consensus encoding
surface. They will be hosted in a separate `sccgub-templates` crate
(or, transitionally, under the `sccgub-types::primitives` submodule
explicitly tagged `#[doc(hidden = "non-consensus")]`) — kernel
consensus code MUST NOT import templates by type. Template additions,
removals, or shape changes never require a chain-version bump,
because by the time a transaction composed from a template reaches
consensus, the template has already decomposed into the three
irreducible primitives and the kernel cannot tell whether the
composition came from a template or from hand-written primitive
calls. The kernel's consensus-layer view of templates is exactly:
zero. Any future contributor who proposes "registering" or
"versioning" a template at the protocol level is contradicting this
property and triggers a §13 amendment.

## §4 Content-addressed off-chain discipline

This is the structural commitment that closes four otherwise-separate
audit fractures simultaneously: H.2 (GDPR vs append-only), H.8
(Message-as-DoS), N3 (regulatory infeasibility of "H is sacred"), and
the broader regulated-domain (HIPAA, financial PII) compatibility
problem.

**Rule**: any payload that is large (> ~1 KiB), sensitive (any PII or
regulated content), or operationally bulky (datasets, scans, long
documents) **MUST** be stored off-chain by the producing adapter and
referenced on-chain only by its content hash plus metadata.

Concretely:

- The kernel `Message` body is hard-capped at
  `MAX_MESSAGE_BODY_BYTES = 1024`. Anything larger is structurally
  invalid as a `Message` and must be carried as a `ReferenceLink`
  pointing to off-chain content.
- Attestations carry `claims_hash` (existing `ArtifactAttestation`
  pattern), not the claim body itself. The off-chain document is the
  ground truth; the attestation cryptographically commits to it
  without retaining it on-chain.
- Adapters are responsible for the lifecycle of their off-chain
  storage: durability, retention policy, encryption-at-rest,
  jurisdiction, deletion under right-to-erasure. The kernel never
  retains the payload.
- A right-to-erasure event in a regulated domain is implemented by
  the adapter destroying the off-chain content; the on-chain hash
  remains, but no party can produce the pre-image without the data.
  This is the standard regulator-acceptable pattern (see GDPR
  Working Party Opinion 05/2014; analogous treatments in HIPAA, BSA).

**Consequence for INV-9 (append-only H)**: H continues to retain the
hash forever. The substrate's claim is not "every fact is preserved
in full" but "every committed claim is preserved in cryptographic
form, and the off-chain content lifecycle belongs to the adapter."
This is a real weakening of the original "H is sacred" framing — and
it is the only weakening compatible with the regulatory regimes
SCCGUB needs to coexist with.

**Hash scheme commitment**: content addressing uses **32-byte BLAKE3**
over the off-chain payload as the on-chain commitment. Full
content-addressing scheme (CID, multihash, IPFS compatibility) is
deferred to Patch-08 §C; the **32-byte hash width is pinned now** and
cannot change without a chain-version bump. Any adapter producing
on-chain hash commitments **MUST** use this same BLAKE3-32 scheme
during the interim period; adapter-specific hash schemes (SHA-256,
Keccak-256, etc.) are not permitted before Patch-08 §C ratifies a
multi-scheme container, because allowing per-adapter schemes now
breaks cross-domain `ReferenceLink` semantics the moment two
adapters disagree on hash construction.

## §5 Mfidel — semantic category, not unique identifier

The thesis documents and earlier README implied that Mfidel-grounded
identity is the substrate's unique-identification scheme. The audit
flagged that the 34×8 = 272-position matrix cannot uniquely identify
authorities at any meaningful scale. The audit is correct.

**Position commit**: Mfidel position is a **semantic category** that
binds an authority to a Ge'ez-grounded symbolic frame. It is not a
unique identifier and does not pretend to be one.

Identity uniqueness comes from the **Ed25519 public key**. The
canonical identity is:

```text
identity_id = BLAKE3("sccgub-identity-v1" || public_key || mfidel_seal)
```

The `public_key` makes the identifier unique. The `mfidel_seal`
contributes the semantic category. Both are bound into the canonical
hash so neither can be silently changed; replacing the
`public_key` requires `KeyRotation` per Patch-04 §18.

**Scope boundary**: SCCGUB's identity primitives are not currently
FIPS / NIST / eIDAS certified. Institutions and jurisdictions that
require certified identity primitives cannot adopt SCCGUB without
either (a) a parallel substrate using certified primitives or (b)
SCCGUB's primitives gaining certification through the relevant
standards process. Neither is proposed as a current work item; both
are open downstream paths.

This is a **deliberate scope boundary**, not a defect. It defines
which deployments SCCGUB is and is not for. SCCGUB is for
deployments that accept BLAKE3 + Ed25519 + Mfidel-grounded identity
as appropriate primitives. For deployments that require certified
identity, SCCGUB is not the right substrate today.

## §6 No native token

Earlier theses proposed a `MUL` native token with "zero governance
weight." The audit identified MUL as the single most
regulatorily-loaded decision in the architecture: native token
marketed + listed + value-accruing-from-platform-adoption is a
prima-facie security in the US per Ripple, an asset-referenced token
under MiCA Art. 16-18 if pegged via bridges, and triggers
money-transmission licensing under BSA the moment any operator
custodies it.

**Position commit**: SCCGUB has no native token in v1.0 and no
planned native token thereafter.

Transactions that require fees pay in **user-supplied fee currencies**
selected at adapter integration time. The finance adapter declares
which assets it accepts as fee currency; the kernel routes fee
payment through the adapter's `apply` handler. Candidates include
USDC, EURe, regional CBDCs once available, or domain-specific
non-tradable credits issued by trusted authorities.

**The native-token decision is reversible only against very high
evidence**: a counsel-supported, jurisdiction-by-jurisdiction
analysis showing the regulatory tripwires can be defused, AND a
demonstrated funding pathway that does not depend on token issuance,
AND an adapter requirement the user-supplied-currency model cannot
serve. The burden is on any future MUL proposal to clear all three;
the burden is not on this document to defend their absence.

The design consequence: SCCGUB is positioned as **infrastructure**,
not as a tradable asset. The closest reference point is Hyperledger
Fabric or Ceramic, both of which are tokenless. The funding model
follows from this — see §9.

## §7 Ten invariants as prerequisites to adapter work

Per audit recommendation, no new domain adapter shall be developed
beyond the planned finance extraction until all ten audit-raised
invariants are HELD per [`docs/INVARIANTS.md`](docs/INVARIANTS.md):

**From PR #33 audit (Part 1):**

1. INV-DOMAIN-ISOLATION — adapter X cannot write to adapter Y's
   keyspace except via declared cross-domain refs.
2. INV-ADAPTER-SCHEMA-STABILITY — once an adapter is referenced,
   its schema cannot change in ways that invalidate existing
   references.
3. INV-SUPERSESSION-CLOSURE — references to superseded facts have a
   declared resolution policy (frozen-pointer, propagate-supersession,
   or reject-original).
4. INV-ADAPTER-AUTHORITY-CONTAINMENT — authority granted in
   adapter X does not implicitly carry to adapter Y.

**From PR #34 audit (Part 2):**

5. INV-MESSAGE-RETENTION-PAID — held at the type layer in v0.7.0.
   See `MAX_MESSAGE_BODY_BYTES`. Promotion to consensus-layer-held
   pending phase integration.
6. INV-ESCROW-DECIDABILITY — held at the type layer in v0.7.0.
   See `EscrowPredicateBounds`. Promotion pending phase integration.
7. INV-REFERENCE-DISCOVERABILITY — partial at the type layer (size
   cap, self-reference rejection); target-side discovery policy
   awaits adapter runtime.
8. INV-SUPERSESSION-UNIQUENESS — held at the type layer in v0.7.0
   via `canonical_successor`. Promotion pending phase integration.
9. INV-ASSET-REGISTRY-AUTHORITY — asset registration requires a
   verifiable issuer credential whose revocation propagates.
10. INV-CREDENTIAL-PROVENANCE — every authority credential declares
    its issuer chain up to a genesis-registered root.

The discipline: adapter proliferation that outpaces invariant
enforcement is the failure mode the audits most warned about. The
ten-invariant gate is the structural defense.

## §8 Open problems — named, not solved

These problems do not admit a code-only solution. Naming them is the
only honest treatment.

### §8.1 Capital (audit H.1) — CRITICAL, no resolution

SCCGUB has no funding plan. The pace of v0.6.0 → v0.7.2 (eight
releases in one calendar day) is not a sustainable engineering
model — it is a Claude-Code-assisted burst. Maintaining a substrate
of this scale under sustained development requires either:

- A funded full-time team (no candidate funder identified), OR
- A foundation with corporate-sponsor model (no analogous corporate
  infrastructure stakeholder identified), OR
- A long-arc volunteer maintainer model (compatible with the
  technical work but incompatible with deployed-adopter timelines).

The audit's observation that Linux Foundation, W3C, Apache, and
Signal each had specific identifiable funding mechanisms — and
SCCGUB has none of those mechanisms available — is the load-bearing
gap. Resolution requires a non-engineering decision the project has
not made.

**Decision window (added to prevent open-ended drift)**: if no §8.1
resolution is committed by **2026-12-31**, the project formally adopts
**long-arc volunteer maintainer scope**, the §9 deployed-adopter
timeline extends to **5–10 years** rather than 3–5, and §9's
institutional-velocity narrative is updated to match. Re-evaluation
occurs annually thereafter and **is documented as an amendment to
this section**; if no amendment is filed in a given calendar year,
the volunteer-scope commitment **holds by default** for the
following year. This forces the question into a fixed surface rather
than letting "if we just keep going, funding will appear" run
indefinitely.

### §8.2 GDPR / right-to-erasure (audit H.2) — STRUCTURALLY ADDRESSED, deployment-conditional

The §4 off-chain discipline is the structural answer: regulated
content is destroyed at the off-chain layer; the on-chain hash
remains but cannot be used to reconstruct the pre-image without the
underlying data. This pattern is regulator-recognized and is the
basis on which other content-addressed substrates operate at the
EU/UK/CA boundary.

EU deployment specifically requires per-jurisdiction counsel review
of the content-addressing pattern as applied. SCCGUB is not yet
authorized as deployable in EU jurisdictions; a deployment claiming
GDPR compatibility must obtain its own counsel opinion. The
substrate provides the mechanism; it does not provide the
authorization.

### §8.3 Credential-issuance body (audit H.6) — UNDECIDED

§7's INV-CREDENTIAL-PROVENANCE requires authority credentials to
chain up to a genesis-registered root. SCCGUB has not named the
body that issues genesis-root credentials. Until this is named,
"governance runs on credential-bound precedence" is design intent,
not design.

The body's name, bylaws, funding model, succession plan, and
capture-resistance protocol are out of scope for any technical
patch. They are organizational decisions. Naming them is required
before adapter proliferation begins; naming them is not yet done.

The interim discipline: until the body is named, every authority
credential issued for testing or pilot purposes carries an explicit
"not-genesis-root" tag, so production deployment cannot depend on
unrooted credentials by accident.

### §8.4 Chain-break accounting (audit H.4) — STRUCTURALLY ADDRESSED, costed

PATCH_06 §34 specifies the live-upgrade protocol. PATCH_07 §B
([`docs/PRUNING_RESOLUTION_DESIGN.md`](docs/PRUNING_RESOLUTION_DESIGN.md))
specifies the activation-height pattern for breaking changes.
[`docs/FINANCE_EXTRACTION_PLAN.md`](docs/FINANCE_EXTRACTION_PLAN.md)
§6 specifies the migration mechanics for the finance extraction
specifically.

The mechanism is built; the cost is honestly priced (~3 months of
focused work per chain-version bump). What remains open is the
sequencing: how many bumps in what order over what calendar window.
Per the strategic guidance accepted in this document: **one
invariant per chain-version bump, sequential**, with two weeks
minimum on testnet between bumps. That sequencing is the discipline,
not a hard schedule.

### §8.5 Regulatory Precedent Gap (Audit pt3 H.14) — TWO-SIDED OPEN

**The barrier**: SCCGUB has zero production precedent for
cryptographically-bound-constitutional-immutability substrates in
any major regulated jurisdiction (EU, US, UK, Singapore). The
modern alternative stack (Cosmos-based deployments, Hyperledger
Fabric, EAS, W3C VCs) has years of established compliance patterns;
SCCGUB's pilot adopters in regulated domains will be **establishing
precedent, not following it.** Counsel review must reason about
novel substrate properties rather than relying on existing
compliance patterns. First adopters bear the cost of regulator
education.

**The upside**: whoever lands the first compliant deployment in a
regulated jurisdiction **writes the precedent** for that regime.
The institutional value of being the canonical reference deployment
in (e.g.) EU AI Act algorithmic-accountability registries is
asymmetric — every subsequent deployment in that category cites the
first.

**Deployment-readiness dependencies — none yet committed**:

- **Counsel engagement**: not yet contracted. Counsel review for a
  first-of-category substrate runs $200K–$500K per jurisdiction,
  longer than the standard 3–6 months.
- **Regulator dialogue**: not yet initiated. Regulators in EU/US/UK
  have not seen SCCGUB's submission package because the submission
  package does not exist yet.
- **Pilot partner**: not yet identified. The pilot partner is the
  institution that will operate the first deployment under counsel
  guidance; without one named, regulator dialogue has no concrete
  use case to anchor on.

This is named as **two-sided open**, not one-sided risk. The
substrate provides the property; the operator carries the precedent
risk; the precedent value accrues asymmetrically to the first
adopter that survives counsel review.

### §8.6 Post-Quantum Cryptography Migration (Audit pt3 G.4) — OPEN

Ed25519 is not post-quantum. **NIST PQC standardization deadline is
2030.** Every Ed25519 signature accumulated between now and PQC
activation becomes a forgery liability under a quantum-capable
adversary. SCCGUB's "designed for centuries" framing is structurally
incompatible with "signatures valid for ~4 more years" unless a
re-signing or hash-anchoring strategy is in place **before 2029**.

This problem is **parity-level with the alternative stack** —
Cosmos, Substrate, Ethereum, Fabric all face the same Ed25519 /
secp256k1 PQC migration cost. SCCGUB has no special exposure
relative to peers.

But SCCGUB has one **migration-harder property** unique to the
immutable-meta-governance niche: **you cannot retroactively rewrite
signature semantics under a new scheme if the constitutional
ceiling forbids it.** A naive PQC migration that changes signature
verification semantics (which it must) collides with the moat. The
mitigation pattern is hash-anchoring: rather than re-signing
accumulated H, anchor a Merkle root of all pre-PQC signatures into
a single PQC-signed checkpoint. This preserves the moat while
making the historical signatures verifiable under the new scheme.
Whether this satisfies the §11 ceiling-verifier semantics is a
spec question Patch-N must resolve.

**Open work** (Patch-N where N is TBD, but **before 2029**):

- **Candidate primitive selection**: NIST PQC finalists are
  Dilithium (signature), Falcon (signature), SPHINCS+ (signature).
  Choice is not yet made.
- **Activation-height window**: lead time relative to NIST 2030
  deadline must follow PATCH_06 §34 live-upgrade discipline plus
  an explicit re-signing budget. Conservative target: PQC
  activation by 2028, leaving 2 years of buffer.
- **Re-signing procedure for accumulated H**: the hash-anchoring
  pattern above is the proposed default; alternatives are
  (a) bulk re-signing under PQC (proportional in cost to history
  length), (b) accept-with-warning beyond declared cutoff (trust
  erosion). Spec must declare which is chosen.
- **Compatibility with §11 ceiling-verifier**: the PQC migration
  itself must NOT be a path that raises any ceiling. Verifier
  must explicitly recognize the PQC activation as a non-ceiling-
  raising chain-version transition.

The work is not optional; the deadline is fixed; the planning has
not started. Patch-N scope must commit by end of 2026 to avoid
last-minute compression.

## §9 Resource narrative — code velocity vs institutional velocity

These two velocities are categorically different. Conflating them is
the failure mode that produced the rejected "12 months to v1.0"
estimate.

**Code velocity** in this repo is high: 138 tests added in a single
session, 8 patch releases in one calendar day, 1155 → 1293 tests over
the v0.6.0 → v0.7.2 arc. With Claude-Code-assisted development and
disciplined patch scope, a code-complete v1.0 (Tier-2 primitives
phase-integrated, finance adapter extracted, two reference adapters
shipping) is **plausible in 6–12 months of part-time focused work**.

**Institutional velocity** runs on a different clock:

- Domain expert partnerships for adapters: 6–18 months per partnership,
  cold start.
- Regulatory counsel for any jurisdiction-specific deployment: 3–6
  months typical, longer for novel patterns.
- Foundation formation (if pursued): 18–36 months minimum for
  multi-stakeholder international.
- Pilot adopter conversations: 12–24 months B2B/B2G sales cycle on
  top of trust-building.

**The honest formulation**: v1.0-as-code in 12 months is plausible.
v1.0-as-deployed-with-real-adopters is **3–5 years from this
document's date**, not 12 months, and that is contingent on §8.1
resolution.

This document does not treat these timelines as predictions. It
treats them as scope boundaries. A roadmap claiming faster
deployed-adoption timelines without a corresponding §8.1 resolution
is not credible against current evidence.

## §10 Declined framings

The following framings appeared in earlier theses or README versions
and are formally retired by this document. Future contributions —
including by automated assistants — that re-introduce these framings
require positioning amendment first.

| Retired framing | Why retired |
|---|---|
| "Universal truth store" | Conflates aspiration with product. The substrate hosts governed assertions; it does not arbitrate truth. The framing also invites adoption claims (5% of scientific preprints, 5% of civic records) that have no accretion plan. |
| "Civilizational infrastructure" | Adoption outcome described as architectural property. Same accretion-plan problem. Also commits the project to a capital model (foundation-scale, multi-decade) that §8.1 does not have. |
| "No existing chain has governed attestation + messaging + value as uniform kernel primitives" | Marketing claim, technically false (Ethereum + EAS, Cosmos SDK, Hyperledger Fabric, Ceramic all approximate this). The real differentiator is precedence-as-first-class + 13-phase Φ + Mfidel grounding, which is genuinely uncommon, narrower, and defensible. State that instead. |
| "Six universal primitives" | Three of the six are compositions. Patch-07 shipped the 3+3 split. Future documents must use the corrected count. |
| "Wealth and authority structurally separated" | Holds only if credential issuance is wealth-independent. Per §8.3, the credential issuer is not yet named, so the separation is design intent, not design. State as such. |
| "Foundation-scale capital" (without naming a vehicle) | Named, not planned. Every reference to foundation funding must either name a candidate vehicle or be flagged as unresolved per §8.1. |
| "Mfidel-grounded uniqueness" | The 272-position matrix does not provide uniqueness. Per §5, Mfidel is semantic category; uniqueness comes from the public key. Future references must use the §5 formulation. |
| **"Symbolic governance as the primary moat"** | Audit pt3 (`docs/THESIS_AUDIT_PT3.md`) walked the symbolic layer (Φ + WHBinding + Mfidel + tension homeostasis) against Cosmos+VC+EAS+DID+Fabric and found parity or near-parity on every dimension except one. The genuine moat is **immutable meta-governance** (§1). The symbolic layer remains real and load-bearing for architecture; it moves from lead to supporting. See §10.2 for the substitute primary framing. |
| **"Moat as portfolio of novel properties"** | The earlier framing implied SCCGUB's defensibility came from a portfolio of unique properties (Φ, WHBinding, Mfidel, tension, ceilings). Audit pt3 showed the moat is **one property** (immutable meta-governance), not a portfolio. Future framings must not enumerate "what makes SCCGUB different" as a multi-item list; the answer is one property, named explicitly. |

### §10.2 Substitute primary framing (per Audit pt3)

The retired "symbolic governance + attestation substrate" framing is
replaced. Use **exactly** this language for README, status notes,
external descriptions, and any public material:

> **SCCGUB is a cryptographically-bound-constitutional-immutability
> substrate for institutions whose legitimacy depends on inability
> to modify their own foundations.**

The earlier "symbolic governance + attestation substrate" formulation
remains accurate as **internal architecture description** (§§3, 5)
but is not the lead-with framing. The symbolic layer is the
**mechanism** through which immutability is expressed and audited,
not the moat itself.

**Why this substitute is right**: it names the moat (immutable
meta-governance), names the niche (institutions requiring foundation
immutability per §1.1), and avoids both aspirational scope
("universal," "civilizational") and decorative properties (Mfidel
as primary, symbolic layer as primary). The framing is narrow,
specific, and externally verifiable via §11's ceiling-verifier.

### §10.1 Retirement-scope cleanup checklist (precondition for merge)

Retired framings retire **where they appear**, not only in this
document. Before this PR (POSITIONING.md merge) lands, the following
in-tree files MUST be reviewed and any retired-framings language
either removed, rewritten in compatible terms, or explicitly
contextualized as historical:

- [x] `README.md` — review status banner, headline framing,
  conformance-matrix prose
- [x] `docs/STATUS.md` — review capability framing
- [x] `EXTERNAL_AUDIT_PREP.md` — review summary line, scope
  paragraphs
- [x] `PROTOCOL.md` — check for aspirational language predating the
  audits; spec language as such is preserved, marketing prose is not
- [x] `PATCH_04.md`, `PATCH_05.md`, `PATCH_06.md`, `PATCH_07.md` —
  check for inherited framings; any "civilizational" / "universal" /
  "no existing chain has" style language gets cleaned
- [x] `CHANGELOG.md` — check release notes for marketing prose;
  release-note bullets stay factual

External surfaces (GitHub repo description, any external website,
docs.* domains if they exist, social-post copy) are tracked as
**separate action items in this PR's body**, not blocking merge —
they cannot be edited atomically with the in-tree files and require
operator action outside the repo.

The cleanup is a **precondition** for POSITIONING.md merge. A merge
without the cleanup is structurally inconsistent — the document
declares retirements while contradictions sit one directory away.

**Acronym carve-out**: the project's literal name expansion —
"Symbolic Causal Chain General Universal Blockchain" — is preserved
as historical naming in `README.md`, `EXTERNAL_AUDIT_PREP.md`, and
similar legal/identity surfaces. The phrase "General Universal" in
the acronym is not a current framing claim; it is the name the
project shipped under. It does not need to be edited and contributors
should not interpret the §10 retirements as requiring a project
rename. The retirements concern **marketing / aspirational prose
language**, not identifier strings or acronym expansions.

**Cleanup pass result for this PR (verified 2026-04-18 against main
@ b4c4daf)**: scan of the listed files for the seven retired
framings produced zero hits in `README.md`, `docs/STATUS.md`,
`EXTERNAL_AUDIT_PREP.md`, `PROTOCOL.md`, `PATCH_04.md`,
`PATCH_05.md`, `PATCH_06.md`, `CHANGELOG.md`. `PATCH_07.md` contains
"No 'civilizational infrastructure' public framing" — itself a
retirement declaration, retained. The audit documents
(`docs/THESIS_AUDIT.md`, `docs/THESIS_AUDIT_PT2.md`) contain the
framings as audit-record references and are preserved as historical
record per the same principle. The cleanup precondition is therefore
**satisfied** for in-tree files. External-surface action items
remain operator responsibility outside this PR.

## §11 Ceiling Verification — The Moat's Mechanical Correctness

The §1 moat (immutable meta-governance) is **structurally meaningful
only if it is externally auditable** by parties that do not trust
the maintainer. An institution evaluating SCCGUB for a constitutional-
court use case must be able to verify cryptographically that the
ceilings have not been raised since genesis, **without reading
source code or trusting maintainer claims**.

**The moat's existence depends on the ceiling mechanism's mechanical
correctness.** If governance finds a path around the ceilings, if
the encoding doesn't cover a parameter that should have been
covered, if the genesis-commit rule has an edge case, if the
canonical-encoding admits ambiguity — defensibility drops to LOW
**everywhere, not just in the niche**. The moat is one property,
and the property is one verifier.

**Patch-08 scope elevated**: from "nice-to-have verification"
(Audit pt3 H.15) to **moat-defining required deliverable**.
Concretely, Patch-08 commits to ship:

```text
verify_ceilings_unchanged_since_genesis(chain_state) -> Result<(), CeilingViolation>
```

The function's contract:

- **Input**: a chain identifier (genesis hash + chain-version-history
  trie state).
- **Output**: `Ok(())` if and only if every `ChainVersionTransition`
  from genesis to current tip preserved every
  `ConstitutionalCeilings` field at exactly its genesis value, OR
  returns the specific
  `(transition_height, ceiling_field, before_value, after_value)`
  tuple of the first violation.
- **Discipline**: pure function over chain history. Reproducible by
  any party with read access to the chain log. No node operation
  required.

**Externally-auditable property as structural commitment**: the
verifier must be runnable by **any third party** with access to
the chain's genesis block and current state, without trusting the
maintainer.

**Crate isolation commitment**: the verifier ships in a separate
audit-target crate (`sccgub-audit` or equivalent) with **minimal
dependencies** so it can be:

- Independently compiled by any reviewer in their own toolchain,
  without pulling in the full SCCGUB dependency tree.
- Cross-implemented by independent parties in alternative languages
  (Go, Python, TypeScript) to prove the verifier semantics are
  language-portable, not Rust-bound.
- Run as a standalone CLI (`sccgub-audit verify-ceilings
  --chain-state ./chain.snapshot`) by an external party without
  operating a full node.

**Suggested deployment-readiness target**: a public verification
endpoint operated by **no fewer than three independent parties**
(proves no single party can manipulate the verification result).

**Consequences for adopters and patches**:

- Until Patch-08 ships the verifier, any institutional pilot
  conversation that depends on the §1 moat must include
  "verifier ship date" as a deal-blocking dependency. The
  substrate cannot honestly sell its moat without the verification
  artifact.
- Patch-08 §X (verifier) is consensus-critical infrastructure, not
  auxiliary tooling. Test coverage requirement: **≥ 95%** on the
  verifier path including every ceiling field, every
  chain-version-transition variant, and every adversarial encoding
  case.
- Future patches that defer Patch-08 §X further require a
  positioning amendment under §13 explaining why the moat can
  credibly survive the deferral.

## §12 Non-goals

Explicit non-goals. Stated to prevent scope creep and to set
expectations clearly.

- **Not a general-purpose smart-contract platform.** The 13-phase Φ
  and constitutional ceilings constrain what can run; arbitrary EVM
  or WASM execution is not in scope. Adapters are the unit of
  extension.
- **Not a DeFi platform.** Finance is one adapter. The substrate is
  not designed for high-frequency trading, AMM operation, or
  derivatives. Adapter authors who build finance applications do so
  with the substrate's discipline, not its specialization.
- **Not a consumer crypto product.** No wallet UX work, no consumer
  onboarding, no exchange integration as a project goal. These are
  downstream products that may be built on the substrate by others.
- **Not a Bitcoin/Ethereum/Solana competitor.** Different category.
  Comparison to those is not the right reference class. The right
  reference class is permissioned attestation substrates: Hyperledger
  Fabric, Canton, Corda, Ceramic.
- **Not a "blockchain for everything."** §3 discipline limits what
  goes in the kernel. §7 discipline limits adapter proliferation.
  Both are deliberate.
- **Not a token launch.** Per §6.

## §13 What this document does and does not do

**This document does:**

- Declare SCCGUB's structural commitments at v1.0.
- Anchor every contestable claim to in-tree code, audits, or named
  open problems.
- Set scope boundaries (Mfidel jurisdictions, no-token economics,
  invariant tier gate).
- Retire prior framings that conflict with the structural
  commitments.

**This document does not:**

- Predict adoption.
- Promise timelines beyond the §9 honest formulation.
- Solve §8.1 (capital), §8.3 (credential body), §8.2 (per-
  jurisdiction GDPR authorization), §8.5 (regulatory precedent gap),
  or §8.6 (PQC migration plan).
- Authorize any specific adapter beyond finance extraction.
- Endorse the "civilizational infrastructure" framing.
- Endorse "symbolic governance + attestation substrate" as the
  primary framing (Audit pt3 retired this — see §10.2 substitute).

## §14 Amendment process

This document amends only by PR. A PR amending positioning must:

1. Cite the structural change being committed.
2. Identify which §1–§13 claims are affected.
3. Identify which audits, patches, or invariants need parallel
   amendment.
4. Pass the same CI bar as code patches.
5. Be reviewed against `docs/INVARIANTS.md` for consistency.

A patch that changes runtime behavior in a way that contradicts this
document **MUST** carry a positioning amendment in the **same PR**.
**Review by maintainer against §10's retired-framings list and §1–§13
structural commitments will reject otherwise.** CI does not currently
mechanically enforce positioning consistency; mechanical enforcement
(a CI script that parses `POSITIONING.md` retired-framings + structural
commitments and rejects PRs that introduce contradicting language) is
deferred to a future patch and explicitly scoped there. Until then,
maintainer review is the adjudication mechanism, and "in same PR" is
the procedural lock.

## §15 Concise restatement

SCCGUB is a **cryptographically-bound-constitutional-immutability
substrate** for institutions whose legitimacy depends on inability
to modify their own foundational rules — constitutional courts,
treaty bodies, indigenous data sovereignty councils, international
standards bodies, EU AI Act algorithmic accountability registries,
post-settlement legal archives. The genuine technical moat is one
property: **constitutional ceilings are genesis-write-once and not
modifiable by any governance path, including the governance path
itself.** That property is moat-defining only if the
`verify_ceilings_unchanged_since_genesis(...)` verifier (§11) ships
correctly. The supporting disciplines — three irreducible kernel
primitives (ValueTransfer, Message, Attestation), content-addressed
off-chain storage for large or sensitive payloads, Mfidel-grounded
semantic identity over Ed25519 unique identifiers, no native token,
fees in user-supplied currencies, two-tier invariant gate (§7) on
adapter proliferation — are real but not the moat. **Six open
problems** that no code patch can close: capital, GDPR
jurisdiction, credential body, chain-break sequencing, regulatory
precedent gap, PQC migration. The substrate is code-complete-
plausible in 6–12 months of part-time focused work and
deployment-credible in 3–5 years contingent on §8.1. It is not a
universal truth store, not civilizational infrastructure, not a
DeFi platform, not a token, **not a "symbolic governance" substrate
as the lead framing**. It is **infrastructure for institutions that
cannot afford to be able to modify their own foundations.**
