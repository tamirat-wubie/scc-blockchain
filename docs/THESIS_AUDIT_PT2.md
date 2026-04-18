<!--
Purpose: Companion audit to docs/THESIS_AUDIT.md (PR #33). Audits the claims
introduced by two newer thesis documents:
  (1) "Refined — Money as a Cross-Domain Communication Primitive"
  (2) "SCCGUB — Final Refined Architecture"

that introduce material new structural claims not present in the earlier theses:
  - six universal primitives (ValueTransfer, Message, Escrow, Attestation,
    Reference, Supersession)
  - three-tier "rigidly separated" architecture
  - MUL native token with "zero governance weight"
  - 12-month roadmap to v1.0
  - authority-credential-based governance separated from wealth

Scope: diagnostic only. Assumes the reader has read THESIS_AUDIT.md Part 1.
This Part 2 focuses exclusively on **new structural claims** and does not
re-litigate claims already audited in Part 1.

Date: 2026-04-18. Repo at v0.6.5, main @ e969afd.
-->

# Thesis Audit — Part 2 (Six Primitives / Three Tiers / MUL Token)

**Companion to**: [docs/THESIS_AUDIT.md](THESIS_AUDIT.md) (PR #33).
**New claims audited**: six universal primitives, three-tier rigid separation,
MUL token with zero governance weight, 12-month v1.0 roadmap.
**What stays**: every finding from Part 1 still stands. Part 2 adds rather than
replaces.

## A) Structural Weakness Summary — new surface

The two newer documents tighten the architecture meaningfully — the "three-tier
with six Tier-2 primitives" framing is structurally more coherent than the
"governance kernel + adapters" framing of Part 1. Honest credit: the new
documents are the first version of the thesis where the kernel stays thin by
construction rather than by aspiration. That is a real improvement.

Concentration of **new** weakness:

- **"Six" is rhetoric, not structure.** Four of the six primitives decompose
  into the other two. Escrow is a templated Message+ValueTransfer with a
  predicate. Reference is a pointer that can be encoded in Attestation's
  `causal_anchor`. Supersession is an Attestation with a specific schema
  claim and a pointer to the superseded tx. The irreducible set is closer
  to **three**: ValueTransfer, Message, Attestation — with Escrow,
  Reference, and Supersession as structured compositions on top. Calling
  them all "kernel primitives" inflates the kernel surface.
- **MUL token with "zero governance weight" moves power, does not
  eliminate it.** Governance does not disappear when wealth cannot govern;
  it migrates to whoever issues authority credentials. The documents do
  not name the credential issuer. In every working precedent (W3C, Linux
  Foundation, ICANN, IETF) the issuing body is the capture target. "No
  token-weighted governance" solves plutocracy by introducing
  foundation-capture, which is the same problem with different clothes.
- **"Rigidly separated" three tiers contradicted within the same
  document.** The architecture table in §10 of the Final Refined doc
  labels Tier 2 "semi-frozen; extensions via constitutional governance."
  §11 says "Tier-2 primitives need to be frozen early because every
  adapter depends on them." Either changing Tier 2 is possible (weak
  separation) or it is not (brittle upgrade path). The document picks
  both, back-to-back, in the same file.
- **The "≥3 shape-of-truth domains" discipline has no enforcement
  mechanism.** §5 of Final Refined calls it the kernel's keystone rule.
  No Φ_gov predicate evaluates proposed Tier-2 additions against this
  rule. No code check exists. The rule is a sentence in a roadmap
  document, enforced by discipline — the same discipline the document
  names as "the hardest in platform engineering."
- **12-month roadmap to v1.0 is priced at unfunded-solo-developer pace.**
  At that pace Patch-04 through Patch-06 would have taken 6–9 months each
  rather than the 1–2 weeks each they actually took in this session with
  Claude Code assistance. The 12-month estimate has no team-size or
  assistance model behind it; scaling to 3–5 reference adapters inside 12
  months requires 5–10 person-years of focused work and there is no
  stated resource plan.

## B) Invariant Failures (new)

Invariants implicit in the six-primitive model that are not held by the
design as specified:

| Implicit invariant | Status | Breakage mode |
|---|---|---|
| **Escrow predicates are decidable in bounded steps** | **UNDECLARED** | `ConditionExpr references adapter predicates`. An adapter can supply a predicate that does not terminate, or that costs O(N²) gas. Kernel has no step-bound on escrow predicate evaluation. A single rogue adapter installs an unbounded predicate, locks every escrow referencing it until the adapter is retired. |
| **Messages cost proportional to their H-retention cost** | **UNDECLARED** | Message bodies are arbitrary `Bytes`. Every message lives in H forever. At 1KB per message × 1000 msgs/block × 10⁷ blocks = 10 TB of append-only storage per chain-lifetime. No size cap, no per-byte fee, no compression rule. Messaging is a DoS vector against the substrate itself. |
| **AssetRegistry admits only authorities with provable legitimacy** | **UNDECLARED** | "AssetRegistry — typed registry where adapters/authorities register value-bearing assets." No admission predicate specified. A malicious adapter can register a token named "USDC" with attacker-controlled supply. Kernel cannot distinguish legitimate issuer from impersonator. |
| **Authority credentials are verifiable cross-jurisdictionally** | **UNDECLARED** | "Governance runs on credential-bound precedence." No credential format, no issuer federation, no revocation path, no cross-jurisdictional verification. A credential issued by Authority X in jurisdiction A has no defined trust relationship to Authority Y in jurisdiction B. Governance works only within federations with prior trust. |
| **Supersession is globally consistent** | **UNDECLARED** | If fact F1 is superseded to F2 in one validator's view and to F3 in another's (because two authorities race to supersede), how is the canonical supersession chosen? The document shows `supersedes: Option<TxRef>` on Attestation — implying the first link wins — but does not declare it. INV-SUPERSESSION-UNIQUENESS is required. |
| **Cross-domain references honor target-domain authority** | **UNDECLARED** | `Reference { source_domain, source_key, target_domain, target_key, kind }`. Nothing prevents adapter X from publishing a `Cites` reference to adapter Y's private keyspace entry. The reference is cryptographically authentic but semantically unauthorized. |

**New invariants required but undeclared:**

- **INV-ESCROW-DECIDABILITY** — escrow predicates must terminate in
  bounded steps with bounded gas, enforced at install time.
- **INV-MESSAGE-RETENTION-PAID** — every byte of Message body must pay a
  retention fee proportional to expected H-lifetime storage cost.
- **INV-ASSET-REGISTRY-AUTHORITY** — asset registration requires a
  verifiable issuer credential whose revocation propagates to the asset.
- **INV-CREDENTIAL-PROVENANCE** — every authority credential must declare
  its issuer and the issuer's own credential, forming a verifiable chain
  up to a genesis-registered root.
- **INV-REFERENCE-DISCOVERABILITY** — a referenced target must permit
  discovery-by-source, or the reference is a one-way leak of target's
  keyspace with no target-side recourse.

## C) Assumption Map (new assumptions introduced)

| # | Assumption (new in pt-2 docs) | Label | Collapse mode |
|---|---|---|---|
| N1 | "No existing chain has governed attestation + messaging + value as uniform kernel primitives with cross-domain composability" (§7) | **CRITICAL-false** | Ethereum + EAS + EIP-712 + ERC-4337 approximates this today. Cosmos SDK modules do this natively. Substrate pallets do this natively. Hyperledger Fabric's channel+chaincode model does this at enterprise scale. The claim is marketing, not technical fact. |
| N2 | "Wealth and authority are structurally separated" (§8 discipline 2) | PLAUSIBLE-aspirational | Structurally separated only if credential issuance is wealth-independent. In practice, credential issuers need funding, funding comes from somewhere, and the capital source influences issuance. Separation in theory; entanglement in funding reality. |
| N3 | "H is sacred; nothing is ever removed" (§8 discipline 4) | PLAUSIBLE-regulatorily-infeasible | Already flagged in Part 1 §E. The new documents **repeat** the claim without addressing GDPR. "Privacy concerns handled through encryption and off-chain references" is the proposed answer; encryption keys rotate, get compromised, or are lost, and off-chain references defeat the "H is sacred" invariant by making the referenced content not actually retained. |
| N4 | "MUL has fixed or capped supply" (§6) | FRAGILE | Fixed supply + growing utility = fees rise → users priced out → adoption stalls. Capped supply with halving schedule reproduces Bitcoin's well-documented scaling problem. Neither is specified; "fixed or capped" is hand-waved. |
| N5 | "12 months focused work from v0.3 to v1.0" (§9) | CRITICAL-unfunded | No team, no capital, no assistance model. At the pace of real solo open-source work (~5-10 hrs/wk of focused effort), 12 months yields Tier-2 primitives and possibly one adapter extraction. v1.0 with three live adapters is 3–5× the calendar estimate. |
| N6 | "Authority credentials bound to Mfidel-sealed identities" (§6) | FRAGILE | Mfidel identity is a position in the 34×8 atomic matrix (272 positions). At scale, multiple real-world authorities will share identity positions. Mfidel grounds identity **symbolically**, not uniquely. The "bound to" relationship is structural handwaving. |
| N7 | "Adapter lifecycle is a governance action" (§5) | PLAUSIBLE-weaponizable | Constitutional-level adapter install means a captured constitutional quorum can install malicious adapters. The thesis treats this as elegance; it is also attack surface. |
| N8 | "Domain adapters are hosted, not embedded" (§8 discipline 3) | PLAUSIBLE | Only if the adapter runtime is sandboxed with resource limits. The spec does not name a VM, WASM runtime, or step-metering model for adapter execution. Native Rust adapters compiled into the node binary are not "hosted" in any meaningful sense. |
| N9 | Shape-of-truth taxonomy has 10 categories × ~6 examples each (§5) | UNSUPPORTED | ~60 example adapter domains listed. Project has zero domain experts for ~55 of them. Architecture scales; domain expertise does not. Every adapter needs expertise the project cannot supply. |
| N10 | "Bridge and exchange integration" as revenue surface (§6) | FRAGILE | Exchange listings require (a) liquidity (needs market makers, needs capital, needs demand), (b) compliance (KYC/AML surface the thesis otherwise avoids), and (c) ongoing operational commitment. None specified. |

## D) Scaling Collapse Points (new)

The new primitive surface introduces its own scaling collapse points that
the documents do not acknowledge.

- **D.11 Messaging-in-H unbounded.** Kernel-level messaging with no size
  cap means every block can append arbitrary bytes to the forever-retained
  lineage. At 1KB × 1000 msgs/block × blocktime 2 minutes × 1 year ≈ 260 GB
  of message payload per chain-year. At the "civilizational infrastructure"
  target of multi-decade retention, message storage dominates state
  storage. First bottleneck: node-disk cost at year 2, before any
  "civilizational adoption" materializes.

- **D.12 Escrow-predicate evaluation per block.** Every escrow with a
  non-trivial predicate is re-evaluated every time its predicate's inputs
  could change. At 10⁴ active escrows × 10 inputs each = 10⁵ evaluations
  per block. This assumes constant-time predicates. Any predicate that
  walks H (e.g., "unlock when N superseding attestations exist") is O(|H|)
  per evaluation.

- **D.13 Cross-domain reference graph walk.** §7's worked example shows a
  9-step causal chain across 3 adapters. At real cross-domain composition
  scale (a scientific finding referenced by 100 downstream works, each
  referenced by 100 more), graph walks are O(10⁴) per query. No index is
  proposed. First bottleneck: API layer read latency at year 1 of
  adoption.

- **D.14 AssetRegistry as monotonic set.** Asset registrations accumulate.
  No retirement rule. At 10⁵ registered assets, every value-transfer must
  validate asset-id against a 10⁵-entry table. Hashmap lookup is O(1)
  per-tx but the registry itself is state-root-committed, so hash
  recomputation scales with registry size.

- **D.15 Credential issuance throughput.** If authority depends on
  credentials and credentials must be issued for every new authority-
  bearing identity (every scientist, every judge, every regulator), the
  issuance rate is the network's governance-scaling bottleneck. Projection:
  10⁶ authorities globally, average 30-year credential lifetime, means
  ~30,000 issuances per year steady-state. Above the rate at which any
  single foundation body can authenticate without outsourcing, and
  outsourcing re-introduces the foundation-capture problem.

## E) Regulatory Exposure (new)

The MUL token is a new regulatory surface not present in Part 1's analysis.

- **Howey / ICO precedent**: A native token that is marketed, listed on
  exchanges, and whose value accrues from platform adoption is
  prima-facie a security offering in the US, post-Ripple. "Zero
  governance weight" is not a defense — Ripple ruled on economic
  expectation, not governance rights.
- **MiCA (EU) Art. 16-18 asset-referenced token rules**: If MUL is used
  for platform fees and is pegged to any reference value via market
  pressure (bridges to USDC), MiCA treats it as an asset-referenced
  token; full white-paper and reserve requirements apply.
- **Commodity vs currency classification**: Fixed-supply MUL used for
  payment is commodity-adjacent (Bitcoin precedent); variable-fee MUL
  used for governance of services is utility-token-adjacent; both
  classifications trigger CFTC/SEC overlap in the US.
- **Money transmission**: The kernel's ValueTransfer primitive
  implemented as a service = money transmission under BSA if operators
  custody MUL. Decentralization is not a defense under FinCEN 2019
  guidance.
- **Exchange listing requirements** (referenced in §6): KYC/AML compliance
  for MUL holders the moment MUL reaches a centralized exchange. This
  contradicts the truth-store thesis's appeal to pseudonymous
  scientific/cultural/civic authorities who may not want wallet-level
  identification.

**Net**: adding MUL **triples** the regulatory footprint vs. Part 1's
analysis. The thesis treats MUL as an operational detail; it is the
single most regulatorily-loaded decision in the architecture.

## F) Competitive Pressure (delta from Part 1)

Re-examining competitors against the newly-specific architecture:

- **Ethereum + EAS (Ethereum Attestation Service)** now maps to
  Attestation + Reference + Supersession in the new architecture.
  Already has 100K+ attestations in production. Documents claim §7's
  worked example is "impossible on any existing chain." It is not; it
  has been done on Ethereum with EAS schemas + ERC-20 transfers + typed
  messages. SCCGUB's advantage over EAS is constitutional-grade
  governance and kernel-level primitives; EAS's advantage is existing
  adoption.
- **Hyperledger Fabric** channels with private data collections implement
  domain adapters with asset registries and attestation flows today.
  Production banking deployments (BankClear, we.trade-successor). The
  new documents do not address this competitor at all.
- **Hypercore Protocol (prev. Dat)** implements append-only lineage with
  cross-log references and strong versioning for exactly the
  civilizational-archive use case. Lower ambition, shipping since 2017.
  Not mentioned.
- **Radicle** is append-only, governance-capable, multi-domain-adapter
  (code, issues, patches), operates without a token, uses Ed25519
  identity. Direct architectural overlap. Not mentioned.

**Structural competitive finding (delta from Part 1)**: the newer docs
specify the architecture in enough detail to directly compare to
production competitors. That comparison is weaker than the Part 1 survey
suggested. Existence of a native token and constitutional-level
governance are the two genuine differentiators; every other claimed
differentiator is shared with at least one in-production competitor.

## G) Adversarial Attack Surface (new)

Specific to the six-primitive design:

- **G.9 Escrow lockup attacks.** Predicate that evaluates slowly →
  escrow validation DoS. Predicate that never returns true → permanent
  value lockup. Predicate referencing a soon-to-be-retired adapter →
  orphaned escrows after adapter retirement.
- **G.10 Message-body exfiltration.** Kernel-level messaging with
  optional encryption means unencrypted message bodies are publicly
  readable forever. Adapter authors will leak PII in messages because
  encryption is optional. One adapter that sends unencrypted health
  messages through the kernel is an HIPAA incident for the substrate.
- **G.11 AssetRegistry brand confusion.** Attacker registers "USDC" as an
  asset before the legitimate Circle USDC adapter does. Every subsequent
  transfer "in USDC" goes through the attacker-controlled asset. Kernel
  has no trademark or brand-protection concept; first-registrar wins.
- **G.12 Supersession chain griefing.** Attacker floods
  self-superseding attestations (F → F' → F'' → ...) to bloat the
  fact-graph with no semantic value. If supersession is fee-gated,
  legitimate correction is expensive; if not, the ledger fills with
  noise. No middle-ground proposed.
- **G.13 Cross-domain reference spam.** Attacker publishes `Reference`
  objects pointing from their attacker-controlled domain to every
  record in a target domain. Queries against the target domain now
  return attacker data in reference lists. Kernel has no filter
  semantics.
- **G.14 Authority-credential black market.** If credentials confer
  governance power and are bound to Mfidel-sealed identities, a market
  for compromised credentials emerges. No revocation protocol declared.
- **G.15 Foundation capture.** Per §6, MUL governance weight is zero —
  therefore all governance power concentrates in whoever issues
  authority credentials and whoever controls the foundation. This is a
  single point of failure at the institutional-governance level,
  disguised as "separation of concerns."

## H) Fracture Ranking (Part 2 specific)

Top 5 **new** collapse points introduced by the pt-2 architecture:

### H.6 The foundation/credential-issuer is the actual capture target

Severity: **CRITICAL**. "Wealth and authority separated" is achieved by
moving authority to credential issuers. Credential issuers are unnamed,
unfunded, ungoverned, and unbounded in power. The entire
civilizational-infrastructure thesis turns on a single trust root the
document does not describe.

**Containment**: name the credential-issuance body, its bylaws, its
funding model, its succession plan, its capture-resistance protocol.
Until this is a concrete document, "governance runs on authority" is a
rhetorical flourish, not a design.

### H.7 MUL is a regulatory tripwire not a token

Severity: **CRITICAL**. Minting, listing, bridging, or marketing MUL in
any jurisdiction triggers one or more of: securities enforcement, MiCA
compliance, money-transmission licensing, KYC/AML requirements.
"Fixed or capped supply" does not change the classification; it defines
it.

**Containment**: either publish a securities-law analysis with counsel
opinion per-jurisdiction, or redesign the economic model around
user-supplied fee currencies (USDC, local stablecoins) without a native
token. The latter is structurally simpler and regulatorily survivable.

### H.8 Message primitive is a silent DoS against the substrate

Severity: **HIGH**. A design choice that stores arbitrary bytes in
append-only lineage forever, with optional encryption, has no credible
sustained-adoption story. First real adopter sending large bodies (a
cultural-heritage adapter uploading manuscript scans, a scientific
adapter uploading datasets) collapses node disk economics.

**Containment**: either (a) cap message body to ≤1KB and require
external storage + content-hash for anything larger, or (b) remove
Message from kernel primitives and let adapters layer on top of
Attestation+Reference. Option (b) is cleaner and reduces kernel surface.

### H.9 "Six primitives" is four primitives with marketing

Severity: **MEDIUM-HIGH**. Escrow, Reference, and Supersession are
compositions. Defining them as kernel primitives locks the kernel
into their current shape before any adapter has validated that shape.
Worse, future adapters that need slightly-different supersession
semantics must either reuse the frozen primitive (accepting its
limits) or re-implement supersession in-adapter (defeating the
kernel's claimed role).

**Containment**: promote only ValueTransfer, Message, and Attestation
to kernel primitives. Offer Escrow, Reference, and Supersession as
**standard-library templates** compiled from primitives, not as
frozen kernel verbs. Adapters can vary the templates without kernel
surgery.

### H.10 The 12-month v1.0 timeline has no resource plan

Severity: **HIGH**. Every milestone in §9 is labelled 1–4 months.
Summed, the total is 11 months. This assumes sustained unknown-velocity
development. v0.6.5 sits at 1233 tests with 62K LOC after significant
assisted-development acceleration; reaching v1.0 with three live
adapters requires roughly 3× that surface. No team size, funding
source, or pace assumption is given.

**Containment**: publish a concrete resource plan. Either (a) this is
a full-time funded effort with N engineers, name N and funding source,
or (b) this is part-time hobby-to-research-project, extend timeline to
3–5 years and market accordingly.

## I) Survival Estimate (Part 2 specific)

Adjusting the Part 1 survival table for the new architecture:

| Phase | Part 1 estimate | Part 2 estimate | Rationale |
|---|---|---|---|
| v0.4 — Tier 2 primitives | n/a | LOW–MEDIUM | New claim. 6 primitives at 2–3 months is aggressive; Message and AssetRegistry alone are 3 months each if done right. |
| v0.5 — Adapter API | MEDIUM | LOW | Adapter trait is 1–2 weeks of design but an enforced registry with namespace isolation is a chain-breaking change on top of Patch-06 §34's upgrade path — 3+ months. |
| v0.6 — Finance extracted | LOW | LOW–VERY LOW | Part 1's chain-break analysis still holds; pt-2 docs do not address it. |
| v0.7 — Second adapter | LOW | VERY LOW | Requires domain expert partnership that does not exist. |
| v1.0 at 12 months | n/a (not named) | VERY LOW | Sum of pessimistic estimates on individual milestones is 18–36 months even at assisted-development pace, with no domain experts. |
| MUL economics surviving first-year securities review | n/a | LOW | Securities counsel is expensive and will return "do not list" with high probability. |
| Credential-issuance body founded by month 18 | n/a | VERY LOW | Founding a credible multi-stakeholder credentialing body takes 3–5 years minimum (W3C, IETF, Unicode Consortium all multi-year precedents). |

**Net position**: the new architecture is structurally cleaner than Part 1's
target, but each new structural commitment (MUL, credential-issuance body,
three-tier rigidity, six primitives) adds timeline, regulatory exposure, and
capture surface. The thesis ambition and the thesis resource plan are
mis-scaled against each other.

---

## Concise decision framework

If the user is deciding what to do next with the thesis, the audit suggests a
reduced-commitment path:

1. **Ship the adapter refactor as engineering work, without the
   civilizational-infrastructure framing.** The `DomainAdapter` trait,
   namespace enforcement, and finance extraction are valuable on their own
   merits — they clean the kernel regardless of whether the truth-store
   thesis is ever pursued. Time-box to 4–6 months of code work.

2. **Defer MUL economics until after first adapter is live.** The token is
   the highest-regulatory-risk component; building it speculatively
   before there is production usage is pure downside.

3. **Replace "six primitives" with "three primitives plus three
   standard-library templates."** This halves the kernel's frozen
   surface and preserves adapter expressivity.

4. **Do not claim "civilizational infrastructure" in any public
   document.** The claim invites comparison the substrate cannot yet
   win, and commits the project to a capital model it does not have.

5. **Resolve the four open invariants from Part 1 §B and the six new
   invariants from Part 2 §B before any new adapter work.** All ten
   are structurally required; none are optional.

---

**End of Part 2 audit.** Diagnostic, not constructive. This document does
not argue the theses are wrong. It argues they are under-specified in
several places that matter structurally and regulatorily, and that the
cleaner architecture gains from the newer documents are offset by the
larger surface area they commit to. The reduced-commitment path above is
a way to capture the gains without paying the full cost of the full
thesis until the evidence for the thesis is stronger than the current
repo's accumulated wins can support.
