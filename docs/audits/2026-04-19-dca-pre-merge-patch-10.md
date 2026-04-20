# Deterministic Causal Audit — PATCH_10 (pre-merge)

**Date:** 2026-04-19
**Target:** `PATCH_10.md` draft (§38 symmetric ceiling, §39 forgery-veto decoupling, §40 DCA-before-merge §13 amendment)
**Method:** Adversarial review against the DRAFT state. Status quo not re-audited.
**Reviewer:** DCA agent (general-purpose subagent, context-isolated from drafter).
**Scope constraint:** Only fractures *introduced or exposed by the draft*. Pre-existing fractures (quorum-collusion capture, regulatory lock-in, state growth, fork-choice, evidence-submission incentive) are out of scope per §42.

This is the **bootstrap invocation** of the PATCH_10 §40 adversarial-review-before-merge discipline. The rule being adopted required itself to be applied to its own adoption.

---

## A) Structural Weakness Summary

PATCH_10 closes three fractures cleanly at the *spec* layer but introduces three new coupling surfaces:

1. **§38 symmetric ceiling check operates on a mutable ceiling.** The Rev-2 check evaluates "resulting `(ceiling, param)` pair at `activation_height`." If two overlapping governance proposals are in flight (one moves param, one moves ceiling) and activate within 200 blocks of each other, the submission-time check can green-light a pair that *becomes* invariant-violating only through the second activation. Submission rejection is not sufficient unless the check also re-evaluates at activation or the submission snapshot serializes proposals.
2. **§39 moves a Safety-level authorization decision into the evidence layer.** This eliminates the timelock mismatch but also removes the deliberative / vote-aggregation semantics that Safety-level governance provided. A single block producer's `VetoAttestation` sign-off, plus a valid `ForgeryProof`, is sufficient to cancel a synthetic Remove. The attestation-quorum threshold is "**at least one** active-set signer" per §39.3 rule 3 — that's a 1-of-N authorization on a slashing cancellation. Compare with PATCH_06 §30, which at minimum routed through governance admission.
3. **§40 creates an unbounded, governance-binding artifact class (`docs/audits/`) whose integrity is asserted by a meta-invariant with no runtime checker.** The rule is enforceable only by social review until `sccgub-audit verify-review-artifacts-present` ships — a future-patch dependency that §40.5 names but does not schedule.

Layer-1 invariant closure is real for §38/§39. Layer-2 coupling and Layer-3 procedural exposure are new.

---

## B) Invariant Failures

### B.1 Declared invariants with ambiguous enforcement

| ID | Ambiguity |
|---|---|
| **INV-CEILING-PRESERVATION-SYMMETRIC** (§38.4) | States the pair relation must hold "at every v5 height H," but §38.3 enforces only at *submission*. If two ceiling-affecting proposals with overlapping activation windows are admitted independently (each is valid against the then-current state, but their joint activation violates the invariant), submission-time rejection does not catch the race. §38 does not specify whether a queued-but-not-activated proposal is part of "current on-chain value at the check height." It reads as "current committed state," which is the attack. |
| **INV-FORGERY-VETO-FEASIBLE** (§39.5) | "Structurally invocable within the activation-delay window" is weaker than "can always be admitted." With `activation_delay = 3` (default k=2), `max_forgery_vetoes_per_block = 4`, and a mass-evidence attack (16 evidence records admitted in one block, per §15.7 ceilings), only 4 × 3 = 12 vetoes fit in the window. Four legitimate forgery vetoes are **provably un-admittable** per-block regardless of their validity. INV-FORGERY-VETO-FEASIBLE as worded is false under adversarial mass-evidence load. |
| **INV-ADVERSARIAL-REVIEW-ENFORCED** (§40.5) | Called a "meta-invariant, not checked by the runtime verifier." An unverified invariant is a convention, not an invariant. The §40 text binds merges, not `main`-branch state — a maintainer with direct-push permission bypasses it with no detection until post-hoc `git log` walk. The gating mechanism is GitHub branch protection, which is configuration, not protocol. |

### B.2 Missing invariants required for safety of the new surface

| Missing | Why critical |
|---|---|
| **INV-CEILING-PROPOSAL-SERIALIZABILITY** | §38 requires that concurrent ceiling/param proposals cannot jointly activate into an invariant violation. Not stated. |
| **INV-FORGERY-VETO-ATTESTATION-QUORUM** | §39.3 rule 3 requires ≥1 active-set signer. No quorum threshold. A single colluding validator can cancel any synthetic Remove targeting a colluder, provided a `ForgeryProof` is constructible — and §G.1 of the prior audit already noted that non-canonical signatures are constructable by a misbehaving signer. The attacker is also the forger. |
| **INV-FORGERY-VETO-NON-TARGET** | §39 does not prohibit a validator V from vetoing its own synthetic Remove using its own `VetoAttestation`. Self-veto via self-constructed forgery proof is not forbidden by the rule text. |
| **INV-AUDIT-ARTIFACT-INTEGRITY** | §40 requires an artifact under `docs/audits/`, but does not require the artifact be produced by an adversary-non-colluding agent, nor that its findings be non-trivial. A 200-word "zero fractures found" artifact satisfies §13.N literally. |
| **INV-PATCH-GATE-CLEARING** | §40.2 rule 3: `patch-gate` label "blocks future PRs from merging while that label is open." Label management is a GitHub convention, not a protocol rule. The label can be removed by a maintainer without protocol-visible state change. |

---

## C) Assumption Map

### C.1 VERIFIED

- Governance timelock is 200 blocks for Safety-level proposals (PROTOCOL.md §254).
- `activation_delay = clamp(k+1, 2, k+8)` with k=2 yields 3 by default; ceiling 10 (§39.1).
- `max_forgery_vetoes_per_block_ceiling=8` is field #19, requiring cross-language port sync (§39.4, §41).
- The Rev-2 submission check is a strict superset of Rev-1 at submission time (§38.5).

### C.2 PLAUSIBLE

- Real-world legitimate forgery attempts are rare (§39.4 rationale). Plausible historically; cryptographic-library supply-chain attacks make this weaker than the draft claims. A compromised ed25519 library shipping to N validators produces N concurrent forgery events.
- A 1-of-N attestation is "sufficient authorization" because the `ForgeryProof` itself is cryptographically verifiable (§39.3 rules 2 + 4 composed). Plausible if the forgery predicate is sound, fragile if the predicate is ever found to admit edge cases.
- The 200-block ceiling activation window is enough separation that the inflight-race scenario (B.1 row 1) is "not a realistic concurrent submission surface." Plausible for honest operators; actively adversarial governance submissions can time proposals to overlap.

### C.3 FRAGILE

- **"Submission-time check is sufficient"** (§38.3). Holds only if no other mutation can occur between submission and activation. §17.2 has 13+ pairs; any overlap with another in-flight ceiling-or-param proposal defeats it.
- **"Evidence-layer veto does not need governance deliberation"** (§39.2 rationale). Removes the one veto path where a *social* quorum could reject a specious forgery proof. All verification is now cryptographic. Any cryptographic admissibility bug becomes a direct slashing-cancellation vector with no social brake.
- **"No pre-PATCH_10 chain admitted a governance-routed ForgeryVeto because the mechanism was un-invokable"** (§39.7). True at the timelock-arithmetic level. Does not address the possibility that a pre-PATCH_10 `ForgeryVeto` proposal is *in-flight* at the moment PATCH_10 activates — §39.6 says it's "rejected at submission" post-activation, but does not specify what happens to an already-submitted, queued, not-yet-activated `ForgeryVeto` proposal at the PATCH_10 activation boundary.
- **"`docs/audits/YYYY-MM-DD-<topic>.md` format"** (§40.2 rule 2). The filename convention has no collision-handling rule. Two PRs merging on the same date produce identical prefixes; `<topic>` disambiguation is free-form and not enforced.

### C.4 CRITICAL

- **Assumption A1:** The forgery-proof predicate (`both sigs verify, at least one fails verify_strict`, over same canonical bytes) is cryptographically sound and cannot be satisfied by non-malicious signer error. If an ed25519 upgrade ever produces legitimate sig pairs satisfying this predicate, §39 becomes a universal slashing-veto oracle.
- **Assumption A2:** `max_forgery_vetoes_per_block=4` is large enough to handle "real" forgery storms. See B.1 row 2 — defeated by a 16-evidence-per-block adversary. Capacity is a **ceiling**, not a rate; replenishment does not exist.
- **Assumption A3:** Adversarial reviewers (§40) are actually adversarial. The §40 rule requires "an agent not involved in drafting," but the agent can be an LLM configured to be deferential, a human on the drafter's team, or a minimum-effort auditor. Rule text specifies *separation of actor*, not *separation of incentive*.
- **Assumption A4:** The `patch-gate` label (§40.2 rule 3) is honored by the repository's branch protection. This is infrastructure-configuration-dependent, not protocol-enforced. Absent a CI check that blocks merge based on label presence, the rule is advisory.

---

## D) Scaling Collapse Points

### D.1 Forgery-veto throughput vs. evidence throughput

Under the §15.7 ceilings (16 evidence per block) and §39.4 defaults (4 vetoes per block), the throughput ratio is **4:1** — the veto layer can rebut only one quarter of evidence per block. Under a targeted mass-forgery attack on one active-set validator, a legitimate forgery-vetoer has a 3-block window (`activation_delay = 3`) × 4 vetoes = 12 slots to rebut 16 evidence records. Four slashings proceed with *valid forgery proofs in existence but no admission slot*. The `_ceiling` of 8 permits governance to raise the param to 8, yielding 24-slot capacity — still under 16×3 = 48 ceiling-case evidence slots when raised to max.

### D.2 `docs/audits/` unbounded growth

§40.2 rule 2 appends one `.md` per merged consensus-critical PR. At the observed PR cadence of ~5/week on `main`, this is ~260 `.md` files per year in a single directory, each ~2000–5000 words. Git object growth is linear and survivable, but filesystem ls-time and tooling discovery degrade. §40.5 names `verify-review-artifacts-present` as a future extension; that checker will need to walk the entire history, an O(N) operation growing with every merge.

Not a collapse, but an unbounded append-only registry — the same structural pattern the prior audit flagged for `validator_set_change_history` and `key_index`. The draft does not specify pruning, rotation, or archival.

### D.3 Governance-queue interaction with §38

§38.3 submission-rejects proposals whose hypothetical activation would violate the pair invariant. This introduces a **stateful computation at submission** — the node must compute the resulting `(ceiling, param)` pair for every proposal against every other *in-flight, not-yet-activated* proposal, or the serializability assumption in C.3 fails. The rule text does not require this; naive implementation will pass the invariant check for each proposal in isolation and fail the joint invariant at activation.

If the implementation does include cross-proposal simulation, the submission-time complexity becomes O(P × C) where P = `max_active_proposals = 256` and C = number of ceiling-affecting pairs (17 after §39). This is bounded but non-trivial; it's also a new attack surface (a flood of computationally-expensive governance proposals becomes a DoS on submission).

### D.4 Cross-language port fragility

§39.4 adds `CeilingFieldId::MaxForgeryVetoesPerBlock` as field #19; `EXPECTED_FIELD_COUNT` updates 18 → 19 in three language ports (Rust, Python, TypeScript). This is a **single coordinated change** — if any port lags, cross-language conformance fails. The patch bundles this with the symmetric rule amendment per §43 rationale #7. If §38 or §39 is split for any reason after review, the field-#19 commit becomes orphaned until the ports are updated. No rollback path specified.

---

## E) Regulatory Exposure

### E.1 `docs/audits/` as discoverable recordkeeping

§40.2 rule 2 mandates an audit artifact in `docs/audits/` for every consensus-critical PR. These artifacts:

- Are committed to a public git history (structurally discoverable).
- Contain adversarial findings including security-relevant analysis (attack paths, fracture rankings).
- Are retained indefinitely (§40.5 "auditable post-hoc by any third party with git log access").

**Exposure vectors**:

- **SEC 17 CFR 240.17a-4**: if SCCGUB-operating entities are regulated (broker-dealer, RIA), these artifacts likely qualify as "records made or preserved" and may be subject to 6-year retention with 2-year immediately-accessible tier. The git history satisfies retention trivially but subpoena-responsiveness is new.
- **GDPR recital 26 / Art. 4(1)**: if any audit artifact names a natural-person contributor (e.g., "reviewer: tamirat-wubie"), git blame + commit author tie personal data to findings. Erasure-right requests (Art. 17) become structurally unsatisfiable — the same fracture the prior audit's H.4 flagged for on-chain data now extends to audit artifacts.
- **Responsible-disclosure norms (ISO/IEC 29147)**: audit artifacts disclosed pre-merge expose unremediated vulnerabilities to the public git history. §40.2 rule 3 permits deferral with a `patch-gate` label — meaning known-unfixed fractures are published in `docs/audits/YYYY-MM-DD-*.md` with the issue tracker pointing to the unfixed state. This is the inverse of responsible disclosure.

### E.2 Absence of audit-quality attestation

§40.2 rule 1 specifies the categories an adversarial framework must cover (invariant integrity, assumption extraction, scaling collapse, adversarial surface, regulatory exposure, fracture ranking). It does **not** specify:

- Qualification of the reviewer (human, LLM agent, tool vendor).
- Conflict-of-interest attestation.
- Independence from the PR author's organization.
- Time bound (must audit begin before PR open? within 24h of final diff?).

External regulators reading this rule will find "agent not involved in drafting" insufficient for SOC 2 CC8.1 (change management) or CC1.4 (board oversight). §40 satisfies an *internal* discipline but not an *attested* discipline.

---

## F) Competitive Pressure

Out of scope for this narrow pre-merge review (per §40 categories) — §40.3 tool-agnosticism is the only draft element touching the competitive axis. Flagged only: naming DCA as "one instance" in the amendment text creates a weak brand association between SCCGUB governance and Anthropic tooling. A competing chain forking the amendment must either copy DCA or name their own equivalent. Low concern; noted for record.

---

## G) Adversarial Surface

### G.1 Ceiling-lower + param-raise activation race (NEW)

- **Path**: Attacker controlling 1 submission slot crafts two Safety-level proposals:
  - P1 at height H: raise `max_proof_depth` from 256 to 300.
  - P2 at height H+1: lower `max_proof_depth_ceiling` from 512 to 280.
- **Current state at P1 submission**: ceiling=512, param=256. P1's resulting pair = (512, 300) — valid under §38. Admitted.
- **Current state at P2 submission**: ceiling=512, param=256 (P1 not activated yet, not committed). P2's resulting pair = (280, 256) — valid under §38 against committed state. Admitted.
- **At activation** (P1 activates at H+200, P2 at H+201): committed state becomes (280, 300). INV-CEILING-PRESERVATION-SYMMETRIC violated. Phase 10 rejects every subsequent block.
- **Detectability**: Low. Both proposals pass submission; both pass timelock; the violation surfaces at block N+201 production.
- **Containment**: None in the draft. Requires either joint-activation simulation at submission (unstated) or re-check at activation (unstated).

### G.2 1-of-N veto on a slashing targeting a colluder (NEW)

- **Path**: Validator A forges a signature purportedly from itself (non-canonical). Validator A equivocates legitimately — attacker-constructed evidence exists. Validator B (colluder with A) submits `ForgeryVeto` with B's own attestation signing over A's forgery proof. Rule §39.3 threshold: "at least one active-set signer" — B satisfies. Synthetic Remove against A is cancelled.
- **Attack value**: A slashing that *should* proceed (A genuinely equivocated) is cancelled by a validator-constructible proof wrapped in a 1-of-N attestation.
- **Detectability**: Low — `ForgeryProof` structure is cryptographically valid by construction (A intentionally produced a non-canonical sig to create the defense).
- **Containment**: Attestation-quorum threshold must be raised (e.g., ≥ f+1, or ≥ ⌈N/3⌉+1). The draft specifies 1.

### G.3 `max_forgery_vetoes_per_block` as a griefing floor (NEW)

Under adversarial load where 16 `EquivocationEvidence` records are admitted in one block (all ceiling-rate), only 4 `ForgeryVeto` records can respond per block. An attacker who controls evidence submission *and* wants to target a specific honest validator for guaranteed slashing can:

1. Submit 16 evidence records (15 against self-owned validators, 1 against target).
2. Observe honest forgery-vetoers rate-limited to 4 per block.
3. Flood the 3-block window with their own low-quality veto attempts against self-owned evidence, consuming veto slots.

Honest veto for target is starved of slot availability. Target slashes.

### G.4 Self-veto (NEW)

Nothing in §39.3 prohibits a validator from using its own attestation to veto its own synthetic Remove. If validator A can construct a `ForgeryProof` (non-canonical self-signature), A self-attests and self-cancels. Combined with G.2, an equivocating validator has a trivial one-shot defense.

### G.5 Trivial audit artifacts (NEW)

A PR author commissions an adversarial review from an agent instructed (by prompt, configuration, or social pressure) to produce a "zero fractures found" artifact. The artifact satisfies §40.2 rules 1–4 literally. `patch-gate` label never applied; merge proceeds. §40.5 INV-ADVERSARIAL-REVIEW-ENFORCED is literally true and substantively empty.

This bootstrap review is itself a test of this vector. A complicit reviewer returning "zero" would satisfy the rule while defeating its purpose.

### G.6 Queued-proposal-at-activation-boundary (NEW)

§39.6 says post-PATCH_10 `ForgeryVeto` governance proposals are rejected at submission. What about a pre-PATCH_10 `ForgeryVeto` governance proposal that was submitted *before* PATCH_10 activated, is now in the queue, and reaches its activation height *after* PATCH_10 activates? The draft is silent. Three paths: (a) it activates under its original §15.7 rule, (b) it is invalidated retroactively, (c) it is a no-op. None is specified.

---

## H) Fracture Ranking — Top 3 introduced by the draft

### H.1 FRACTURE-P10-01: Ceiling-lower + param-raise activation race

- **Trigger**: Two Safety-level governance proposals submitted within 200 blocks of each other, one raising a param, one lowering the companion ceiling, each valid against then-current committed state in isolation.
- **Cascade**: Both pass §38.3 submission check (each is valid against committed state; neither accounts for the other's queued activation). Both timelock. Joint activation produces a committed `(ceiling, param)` pair that violates INV-CEILING-PRESERVATION-SYMMETRIC. Phase 10 rejects every subsequent block. Liveness halt identical to the §38.1 scenario the draft purports to close.
- **Detectability**: Low — submission is quiet, activation is quiet, violation surfaces at first block production after the later activation.
- **Containment**: None in the draft text. Closed by (a) requiring §38.3 to simulate against the full queue of ceiling-or-param-affecting proposals, or (b) adding an activation-time re-check that delays activation if the pair would violate.

### H.2 FRACTURE-P10-02: ForgeryVeto 1-of-N attestation on slashing cancellation

- **Trigger**: A colluding validator submits `ForgeryVeto` with their own single attestation against a synthetic Remove targeting a co-colluder, using an attacker-constructed `ForgeryProof`.
- **Cascade**: Rule §39.3(3) "at least one active-set signer" threshold is satisfied by any colluder. `ForgeryProof` cryptographic validity is satisfied by the attacker's own non-canonical signature construction (the exact signer-misbehavior path §15.7's veto mechanism was designed to *defend* an honest validator against, now turned into a slashing-cancellation oracle). Synthetic Remove cancelled; genuine equivocation unpunished. Worst case: self-veto (G.4) — equivocator vetoes own slashing alone.
- **Detectability**: Low — all rules are satisfied; the failure is in the threshold choice, not the mechanism.
- **Containment**: Raise the attestation threshold to ≥ f+1 or require `VetoAttestation` signer to be non-coincident with the evidence's target validator.

### H.3 FRACTURE-P10-03: §40 audit artifact has no integrity predicate

- **Trigger**: A PR author with review authority commissions or produces a trivial adversarial review (e.g., "zero findings," 200 words, categories listed without substantive analysis).
- **Cascade**: §40.2 rules 1–4 satisfied literally. `patch-gate` label not applied. Merge proceeds. INV-ADVERSARIAL-REVIEW-ENFORCED is satisfied syntactically. Subsequent patches continue under a now-empty ritual. The first substantive fracture that slips through will be traced back to this bootstrap artifact and the rule text that permitted it.
- **Detectability**: High for egregious cases (artifact obviously trivial), low for subtle cases (artifact looks plausible, findings are all "accepted-residual"). Detection requires a *meta*-review of review quality, which §40 does not require.
- **Containment**: §40.2 rule 1 needs a non-triviality predicate — e.g., minimum word count per category, adversarial-reviewer qualification attestation, or a second-pass spot-audit cadence. Alternatively, INV-ADVERSARIAL-REVIEW-ENFORCED must be upgraded from meta-invariant to runtime-checked via `sccgub-audit verify-review-artifacts-present` as §40.5 promises, with minimum-content predicates encoded there.

---

## I) Survival Estimate (for this patch's closure claims)

| Claim | Estimate | Justification |
|---|---|---|
| §38 closes issue #55 completely | **MEDIUM** | Closes the single-proposal case. Does not close the concurrent-proposal race (H.1). Claim "ceiling-lowering attack closed" is true for the attack as narrated; the attack generalizes. |
| §39 closes issue #50 completely | **MEDIUM** | Removes the timelock mismatch (the stated fracture). Introduces two new fractures (H.2, G.3) at a smaller magnitude. Net structural improvement, not a clean closure. |
| §40 institutes effective DCA-before-merge discipline | **LOW–MEDIUM** | As written, the rule is proceduralism without integrity predicates. Survives until the first trivial audit artifact is merged unchallenged, at which point it becomes norm that "zero fractures" is an acceptable review output. The bootstrap self-reference (§40.4) is a positive signal; this review exists. Whether future reviews sustain the bar is not protocol-enforceable under the current text. |
| **Overall PATCH_10 merge readiness** | **CONDITIONAL** | Merge is not blocked by anything requiring a full redesign. The three top fractures above should be either remediated in this PR (preferred for H.2, trivial fix) or explicitly deferred with tracking issues per §40.2 rule 3 (acceptable for H.1, H.3 if flagged). |

---

## Required dispositions (for the PR's §40 Review cross-map)

| Finding | Suggested disposition | Rationale |
|---|---|---|
| H.1 Ceiling-lower + param-raise activation race | **deferred-tracked** — new issue "INV-CEILING-PROPOSAL-SERIALIZABILITY enforcement" | Requires implementation-level queue-simulation or activation-time re-check. Spec amendment modest; implementation surface nontrivial. |
| H.2 ForgeryVeto 1-of-N attestation | **remediated-in-PR** — amend §39.3 rule 3 to require ≥ f+1 attestations from distinct active-set members AND add a new §39.3 rule 5 prohibiting self-attestation where evidence target = attestation signer's agent_id | Trivial text change. Catches the worst case. |
| H.3 §40 audit artifact integrity | **deferred-tracked** — new issue "§40 audit-artifact non-triviality predicate" | Social/procedural; scheduling for `sccgub-audit verify-review-artifacts-present` (§40.5). |
| G.3 Forgery-veto rate starvation | **accepted-residual** — document trade-off in §39.4 rationale; tracking issue for future rate-raise if observed | Mass-forgery scenario is rare; containment cost (raising ceiling) is future-adjustable. |
| G.6 Queued governance-ForgeryVeto at activation boundary | **remediated-in-PR** — add §39.7 text specifying behavior | One sentence. |
| C.3 filename-collision in `docs/audits/` | **remediated-in-PR** — add suffix rule (e.g., `-N` if same-date collision) in §40.2 | One sentence. |

---

## Zero-fracture reasoning (per §40 rule 1)

Zero fractures would be suspicious. This review found six substantive items across three fracture-ranked and three surface-level findings. I specifically looked for but did not find: a byte-encoding collision in the new `ForgeryVeto` canonical form (§39.2 struct → bincode is consistent with existing patterns); a `change_id` space collision with other evidence types (§39.3 references existing `ChangeId` semantics); a cross-port arithmetic mismatch in `EXPECTED_FIELD_COUNT` beyond what the conformance harness will catch (§41 covers it).

The draft is substantively sound. It is not ready to merge under its own rule (§40) without either the in-PR remediations above or explicit deferred-tracking entries in the cross-map.

---

*End of pre-merge DCA audit.*
