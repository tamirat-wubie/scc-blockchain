# PATCH_10 — Spec-patch closures of three DCA v0.5.0 fractures + DCA-before-merge governance discipline

**Chain version introduced:** none (PATCH_10 does not introduce a new chain version; §38 and §39 amend behavior within v5, §40 is a governance/process rule).
**Supersedes:** nothing.
**Scope:** three specification-level closures from the 2026-04-18 DCA audit (`docs/audits/2026-04-18-dca-v0.5.0-layers-2-3-4.md`) plus formal adoption of adversarial-structural-review-before-merge as a §13 amendment.

This patch is **deliberately narrow**. The DCA audit found ~16 structural findings; this patch closes the three cheapest, best-bounded ones. Harder items (quorum-collusion capture, regulatory impossibility, state-growth operational tooling, non-validator key recovery, evidence-submission incentive) remain tracked in their own issues and are out of scope here.

Addresses:

- **§38 closes issue #55** — Ceiling-lowering asymmetric invariant (FRACTURE-SECONDARY from DCA §G.3). A governance proposal that lowers a `ConstitutionalCeiling` below current `ConsensusParams` would pass submission validation and trigger a 200-block liveness halt at activation. §17.8 was unidirectional (prevented raising only); this patch makes the bound symmetric.

- **§39 closes issue #50** — Veto–timelock structural mismatch (FRACTURE-L2-01, DCA §H.1 remainder). The forgery-veto mechanism (§15.7) was specified with a ≤10-block activation-delay window but depends on Safety-level governance (§12) with a 200-block timelock. The veto was un-invokable through normal governance; an honest validator facing a forgery-induced slashing had no defensible remediation path. This patch decouples the veto from governance entirely — the forgery check becomes an in-block evidence-layer admission, not a Safety-level proposal.

- **§40 closes issue #57** — §13 amendment instituting DCA-before-merge discipline. From this patch forward, no specification patch or consensus-critical implementation PR may merge without an adversarial structural review performed by an agent not involved in drafting the patch, with findings attached as a record artifact.

All three closures are governance-level. **None introduces a new chain-version rule; none changes a state-root computation.** Existing v5 chains replay under the amended rules exactly as they did before, because the amended rules constrain **which proposals are admitted at submission**, not **what effect they have when activated**.

---

## §38 Symmetric Ceiling-Preservation (closes issue #55)

### §38.1 Problem

PATCH_04 §17.8 states:

> A governance proposal whose payload would modify any field in `ConstitutionalCeilings`, or whose modification of `ConsensusParams` would cause any pair in §17.2 to exceed its ceiling, is **rejected at submission**.

This wording prohibits **raising** a ceiling above its companion `ConsensusParams` value, or **raising** a param above its ceiling. It does not prohibit **lowering** a ceiling below its current param value.

**Attack vector**: a Safety-level governance proposal lowers `max_proof_depth_ceiling` from 512 to 100. The current `max_proof_depth` param is 256 (well below the original ceiling). At submission, §17.8 checks only raising; the proposal passes. 200 blocks later the proposal activates; the new ceiling (100) is committed. Current param (256) now exceeds the new ceiling. Phase 10 (Architecture) validation, per INV-CEILING-PRESERVATION, rejects every block produced thereafter. The chain halts until a separate governance proposal raises the param back under the new ceiling — which itself takes 200 blocks.

**Outcome**: 200+ block liveness halt triggered by a single proposal that passed submission validation. No malicious implementation bug; the proposal was valid under the letter of §17.8.

### §38.2 Amended rule

§17.8 is **replaced** with the symmetric form. The amended section reads (substantive changes **bolded**):

> A governance proposal is **rejected at submission** if, at its declared `activation_height`, the resulting `(ConstitutionalCeilings, ConsensusParams)` pair would violate any of the following invariants for any pair `(param_i, ceiling_i)` declared in §17.2 (as extended by §29 and §34):
>
> **(a) Upper-bound pairs** (all §17.2 / §29 entries): `param_i ≤ ceiling_i`. Rejects the raise-the-param attack AND the lower-the-ceiling attack symmetrically.
>
> **(b) Lower-bound pairs** (`min_effective_fee_floor` and any future `min_*` ceiling): `param_i ≥ ceiling_i`. The min-floor family is inverted — the ceiling is a lower bound that the param must not fall below. The attack mirror: raising the lower-bound ceiling above the current param halts the chain identically.

> The check runs against the **resulting** `(ceiling, param)` pair, computed by applying the proposal's payload to the current state. If the proposal modifies only one side of a pair, the other side is taken as its current on-chain value at the check height.

The rejection taxonomy extends:

- `ProposalRejection::CeilingParamMismatch::RaiseParamAboveCeiling` — pre-existing.
- `ProposalRejection::CeilingParamMismatch::LowerCeilingBelowParam` — **new**, introduced by this patch.
- `ProposalRejection::CeilingParamMismatch::LowerParamBelowFloorCeiling` — new, lower-bound analog.
- `ProposalRejection::CeilingParamMismatch::RaiseFloorCeilingAboveParam` — new, lower-bound analog.

### §38.3 Enforcement phase

Governance submission (§12.N) — NOT at activation. Submission-time rejection prevents the proposal from occupying a queue slot for 200 blocks while being known-invalid, same rationale as §17.8 Rev-1.

### §38.4 Invariant

**INV-CEILING-PRESERVATION-SYMMETRIC** (replaces INV-CEILING-PRESERVATION): For all v5 heights H, every pair `(param, ceiling)` declared in §17.2 / §29 / §34 satisfies:

- If the pair is upper-bound: `state.consensus_params.param(H) ≤ state.constitutional_ceilings.ceiling(H)`.
- If the pair is lower-bound: `state.consensus_params.param(H) ≥ state.constitutional_ceilings.ceiling(H)`.

### §38.5 Backward compatibility

Pre-PATCH_10 chains are unaffected at replay: §17.8 Rev-1 enforced only the raise-direction, and INV-CEILING-PRESERVATION (the Rev-1 invariant) implied the same bound. No historical block was admitted that would have been rejected under Rev-2 — the Rev-2 check is a **strict superset** of the Rev-1 check at submission time, and a **behavioral equivalent** at all heights for which no ceiling-lowering proposal ever passed. Historical chains had no such proposal by construction (§17.8 Rev-1 did not reject them, but no proposer submitted one either — the bug was a latent one).

The moat verifier (`sccgub-audit`) does NOT need to be updated. The verifier checks `ceilings_unchanged_since_genesis`, which is a stricter property than the §38 check. A chain that passed the verifier pre-PATCH_10 also passes post-PATCH_10.

---

## §39 Forgery-veto mechanism decoupling from governance (closes issue #50)

### §39.1 Problem

PATCH_04 §15.7 specifies a two-stage equivocation slashing:

1. Stage 1 at `H_admit`: evidence admitted, synthetic `ValidatorSetChange::Remove` queued with `effective_height = H_admit + activation_delay`.
2. Stage 2: during `[H_admit, H_admit + activation_delay)` window, a **Safety-level governance proposal** may veto the synthetic Remove iff it provides cryptographic proof of signature forgery.

Under PATCH_05/06 defaults:
- `activation_delay = clamp(k+1, 2, k+8)` where `k = confirmation_depth = 2`, so `activation_delay = 3` (ceiling k+8 = 10 if `k` is raised to 2).
- Safety-level governance timelock per §12 = **200 blocks**.

**200 > 10.** A valid forgery-veto proposal submitted at `H_admit` cannot activate before the synthetic Remove takes effect. The veto window exists only on paper; in the protocol's actual timing, the forgery veto is un-invokable.

PATCH_06 §30 added `ForgeryVeto` with authorization requirements (closing who-can-submit), but still routed the veto through Safety-level governance. The authorization fix was necessary but not sufficient.

### §39.2 Amended design: evidence-layer veto

The forgery-veto is **removed from governance** entirely. It becomes an **in-block evidence-layer admission**, handled in Phase 12 (Feedback) alongside `EquivocationEvidence` and the synthetic Remove it may cancel.

A block producer who has received (or constructed) a valid `ForgeryProof` against an active `EquivocationEvidence` includes a `ForgeryVeto` record directly in `body.forgery_vetoes: Option<Vec<ForgeryVeto>>`. The record is validated in the same block as the evidence it cancels (if same-block) or in any subsequent block during `[H_admit, H_admit + activation_delay)`.

```rust
pub struct ForgeryVeto {
    pub target_evidence_change_id: ChangeId,       // the synthetic Remove being vetoed
    pub proof: OwnedForgeryProof,                  // two byte-distinct sigs over same canonical bytes, at least one failing verify_strict
    pub submitted_at_height: u64,                  // must be in [H_admit, H_admit + activation_delay)
    pub attestations: Vec<VetoAttestation>,        // from PATCH_06 §30.2 — at least one active validator's signature over canonical_veto_bytes
}
```

No governance path is involved.

### §39.3 Validation rule (Phase 12)

A `ForgeryVeto` V is admitted iff:

1. V references an `EquivocationEvidence` E with `change_id == V.target_evidence_change_id` that was admitted at some height `H_admit ≤ V.submitted_at_height < H_admit + activation_delay`, AND
2. V.proof's two signatures pass the PATCH_04 §15.7 forgery predicate (both verify non-strict; at least one fails `verify_strict`), AND
3. **`V.attestations` contains signatures from at least `f + 1` distinct members of `active_set(V.submitted_at_height)`**, where `f = floor((n - 1) / 3)` is the Byzantine bound from §6.Byzantine tolerance. Duplicate signers (by `agent_id`) are ignored for threshold counting but each signature is still cryptographically verified. Rationale: a 1-of-N authorization on a slashing cancellation would let any single colluding validator cancel slashing targeting a co-colluder using an attacker-constructed forgery proof. An f+1 threshold matches the BFT safety assumption — a successful veto requires attestation from at least one honest validator's worth of signers (pigeonhole: in any set of f+1 validators, at least one is honest). AND
4. The `VetoAttestation` signatures verify under `verify_strict` against `canonical_veto_bytes(V)`. AND
5. **No `VetoAttestation` signer's `agent_id` coincides with the `agent_id` of the validator targeted by E's synthetic Remove.** Self-attestation is prohibited: a validator whose slashing is pending MAY NOT be a signer on the veto cancelling that slashing. The rule reflects the principle that the party with the strongest defect-incentive on the slashing outcome is the least credible attestor to the forgery's legitimacy. Structurally: `E.target_agent_id ∉ { att.signer_agent_id | att ∈ V.attestations }`.

Admission at Phase 12: the synthetic Remove referenced by V is **atomically cancelled**. The underlying equivocating-validator continues in the active set; the slashing event does not take effect at `H_admit + activation_delay`.

**No Safety-level proposal. No 200-block timelock. No un-invokable window.**

### §39.4 Constitutional ceiling

To prevent an attacker from spamming forgery-vetoes as a DoS vector (each vetoed evidence requires CPU work for both producer and verifier):

```
max_forgery_vetoes_per_block_ceiling: u32   // default 8
```

Added to `ConstitutionalCeilings` (field #19; `EXPECTED_FIELD_COUNT` updates from 18 to 19 in cross-language ports).

Companion `ConsensusParams`:

```
max_forgery_vetoes_per_block: u32           // default 4
```

Headroom ×2. Rationale: real-world legitimate forgery attempts are rare (requires a deployed signer with a broken crypto lib). Capacity for 4 per block handles a whole-set-forgery scenario in one chain's worth of validators at max 128 set size, conservatively, without creating a DoS surface.

**Known residual (tracked issue, accepted for v5)**: under adversarial mass-evidence load (up to 16 evidence records per block per §15.7 ceiling), the activation-delay window (default 3 blocks) × `max_forgery_vetoes_per_block` (default 4; max 8 under ceiling) gives 12–24 veto slots to respond to as many as 48 evidence slots in the same window. Under a targeted mass-forgery attack where the attacker controls both evidence submission and spams low-quality vetoes against self-owned evidence, honest forgery-vetoers can be starved of slot availability and legitimate targets slashed. This is accepted as a residual for v5 — mass-forgery attacks are observable (the evidence surface is on-chain) and the ceiling is future-adjustable by governance. A future patch MAY raise the ceiling or introduce priority-ordered veto admission (evidence-targeting-multiple-validators or honest-signer attestations weighted higher). See tracking issue for any subsequent revision.

### §39.5 Invariant

**INV-FORGERY-VETO-FEASIBLE** (closes missing invariant from DCA §B.2): For every `EquivocationEvidence` E admitted at height `H_admit` against a non-forged signature, if a valid `ForgeryProof` for that signature exists, a `ForgeryVeto` referencing E can be admitted at any height in `[H_admit, H_admit + activation_delay)` without any governance-timelock dependency. The forgery-veto path is **structurally invocable** within the activation-delay window.

### §39.6 Deprecation of PATCH_06 §30 governance-routed veto

The PATCH_06 §30 `ForgeryVeto` governance proposal path is **deprecated but preserved for v5-compat**. It continues to parse under v5 but is never admitted — phase-12 `ForgeryVeto` (this section) strictly supersedes it. A `ForgeryVeto` submitted as a governance proposal after PATCH_10 activation is rejected at submission with `ProposalRejection::DeprecatedPath`.

v6 chains MAY remove the governance-routed path entirely. This patch keeps the submission-time rejection so operators migrating from v5 see a clear error rather than a silent acceptance that will never activate.

### §39.7 Backward compatibility

Pre-PATCH_10 chains: no behavioral change. Existing `EquivocationEvidence` records activate after `activation_delay` as before. No pre-PATCH_10 chain admitted a PATCH_06 §30 governance-routed `ForgeryVeto` because the mechanism was un-invokable (the bug this patch closes).

**Activation-boundary case for in-flight governance-routed vetoes**: a PATCH_06 §30 `ForgeryVeto` proposal that was submitted before PATCH_10 activation and is still in `Submitted | Voting | Timelocked` state at PATCH_10 activation height is **transitioned to `Invalidated` with reason `SupersededByPATCH_10`**. The proposal slot is freed in the governance queue (contributing to `max_active_proposals` capacity). The underlying forgery concern, if real, must be re-submitted as a phase-12 `ForgeryVeto` per §39.2 before `H_admit + activation_delay` expires. Rationale: retroactive admission under pre-PATCH_10 rules would create a path where a queued `ForgeryVeto` *could* activate after its activation_delay window had already closed (a semantic that was never coherent), and silent no-op would hide the proposal's fate from its submitter.

---

## §40 §13 Amendment: DCA-before-merge discipline (closes issue #57)

### §40.1 Motivation

The 2026-04-18 DCA audit found structural fractures that approval-style review had missed. The audit's advisory note (archived at `docs/audits/2026-04-18-dca-v0.5.0-layers-2-3-4.md`) recommended instituting adversarial structural review as a **merge gate**, not a post-hoc artifact. Issue #57 tracks the governance adoption of that discipline.

Informal conventions decay. Formal §13 adoption prevents silent erosion.

### §40.2 Amendment text

Appended to PROTOCOL.md v2.0 §13 as a new subsection:

> **§13.N — Adversarial structural review discipline.**
>
> From PATCH_10 forward, no specification patch or consensus-critical implementation PR may merge until:
>
> 1. An adversarial structural review has been performed against the patch spec and implementation diff by an agent not involved in drafting the patch. The review must use a documented adversarial framework (Deterministic Causal Auditor or equivalent) that produces findings under at least the following categories: invariant integrity, assumption extraction, scaling collapse, adversarial surface, regulatory exposure, and fracture ranking.
>
> 2. The review's findings are attached to the PR as a record artifact in `docs/audits/YYYY-MM-DD-<topic>.md`, following the archival precedent established by `docs/audits/2026-04-18-dca-v0.5.0-layers-2-3-4.md`. If multiple audit artifacts are produced on the same date, disambiguation suffix `-N` is appended (e.g., `2026-04-19-dca-pre-merge-patch-10.md`, `2026-04-19-dca-pre-merge-patch-10-2.md`). Filename collisions are rejected at PR check time.
>
> 3. Each finding is either remediated in the same PR or explicitly deferred with a dated, labeled tracking issue. The `patch-gate` label applied to the issue blocks future PRs from merging while that label is open, unless the PR's description explicitly acknowledges the deferral.
>
> 4. The PR description includes a "Review cross-map" table with three columns: finding → disposition (remediated / deferred-tracked / accepted-residual) → tracking issue (required for deferred or accepted-residual).
>
> **Exceptions** (exempt from §13.N):
>
> - Non-consensus documentation PRs (e.g., README, operator runbooks).
> - Release-engineering PRs that do not alter protocol rules (version bumps, changelog-only, regenerated artifacts, CHANGELOG entries).
> - CI infrastructure PRs that do not alter protocol rules.
>
> **Not exempt** (§13.N applies fully):
>
> - Patch-level specification changes (PATCH_N.md drafts or amendments).
> - New crate additions to `sccgub-audit*` (moat-verifier family).
> - Any change touching consensus-critical code paths in `sccgub-execution`, `sccgub-state`, `sccgub-consensus`, `sccgub-governance`, or `sccgub-types`.

### §40.3 Tool-agnostic adoption

The amendment names the Deterministic Causal Auditor as **one instance** of an acceptable adversarial framework, not the only one. Any framework producing findings under the six specified categories (invariant integrity, assumption extraction, scaling collapse, adversarial surface, regulatory exposure, fracture ranking) satisfies §13.N — external audit-firm engagements, formal-methods passes, or in-house adversarial review checklists all qualify provided they produce the documented artifact.

This prevents §13.N from becoming tool-lock-in. If a future project fork wants to use a different framework, they amend §13.N to name their preferred tool; the governance requirement remains.

### §40.4 Bootstrap closure

This PATCH_10 itself is the **first patch that merges under §13.N discipline**. The adversarial review artifact for PATCH_10 is `docs/audits/2026-04-19-dca-pre-merge-patch-10.md`, produced by an agent separate from the draft author. The review's findings appear in the PATCH_10 PR description's "Review cross-map" table.

The bootstrap is deliberately self-referential: the rule that "all future patches are reviewed before merge" must itself be reviewed before merge. Otherwise the adoption would violate the rule it's adopting.

### §40.5 Invariant

**INV-ADVERSARIAL-REVIEW-ENFORCED**: Every merged commit on `main` that touches consensus-critical code or patch-level specifications has a corresponding adversarial-review artifact under `docs/audits/`, cross-referenced from the commit's originating PR.

This is a **meta-invariant** — not checked by the runtime verifier, but auditable post-hoc by any third party with `git log` access. The `sccgub-audit` crate is expected to be extended in a future patch with a `verify-review-artifacts-present` subcommand that audits the git history for compliance.

---

## §41 Conformance Matrix (PATCH_10)

Each normative rule has at least one conformance test under `patch_10_*` naming:

| Rule | Test | Crate |
|---|---|---|
| §38.2 submission rejects ceiling-lower below param | `patch_10_governance_rejects_ceiling_lower_below_param` | `sccgub-governance` |
| §38.2 submission rejects floor-raise above param | `patch_10_governance_rejects_floor_raise_above_param` | `sccgub-governance` |
| §38.4 INV-CEILING-PRESERVATION-SYMMETRIC | `patch_10_ceiling_preservation_symmetric` | `sccgub-execution` |
| §39.3 in-block ForgeryVeto admits without governance | `patch_10_forgery_veto_admits_in_activation_window` | `sccgub-execution` |
| §39.3 ForgeryVeto outside activation window rejected | `patch_10_forgery_veto_outside_window_rejected` | `sccgub-execution` |
| §39.3 ForgeryVeto without attestation rejected | `patch_10_forgery_veto_requires_active_validator_attestation` | `sccgub-execution` |
| §39.4 max_forgery_vetoes_per_block ceiling enforced | `patch_10_forgery_vetoes_per_block_bounded` | `sccgub-execution` |
| §39.5 INV-FORGERY-VETO-FEASIBLE | `patch_10_forgery_veto_feasible_in_activation_window` | `sccgub-consensus` |
| §39.6 governance-routed ForgeryVeto rejected | `patch_10_governance_forgery_veto_deprecated` | `sccgub-governance` |
| §40 adversarial-review artifact present | `patch_10_review_artifact_exists` | workspace root |
| cross-port: ceiling field #19 in CeilingFieldId | `patch_10_max_forgery_vetoes_in_ceiling_field_id` | `sccgub-audit` + `sccgub-audit-py` + `sccgub-audit-ts` |
| Cross-cutting | `patch_10_conformance` (integration) | workspace root |

Cross-language conformance: the addition of `max_forgery_vetoes_per_block_ceiling` as field #19 requires coordinated update to `CeilingFieldId` in all three language ports. `EXPECTED_FIELD_COUNT` goes from 18 to 19. The cross-language conformance harness will automatically flag any port that fails to update.

---

## §41.N Pre-merge adversarial-review cross-map (bootstrap §40 compliance)

Per §40.2 rule 4, PATCH_10 must attach a Review cross-map showing how each finding from the pre-merge adversarial review was dispositioned. The review artifact is `docs/audits/2026-04-19-dca-pre-merge-patch-10.md`. The mapping is:

| Finding | Severity | Disposition | Action in this PR | Tracking issue |
|---|---|---|---|---|
| **H.1** — Ceiling-lower + param-raise activation race | HIGH | deferred-tracked | None in this PR | [#62](https://github.com/tamirat-wubie/scc-blockchain/issues/62) |
| **H.2** — ForgeryVeto 1-of-N attestation | HIGH | remediated-in-PR | §39.3 rule 3 requires ≥ f+1 distinct signers; new rule 5 prohibits self-attestation | — |
| **H.3** — Audit artifact has no integrity predicate | MEDIUM | deferred-tracked | None in this PR | [#63](https://github.com/tamirat-wubie/scc-blockchain/issues/63) |
| **G.3** — Forgery-veto rate starvation | MEDIUM | accepted-residual | §39.4 rationale documents the residual and remediation path | [#64](https://github.com/tamirat-wubie/scc-blockchain/issues/64) |
| **G.6** — Queued governance-ForgeryVeto at activation boundary | LOW | remediated-in-PR | §39.7 transitions in-flight proposals to `Invalidated::SupersededByPATCH_10` | — |
| **C.3** — Filename collision in `docs/audits/` | LOW | remediated-in-PR | §40.2 rule 2 adds `-N` suffix rule | — |

The three remediated-in-PR findings are closed by this patch. The three tracked findings are open under `patch-gate` label and must be explicitly acknowledged in any future PR that would be affected by them.

**Survival estimate after remediation** (reviewer's assessment, adopted): §38 closes #55 completely for single-proposal case; H.1 is the open edge case. §39 closes #50 with H.2 and G.3 as known residuals (one remediated, one accepted-and-tracked). §40 institutes the discipline with H.3 as the integrity gap to be closed by a follow-up patch. **Overall merge readiness**: UNCONDITIONAL for the remediated items; CONDITIONAL on tracking issues being filed before merge (§13.N rule 3).

---

## §42 PATCH_10 does NOT address

For audit clarity, these fractures from the 2026-04-18 DCA audit are explicitly out of scope for PATCH_10:

- **H.2 — State growth operational tooling + snapshot/fast-sync** (issue #51). Deferred to a dedicated operational-hardening workstream.
- **H.3 — Quorum-collusion validator-set capture** (issue #52, closed as accepted residual risk at BFT threshold).
- **H.4 — Regulatory impossibility lock-in** (issue #53). Quarterly review cadence; first review 2026-07-18.
- **Evidence-submission incentive gap** (issue #54). Design-required; no spec change possible until the design-space-trade-off decision is made.
- **Non-validator key-revocation path** (issue #56). Design-required; depends on the user-model decision for the project.

---

## §43 Resolved decisions (drafting audit trail)

1. **Separate vs. bundled patch**: chose to bundle §38, §39, §40 in one patch because all three are specification-only changes at similar review cost. Bundling harder items (#51 operational, #54/#56 design-required) would create uneven review surface.

2. **§38 symmetric rule placement**: chose to amend §17.8 directly rather than add a new §17.10. Reason: the asymmetry is a bug in the original rule, not a new concept; readers of §17.8 need to see the symmetric form in place.

3. **§39 decoupling from governance**: chose evidence-layer admission over expedited-governance-class. Reason: expedited governance (< 200 blocks) would require §12 timelock amendment, which creates a whole new governance class and a new risk surface. Evidence-layer removes the dependency entirely, which is simpler and eliminates the mechanism rather than refining it.

4. **§39.4 ceiling default 8**: chose default 4 + ceiling 8 (×2 headroom). Rationale: forgery is rare; ×2 is enough for a double-failure scenario plus headroom for an unknown-unknown, while keeping DoS surface bounded.

5. **§40 bootstrap self-reference**: chose to have PATCH_10 itself be the first patch reviewed under §13.N. Reason: otherwise the adoption would violate the rule it's adopting. Self-reference is the natural closure.

6. **§40.2 exception list**: explicit "Not exempt" list prevents drift. Without it, operators could argue any PR into the exempt bucket. The list is closed-form; adding an exemption requires a new §13.N amendment.

7. **Cross-language conformance field #19**: chose to bundle the ceiling addition with the symmetric-rule amendment because they share a review surface (both are `ConstitutionalCeilings` surface changes). Separating would require two cross-port updates; one is simpler.

---

*End of PATCH_10.md (draft).*
