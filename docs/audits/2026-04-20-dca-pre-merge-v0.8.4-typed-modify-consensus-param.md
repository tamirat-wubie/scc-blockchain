# DCA Pre-Merge Review — v0.8.4 Typed `ModifyConsensusParam`

**Date:** 2026-04-20
**Target:** `impl/patch-10-v0.8.4` local branch (unpushed)
**Diff scope:** `crates/sccgub-governance/src/{proposals.rs,patch_04.rs}` (+194 / −13 lines)
**Spec basis:** PATCH_05 §25; PATCH_10 §38 composition; §40.2 rule 3 gate
**Auditor:** DCA, third application of §40 discipline
**Verdict:** **DO NOT MERGE.** Two blocker fractures, two major fractures, one observation.

---

## Scope confirmed

Read: the full diff; `proposals.rs` (710 lines); `patch_04.rs` (566 lines); `consensus_params.rs::validate()` (lines 219–379); caller enumeration via Grep; `sccgub-node/src/chain.rs:1938–1979` activation dispatcher; `sccgub-node/src/network.rs:5820`; pre-v0.8.4 discovery artifact. Ran `cargo check -p sccgub-governance` (passes) and `cargo check -p sccgub-node` (**fails**).

---

## FRACTURE-V084-01 — BLOCKER — compilation breakage: non-exhaustive match in node activation dispatcher

`crates/sccgub-node/src/chain.rs:1942` is a `match proposal.kind` arm (the `Ok(None)` branch of `proposals.activate()`). It currently enumerates `DeactivateNorm`, `ModifyParameter`, `ActivateEmergency`, `DeactivateEmergency`, `AddNorm { .. } => {}`. The new `ProposalKind::ModifyConsensusParam { .. }` is **not covered**.

Ran `cargo check -p sccgub-node`; compiler emits **E0004 non-exhaustive patterns: `ProposalKind::ModifyConsensusParam { .. }` not covered** at `chain.rs:1942:35`. The workspace does not build. The drafter did not run a whole-workspace `cargo check` before presenting this diff for review (the attempted check piped through `tail`, which masked cargo's non-zero exit code).

A second instance of the same pattern exists at `chain.rs:3884` (a `matches!` macro — non-fatal but semantically stale).

**Required remediation:** add a `ProposalKind::ModifyConsensusParam { field, new_value, activation_height }` arm to the dispatcher that actually applies the typed change to `ConsensusParams` at (or after) `activation_height`. An empty `{}` arm would compile but leave F-03 unaddressed.

## FRACTURE-V084-02 — BLOCKER — submission path bypasses the ceiling validator it was written for

`ProposalRegistry::submit()` in `proposals.rs:137–194` accepts `ProposalKind::ModifyConsensusParam` and inserts it into the registry **without** calling `validate_typed_param_proposal`. The only gate is the precedence check (`Meaning` → `Safety`).

The discovery artifact's own §Implication claim ("closes the §25 gap ... §38 becomes meaningful because the submission path now enforces ceilings") is **false for this diff**. `validate_typed_param_proposal` remains, as it was in v0.8.3, a standalone function with only test callers. The new enum variant is a second, parallel, unvalidated route.

Concrete adversarial consequence: a Safety-level proposer can submit `ModifyConsensusParam { field: MaxProofDepthCeiling-adjacent, new_value: well-above-ceiling, activation_height: u64::MAX }`. It passes `submit()`, occupies a registry slot, collects votes, reaches `Timelocked`, and either (a) panics the node at activation if a naïve applier is added in a follow-up, or (b) silently applies over-ceiling values if the applier omits re-validation.

Compare: PATCH_04.md §17.8 mandates "rejected at submission." §25 says the same. Neither is enforced on this path. The §38 claim in the release notes ("§38 is now meaningful because ModifyConsensusParam can carry param mutations that require ceiling validation at submission; the validate_typed_param_proposal path enforces it") is not truthful about the as-shipped code.

**Required remediation:** inside `submit()`, when `kind` is `ModifyConsensusParam`, call `validate_typed_param_proposal(current_params, current_ceilings, field, new_value, activation_height, current_height)` and return the error as a `String` (to match the existing `Result<Hash, String>`). This requires threading `&ConsensusParams` and `&ConstitutionalCeilings` into `submit()` — **an API break** that further changes N callers. The diff does none of this.

## FRACTURE-V084-03 — MAJOR — §25.4 INV-TYPED-PARAM-CEILING second half is undelivered, not "applied in the state crate"

The docstring for `validate_typed_param_proposal` (patch_04.rs:197–200) and for `ProposalKind::ModifyConsensusParam` (proposals.rs:61–62) both claim re-validation happens "at activation" or "in the state crate when the timelock expires." No such code exists.

Evidence:

- `chain.rs:1938–1979` is the sole `proposals.activate()` consumer. It has no applier for the new variant (F-01).
- Grep for `apply_typed_param` outside `sccgub-types` and `sccgub-governance`: **zero production callers**.
- `sccgub-state` does not call `validate_typed_param_proposal`, `ceilings.validate`, or `apply_typed_param` for governance activation.

The drafter's own pre-check hypothesis in the task brief ("Defensible answer: the state-crate applier will re-validate when it applies the param change. Check whether that's actually true somewhere in the codebase, or whether it's an unshipped obligation.") — it is an **unshipped obligation**. This is documented-but-not-implemented behavior. Shipping it in a docstring without the code satisfies spec-text review (which is why PATCH_10's spec-level DCA at `2026-04-19-dca-pre-merge-patch-10.md` missed it) but fails runtime conformance.

**Required remediation:** either (a) implement re-validation in the chain applier added to remediate F-01, calling `ceilings.validate(&hypothetical)` against the ceilings as-of `activation_height`, OR (b) amend the docstrings to say "§25.4 second half is deferred to v0.8.5" and file an issue. Option (a) is preferred and is small (~20 LOC inside the match arm).

## FRACTURE-V084-04 — MAJOR — `activation_height` is unbounded; parking attack and arithmetic-overflow surface

`submit()` performs no sanity on `activation_height`. The in-struct `validate_typed_param_proposal` accepts any value strictly greater than `current_height`, including `u64::MAX`. Consequences:

1. **Parking attack.** A Safety-level proposer (one of a small set) can submit `ModifyConsensusParam { activation_height: u64::MAX }`, have it voted through (Safety cohort may be small enough to collude, or simply approve as innocuous-looking), and leave a sleeper proposal that activates under future state the community never reviewed. Note: today no applier exists (F-01, F-03), so the sleeper is inert — but fixing F-01 without adding a cap weaponizes it.
2. **Arithmetic overflow.** `voting_deadline: current_height + voting_period` and `timelock_until: current_height + timelock_duration` at `proposals.rs:187, 256` use unchecked addition. This pre-existed, but the new variant amplifies risk because `ModifyConsensusParam` admits large u64 scalars next to block-height scalars in the same struct, making the mental model sloppier. Not strictly the new diff's fault; flagged for context.

**Required remediation:** introduce an explicit `MAX_ACTIVATION_HEIGHT_OFFSET` (e.g., `current_height + timelocks::CONSTITUTIONAL + 10 * timelocks::CONSTITUTIONAL` — i.e., no more than ~10× the timelock beyond timelock expiry) and reject beyond it in `validate_typed_param_proposal`. Separately, change the two `+` sites in `submit()`/`finalize()` to `saturating_add` to match the existing `votes_for.saturating_add(1)` discipline at lines 225, 227.

## OBSERVATION — bincode discriminant stability — OK by placement

Appending `ModifyConsensusParam` to the **tail** of the `ProposalKind` enum preserves the discriminant of all pre-existing variants under bincode's default encoding (`varint` u32 tag of enum index). Pre-v0.8.4 proposals stored at-rest will deserialize unchanged. The `GovernanceProposal::kind` field is present and typed identically. No migration needed for read paths.

Cross-version write compatibility: a v0.8.3 node encountering a v0.8.4-emitted `ModifyConsensusParam` in a replicated block will fail to decode. **This is a hard-fork-at-activation boundary** and must be documented in CHANGELOG as such. The diff does not add a CHANGELOG entry.

## Test coverage — meaningful but incomplete

The five new tests in `proposals.rs:558–708` cover: precedence rejection, happy-path submit, timelock class, activate-without-norm, serde roundtrip. They do **not** cover:

- A `ModifyConsensusParam` proposal whose `new_value` would violate a ceiling — because `submit()` does not call the validator (F-02), there is no test that could pass. The absence of this test is itself a tell.
- Cross-crate: no integration test in `sccgub-node` that submits → votes → finalizes → activates → observes the live `ConsensusParams` mutation. This is gated on F-01 and F-03 remediation.
- Adversarial `activation_height` (zero, past, `u64::MAX`).
- Re-validation behavior if the ceiling is lowered between submission and activation. (§25.4 core claim.)

## Methodology note — what the drafter missed

The drafter ran `cargo check -p sccgub-governance` locally (it passes) and concluded the diff was shippable. They did not run `cargo check --workspace`. Recommend adding a pre-merge local gate: **"`cargo check --workspace` must pass"** as a §40.2 rule addition. Current discipline stops at in-crate compilation, which is insufficient when a diff changes a public enum.

**Separately:** the drafter's attempted workspace check used `cargo check --workspace 2>&1 | tail -5` — piping through `tail` returns `tail`'s exit code (0) to the shell, **masking cargo's real exit code**. This is a false-positive sanity pattern that should be retired from the release discipline. Use `cargo check --workspace` directly, or `set -o pipefail` explicitly.

## Verdict

**Merge blocked.** F-01 is a compile-break; shipping is mechanically impossible. F-02 is a capability fracture that makes the release's stated §25/§38 closure false; the advertised guarantee does not hold. F-03 and F-04 must be addressed before the next DCA pass. The five-test suite is directionally correct but cannot be considered conformance until F-02 is fixed.

**Minimum remediation set:**

1. Add `ProposalKind::ModifyConsensusParam` arm to `chain.rs:1942` dispatcher with ceiling re-validation against activation-time ceilings and actual live-state mutation.
2. Thread `&ConsensusParams` + `&ConstitutionalCeilings` through `ProposalRegistry::submit()`; call `validate_typed_param_proposal` for the typed variant; return rejection as the submission error.
3. Cap `activation_height` at `current_height + timelocks::CONSTITUTIONAL × K` (propose K = 10; document).
4. Add integration test in `sccgub-node` covering submit-through-activate and a ceiling-violating submission (expect rejection).
5. Add CHANGELOG entry noting enum extension is a network hard-fork boundary.
6. Add `cargo check --workspace` to §40.2 pre-merge local gate.

After remediation, re-run DCA.

---

## Drafter response (applied in-PR)

All four fractures remediated before proceeding. Methodology note #6 also adopted: workspace-level `cargo check` + `cargo test` run without pipe-truncation before any CI push. Details in PR description "Review cross-map" per §40.2 rule 4.

*End DCA v0.8.4.*
