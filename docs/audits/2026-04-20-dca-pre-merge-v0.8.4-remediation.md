# DCA Pre-Merge Audit — v0.8.4 Typed ModifyConsensusParam (Second Pass)

**Date**: 2026-04-20
**Target**: `impl/patch-10-v0.8.4-remediated` vs `origin/main`
**Scope**: Remediation review against `docs/audits/2026-04-20-dca-pre-merge-v0.8.4-typed-modify-consensus-param.md`
**Verdict**: **BLOCK — 2 new fractures discovered during remediation; 1 original fracture closed incompletely.**

---

## Original Fractures — Remediation Status

### FRACTURE-V084-01 (Non-exhaustive activation dispatcher) — **CLOSED**
The `ModifyConsensusParam` arm is present at `chain.rs:2030-2066`. The enum has 6 variants (`AddNorm`, `DeactivateNorm`, `ModifyParameter`, `ActivateEmergency`, `DeactivateEmergency`, `ModifyConsensusParam`); all 6 appear as explicit arms with no `_` wildcard. Compiler exhaustiveness check holds. `replay_governance_from_transitions` signature extension with closure `G` is type-clean at both call sites (lines 374-383, 1053-1082).

### FRACTURE-V084-02 (submit() admits unvalidated variant) — **PARTIALLY CLOSED**
The `submit_typed_consensus_param_proposal` wrapper (proposals.rs:228-255) composes `validate_typed_param_proposal` with `submit()`. However, `ProposalRegistry::submit()` itself still admits the variant without validation (acknowledged in docstring, lines 206-213). The "document the trap" remediation is weak: the module is `pub`, any downstream crate can call `submit()` directly with a ceiling-violating `ModifyConsensusParam` and it enters the registry. A stronger closure would be a sealed `#[doc(hidden)]` submit or a submit-time validation trait discriminating by kind.

### FRACTURE-V084-03 (§25.4 re-validation at activation) — **CLOSED (in-memory)** / **NEW FRACTURE OPENED (persistence)**
Closure at `chain.rs:1061-1081` correctly re-reads ceilings from trie, re-runs `apply_typed_param`, `ceilings.validate`, and `hypothetical.validate()` before committing `*consensus_params_mut = hypothetical`. Split-borrow of `ManagedWorldState` into `governance_state_mut`/`consensus_params_mut` is sound — disjoint fields, Rust NLL permits. See **NEW-F1** below for the persistence fracture this introduces.

### FRACTURE-V084-04 (activation_height unbounded) — **CLOSED**
`MAX_ACTIVATION_HEIGHT_OFFSET = 2000` constant (patch_04.rs:208). `ActivationTooFarInFuture` rejection path enforced in `validate_typed_param_proposal`. `saturating_add` applied to `voting_deadline` (proposals.rs:190) and `timelock_until` (proposals.rs:319). Test at `patch_10_submit_typed_consensus_param_rejects_u64_max_activation_height` covers the extreme boundary.

---

## NEW FRACTURES Introduced During Remediation

### FRACTURE-V084-R01 (BLOCKER) — Live-state mutation not persisted to trie
**Location**: `chain.rs:1061-1081` (live closure), `world.rs:168-176` (`commit_consensus_params`)
**Finding**: The live-path closure commits the typed-param mutation via `*consensus_params_mut = hypothetical;` — this is an in-memory field assignment on `ManagedWorldState.consensus_params`. It is NEVER followed by a call to `commit_consensus_params()`, which is the only path that writes `consensus_params` bytes under `ConsensusParams::TRIE_KEY` in the state trie. Consequences:
1. The post-activation `state_root` does not reflect the mutation — another node running the same block history will compute a different root, breaking block-producer/validator determinism.
2. `Chain::from_blocks` cold-replay uses `ManagedWorldState::default()` and the replay closure is a no-op (`chain.rs:382`). A post-restart node will have `consensus_params` at genesis defaults, diverging from the live-head params on the node that never restarted.
3. The in-memory mutation's lifetime is bounded by the process. Any code path that reads `consensus_params_from_trie(&self.state)` after activation but before a future (nonexistent) commit gets the stale genesis value — inconsistent with `self.state.consensus_params`.

The drafter's comment at `chain.rs:367-373` explicitly claims "replay reconstructs consensus_params from genesis bytes" as if that is correct by design. It is not: it reconstructs from genesis, but live chains activate mutations post-genesis, so the reconstruction is wrong for any chain that has ever activated a `ModifyConsensusParam`.

**Required remediation**: the closure must either (a) invoke `commit_consensus_params(managed_state)` after a successful mutation, OR (b) block-commit hook must re-commit consensus_params whenever the field differs from the trie-recorded value. The replay closure at `chain.rs:382` must also apply the mutation (it is currently a no-op).

### FRACTURE-V084-R02 (MAJOR) — Integration tests never observe live-state mutation
**Location**: `crates/sccgub-node/tests/patch_10_typed_consensus_param_lifecycle.rs:29-87`
**Finding**: The task description explicitly warned about this: "Does the test at line 29-87 actually observe the mutation on live state, or just on the proposal kind? If the latter, that's a MAJOR gap."
Test `patch_10_typed_consensus_param_full_governance_lifecycle` constructs a bare `ProposalRegistry`, never a `Chain` nor `ManagedWorldState`. It asserts (line 83) that `*activation_height == 400` on the `proposal.kind`, which is proposal metadata, not live state. The closure at `chain.rs:1061-1081` — the load-bearing line of the entire remediation — is dead code under integration-test coverage. No assertion anywhere verifies that `chain.state.consensus_params.max_proof_depth` changes after activation. The 7 new tests establish registry-level behavior only; cross-crate live-state mutation cross-over is untested, so FRACTURE-V084-R01 would not be caught by CI.

**Required remediation**: add one integration test that produces a block containing a `ModifyConsensusParam` activation trigger, invokes `chain.replay_governance_transitions` (or the equivalent block-import path), and asserts `chain.state.consensus_params.<field>` equals the proposed value AND `consensus_params_from_trie(&chain.state).unwrap().unwrap().<field>` equals the same.

---

## Minor Observations

- Lossy error conversion in `submit_typed_consensus_param_proposal`: `Result<_, String>` collapses structured `TypedParamProposalRejection`. Tests rely on substring matching. Follow-up: return the structured enum.
- Advisory-only `activation_height` per §25.3: mutation applies at `timelock_until` not at declared `activation_height`. Documented deferred refactor.
- `ceilings_snapshot` scope: OK (ceilings are genesis-write-once).

---

## Verdict

**BLOCK on FRACTURE-V084-R01** (persistence) + **FRACTURE-V084-R02** (test coverage gap that would have caught R01).

Minimum remediation before next DCA re-run:
1. Call `commit_consensus_params(&mut self.state)` after successful in-memory mutation in the live closure.
2. Wire the replay closure (line 382, currently `Ok(())`) to actually apply the mutation — a replay encountering a `ModifyConsensusParam` activation trigger must re-apply to reach the same `state_root`.
3. Add integration test with a real `Chain` that observes the live mutation AND `constitutional_ceilings_from_trie`-read consistency AND `from_blocks` cold-replay round-trip convergence.

---

## Drafter response (applied in-PR)

All three required remediations applied. Details in PR description.

Third DCA pass to follow after remediation.

*End DCA v0.8.4 remediation pass.*
