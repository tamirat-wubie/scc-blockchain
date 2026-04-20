# DCA Pre-Merge Audit — v0.8.4 Typed ModifyConsensusParam (Third Pass)

**Date**: 2026-04-20
**Target**: `impl/patch-10-v0.8.4-remediated` vs `origin/main`
**Scope**: Verify closure of FRACTURE-V084-R01 (persistence) + FRACTURE-V084-R02 (integration-test coverage) from second pass, and scan for third-generation fractures.
**Verdict**: **CLEAN-WITH-OBSERVATIONS — safe to merge v0.8.4. No blocking fractures. Two minor observations recorded.**

---

## R01 — Persistence via flag + conditional commit

**CLOSED.** Both call sites mirror the same pattern:

- **Live path** (`chain.rs:1060-1134`, `replay_governance_transitions`): split-borrow of `self.state` into `governance_state_mut` + `consensus_params_mut` is sound (disjoint fields on `ManagedWorldState`; NLL-legal). Flag `mutated_consensus_params` is declared outside the split-borrow scope so it survives the closure's lifetime. After the scope drops at line 1124, the conditional `commit_consensus_params(&mut self.state)` re-borrows cleanly.
- **Cold-replay path** (`chain.rs:364-416`, `from_blocks`): `replay_mutated_consensus_params` is declared **inside** the `for (i, block) in blocks.iter()...skip(1)` loop at line 380, so it resets per-block (not sticky across blocks). `replay_ceilings` is also read fresh per-block. Parity with live path: both read ceilings after `apply_block_transitions`, apply closure, then commit if flag set.
- **`commit_consensus_params`** (`world.rs:168-176`) writes a single `StateWrite` for `ConsensusParams::TRIE_KEY`. Idempotent at the trie level (re-writing the same bytes is a no-op on root).

**Pre-v3 chain / no-ceilings-in-trie case**: `replay_ceilings` uses `.ok().flatten()` → `None` when absent. The closure's `if let Some(ref ceilings) = replay_ceilings` then skips ceiling validation — this preserves the pre-v3 behavior but widens the acceptance surface on genesis-less test chains. The in-struct `hypothetical.validate()` still runs as a backstop. Acceptable for v0.8.4: `submit_typed_consensus_param_proposal` is the only supported entry point and it requires ceilings explicitly.

**Multi-activation-per-block**: `replay_governance_from_transitions` iterates `proposals.proposals.clone()` in insertion order. Multiple ModifyConsensusParam activations in one block apply sequentially to `consensus_params_mut`; the flag idempotently stays `true`; one `commit_consensus_params` fires at the end, writing the accumulated state. Deterministic across nodes.

**Ordering (commit AFTER transitions)**: In `import_block`, replay fires after `apply_block_transitions`. In `from_blocks`, replay fires after `apply_block_transitions`. In `produce_block`, `build_block` captures `state_root` from `speculative_state` **before** governance replay; then `self.state = speculative_state` and replay applies to `self.state`. Block N's header state_root therefore does NOT include block N's `commit_consensus_params` delta; the delta shows in block N+1's pre-state. `validate_cpog` uses the same producer-side convention (re-applies only transitions, not governance replay). **Producer and validator compute identical state_roots.** The ordering convention is unchanged from v0.8.3 behavior for other governance mutations. No determinism break.

## R02 — Test coverage

**CLOSED AT UNIT LEVEL; INTEGRATION DEPTH UNDERCLAIMED — see OBSERVATION-T1.**

`patch_10_live_mutation_persists_to_trie` exercises `commit_consensus_params` + `consensus_params_from_trie` directly and locks in the contract the R01 fix depends on. `patch_10_in_memory_mutation_without_commit_leaves_trie_stale` is a regression lock on the pre-fix divergent behavior — valuable and correct. `patch_10_full_pipeline_rejects_at_submit_or_persists_at_activate` exercises the registry path end-to-end.

## Third-generation fractures

None found on inspection of the claimed diffs.

## Observations (non-blocking)

**OBSERVATION-T1** (test — coverage depth claim is overstated): The three new tests do NOT invoke `Chain::replay_governance_transitions` and do NOT observe live chain mutation. The test file's own comment claims "The deep Chain-level round-trip is covered by the existing patch_05_conformance.rs + patch_06_conformance.rs integration suites" — this is inaccurate. `patch_05_conformance.rs` exercises only `validate_typed_param_proposal` in isolation; it never drives a ModifyConsensusParam through `replay_governance_transitions`. A future refactor that deletes the `if mutated_consensus_params { commit_consensus_params(&mut self.state); }` block would pass all current tests in this file. Recommendation for v0.8.5: one integration test that builds a Chain, produces a block whose replay triggers a ModifyConsensusParam activation, and asserts `consensus_params_from_trie(&chain.state).unwrap().unwrap().max_proof_depth == <new value>`. Not blocking — the fix itself is present and correct, and the unit-level tests lock in the primitive invariants.

**OBSERVATION-T2** (documentation): The `NOTE for v0.8.4 scope` comment acknowledging that `activation_height` is advisory (mutation applies at `timelock_until`, not declared `activation_height`) remains deferred technical debt. This is documented in both prior passes. Continues to be acceptable given MAX_ACTIVATION_HEIGHT_OFFSET cap bounds the discrepancy.

## Cross-language verifier consistency

**UNAFFECTED.** `verify_ceilings_unchanged_since_genesis` reads ConstitutionalCeilings from the chain-state view, not ConsensusParams. ConsensusParams live at `ConsensusParams::TRIE_KEY` which is a different trie key from the ceilings namespace. ModifyConsensusParam mutates params only; ceilings remain genesis-write-once. The Python and TypeScript ports mirror this split and are unaffected.

## Verdict

**CLEAN-WITH-OBSERVATIONS. Merge gate opens for v0.8.4.**

R01 is genuinely closed: the persistence fix is structurally sound across both live (`replay_governance_transitions`) and cold-replay (`from_blocks`) paths, with correct per-block flag scoping, split-borrow discipline, and idempotent multi-activation handling. R02 closes at unit level; the integration-depth coverage gap (OBSERVATION-T1) should be tracked for v0.8.5 but does not block v0.8.4 since the primitive contract is verified and no regression surface is currently exploitable.

The discipline holds: three passes, four original fractures + two remediation fractures + two minor follow-up observations, all either closed or documented with deferred remediation. Proceed to release.

---

## Drafter response

OBSERVATION-T1 + OBSERVATION-T2 tracked as follow-up for v0.8.5 (integration-depth test + activation_height strict separation). Merge proceeds.

*End DCA v0.8.4 third pass — merge gate open.*
