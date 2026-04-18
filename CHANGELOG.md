# Changelog

All notable changes to SCCGUB are documented here.

## [v0.6.4] — Patch-07: wire §32 fork-choice into Chain::should_switch_to

Closes audit item H.1′ (v0.6.3 audit): the live `Chain::should_switch_to`
no longer uses the pre-Patch-06 implicit (finalized_height, total_height)
rule; it now routes through `sccgub_consensus::fork_choice::ChainTip::score_cmp`,
the §32 lexicographic ordering declared in PATCH_06.md.

Before this PR: the declared fork-choice rule was dead code from a
production standpoint. `select_canonical_tip` existed and was
unit-tested, but the live import path used a different rule — honest
nodes could select divergent tips under adversarial network ordering.
G.11 in the v0.6.3 audit.

After this PR: `should_switch_to` constructs a `ChainTip` from each
chain and compares via `score_cmp`. The BFT-mode safety valve is
retained (both chains in deterministic mode OR finality-tied reorgs
refused) to preserve pre-Patch-06 behavior where the new rule would
equivalently admit a reorg.

### Design notes

- `cumulative_voting_power` is approximated by block height — each
  committed block represents ≥⅔ of active voting power, so height is
  a faithful proxy for "cumulative signed work" without walking every
  precommit set on every comparison. A dedicated per-block counter
  folded into `block.header` is available as a follow-up if a tighter
  accounting becomes necessary.
- `is_safe_reorg` is **not** yet called — it needs a common-ancestor
  height which `Chain` does not currently track. The BFT-mode tie
  refusal serves as the belt-and-braces equivalent until common-
  ancestor tracking lands.

### New test

`chain::tests::patch_06_fork_choice_uses_score_cmp_lexicographic_ordering`
is a regression fence against the primary-component-dominates property:
a chain with higher `finalized_depth` MUST beat a chain with higher
`height` when the two disagree. This was not true under the pre-§32
rule (it was, coincidentally, sometimes true for non-trivial cases —
making the bug silent).

### Release summary

**1219 tests, 9 crates, persistent block log + snapshots, all CI green.**

- 1219 tests across 9 crates (up from 1217 in v0.6.3).
- 27 versioned REST endpoints with CORS.
- 14 machine-readable ErrorCode variants.
- OpenAPI contract for the 27 versioned API routes, refreshable from
  Rust source in one command.

### Breaking changes

None. All 6 pre-existing `test_fork_choice_*` tests pass unchanged:
the §32 rewiring is behavior-equivalent on the scenarios they cover
(finalized_depth tiebreak first, height tiebreak second, BFT-mode
incumbency preserved). Hash tie-break is new but was reachable only
via same-finalized-same-height-different-block_id which the old rule
would have said "no switch" for — §32 says "switch to whichever has
the greater block_id," a strictly-deterministic total order.

## [v0.6.3] — Patch-07 §A groundwork: multi-validator convergence test

Patch-level release. Establishes the first multi-validator integration
test, closing one of the §36 deferrals from Patch-06 with a narrow
replay-determinism slice that exercises the full Patch-06 state
surface across three independent validators.

### New: `tests/multi_validator_convergence.rs`

Three validators drive an identical deterministic sequence of mutations
across:

- Constitutional-ceilings commit (§17)
- Validator-set commit (§15)
- Tension-history appends (§20)
- Admission-history appends (§27)
- Chain-version transition (§34)

After the sequence, all three validators MUST agree on `state_root()`
and on every projection (admission history, tension history, ceilings,
chain-version history). Three tests:

1. `multi_validator_state_roots_converge_on_patch_06_surface`
2. `multi_validator_patch_06_projections_match`
3. `multi_validator_repeated_runs_stable`

### Why this matters

The v0.5.0 and v0.6.0 audits both flagged the absence of multi-validator
integration. A full BFT harness is large and coupled to network
plumbing; this PR takes the narrower "replay determinism across N
independent validators" slice that is sufficient to regress-guard the
Patch-06 invariants. Any future change that introduces nondeterminism
(HashMap iteration, wall-clock read, non-canonical serialization) will
cause the state roots to diverge here.

### Release summary

**1217 tests, 9 crates, persistent block log + snapshots, all CI green.**

- 1217 tests across 9 crates (up from 1214 in v0.6.2).
- 27 versioned REST endpoints with CORS.
- 14 machine-readable ErrorCode variants.
- OpenAPI contract for the 27 versioned API routes, refreshable from
  Rust source in one command.

### Breaking changes

None. Test-only addition.

## [v0.6.2] — Patch-06.2: §33 state-root-preservation caveat + warming-window floor coverage

Patch-level release. Documentation and coverage; no behavior change.

### PATCH_06.md §33.4.1 addendum

Post-release review identified that the original §33.4 invariant
`post_root == pre_root` could not hold for in-trie namespaces —
specifically `system/validator_set_change_history`, whose serialized
value IS folded into the state root. Pruning those entries changes the
root, so admission-history pruning breaks cross-node state-root equality.

§33.4.1 (new subsection) documents this honestly:

- `post_root == pre_root` holds ONLY for outside-root namespaces
  (`block_receipts/*`, `snapshots/*`, `pruned_archive/*`).
- In-trie namespace pruning is intentionally stubbed
  (`PruningError::NotYetWired`) until Patch-07 §B defines a two-surface
  trie / deterministic-combiner accounting that preserves the
  cross-node invariant.
- Identification predicates remain consensus-neutral; no node has
  actually pruned anything.

`PruningReceipt::state_root_preserved` docstring updated to reflect the
narrower contract.

### Coverage: warming-window floor (§31)

New test `patch_06_floor_lifts_warming_window_fee` verifies that
`effective_fee_median_floored` applies the floor even when
`prior_tensions` is empty (the warming-window path that returns
`base_fee`). Closes a subtle INV-FEE-FLOOR-ENFORCED coverage gap — a
chain with no tension history is exactly the state an attacker would
engineer for fee bypass.

### Release summary

**1214 tests, 9 crates, persistent block log + snapshots, all CI green.**

- 1214 tests across 9 crates (up from 1213 in v0.6.1).
- 27 versioned REST endpoints with CORS.
- 14 machine-readable ErrorCode variants.
- OpenAPI contract for the 27 versioned API routes, refreshable from
  Rust source in one command.

### Breaking changes

None. No behavior changes in any runtime code path. Spec addendum is
additive.

## [v0.6.1] — Patch-06.1: INV-UPGRADE-ATOMICITY enforcement integration

Patch-level release. No new chain version; v5 rules unchanged.

### Wires INV-UPGRADE-ATOMICITY from "declared" to "enforced on every block"

Patch-06 §34 shipped the `verify_block_version_alignment` predicate
plus `UpgradeProposal` / `ChainVersionTransition` wire types, but the
block-import path did not yet consult the transition history — every
block was validated against a single `self.block_version` field. v0.6.1
closes the integration:

- **sccgub-state::chain_version_history_state** — new module with
  `chain_version_history_from_trie` reader and
  `append_chain_version_transition` writer. Trie key is
  `system/chain_version_history` (Patch-06 §34.4). 4 unit tests
  covering empty state, append+read, replay determinism, and
  end-to-end alignment-predicate round trip.
- **sccgub-node::chain::validate_candidate_block_for_round** — when
  `system/chain_version_history` contains transitions, the block's
  declared version is now checked via
  `sccgub_execution::chain_version_check::verify_block_version_alignment`
  against the active rule at its height. Pre-upgrade chains (empty
  history) retain the existing single-version check unchanged.

### Release summary

**1213 tests, 9 crates, persistent block log + snapshots, all CI green.**

- 1213 tests across 9 crates (up from 1209 in v0.6.0).
- 27 versioned REST endpoints with CORS.
- 14 machine-readable ErrorCode variants.
- OpenAPI contract for the 27 versioned API routes, refreshable from
  Rust source in one command.

### Breaking changes

None. Chains without admitted UpgradeProposals see zero behavior
change. Chains that admit an UpgradeProposal and append a
ChainVersionTransition now have INV-UPGRADE-ATOMICITY enforced at
block-import rather than only at unit-test-level predicate calls.

## [v0.6.0] — Patch-06: Layer 2 hardening (auth, fee floor, fork-choice, pruning, live-upgrade)

**Chain version introduced:** `header.version = 5`. v2–v4 chains continue
to replay under their existing rules; no forced migration. `v5` adds the
five Patch-06 invariants on top of PROTOCOL.md v2.0.

**Spec:** [PATCH_06.md](PATCH_06.md) — amends PROTOCOL.md v2.0. Introduces
§30–§34.

### Closes the top-5 fractures from the v0.5.0 adversarial audit

- **H.3 (CRITICAL) Forgery-proof authorization** → §30 introduces the
  `ForgeryVeto` envelope as the only admission vehicle for §15.7 Stage 2
  vetoes. A veto requires cryptographic malleability evidence AND ≥⅓
  voting-power of active-set attestations. Closes the "any caller can
  DoS a synthetic Remove" gap. INV-FORGERY-VETO-AUTHORIZED.
- **H.4 Fee floor** → §31 adds `min_effective_fee_floor` to
  `ConstitutionalCeilings`. Post-multiplier clamp in
  `effective_fee_median_floored` prevents coordinated low-tension
  blocks from collapsing the fee below spam-resistance threshold.
  Default 0.01 fee units; no-op on healthy chains. Legacy cascade via
  `LegacyConstitutionalCeilingsV1`. INV-FEE-FLOOR-ENFORCED.
- **H.5 Fork-choice determinism** → §32 declares the lexicographic rule
  `score(tip) = (finalized_depth, cumulative_voting_power,
  tie_break_hash)` and a reorg-safety predicate that rejects any reorg
  past `confirmation_depth` finalized blocks. Exercises
  INV-FORK-CHOICE-DETERMINISM via order-independent selection.
- **H.1 State pruning contract** → §33 declares
  `identify_prunable_admission_history` (retains newest per
  `agent_id`, marks superseded entries older than `pruning_depth =
  confirmation_depth * 16` as prunable) and the `PruningReceipt` with
  a `state_root_preserved()` invariant. Execution path
  (archive-and-delete over `pruned_archive/*`) stubbed with
  `PruningError::NotYetWired`; Patch-07 wires the redb-backed runtime.
  INV-STATE-BOUNDED contract.
- **H.2 Live-upgrade protocol** → §34 introduces `UpgradeProposal` with
  activation-height pattern, `DEFAULT_MIN_UPGRADE_LEAD_TIME = 14_400`
  blocks, adjacent-version and proposal_id-consistency checks, and
  `ChainVersionTransition` appended to
  `system/chain_version_history`. `verify_block_version_alignment`
  enforces INV-UPGRADE-ATOMICITY at block-import. Binary-registry
  integration deferred to Patch-07.

### Patch-06 v5 invariants

- INV-FORGERY-VETO-AUTHORIZED
- INV-FEE-FLOOR-ENFORCED
- INV-FORK-CHOICE-DETERMINISM
- INV-STATE-BOUNDED
- INV-UPGRADE-ATOMICITY

### Conformance

`crates/sccgub-node/tests/patch_06_conformance.rs` exercises all five
systems end-to-end plus a replay-determinism test. Deferrals enumerated
in PATCH_06.md §36.

### Breaking changes

None. v2/v3/v4 chains replay unchanged. v5 features activate only on
chains whose `header.version == 5`.

### Release summary

**1209 tests, 9 crates, persistent block log + snapshots, all CI green.**

- 1209 tests across 9 crates (up from 1155 in v0.5.0).
- 27 versioned REST endpoints with CORS.
- 14 machine-readable ErrorCode variants.
- OpenAPI contract for the 27 versioned API routes, refreshable from
  Rust source in one command.
- Five new Patch-06 invariants exercised by
  `patch_06_conformance.rs` end-to-end + replay-determinism tests.
- New modules: `sccgub-types::forgery_veto`, `sccgub-types::upgrade`,
  `sccgub-state::pruning`, `sccgub-consensus::fork_choice`,
  `sccgub-execution::forgery_veto`,
  `sccgub-execution::chain_version_check`.

## [v0.5.0] — Patch-05: Fee Oracle Hardening, Mfidel VRF, Patch-04 Deferrals

**Chain version introduced:** `header.version = 4`. v2 and v3 chains continue
to replay under their existing rules; no forced migration.

**Spec:** [PATCH_05.md](PATCH_05.md) — amends PROTOCOL.md v1.0 + PATCH_04.md.
On v0.5.0 tag, the three documents merge into PROTOCOL.md v2.0 (consolidated).

### Closes the last two structural fractures from the external audit

- **F5 — `T_prior` fee-oracle manipulability** → §20 replaces
  `gas_price = base_fee · (1 + α · T_prior / T_budget)` with a
  median-over-window oracle. Single-validator manipulation cannot move
  the median on odd windows; α and W gain constitutional ceilings.
- **F6 — Mfidel-seal grinding** → §21 folds `prior_block_hash` into
  registration seal derivation. A registrant cannot pre-compute the
  grid cell they will receive; wasted attempts cost registration gas.

### Closes all seven Patch-04 deferrals

- Evidence-sourced synthetic `Remove` admission wired into block
  builder (§22, INV-SLASHING-LIVENESS).
- `#![deny(clippy::iter_over_hash_type)]` extended to `sccgub-state`
  and `sccgub-execution` (§23).
- `confirmation_depth` moved from hardcoded `k=2` to `ConsensusParams`;
  §15.5 `activation_delay` consults the live field (§24).
- Typed `ProposalKind::ModifyConsensusParam` with closed
  `ConsensusParamField` + typed `ConsensusParamValue` enums (§25,
  INV-TYPED-PARAM-CEILING).
- `verify_strict` migration across consensus/execution/governance
  signature-verification paths (§26). Only `check_forgery_proof`
  retains intentional non-strict `verify` calls (demonstrates
  malleability by construction).
- Admitted-and-activated `ValidatorSetChange` history projection at
  `system/validator_set_change_history` + `GET /api/v1/validators/history/all`
  with cursor pagination (§27, INV-HISTORY-COMPLETENESS).
- PROTOCOL v2.0 consolidation (this release).

### New on-chain system entries

- `system/tension_history` — ring buffer of last `W ≤ 64` block
  tensions. Populated at v4 block commit; consumed by the median-fee
  oracle.
- `system/validator_set_change_history` — append-only admission tape;
  never pruned.

### New invariants

| ID | Enforcement |
|---|---|
| INV-FEE-ORACLE-BOUNDED (§20.5) | Fee-price bounded between window min and max |
| INV-SEAL-NO-GRIND (§21.4) | Phase 11 registration-seal match |
| INV-SLASHING-LIVENESS (§22.4) | Phase 12 evidence → synthetic Remove pairing |
| INV-TYPED-PARAM-CEILING (§25.4) | Governance submission |
| INV-HISTORY-COMPLETENESS (§27.4) | State-apply admission path |

### Per-crate changes

- **sccgub-types**: `ConsensusParams` +4 v4 fields, `ConstitutionalCeilings`
  +4 v4 ceilings, `EconomicState::effective_fee_median`,
  `MfidelAtomicSeal::from_height_v4`, `LegacyConsensusParamsV3` fallback,
  `BlockBody.equivocation_evidence: Option<_>`, `typed_params` module,
  `PATCH_05_BLOCK_VERSION = 4`.
- **sccgub-state**: new `tension_history` module, new
  `system/validator_set_change_history` trie entry + accessors,
  `#![deny(clippy::iter_over_hash_type)]` at crate root.
- **sccgub-execution**: new `evidence_admission` module, phase 11 v4
  seal check, phase 12 evidence branch + `max_equivocation_evidence_per_block`
  cap, CPoG check #12 now proposer-sourced-only, fee oracle wired
  (v4 → median, v1–v3 → legacy), `#![deny]` at crate root.
- **sccgub-consensus**: `verify_strict` migration across protocol +
  safety modules; intentional `verify` in `check_forgery_proof` retained.
- **sccgub-governance**: `validate_typed_param_proposal` for §25
  submission-time ceiling validation.
- **sccgub-api**: new `GET /api/v1/validators/history/all` with cursor
  pagination. OpenAPI artifact regenerated.

### Migration notes (v3 → v4)

Same §19.5 discipline: no in-place v3 → v4 upgrade on the same chain.
v4 chains are created by constructing a new genesis that forks state
from a v3 snapshot. v4 genesis requires `ConsensusParams` with the
four new fields and `ConstitutionalCeilings` with the four new
ceilings; every `(param, ceiling)` pair must be in bounds.

### Release summary

**1155 tests, 9 crates, persistent block log + snapshots, all CI green.**

- 1155 tests across 9 crates (up from 1078 in v0.4.0).
- 27 versioned REST endpoints with CORS.
- 14 machine-readable ErrorCode variants.
- OpenAPI contract for the 27 versioned API routes, refreshable from
  Rust source in one command.

Workspace clippy clean under
`cargo clippy --workspace --all-targets -- -D warnings`.

### Deferred to v0.6.x and beyond

- Formal finality proof (TLA+ / Ivy) for two-round BFT + view-change.
- State pruning.
- PII-exclusion rule for payloads (regulatory).
- Snapshot / fast-sync trust model.
- External price-oracle attestation (§20.3 reservation).
- Multi-validator production hardening + adversarial testnet.
- SOC 2 / regulatory certification.

---

## [v0.4.0] — Patch-04: Validator Set, Constitutional Ceilings, View-Change, Key Rotation

**Chain version introduced:** `header.version = 3`. v2 chains continue to replay
under v2 rules; no forced migration (see migration notes below).

**Spec amendment:** [PATCH_04.md](PATCH_04.md) — will be merged into PROTOCOL.md
as PROTOCOL v2.0 on v0.4.0 tag. PROTOCOL.md v1.0 remains the source of truth for v2.

### Closes structural fractures from the external audit

- **F1 — Undefined validator-set mutation** → §15 on-chain
  `ValidatorSetChange` events with deferred activation, replay-deterministic
  `active_set(H)`, auto-slashing on equivocation.
- **F2 — Missing view-change / liveness protocol** → §16 round timeouts
  with exponential backoff, deterministic leader selection folding
  `prior_block_hash`, signed `NewRound` messages, quorum-based round
  advancement.
- **F3 — Recursive-governance expansion of `ConsensusParams`** → §17
  `ConstitutionalCeilings` parallel struct, write-once at genesis,
  submission-time rejection of ceiling-raising proposals, phase-10
  enforcement.
- **F4 — Identity permanently bound to initial key material** → §18 signed
  `KeyRotation` events preserving `agent_id`, dual-signature requirement,
  global key index preventing reuse, phase-8 rejection of superseded keys.

### New on-chain system entries

- `system/validator_set` — canonical `ValidatorSet` with per-record
  `active_from` / `active_until`.
- `system/pending_validator_set_changes` — deferred-activation queue sorted
  by `(effective_height, change_id)`.
- `system/constitutional_ceilings` — genesis-committed ceiling values; any
  subsequent write is a phase-6 violation.
- `system/key_rotations` — append-only registry of `KeyRotation` events
  sorted by `(agent_id, rotation_height)`.
- `system/key_index` — global public-key-to-agent index, permanently
  retained, enforces §18.2 rule 7 (no reuse across agents).

### New invariants

| ID | Enforcement | Location |
|---|---|---|
| INV-VALIDATOR-SET-CONTINUITY | Replay-derivable from genesis + changes | Phase 12 |
| INV-VALIDATOR-KEY-COHERENCE | Record `validator_id` tracks `active_public_key` | Phase 8 + 12 |
| INV-VIEW-CHANGE-LIVENESS | Round history evidence for blocks at round > 0 | Phase 10 |
| INV-CEILING-PRESERVATION | Every ConsensusParams value ≤ its ceiling | Phase 10 |
| INV-KEY-ROTATION | Signatures verify under `active_public_key` | Phase 8 |

### Types layer (sccgub-types)

- `validator_set.rs` — `ValidatorRecord`, `ValidatorSet` (sorted by
  `agent_id` so key rotation does not reorder), `ValidatorSetChangeKind`
  with four variants (`Add`, `Remove`, `RotatePower`, `RotateKey`),
  `EquivocationEvidence` + `EquivocationVote`.
- `constitutional_ceilings.rs` — struct with `validate(&ConsensusParams)
  -> Result<(), CeilingViolation>` and PATCH_04.md §17.2 default values
  (safety-adjacent ×1–×2, throughput/economic ×4–×16 headroom).
- `key_rotation.rs` — `KeyRotation`, `KeyRotationRegistry`, `KeyIndex`,
  `KeyIndexEntry`.
- `ConsensusParams` extended with six v3 fields
  (`view_change_base_timeout_ms`, `view_change_max_timeout_ms`,
  `max_block_bytes`, `max_active_proposals`, `max_validator_set_size`,
  `max_validator_set_changes_per_block_param`);
  `LegacyConsensusParamsV2` fallback so v2 bytes continue to decode with
  v3 defaults injected.
- `BlockHeader.round_history_root: Hash` new at the end;
  `LegacyBlockHeaderV2` fallback for v2 bytes.
- `BlockBody.validator_set_changes: Option<Vec<ValidatorSetChange>>` — new
  optional field (`None` emits zero bytes under bincode; v2 canonical
  encoding preserved).
- `ChainEvent::ValidatorSetChanged` and `ChainEvent::KeyRotated` variants.

### State layer (sccgub-state)

- `validator_set_state.rs` — `commit_validator_set`,
  `validator_set_from_trie`, `apply_validator_set_change_admission` (with
  deduplication and canonical ordering), `advance_validator_set_to_height`
  (activation sweep applying Add / Remove / RotatePower / RotateKey with
  variant predicates).
- `key_rotation_state.rs` — `register_original_key`, `apply_key_rotation`
  (verifies both signatures with `verify_strict`), `active_public_key`
  resolver, global `KeyIndex` management.
- `constitutional_ceilings_state.rs` —
  `commit_constitutional_ceilings_at_genesis` (write-once enforcer),
  `constitutional_ceilings_from_trie`.

### Execution layer (sccgub-execution)

- `validator_set.rs` — §15.5 admission predicates as
  `validate_validator_set_change` / `validate_all_validator_set_changes`.
  Capture-prevention property explicitly tested: a post-change majority
  cannot self-admit because quorum is tallied against
  `active_set(H_admit)`.
- `ceilings.rs` — `validate_ceilings_for_block` short-circuiting to
  `NotV3` on pre-v3 blocks.
- `key_rotation_check.rs` — `check_tx_superseded_key` for phase 8.
- Phase 8 extension: rejects txs signed by superseded keys.
- Phase 10 extension: enforces constitutional ceilings on v3 blocks.
- Phase 12 extension: validates `ValidatorSetChange` events in block body.
- CPoG check #12: block-envelope re-validation of validator-set changes.

### Consensus layer (sccgub-consensus)

- `view_change.rs` — `NewRoundMessage`, `round_timeout_ms` with
  exponential backoff and saturating cap, `select_leader` folding
  `prior_block_hash` (ZERO_HASH sentinel for height 1), `RoundAdvance`
  state machine (BTreeMap-backed, quorum-tally by voting power).
- `equivocation.rs` — `synthesize_equivocation_removal` producing §15.7
  Stage 1 synthetic `Remove` with empty quorum_signatures (evidence-sourced
  bypass). `check_forgery_proof` for §15.7 Stage 2 narrow forgery-only
  veto.
- `#![deny(clippy::iter_over_hash_type)]` at the crate root. Existing
  iterations over HashMap converted to BTreeMap or sorted-iteration;
  9 HashMap usages removed from the consensus crate.

### Governance layer (sccgub-governance)

- `patch_04.rs` — `validate_consensus_params_proposal` for §17.8
  submission-time ceiling enforcement, `validate_ceilings_immutable`
  rejecting direct ceiling modifications, `required_precedence_for_change`
  mapping validator-set variants to precedence (Add/Remove → Safety;
  RotatePower/RotateKey → Meaning), `validate_key_rotation_submission`
  for §18.2 structural predicates.

### API layer (sccgub-api)

Four new versioned REST endpoints (total 26, up from 22):
- `GET /api/v1/validators` — active set with power + quorum tallies.
- `GET /api/v1/validators/history` — pending `ValidatorSetChange` queue.
- `GET /api/v1/ceilings` — `ConstitutionalCeilings` from state.
- `POST /api/v1/tx/key-rotation` — submit signed `KeyRotation` to
  mempool (idempotent by `(agent_id, rotation_height)`).

`AppState` extended with `pending_key_rotations: Vec<KeyRotation>`.
OpenAPI artifact regenerated to 26 documented paths.

### CLI (sccgub-node)

Three new subcommands:
- `sccgub validators` — print active validator set and quorum.
- `sccgub ceilings` — print `ConstitutionalCeilings`.
- `sccgub rotate-key --rotation-height N` — generate fresh keypair, sign
  `KeyRotation`, emit JSON on stdout with new-key hex on stderr.

### Crypto layer (sccgub-crypto)

- `verify_strict` added alongside existing `verify`. Used by all Patch-04
  consensus paths (§15.5, §16.4, §18.2). Existing `verify` call sites
  are untouched; migration of existing consensus paths beyond those
  introduced by Patch-04 is tracked for a follow-up.

### Conformance test

- `crates/sccgub-node/tests/patch_04_conformance.rs` exercises all four
  systems end-to-end in one deterministic flow (genesis → ceilings →
  validator-set Add/RotatePower/RotateKey/Remove → key rotation →
  view-change leader + timeout + partition quorum). Includes an explicit
  replay-determinism test: two independent runs produce identical state
  roots.

### Migration notes (v2 → v3)

There is **no in-place upgrade path** from v2 to v3 on the same chain
(§19.5). v2 chains continue to replay under v2 rules; they cannot admit
v3 events (parsers reject `ValidatorSetChange`, `KeyRotation`,
`NewRound`, `EquivocationEvidence` in v2 bodies). Operators who want v3
semantics must construct a new v3 genesis forking state from a v2
snapshot — this is a chain-identity change and is explicitly out of
scope for Patch-04.

v3 genesis requires `body.genesis_consensus_params`,
`body.genesis_validator_set`, and `body.genesis_constitutional_ceilings`;
every `(param, ceiling)` pair must be in bounds at genesis.

### Release summary

**1078 tests, 9 crates, persistent block log + snapshots, all CI green.**

- 1078 tests across 9 crates (up from 922 in v0.3.0).
- 26 versioned REST endpoints with CORS.
- 14 machine-readable ErrorCode variants.
- OpenAPI contract for the 26 versioned API routes, refreshable from Rust
  source in one command.

Workspace clippy clean under
`cargo clippy --workspace --all-targets -- -D warnings`.

### Deferred to follow-up patches

- Evidence-sourced synthetic Remove admission wiring in the block builder
  (the synthesis function exists in `sccgub-consensus/src/equivocation.rs`;
  builder-side integration scheduled for v0.4.x).
- Broad `HashMap → BTreeMap` replacement in `sccgub-state` (20 usages) and
  `sccgub-execution` (2 usages). The lint is enforced in the consensus
  crate only; state and execution currently rely on sorted-trie-based
  state roots for replay determinism.
- A block indexer exposing admitted-but-activated `ValidatorSetChange`
  history beyond the pending queue.
- Typed `ProposalKind::ModifyConsensusParam` variant;
  `validate_consensus_params_proposal` is callable today against a parsed
  proposal but no typed parser ships with v0.4.0.

---

## [v0.3.0] — 2026-04-08

### Production Hardening Release

**922 tests, 9 crates, persistent block log + snapshots, all CI green.**

#### Security
- Replace unmaintained `sled` with `redb 4.0` to resolve RUSTSEC-2025-0057 (fxhash) and RUSTSEC-2024-0384 (instant)
- Argon2id + ChaCha20-Poly1305 keystore with constant-time comparison (subtle crate)
- Domain-separated vote signatures: chain_id + epoch binding prevents cross-chain replay
- Signature minimum length enforcement (>= 64 bytes) across all 7 admission points
- Zeroize for all sensitive key material (derived keys, plaintext, key copies)
- String length limits on all artifact-layer types (DoS prevention)
- Sequential nonce enforcement (no gaps, exact last+1)
- API pending tx buffer capped (10K), seen IDs capped (100K)
- Peer registry capped (1K), subnet diversity enforced

#### Consensus
- Signed quorum certificates with cryptographic verification
- Persistent equivocation evidence store with cross-round tracking
- 13/13 Phi phases with real enforcement (Architecture, Feedback, Evolution)
- Deterministic fair tx ordering in mempool (anti-MEV)
- All discarded Results in consensus paths now logged
- Canonical `ConsensusParams` now embed in genesis, commit under `system/consensus_params`, and replay through import + snapshot restoration
- SCCE propagation depth/step caps, per-symbol scan/constraint caps, contract default step limits, gas schedule + limits, and validation size caps now replay from chain-bound `ConsensusParams`
- Default gas/world-state helper constructors now derive from `ConsensusParams`, and contract invoke arg-size rejection uses the live `max_state_entry_size` bound
- P2P block gossip + sync loop wired (hello/heartbeat/tx gossip/block request-response), proposer rotation gating, consensus vote propagation, and multi-round timeouts

#### Economics
- Gas metering wired into block production (12 cost categories)
- Treasury with fee/reward/burn lifecycle and epoch management
- Fee debits, treasury counters, and fixed block rewards now replay through CPoG/import and commit into trie-backed state
- Block version 2 now funds validator liquidity through the canonical agent account while preserving block version 1 signer-account replay compatibility
- Escrow with StateProof conditions (value + authority match)
- Block gas limit enforcement (50M default)
- Delta-only balance trie commits remove the prior O(n) end-of-block rewrite

#### Governance
- Timelocks: ordinary 50 blocks, constitutional 200 blocks
- Settlement finality classes: Soft, Economic, Legal
- 6 operator key roles with rotation ceremony
- On-chain parameter proposals via `norms/governance/params/propose` and votes via `norms/governance/proposals/...`
- CLI governance registry status command

#### Known Limits (MVP)
- Default single-proposer mode when no validator set is configured (validator set snapshots persist across restarts)
- Replay-authoritative state without a fully durable state database (optional redb-backed trie mirror available)
- Minimal p2p networking (no hardened peer discovery or deeper DoS protection)
- No ZK/privacy layer (placeholder types only)
- ContractInvoke namespace tightened to `contract/` only (was `contract/` + `data/`)
- No state pruning implementation yet

#### API
- 22 versioned REST endpoints with CORS
- 14 machine-readable ErrorCode variants
- OpenAPI contract for the 22 versioned API routes, refreshable from Rust source in one command
- Block detail response now includes governance limits and finality config snapshots
- Network peers endpoint with bandwidth + score visibility
- Idempotency key support
- Transaction validation against state before admission
- Receipt and block-receipts lookup endpoints
- Governance parameter proposal and vote submission endpoints
- Governance proposal registry endpoint

#### Observability
- 18 typed ChainEvent variants with active emission in block production
- Runtime invariant monitor (7 checks: supply, nonce, state root, tension, receipts, causality)
- Production-grade ChainMetrics (finality, economics, mempool, security)

#### External Artifact Layer
- ArtifactRef, ArtifactAttestation, LineageEdge, AccessGrant, UsageLicense
- PolicyVerdictReceipt, SessionCommit, EpochCommit, DisputeClaim
- SchemaEntry with lifecycle (Active/Deprecated/Frozen/Retired)

#### Future Primitives
- Post-quantum crypto agility (ML-DSA, SLH-DSA, hybrid signatures)
- Session keys / account abstraction
- State pruning / archival policies
- Zero-knowledge commitment support
- Symbolic intelligence agent circuit breakers (Closed/Open/HalfOpen lifecycle)

#### Five-Plane Coordination
- CapabilityLease with bounded delegation
- Mission ledger (11-state lifecycle)
- Evidence gateway (6 evidence types)
- 7 safety modes (Normal through Quarantine)
- Autonomy budgets for off-chain decision authority

#### Testing
- 922 tests across 9 crates
- Property-based tests (3000+ random scenarios)
- Adversarial consensus tests (Byzantine, partition, equivocation)
- Full-pipeline integration tests (treasury, escrow, artifacts, delegation, events)
- Financial conservation proofs (transfer, treasury, escrow)

## [v0.2.0] — 2026-04-07

- 9-crate architecture established
- Two-round BFT consensus with Ed25519 signatures
- 13-phase Phi validation framework
- Multi-asset ledger and balance trie commitment
- CLI with 20 commands
- REST API with health/status/block/state endpoints
- GDPR compliance module
- Bridge adapter framework

## [v0.1.0] — 2026-04-07

- Initial implementation from SCCGUB v2.1 specification
- Core types, crypto, and state modules
- Genesis block production and validation
