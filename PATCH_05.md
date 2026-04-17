# SCCGUB Protocol Amendment — Patch 05

**Target version:** v0.5.0
**Amends:** PROTOCOL.md v1.0 (FROZEN) + PATCH_04.md §15–§19
**Amendment status:** DRAFT — pending governance proposal with constitutional timelock (200 blocks).
**Chain version introduced:** `header.version = 4`. v2 and v3 chains replay under their existing rules.

This document amends PROTOCOL.md v1.0 and extends the PATCH_04.md §15–§19 amendments. When v0.5.0 ships, PROTOCOL.md, PATCH_04.md, and PATCH_05.md merge into PROTOCOL v2.0 (single consolidated spec). Until then, all three documents are load-bearing.

Patch-05 closes the two remaining structural fractures from the external audit — F5 (fee-oracle manipulability) and F6 (Mfidel-seal grinding) — plus the seven Patch-04 deferrals.

- **F5 — `T_prior` fee-oracle manipulability** → §9 replaced with median-over-window; constitutional cap on `α`; external-signal option for future extension (§20).
- **F6 — Mfidel-seal grinding** → §3 seal derivation folds `prior_block_hash` into a VRF-derivable position; grinding attacker cannot choose registration grid cell (§21).
- **Follow-up 1** — Evidence-sourced synthetic `Remove` admission wired into the block builder (§22).
- **Follow-up 2** — Broad `HashMap → BTreeMap` replacement; `#![deny(clippy::iter_over_hash_type)]` extended to `sccgub-state` and `sccgub-execution` (§23).
- **Follow-up 3** — `confirmation_depth` moved from hardcoded `k=2` to `ConsensusParams`; `activation_delay` (§15.5) consults it live (§24).
- **Follow-up 4** — Typed `ProposalKind::ModifyConsensusParam` variant; `validate_consensus_params_proposal` from Patch-04 governance now has a typed submission path (§25).
- **Follow-up 5** — `verify_strict` migration across all consensus signature verification paths; existing `verify` calls replaced crate-by-crate (§26).
- **Follow-up 6** — Admitted-and-activated `ValidatorSetChange` history projection (§27); new API endpoint `GET /api/v1/validators/history/all`.
- **Follow-up 7** — PROTOCOL v2.0 consolidation: on v0.5.0 tag, PATCH_04.md §15–§19 + PATCH_05.md §20–§27 are merged into a single `PROTOCOL.md` v2.0 document.

All Patch-05 rules are consensus-critical. Any conforming v4 implementation MUST produce identical state roots given identical inputs.

---

## §20 Fee Model Hardening (replaces §9 for v4)

Before Patch-05, `gas_price = base_fee · (1 + α · T_prior / T_budget)` allowed the producer of block N-1 to unilaterally influence the fees users of block N paid. A cartel of validators could drive `T_prior` up or down to manipulate the fee oracle. §20 closes this by replacing the single-block lookup with a bounded median over a rolling window.

### 20.1 Median-over-window fee oracle

```
T_window(H)  = [T(H-W), T(H-W+1), ..., T(H-1)]          # W prior tensions
T_median(H)  = median(T_window(H))                       # sorted-middle value
gas_price(H) = base_fee * (1 + α * T_median(H) / T_budget)
tx_fee       = gas_used * gas_price(H)
```

- `W` (median window size) is a new `ConsensusParams` field, `median_tension_window`. Default 8 blocks. Must be odd (deterministic middle); if set even, validation rejects.
- `α` (tension multiplier) is a new `ConsensusParams` field, `fee_tension_alpha`. Default 0.5 (fixed-point, i128 / SCALE).
- For blocks where `H < W`, the window shortens to `[T(0), ..., T(H-1)]`. Below height W, the oracle effectively smooths less aggressively.

### 20.2 Constitutional caps on α and W

`ConstitutionalCeilings` gains two new fields:
- `max_fee_tension_alpha_ceiling: i128` — upper bound on `α`. Default `1.0 · SCALE` (= `SCALE`). No governance path may raise `α` beyond unit. An `α > 1` means T_median can more than double the base fee, which is an economic capture vector; capped at unit.
- `max_median_tension_window_ceiling: u32` — upper bound on `W`. Default 64 blocks. Larger windows smooth more but also make the oracle lag actual network state; capped to prevent governance-driven stalling of the fee signal.

### 20.3 External signal (reserved for future extension)

§20.3 is reserved. Future patches MAY introduce an externally-provided price oracle that feeds `base_fee` via a signed attestation from a multi-sig committee. Patch-05 does not specify this mechanism; the spec slot is reserved so that downstream patches can reference §20.3 without renumbering.

### 20.4 Replay-determinism clause

`T_median` is computed from on-chain tension values only. Every conforming node with the same block history MUST produce identical `T_median(H)` for every `H`. No wall-clock, no randomness, no external input.

### 20.5 Invariant

**INV-FEE-ORACLE-BOUNDED**: For all v4 heights H with `H >= W`:
- `T_median(H) >= min(T_window(H))`, and
- `T_median(H) <= max(T_window(H))`,

which together bound `gas_price(H) <= base_fee · (1 + α · max(T_window) / T_budget)`. A single block's tension spike cannot move the median by more than its rank-contribution; a cartel would need to control at least `ceil(W/2)` consecutive producers to push the median.

---

## §21 Mfidel Seal De-grinding (amends §3 for v4)

Before Patch-05, `seal(height) = MfidelAtomicSeal::from_height(height)` made the seal a pure function of registration height. An attacker could time registrations to land on preferred grid cells (e.g., if any governance weight or symbolic semantic gets attached to specific fidels). §21 closes this by folding the prior block hash into seal derivation, so a registrant cannot predict the grid cell they'll receive more than one block in advance.

### 21.1 v4 seal derivation

```
seal_v4(height, prior_block_hash) =
    let h = BLAKE3("sccgub-mfidel-seal-v4" || prior_block_hash || height.to_le_bytes())
    let row    = (h[0] as u32 % 34) + 1     # 1..=34
    let column = (h[1] as u32 % 8)  + 1     # 1..=8
    MfidelAtomicSeal { row, column }
```

- For `height == 0` (genesis), `prior_block_hash = ZERO_HASH` (consistent with §16.2 convention).
- For `height >= 1`, `prior_block_hash = block[height - 1].block_id`.
- The domain separator `"sccgub-mfidel-seal-v4"` prevents cross-version preimage collisions with `MfidelAtomicSeal::from_block` (Patch-03 content-bound seal, still present for header-level seals at v3 and earlier).

### 21.2 Backwards compatibility

- v1/v2/v3 chains continue to use `MfidelAtomicSeal::from_height` for all seal derivations (both header seals and registration seals).
- v4 chains use `seal_v4(height, prior_block_hash)` for **registration seals only**. Header seals (§5 block header `mfidel_seal` field) continue to use `from_height` — this keeps the deterministic-per-height Ge'ez cycle visible in the header stream.
- The chain version selector is `header.version`, so v3 and v4 block replays produce distinct seals by construction.

### 21.3 Grinding cost

With v4 seal derivation, an attacker who wants a specific `(row, column)` must:
1. Wait for a block to be produced.
2. Compute the seal that would result if they registered in block N+1.
3. If not their preferred cell: abandon and wait for block N+2.

Each attempt has probability `1 / 272` (the grid size) of landing on a specific cell. Over K attempts, cost is O(K blocks × registration cost). Registration is gas-metered at `gas_tx_base + gas_payload_byte · |payload|`, so the attacker pays for every miss. This degrades grinding from trivial (pick your height) to economically bounded.

### 21.4 Invariant

**INV-SEAL-NO-GRIND**: For all v4 heights H > 0 and all registration transactions admitted at H:
- `tx.actor.mfidel_seal == seal_v4(H, block[H-1].block_id)`.

Any registration whose seal does not match the current block's expected value is rejected at phase 3 (Ontology) or phase 8 (Execution).

---

## §22 Evidence-Sourced Slashing Admission (completes §15.7)

Patch-04 Commit 5 introduced `synthesize_equivocation_removal` producing a synthetic `ValidatorSetChange::Remove` with empty `quorum_signatures` (§15.7 Stage 1 "evidence-sourced bypass"). The block-builder integration was deferred. §22 closes this.

### 22.1 Block admission with evidence-sourced Remove events

When a block carries an `EquivocationEvidence` record in `body.equivocation_evidence: Option<Vec<EquivocationEvidence>>` (new v4 field), the block producer MUST:

1. For each admitted `EquivocationEvidence`, compute `synthesize_equivocation_removal`.
2. Include each resulting synthetic `ValidatorSetChange::Remove` in `body.validator_set_changes`.
3. The synthetic event's `quorum_signatures` is empty — this is §15.7's explicit bypass.

### 22.2 Phase 12 validation branch

Phase 12 (Feedback) now admits `ValidatorSetChange::Remove` events under two branches:

- **Proposer-sourced** (normal path): `quorum_signatures` non-empty; validated by §15.5 predicates including quorum against `active_set(H_admit)`.
- **Evidence-sourced** (§22): `quorum_signatures` empty; validated by cross-checking the referenced `EquivocationEvidence` in the same block body. The evidence must be structurally valid (§15.7), signatures must verify under `verify_strict`, and the resolved validator must be in `active_set(H_admit)`.

A synthetic Remove without a matching evidence record in the same block is rejected. A non-empty `quorum_signatures` on an evidence-sourced event is also rejected (the two paths MUST be distinguishable).

### 22.3 Block body extension

`BlockBody` gains a new optional field:
```
#[serde(default, skip_serializing_if = "Option::is_none")]
pub equivocation_evidence: Option<Vec<EquivocationEvidence>>,
```
Same Option-discipline as §15.4 `validator_set_changes`: `None` emits zero bytes under bincode; v3 canonical encoding preserved.

### 22.4 New invariant

**INV-SLASHING-LIVENESS**: For every admitted `EquivocationEvidence` record at height H, `body.validator_set_changes` MUST contain a synthetic `ValidatorSetChange::Remove` with:
- `kind.agent_id` resolving from `evidence.vote_a.validator_id` via `active_set(H)`,
- `kind.reason == RemovalReason::Equivocation`,
- `kind.effective_height == H + activation_delay`,
- `quorum_signatures.is_empty()`.

---

## §23 Determinism Lint Extension (completes Patch-04 Commit 5)

Patch-04 enforced `#![deny(clippy::iter_over_hash_type)]` at the `sccgub-consensus` crate root. State and execution retained 20+2 HashMap iterations as deferred follow-up. §23 closes this.

### 23.1 Extended lint coverage

The lint is now enforced at the crate root of:
- `sccgub-state`
- `sccgub-execution`
- (already-enforced) `sccgub-consensus`

### 23.2 Audit outcome

All existing HashMap iterations in `sccgub-state` (primarily `ManagedWorldState.agent_nonces` for nonce tracking and `TensionField.map` for per-symbol tension) are either:
- Replaced with `BTreeMap` (where iteration affects state root or replay determinism), or
- Confirmed as lookup-only (`.get()`, `.contains_key()`, `.insert()`) and retained with explicit `#[allow]` annotations where the lint would false-positive.

The per-crate inventory and migration rationale lives in a commit-scoped audit note; the spec-level requirement is: **any consensus-critical iteration produces a deterministic ordering**.

### 23.3 Canonical encoding discipline (restatement)

This section restates the PATCH_04.md Canonical Encoding Discipline and extends it: no `HashMap` / `HashSet` iteration in any consensus-critical path in any consensus-critical crate. Lookup-only uses are permitted.

---

## §24 Finality Configuration (completes hardcoded k=2)

Patch-04 Commit 4 used `confirmation_depth = 2` as a hardcoded constant in phase-12 validator-set-change activation. §24 makes it a tunable `ConsensusParams` field.

### 24.1 ConsensusParams addition

```
confirmation_depth: u64,                  // default 2
```

### 24.2 Consumers

- §15.5 `activation_delay = clamp(confirmation_depth + 1, 2, confirmation_depth + 8)` now consults the live field.
- §7 Settlement classes continue to use fixed depths (0 / 2 / 6) — those are semantic finality classes, not consensus parameters.

### 24.3 Constitutional ceiling

`ConstitutionalCeilings` gains:
```
max_confirmation_depth_ceiling: u64,      // default 8
```
The upper bound prevents governance from raising `k` to a value that freezes validator-set changes indefinitely (since `activation_delay` scales with `k`).

### 24.4 Validation

`ConsensusParams::validate` rejects `confirmation_depth == 0` (zero would collapse to instant finality without any confirmation window) and `confirmation_depth > max_confirmation_depth_ceiling`.

---

## §25 Typed ConsensusParams Proposals

Patch-04 §17.8 added `validate_consensus_params_proposal` but governance submissions remained string-based via `ProposalKind::ModifyParameter { key, value }`. §25 adds a typed submission path.

### 25.1 New proposal variant

```
ProposalKind::ModifyConsensusParam {
    field: ConsensusParamField,           // enum: MaxProofDepth, DefaultTxGasLimit, ...
    new_value: ConsensusParamValue,       // enum: U32, U64, I64, I128
    activation_height: BlockHeight,       // when change takes effect if activated
}
```

### 25.2 Submission path

At submission:
1. The proposer parses the typed `(field, new_value)` pair into a `ConsensusParams` clone with just that field modified.
2. Patch-04 `validate_consensus_params_proposal(modified, ceilings)` runs against the current `ConstitutionalCeilings`.
3. If any ceiling would be violated, submission is rejected (§17.8).

The existing string-based `ProposalKind::ModifyParameter` continues to work for non-consensus parameters.

### 25.3 Typed activation

When a `ModifyConsensusParam` proposal activates after timelock, the corresponding `ConsensusParams` field is updated at `activation_height` (not at activation-block height). This separates governance timelock from live-state cut-over.

### 25.4 New invariant

**INV-TYPED-PARAM-CEILING**: Every accepted `ModifyConsensusParam` proposal satisfies `validate_consensus_params_proposal` at submission AND at activation. If the ceiling changes between submission and activation (via a separate hard-fork path), the proposal is re-checked and rejected at activation if no longer valid.

---

## §26 verify_strict Migration (closes signature malleability surface)

Patch-04 Commit 3 added `verify_strict` and used it in Patch-04 paths only. Existing consensus paths (§6 vote admission, §12 governance-signature checks) continued to use the non-strict `verify`. §26 migrates all consensus-critical signature verification to `verify_strict`.

### 26.1 Migration scope

All call sites in `sccgub-consensus/src/protocol.rs` (vote admission), `sccgub-consensus/src/safety.rs` (finality certificate signing), `sccgub-execution/src/validate.rs` (tx signature verification), and `sccgub-governance/src/proposals.rs` (proposal-vote signature verification) are migrated.

### 26.2 Backwards compatibility

`verify_strict` rejects non-canonical Ed25519 signatures that `verify` accepts. In theory, this could reject already-admitted historical votes. In practice, Ed25519 signers (`ed25519-dalek`) never produce non-canonical signatures; `verify_strict` only rejects adversarially-constructed ones. Replay of v1/v2/v3 chains continues to succeed under `verify_strict` as long as historical signatures were produced by conforming signers.

### 26.3 Non-strict call sites retained

`verify_strict` is NOT used in:
- `sccgub-consensus/src/equivocation.rs::check_forgery_proof` — this function explicitly calls both `verify` and `verify_strict` to demonstrate malleability (§15.7 Stage 2).
- Test helpers that need to construct specific signature scenarios.

---

## §27 Admitted-and-Activated Change History Projection

Patch-04 `GET /api/v1/validators/history` returned only the pending queue (admitted but not yet effective). Observers had no way to see what changes had historically taken effect. §27 adds a durable history projection.

### 27.1 New state entry

`system/validator_set_change_history` stores `Vec<ValidatorSetChange>` — the full admission-ordered list of every change ever admitted to the chain. At each admission in §15.5, the change is appended here in addition to the pending queue.

Canonical ordering: admission order (append-only). Canonical bincode of the entry commits to the full historical tape.

### 27.2 New API endpoint

`GET /api/v1/validators/history/all` returns the full list with a cursor-based pagination parameter (`?after_change_id=...&limit=N`).

### 27.3 Pruning

History is permanent by default. Future patches MAY introduce pruning gated on finality depth; §27 does not specify a pruning mechanism.

### 27.4 Invariant

**INV-HISTORY-COMPLETENESS**: For any admitted `ValidatorSetChange`, the event appears in `system/validator_set_change_history` at admission. No admitted change is silently lost; no non-admitted change appears here.

---

## §28 Version 4 Migration

v0.5.0 introduces `header.version = 4`. v2 and v3 chains replay under their existing rules.

### 28.1 v4 genesis requirements

A v4 genesis block MUST satisfy:
1. `header.version == 4`.
2. All v3 genesis requirements (§19.1).
3. `body.genesis_consensus_params` includes the v4 additions:
   - `median_tension_window: u32` (default 8, must be odd)
   - `fee_tension_alpha: i128` (default 0.5 · SCALE)
   - `confirmation_depth: u64` (default 2)
4. `body.genesis_constitutional_ceilings` includes:
   - `max_fee_tension_alpha_ceiling: i128`
   - `max_median_tension_window_ceiling: u32`
   - `max_confirmation_depth_ceiling: u64`
5. Every `(param, ceiling)` pair in the expanded §17.2 table is in bounds.

### 28.2 v4 consensus semantics

v4 chains enforce:
- §20: fee oracle via median-over-window instead of single-block `T_prior`.
- §21: registration seals via VRF-over-prior-block-hash.
- §22: evidence-sourced slashing admission with empty `quorum_signatures`.
- §23: broad determinism lint discipline.
- §24: dynamic `confirmation_depth` from `ConsensusParams`.
- §25: typed `ModifyConsensusParam` submissions.
- §26: `verify_strict` on every consensus signature.
- §27: admitted-and-activated change history projection.

### 28.3 v3 chain behavior

v3 chains continue to replay under PATCH_04.md rules. They cannot admit v4 events; parsers reject `EquivocationEvidence` in v3 `body` decoding. The v3 fee oracle remains as-specified in PROTOCOL.md §9.

### 28.4 No silent upgrade

Same clause as §19.5: there is no in-place upgrade from v3 to v4 on the same chain. Operators migrate by producing a new v4 genesis forking state from a v3 snapshot.

---

## §29 Expanded ConstitutionalCeilings (v4)

`ConstitutionalCeilings` gains four new fields in v4:

| Field | v4 default | Headroom | Companion `ConsensusParams` | v4 default |
|---|---|---|---|---|
| `max_fee_tension_alpha_ceiling` | `SCALE` (1.0) | ×2 (economic) | `fee_tension_alpha` | `SCALE/2` (0.5) |
| `max_median_tension_window_ceiling` | 64 | ×8 (signal lag) | `median_tension_window` | 8 |
| `max_confirmation_depth_ceiling` | 8 | ×4 (finality) | `confirmation_depth` | 2 |
| `max_equivocation_evidence_per_block` | 16 | — (slashing DoS) | `max_equivocation_evidence_per_block_param` | 4 |

Canonical bincode field order (v4 expansion): existing v3 fields in their declaration order, followed by the four v4 additions in the order above.

---

## Amended invariants (v0.5.0)

Patch-05 preserves all PROTOCOL.md v1.0 + PATCH_04.md invariants and adds five new v4-only invariants:

| ID | Enforcement |
|---|---|
| INV-FEE-ORACLE-BOUNDED (§20.5) | Phase 9 |
| INV-SEAL-NO-GRIND (§21.4) | Phase 3 (Ontology) / Phase 8 (Execution) for registrations |
| INV-SLASHING-LIVENESS (§22.4) | Phase 12 |
| INV-TYPED-PARAM-CEILING (§25.4) | Governance submission + activation |
| INV-HISTORY-COMPLETENESS (§27.4) | State-apply invariant |

---

## Conformance Matrix (Patch-05)

Each normative rule has at least one conformance test under `patch_05_*` naming:

| Rule | Test | Crate |
|---|---|---|
| §20.1 median-over-window computation | `patch_05_fee_oracle_median_window` | `sccgub-execution` |
| §20.2 α ceiling rejection | `patch_05_fee_alpha_over_ceiling_rejected` | `sccgub-governance` |
| §20.5 INV-FEE-ORACLE-BOUNDED | `patch_05_fee_bounded_between_min_and_max` | `sccgub-execution` |
| §21.1 v4 seal derivation | `patch_05_seal_v4_includes_prior_hash` | `sccgub-types` |
| §21.2 backwards compat | `patch_05_seal_v3_unchanged_under_v4_code` | `sccgub-types` |
| §21.4 INV-SEAL-NO-GRIND | `patch_05_registration_with_wrong_seal_rejected` | `sccgub-execution` |
| §22.2 evidence-sourced branch | `patch_05_evidence_sourced_remove_admitted` | `sccgub-execution` |
| §22.2 proposer-sourced rejection with empty sigs | `patch_05_proposer_sourced_empty_sigs_rejected` | `sccgub-execution` |
| §22.4 INV-SLASHING-LIVENESS | `patch_05_slashing_liveness_enforced` | `sccgub-execution` |
| §23.1 lint extension | `patch_05_state_crate_enforces_iter_over_hash_type` | compile-time |
| §24.1 confirmation_depth field | `patch_05_confirmation_depth_ceiling` | `sccgub-types` |
| §24.3 ceiling rejection | `patch_05_confirmation_depth_over_ceiling_rejected` | `sccgub-governance` |
| §25.1 typed variant | `patch_05_typed_modify_consensus_param_submission` | `sccgub-governance` |
| §25.4 INV-TYPED-PARAM-CEILING | `patch_05_typed_param_re_check_at_activation` | `sccgub-governance` |
| §26.1 migration coverage | `patch_05_all_consensus_paths_use_verify_strict` | grep-based CI check |
| §27.1 history append | `patch_05_history_projection_append_only` | `sccgub-state` |
| §27.4 INV-HISTORY-COMPLETENESS | `patch_05_no_admitted_change_missing_from_history` | `sccgub-state` |
| §28.1 v4 genesis | `patch_05_v4_genesis_requires_fields` | `sccgub-state` |
| Cross-cutting | `patch_05_conformance` (integration) | workspace root |

---

## Patch-05 does NOT address

Explicitly deferred to v0.6.x and beyond:

- **Formal finality proof** (TLA+ / Ivy mechanized model of two-round BFT + view-change). Required for v0.6.0.
- **State pruning** — state trie grows unboundedly; pruning gated on finality depth is a v0.6.x item.
- **PII-exclusion for payloads** (regulatory / GDPR) — v0.9.x regulatory patch.
- **Snapshot / fast-sync trust model** — v0.6.x operational hardening.
- **External price-oracle attestation** (§20.3 reservation) — v0.6.x+.
- **SOC 2 / regulatory certification** — v0.9.x.

---

## Resolved decisions (drafting audit trail)

1. **Fee oracle window size W**: chose 8 as default (balance between smoothing and signal lag). Constitutional ceiling 64 caps governance-driven stalling.
2. **α cap at 1.0 · SCALE**: `α > 1` means a single window of high tension can more than double the base fee. That's an economic capture vector even with median smoothing; pinned at unit.
3. **v4 seal only on registration**: header seal (§5) stays deterministic-per-height so observers can see the Ge'ez cycle in the header stream. Only registration is de-grinded.
4. **Evidence-sourced Remove carries empty `quorum_signatures`**: §15.7's explicit bypass. Phase 12 branches on the empty-vs-non-empty distinction rather than adding a variant flag.
5. **`verify_strict` migration is all-or-nothing per consensus crate**: partial migration leaves a malleability surface. Crate-by-crate migration with explicit `#[allow]` on intentional `verify` call sites (forgery-proof check).
6. **History projection is append-only with no pruning in v0.5.0**: pruning introduces a trust model (who decides to prune?) that belongs in a later operational-hardening patch.
7. **v4 introduced as a new chain version, not a migration on v3**: consistent with §19.5 discipline. Operators choose v3 or v4 at genesis; no live upgrade.

---

*End of PATCH_05.md.*
