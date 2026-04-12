# SCCGUB External Audit Preparation Guide

**Version:** 0.3.0
**Date:** 2026-04-11
**Repo:** 9 crates, 608 tests, hardening-stage reference runtime with optional p2p alpha

**Known Limits (MVP) Summary:**
- Default single-proposer mode when no validator set is configured
- Replay-authoritative state without a fully durable state database
- Minimal p2p networking (no hardened peer discovery or deeper DoS protection)
- No ZK/privacy layer (placeholder types only)
- ContractInvoke namespace still maps to both `contract/` and `data/`
- No state pruning implementation yet

---

## 1. Project Overview

SCCGUB (Symbolic Causal Chain General Universal Blockchain) is a Rust governed
blockchain kernel with a reference runtime that can run in single-node mode
or with optional p2p networking. Every
state transition carries a causal proof, is validated through a 13-phase Phi
traversal pipeline, and is governed by a strict precedence hierarchy
(GENESIS > SAFETY > MEANING > EMOTION > OPTIMIZATION).

**Core differentiators:**
- Causal Proof-of-Governance (CPoG) consensus — blocks carry verifiable proofs
  that every transition was validated against the governance framework
- 13-phase Phi traversal — each transition is checked for distinction, constraint
  satisfaction, ontology compliance, topology, form, organization, module binding,
  payload consistency, body coherence, architecture, performance, feedback, and evolution
- Default-deny namespace ontology — each TransitionKind can only write to
  explicitly allowed namespace prefixes
- Fixed-point arithmetic (i128, 18 decimal places) — no floating-point in
  consensus-critical code
- WHBinding 7-tuple (who/when/where/why/how/which/what) — every transition
  declares and is verified against its full causal context

## 2. Architecture

```
sccgub-types       Core type definitions (Block, Transition, WHBinding, TensionValue, etc.)
sccgub-crypto      Blake3 hashing, Merkle trees, Ed25519 signatures, Argon2id keystore
sccgub-state       Replay-authoritative Merkle Patricia Trie, WorldState, BalanceLedger, TensionField
sccgub-execution   13-phase Phi traversal, CPoG validation, SCCE constraint engine
sccgub-consensus   Two-round BFT protocol, safety certificates, equivocation detection
sccgub-governance  Precedence enforcement, norm registry, validator selection, proposals
sccgub-network     P2P message types, peer registry, basic runtime hooks
sccgub-api         REST API router + handlers, structured errors, 21 versioned endpoints
                   OpenAPI contract: `crates/sccgub-api/openapi.yaml` (refreshable from Rust source in one command)
sccgub-node        CLI binary: genesis, block production, chain lifecycle, mempool, block log, snapshots
```

## 3. Consensus-Critical Code Paths

Auditors should focus on these files first:

| File | Purpose | Lines |
|------|---------|-------|
| `sccgub-execution/src/phi.rs` | Phi traversal engine (dual-path: block + tx) | ~810 |
| `sccgub-execution/src/validate.rs` | Transaction validation (8-step pipeline) | ~350 |
| `sccgub-execution/src/cpog.rs` | CPoG 11-check block validation | ~310 |
| `sccgub-execution/src/ontology.rs` | Default-deny namespace table | ~210 |
| `sccgub-execution/src/payload_check.rs` | Payload-intent consistency | ~280 |
| `sccgub-execution/src/scce.rs` | Constraint propagation walker | ~570 |
| `sccgub-execution/src/wh_check.rs` | WHBinding completeness checker | ~170 |
| `sccgub-node/src/chain.rs` | Chain lifecycle, block production | ~1370 |
| `sccgub-state/src/apply.rs` | State application (checks-effects-interactions) | ~320 |

## 4. Security Properties

### 4.1 Invariants Maintained

1. **No floating-point in consensus** — All monetary values use `TensionValue(i128)` with 18 decimal places
2. **Default-deny ontology** — `allowed_namespaces()` returns empty slice for unimplemented kinds
3. **system/ namespace unreachable** — No TransitionKind maps to NS_SYSTEM (exhaustive test)
4. **Duplicate tx_id rejection** — HashSet guard in `apply_block_transitions()`
5. **Sequential nonce enforcement** — `nonce == last_nonce + 1` in validate.rs, world.rs, mempool.rs
6. **Checks-effects-interactions** in state application — all transfers computed, then state writes, then trie commitment
7. **Single signing payload source** — `block_signing_payload()` used by both sign and verify paths
8. **Domain-separated vote signatures** — chain_id + epoch bound into vote signing data
9. **Fail-closed constraint propagation** — SCCE rejects on step exhaustion, not accepts
10. **Null-byte terminated constraint keys** — Prevents prefix collision (N-1 fix)

### 4.2 Known Limitations (MVP)

1. **Default single-proposer mode** — Proposer rotation is active when a validator set is configured, but the reference CLI defaults to a single validator
2. **Replay-authoritative state** — Blocks, metadata, encrypted validator keys, and periodic snapshots persist across restarts, but there is no fully durable state database
3. **P2P networking is minimal** — Hello/heartbeat/tx gossip, block sync, vote propagation, multi-round timeouts, equivocation evidence propagation, per-peer rate limits, peer scoring, and basic bandwidth caps are wired, but there is no hardened peer discovery or deeper DoS protection beyond simple per-peer limits
4. **No ZK/privacy layer** — Placeholder types exist (ZkCommitment) but no implementation
5. **ContractInvoke namespace is loose** — Maps to both NS_CONTRACT and NS_DATA; should tighten to per-contract namespace
6. **No state pruning** — RetentionClass types exist but no pruning implementation

### 4.3 Hardening Applied

- **Zero unwrap() in consensus code** — All production expect() calls are either infallible serialization (canonical.rs) or CLI I/O (main.rs)
- **Collection caps on all governance registries** — MAX_PROPOSALS(10K), MAX_AGENTS(100K), MAX_NORMS(10K), MAX_AGENT_POLICIES(50K), MAX_TRACKED_NODES(10K)
- **Namespace literals eliminated** — All namespace references go through NS_* constants from sccgub-types
- **Argon2id + ChaCha20-Poly1305 keystore** with constant-time comparison and zeroize
- **Ed25519 signature verification** on every imported block (not just produced blocks)
- **CPoG validation on import** — `from_blocks()` returns `Result<Self, ImportError>` with full 11-check validation
- **Explicit spend-account version boundary** — block v1 replays legacy signer-public-key balances, block v2 funds the canonical validator agent account
- **Chain-bound consensus parameters** — proof depth, SCCE walker bounds, contract default step limit, gas schedule + limits, validation size caps, and contract invoke arg-size bounds replay from `system/consensus_params` instead of local compile-time defaults
- **Governance activation is live** — accepted + timelocked proposals can toggle emergency mode and update parameter allowlist keys: `governance.max_consecutive_proposals`, `governance.max_actions_per_agent_pct`, `governance.safety_change_min_signers`, `governance.genesis_change_min_signers`, `governance.max_authority_term_epochs`, `governance.authority_cooldown_epochs`, `finality.confirmation_depth`, `finality.max_finality_ms`, `finality.target_block_time_ms`
- **On-chain governance proposals** — parameter proposals use `norms/governance/params/propose` with payload `key=value`, votes use `norms/governance/proposals/...`
- **Governance snapshot surface** — block responses now expose governance limits + finality config snapshots for external verification
- **Peer diversity thresholds configurable** — `network.min_connected_peers` and `network.max_same_subnet_pct` control eclipse-resistance gating in networked mode

- **Peer seed exchange bounded** — Hello messages carry a bounded peer hint list to expand seed connectivity without unbounded growth

## 5. Phi Traversal Architecture

There is one per-tx phase check function: `phi_check_single_tx()`. It is called
from two contexts:

- **Block-level** (`phi_traversal_block`): CPoG validation at block import/production
  time. Iterates all txs through the shared function for per-tx phases. Runs
  block-only phases (Topology, Body, Architecture, Performance, Feedback, Evolution)
  with block-level logic.

- **Gas loop** (`validate_transition`): Per-transaction validation in `produce_block`.
  Iterates per-tx phases calling `phi_check_single_tx` directly. Every rejection
  produces a `CausalReceipt` via `validate_transition_metered`.

`phi_traversal_tx` has been deleted. There is no wrapper function between
`validate_transition` and the shared checker. Drift is structurally impossible.

**Mempool admission** uses `admit_check()` (lightweight: signature length,
nonce sequence, size limits, WHBinding structural completeness). It does NOT
run Phi traversal, Ed25519 verification, SCCE constraint propagation, or
ontology checks. Those all run in the gas loop where every rejection produces
a receipt (N-3-mempool closed).

**Recommended audit action**: Verify that `phi_check_single_tx` covers all
per-tx-relevant checks, and that `admit_check` does not accidentally run
expensive checks that belong in the gas loop.

## 6. Ontology Table (Consensus-Critical)

```
StateWrite        => [data/]
StateRead         => [data/, balance/, norms/, agents/]
AssetTransfer     => [balance/, escrow/]
GovernanceUpdate  => [norms/, treasury/]
NormProposal      => [norms/]
ConstraintAddition => [constraints/]
AgentRegistration => [agents/]
ContractDeploy    => [contract/]
ContractInvoke    => [contract/, data/]
DisputeResolution => []  (intentional gate — denied until machinery exists)
```

Changing this table is a **hard fork**. The exhaustive test `no_kind_can_write_to_system` verifies system/ is unreachable.

## 7. Audit Findings Summary

Internal audit cycle plus 5 hardening passes identified 48 tracked findings:
- **48 closed** (all code fixes applied and verified)

### F-5 lifecycle (worth noting for credibility)

F-5 originally alleged `phi_traversal_tx` was dead code. The implementer
traced the call chain and reclassified it as live code (false positive).
Later, `validate_transition` was refactored to call `phi_check_single_tx`
directly, removing the only caller of `phi_traversal_tx`. The function was
then safely deleted after a workspace-wide grep confirmed zero callers.
F-5 went from false positive → reclassified live → genuinely deleted.
This lifecycle is documented because external reviewers should know the
internal audit process caught its own errors and the eventual deletion
was verified, not assumed.

### N-13: panic-free consensus property

Zero `unwrap()` calls in any consensus-critical crate. All production
`expect()` calls (16 total) are either infallible serialization
(canonical.rs, 2 sites) or CLI I/O (main.rs, 14 sites). No crate in
the validation pipeline (sccgub-execution, sccgub-state, sccgub-consensus,
sccgub-governance) contains any `unwrap()` or `expect()` in production code.

### Critical fixes applied:
- F-1: CPoG validation on block import (was: infallible `from_blocks()`)
- F-2: SCCE real constraint propagation (was: no-op stub)
- F-3: Ontology wired into both Phi paths (was: missing from tx-level)
- F-4: Payload consistency checker added (was: no payload validation)
- N-1: Null-byte constraint key convention (was: prefix collision vulnerability)
- N-8: Namespace literal elimination (was: inline b"balance/" strings)
- N-12: Zero unwrap() in consensus (was: 2 sites with potential panic)
- N-14: Phase 5 (Form) drift — block path checked sig length only, tx path checked addr length only. Unified.
- N-15: Phase 6 (Organization) drift — governance precedence enforcement missing from tx path. Medium severity: DoS surface where governance-kind txs with insufficient authority were accepted into the mempool unchecked. Fixed.
- N-16: Phase 8 (Execution) drift — inconsistent completeness checks between paths. Unified.

### Post-Patch03 hardening (5th sweep):
- N-17: Gas loop pre-filters (solvency + nonce) produced no receipt on rejection. Fixed with `make_prefilter_reject_receipt`.
- N-18: `admit_check` payload size check only covered Write. DeployContract/InvokeContract payloads could be unbounded. Fixed with per-variant size checks.
- N-19: `gas.charge_compute(13)` result silently discarded. Fixed to return reject receipt.
- N-21: `balances_from_trie` silently skipped malformed hex entries. Fixed to fail-closed on import.
- N-23: Block reward credited before CPoG validation, causing state-root divergence. Moved to commit phase.
- N-24: `save_metadata` used `.unwrap()` on serde_json. Replaced with `.map_err()?`.
- N-25: `handle_block_response` silently discarded import errors. Now logs with `tracing::warn`.
- N-26: `key_passphrase` stored plaintext in config. Added security warning, recommend env var.
- N-13 extended: removed last 2 unwraps in governance crate (norms.rs) and 2 in consensus crate (partition.rs).

### N-3-mempool closed:
- Mempool admission refactored to `admit_check()` (lightweight structural checks).
- All Phi-phase semantic checks moved to the gas loop (`validate_transition_metered`),
  where every rejection produces a `CausalReceipt`.
- Proven by integration test: `test_scce_rejects_tx_targeting_constrained_symbol`
  asserts that a semantically-bad tx produces a reject receipt.

### Open items:
- None currently tracked in this hardening pass.

### Closed hardening items:
- **N-9 closed** — `what_actual` is now populated from the per-transaction `StateDelta`
  returned by `apply_block_transitions`, then sealed into receipts during block production.
- **N-20 closed** — `apply_block_transitions` now commits only balance entries changed by
  the current block's transitions. The prior end-of-block O(n) trie rewrite was removed.
- **Patch 03 closed** — canonical `ConsensusParams` bytes now embed in genesis, commit into
  `system/consensus_params`, restore through `from_blocks()` and snapshot recovery, and
  drive proof-depth, tx gas, block gas, and state-entry bounds from chain-bound values.

- **Economics replay closure** — fee debits, treasury counters, and the fixed block reward
  now commit into trie-backed state and replay identically in block production, CPoG,
  `from_blocks()`, and snapshot restoration.

### Dismissed false positives (12):
Aggressive automated tooling across 2 sweeps flagged 12 items verified as non-issues:

**Sweep 1 (post-refactor):**

| Claim | Why dismissed |
|---|---|
| TOCTOU in nonce check (later reclassified) | Originally dismissed because `check_nonce` mutates a clone. **Reclassified as real bug** when N-9 test exposed it — the clone mutation caused duplicate nonce rejection in the gas loop. Fixed by making pre-filter read-only. |
| Transfer failure corrupts state | `transfer()` returns `Err`; ledger unchanged. The `eprintln` is a consensus-bug detector. |
| TensionValue overflow | All ops use saturating arithmetic (Add, Sub, mul_fp). Verified in type definition. |
| Hex injection via balance/ keys | Ontology table maps `StateWrite => [data/]` only. Any Write targeting `balance/` rejected at Phase 3. Snapshot-layer concern separately closed as N-21. |
| Module phase 7 auto-passes | By design; per-tx module checks are a future item for richer contract semantics. |
| `unreachable!` can panic | Both callers filter via `is_per_tx_phase()` before calling. Structurally guarded. |

**Sweep 2 (post-Patch03):**

| Claim | Why dismissed |
|---|---|
| CPoG doesn't validate consensus_params | State-root replay IS the validation. Tampered params produce a different root; CPoG rejects. |
| Malicious snapshot injects params | `from_blocks` validates every block via CPoG. Snapshot restore is local persistence recovery, not untrusted import. |
| Uninitialized default code path | `from_blocks` loads params at genesis via `load_genesis_consensus_params`. `Chain::init()` writes them. Only test code uses `ManagedWorldState::new()` defaults. |
| Fee multiplication overflow | `saturating_mul` is the correct choice — caps at MAX rather than wrapping. |
| TensionValue arithmetic unchecked | Already verified saturating in previous audit sweep. |
| Treasury key matching fragility | Design debt, same module reads and writes. Not a correctness issue. |

## 8. Test Coverage Strategy

- **Unit tests**: Every module has tests. Key coverage areas: ontology (14 tests), payload check (12 tests), SCCE (8+ tests), CPoG (8 tests), Phi phases (9 tests), chain import (7 error variant tests)
- **Integration test**: `test_end_to_end_block_validation` in chain.rs — genesis → submit → produce → validate → verify state roots
- **Negative tests**: Each validation gate has at least one test that triggers rejection
- **Exhaustive tests**: `no_kind_can_write_to_system` iterates all 10 TransitionKind variants

## 8.1 Recommended Reading Order

For external reviewers unfamiliar with the codebase, this reading order
builds understanding incrementally:

1. `sccgub-types/src/namespace.rs` — namespace constants (small, sets vocabulary)
2. `sccgub-types/src/transition.rs` — SymbolicTransition, WHBindingIntent, OperationPayload
3. `sccgub-execution/src/ontology.rs` — default-deny namespace table (consensus-critical)
4. `sccgub-execution/src/wh_check.rs` — WHBinding completeness + cross-checks
5. `sccgub-execution/src/payload_check.rs` — payload-intent consistency
6. `sccgub-execution/src/phi.rs` — Phi traversal engine (shared per-tx checker + block-only phases)
7. `sccgub-execution/src/validate.rs` — transaction validation pipeline
8. `sccgub-execution/src/cpog.rs` — CPoG 11-check block validation
9. `sccgub-state/src/apply.rs` — state application (checks-effects-interactions)
10. `sccgub-node/src/chain.rs` — chain lifecycle, block production, import validation

## 9. Build and Run

```bash
# Build
cargo build --workspace

# Test
cargo test --workspace

# Lint
cargo clippy --workspace -- -D warnings

# Run node
cargo run --bin sccgub-node -- init
cargo run --bin sccgub-node -- submit-tx --key <key> --value <value>
cargo run --bin sccgub-node -- produce-block
cargo run --bin sccgub-node -- show-chain
```

```powershell
# Windows fallback for full-suite verification if link.exe reports LNK1104 on the default target dir
$env:CARGO_TARGET_DIR='target-windows-full'; cargo test -j 1 --workspace
```

## 10. Recommended Audit Focus Areas

1. **Ontology table completeness** — Are all TransitionKind variants correctly restricted?
2. **Phi shared checker completeness** — Does `phi_check_single_tx` cover all per-tx checks? Do block-only phases avoid duplicating per-tx logic?
3. **Nonce enforcement** — Is sequential nonce checked in all three sites?
4. **State application ordering** — Does checks-effects-interactions hold under all payload types?
5. **SCCE termination** — Can the constraint walker be induced to loop or exceed bounds?
6. **Signing payload canonicalization** — Is `block_signing_payload()` truly the single source?
7. **Fixed-point overflow** — Can TensionValue arithmetic overflow i128?
8. **Collection cap enforcement** — Are all governance registries properly bounded?
9. **Keystore timing side-channels** — Is constant-time comparison used consistently?
10. **Import validation completeness** — Does `from_blocks()` reject all malformed chains?
