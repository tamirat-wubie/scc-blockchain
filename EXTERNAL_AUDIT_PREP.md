# SCCGUB External Audit Preparation Guide

**Version:** 0.3.0
**Date:** 2026-04-07
**Repo:** 111 commits, 496 tests, 9 crates, ~22.5K lines Rust

---

## 1. Project Overview

SCCGUB (Symbolic Causal Chain General Universal Blockchain) is a Rust blockchain
kernel that enforces governance constraints through symbolic causal chains. Every
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
sccgub-state       In-memory Merkle Patricia Trie, WorldState, BalanceLedger, TensionField
sccgub-execution   13-phase Phi traversal, CPoG validation, SCCE constraint engine
sccgub-consensus   Two-round BFT protocol, safety certificates, equivocation detection
sccgub-governance  Precedence enforcement, norm registry, validator selection, proposals
sccgub-network     P2P message types, peer management (stub for MVP)
sccgub-api         REST API types, structured errors (stub for MVP)
sccgub-node        CLI binary: genesis, block production, chain lifecycle, mempool
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

1. **Single-proposer mode** — No BFT rotation in production path yet (consensus crate has the protocol)
2. **In-memory state** — No persistence across restarts (HashMap-backed trie)
3. **No networking** — Single-node only; network crate is stub
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

## 5. Phi Traversal Architecture

The 13-phase Phi traversal runs in two contexts:

- **Block-level** (`phi_traversal_block`): Called during CPoG validation at block import/production time. Runs all 13 phases.
- **Transaction-level** (`phi_traversal_tx`): Called inside the gas loop via `validate_transition_metered` → `validate_transition`. Runs per-tx phases; block-only phases auto-pass. Every rejection here produces a `CausalReceipt`.

**N-11 structural enforcement**: Both paths call `phi_check_single_tx()` for
per-tx phases (Distinction, Constraint, Ontology, Form, Organization, Module,
Execution). This shared function is the single source of truth for per-tx
semantics. Adding a check to a per-tx phase means editing one function; both
paths pick it up automatically.

Block-only phases (Topology, Body, Architecture, Performance, Feedback,
Evolution) run only in `phi_traversal_block`.

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

An 11-session internal audit cycle identified 38 findings:
- **37 closed** (code fixes applied and verified, including N-3-mempool)
- **1 false positive** (F-5: see below)
- **1 deferred** (Patch 03: ConsensusParams in genesis — architectural, ~1 day effort)

### F-5 false positive (worth noting for credibility)

F-5 alleged `phi_traversal_tx` was dead code across three audit sessions.
The implementer traced the call chain: `phi_traversal_tx` is called by
`validate_transition` (validate.rs:123), which is called by
`validate_transition_metered`, which is called by `mempool::drain_validated`,
which is called by `produce_block`. Reclassified as live code, not dead.
This is documented because external reviewers should know the internal
audit process caught and corrected its own errors.

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

### N-3-mempool closed:
- Mempool admission refactored to `admit_check()` (lightweight structural checks).
- All Phi-phase semantic checks moved to the gas loop (`validate_transition_metered`),
  where every rejection produces a `CausalReceipt`.
- Proven by integration test: `test_scce_rejects_tx_targeting_constrained_symbol`
  asserts that a semantically-bad tx produces a reject receipt.

### Open items:
- N-9: `what_actual` capture not implemented (StateDelta recording during apply).
- Patch 03: ConsensusParams embedded in genesis block for fork-safe parameter evolution.

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
