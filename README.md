# SCCGUB — Symbolic Causal Chain General Universal Blockchain

A Rust implementation of the SCCGUB v2.1 specification: a deterministic causal chain of governed symbolic transformations with proof-carrying blocks, Mfidel-grounded identity, and Phi-squared-enforced invariants.

## Architecture

| Layer | Component | Description |
|-------|-----------|-------------|
| 7 | Application | Agents, queries, CLI (13 commands) |
| 6 | Contract | Symbolic Causal Contracts (decidable, step-bounded) |
| 5 | Governance | Norms, precedence, proposals, agent registration |
| 4 | Consensus | Causal Proof-of-Governance (CPoG) with 5 Merkle root verifications |
| 3 | Execution | 13-phase Phi traversal + SCCE constraint engine |
| 2 | State | Merkle trie, tension field, balance ledger |
| 1 | Network | Causal gossip (spec-defined, networking TBD) |
| 0 | Foundation | Blake3 + Ed25519, Mfidel 34x8 Ge'ez seal substrate |

## Key Properties

- **Consensus:** Causal Proof-of-Governance (CPoG) — not PoW/PoS
- **Finality:** Deterministic and immediate — no forks, no probabilistic confirmation
- **Validation:** 13-phase Phi traversal on every block and transaction
- **Contracts:** Decidable symbolic constraint programs — no halting problem, no gas estimation
- **Identity:** Mfidel 34x8 Ge'ez atomic seal on every block (272-fidel cycle)
- **Governance:** Phi-squared precedence order (GENESIS > SAFETY > MEANING > EMOTION > OPTIMIZATION)
- **Arithmetic:** Fixed-point i128 with 18 decimal places — no floating-point in consensus
- **Signatures:** Ed25519 covering all semantic fields (kind, target, nonce, payload, preconditions, WH binding, causal chain)
- **Security:** 3 audit passes, ~170+ findings resolved, domain-separated Merkle trees

## Performance

| Operation | Throughput |
|-----------|-----------|
| Transaction creation + Ed25519 signing | ~15,000-17,000 tx/s |
| Full validation (13-phase Phi + SCCE + signature verify) | ~9,000-11,000 tx/s |
| Merkle root computation (1000 leaves) | ~670 microseconds |

## Crate Structure

```
crates/
  sccgub-types/       14 modules: blocks, transitions, WHBinding, Mfidel seals,
                       tension (fixed-point), causal graph, governance, proofs,
                       receipts, economics, contracts, state, agents
  sccgub-crypto/       Blake3 hashing (domain-separated), Merkle trees (with
                       proof generation + verification), Ed25519 signatures
  sccgub-state/        State trie (BTreeMap with prefix scan), world state
                       (nonce tracking, size limits), tension computation,
                       balance ledger (credit/debit/transfer)
  sccgub-execution/    13-phase Phi traversal, CPoG (5 root verifications),
                       SCCE constraint engine, contract execution (step-bounded),
                       WHBinding cross-checks, Ed25519 signature verification
  sccgub-governance/   Precedence enforcement, norm replicator dynamics,
                       validator selection, responsibility accounting (exp-by-squaring
                       decay), adversarial containment, emergency governance,
                       governance proposals (voting lifecycle), agent registration
  sccgub-node/         CLI binary (13 commands), chain lifecycle, mempool
                       (VecDeque + dedup + confirmed IDs), persistence
                       (atomic writes + integrity checks), benchmarks
```

## CLI Commands

```bash
# Chain lifecycle
sccgub init               # Create genesis block with 1M token mint
sccgub produce --txs N    # Produce CPoG-validated block with N transactions
sccgub verify             # Replay entire chain, verify all roots + state

# Inspection
sccgub status             # Chain summary with block history
sccgub stats              # Detailed statistics (graph, state, governance, tension)
sccgub show-block N       # Full block detail with all transactions
sccgub show-state         # All world state entries (key = value)
sccgub search-tx PREFIX   # Find transaction by ID hex prefix
sccgub balance PREFIX     # Show agent balances with total supply

# Portability
sccgub export FILE        # Export chain as portable JSON snapshot
sccgub import FILE        # Import chain with full CPoG re-validation

# Reference
sccgub demo               # In-memory demonstration of full lifecycle
sccgub info               # Spec, invariants, and architecture reference
```

## Quick Start

```bash
# Build
cargo build

# Run all 143 tests
cargo test

# Initialize and produce blocks
cargo run -- init
cargo run -- produce --txs 5
cargo run -- produce --txs 3
cargo run -- verify
cargo run -- stats

# Run benchmarks
cargo bench
```

## Security Model

### Invariants Enforced

| ID | Invariant |
|----|-----------|
| INV-1 | No block without valid CPoG (13-phase Phi + 5 Merkle roots) |
| INV-2 | No state change without Phi traversal |
| INV-3 | No governance change below MEANING precedence |
| INV-4 | No fork (deterministic finality) |
| INV-5 | No unbounded tension growth (budget enforcement) |
| INV-6 | No identity mutation post-genesis |
| INV-7 | No transition without complete WHBinding (7 fields + cross-checks) |
| INV-8 | No contract beyond decidability bound (step-limited) |
| INV-13 | Responsibility bounded by R_max_imbalance |
| INV-17 | Causal graph acyclicity (iterative DFS) |

### Audit Summary (4 passes)

- ~185+ issues identified and resolved
- All critical/high severity issues fixed
- Domain-separated Merkle trees (leaf/internal tags, length-prefixed hashing)
- Saturating arithmetic throughout (no panic on untrusted input)
- Nonce replay protection (per-agent monotonic tracking)
- Agent identity cryptographically bound to public key + Mfidel seal
- Canonical signatures cover all semantic fields
- Adversarial containment with gradual de-escalation
- Atomic persistence writes (crash-safe)

## Specification

Full specification documents in `specs/`:

- `SCCGUB_SPEC.md` — v1.0 original specification
- `SCCGUB_v2_ENHANCED.md` — v2.0 enhanced (dual-source merge)
- `SCCGUB_v2.1_AUDIT_AND_REFINEMENT.md` — v2.1 DCA audit + fixes

## v2.1 Audit Fixes Applied

- **FIX-1:** CausalTimestamp uses hash reference (not recursive embedding)
- **FIX-2:** Finality mode as immutable genesis parameter
- **FIX-3:** Tension budget with FIXED/GOVERNANCE/ADAPTIVE modes
- **FIX-4:** Responsibility conservation replaced with enforceable bound
- **FIX-5:** Mfidel seal deterministic assignment from block height
- **FIX-6:** SCCE learning removed from consensus-critical validation path
- **FIX-7:** WHBinding split into intent (submission) and resolved (receipt)
- **FIX-8:** Phi traversal phase responsibility clarified (per-tx vs block-only)
- **C-9:** Fixed-point arithmetic throughout (no floating-point in consensus)
- **B-10:** Fee computation uses prior block tension (no circular dependency)

## License

MIT
