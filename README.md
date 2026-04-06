# SCCGUB — Symbolic Causal Chain General Universal Blockchain

A Rust implementation of the SCCGUB v2.1 specification: a deterministic causal chain of governed symbolic transformations with proof-carrying blocks, Mfidel-grounded identity, and Phi-squared-enforced invariants.

## Architecture

| Layer | Component | Description |
|-------|-----------|-------------|
| 7 | Application | Agents, queries, CLI |
| 6 | Contract | Symbolic Causal Contracts (decidable) |
| 5 | Governance | Norms, precedence, evolution |
| 4 | Consensus | Causal Proof-of-Governance (CPoG) |
| 3 | Execution | 13-phase Phi traversal engine |
| 2 | State | Merkle trie, tension field |
| 1 | Network | Causal gossip, node management |
| 0 | Foundation | Cryptography, Mfidel substrate |

## Key Properties

- **Consensus:** Causal Proof-of-Governance (CPoG) — not PoW/PoS
- **Finality:** Deterministic and immediate — no forks, no probabilistic confirmation
- **Validation:** 13-phase Phi traversal on every block
- **Contracts:** Decidable symbolic constraint programs — no halting problem
- **Identity:** Mfidel 34x8 Ge'ez atomic seal on every block
- **Governance:** Phi-squared precedence order (GENESIS > SAFETY > MEANING > EMOTION > OPTIMIZATION)
- **Arithmetic:** Fixed-point i128 with 18 decimal places — no floating-point in consensus

## Crate Structure

```
crates/
  sccgub-types/       Core type definitions (blocks, transitions, WHBinding, etc.)
  sccgub-crypto/      Blake3 hashing, Merkle trees, Ed25519 signatures
  sccgub-state/       State trie, world state, tension field computation
  sccgub-execution/   13-phase Phi traversal, CPoG validation, WHBinding checks
  sccgub-governance/  Precedence enforcement, norm evolution, validator selection
  sccgub-node/        CLI node binary
```

## Quick Start

```bash
# Build
cargo build

# Run tests
cargo test

# Initialize a chain
cargo run -- init

# Run the demo (genesis + transactions + block production)
cargo run -- demo

# Show system info
cargo run -- info
```

## Specification

Full specification documents are in the `specs/` directory:

- `SCCGUB_SPEC.md` — v1.0 original specification
- `SCCGUB_v2_ENHANCED.md` — v2.0 enhanced specification (dual-source merge)
- `SCCGUB_v2.1_AUDIT_AND_REFINEMENT.md` — v2.1 audit findings and fixes

## v2.1 Audit Fixes Applied

- **FIX-1:** CausalTimestamp uses hash reference (not recursive embedding)
- **FIX-2:** Finality mode as genesis parameter (DETERMINISTIC / BFT_CERTIFIED)
- **FIX-3:** Tension budget with FIXED/GOVERNANCE/ADAPTIVE modes
- **FIX-4:** Responsibility conservation replaced with enforceable bound
- **FIX-5:** Mfidel seal deterministic assignment from block height
- **FIX-6:** SCCE learning removed from consensus-critical validation path
- **FIX-7:** WHBinding split into intent (submission) and resolved (receipt)
- **FIX-8:** Phi traversal phase responsibility clarified (per-tx vs block-only)
- **C-9:** Fixed-point arithmetic throughout (no floating-point in consensus)

## License

MIT
