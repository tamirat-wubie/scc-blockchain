# SCCGUB — Symbolic Causal Chain General Universal Blockchain

A Rust implementation of the SCCGUB v2.1 specification: a deterministic causal chain of governed symbolic transformations with proof-carrying blocks, Mfidel-grounded identity, and Phi-squared-enforced invariants.

**Status:** Production hardening phase. Protocol spec frozen ([PROTOCOL.md](PROTOCOL.md)). 9 crates, 78 source files, ~20K lines Rust, 315 tests, all CI green (Ubuntu + Windows + security audit).

## Architecture (9 crates)

| Layer | Crate | Description |
|-------|-------|-------------|
| 7 | `sccgub-node` | 16 CLI commands, chain lifecycle, mempool, persistence, observability |
| 6 | `sccgub-api` | REST API (7 endpoints), CORS, structured error codes, versioned routes |
| 5 | `sccgub-governance` | Norms, precedence, proposals with timelocks, anti-concentration, AI agent policy |
| 4 | `sccgub-consensus` | Two-round BFT voting, bounded finality, slashing, partition recovery, safety proofs |
| 3 | `sccgub-execution` | 13-phase Phi traversal (all real), CPoG, gas metering, runtime invariant monitor |
| 2 | `sccgub-state` | Merkle trie (lazy cache), balance ledger, treasury, escrow/DvP, multi-asset |
| 1 | `sccgub-types` | 20 modules: blocks, transitions, causal graph, events, economics, compliance |
| 0 | `sccgub-crypto` | BLAKE3, Ed25519, Merkle proofs, Argon2id+ChaCha20-Poly1305 keystore, role keys |
| - | `sccgub-network` | Peer protocol, 9 message types, peer registry |

## Key Properties

- **Consensus:** Causal Proof-of-Governance (CPoG) with two-round BFT voting (Ed25519-verified votes)
- **Finality:** Bounded k-block confirmation with 3 settlement classes (Soft/Economic/Legal)
- **Validation:** 13-phase Phi traversal — all 13 phases have real enforcement
- **Contracts:** Decidable step-bounded symbolic programs with gas metering
- **Identity:** Mfidel 34x8 Ge'ez atomic seal + cryptographic agent binding
- **Governance:** Precedence hierarchy with timelocks (ordinary 50 / constitutional 200 blocks)
- **Economics:** Gas metering, treasury (fee/reward/burn lifecycle), escrow/DvP
- **Custody:** 6 operator key roles (Genesis/Governance/Treasury/Validator/Operator/Auditor)
- **Keystore:** Argon2id KDF + ChaCha20-Poly1305 AEAD (finance-grade)
- **Arithmetic:** Fixed-point i128 (18 decimals) — no floating-point in consensus
- **Signatures:** Ed25519 over canonical bincode covering all 9 semantic fields
- **Compliance:** GDPR erasure proofs, off-chain data references, audit trails
- **AI Agents:** OWASP-compliant policy enforcement (default-deny, write/read prefixes)
- **Assets:** Multi-asset ledger (Native, Stablecoin, Bond, RealEstate, Commodity, Custom)
- **Events:** 11 typed chain events for full audit trail
- **Safety:** Signed quorum certificates, equivocation evidence store, runtime invariant monitor

## REST API (7 endpoints)

```
GET  /api/v1/status          Chain summary (height, finality, tension, governance)
GET  /api/v1/health          System health + finality SLA
GET  /api/v1/block/:height   Block detail with transaction list
GET  /api/v1/state           Paginated world state (?offset=&limit=)
GET  /api/v1/tx/:tx_id       Transaction detail by hex ID
POST /api/v1/tx/submit       Submit signed transaction (hex-encoded canonical bytes)
```

Structured error codes (12 machine-readable `ErrorCode` variants). CORS enabled. Legacy routes at `/api/*`.

## CLI Commands (16)

```bash
# Chain lifecycle
sccgub init               # Genesis + 1M token mint + validator key
sccgub produce --txs N    # Produce gas-metered CPoG-validated block
sccgub transfer AMOUNT    # Asset transfer with Ed25519 signature
sccgub verify             # Replay + verify all Merkle roots + state

# Inspection
sccgub status             # Chain summary with block history
sccgub stats              # Detailed statistics (graph, state, governance)
sccgub health             # Health report (finality, economics, security)
sccgub show-block N       # Block detail with all transactions
sccgub show-state         # World state entries
sccgub search-tx PREFIX   # Find transaction by ID
sccgub balance PREFIX     # Show agent balances

# Portability
sccgub export FILE        # Portable chain snapshot
sccgub import FILE        # Import with CPoG re-validation

# API server
sccgub serve --port 3000  # Start REST API

# Reference
sccgub demo               # In-memory demonstration
sccgub info               # Spec + invariants reference
```

## Quick Start

```bash
cargo build                    # Build all 9 crates
cargo test                     # Run all 315 tests
cargo run -- init              # Initialize chain
cargo run -- produce --txs 5   # Produce a block
cargo run -- transfer 10000    # Transfer tokens
cargo run -- verify            # Verify chain integrity
cargo run -- health            # Chain health report
cargo run -- serve             # Start API server
```

## Production Gate Status

| Gate | Status | Evidence |
|------|--------|----------|
| Protocol freeze | Done | [PROTOCOL.md](PROTOCOL.md) — 14-section canonical spec |
| Consensus adversarial | 12 tests | Byzantine tolerance, vote forgery, equivocation, partition recovery |
| Financial conservation | 7 tests | Transfer, treasury, escrow (release + refund), no phantom supply |
| Replay determinism | Verified | Identical operations produce identical state roots |
| Keystore crypto | Argon2id + ChaCha20-Poly1305 | AEAD tamper detection, memory-hard KDF |
| Custody roles | 6 roles | Validator/Treasury/Governance separation with rotation and revocation |
| Structured API errors | 12 error codes | Machine-readable rejection for every failure path |
| Escrow attack surface | 5 tests | Double-release, premature refund, self-escrow, zero-amount |
| Gas metering | Wired | Per-tx gas (12 cost categories), per-block limit (50M), treasury integration |
| Governance timelocks | Enforced | Ordinary 50 blocks, constitutional 200 blocks |
| Runtime invariants | 7 checks | Supply, nonce, state root, tension, receipts, causality |
| CI | 3 jobs | Ubuntu (fmt+build+test+clippy), Windows (build+test), security (cargo-audit) |

## Conformance Matrix

| Invariant | Enforcing Module | Test File | Failure Mode |
|-----------|-----------------|-----------|--------------|
| INV-1: Valid CPoG | `execution/cpog.rs` | `integration_test.rs` | Block rejected with error list |
| INV-2: Phi traversal | `execution/phi.rs` | `integration_test.rs` | Phase failure halts traversal |
| INV-3: Governance precedence | `execution/phi.rs` (phase 6) | `integration_test.rs` | Transition rejected |
| INV-4: No fork | `consensus/safety.rs` | `adversarial_test.rs` | Equivocators identified + slashed |
| INV-5: Tension budget | `execution/phi.rs` (phase 9) | `integration_test.rs` | Block rejected |
| INV-6: Identity immutable | `execution/validate.rs` | `integration_test.rs` | agent_id mismatch rejected |
| INV-7: WHBinding complete | `execution/wh_check.rs` | `integration_test.rs` | Transition rejected |
| INV-8: Contract decidability | `execution/contract.rs` | `execution` unit tests | Step limit exceeded → reject |
| INV-13: Responsibility bound | `governance/responsibility.rs` | `integration_test.rs` | Contribution capped |
| INV-17: Causal acyclicity | `execution/phi.rs` (phase 4) | `integration_test.rs` | Cycle detected → reject |
| Supply conservation | `state/apply.rs`, `invariants.rs` | `adversarial_test.rs` | Transfer/escrow/treasury tests |
| Treasury conservation | `state/treasury.rs` | `adversarial_test.rs` | collected = distributed + burned + pending |
| Escrow conservation | `state/escrow.rs` | `adversarial_test.rs` | supply = balances + locked |
| Nonce monotonicity | `state/world.rs`, `execution/validate.rs` | `adversarial_test.rs` | Replay rejected |
| Vote authentication | `consensus/protocol.rs` | `adversarial_test.rs` | Forged/corrupted/non-member rejected |
| Receipt completeness | `execution/invariants.rs` | `execution` unit tests | Missing/rejected receipt detected |

## Security Model

### Conservation Laws (consensus-critical)

| Law | Enforcement |
|-----|-------------|
| Supply conservation | `total_supply` constant except at genesis mint |
| Treasury conservation | `collected = distributed + burned + pending` |
| Escrow conservation | `total_supply = balances + escrow_locked` |
| Nonce monotonicity | Per-agent strictly increasing |
| Tension homeostasis | `tension_after <= tension_before + budget` |

### Invariants (10 enforced)

| ID | Invariant |
|----|-----------|
| INV-1 | No block without valid CPoG (13-phase Phi + Merkle roots) |
| INV-2 | No state change without Phi traversal |
| INV-3 | No governance change below MEANING precedence |
| INV-4 | No fork (deterministic finality) |
| INV-5 | No unbounded tension growth |
| INV-6 | No identity mutation post-genesis |
| INV-7 | No transition without complete WHBinding (7 fields) |
| INV-8 | No contract beyond decidability bound |
| INV-13 | Responsibility bounded |
| INV-17 | Causal graph acyclicity |

## Specification

- [PROTOCOL.md](PROTOCOL.md) — Frozen protocol spec (consensus, finality, fees, replay rules)
- `specs/SCCGUB_SPEC.md` — v1.0 original specification
- `specs/SCCGUB_v2_ENHANCED.md` — v2.0 enhanced
- `specs/SCCGUB_v2.1_AUDIT_AND_REFINEMENT.md` — v2.1 audit + refinement

## License

MIT
