# SCCGUB — Symbolic Causal Chain General Universal Blockchain

A Rust implementation of the SCCGUB v2.1 specification: a deterministic causal chain of governed symbolic transformations with proof-carrying blocks, Mfidel-grounded identity, and Phi-squared-enforced invariants.

## Architecture (8 crates)

| Layer | Component | Description |
|-------|-----------|-------------|
| 7 | Application | 15 CLI commands, observability, health monitoring |
| 6 | Contract | Decidable step-bounded contracts + formal constraint evaluator |
| 5 | Governance | Norms, precedence, proposals, agent policy, anti-concentration |
| 4 | Consensus | Two-round BFT voting, bounded finality, slashing, law sync, partition recovery |
| 3 | Execution | 13-phase Phi traversal + SCCE constraint engine |
| 2 | State | Merkle trie (lazy cache), tension field, balance + multi-asset ledger |
| 1 | Compliance | GDPR data lifecycle, bridge adapters, domain packs |
| 0 | Foundation | Blake3 + Ed25519, Mfidel 34x8 Ge'ez seal, Merkle proofs |

## Key Properties

- **Consensus:** Causal Proof-of-Governance (CPoG) with two-round BFT voting
- **Finality:** Bounded k-block confirmation with SLA monitoring
- **Validation:** 13-phase Phi traversal on every block and transaction
- **Contracts:** Decidable step-bounded symbolic programs — no halting problem
- **Identity:** Mfidel 34x8 Ge'ez atomic seal + cryptographic agent binding
- **Governance:** Phi-squared precedence with anti-concentration limits
- **Arithmetic:** Fixed-point i128 (18 decimals) — no floating-point in consensus
- **Signatures:** Ed25519 covering all 9 semantic fields
- **Compliance:** GDPR erasure proofs, off-chain data references, audit trails
- **AI Agents:** OWASP-compliant policy enforcement (write/read limits, cosign, budgets)
- **Assets:** Multi-asset ledger (Native, Stablecoin, Bond, RealEstate, Commodity)
- **Security:** 4 audit passes, ~185+ issues resolved, domain-separated Merkle trees

## Performance

| Operation | Throughput |
|-----------|-----------|
| Transaction creation + Ed25519 signing | ~15,000-17,000 tx/s |
| Full validation (13-phase Phi + SCCE + signature verify) | ~9,000-11,000 tx/s |
| Merkle root computation (1000 leaves) | ~670 microseconds |

## CLI Commands (15)

```bash
# Chain lifecycle
sccgub init               # Genesis + 1M token mint + validator key
sccgub produce --txs N    # Produce CPoG-validated block
sccgub transfer AMOUNT    # Asset transfer with Ed25519 signature
sccgub verify             # Replay + verify all 7 Merkle roots + state

# Inspection
sccgub status             # Chain summary with block history
sccgub stats              # Detailed statistics (graph, state, governance)
sccgub health             # Health report (finality, security, SLA)
sccgub show-block N       # Block detail with all transactions
sccgub show-state         # World state entries
sccgub search-tx PREFIX   # Find transaction by ID
sccgub balance PREFIX     # Show agent balances

# Portability
sccgub export FILE        # Portable chain snapshot
sccgub import FILE        # Import with CPoG re-validation

# Reference
sccgub demo               # In-memory demonstration
sccgub info               # Spec + invariants reference
```

## Quick Start

```bash
cargo build                    # Build
cargo test                     # Run all 203 tests
cargo run -- init              # Initialize chain
cargo run -- produce --txs 5   # Produce a block
cargo run -- transfer 10000    # Transfer tokens
cargo run -- verify            # Verify chain integrity
cargo run -- health            # Chain health report
cargo bench                    # Run benchmarks
```

## Crate Structure

```
crates/
  sccgub-network/      Peer protocol, 9 message types (bincode-encoded), peer
                        registry with sync candidate selection
  sccgub-consensus/    Two-round BFT voting, bounded finality, slashing engine,
                        Phase 4 law synchronization, partition recovery, BFT safety proofs
  sccgub-types/        19 modules: blocks, transitions, WHBinding, Mfidel seals,
                        tension, causal graph, governance, proofs, receipts,
                        economics, contracts, domain packs, bridge adapters,
                        transaction builder, compliance (GDPR), multi-asset
  sccgub-crypto/       Blake3 (domain-separated), Merkle trees (with proofs),
                        Ed25519 signatures, bincode canonical encoding
  sccgub-state/        State trie (lazy cache + prefix scan), world state (nonces),
                        tension computation, balance ledger, multi-asset ledger
  sccgub-execution/    13-phase Phi traversal, CPoG (7 root verifications), SCCE,
                        formal constraint evaluator, contract execution, WHBinding,
                        signature verification
  sccgub-governance/   Precedence enforcement, norm replicator dynamics, validator
                        selection, responsibility, containment, emergency governance,
                        proposals (voting), agent registration, anti-concentration,
                        AI agent policy enforcement
  sccgub-node/         15 CLI commands, chain lifecycle, mempool (dedup + confirmed),
                        persistence (atomic + snapshots), observability, benchmarks
```

## Security Model

### Invariants (10 enforced)

| ID | Invariant |
|----|-----------|
| INV-1 | No block without valid CPoG (13-phase Phi + 7 Merkle roots) |
| INV-2 | No state change without Phi traversal |
| INV-3 | No governance change below MEANING precedence |
| INV-4 | No fork (deterministic finality) |
| INV-5 | No unbounded tension growth (budget enforcement) |
| INV-6 | No identity mutation post-genesis |
| INV-7 | No transition without complete WHBinding (7 fields + cross-checks) |
| INV-8 | No contract beyond decidability bound (step-limited) |
| INV-13 | Responsibility bounded by R_max_imbalance |
| INV-17 | Causal graph acyclicity (iterative DFS) |

### Audit Summary (4 passes, ~185+ issues resolved)

- Domain-separated Merkle trees (leaf/internal tags, length-prefixed hashing)
- Saturating arithmetic throughout (no panic on untrusted input)
- Nonce replay protection (per-agent monotonic tracking)
- Agent identity cryptographically bound to public key + Mfidel seal
- Canonical signatures cover all 9 semantic fields
- Adversarial containment with gradual de-escalation + positive decay
- Atomic persistence writes (crash-safe)
- State root verified via speculative replay in CPoG
- Balance root committed in block header
- Anti-concentration: 33% action cap, consecutive proposal limits, term limits, multi-sig

### Real-World Problems Addressed

| Problem | Solution |
|---------|----------|
| OWASP Agentic Risks (2025) | AI agent policy: write/read prefixes, transfer limits, cosign |
| $30B RWA Tokenization | Multi-asset ledger: 6 asset types, mint/burn/freeze |
| GDPR vs Immutability | Off-chain refs + deletion proofs + erasure verification |
| $17B Smart Contract Exploits | Formal constraint evaluator + decidable contracts |
| Consortium Governance Collapse | CPoG + on-chain proposals + anti-concentration |
| Enterprise Pilot Failures | Single-binary deployment, built-in finality, snapshots |
| Ethiopian Digital Identity Gap | Mfidel cultural grounding + agent registration |
| Cross-Border Payments | Multi-asset + bridge adapters (EVM/Cosmos/Fabric) |

## Specification

Full specification documents in `specs/`:
- `SCCGUB_SPEC.md` — v1.0 original specification
- `SCCGUB_v2_ENHANCED.md` — v2.0 enhanced (dual-source merge)
- `SCCGUB_v2.1_AUDIT_AND_REFINEMENT.md` — v2.1 DCA audit + fixes

## License

MIT
