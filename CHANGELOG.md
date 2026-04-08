# Changelog

All notable changes to SCCGUB are documented here.

## [v0.3.0] — 2026-04-08

### Production Hardening Release

**442 tests, 9 crates, ~30K lines Rust, all CI green.**

#### Security
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

#### Economics
- Gas metering wired into block production (12 cost categories)
- Treasury with fee/reward/burn lifecycle and epoch management
- Escrow with StateProof conditions (value + authority match)
- Block gas limit enforcement (50M default)

#### Governance
- Timelocks: ordinary 50 blocks, constitutional 200 blocks
- Settlement finality classes: Soft, Economic, Legal
- 6 operator key roles with rotation ceremony

#### API
- 8 versioned REST endpoints with CORS
- 12 machine-readable ErrorCode variants
- Idempotency key support
- Transaction validation against state before admission
- Receipt and block-receipts lookup endpoints

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
- AI agent circuit breakers (Closed/Open/HalfOpen lifecycle)

#### Five-Plane Coordination
- CapabilityLease with bounded delegation
- Mission ledger (11-state lifecycle)
- Evidence gateway (6 evidence types)
- 7 safety modes (Normal through Quarantine)
- Autonomy budgets for off-chain decision authority

#### Testing
- 442 tests across 9 crates
- Property-based tests (3000+ random scenarios)
- Adversarial consensus tests (Byzantine, partition, equivocation)
- Full-pipeline integration tests (treasury, escrow, artifacts, delegation, events)
- Financial conservation proofs (transfer, treasury, escrow)

## [v0.2.0] — 2026-04-07

- 9-crate architecture established
- Two-round BFT consensus with Ed25519 signatures
- 13-phase Phi validation framework
- Multi-asset ledger and balance trie commitment
- CLI with 16 commands
- REST API with health/status/block/state endpoints
- GDPR compliance module
- Bridge adapter framework

## [v0.1.0] — 2026-04-07

- Initial implementation from SCCGUB v2.1 specification
- Core types, crypto, and state modules
- Genesis block production and validation
