# Changelog

All notable changes to SCCGUB are documented here.

## [v0.3.0] — 2026-04-08

### Production Hardening Release

**898 tests, 9 crates, persistent block log + snapshots, all CI green.**

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
- 898 tests across 9 crates
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
