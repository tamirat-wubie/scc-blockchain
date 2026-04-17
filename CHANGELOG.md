# Changelog

All notable changes to SCCGUB are documented here.

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
