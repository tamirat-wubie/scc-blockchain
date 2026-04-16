# SCCGUB — Symbolic Causal Chain General Universal Blockchain

[![CI](https://github.com/tamirat-wubie/scc-blockchain/actions/workflows/ci.yml/badge.svg)](https://github.com/tamirat-wubie/scc-blockchain/actions/workflows/ci.yml)

A Rust implementation of the SCCGUB v2.1 specification: a deterministic causal chain of governed symbolic transformations with proof-carrying blocks, Mfidel-grounded identity, and Phi-squared-enforced invariants.

**Status:** Hardening-stage governed blockchain kernel - v0.3.0. Protocol spec frozen ([PROTOCOL.md](PROTOCOL.md)). Single-node reference runtime with optional p2p alpha, persistent block log, encrypted validator keystore, genesis-embedded consensus params, periodic snapshots, and 793 tests in the current workspace listing. New chains default to block version 2, where validator liquidity lives under the canonical agent account; block version 1 replay remains supported for legacy compatibility. CI is green on Ubuntu, Windows, and the security audit job. Canonical status note: [docs/STATUS.md](docs/STATUS.md).

## Where It Stands (Executive Summary)

**What it is**  
A Rust blockchain that enforces rules through code, not just trust. Every transition must pass the 13-phase Phi traversal and produce a causal receipt that proves what changed and why.

**What works right now**  
- Genesis -> submit tx -> produce blocks -> import/replay with full verification.
- Deterministic validation: every rejection has a reason (receipts).
- Governance proposals: submit -> vote -> timelock -> activate into live governance state.
- REST API with 22 versioned endpoints for state, blocks, receipts, governance, and finality.
- Consensus-critical values live in `ConsensusParams` embedded at genesis (no hardcoded drift).
- Hardening posture: 793 tests, CI green on Ubuntu + Windows + security audit.

**What it cannot do yet**  
- Multi-validator consensus is wired in the p2p alpha path but not production-hardened; default mode is single proposer.
- No fully durable state database by default: state still replays from persisted blocks + snapshots unless `storage.state_store_authoritative = true` is enabled for redb-backed startup.
- Contract VM is not implemented (contract types exist, structural validation only).
- No ZK/privacy implementation (placeholders only).

**Where to work next (priority order)**  
1. Multi-validator BFT wiring (turns the kernel into a distributed chain).
2. Durable state database (replace replay-only state with persistent storage).
3. Contract VM (WASM or similar) using the existing validation + gas scaffolding.
4. Expand governed parameter surface beyond the current allowlist.
5. Block explorer/indexer using receipts + API.

**One-sentence summary**  
The validation kernel is hardened and truthful; the next work is making it distributed, persistent, and programmable.

## Known Limits (MVP)

- **Default single-proposer mode:** Proposer rotation is active when a validator set is configured, but the reference CLI defaults to a single validator; multi-validator BFT remains alpha.
- **Replay-authoritative state by default:** Blocks, metadata, encrypted validator keys, and periodic snapshots persist across restarts; an optional redb-backed state store can mirror the trie, or become startup-authoritative when `storage.state_store_authoritative = true`.
- **P2P networking is minimal:** Hello/heartbeat/tx gossip, block sync, vote propagation, multi-round timeouts, equivocation evidence propagation, per-peer rate limits, peer scoring, and basic bandwidth caps are wired, but there is no hardened peer discovery or deeper DoS protection beyond simple per-peer limits.
- **No ZK/privacy layer:** Placeholder types exist (ZkCommitment) but no implementation.
- **ContractInvoke namespace:** Now scoped to `contract/` only. Per-contract sub-namespace (`contract/<id>/`) is a future item.
- **No state pruning:** RetentionClass types exist but no pruning implementation.


## Architecture (9 crates)

| Layer | Crate | Description |
|-------|-------|-------------|
| 7 | `sccgub-node` | 23 CLI commands, chain lifecycle, mempool, block log + snapshots, observability |
| 6 | `sccgub-api` | REST API (22 versioned endpoints), CORS, structured error codes, versioned routes |
| 5 | `sccgub-governance` | Norms, precedence, proposals with timelocks, anti-concentration, symbolic intelligence agent policy |
| 4 | `sccgub-consensus` | Two-round BFT voting, bounded finality, slashing, partition recovery, safety proofs |
| 3 | `sccgub-execution` | 13-phase Phi traversal (all real), CPoG, gas metering, runtime invariant monitor |
| 2 | `sccgub-state` | Merkle trie (lazy cache), balance ledger, treasury, escrow/DvP, multi-asset |
| 1 | `sccgub-types` | 25 modules: blocks, transitions, causal graph, events, economics, compliance, artifacts, attestations, lineage, rights, sessions, disputes |
| 0 | `sccgub-crypto` | BLAKE3, Ed25519, Merkle proofs, Argon2id+ChaCha20-Poly1305 keystore, role keys |
| - | `sccgub-network` | Peer protocol, 10 message types, peer registry + basic p2p runtime |

## Key Properties

- **Consensus:** Deterministic proposer rotation with optional p2p block gossip and vote propagation (single-height, multi-round timeouts); BFT voting and safety machinery are implemented in `sccgub-consensus`
- **Peer diversity gate (configurable):** `network.min_connected_peers` and `network.max_same_subnet_pct` enforce eclipse-resistance when p2p is enabled
- **Peer seed exchange (bounded):** Hello messages exchange a bounded seed list to expand connectivity without unbounded discovery
- **Finality:** Deterministic by default; BFT finality is available in the p2p alpha path via `finality.mode` governance settings
- **Validation:** 13-phase Phi traversal — all 13 phases enforce real invariants (Phase 3: namespace ontology, Phase 8: payload consistency)
- **Contracts:** Decidable step-bounded symbolic programs with chain-bound gas metering and default step limits
- **Identity:** Mfidel 34x8 Ge'ez atomic seal + cryptographic agent binding
- **Governance:** Precedence hierarchy enforced at validation time. Accepted proposals finalize, enter timelock (ordinary 50 / constitutional 200 blocks), and activate into live governance state during block production
- **Governed parameters (live):** `governance.max_consecutive_proposals`, `governance.max_actions_per_agent_pct`, `governance.safety_change_min_signers`, `governance.genesis_change_min_signers`, `governance.max_authority_term_epochs`, `governance.authority_cooldown_epochs`, `finality.confirmation_depth`, `finality.max_finality_ms`, `finality.target_block_time_ms`
- **Governance transitions:** parameter proposals use `norms/governance/params/propose` with payload `key=value`, votes use `norms/governance/proposals/...`
- **Economics:** Gas metering, treasury (fee/reward/burn lifecycle), escrow/DvP
- **Custody:** 6 operator key roles (Genesis/Governance/Treasury/Validator/Operator/Auditor)
- **Persistence:** Replay-authoritative world state by default, backed by on-disk blocks, encrypted validator keystore, chain metadata, and periodic snapshots, with an optional redb-backed state store mirror or startup-authoritative mode via `storage.state_store_authoritative` (API reads live-sync to in-process state when event hooks are active; default sync throttle 250ms via `api_sync.min_interval_ms`)
- **Consensus parameters:** Canonical `ConsensusParams` embedded in genesis, committed under `system/consensus_params`, restored during import + snapshot recovery, and used for proof depth, SCCE propagation bounds, contract default step limits, gas schedule + limits, and validation size caps
- **Keystore:** Argon2id KDF + ChaCha20-Poly1305 AEAD (finance-grade)
- **Arithmetic:** Fixed-point i128 (18 decimals) — no floating-point in consensus
- **Signatures:** Ed25519 over canonical bincode covering all 9 semantic fields
- **Compliance:** GDPR erasure proofs, off-chain data references, audit trails
- **Symbolic intelligence agents:** OWASP-compliant policy enforcement (default-deny, write/read prefixes)
- **Assets:** Multi-asset ledger (Native, Stablecoin, Bond, RealEstate, Commodity, Custom)
- **Events:** 18 typed chain events (economics + governance + artifact lifecycle)
- **Artifacts:** External artifact governance layer (provenance, attestations, lineage, rights, sessions, disputes)
- **Safety:** Signed quorum certificates, equivocation evidence store, runtime invariant monitor

## REST API (22 versioned endpoints)

```
GET  /api/v1/status                  Chain summary (height, finality, tension, governance)
GET  /api/v1/status/schema           JSON schema for status output
GET  /api/v1/openapi                 OpenAPI spec (YAML string payload)
GET  /api/v1/health                  System health + finality SLA
GET  /api/v1/finality/certificates   Finality safety certificates
GET  /api/v1/governance/params       Governed parameter values
GET  /api/v1/governance/params/schema JSON schema for governed parameters
GET  /api/v1/governance/proposals    Governance proposal registry summary (?offset=&limit=&status=)
GET  /api/v1/network/peers           Peer network stats (bandwidth, score, violations)
GET  /api/v1/network/peers/{validator_id} Peer detail by validator id
GET  /api/v1/slashing                Slashing summary + events
GET  /api/v1/slashing/{validator_id} Validator slashing detail
GET  /api/v1/slashing/evidence       Equivocation evidence (all validators)
GET  /api/v1/slashing/evidence/{validator_id} Equivocation evidence for validator
GET  /api/v1/block/{height}           Block detail with transaction list + governance snapshot (limits + finality config)
GET  /api/v1/block/{height}/receipts  Block receipts with gas breakdown
GET  /api/v1/state                   Paginated world state (?offset=&limit=)
GET  /api/v1/tx/{tx_id}              Transaction detail by hex ID
GET  /api/v1/receipt/{tx_id}         Receipt with verdict + resource usage
POST /api/v1/tx/submit               Submit signed transaction (hex-encoded)
POST /api/v1/governance/params/propose Submit signed parameter proposal (hex-encoded)
POST /api/v1/governance/proposals/vote Submit signed proposal vote (hex-encoded)
```

Structured error codes (14 machine-readable `ErrorCode` variants). CORS enabled. Legacy routes at `/api/*`. OpenAPI contract: `crates/sccgub-api/openapi.yaml`. Refresh with `cargo run -q -p sccgub-api --bin generate_openapi -- --write crates/sccgub-api/openapi.yaml`. API state live-syncs when event hooks are active.

## CLI Commands (23)

```bash
# Chain lifecycle
sccgub init               # Genesis + 1M token mint + validator key
sccgub produce --txs N    # Produce gas-metered CPoG-validated block
sccgub transfer AMOUNT    # Asset transfer with Ed25519 signature
sccgub verify             # Replay + verify all Merkle roots + state

# Inspection
sccgub status             # Chain summary with block history
sccgub status --schema    # JSON schema for status output
sccgub stats              # Detailed statistics (graph, state, governance)
sccgub health             # Health report (finality, economics, security)
sccgub show-block N       # Block detail with all transactions
sccgub show-state         # World state entries
sccgub search-tx PREFIX   # Find transaction by ID
sccgub balance PREFIX     # Show agent balances
sccgub governed           # Governed parameter values
sccgub governed-propose KEY VALUE  # Propose governed parameter update
sccgub governed-vote PROPOSAL_ID   # Vote for a governance proposal
sccgub governed-status             # Show governance proposal registry

# Portability
sccgub export FILE        # Portable chain snapshot
sccgub import FILE        # Import with CPoG re-validation

# API server
sccgub serve --port 3000  # Start REST API
sccgub observe --port 3000 --interval 5  # Start API + live metrics
sccgub observe --json --interval 1       # JSON lines for tooling
sccgub governed --json       # Governed parameters as JSON
sccgub governed --schema     # JSON schema for governed output
```

### Observe JSON Output

When `sccgub observe --json` is enabled, each line is a JSON object:

```json
{
  "height": 42,
  "finalized_height": 40,
  "mempool": 12,
  "slashing_events": 1,
  "api_sync_events": 25
}
```

Canonical schema: `specs/OBSERVE_JSON_SCHEMA.md`.

# Economics
sccgub treasury           # Treasury status + conservation check
sccgub escrow             # Escrow registry summary

# Reference
sccgub demo               # In-memory demonstration
sccgub info               # Spec + invariants reference
```

## Quick Start

```bash
cargo build                    # Build all 9 crates
cargo test                     # Run all tests
cargo run -- init              # Initialize chain
cargo run -- produce --txs 5   # Produce a block
cargo run -- transfer 10000    # Transfer tokens
cargo run -- verify            # Verify chain integrity
cargo run -- health            # Chain health report
cargo run -- serve             # Start API server
```

```powershell
# Windows full-suite fallback: isolate the target dir to avoid intermittent link.exe file locks
$env:CARGO_TARGET_DIR='target-windows-full'; cargo test -j 1 --workspace
```

To enable p2p networking: set `network.enable = true` (optional `network.peers`, `network.validators`, and `network.allowed_peers`) in `sccgub.toml`, then run `sccgub serve --p2p`.

Canonical end-to-end demo path: `specs/DEMO_GOVERNED_LIFECYCLE.md`.
Verification checklist: run the governance lifecycle demo and API surface demo
from `scripts/README.md` to reproduce proposal activation and receipt queries.

## Production Gate Status

| Gate | Status | Evidence |
|------|--------|----------|
| Protocol freeze | Done | [PROTOCOL.md](PROTOCOL.md) — 14-section canonical spec |
| Consensus adversarial | 12 tests | Byzantine tolerance, vote forgery, equivocation, partition recovery |
| Financial conservation | 7 tests | Transfer, treasury, escrow (release + refund), no phantom supply |
| Replay determinism | Verified | Identical operations produce identical state roots |
| Keystore crypto | Argon2id + ChaCha20-Poly1305 | AEAD tamper detection, memory-hard KDF |
| Custody roles | 6 roles | Validator/Treasury/Governance separation with rotation and revocation |
| Structured API errors | 14 error codes | Machine-readable rejection for every failure path |
| Escrow attack surface | 6 tests | Double-release, premature refund, self-escrow, zero-amount |
| Gas metering | Wired | Chain-bound gas schedule + limits, trie-backed fee/reward replay |
| Governance timelocks | Enforced | Ordinary 50 blocks, constitutional 200 blocks, activated in live chain lifecycle |
| Runtime invariants | 7 checks | Supply, nonce, state root, tension, receipts, causality |
| CI | 3 jobs | Ubuntu (fmt+build+test+clippy), Windows (build+test), security (cargo-audit) |

## Local CI Gate

Use the local gate scripts to mirror CI before pushing:

```bash
./scripts/run-ci.sh
```

```powershell
pwsh ./scripts/run-ci.ps1
```

```powershell
pwsh ./scripts/ci-local.ps1
```

## Conformance Matrix

| Invariant | Enforcing Module | Test File | Failure Mode |
|-----------|-----------------|-----------|--------------|
| INV-1: Valid CPoG | `execution/cpog.rs` | `integration_test.rs` | Block rejected with error list |
| INV-2: Phi traversal | `execution/phi.rs` | `integration_test.rs` | Phase failure halts traversal |
| INV-3: Governance precedence | `execution/phi.rs` (phase 6) | `integration_test.rs` | Transition rejected |
| INV-4: No fork | `consensus/safety.rs` | `adversarial_test.rs` | Equivocators identified + slashed |
| INV-5: Tension budget | `execution/phi.rs` (phase 9) | `integration_test.rs` | Block rejected |
| INV-6: Identity immutable | `execution/validate.rs` | `integration_test.rs` | agent_id mismatch rejected |
| INV-7: WHBinding complete | `execution/wh_check.rs` | `integration_test.rs` | WHO+WHERE cross-checked, WHAT/WHEN/HOW/WHICH structural only |
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
| INV-7 | No transition without WHBinding (7 fields present; WHO+WHERE cross-checked, others structural) |
| INV-8 | No contract beyond decidability bound |
| INV-13 | Responsibility bounded across the live chain lifecycle |
| INV-17 | Causal graph acyclicity |

## Specification

- [PROTOCOL.md](PROTOCOL.md) — Frozen protocol spec (consensus, finality, fees, replay rules)
- `specs/SCCGUB_SPEC.md` — v1.0 original specification
- `specs/SCCGUB_v2_ENHANCED.md` — v2.0 enhanced
- `specs/SCCGUB_v2.1_AUDIT_AND_REFINEMENT.md` — v2.1 audit + refinement

## License

MIT
