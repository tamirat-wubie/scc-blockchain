<!--
Purpose: Canonical, truth-aligned snapshot of SCCGUB runtime status and priorities.
Governance scope: OCE, RAG, CDCV, CQTE, UWMA, SRCA, PRS.
Dependencies: README.md, EXTERNAL_AUDIT_PREP.md, PROTOCOL.md.
Invariants: Counts and capabilities match scripts/verify-repo-truth.ps1 outputs.
-->

# SCCGUB Blockchain - Where It Stands

## What it is
A Rust blockchain that enforces rules through code, not trust. Every transition must satisfy the 13-phase Phi
traversal and produce a causal receipt that proves what changed and why.

## What works right now
- Genesis, transaction submission, block production, import, and replay with full verification.
- Deterministic validation: every rejection has a reason (receipts).
- Governance proposals: submit -> vote -> timelock -> activate into live governance state.
- REST API with 22 versioned endpoints for state, blocks, receipts, governance, and finality.
- Consensus-critical values live in `ConsensusParams` embedded at genesis (no hardcoded drift).
- Hardening posture: 824 tests, CI green on Ubuntu + Windows + security audit.
- Minimal p2p networking: peer registry, hello/heartbeat, block sync, tx gossip, vote propagation, and per-peer
  limits (no hardened peer discovery or deeper DoS protection).
- Persistence: block log and periodic snapshots; state is replay-authoritative by default on restart, with optional redb-backed startup-authoritative mode.

## What it cannot do yet
- Multi-validator consensus is wired in the p2p alpha path but not production-hardened; default mode is single proposer.
- No fully durable state database by default: state is reconstructed from persisted blocks + snapshots unless redb-backed startup-authoritative mode is enabled.
- Contract VM is not implemented (contract types exist, structural validation only).
- No ZK/privacy implementation (placeholders only).

## Where to work next (priority order)
1. Multi-validator BFT wiring (turns the kernel into a distributed chain).
2. Durable state database (replace replay-only state with persistent storage).
3. Contract VM (WASM or similar) using the existing validation + gas scaffolding.
4. Expand governed parameter surface beyond the current allowlist.
5. Block explorer/indexer using receipts + API.

## One-sentence summary
The validation kernel is hardened and truthful; the next work is making it distributed, persistent, and programmable.
