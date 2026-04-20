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
- REST API with 27 versioned endpoints for state, blocks, receipts, governance, finality, v3 validator-set/ceilings/key-rotation views, and v4 full admission-history projection. v5 adds forgery-veto authorization, base-fee floor, declared fork-choice rule, pruning-contract predicates, and live-upgrade protocol types (see PATCH_06.md).
- Consensus-critical values live in `ConsensusParams` embedded at genesis (no hardcoded drift).
- Hardening posture: 1338 Rust tests + 30 Python-port tests + 36 TypeScript-port tests + 30 cross-language conformance runs, CI green on Ubuntu + Windows + security audit.
- Cross-language moat verifier: three independent implementations producing byte-identical output — Rust (`sccgub-audit`, reference), Python (`sccgub-audit-py`, PATCH_09.md §A.1), TypeScript (`sccgub-audit-ts`, PATCH_09.md §C). All three at v0.8.3, with CeilingFieldId updated to 19 variants per PATCH_10 §39.4. Go port (PATCH_09 §B) deferred. CI enforces 30 byte-identical runs per release per PATCH_09 §C semantic baseline + cross-port version-sync per PR #61.
- PATCH_10 rollout (v0.8.3 = types foundation; v0.8.4 = §38 symmetric governance check; v0.8.5 = §39 evidence-layer ForgeryVeto admission). Each under its own DCA-before-merge pre-review per PATCH_10 §40.
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
