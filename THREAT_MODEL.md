# SCCGUB Threat Model

**Version:** 0.4.0
**Last updated:** 2026-04-18

This document defines what the SCCGUB blockchain defends against, what it
does not defend against, and the concrete security boundaries at each layer.

---

## 1. Adversary Model

### What the chain tolerates

| Threat | Defense | Bound |
|---|---|---|
| Byzantine validators | BFT quorum (u64 intermediate arithmetic): block finalized only when >2/3 prevote AND >2/3 precommit | f < n/3 |
| Double-signing | Equivocation detection + 32% stake slash | Per-evidence, immediate |
| Validator absence | 1% stake slash per epoch, forced removal after 10 epochs | Configurable |
| Law set divergence | 10% stake slash on hash mismatch | Per-evidence |
| Replay attacks | Sequential nonce enforcement (exactly last+1) at 3 sites | Per-agent |
| Cross-chain replay | Vote domain separation: chain_id + epoch bound into every signature | Per-vote |
| Namespace violation | Default-deny ontology: each TransitionKind can only write to declared prefixes | Per-tx, Phi Phase 3 |
| system/ namespace write | No TransitionKind maps to system/ (exhaustive test) | Structural |
| Mempool spam | admit_check: sig length, nonce, size limits on all payload variants | Per-tx |
| Gas exhaustion | Per-tx gas limit (1M default), per-block limit (50M default), reject receipt on exhaustion | Per-block |
| Oversized messages | Frame size limit: 8 MiB per network message | Per-peer |
| Peer flooding | Rate limit: 50 msgs/window, 64 KB bandwidth/window per peer; disconnect at 3 violations | Per-peer |
| Key theft (at rest) | Argon2id KDF + ChaCha20-Poly1305 AEAD; 32-byte salt, 12-byte nonce; constant-time comparison; zeroize after use | Per-keystore |
| Corrupt snapshot import | balances_from_trie and treasury_from_trie fail-closed on malformed entries; CPoG validates every imported block | Per-import |
| Consensus param tampering | ConsensusParams embedded in genesis state root; bounds-validated on deserialization; any change = different state root = CPoG rejection | Per-chain |
| Escrow unauthorized release | StateProof conditions verify writer identity via block_writers map | Per-escrow |
| Governance escalation | Precedence check: actor level <= required level for governance ops | Per-tx, Phi Phase 6 |

### What the chain does NOT yet defend against

| Threat | Gap | Mitigation path |
|---|---|---|
| Network partitions | No view-change protocol; consensus stalls if <2/3 reachable | Implement PBFT-style view change with leader escalation |
| Eclipse attacks | min_connected_peers (default 3) + max_same_subnet_pct (50%) but no peer diversity proof | Add peer certificate exchange or trusted seed nodes |
| Long-range attacks | No checkpoint system; an attacker with old keys could fork from deep history | Implement periodic checkpoints signed by supermajority |
| Validator set >2B | Quorum calculation uses u64 intermediate but u32 output; safe to ~4B validators | Unlikely to matter in practice |
| Contract execution | No VM — contracts validated structurally only | Integrate WASM runtime for ContractInvoke |
| State database DoS | State is in-memory (HashMap-backed trie); large state causes OOM | Replace with disk-backed store (RocksDB) |
| MEV / front-running | Deterministic tx ordering (nonce, tx_id) prevents validator reordering but doesn't prevent observation | Consider encrypted mempool or commit-reveal |

---

## 2. Cryptographic Assumptions

| Primitive | Algorithm | Key/Output Size | Assumption |
|---|---|---|---|
| Hashing | BLAKE3 | 256-bit | Collision resistance |
| Signatures | Ed25519 | 256-bit keys, 512-bit signatures | EUF-CMA security |
| Key derivation | Argon2id | 32-byte output, 32-byte salt | Memory-hard; GPU/ASIC resistant |
| Authenticated encryption | ChaCha20-Poly1305 | 256-bit key, 96-bit nonce | IND-CCA2 security |
| Merkle tree | BLAKE3 of sorted leaves | 256-bit root | Binding + collision resistance |

All consensus-critical arithmetic uses `i128` with **saturating operations** (no floating-point,
no unchecked overflow). Fixed-point precision: 18 decimal places via TensionValue.

---

## 3. Consensus Safety Properties

1. **No block finalized without supermajority.** Quorum = floor(2n/3) + 1 for both prevote and precommit.
2. **No double-finalization.** Two conflicting blocks at the same height require >1/3 equivocating validators, which triggers slashing.
3. **Deterministic proposer selection.** round_robin_proposer sorts by node_id; same input = same proposer on all nodes.
4. **Vote binding.** Every vote is signed over (chain_id, epoch, block_hash, height, round, vote_type). Cross-chain, cross-epoch, and cross-height replay is impossible.
5. **Stake non-negative.** Slashing penalties capped at available stake; no negative balance or stake inflation.
6. **Population shares in [0, SCALE].** Norm evolution clamps shares and falls back to equal distribution if total collapses.

---

## 4. Validation Pipeline Invariants

1. **Single source of truth for per-tx checks:** `phi_check_single_tx()`. Both block-level and gas-loop validation call it.
2. **Every rejection produces a receipt.** No silent drops — mempool admission uses lightweight `admit_check()` (with checked nonce arithmetic), all semantic rejections happen in the gas loop with `Verdict::Reject` receipts.
3. **Checks-effects-interactions** in state application. All transfers computed, then state writes, then trie commitment.
4. **Zero unwrap/expect in consensus crates.** Verified across sccgub-execution, sccgub-state, sccgub-consensus, sccgub-governance.
5. **Constraint key null-byte termination.** Prevents prefix collision (N-1 fix). `constraint_key()` returns `Result`, not panic.
6. **Default-deny ontology.** Any TransitionKind not explicitly mapped to a namespace is rejected.

---

## 5. Governance Safety Properties

1. **Timelock enforcement.** Proposals must pass: submit → vote → finalize → timelock → activate. No shortcut.
2. **Precedence hierarchy.** GENESIS > SAFETY > MEANING > EMOTION > OPTIMIZATION. Lower-authority agents cannot perform higher-authority actions.
3. **Collection caps enforced.** MAX_PROPOSALS(10K), MAX_AGENTS(100K), MAX_NORMS(10K), MAX_AGENT_POLICIES(50K), MAX_TRACKED_NODES(10K). Registry full returns explicit error.
4. **Parameter bounds.** All governance-mutable parameters validated: max_consecutive_proposals >= 1, authority_cooldown_epochs <= 1000, max_finality_ms in [1, 300000], etc.
5. **Dynamic validator set.** `validators.add` / `validators.remove` via governance proposals. Sorted deterministically. Deduplicated.

---

## 6. Network Trust Model

| Phase | Trust level | Verification |
|---|---|---|
| TCP connect | Untrusted | Rate-limited before any parsing |
| Hello handshake | Signature-verified | Ed25519 + validator set membership + epoch + protocol version |
| Block proposal | Fully verified | Signature + proposer rotation + CPoG 11-check validation |
| Vote admission | Fully verified | Signature + membership + height/round/type + duplicate rejection |
| Block import | Fully verified | validate_candidate_block + apply_block_economics + CPoG |
| Snapshot restore | Locally trusted | State root + balance root validated against block headers |

---

## 7. Operational Security

- **Key storage:** Argon2id + ChaCha20-Poly1305 encrypted bundles. Plaintext config passphrase discouraged (env var SCCGUB_PASSPHRASE preferred).
- **Consensus state persistence:** Round votes saved to disk after each vote, cleared after finalization. Crash-safe restart.
- **Block persistence:** Atomic write-then-rename pattern. Height continuity + parent linkage validated on load.
- **Snapshot persistence:** Periodic snapshots with full state capture. Validated against chain tip on restore.

---

## 8. Audit History

- 10 hardening passes across 21+ sessions
- 85+ findings identified, all closed (N-1 through N-50)
- 12 false positives dismissed with documented reasoning
- Zero unwrap/expect in consensus-critical production code
- All `.len() as u32` casts guarded with `.min(u32::MAX as usize)`
- All `+ 1` arithmetic in production code uses checked/saturating operations
- 1320 Rust tests + 30 Python-port tests + 20 cross-language conformance runs, CI green on Linux + Windows + security audit (v0.8.1)

Formal adversarial passes archived in `docs/audits/`:
- **2026-04-18 DCA v0.5.0 Layers 2–3–4** — `docs/audits/2026-04-18-dca-v0.5.0-layers-2-3-4.md`. Cross-map of findings to remediation status in §9 below.

---

## 9. Residual Risks at the BFT Threshold

The following risks are **explicitly accepted** as residuals at the 2/3+1-honesty assumption on which the BFT consensus model rests. Protocol-level remediation at the BFT threshold would contradict that assumption and is not planned. Operator-level mitigations are documented per-item.

### 9.1 Quorum-collusion validator-set capture

**Source:** 2026-04-18 DCA audit §G.4 + §H.3 (FRACTURE-L2-03). Tracking issue: #52.

**Description:** A 2/3+1 quorum of colluding validators can:
- Rotate any non-colluding validator's key to a key of the quorum's choosing via §18.6 `ValidatorSetChange::RotateKey` (satisfiable because §18.2 rule 7 only prohibits key *reuse*, not attacker-chosen fresh keys).
- Slash any non-colluding validator via `EquivocationEvidence` constructed by the quorum (§22 admission requires only that signatures verify and the target was in active set — both trivially satisfiable for an innocent target).

**Why accepted:** the attacker threshold matches the BFT safety-assumption threshold. A protocol defense *at* 2/3+1 would break the assumption that 2/3+1 is honest.

**Operator mitigations:**
- **Validator selection diligence.** Treat validator-set composition as a first-class governance decision; do not admit validators without independently verified identity and operational-security posture.
- **Multi-sig validator keys.** Where practical, validators operate their signing key under an M-of-N threshold scheme internal to the validator's organization. Compromising one signer's credentials is insufficient.
- **Off-chain social attestation.** Validator identity anchored to externally-verifiable commitments (stake, legal identity, reputation). Chain-level governance remains the authoritative on-chain source, but off-chain slashing-equivalent social mechanisms raise the cost of collusion.

**Residual:** a 2/3+1 quorum that coordinates under adversarial intent can capture the validator set. No protocol defense exists; none is planned.

### 9.2 Slashing as privilege attack

**Source:** 2026-04-18 DCA audit §G.4, sub-item.

**Description:** The same quorum-collusion posture that enables validator-set capture also enables weaponization of slashing: the colluding quorum constructs two conflicting votes under the target validator's key and admits them as `EquivocationEvidence`. Target is slashed; quorum retains control.

**Why accepted:** same as 9.1 — the attack requires 2/3+1 collusion, at which point the BFT safety assumption is already broken.

**Operator mitigations:**
- Same as 9.1.
- Evidence-monitoring tooling can alert non-colluding validators to emerging patterns (e.g., Remove events targeting validators outside the quorum), supporting off-chain coordination to remove the colluding quorum via governance before capture completes.

**Residual:** weaponized slashing is structurally possible under quorum collusion. Off-chain monitoring is the only early-warning mechanism.

### 9.3 Accepted-for-now vs. accepted-forever

These residuals are accepted **under the current BFT model**. They are not accepted under a hypothetical future consensus model. Specifically:

- Future work on **quorum-robust identity** (e.g., stake-collateralized validator registration, decentralized social recovery of captured validator-agents, proof-of-personhood layers) could narrow the quorum-collusion attack surface *below* the 2/3+1 threshold. Such work is not scoped to any current patch but is not foreclosed.
- **Chain-forking recovery** under detected quorum capture is an operational-continuity mechanism outside the protocol. Operators facing confirmed quorum capture may coordinate an external fork from the last-known-honest state; this breaks on-chain consensus with the captured chain but preserves honest operator continuity.

---

## 10. Deferred compliance and recovery gaps (cross-reference)

The following fractures from the 2026-04-18 DCA audit are **not accepted as residuals** — they are tracked for remediation but not addressed in the current release. Each has its own tracking issue:

| Issue | Fracture | Layer | Triage disposition |
|---|---|---|---|
| #50 | Veto-timelock timing reconciliation | L2 | spec-patch candidate |
| #51 | State growth operational tooling + fast-sync | L4 | operational workstream |
| #53 | Regulatory impossibility lock-in | L3 | quarterly review (first review 2026-07-18) |
| #54 | Evidence-submission incentive gap | L2 | design-required |
| #55 | Ceiling-lowering asymmetric invariant | L2 | spec-patch candidate |
| #56 | Non-validator key-recovery under compromise | L4 | design-required |
| #57 | §13 amendment: DCA-before-merge discipline | governance | spec-patch candidate |

Unlike §9 residuals, these are addressable within the current protocol paradigm. Deferral is scheduling, not acceptance.
