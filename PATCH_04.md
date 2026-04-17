# SCCGUB Protocol Amendment — Patch 04

**Target version:** v0.4.0
**Amends:** PROTOCOL.md v1.0 (FROZEN)
**Amendment status:** DRAFT (revision 2) — pending governance proposal with constitutional timelock (200 blocks).
**Chain version introduced:** `header.version = 3` (v2 replay compatibility preserved).

This document amends PROTOCOL.md. When v0.4.0 is tagged, sections §15–§19 are merged into PROTOCOL.md as PROTOCOL v2.0 and this document is archived. Until then, PROTOCOL.md remains frozen and this draft is the sole source of truth for v3 consensus rules.

Patch-04 closes three structural fractures identified by external audit, plus one identity-continuity gap:
- **F1 — Undefined validator-set mutation** (addressed in §15).
- **F2 — Missing view-change / liveness protocol in two-round BFT** (addressed in §16).
- **F3 — Recursive-governance expansion of `ConsensusParams`** (addressed in §17).
- **F4 — Identity permanently bound to initial key material** (addressed in §18, closes INV-6 aspirational gap).

All Patch-04 rules are consensus-critical. Any conforming v3 implementation MUST produce identical state roots given identical inputs.

> **Revision 2 notes:** following initial-draft review, five normative amendments applied: (a) leader selection folds in `prior_block_hash` (§16.2) to eliminate arbitrary-distance leader-schedule prediction, (b) validator-scoped key rotation requires coupled `ValidatorSetChange::RotateKey` with quorum signatures (§18.6, new INV-VALIDATOR-KEY-COHERENCE), (c) equivocation slashing admits a narrow forgery-only veto window during the activation delay (§15.7), (d) `activation_delay` is clamped to `[2, k+8]` (§15.5), (e) ceiling values in §17.2 reconciled to risk-profiled headroom (safety-adjacent ×1–×2, throughput/economic ×4–×16).

---

## §15 Validator Set Management

Before Patch-04, the validator set was implicitly fixed at genesis, with no on-chain rule for membership change. Two honest nodes that disagreed on membership could admit different quorums against the same vote stream. §15 makes validator-set membership a consensus-critical, replay-deterministic function of signed on-chain events.

### 15.1 ValidatorRecord

```
ValidatorRecord := {
    agent_id:       AgentId,              // BLAKE3, 32 bytes — persistent identity (§3)
    validator_id:   Ed25519PublicKey,     // current signing key; may rotate via RotateKey (§15.4)
    mfidel_seal:    MfidelAtomicSeal,     // from_height(registration_height)
    voting_power:   u64,                   // non-zero for active validators
    active_from:    BlockHeight,           // u64, inclusive
    active_until:   Option<BlockHeight>,   // None = indefinite; Some(h) = last active at h
}
```

Canonical bincode field order: `agent_id, validator_id, mfidel_seal, voting_power, active_from, active_until`. `Option` encodes as bincode tag byte followed by `BlockHeight` if present.

A validator is **active at height H** iff `active_from <= H && active_until.map_or(true, |u| H <= u) && voting_power > 0`.

`validator_id` is the *current* Ed25519 signing key. `agent_id` is the stable cross-rotation identity (§3): `agent_id = BLAKE3(original_public_key || canonical_bytes(mfidel_seal))`, where `original_public_key` is the key supplied at registration. A `RotateKey` event (§15.4) replaces `validator_id` while preserving `agent_id`.

### 15.2 ValidatorSet

```
ValidatorSet := Vec<ValidatorRecord>
```

Canonical ordering: **sorted ascending by `agent_id` bytes**. Duplicate `agent_id` or duplicate `validator_id` values are invalid. `agent_id` is used for canonical ordering (not `validator_id`) so that key rotation does not reorder the set and cause unrelated state-root churn.

Commitment key: `system/validator_set`. Value: `bincode(ValidatorSet)`.

The active subset at height H is derived from the full record list via the §15.1 predicate. Only active records participate in quorum calculation under §6.

### 15.3 Quorum (amends §6)

```
active_set(H)   = [r for r in ValidatorSet if r is active at H, sorted by agent_id]
total_power(H)  = sum(r.voting_power for r in active_set(H))
quorum_power(H) = floor(2 * total_power(H) / 3) + 1
```

Vote admission (replaces §6.4 membership check): a vote signed by Ed25519 key PK at height H is admitted iff there exists `r in active_set(H)` with `r.validator_id == PK`. Because `validator_id` can rotate, this lookup must be performed against the active set AS OF the vote's height. All other §6.4 admission checks continue to apply.

### 15.4 ValidatorSetChange event

```
ValidatorSetChangeKind :=
    | Add(ValidatorRecord)
    | Remove       { agent_id, reason: RemovalReason, effective_height }
    | RotatePower  { agent_id, new_voting_power: u64, effective_height }
    | RotateKey    { agent_id, old_validator_id: Ed25519PublicKey,
                                 new_validator_id: Ed25519PublicKey, effective_height }

RemovalReason := Voluntary | Equivocation | Inactivity | Governance

ValidatorSetChange := {
    change_id:         BLAKE3Hash,                                     // BLAKE3(canonical_change_bytes)
    kind:              ValidatorSetChangeKind,
    proposed_at:       BlockHeight,
    quorum_signatures: Vec<(Ed25519PublicKey, Ed25519Signature)>,
}
```

Canonical bincode field order for `ValidatorSetChange`: `change_id, kind, proposed_at, quorum_signatures`. `effective_height` is part of the kind payload (it varies by variant, and is included in `canonical_change_bytes`).

`quorum_signatures` is sorted ascending by signer public key bytes; duplicate signers are invalid.

`canonical_change_bytes` (input to `change_id` and to the per-signer signatures) covers:
```
bincode(kind, proposed_at)
```
`quorum_signatures` is excluded from the hash to prevent signature malleability from affecting `change_id`.

`RotatePower` adjusts `voting_power` only. `RotateKey` replaces `validator_id` only. The two variants are split so that neither may silently carry the other's effect, and so that phase-level validators can apply them with distinct predicates.

### 15.5 Activation rule

A `ValidatorSetChange` is admitted at block height `H_admit` iff:

1. `kind.effective_height >= H_admit + activation_delay`, where:
   ```
   activation_delay = clamp(confirmation_depth + 1, 2, confirmation_depth + 8)
   ```
   The floor (2) is constitutional — never less, regardless of `k`. The ceiling (`k+8`) is defensive against future `ConsensusParams` additions that might attempt to set `activation_delay` independently of `k`. Under the default `k=2`, `activation_delay = 3`.
2. The signer set of `quorum_signatures` is a subset of `active_set(H_admit)`.
3. The sum of `voting_power` over signers reaches `quorum_power(H_admit)`.
4. Every signature in `quorum_signatures` verifies under `verify_strict` against `canonical_change_bytes`.
5. `change_id == BLAKE3(canonical_change_bytes)`.
6. Variant-specific predicates (§15.5.1).

Activation is deferred: the change is recorded in state at `H_admit` but the derived `active_set` only reflects the change from `effective_height` onward. Quorum for `ValidatorSetChange` admission always uses `active_set(H_admit)`, never `active_set(effective_height)`. This prevents a post-change majority from self-admitting.

#### 15.5.1 Variant predicates

- **Add**: `record.agent_id` not already present in ValidatorSet (even as inactive).
- **Remove**: `agent_id` present and currently active.
- **RotatePower**: `agent_id` present; `new_voting_power > 0`.
- **RotateKey**: `agent_id` present; `old_validator_id == ValidatorSet[agent_id].validator_id`; `new_validator_id != old_validator_id`; `new_validator_id` not in use by any other ValidatorRecord; coupled `KeyRotation` event present in the same block (see §18.6).

### 15.6 Replay derivation

Validator set replay is deterministic:
```
active_set(H) =
    starting from genesis.validator_set,
    apply all ValidatorSetChange events from blocks [1..=H]
    in order of (effective_height ascending, change_id ascending),
    where:
        Add           → append ValidatorRecord
        Remove        → set active_until = effective_height - 1
        RotatePower   → set voting_power = new_voting_power at effective_height
        RotateKey     → set validator_id = new_validator_id at effective_height
```

Changes with `effective_height > H` are recorded in state but not reflected in `active_set(H)`.

### 15.7 Equivocation slashing (amends §6)

When a validator signs two distinct votes `(block_hash_a, block_hash_b)` for the same `(height, round, vote_type)` with `block_hash_a != block_hash_b`, both signatures constitute equivocation evidence. Any block may include an `EquivocationEvidence` record:

```
EquivocationEvidence := (vote_a: Vote, vote_b: Vote)
```

Canonical bincode field order: `vote_a, vote_b` (sorted ascending by `vote.signature` bytes to canonicalize ordering of the two votes).

Admission of an `EquivocationEvidence` record triggers a **two-stage slashing event**:

1. **Stage 1 — evidence admission at `H_admit`.** The evidence is recorded in state. A synthetic `ValidatorSetChange::Remove { agent_id: vote_a.signer_agent_id, reason: Equivocation, effective_height: H_admit + activation_delay }` is queued. The synthetic event bypasses the quorum-signature requirement of §15.5 (evidence-sourced, not proposer-sourced) but must still satisfy the canonical-bytes and variant-predicate rules.

2. **Stage 2 — veto window `[H_admit, H_admit + activation_delay)`.** During this window, a Safety-level governance proposal (precedence 1) MAY veto the synthetic `Remove` iff it produces cryptographic proof of signature forgery: specifically, two byte-distinct signatures `S_1 != S_2` over the same canonical vote bytes that both pass non-strict Ed25519 `verify` but at least one of which is rejected by `verify_strict`. Forgery proof rejection is mandatory; the veto proposal is admitted only if the proof is valid. No other grounds for veto (mistake, mercy, policy) are permitted.

At `H_admit + activation_delay`, the synthetic `Remove` takes effect unless a valid veto was admitted. Slashing is otherwise absolute: no post-effective-height appeal, no non-forgery-based veto, no governance-level reversal.

The veto window exists solely to rescue honest validators from signature-forgery attacks exploiting a broken verifier implementation. Defense-in-depth against a class of bug that §18 `verify_strict` discipline is supposed to prevent; the narrow veto exists because if `verify_strict` is itself broken, evidence-based slashing would slash innocents.

### 15.8 New invariants

**INV-VALIDATOR-SET-CONTINUITY**: For all heights H > 0, `active_set(H)` is derivable solely from `genesis.validator_set` and all `ValidatorSetChange` records in blocks `[1..=H]`. No implicit, time-based, or off-chain modification is permitted.

**INV-VALIDATOR-KEY-COHERENCE**: For all heights H and all `r in active_set(H)`, `r.validator_id == active_public_key(r.agent_id, H)` (see §18.4). Equivalently: a validator's record-level signing key equals its agent-level current signing key at every height.

---

## §16 View-Change Protocol

§6 specified prevote/precommit admission but not round advancement. A silent leader halted liveness indefinitely. §16 specifies round timeouts, leader selection, and the message that advances the round.

### 16.1 Round timeout

```
T_round(r) = min(view_change_base_timeout_ms * 2^r, view_change_max_timeout_ms)
```
where `r` is the zero-indexed round number. `view_change_base_timeout_ms` and `view_change_max_timeout_ms` are fields in `ConsensusParams` (see §17.3); ceilings in §17.2.

### 16.2 Leader selection

```
leader(height, round) = active_set(height)[
    BLAKE3(prior_block_hash || height_bytes || round_bytes) mod |active_set(height)|
]
```
where:
- `height_bytes = height.to_le_bytes()` (8 bytes, u64).
- `round_bytes = round.to_le_bytes()` (4 bytes, u32).
- `prior_block_hash` is `block[height - 1].block_id` for `height >= 2`, and `ZERO_HASH` for `height == 1` (first post-genesis block, by convention).
- `active_set(height)` is the §15.3 canonically-sorted vector.
- BLAKE3 output is interpreted as a big-endian u256 prior to the modulo; the modulo is defined over `u256 mod n` with `n = |active_set(height)|`.

Folding `prior_block_hash` into the leader hash makes the leader schedule unpredictable beyond the current tip while remaining fully deterministic on replay. Without this, an attacker could identify the leader of any future block at genesis and mount targeted DoS against that validator arbitrarily far in advance.

Leader selection is independent of vote history. Future patches may replace BLAKE3 with a VRF; this patch preserves structural simplicity.

### 16.3 NewRound message

```
NewRound := {
    height:       BlockHeight,
    round:        u32,                      // the round the signer wishes to enter
    last_prevote: Option<BlockHash>,        // last prevote this validator cast at `height`
    signer:       Ed25519PublicKey,
    signature:    Ed25519Signature,
}
```

Canonical bincode field order: `height, round, last_prevote, signer, signature`.

`canonical_newround_bytes` (input to signature) covers: `bincode(height, round, last_prevote, signer)`.

### 16.4 Round advancement

A validator advances from round `r` to round `r+1` at height `h` iff:
1. It has received `NewRound` messages from a subset of `active_set(h)` whose voting-power sum reaches `quorum_power(h)`, AND
2. All referenced `NewRound` messages have `height == h && round == r+1`, AND
3. Each signature verifies under `verify_strict` against `canonical_newround_bytes`, AND
4. Each signer is in `active_set(h)` and its `NewRound.signer == active_public_key(signer_agent_id, h)`.

`NewRound` messages are not votes; they do not affect prevote or precommit tallies of round `r`. They are purely a view-change signal.

### 16.5 Timeout behavior

A validator waits at most `T_round(r)` for prevote quorum at round `r`. On expiry with no prevote quorum, it broadcasts `NewRound(h, r+1, last_prevote)`. The same applies at the precommit phase. The wall-clock reading is local and non-consensus; consensus outcomes depend only on received messages, not on local clocks.

### 16.6 Round history

A node that receives a block with a commit certificate at `round > 0` MUST retain prevote and precommit evidence for all rounds `[0..=round]` referenced by the certificate, alongside the `NewRound` messages that justified each advancement. Evidence is stored in a new section `body.round_history: Vec<RoundRecord>`. The block ID commits to `BLAKE3(canonical_bytes(round_history))` via a new header field `round_history_root`. An empty history encodes as `ZERO_HASH`, not as the Merkle root of an empty vector, consistent with §5.

`body.round_history` is **included in the block-size calculation** enforced by §17.5 against `ConsensusParams.max_block_bytes`. No consensus-critical data is exempted from the block-size ceiling.

### 16.7 New invariant

**INV-VIEW-CHANGE-LIVENESS**: For every admitted block B at `round > 0`, `body.round_history` contains valid `RoundRecord` entries for rounds `[0..round]`, each containing the `NewRound` messages that justified advancement, signed under `verify_strict` by agents in `active_set(B.height)`.

---

## §17 Constitutional Ceilings

Before Patch-04, any `ConsensusParams` value could be raised by a Safety-level governance proposal with 200-block timelock. §17 introduces a parallel struct, `ConstitutionalCeilings`, whose values are bound at genesis and CANNOT be raised by any governance proposal. This closes the recursive-governance path that allowed the chain to drift outside its originally-safe parameter regime.

### 17.1 ConstitutionalCeilings struct

```
ConstitutionalCeilings := {
    // ── §11 CPoG bounds ───────────────────────────────────────────────
    max_proof_depth_ceiling:              u32,

    // ── Gas bounds ────────────────────────────────────────────────────
    max_tx_gas_ceiling:                   u64,
    max_block_gas_ceiling:                u64,

    // ── Contract execution ────────────────────────────────────────────
    max_contract_steps_ceiling:           u64,

    // ── Address / state size ──────────────────────────────────────────
    max_address_length_ceiling:           u32,
    max_state_entry_size_ceiling:         u32,

    // ── Tension ───────────────────────────────────────────────────────
    max_tension_swing_ceiling:            i64,

    // ── Block size ────────────────────────────────────────────────────
    max_block_bytes_ceiling:              u32,

    // ── Governance queue ──────────────────────────────────────────────
    max_active_proposals_ceiling:         u32,

    // ── View-change (§16) ─────────────────────────────────────────────
    max_view_change_base_timeout_ms:      u32,
    max_view_change_max_timeout_ms:       u32,

    // ── Validator set (§15) ───────────────────────────────────────────
    max_validator_set_size_ceiling:       u32,
    max_validator_set_changes_per_block:  u32,
}
```

Canonical bincode field order matches the declaration above, top to bottom. No field may be added, removed, or reordered without a chain hard fork (new `header.version`).

### 17.2 Mandatory Patch-04 default values

Headroom profile per external-audit follow-up: parameters affecting **safety decidability** receive ×1–×2 headroom; parameters affecting **throughput/economics** receive ×4–×16 headroom; parameters with no legitimate growth reason are pinned at default (×1).

| Ceiling field | v3 default | Headroom | Companion `ConsensusParams` field | v3 companion default |
|---|---|---|---|---|
| `max_proof_depth_ceiling` | 512 | ×2 (safety) | `max_proof_depth` | 256 |
| `max_tx_gas_ceiling` | 16_000_000 | ×16 (economic) | `default_tx_gas_limit` | 1_000_000 |
| `max_block_gas_ceiling` | 800_000_000 | ×16 (economic) | `default_block_gas_limit` | 50_000_000 |
| `max_contract_steps_ceiling` | 40_000 | ×4 (decidability) | `default_max_steps` | 10_000 |
| `max_address_length_ceiling` | 4_096 | ×1 (pinned) | `max_symbol_address_len` | 4_096 |
| `max_state_entry_size_ceiling` | 4_194_304 | ×4 (throughput) | `max_state_entry_size` | 1_048_576 |
| `max_tension_swing_ceiling` | 4_000_000 | ×2 (safety) | `max_tension_swing` | 2_000_000 |
| `max_block_bytes_ceiling` | 8_388_608 | ×4 (network) | `max_block_bytes` *(new)* | 2_097_152 |
| `max_active_proposals_ceiling` | 256 | ×2 (governance DoS) | `max_active_proposals` *(new)* | 128 |
| `max_view_change_base_timeout_ms` | 60_000 | — | `view_change_base_timeout_ms` *(new)* | 1_000 |
| `max_view_change_max_timeout_ms` | 3_600_000 | — | `view_change_max_timeout_ms` *(new)* | 60_000 |
| `max_validator_set_size_ceiling` | 128 | — | `max_validator_set_size` *(new)* | 64 |
| `max_validator_set_changes_per_block` | 8 | — | `max_validator_set_changes_per_block_param` *(new)* | 4 |

> **Note**: these values are v3-specific. Future chain versions MAY revise via hard fork. The audit-prose values that diverged from current v0.3.0 defaults (e.g., `max_proof_depth <= 16`, `max_address_length <= 64`, `max_state_entry_size <= 2^16`) are explicitly rejected: they would render default `ConsensusParams` invalid at v3 genesis. The headroom-profiled values above preserve default validity while maintaining structural safety headroom.

> **Note on signed tension**: `max_tension_swing_ceiling` is `i64` because tension swings are conceptually signed (tension may decrease block-over-block). If the existing `ConsensusParams::max_tension_swing` or any internal tension representation uses `u64`, the unsigned form does not handle negative swings explicitly — this should be treated as a separate audit item out of Patch-04 scope. Ceiling typing is chosen defensively.

### 17.3 ConsensusParams additions (v3)

Six new fields are appended to `ConsensusParams` in v3 (canonical bincode field order matches declaration):
- `view_change_base_timeout_ms: u32` — default 1_000.
- `view_change_max_timeout_ms: u32` — default 60_000, must be `>= view_change_base_timeout_ms`.
- `max_block_bytes: u32` — default 2_097_152 (2 MiB).
- `max_active_proposals: u32` — default 128.
- `max_validator_set_size: u32` — default 64.
- `max_validator_set_changes_per_block_param: u32` — default 4.

These fields are present only when `header.version >= 3`. v2 chains continue to deserialize the v2 `ConsensusParams` schema via the existing `LegacyConsensusParamsV1` fallback. A new `LegacyConsensusParamsV2` fallback is added for v2 → v3 canonical-bytes compatibility (defaults are injected for the six new fields when reading a v2-encoded struct).

### 17.4 Validation rule

A v3 block is **ceiling-valid** iff, for the active `ConsensusParams` at its height, every declared pair in §17.2 satisfies `param_value <= ceiling_value`. Phase 10 (Architecture) is extended with this check. Any mismatch rejects the block.

### 17.5 Block size bound (Phase 10)

Phase 10 additionally rejects any block whose `bincode(block)` length exceeds the active `ConsensusParams.max_block_bytes`. Enforcement is on canonical-encoded bytes, including `body.round_history` (§16.6). No consensus-produced data is exempt from this bound.

### 17.6 Active proposal queue bound (Governance)

At most `ConsensusParams.max_active_proposals` governance proposals may be in states `Submitted | Voting | Timelocked` at any time. A submission that would exceed the bound is rejected at mempool admission with `ProposalQueueFull`.

### 17.7 Storage

Commitment key: `system/constitutional_ceilings`. Value: `bincode(ConstitutionalCeilings)`. Written **exactly once** at genesis for v3 chains. Any subsequent write attempt (via any transition kind or governance proposal) is rejected as a phase-6 (Organization) violation.

### 17.8 Governance rejection rule

A governance proposal whose payload would modify any field in `ConstitutionalCeilings`, or whose modification of `ConsensusParams` would cause any pair in §17.2 to exceed its ceiling, is **rejected at submission** (not at timelock expiry). The rejection is a phase-6 (Organization) violation. Submission-time rejection is mandatory because timelock-expiry rejection would let the proposal occupy a queue slot for 200 blocks while being known-invalid.

### 17.9 New invariant

**INV-CEILING-PRESERVATION**: For all v3 heights H, every pair `(param, ceiling)` in §17.2 satisfies `state.consensus_params.param_at(H) <= state.constitutional_ceilings.ceiling` where both values are read from the canonical state at H.

---

## §18 Identity Preservation

§3 defines `agent_id = BLAKE3(public_key || canonical_bytes(mfidel_seal))`. If an agent's private key is compromised, the attacker controls the agent_id permanently; there is no on-chain remediation. §18 introduces a signed key-rotation event that preserves agent_id while replacing the signing key material. For validators (§18.6), key rotation requires coupled consensus-level consent.

### 18.1 KeyRotation event

```
KeyRotation := {
    agent_id:              AgentId,            // BLAKE3 hash, 32 bytes
    old_public_key:        Ed25519PublicKey,
    new_public_key:        Ed25519PublicKey,
    rotation_height:       BlockHeight,
    signature_by_old_key:  Ed25519Signature,
    signature_by_new_key:  Ed25519Signature,
}
```

Canonical bincode field order: `agent_id, old_public_key, new_public_key, rotation_height, signature_by_old_key, signature_by_new_key`.

`canonical_rotation_bytes` (input to both signatures) covers:
```
bincode(agent_id, old_public_key, new_public_key, rotation_height)
```

### 18.2 Admission rule

A `KeyRotation` event is admitted at block height `H_admit` iff:
1. `rotation_height == H_admit`.
2. The `agent_id` exists in state (has been registered under §3).
3. `old_public_key == active_public_key(agent_id, H_admit)` (see §18.4).
4. `new_public_key != old_public_key`.
5. `signature_by_old_key` verifies under `verify_strict` against `canonical_rotation_bytes`.
6. `signature_by_new_key` verifies under `verify_strict` against `canonical_rotation_bytes`. This prevents new-key binding by a compromised old key without the new-key holder's consent.
7. `new_public_key` has not been used as an active key by any agent, past or present, per the global key index (§18.3). This prevents impersonation by reusing another agent's key, even one that has been rotated away.
8. If `agent_id` is in `active_set(H_admit)` (§15.3), the block MUST also include a matching `ValidatorSetChange::RotateKey` (§18.6). Absence or mismatch is a phase-8 (Execution) failure.

### 18.3 KeyRotationRegistry and global key index

```
KeyRotationRegistry := Vec<KeyRotation>
```

Canonical ordering: sorted ascending by `(agent_id, rotation_height)`. At most one rotation per `agent_id` per block height; §18.2 rule 1 with rule 3 makes a second rotation at the same height impossible (the second rotation's `old_public_key` would not match the post-first-rotation active key).

Commitment key: `system/key_rotations`. Value: `bincode(KeyRotationRegistry)`. Append-only: records are never removed or modified; new records extend the vector while preserving canonical ordering.

**Global key index**: a derived lookup `public_key -> Vec<(agent_id, superseded_at_height | None)>` supports §18.2 rule 7. The index is stored under `system/key_index` as:
```
KeyIndex := Vec<KeyIndexEntry>
KeyIndexEntry := { public_key: Ed25519PublicKey,
                   agent_id: AgentId,
                   active_from: BlockHeight,
                   superseded_at: Option<BlockHeight> }
```
Canonical ordering: sorted ascending by `(public_key, active_from)`. Every public key ever used (at registration or via rotation) appears exactly once. A key is considered "in use by an agent, past or present" iff it has an entry in `KeyIndex`; §18.2 rule 7 rejects any new key already in the index.

Rebuild is deterministic: replay registration events and `KeyRotation` events in order; each yields exactly one new `KeyIndexEntry` (for the newly-bound key) and one `superseded_at` update (for the rotated-away key, if any).

### 18.4 Active-key resolution

```
active_public_key(agent_id, H) =
    let rotations = KeyRotationRegistry filtered to agent_id, with rotation_height <= H,
                    sorted by rotation_height ascending
    if rotations is empty:
        original_public_key(agent_id)   // from registration record
    else:
        rotations.last().new_public_key
```

`original_public_key` is the public key supplied at registration, retained in the agent record. This is distinct from `active_public_key` and is never overwritten; `agent_id` identity is permanently anchored to `original_public_key` via §3.

### 18.5 Phase 8 enforcement

Phase 8 (Execution) signature verification uses `active_public_key(tx.actor.agent_id, block.height)` under `verify_strict`. A transaction signed by a superseded key is rejected as an Execution-phase failure with a distinct error code from "signature absent", so that equivocation detectors can distinguish "wrong key" from "unsigned".

### 18.6 Validator-scoped key rotation (coupling requirement)

When `agent_id` corresponds to a validator in `active_set(rotation_height)`, the standalone `KeyRotation` event is insufficient. The block MUST contain BOTH:

- A `KeyRotation` event satisfying §18.2 rules 1–7.
- A `ValidatorSetChange::RotateKey` event satisfying §15.5, with:
  - `kind.agent_id == KeyRotation.agent_id`
  - `kind.old_validator_id == KeyRotation.old_public_key`
  - `kind.new_validator_id == KeyRotation.new_public_key`
  - `kind.effective_height == rotation_height + activation_delay` (standard §15.5 activation deferral)

If either event is present without the other, or if the fields mismatch, phase 8 rejects the block. The `KeyRotation` cannot be admitted without consensus-level quorum approval of the corresponding `RotateKey`.

Because `ValidatorSetChange::RotateKey` requires quorum signatures, a validator whose signing key has been compromised cannot silently rotate without the current active set's consent. An attacker who compromises one validator's key cannot unilaterally transfer that validator's identity to themselves.

The `active_public_key` resolution (§18.4) updates at `rotation_height`. The `ValidatorSet` record's `validator_id` updates at `effective_height = rotation_height + activation_delay`. Between these two heights, `INV-VALIDATOR-KEY-COHERENCE` is satisfied via a compatibility clause:

> For heights `H` in `[rotation_height, effective_height)`, vote admission (§15.3) accepts signatures under EITHER `old_validator_id` OR `new_validator_id` for the subject validator, provided the signature verifies under `verify_strict`. This transitional acceptance prevents liveness stalls during the activation window. At `effective_height` and beyond, only `new_validator_id` is accepted.

### 18.7 New invariants

**INV-KEY-ROTATION**: For all v3 heights H and all transactions T admitted at height H, `T.signature` verifies against `active_public_key(T.actor.agent_id, H)` under `verify_strict`. Signatures by superseded keys are rejected. `agent_id = BLAKE3(original_public_key || canonical_bytes(mfidel_seal))` remains invariant across all rotations.

**INV-VALIDATOR-KEY-COHERENCE** (duplicated from §15.8 for locality): For all heights H >= effective_height of any RotateKey, and all `r in active_set(H)`, `r.validator_id == active_public_key(r.agent_id, H)`. During the `[rotation_height, effective_height)` transitional window, either key is accepted for vote verification per §18.6.

---

## §19 Version 3 Migration

v0.4.0 introduces `header.version = 3`. v2 chains continue to replay under v2 rules. No forced migration.

### 19.1 v3 genesis requirements

A v3 genesis block MUST satisfy:
1. `header.version == 3`.
2. `body.genesis_validator_set: ValidatorSet` present and non-empty.
3. `body.genesis_consensus_params: ConsensusParams` present. **Required, not optional** — v3 has no implicit defaults; every parameter is explicit on-chain. v3 genesis without this field is rejected.
4. `body.genesis_constitutional_ceilings: ConstitutionalCeilings` present. **Required, not optional.**
5. For every pair `(param, ceiling)` declared in §17.2, `param_value <= ceiling_value`.
6. Every `agent_id` in `body.genesis_validator_set` is registered in the genesis agent registry; registration records populate `system/key_index` (§18.3) with one entry per validator.

Canonical bincode of `body` for v3 includes the new fields in order: `transitions, causal_edges, genesis_mint, genesis_consensus_params, genesis_validator_set, genesis_constitutional_ceilings`.

### 19.2 v3 consensus semantics

v3 chains enforce:
- §15: all validator-set changes occur via signed `ValidatorSetChange` events admitted into blocks. v2 rule (implicit genesis-only set) is rejected.
- §16: round advancement requires `NewRound` messages; `body.round_history` must be present for blocks produced at round > 0.
- §17: constitutional ceilings enforced at phase 10 and at governance submission.
- §18: transaction signatures verify against `active_public_key`; superseded-key signatures rejected; validator key rotations require coupled `ValidatorSetChange::RotateKey`.

### 19.3 v2 chain behavior

v2 chains continue to replay under existing rules. No v2 block is rejected by Patch-04 code. The v2 validator set is implicit (genesis signer list); v2 chains cannot admit `ValidatorSetChange`, `KeyRotation`, `NewRound`, or `EquivocationEvidence` events — parsers reject these in v2 bodies.

### 19.4 Cross-version compatibility

A node MAY participate in both v2 and v3 chains simultaneously. The version is determined per-chain by the genesis header. A v3 node importing a v2 chain uses v2 rules; a v2 node importing a v3 chain rejects at genesis (`header.version == 3` is unknown).

### 19.5 No silent upgrade

There is no in-place upgrade path from v2 to v3 on the same chain. Operators who wish to migrate a v2 chain to v3 semantics must produce a new genesis block that forks state from a v2 snapshot; this is a chain-identity change and is out of scope for Patch-04.

---

## Amended invariants (v0.4.0)

Patch-04 preserves all PROTOCOL.md v1.0 invariants (INV-1 through INV-7, Treasury, Escrow) and adds five new v3-only invariants:

| ID | Statement | Enforcement phase |
|---|---|---|
| INV-VALIDATOR-SET-CONTINUITY | `active_set(H)` derivable from genesis + `ValidatorSetChange` records (§15.8) | Phase 12 |
| INV-VALIDATOR-KEY-COHERENCE | Record-level `validator_id` tracks agent-level `active_public_key` per §18.6 transitional rules (§15.8 / §18.7) | Phase 8 + Phase 12 |
| INV-VIEW-CHANGE-LIVENESS | Round-history evidence present for all round > 0 blocks (§16.7) | Phase 10 |
| INV-CEILING-PRESERVATION | Every ConsensusParams value `<=` its ceiling (§17.9) | Phase 10 |
| INV-KEY-ROTATION | Signatures verify under `active_public_key`; superseded keys rejected (§18.7) | Phase 8 |

---

## Conformance Matrix (Patch-04)

Each normative rule in this document is paired with at least one conformance test, added under the naming scheme `patch_04_*` in the corresponding crate's test suite.

| Rule | Test name | Crate |
|---|---|---|
| §15.1 ValidatorRecord canonical bytes | `patch_04_validator_record_canonical_bytes` | `sccgub-types` |
| §15.2 ValidatorSet canonical ordering (by agent_id) | `patch_04_validator_set_canonical_order_by_agent_id` | `sccgub-types` |
| §15.4 ValidatorSetChange canonical bytes (all variants) | `patch_04_validator_set_change_canonical_bytes` | `sccgub-types` |
| §15.5 Activation delay clamp | `patch_04_activation_delay_clamp` | `sccgub-execution` |
| §15.5 Quorum from current set, not post-change | `patch_04_validator_set_change_quorum_is_current` | `sccgub-execution` |
| §15.5.1 RotateKey predicate (key uniqueness) | `patch_04_rotate_key_rejects_reused_key` | `sccgub-execution` |
| §15.6 Replay determinism over 100+ events | `patch_04_validator_set_replay_determinism` | `sccgub-state` |
| §15.7 Equivocation two-stage slashing | `patch_04_equivocation_two_stage_slashing` | `sccgub-consensus` |
| §15.7 Forgery-only veto admits on valid proof | `patch_04_slashing_veto_accepts_forgery_proof` | `sccgub-governance` |
| §15.7 Forgery-only veto rejects non-forgery grounds | `patch_04_slashing_veto_rejects_non_forgery` | `sccgub-governance` |
| §15.7 No appeal after effective_height | `patch_04_slashing_absolute_post_effective` | `sccgub-governance` |
| §16.2 Leader selection folds prior_block_hash | `patch_04_leader_includes_prior_block_hash` | `sccgub-consensus` |
| §16.2 Leader selection deterministic (replay) | `patch_04_leader_selection_deterministic` | `sccgub-consensus` |
| §16.2 Block 1 uses ZERO_HASH prior | `patch_04_leader_block1_zero_hash_prior` | `sccgub-consensus` |
| §16.3 NewRound canonical bytes | `patch_04_newround_canonical_bytes` | `sccgub-types` |
| §16.4 Round advancement under partition | `patch_04_round_advancement_quorum` | `sccgub-consensus` |
| §16.1 Timeout exponential backoff capped | `patch_04_timeout_backoff_capped` | `sccgub-consensus` |
| §16.6 round_history counts toward max_block_bytes | `patch_04_round_history_counts_toward_block_size` | `sccgub-execution` |
| §17.1 ConstitutionalCeilings canonical bytes | `patch_04_ceilings_canonical_bytes` | `sccgub-types` |
| §17.2 Default ConsensusParams below all ceilings | `patch_04_default_params_below_all_ceilings` | `sccgub-types` |
| §17.4 Phase 10 rejects ceiling-violating block | `patch_04_phase_10_rejects_ceiling_violation` | `sccgub-execution` |
| §17.5 Block-byte ceiling enforced | `patch_04_phase_10_rejects_oversized_block` | `sccgub-execution` |
| §17.6 Active proposal queue bound | `patch_04_proposal_queue_bound` | `sccgub-governance` |
| §17.7 Ceilings write-once at genesis | `patch_04_ceilings_write_once` | `sccgub-state` |
| §17.8 Submission-time governance rejection | `patch_04_governance_rejects_ceiling_raise` | `sccgub-governance` |
| §18.1 KeyRotation canonical bytes | `patch_04_key_rotation_canonical_bytes` | `sccgub-types` |
| §18.2 Both signatures required | `patch_04_key_rotation_requires_both_signatures` | `sccgub-execution` |
| §18.2 rule 7 Global key index rejects reuse | `patch_04_key_index_rejects_reused_key` | `sccgub-state` |
| §18.2 Rotation chain A→B→C | `patch_04_key_rotation_chain` | `sccgub-state` |
| §18.3 KeyIndex replay determinism | `patch_04_key_index_replay_determinism` | `sccgub-state` |
| §18.5 Superseded-key signature rejected | `patch_04_superseded_key_rejected` | `sccgub-execution` |
| §18.6 Validator rotation requires coupled RotateKey | `patch_04_validator_rotation_requires_rotatekey` | `sccgub-execution` |
| §18.6 Transitional window accepts either key | `patch_04_validator_rotation_transitional_window` | `sccgub-consensus` |
| §18.7 Agent identity preserved across rotation | `patch_04_agent_id_preserved` | `sccgub-state` |
| §19.1 v3 genesis requires all four fields | `patch_04_v3_genesis_requires_fields` | `sccgub-state` |
| §19.3 v2 chain rejects v3 events | `patch_04_v2_rejects_v3_events` | `sccgub-execution` |
| Cross-cutting | `patch_04_conformance` (integration) | workspace root |

---

## Canonical Encoding Discipline (Patch-04)

All new Patch-04 structures follow the PROTOCOL.md §1 canonical-bincode rule. Field order is explicitly declared at the point of definition and MUST NOT be reordered without a chain hard fork. In addition:

- No `HashMap` or `HashSet` may be introduced in `sccgub-consensus`, `sccgub-execution`, or `sccgub-state` as part of Patch-04. Existing instances in these crates are audited and replaced with `BTreeMap` / `BTreeSet` during Commit 5.
- All signature verification paths in Patch-04 use `ed25519_dalek::VerifyingKey::verify_strict`. Non-strict `verify()` is deprecated for consensus-critical paths.
- All vector fields that are canonically ordered (validator sets, signature lists, registry entries) declare their ordering at definition and reject duplicates at admission.

---

## Patch-04 does NOT address

For audit clarity, these fractures from the external report are explicitly out of scope for v0.4.0:

- **F5 — T_prior fee-oracle manipulability**: deferred to Patch-05. §9 remains unchanged.
- **F6 — Mfidel-seal grinding**: deferred. §3 remains unchanged.
- **F7 — PII-exclusion in payloads**: deferred; regulatory hardening patch.
- **F8 — Snapshot / fast-sync trust model**: deferred; §13 genesis replay remains the sole trust anchor.
- **Tension signedness**: if `ConsensusParams::max_tension_swing` or internal tension storage uses `u64` while negative swings are semantically valid, this is a type-correctness audit item distinct from Patch-04 ceiling work. Flagged here for the next audit cycle.

---

## Resolved decisions (drafting audit trail)

The following decisions were surfaced during initial drafting and resolved before revision 2. Preserved here for review-cycle traceability; they are not load-bearing for implementation.

1. **Ceiling reconciliation (§17.2)**: adopted `default × profiled-headroom` table. External-audit prose values (`max_proof_depth ≤ 16`, etc.) rejected as below-default and would invalidate v3 genesis.
2. **Leader-selection input (§16.2)**: folded `prior_block_hash` into BLAKE3 input to prevent arbitrary-distance leader-schedule prediction. Block 1 uses `ZERO_HASH` sentinel.
3. **Validator key rotation (§18.6)**: coupled with `ValidatorSetChange::RotateKey` for quorum approval. Split `Rotate` into `RotatePower` (power-only) and `RotateKey` (key-only) to avoid half-update anti-pattern. New `INV-VALIDATOR-KEY-COHERENCE`.
4. **Equivocation slashing (§15.7)**: two-stage with narrow forgery-only veto window during activation delay. No appeal after `effective_height`; no non-forgery grounds.
5. **Activation-delay clamp (§15.5)**: `clamp(k+1, 2, k+8)`. Floor is constitutional, ceiling is defensive.
6. **Global key-index scope (§18.3)**: global, by `public_key`, permanently retained. Per-agent scoping rejected as it would create replay-ambiguity if `agent_id` were ever reassignable.
7. **round_history (§16.6)** counted against `max_block_bytes`. No off-budget data in consensus paths.
8. **v3 genesis (§19.1)**: `genesis_consensus_params` and `genesis_constitutional_ceilings` are both **required**, not optional. v3 has no implicit defaults.
9. **Tension signedness (§17.2 note)**: `i64` for the ceiling type; separate audit item flagged for internal tension representation.
10. **`max_validator_set_size_ceiling`**: 128 (not 256). Tighter constitutional cap; BFT security plateaus before 128, further growth requires hard fork.

---

*End of PATCH_04.md (revision 2).*
