# SCCGUB Protocol Amendment — Patch 04

**Target version:** v0.4.0
**Amends:** PROTOCOL.md v1.0 (FROZEN)
**Amendment status:** DRAFT — pending governance proposal with constitutional timelock (200 blocks).
**Chain version introduced:** `header.version = 3` (v2 replay compatibility preserved).

This document amends PROTOCOL.md. When v0.4.0 is tagged, sections §15–§19 are merged into PROTOCOL.md as PROTOCOL v2.0 and this document is archived. Until then, PROTOCOL.md remains frozen and this draft is the sole source of truth for v3 consensus rules.

Patch-04 closes three structural fractures identified by external audit:
- **F1 — Undefined validator-set mutation** (addressed in §15).
- **F2 — Missing view-change / liveness protocol in two-round BFT** (addressed in §16).
- **F3 — Recursive-governance expansion of `ConsensusParams`** (addressed in §17).
- **F4 — Identity permanently bound to initial key material** (addressed in §18, closes INV-6 aspirational gap).

All Patch-04 rules are consensus-critical. Any conforming v3 implementation MUST produce identical state roots given identical inputs.

---

## §15 Validator Set Management

Before Patch-04, the validator set was implicitly fixed at genesis, with no on-chain rule for membership change. Two honest nodes that disagreed on membership could admit different quorums against the same vote stream. §15 makes validator-set membership a consensus-critical, replay-deterministic function of signed on-chain events.

### 15.1 ValidatorRecord

```
ValidatorRecord := {
    validator_id:   Ed25519PublicKey,    // 32 bytes
    mfidel_seal:    MfidelAtomicSeal,    // from_height(registration_height)
    voting_power:   u64,                  // non-zero for active validators
    active_from:    BlockHeight,          // u64, inclusive
    active_until:   Option<BlockHeight>,  // None = indefinite; Some(h) = last active at h
}
```

Canonical bincode field order: `validator_id, mfidel_seal, voting_power, active_from, active_until`. `Option` encodes as bincode tag byte followed by `BlockHeight` if present.

A validator is **active at height H** iff `active_from <= H && active_until.map_or(true, |u| H <= u) && voting_power > 0`.

### 15.2 ValidatorSet

```
ValidatorSet := Vec<ValidatorRecord>
```

Canonical ordering: **sorted ascending by `validator_id` bytes**. Duplicate `validator_id` values are invalid.

Commitment key: `system/validator_set`. Value: `bincode(ValidatorSet)`.

The active subset at height H is derived from the full record list via 15.1 predicate. Only active records participate in quorum calculation under §6.

### 15.3 Quorum re-definition (amends §6)

```
active_set(H)   = [r for r in ValidatorSet if r is active at H, sorted by validator_id]
total_power(H)  = sum(r.voting_power for r in active_set(H))
quorum_power(H) = floor(2 * total_power(H) / 3) + 1
```

A vote is admitted iff the signing validator is in `active_set(height)`. All six admission checks of §6.4 continue to apply; the membership check is now against `active_set(vote.height)`, not a fixed genesis set.

### 15.4 ValidatorSetChange event

```
ValidatorSetChangeKind :=
    | Add(ValidatorRecord)
    | Remove { validator_id, reason: RemovalReason, effective_height }
    | Rotate { validator_id, new_voting_power, effective_height }

RemovalReason := Voluntary | Equivocation | Inactivity | Governance

ValidatorSetChange := {
    change_id:         BLAKE3Hash,               // BLAKE3(canonical_change_bytes)
    kind:              ValidatorSetChangeKind,
    effective_height:  BlockHeight,
    proposed_at:       BlockHeight,
    quorum_signatures: Vec<(Ed25519PublicKey, Ed25519Signature)>,
}
```

Canonical bincode field order for `ValidatorSetChange`: `change_id, kind, effective_height, proposed_at, quorum_signatures`. `quorum_signatures` is sorted ascending by signer public key bytes; duplicate signers are invalid.

`canonical_change_bytes` (input to `change_id` and to signatures) covers:
```
bincode(kind, effective_height, proposed_at)
```
`quorum_signatures` is excluded from the hash to prevent signature malleability from affecting `change_id`.

### 15.5 Activation rule

A `ValidatorSetChange` is admitted at block height `H_admit` (the block that contains it) iff:

1. `change.effective_height >= H_admit + activation_delay`, where
   `activation_delay = max(confirmation_depth + 1, 2)`. With default `k=2`, `activation_delay = 3`.
2. The signer set of `quorum_signatures` is a subset of `active_set(H_admit)`.
3. The sum of `voting_power` over signers reaches `quorum_power(H_admit)`.
4. Every signature in `quorum_signatures` verifies under `verify_strict` against `canonical_change_bytes`.
5. `change_id` equals `BLAKE3(canonical_change_bytes)`.

Activation is deferred: the change is recorded in state at `H_admit` but the derived `active_set` only reflects the change from `effective_height` onward. Quorum for `ValidatorSetChange` admission always uses `active_set(H_admit)`, never `active_set(effective_height)`. This prevents a post-change majority from self-admitting.

### 15.6 Replay derivation

Validator set replay is deterministic:
```
active_set(H) =
    genesis.validator_set
    ∪ {Add records with effective_height <= H}
    ∖ {validator_ids with any Remove record where effective_height <= H}
    with voting_power overridden by latest Rotate record where effective_height <= H
```
Applied in `effective_height` order; ties broken by `change_id` ascending.

### 15.7 Equivocation slashing (amends §6)

When a validator signs two distinct votes `(block_hash_a, block_hash_b)` for the same `(height, round, vote_type)` with `block_hash_a != block_hash_b`, both signatures constitute equivocation evidence. Any block may include an `EquivocationEvidence` record. Admission of such a record emits a synthetic `ValidatorSetChange` with kind `Remove { reason: Equivocation, effective_height: H_admit + activation_delay }`. Slashing is mandatory and requires no governance proposal.

`EquivocationEvidence := (vote_a: Vote, vote_b: Vote)` with canonical bincode field order `vote_a, vote_b`.

### 15.8 New invariant

**INV-VALIDATOR-SET-CONTINUITY**: For all heights H > 0, `active_set(H)` is derivable solely from `genesis.validator_set` and all `ValidatorSetChange` records in blocks `[1..=H]`. No implicit, time-based, or off-chain modification is permitted.

---

## §16 View-Change Protocol

§6 specified prevote/precommit admission but not round advancement. A silent leader halted liveness indefinitely. §16 specifies round timeouts, leader selection, and the message that advances the round.

### 16.1 Round timeout

```
T_round(r) = min(base_timeout_ms * 2^r, max_timeout_ms)
```
where `r` is the zero-indexed round number. `base_timeout_ms` and `max_timeout_ms` are fields in `ConsensusParams` (see §17.2); ceilings in §17.3.

### 16.2 Leader selection

```
leader(height, round) = active_set(height)[BLAKE3(height_bytes || round_bytes) mod |active_set(height)|]
```
where `height_bytes = height.to_le_bytes()` (8 bytes), `round_bytes = round.to_le_bytes()` (4 bytes, u32). `active_set(height)` is the §15.3 canonically-sorted vector. BLAKE3 output is interpreted as a big-endian u256 prior to the modulo. The modulo is defined over `u256 mod n` with `n = |active_set(height)|`.

Leader selection is independent of vote history; this is intentional for simplicity. Future patches may replace it with a VRF.

### 16.3 NewRound message

```
NewRound := {
    height:            BlockHeight,
    round:             u32,
    last_prevote:      Option<BlockHash>,   // last prevote this validator cast at `height`
    signer:            Ed25519PublicKey,
    signature:         Ed25519Signature,
}
```

Canonical bincode field order: `height, round, last_prevote, signer, signature`.

`canonical_newround_bytes` (input to signature) covers: `bincode(height, round, last_prevote, signer)`.

### 16.4 Round advancement

A validator advances from round `r` to round `r+1` at height `h` iff:
1. It has received `NewRound` messages from a subset of `active_set(h)` whose voting-power sum reaches `quorum_power(h)`, AND
2. All referenced `NewRound` messages have `height == h && round == r+1` (validators signal the round they wish to enter), AND
3. Each signature verifies under `verify_strict` against `canonical_newround_bytes`, AND
4. Each signer is in `active_set(h)`.

`NewRound` messages are not votes; they do not affect prevote or precommit tallies of round `r`. They are purely a view-change signal.

### 16.5 Timeout behavior

A validator waits at most `T_round(r)` for prevote quorum at round `r`. On expiry with no prevote quorum, it broadcasts `NewRound(h, r+1, last_prevote)`. The same applies at the precommit phase. The wall-clock reading is local and non-consensus; consensus outcomes depend only on received messages, not on local clocks.

### 16.6 Catch-up

A node that receives a block with `round > 0` in its commit certificate MUST retain the prevote and precommit evidence for all rounds `[0..round]` referenced by the certificate. Evidence is kept alongside the block in a new section `body.round_history: Vec<RoundRecord>`; the block ID commits to `BLAKE3(canonical_bytes(round_history))` via a new header field `round_history_root`. An empty history encodes as `ZERO_HASH`, not as the Merkle root of an empty vector, consistent with §5.

### 16.7 New invariant

**INV-VIEW-CHANGE-LIVENESS**: For every admitted block B at round r > 0, `body.round_history` contains valid `RoundRecord` entries for rounds `[0..r]`, each containing the NewRound messages that justified advancement.

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

These are the v3 genesis defaults. Any v3 genesis that omits `body.genesis_constitutional_ceilings` uses them; any v3 genesis that supplies the field MUST satisfy `param <= ceiling` for every pair in §17.4.

| Ceiling field | v3 default | Companion ConsensusParams field | Current (v0.3.0) default |
|---|---|---|---|
| `max_proof_depth_ceiling` | 512 | `max_proof_depth` | 256 |
| `max_tx_gas_ceiling` | 10_000_000 | `default_tx_gas_limit` | 1_000_000 |
| `max_block_gas_ceiling` | 500_000_000 | `default_block_gas_limit` | 50_000_000 |
| `max_contract_steps_ceiling` | 1_048_576 | `default_max_steps` | 10_000 |
| `max_address_length_ceiling` | 4096 | `max_symbol_address_len` | 4096 |
| `max_state_entry_size_ceiling` | 1_048_576 | `max_state_entry_size` | 1_048_576 |
| `max_tension_swing_ceiling` | 4_294_967_296 | `max_tension_swing` | 2_000_000 |
| `max_block_bytes_ceiling` | 4_194_304 | *(new in §17.5)* | — |
| `max_active_proposals_ceiling` | 256 | *(new in §17.6)* | — |
| `max_view_change_base_timeout_ms` | 60_000 | *(new in §16.1)* | — |
| `max_view_change_max_timeout_ms` | 3_600_000 | *(new in §16.1)* | — |
| `max_validator_set_size_ceiling` | 256 | *(new)* | — |
| `max_validator_set_changes_per_block` | 8 | *(new)* | — |

> **Note on ceiling reconciliation:** external audit prose suggested tighter ceilings (e.g. `max_proof_depth <= 16`, `max_address_length <= 64`). Those values are rejected because they are below current v0.3.0 defaults; adopting them verbatim would render the default `ConsensusParams` invalid at v3 genesis. The values above preserve default validity with explicit headroom. See OPEN QUESTIONS section at the end of this document.

### 17.3 ConsensusParams additions (v3)

Three new fields are appended to `ConsensusParams` in v3:
- `view_change_base_timeout_ms: u32` — default 1_000, must be `<= max_view_change_base_timeout_ms`.
- `view_change_max_timeout_ms: u32` — default 60_000, must be `<= max_view_change_max_timeout_ms && >= view_change_base_timeout_ms`.
- `max_block_bytes: u32` — default 2_097_152 (2 MiB), must be `<= max_block_bytes_ceiling`.
- `max_active_proposals: u32` — default 128, must be `<= max_active_proposals_ceiling`.

These fields are present only when `header.version >= 3`. v2 chains continue to deserialize the v2 `ConsensusParams` schema via the existing `LegacyConsensusParamsV1` fallback mechanism. A new `LegacyConsensusParamsV2` fallback is added for v2 → v3 migration.

### 17.4 Validation rule

A v3 block is **ceiling-valid** iff, for the active `ConsensusParams` at its height, every declared pair in §17.2 satisfies `param_value <= ceiling_value`. Phase 10 (Architecture) is extended with this check. Any mismatch rejects the block.

### 17.5 Block size bound (Phase 10)

Phase 10 additionally rejects any block whose `bincode(block)` length exceeds the active `ConsensusParams.max_block_bytes`. Enforcement is on canonical-encoded bytes, not on in-memory size.

### 17.6 Active proposal queue bound (Governance)

At most `ConsensusParams.max_active_proposals` governance proposals may be in states `Submitted | Voting | Timelocked` at any time. A proposal submission that would exceed the bound is rejected at mempool admission with `ProposalQueueFull`.

### 17.7 Storage

Commitment key: `system/constitutional_ceilings`. Value: `bincode(ConstitutionalCeilings)`. Written **exactly once** at genesis for v3 chains. Any subsequent write attempt (via any transition kind or governance proposal) is rejected as a phase-6 (Organization) violation.

### 17.8 Governance rejection rule

A governance proposal whose payload would modify any field in `ConstitutionalCeilings`, or whose modification of `ConsensusParams` would cause any pair in §17.2 to exceed its ceiling, is **rejected at submission** (not at timelock expiry). The rejection is a phase-6 (Organization) violation. Submission-time rejection is mandatory because timelock-expiry rejection would let the proposal occupy a queue slot for 200 blocks while being known-invalid.

### 17.9 New invariant

**INV-CEILING-PRESERVATION**: For all v3 heights H, every pair `(param, ceiling)` in §17.2 satisfies `state.consensus_params.param_at(H) <= state.constitutional_ceilings.ceiling` where both values are read from the canonical state at H.

---

## §18 Identity Preservation

§3 defines `agent_id = BLAKE3(public_key || canonical_bytes(mfidel_seal))`. If an agent's private key is compromised, the attacker controls the agent_id permanently; there is no on-chain remediation. §18 introduces a signed key-rotation event that preserves agent_id while replacing the signing key material.

### 18.1 KeyRotation event

```
KeyRotation := {
    agent_id:               AgentId,            // BLAKE3 hash, 32 bytes
    old_public_key:         Ed25519PublicKey,
    new_public_key:         Ed25519PublicKey,
    rotation_height:        BlockHeight,
    signature_by_old_key:   Ed25519Signature,
    signature_by_new_key:   Ed25519Signature,
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
3. `old_public_key` is the **currently active** public key for `agent_id` (see §18.4 resolution function).
4. `new_public_key != old_public_key`.
5. `signature_by_old_key` verifies under `verify_strict` against `canonical_rotation_bytes`.
6. `signature_by_new_key` verifies under `verify_strict` against `canonical_rotation_bytes`. This prevents new-key binding by a compromised old key without the new-key holder's consent.
7. `new_public_key` has not been used as an active key for any other `agent_id`. (Prevents impersonation by reusing another agent's key.)

### 18.3 KeyRotationRegistry

```
KeyRotationRegistry := Vec<KeyRotation>
```

Canonical ordering: sorted ascending by `(agent_id, rotation_height)`. Ties are impossible because §18.4 forbids multiple rotations at the same height for the same agent_id.

Commitment key: `system/key_rotations`. Value: `bincode(KeyRotationRegistry)`. Append-only: records are never removed or modified; new records extend the vector while preserving canonical ordering.

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

`original_public_key` is the public key supplied at registration, retained in the agent record. This is distinct from `active_public_key` and is never overwritten; `agent_id` identity is permanently anchored to `original_public_key`.

### 18.5 Phase 8 enforcement

Phase 8 (Execution) signature verification uses `active_public_key(tx.actor.agent_id, block.height)`. A transaction signed by a superseded key is rejected as an Execution-phase failure, not as a signature-absence failure, so that equivocation detectors can distinguish "wrong key" from "unsigned".

### 18.6 Validator key rotation

When a validator rotates its key, the `active_public_key` change applies to validator operations as well. The validator set (§15) records `validator_id` fields that refer to the **original** Ed25519 public key for binding continuity; vote signatures are verified against `active_public_key(agent_id_of(validator_id), height)`. A `ValidatorSetChange::Rotate` event is NOT required for key rotation — only for voting-power changes. Key rotation is an agent-level primitive; voting power is a set-level primitive.

### 18.7 New invariant

**INV-KEY-ROTATION**: For all v3 heights H and all transactions T admitted at height H, `T.signature` verifies against `active_public_key(T.actor.agent_id, H)` under `verify_strict`. Signatures by superseded keys are rejected. `agent_id = BLAKE3(original_public_key || canonical_bytes(mfidel_seal))` remains invariant across all rotations.

---

## §19 Version 3 Migration

v0.4.0 introduces `header.version = 3`. v2 chains continue to replay under v2 rules. No forced migration.

### 19.1 v3 genesis requirements

A v3 genesis block MUST satisfy:
1. `header.version == 3`.
2. `body.genesis_validator_set: ValidatorSet` present and non-empty.
3. `body.genesis_consensus_params: ConsensusParams` present (the field was optional in v2; v3 requires it).
4. `body.genesis_constitutional_ceilings: ConstitutionalCeilings` present.
5. For every pair `(param, ceiling)` declared in §17.2, `param_value <= ceiling_value`.

Canonical bincode of `body` for v3 includes the new fields in order: `transitions, causal_edges, genesis_mint, genesis_consensus_params, genesis_validator_set, genesis_constitutional_ceilings`.

### 19.2 v3 consensus semantics

v3 chains enforce:
- §15: all validator-set changes occur via signed `ValidatorSetChange` events admitted into blocks. v2 rule (implicit genesis-only set) is rejected.
- §16: round advancement requires `NewRound` messages; `body.round_history` must be present for blocks produced at round > 0.
- §17: constitutional ceilings are enforced at phase 10 and at governance submission.
- §18: transaction signatures verify against `active_public_key`; superseded-key signatures are rejected.

### 19.3 v2 chain behavior

v2 chains continue to replay under existing rules. No v2 block is rejected by Patch-04 code. The v2 validator set is implicit (genesis signer list); v2 chains cannot admit `ValidatorSetChange`, `KeyRotation`, or `NewRound` events — parsers reject these in v2 bodies.

### 19.4 Cross-version compatibility

A node MAY participate in both v2 and v3 chains simultaneously. The version is determined per-chain by the genesis header. A v3 node importing a v2 chain uses v2 rules; a v2 node importing a v3 chain rejects at genesis (`header.version == 3` is unknown).

### 19.5 No silent upgrade

There is no in-place upgrade path from v2 to v3 on the same chain. Operators who wish to migrate a v2 chain to v3 semantics must produce a new genesis block that forks state from a v2 snapshot; this is a chain-identity change and is out of scope for Patch-04.

---

## Amended invariants (v0.4.0)

Patch-04 preserves all PROTOCOL.md v1.0 invariants (INV-1 through INV-7, Treasury, Escrow) and adds four new v3-only invariants:

| ID | Statement | Enforcement phase |
|---|---|---|
| INV-VALIDATOR-SET-CONTINUITY | `active_set(H)` is derivable from genesis + `ValidatorSetChange` records (§15.8) | Phase 12 |
| INV-VIEW-CHANGE-LIVENESS | Round-history evidence present for all round > 0 blocks (§16.7) | Phase 10 |
| INV-CEILING-PRESERVATION | Every ConsensusParams value `<=` its ceiling (§17.9) | Phase 10 |
| INV-KEY-ROTATION | Signatures verify under `active_public_key`; superseded keys rejected (§18.7) | Phase 8 |

---

## Conformance Matrix (Patch-04)

Each normative rule in this document is paired with at least one conformance test, added under the naming scheme `patch_04_*` in the corresponding crate's test suite. The mapping is:

| Rule | Test name | Crate |
|---|---|---|
| §15.2 ValidatorSet canonical ordering | `patch_04_validator_set_canonical_order` | `sccgub-types` |
| §15.4 ValidatorSetChange canonical bytes | `patch_04_validator_set_change_canonical_bytes` | `sccgub-types` |
| §15.5 Activation delay enforcement | `patch_04_validator_set_change_activation_delay` | `sccgub-execution` |
| §15.5 Quorum from current set, not post-change | `patch_04_validator_set_change_quorum_is_current` | `sccgub-execution` |
| §15.6 Replay determinism over 100+ events | `patch_04_validator_set_replay_determinism` | `sccgub-state` |
| §15.7 Equivocation auto-slashing | `patch_04_equivocation_triggers_remove` | `sccgub-consensus` |
| §16.2 Leader selection determinism | `patch_04_leader_selection_deterministic` | `sccgub-consensus` |
| §16.3 NewRound canonical bytes | `patch_04_newround_canonical_bytes` | `sccgub-types` |
| §16.4 Round advancement under partition | `patch_04_round_advancement_quorum` | `sccgub-consensus` |
| §16.1 Timeout exponential backoff capped | `patch_04_timeout_backoff_capped` | `sccgub-consensus` |
| §17.1 ConstitutionalCeilings canonical bytes | `patch_04_ceilings_canonical_bytes` | `sccgub-types` |
| §17.4 Phase 10 rejects ceiling-violating block | `patch_04_phase_10_rejects_ceiling_violation` | `sccgub-execution` |
| §17.5 Block-byte ceiling enforced | `patch_04_phase_10_rejects_oversized_block` | `sccgub-execution` |
| §17.6 Active proposal queue bound | `patch_04_proposal_queue_bound` | `sccgub-governance` |
| §17.7 Ceilings write-once at genesis | `patch_04_ceilings_write_once` | `sccgub-state` |
| §17.8 Submission-time governance rejection | `patch_04_governance_rejects_ceiling_raise` | `sccgub-governance` |
| §18.1 KeyRotation canonical bytes | `patch_04_key_rotation_canonical_bytes` | `sccgub-types` |
| §18.2 Both signatures required | `patch_04_key_rotation_requires_both_signatures` | `sccgub-execution` |
| §18.2 Rotation chain A→B→C | `patch_04_key_rotation_chain` | `sccgub-state` |
| §18.2 Double-rotation at same height rejected | `patch_04_key_rotation_double_rejected` | `sccgub-execution` |
| §18.5 Superseded-key signature rejected | `patch_04_superseded_key_rejected` | `sccgub-execution` |
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

---

## OPEN QUESTIONS — for review before Commit 2

These decisions require user confirmation before the types layer is written. Each affects canonical encoding or enforcement semantics and is therefore consensus-critical.

1. **Ceiling values in §17.2 diverge from the audit prose.** Audit suggested `max_proof_depth <= 16`, `max_address_length <= 64`, `max_state_entry_size <= 2^16`. These are below current v0.3.0 defaults and would invalidate v3 genesis at birth. The draft reconciles by setting ceilings at current default × headroom. Confirm the reconciled values (§17.2 table) or supply alternatives.

2. **`max_tension_swing_ceiling = 2^32`** uses `i64` for type compatibility with existing `max_tension_swing: i64`. The field is nominally signed, though tension swings are non-negative in practice. Keep `i64`, or change the ceiling to `u64`? (Changing type breaks canonical bincode of existing `ConsensusParams`.)

3. **`activation_delay = max(confirmation_depth + 1, 2)`** in §15.5 is derived from `k=2` default. If `confirmation_depth` is raised by governance, `activation_delay` rises with it. Is this the intended coupling, or should `activation_delay` be independent (e.g., constant 3 blocks regardless of `k`)?

4. **Leader-selection hash input in §16.2** uses `height_bytes || round_bytes` with no prior-block hash. This means leader schedule is predictable arbitrarily far in advance, enabling targeted DoS against the next leader. Acceptable for v3, or fold `prior_block_hash` into the leader hash? (Folding changes canonical semantics.)

5. **§18.6 validator key rotation** decouples `agent_id`-level key rotation from `validator_id`-level set changes. An attacker who compromises a validator's key can rotate it via §18 without notifying other validators via §15. Is this the intended threat model (key compromise is an agent-level concern, not a set-level event), or should validator key rotation require an accompanying §15 event for transparency?

6. **`KeyRotation` reuse prevention (§18.2 rule 7)** requires a global index of public keys in use. This is O(#agents) state lookup per rotation. Acceptable, or restrict to "key not used in last N blocks" to bound the check?

7. **`body.round_history` in §16.6** adds variable-size data to blocks. Is this size counted against `max_block_bytes` (§17.3)? The draft assumes yes; confirm.

8. **v3 genesis §19.1 requires `genesis_consensus_params`** which was optional in v2. This means a v3 genesis cannot reuse a v2 genesis file without modification. Acceptable, or keep it optional with defaults?

9. **Equivocation evidence §15.7** auto-slashes via synthetic `ValidatorSetChange::Remove`. Should there be a governance-level appeal path (false positives: network re-transmission bugs producing phantom "equivocation"), or is auto-slashing absolute?

10. **`max_validator_set_size_ceiling = 256`** is generous. At 256 validators with two-round BFT and `NewRound` messages per round per validator, vote volume per block is 3 × 256 = 768 messages on the happy path, more under partition. Confirm the ceiling, or tighten to 128?

Please reply with answers (or "accept draft values") before I proceed to Commit 2 (types layer). If you want any section rewritten, say which.

---

*End of PATCH_04.md draft.*
