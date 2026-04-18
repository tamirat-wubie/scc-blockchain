# SCCGUB Protocol Specification v2.0

**Status: FROZEN** — Changes require a governance proposal with constitutional timelock (200 blocks).

This document defines the consensus-critical rules. Any conforming implementation must produce identical state roots given identical inputs.

**Canonical spec layout:**
- §1–§14 of this document — v1/v2/v3/v4 common rules (canonical encoding, cryptography, identity, transactions, blocks, consensus, finality, state, fees, Φ traversal, CPoG, governance, replay, conservation laws).
- [PATCH_04.md](PATCH_04.md) §15–§19 — **v3 additions:** validator-set management, view-change protocol, constitutional ceilings, identity-preserving key rotation, v3 migration.
- [PATCH_05.md](PATCH_05.md) §20–§29 — **v4 additions:** fee oracle hardening, Mfidel seal VRF, evidence-sourced slashing admission, dynamic `confirmation_depth`, typed `ModifyConsensusParam`, `verify_strict` migration, admitted-history projection, v4 migration, expanded ceilings.

Chain version selects which rule set applies: v1/v2 use only §1–§14; v3 adds §15–§19; v4 adds §20–§29. All versions continue to replay under their admission-time rules (§19.3 / §28.3 no-silent-upgrade discipline).

---

## 1. Canonical Encoding

All consensus-critical data is serialized using **bincode** (little-endian, variable-length integers). This is the ONLY encoding used for:
- Transaction signing (canonical_tx_bytes)
- Block ID computation
- Merkle tree leaf hashing
- State root computation
- Vote signing
- Receipt hashing

JSON is used only at the API boundary. It is NEVER used in consensus paths.

## 2. Cryptographic Primitives

| Primitive | Algorithm | Library |
|-----------|-----------|---------|
| Hashing | BLAKE3 (32 bytes) | `blake3` |
| Signatures | Ed25519 | `ed25519-dalek` |
| Merkle trees | Domain-separated BLAKE3 (leaf tag `0x00`, internal tag `0x01`) |
| Key derivation | BLAKE3 iterated KDF (100K rounds) |
| Arithmetic | Fixed-point i128, 18 decimal places (SCALE = 10^18) |

**No floating-point arithmetic in any consensus path.**

## 3. Identity

```
agent_id = BLAKE3(public_key || canonical_bytes(mfidel_seal))
```

The Mfidel seal is deterministic: `seal = MfidelAtomicSeal::from_height(registration_height)`, mapping to a position in the 34x8 Ge'ez matrix.

## 4. Transaction Format

A `SymbolicTransition` contains:
- `tx_id`: BLAKE3 hash of canonical_tx_bytes
- `actor`: AgentIdentity (agent_id, public_key, mfidel_seal, governance_level)
- `intent`: (kind, target, declared_purpose)
- `payload`: Write | AssetTransfer | InvokeContract | Noop
- `wh_binding_intent`: 7-dimensional causal binding (who, what, when, where, why, how, which)
- `nonce`: u128, strictly sequential per agent (must be exactly last + 1, starting at 1)
- `signature`: Ed25519 over canonical_tx_bytes

### canonical_tx_bytes coverage:
```
bincode(agent_id, intent.kind, intent.target, nonce,
        BLAKE3(payload), BLAKE3(preconditions), BLAKE3(postconditions),
        BLAKE3(wh_binding_intent), BLAKE3(causal_chain))
```

## 5. Block Format

A `Block` contains: header, body, receipts, causal_delta, proof, governance.

### Block ID:
```
header.block_id = ZERO_HASH  (placeholder)
block_id = BLAKE3(bincode(header))
```
The block ID commits to all header fields including state_root, transition_root, receipt_root.

### Merkle Roots:
- `transition_root`: Merkle tree over `[tx.tx_id for tx in transitions]`
- `receipt_root`: Merkle tree over `[bincode(receipt) for receipt in receipts]`
- `causal_root`: Merkle tree over `[bincode(edge) for edge in causal_edges]`
- Empty sections use `ZERO_HASH` (not the Merkle root of an empty list)

### Block version and validator identity

- `header.validator_id` is the Ed25519 public key used to verify the producer signature.
- `header.version` is consensus-critical and fixed by genesis for the life of the chain.
- Supported versions:
  - `1`: legacy replay mode. Genesis mint and validator rewards are committed to the signer public-key account (`validator_id`) directly.
  - `2`: canonical replay mode. `validator_id` remains the block-signing public key, but validator-controlled liquidity is committed to the canonical agent account:

```
validator_spend_account(version, validator_public_key) =
  if version == 1:
    validator_public_key
  else:
    BLAKE3(validator_public_key || canonical_bytes(MfidelAtomicSeal::from_height(0)))
```

- New chains default to version `2`.
- Any non-genesis block whose `header.version` differs from the genesis version is invalid.
- Genesis may embed canonical `ConsensusParams` bytes in `body.genesis_consensus_params`.
  When present, import/replay MUST deserialize those bytes, commit them under
  `system/consensus_params`, and use those values for consensus-critical bounds,
  including proof depth, SCCE propagation limits, contract default step limits,
  gas pricing, gas limits, address length, and state-entry size caps.
  Legacy genesis blocks without the field replay with the v0.3.0 default parameter set.

## 6. Consensus: Two-Round BFT

### Quorum:
```
quorum = floor(2n/3) + 1
```
where `n` = number of validators in the authorized set.

### Rounds:
1. **Prevote**: Validators sign `(block_hash, height, round, PREVOTE)` and broadcast.
2. **Precommit**: After prevote quorum, validators sign `(block_hash, height, round, PRECOMMIT)`.
3. **Commit**: Both prevote and precommit quorum reached -> block finalized.

### Vote admission (ALL checks mandatory):
1. Validator must be in the authorized set (membership check).
2. Height and round must match the current consensus round.
3. Vote type must match the expected phase.
4. No duplicate votes from the same validator in the same round.
5. Ed25519 signature must verify against the validator's registered public key.
6. Empty signatures are rejected.

### Byzantine tolerance:
```
max_byzantine = floor((n-1) / 3)
```

## 7. Finality

A block is **final** when:
1. It has achieved two-round consensus (prevote + precommit quorum), AND
2. `k` subsequent blocks have been appended above it.

Default: `k = 2` (confirmation_depth).

### Settlement classes:
| Class | Depth | Use case |
|-------|-------|----------|
| Soft | 0 | Notifications, low-value |
| Economic | 2 | Payments, transfers |
| Legal | 6 | Regulated finance, compliance |

Finality is monotonic: `finalized_height` never decreases.

## 8. State

State is an in-memory key-value trie. The state root is computed as BLAKE3 over sorted `(key, value)` pairs with dirty-flag caching.

### Balance commitment:
All balances are written to the state trie as:
```
key = "balance/" + hex(agent_id)
value = balance.raw().to_le_bytes()  (16 bytes, i128 little-endian)
```
This ensures the state_root commits to both symbolic state and economic state.

For validator-controlled balances, the credited account is version-dependent:
- Genesis mint -> `validator_spend_account(genesis.header.version, genesis.header.validator_id)`
- Block reward -> `validator_spend_account(block.header.version, block.header.validator_id)`

## 9. Fee Model

```
gas_price = base_fee * (1 + alpha * T_prior / T_budget)
tx_fee = gas_used * gas_price
```

Where `T_prior` is the PRIOR block's tension (not the current block, to avoid circularity).

### Gas costs (genesis-bound default parameter values):
| Operation | Gas |
|-----------|-----|
| TX base overhead | 1,000 |
| Compute step | 10 |
| State read | 100 |
| State write | 500 |
| Signature verify | 3,000 |
| Hash operation | 50 |
| Proof byte | 5 |
| Payload byte | 2 |

These values are the default `ConsensusParams` schedule. Conforming nodes MUST
read the active gas schedule from `system/consensus_params`, not from local
compile-time constants.

Default per-transaction limit: 1,000,000 gas. Default per-block limit: 50,000,000 gas.

Fee payer resolution is consensus-critical:

```
fee_payer(version, tx, balances, tx_fee) =
  if tx_fee <= 0:
    tx.actor.agent_id
  else if balances[tx.actor.agent_id] >= tx_fee:
    tx.actor.agent_id
  else if version == 1 and balances[tx.actor.public_key] >= tx_fee:
    tx.actor.public_key
  else:
    REJECT
```

Fees flow to Treasury. Block reward (10 tokens) distributed from Treasury to `validator_spend_account(block.header.version, block.header.validator_id)`.

## 10. Validation: 13-Phase Phi Traversal

Every block passes all 13 phases. Failure at any phase rejects the block.

| # | Phase | Checks |
|---|-------|--------|
| 1 | Distinction | WHBinding completeness |
| 2 | Constraint | SCCE validation |
| 3 | Ontology | Target type validity |
| 4 | Topology | Causal graph acyclicity (block-only) |
| 5 | Form | Payload structure, address length |
| 6 | Organization | Governance invariant preservation |
| 7 | Module | Receipt-transition count consistency |
| 8 | Execution | Transition count, signature presence |
| 9 | Body | Tension budget (block-only) |
| 10 | Architecture | Block version, validator_id, signed txs |
| 11 | Performance | Mfidel seal correctness |
| 12 | Feedback | Tension stability, receipt verdict consistency |
| 13 | Evolution | Proof height, causal edge integrity |

## 11. CPoG Validation (11 checks)

1. Parent linkage (genesis parent = ZERO_HASH)
2. Mfidel seal matches `from_height(block.height)`
3. Proof recursion depth <= `state.consensus_params.max_proof_depth`
4. Tension within budget
5. Transition root Merkle verification
6. Transition count matches body
7. Receipt root Merkle verification
8. Governance hash verification
9. Causal root Merkle verification
10. State root via speculative replay
11. Full Phi traversal

## 12. Governance

### Precedence hierarchy (lower number = higher authority):
0. Genesis, 1. Safety, 2. Meaning, 3. Emotion, 4. Optimization

### Proposal lifecycle:
Submitted -> Voting -> Timelocked -> Activated

### Timelocks:
- Ordinary proposals (norms): 50 blocks
- Constitutional proposals (Safety-level): 200 blocks

## 13. Replay Rule

Any conforming node MUST produce identical state roots when replaying blocks from genesis. The replay function is:

```
genesis = chain[0]
chain_version = genesis.header.version
params =
  if genesis.body.genesis_consensus_params exists:
    decode_consensus_params(genesis.body.genesis_consensus_params)
  else:
    ConsensusParams::default()
state.consensus_params = params
state["system/consensus_params"] = canonical_bytes(params)
apply_genesis_mint(
    state,
    balances,
    validator_spend_account(chain_version, genesis.header.validator_id)
)
state.set_height(0)

for each block in chain[1..]:
    reject if block.header.version != chain_version
    # Atomically validate nonces BEFORE any state/balance mutation.
    # On failure, agent_nonces is rolled back to its pre-block snapshot.
    state.validate_nonces(block.body.transitions)
    gas_price = effective_fee(T_prior, T_budget)
    apply_block_economics(
        state,
        balances,
        treasury,
        block.body.transitions,
        block.receipts,
        block.header.version,
        block.header.validator_id,
        gas_price,
        block_reward
    )
    apply_block_transitions(state, balances, block.body.transitions)
    state.set_height(block.header.height)
```

The imported `params` are also the source of truth for:
- SCCE propagation depth and step budgets
- SCCE activated-symbol, scan, and constraint caps
- Contract default step bound
- Contract invoke argument-size bound
- Per-tx and per-block gas limits
- Gas cost schedule
- Address-length and state-entry size caps

## 14. Conservation Laws

These invariants MUST hold at every block height:

- **INV-1**: `total_supply` is constant except at genesis mint.
- **INV-2**: Per-agent nonces are strictly sequential (nonce == last + 1, no gaps).
- **INV-3**: `state_root` matches the computed trie root.
- **INV-5**: `tension_after <= tension_before + budget`.
- **INV-6**: Every accepted transition has exactly one receipt with Accept verdict.
- **INV-7**: Causal graph contains no cycles.
- **Treasury**: `collected = distributed + burned + pending`.
- **Escrow**: `total_supply = balances + escrow_locked`.
