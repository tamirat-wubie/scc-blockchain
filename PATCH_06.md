# PATCH_06 — Layer 2 hardening: auth, fee floor, fork-choice, pruning, live-upgrade

**Chain version introduced:** v5
**Supersedes:** PATCH_05 §20–§29 is retained and unchanged; PATCH_06 adds §30–§35.
**Scope:** Close the five highest-ranked fractures identified in the v0.5.0
adversarial audit (H.1–H.5). One new CRITICAL fix (H.3), one economic fix
(H.4), one determinism declaration (H.5), one scaling remediation (H.1), and
one operational contract (H.2).

## Motivation

Patch-04 and Patch-05 closed the Layer 1 structural fractures (F1–F6). The
subsequent adversarial audit surfaced a new tier of fractures concentrated in
Layer 2 (adversarial robustness) and Layer 4 (operational hardening). In
priority order:

| Fracture | Layer | Status before Patch-06 | Severity |
|---|---|---|---|
| H.1 State growth unbounded | L4 | No pruning rule exists | HIGH (scaling) |
| H.2 No live-upgrade protocol | L4 | Only cold-start activation | HIGH (ops) |
| H.3 Forgery-proof authorization absent | L2 | `check_forgery_proof` accepts any caller | **CRITICAL** |
| H.4 Fee floor absent | L2 | Fee can collapse to near-zero on low tension | HIGH |
| H.5 Fork-choice under partition undeclared | L2 | No explicit rule | HIGH |

All five are addressed by this patch. Items still open after Patch-06 are
enumerated in §36.

---

## §30 Forgery-proof authorization (H.3)

### §30.1 Problem

`sccgub-consensus::equivocation::check_forgery_proof` performs a pure
cryptographic check that two distinct signatures on the same canonical bytes
both pass non-strict `verify` but at least one fails `verify_strict`. The
function's signature documents the veto semantics, but nothing in the
execution layer constrains **who** may submit such a proof. Consequence:
any party (including a malicious node outside the validator set) can submit
a crafted proof that passes the check and vetoes a synthetic Remove during
its activation-delay window, unblocking an equivocating validator.

### §30.2 Authorization rule

A `ForgeryVeto` message is a typed envelope carrying a `ForgeryProof`
together with an attestation that the submitter is authorized:

```rust
pub struct ForgeryVeto {
    pub proof: OwnedForgeryProof,          // the §15.7 Stage 2 proof
    pub target_change_id: ChangeId,        // the synthetic Remove being vetoed
    pub submitted_at_height: u64,          // must be in [H_admit, H_admit + activation_delay)
    pub attestations: Vec<VetoAttestation>,// §30.3 — signed by authorized set
}

pub struct VetoAttestation {
    pub signer: Ed25519PublicKey,          // must be in active_set(submitted_at_height)
    pub signature: Ed25519Signature,       // verify_strict(signer, canonical_veto_bytes, signature)
}
```

A `ForgeryVeto` is **admitted** iff all the following hold:

1. `submitted_at_height ∈ [H_admit, H_admit + activation_delay)` where
   `H_admit` and `activation_delay` come from the synthetic Remove being
   vetoed. Late vetoes are rejected.
2. The referenced synthetic Remove exists in the admitted history with
   `reason = Equivocation`.
3. `check_forgery_proof(&proof)` returns `Ok(())`.
4. Every attestation's `signer` is a distinct member of
   `active_set(submitted_at_height)`.
5. The aggregate voting power of attestors is `≥ (1/3) × total_voting_power`.
   The one-third-plus-one threshold is sufficient because a forgery proof is
   a fact about cryptography, not a policy decision — a minority of honest
   validators is enough to surface a genuine malleability.

Rule 5's one-third threshold is a deliberate asymmetry versus §15.5's
two-thirds quorum for proposer-sourced changes. The justification: §30 is a
**safety valve**, not a governance decision. A higher threshold would enable
a malicious majority to suppress legitimate forgery vetoes; a lower
threshold (single signer) recreates the unauthorized-submission problem. A
super-minority threshold is the standard slashing-safety-valve pattern.

### §30.3 Canonical veto bytes

```rust
canonical_veto_bytes(height, round, target_change_id, proof_canonical_bytes,
                     proof_public_key, proof_signature_a, proof_signature_b)
```

Attestation signatures cover `canonical_veto_bytes(...)` with the domain
separator `b"sccgub-forgery-veto-v5"` prepended.

### §30.4 Effect of admitted veto

An admitted `ForgeryVeto` marks the target synthetic Remove as `Vetoed`.
A Vetoed change:

- Does NOT transition the validator's `active_until` field.
- IS retained in `system/validator_set_change_history` with a `veto_record`
  annotation pointing at the veto's admission height.
- Does NOT consume a `max_validator_set_changes_per_block` slot on the
  activation height it would otherwise have occupied.

### §30.5 Invariant

**INV-FORGERY-VETO-AUTHORIZED** — a synthetic Remove can only be vetoed by
an admitted `ForgeryVeto` carrying (a) cryptographic malleability evidence
and (b) ≥⅓ validator-set voting power of attestation. All other veto paths
are rejected.

Enforcement: `sccgub-execution::forgery_veto::validate_forgery_veto_admission`
at phase 12, alongside evidence admission.

---

## §31 Base fee floor (H.4)

### §31.1 Problem

`EconomicState::effective_fee_median` returns `base_fee * (1 + α *
median / budget)`. With `median = 0` (consecutive zero-tension blocks)
the multiplier is `1.0` and the effective fee collapses to `base_fee`, but
an attacker who controls `base_fee` via a governance proposal can drive it
arbitrarily close to zero (no lower bound on `base_fee`).

### §31.2 Floor mechanism

Add two fields to `ConstitutionalCeilings`:

- `min_base_fee_floor: i128` — lower bound on `base_fee`. Default
  `TensionValue::SCALE / 100` (= 0.01 fee units).
- `min_effective_fee_floor: i128` — lower bound on the composed
  `effective_fee_median` output. Default `TensionValue::SCALE / 100`.

The second floor is applied **after** the multiplier. `effective_fee_median`
is redefined as:

```
gas_price = max(base_fee * (1 + α * median / budget), min_effective_fee_floor)
```

### §31.3 Governance interaction

A `ModifyConsensusParam` proposal that would reduce `base_fee` below
`min_base_fee_floor` is rejected by `validate_typed_param_proposal`
(existing §25 path). A `ModifyCeiling` path for the floor itself is NOT
introduced — ceilings remain write-once at genesis.

### §31.4 Invariant

**INV-FEE-FLOOR-ENFORCED** — for every block of chain-version ≥ v5:
`effective_fee_median(...) ≥ constitutional_ceilings.min_effective_fee_floor`.

Enforcement: direct composition in `effective_fee_median` when
`params.chain_version >= 5`. Pre-v5 paths are unchanged.

### §31.5 Deferral from Patch-05 closed

Resolves the CRITICAL gap noted in the v0.5.0 audit §B row
"INV-FEE-ORACLE-BOUNDED: no floor under the final effective fee."

---

## §32 Fork-choice rule (H.5)

### §32.1 Problem

Under a network partition, two validator sub-quorums can each admit
divergent blocks. On partition recovery the node must deterministically
select one fork. The code currently implements implicit "first-seen"
behavior; this is neither declared nor sufficient under adversarial
reorg.

### §32.2 Declared rule

**Fork-choice v5:** among candidate chains of equal `block.height`, prefer
the chain whose **tip** has the greater canonical score:

```
score(tip) = (finalized_depth(tip), cumulative_voting_power(tip), tie_break_hash(tip))
```

Compared lexicographically. Higher is preferred.

- `finalized_depth(tip)` is the number of ancestors in `tip`'s chain that
  have reached finality (signed by ≥⅔ of the active set at their height).
  A finalized block cannot be reverted.
- `cumulative_voting_power(tip)` is the sum across every block `b` from
  genesis to `tip` of the sum of voting power of precommit signers on `b`,
  mod `2^64` (saturating). This rewards the chain with more collective
  signed work.
- `tie_break_hash(tip)` is `tip.block_id` interpreted as an unsigned
  big-endian integer. Lexicographic comparison yields a total order.

### §32.3 Reorg rule

A node switches to an alternative chain `B` iff `score(B.tip) >
score(current.tip)` AND the alternative does not attempt to revert any
block `b` with `finalized_depth(b) >= confirmation_depth`. An attempted
revert beyond the confirmation-depth safety boundary is a **consensus
fault**; the node rejects the alternative chain and logs an operator
alert.

### §32.4 Invariant

**INV-FORK-CHOICE-DETERMINISM** — given the same set of observed blocks
and votes, every honest node selects the same tip.

Enforcement: `sccgub-consensus::fork_choice::select_canonical_tip`, pure
function over observed state. Exercised by a determinism replay test.

### §32.5 Interaction with §27 admitted history

`validator_set_change_history` is keyed by admission order within the
selected chain. On reorg, history entries from the discarded branch are
dropped from the projection; the retained chain's history is authoritative.
Nodes do NOT merge histories across forks.

---

## §33 State pruning gated on finality (H.1)

### §33.1 Problem

State storage grows monotonically with chain age (admission records, key
rotations, receipt history). At 10⁷ operations the state root recompute
exceeds the block budget. Loader caps (N-61) prevent malicious bloat on
load but do not bound steady-state size.

### §33.2 Pruning model

Pruning is a **local operation** — it does not affect the state root of
any post-finality block, because the state root is computed over the
pre-pruning canonical keys, and pruning only removes entries the protocol
guarantees will never be referenced again.

A trie entry is **prunable** when all of the following hold:

1. It belongs to a declared prunable namespace (§33.3).
2. The youngest block that referenced or mutated it has `finalized_depth
   ≥ params.pruning_depth` where `pruning_depth` is a new field in
   `ConsensusParams`, default `params.confirmation_depth * 16` = 32 blocks
   (equivalent to ~1 hour at 2-minute blocks).
3. The entry is superseded (there exists a younger non-prunable entry
   that supersedes it) OR the entry has explicit `pruning_hint::Expired`
   metadata.

### §33.3 Prunable namespaces

| Namespace | Prunable? | Supersession rule |
|---|---|---|
| `system/validator_set` (current) | NO | Latest only; inherently bounded |
| `system/validator_set_change_history` | PARTIAL | Entries older than `pruning_depth` AND superseded by a newer admission for the same `agent_id` are prunable; the head entry per agent is retained |
| `system/key_index` | PARTIAL | Superseded KeyIndex entries (rotations older than `pruning_depth`) prunable; active entry per agent retained |
| `system/tension_history` | NO | Already bounded at `TENSION_HISTORY_MAX_LEN = 64` |
| `system/constitutional_ceilings` | NO | Genesis-only; single entry |
| `block_receipts/*` | YES | Entries older than `pruning_depth` blocks are prunable wholesale |
| `snapshots/*` | YES | Snapshots older than the most recent non-prunable one are prunable |

Transaction-level state (`account/*`, `contract/*`) is NOT prunable by this
patch. Account pruning requires a separate invariant about zero-balance
account garbage collection and is deferred.

### §33.4 Pruning process

Pruning is triggered by a node-local maintenance task (NOT consensus). The
trigger reads `finalized_depth(current_tip)` and walks the prunable
namespaces, emitting a **pruning receipt** that records:

```rust
pub struct PruningReceipt {
    pub height: u64,                 // tip at which pruning ran
    pub namespaces: Vec<(Namespace, u32)>,  // (namespace, keys_pruned)
    pub pre_root: Hash,              // state root before
    pub post_root: Hash,             // state root after; MUST equal pre_root
}
```

`post_root == pre_root` is the structural invariant for namespaces that
live **outside** the state-root computation domain — specifically,
`block_receipts/*` (in-memory / node-local), `snapshots/*` (node-local
on-disk), and any entries written under the reserved `pruned_archive/*`
prefix once §33.6 is wired.

### §33.4.1 Post-release addendum (v0.6.2+)

The original §33.4 wording implied `post_root == pre_root` holds for
**every** prunable namespace. Post-release review (v0.6.2, 2026-04-18)
identified that `system/validator_set_change_history` is an in-trie
namespace whose value IS folded into the state root. Pruning entries
from this namespace necessarily changes the serialized value at that
key, and therefore changes the state root. The invariant `post_root ==
pre_root` CANNOT hold for in-trie admission-history pruning.

Two consequences:

1. **INV-STATE-BOUNDED applies** to `system/validator_set_change_history`
   only as a **non-replay-deterministic node-local compaction**. Nodes
   that have pruned admission history have a different state root than
   nodes that have not. This breaks cross-node `state_root` comparison,
   which is consensus-critical.

2. **True replay-deterministic admission-history pruning** requires a
   separate accounting: either (a) a two-surface trie (live + archive,
   both folded into the root via a deterministic combiner), or (b) a
   protocol rule that all honest nodes prune at identical heights, or
   (c) excluding admission history from the state root entirely (which
   weakens INV-HISTORY-COMPLETENESS enforcement).

Patch-07 §B will resolve this. Until then, Patch-06 §33's execution
path is intentionally stubbed (`PruningError::NotYetWired`), and the
identification predicates remain consensus-neutral (they only enumerate
what *could* be pruned; no node has actually pruned anything).

For the namespaces that ARE outside the root domain —
`block_receipts/*` and `snapshots/*` — `post_root == pre_root` does
hold, and those are candidates for first-wave execution in Patch-07.

### §33.5 Invariant

**INV-STATE-BOUNDED** — for a chain of height `H` with confirmation_depth
`k`, steady-state prunable-namespace size is `O(active_validators + k *
block_span)` rather than `O(H)`. Formally:

```
|live_state(H)| <= |live_state(H-1)| + constant_per_block
```

No invariant reads or modifies state before finality; a pending-block
state view retains its full pre-pruning surface.

### §33.6 Archive namespace

`pruned_archive/*` is a separate key-value surface (redb table or flat
file) NOT included in the state root. It is consulted only by:

- Audit tooling (`sccgub-api::admin::pruned_archive` endpoint, gated behind
  operator authentication)
- Full-replay paths (`cargo run -p sccgub-node -- replay --from=genesis`)

Archive retention is operator-configurable; default is "retain forever."

---

## §34 Live-upgrade protocol (H.2)

### §34.1 Problem

v3→v4 and v4→v5 transitions are performed via a genesis flag
(`chain_version` field embedded at genesis). To upgrade a live chain from
v_current → v_next, every validator must stop, modify genesis (or
configuration), and restart simultaneously. This is an operational
impossibility at production scale.

### §34.2 Activation-height pattern

A v_next upgrade is declared via a special **Governance-level**
`UpgradeProposal`:

```rust
pub struct UpgradeProposal {
    pub proposal_id: ProposalId,
    pub target_chain_version: u32,
    pub activation_height: u64,         // future height at which v_next takes effect
    pub upgrade_spec_hash: Hash,        // BLAKE3 over the binary spec reference
    pub submitted_at: u64,
    pub quorum_signatures: Vec<ValidatorSignature>,
}
```

Admission requirements (beyond standard Governance-level proposal rules):

1. `activation_height >= submitted_at + params.min_upgrade_lead_time`
   where `min_upgrade_lead_time` is a new `ConstitutionalCeilings` field,
   default 14400 blocks (~10 days at 60s blocks). Prevents last-minute
   upgrades.
2. `target_chain_version == current_chain_version + 1`. No
   version-skipping.
3. Quorum signatures sum to `≥ (2/3) × total_voting_power` at
   `submitted_at`.
4. `upgrade_spec_hash` must match a binary in the node's
   recognized-upgrade registry OR the node refuses to admit and logs an
   upgrade-awareness alert.

### §34.3 Waiting-room semantics

Between `submitted_at` and `activation_height`:

- The upgrade is `Admitted` but not `Active`.
- Nodes that do not recognize `upgrade_spec_hash` emit `UpgradeBlockedWarning`
  every block; block validation is unaffected until `activation_height`.
- Operators upgrade binaries during this window.

### §34.4 Activation

At block `activation_height`:

- `ConsensusParams.chain_version` is atomically incremented.
- All v_next rules take effect for blocks `>= activation_height`.
- A new `ChainVersionTransition` entry is appended to a new trie namespace
  `system/chain_version_history`.

### §34.5 Non-goals for this spec

This §34 declares the **protocol contract** for live upgrades. Binary
distribution, registry maintenance, and operator tooling are
implementation concerns deferred to Patch-07 operational tooling. The
structural types and admission path ARE implemented in this patch; the
activation path is stubbed with a TODO-guarded runtime panic until
Patch-07 completes the binary registry surface.

### §34.6 Invariant

**INV-UPGRADE-ATOMICITY** — if a block with height `h >= activation_height`
is admitted under the v_current rules, OR a block `h < activation_height` is
admitted under v_next rules, the chain is rejected.

Enforcement: `sccgub-execution::chain_version_check::verify_block_version_alignment`
as phase 0 (pre-Phi).

---

## §35 Patch-06 invariants summary

| ID | Source | Declared in |
|---|---|---|
| INV-FORGERY-VETO-AUTHORIZED | §30.5 | `sccgub-execution::forgery_veto` |
| INV-FEE-FLOOR-ENFORCED | §31.4 | `sccgub-types::economics` |
| INV-FORK-CHOICE-DETERMINISM | §32.4 | `sccgub-consensus::fork_choice` |
| INV-STATE-BOUNDED | §33.5 | `sccgub-state::pruning` |
| INV-UPGRADE-ATOMICITY | §34.6 | `sccgub-execution::chain_version_check` |

All five invariants must hold for chains of version ≥ v5. Pre-v5 chains
retain their pre-Patch-06 semantics.

## §36 Deferrals from Patch-06

| Item | Reason for deferral | Target patch |
|---|---|---|
| Multi-validator BFT adversarial test harness | Requires network simulation infrastructure | Patch-07 |
| Warming-window clamp on effective fee (separate from §31 floor) | §31 floor subsumes the urgent case | Patch-07 |
| Remove-source discriminator (`RemovalSource::{Proposer, Evidence}`) | Cosmetic; change_id.quorum_signatures already distinguishes | Patch-07 |
| KeyIndex B+tree | O(n) lookup not yet a production blocker | Patch-07 |
| Upgrade binary registry + op tooling | Out of scope for a protocol-level patch | Patch-07 |
| Account pruning | Requires zero-balance GC invariant | Patch-08 |
| Gossip fan-out bound (D.7) | Network-layer; touches peer lifecycle | Patch-07 |
| Regulatory mapping artifacts (MiCA, SOC 2) | Not a protocol concern | Separate workstream |

## §37 Conformance

A new `crates/sccgub-node/tests/patch_06_conformance.rs` exercises all five
invariants end-to-end in a single deterministic scenario and asserts replay
determinism across v5 systems. The test mirrors the PATCH_04/05 pattern.
