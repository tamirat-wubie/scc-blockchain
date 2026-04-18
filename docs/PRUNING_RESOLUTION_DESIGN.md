<!--
Purpose: Resolve the in-trie pruning problem PATCH_06.md §33.4.1 declared
unresolved. The earlier addendum honestly documented that pruning an in-
trie namespace changes the state root, making cross-node equality impossible
under the "local compaction" model the original §33.4 implied.

This document proposes a concrete mechanism — pruning-as-scheduled-checkpoint
— that makes in-trie pruning consensus-safe: every honest node prunes the
same entries at the same height, and the post-prune state root differs from
the pre-prune root but every validator agrees on both.

The design is tagged "Patch-07 §B" per the forward-references table in
PATCH_07.md §H. This doc is a design proposal; an actual PATCH_08 spec would
ratify it before implementation.

Governance scope: doc-only. Every claim is a design proposal. No code ships
from this document.

Invariants: the design preserves INV-HISTORY-COMPLETENESS at the chain
level (all pruned data is archived, accessible by audit tools) while making
INV-STATE-BOUNDED enforceable (steady-state live-trie size is bounded).

Dependencies: docs/INVARIANTS.md, PATCH_06.md §33, docs/THESIS_AUDIT.md,
docs/THESIS_AUDIT_PT2.md, docs/FINANCE_EXTRACTION_PLAN.md §8.4 (the
prerequisite that motivated this doc).
-->

# Patch-07 §B — In-Trie Pruning Resolution

**Status**: design proposal. Not a spec. Not a PR against code.
**Resolves**: PATCH_06.md §33.4.1 "post_root == pre_root" caveat.
**Unblocks**: docs/FINANCE_EXTRACTION_PLAN.md §8.4 prerequisite.
**Target patch**: Patch-08 (when ratified).

## 1 · The problem, precisely

PATCH_06 §33 declared INV-STATE-BOUNDED and the `PruningReceipt` type,
with the claim that pruning is a no-op at the state-root level because
archived entries move outside the root-computation domain. §33.4.1
retracted that claim for in-trie namespaces like
`system/validator_set_change_history`: the serialized value at that
key IS in the root, so shrinking it changes the root.

Three candidate resolutions were sketched in §33.4.1:

- **(a) Two-surface trie** — a live + archive surface with a
  deterministic combiner that commits both into the root, making
  archive operations root-neutral by construction.
- **(b) Protocol rule for synchronized pruning** — every honest
  node prunes the same entries at the same height, so the post-prune
  root differs from the pre-prune root but every validator agrees on
  both.
- **(c) Exclude admission history from the state root** — simplest
  but weakens INV-HISTORY-COMPLETENESS enforcement because a malicious
  node could drop entries without detection.

This document commits to **(b) synchronized pruning**. It is the
simplest mechanism that preserves INV-HISTORY-COMPLETENESS without
introducing a new combiner primitive into `ManagedWorldState::state_root`
(which is itself consensus-critical and should not be touched lightly).

## 2 · The mechanism — pruning-as-checkpoint

### 2.1 · Pruning becomes a scheduled consensus action

Today, `sccgub-state::pruning::perform_pruning` is stubbed with
`PruningError::NotYetWired`. The proposed resolution promotes pruning
from "node-local compaction" to "consensus-scheduled checkpoint":

1. **Schedule**: pruning fires automatically at every block `h` where
   `h % params.pruning_checkpoint_interval == 0` AND
   `h >= params.pruning_checkpoint_start_height`. Both fields are new
   `ConsensusParams` entries (legacy-cascaded for pre-Patch-08 chains).
2. **Determinism**: at a pruning checkpoint, every validator runs
   `identify_prunable_admission_history(history, h, pruning_depth)`
   (the existing pure function from PATCH_06 §33). Every validator
   receives the same input state, so every validator identifies the
   same prunable set.
3. **Execution**: each validator archives the identified entries into
   a `system/pruned_archive/...` namespace AND rewrites the live
   namespace with the retained entries. Both operations are
   deterministic functions of the input state.
4. **Verification**: the post-checkpoint state root is computed
   normally (trie root over all remaining keys). Validators proceed
   to propose/admit block `h` with the new root. Disagreement on the
   root at a pruning-checkpoint height is a consensus fault, same as
   any other.

**Key insight**: the state root DOES change at a pruning checkpoint.
That is intentional. What matters is that every honest validator
computes the **same new root**. Synchronized pruning makes this
automatic because the pruning function is pure over inputs every
validator shares.

### 2.2 · Pre-prune vs post-prune roots

At checkpoint height `h`:

```
state_root(h-1) = R_old   (computed with live admission history containing N entries)
state_root(h)   = R_new   (computed with live admission history containing M entries,
                           M < N, plus archive entries at pruned_archive/... keys)
```

`R_new != R_old` and that is fine. The chain's lineage at block `h`
commits to `R_new` via the standard block-header `state_root` field.
Subsequent blocks chain off `R_new`. No validator is ever uncertain
which root is canonical.

### 2.3 · Archive namespace is in the root

Unlike PATCH_06 §33.4 which proposed excluding `pruned_archive/*` from
the root via a filter, this design keeps archive entries in the root.
Rationale: if the archive is in the root, INV-HISTORY-COMPLETENESS
is preserved cryptographically — a node cannot silently drop archive
entries without diverging from the canonical root. The filter-based
exclusion the previous patch sketched would have weakened this
guarantee.

**Net storage impact**: the archive namespace lives in the trie
alongside live namespaces. Size is the same as "no pruning" for total
bytes stored. The gain is **access-pattern separation**: reads of
live admission history skip the archive prefix (O(1) range scan
avoiding the archive), so hot-path reads stay fast.

## 3 · Concrete algorithm

Pseudocode for the checkpoint handler:

```rust
// Called by the block builder at every pruning checkpoint height h.
pub fn execute_pruning_checkpoint(
    state: &mut ManagedWorldState,
    tip_height: u64,
    params: &ConsensusParams,
) -> Result<PruningReceipt, PruningError> {
    // Guard: only fires at scheduled heights.
    if !is_pruning_checkpoint(tip_height, params) {
        return Ok(PruningReceipt::empty(tip_height));
    }

    let pruning_depth = params.pruning_depth();
    let pre_root = state.state_root();

    // 1. Prune admission history.
    let history = validator_set_change_history_from_trie(state)?;
    let prunable = identify_prunable_admission_history(
        &history, tip_height, pruning_depth,
    );
    let mut retained_history = history.clone();
    retained_history.retain(|c| !prunable.iter().any(|p| p.key == c.change_id));

    // 2. Archive the pruned entries (deterministic keys).
    for entry in &prunable {
        let archive_key = format!(
            "pruned_archive/validator_set_change_history/{}",
            hex::encode(entry.key),
        );
        let archived_bytes = bincode::serialize(&history_entry_for(entry))?;
        state.set(archive_key.as_bytes().to_vec(), archived_bytes);
    }

    // 3. Overwrite live admission history with retained entries.
    commit_history(state, &retained_history);

    // 4. Post-root is whatever the trie now computes.
    let post_root = state.state_root();

    Ok(PruningReceipt {
        tip_height,
        pruning_depth,
        namespaces: vec![(
            PrunableNamespace::ValidatorSetChangeHistory,
            prunable.len() as u32,
        )],
        pre_root,
        post_root,
    })
}
```

**Deterministic by construction**: every input to the function is a
pure read from `state` plus `params`; every operation is
deterministic; no wall-clock, no randomness. Two validators running
this on the same pre-checkpoint state produce the same post-checkpoint
state.

## 4 · Why `state_root_preserved` is retired as a meaningful check

PATCH_06 §33 introduced `PruningReceipt::state_root_preserved()`
returning `pre_root == post_root`. The v0.6.2 amendment (PATCH_06
§33.4.1) narrowed its meaning to outside-root namespaces only.
Under this design:

- For `pruned_archive/*` additions from in-trie pruning: `pre_root
  != post_root` always. The check returns `false` and that is
  semantically correct — the root changed because it was supposed to.
- For snapshots / block_receipts (outside the trie): the check still
  applies and returns `true`.

**Recommended future action**: rename `state_root_preserved()` to
`archive_is_outside_root()` or similar so the name matches the actual
semantic. Keep the current name as a `#[deprecated]` alias for
backward compatibility until Patch-10.

## 5 · New invariant

Patch-08 declares:

**INV-PRUNING-CHECKPOINT-DETERMINISM** — at every block `h` where
`is_pruning_checkpoint(h, params)` is true, every honest validator
produces the same post-checkpoint state root. Formally:

```
∀ validators V1, V2 with equal pre-checkpoint state:
  V1.execute_pruning_checkpoint(h) = V2.execute_pruning_checkpoint(h)
```

Enforcement: type-layer purity of `execute_pruning_checkpoint` (no
allocator-dependent iteration, no HashMap, no wall-clock) + consensus-
layer root agreement at block `h`. A divergence is a consensus fault
handled exactly like any other root disagreement.

## 6 · New ConsensusParams fields

```rust
pub struct ConsensusParams {
    // ... existing fields ...

    /// Patch-08 §B: block-height interval between pruning checkpoints.
    /// Default 1000 blocks (~33 hours at 2-min blocks).
    pub pruning_checkpoint_interval: u64,

    /// Patch-08 §B: first block at which pruning checkpoints begin
    /// firing. Default 100000 (prevents pruning during early chain
    /// bring-up when admission history is small anyway).
    pub pruning_checkpoint_start_height: u64,
}
```

Legacy cascade via `LegacyConsensusParamsV4` (prior version) fills
these fields with defaults on upgrade, preserving pre-Patch-08 replay
determinism.

## 7 · New ConstitutionalCeilings fields

```rust
pub struct ConstitutionalCeilings {
    // ... existing fields ...

    /// Upper bound on pruning_checkpoint_interval. Caps governance-
    /// driven pruning avoidance. Default 10000 (= roughly weekly).
    pub max_pruning_checkpoint_interval: u64,

    /// Lower bound on pruning_checkpoint_interval. Caps governance-
    /// driven pruning spam. Default 100 (= roughly every 3 hours).
    pub min_pruning_checkpoint_interval: u64,
}
```

Legacy cascade via `LegacyConstitutionalCeilingsV2`.

## 8 · Chain-version implications

Introducing `execute_pruning_checkpoint` into the block-production
path is a **chain-breaking change**. Rationale:

- Pre-checkpoint chains never executed pruning; their historical
  block-height sequence has pure block contents.
- A post-checkpoint chain at height `h = N * pruning_checkpoint_interval`
  has a state-root value derived from a different namespace shape
  (archive entries + shortened live history).
- Replaying a pre-Patch-08 chain under Patch-08 code would fire the
  checkpoint at (say) height 1000 and produce a state root that no
  pre-Patch-08 validator ever computed.

The fix is the standard live-upgrade per PATCH_06 §34:

1. `UpgradeProposal` naming `target_chain_version = v8`.
2. Waiting-room window per `DEFAULT_MIN_UPGRADE_LEAD_TIME = 14_400`.
3. At activation height `h_a`:
   - `pruning_checkpoint_start_height` is set to `max(h_a +
     pruning_checkpoint_interval, default)` so the first pruning
     checkpoint fires **after** activation, not retroactively.
   - Pre-activation blocks continue to have pre-Patch-08 semantics.

Post-activation, pruning fires normally.

## 9 · Migration cost

| Work phase | Estimate |
|---|---|
| `execute_pruning_checkpoint` implementation + tests | 2 weeks |
| `ConsensusParams` + legacy cascade for new fields | 1 week |
| `ConstitutionalCeilings` + legacy cascade for new fields | 1 week |
| Block-builder integration (call checkpoint at scheduled heights) | 1 week |
| Replay harness extension (validate checkpoint roots match across validators) | 2 weeks |
| Conformance test (multi-checkpoint scenario) | 1 week |
| Live-upgrade migration path + activation-height handling | 2 weeks |
| Archive-read API endpoint (operator auth gated, per v0.6.5 pattern) | 1 week |
| OpenAPI + docs | 1 week |

**Total**: ~12 weeks = **~3 months** of focused work. This does NOT
depend on the finance extraction landing first; Patch-08 §B can be
scheduled independently.

## 10 · Interaction with finance extraction

The FINANCE_EXTRACTION_PLAN.md §8.4 flagged Patch-07 §B as a
prerequisite. Now that the mechanism is concrete, the dependency
becomes explicit:

- Finance extraction changes trie keyspaces (`balance/*` →
  `finance.v1/balance/*`). The pruning-checkpoint mechanism above
  only prunes `system/validator_set_change_history`. It does NOT
  currently prune any finance-adapter namespace.
- After extraction, if any finance-adapter namespace becomes
  unbounded (e.g., closed escrow records), the adapter itself
  declares its prunable namespaces to the kernel, and the
  checkpoint handler iterates all registered adapters' prunable-
  namespace predicates.
- This requires a small addition to the `DomainAdapter` trait (§4 of
  FINANCE_EXTRACTION_PLAN.md): `fn prunable_namespaces(&self) ->
  Vec<PrunableNamespaceDecl>`. Non-breaking; add in v2 of the trait.

**Net**: resolving Patch-07 §B (this document) AND then doing the
finance extraction is cleaner than interleaving. Recommended
sequence: Patch-08 (this design) → Patch-09 (finance extraction).

## 11 · Alternatives considered and rejected

### (a) Two-surface trie with deterministic combiner

Would require modifying `ManagedWorldState::state_root` to fold
live + archive surfaces via a new combiner function. Every existing
invariant that hashes state keys becomes potentially affected. The
change is consensus-critical surgery on a single function used
everywhere. Rejected as disproportionate to the problem.

### (c) Exclude admission history from the state root

A node that drops admission history entries would produce the same
state root as a node that retained them. This breaks
INV-HISTORY-COMPLETENESS cryptographically — the invariant devolves
to "we ask nodes politely not to drop." Rejected as an invariant
weakening without a compensating gain.

### Keep the status quo (stubbed pruning)

Indefinite deferral means admission history grows monotonically.
At 10⁶ admissions the state root recompute cost exceeds block budget
and block production halts. Rejected because it defers a bug rather
than avoids one.

## 12 · What this document does not do

- Not a PATCH_08 spec. A formal spec would ratify the field names,
  default values, and semantics used here.
- Not a code PR. The implementation path is clear but is not
  authored by this document.
- Not a unilateral decision. The alternative approaches in §11 remain
  open until a formal spec commits.

## 13 · Decision matrix for the reader

| If you want to… | Read next |
|---|---|
| Approve the checkpoint design | §2 + §5 |
| Compare alternatives | §11 |
| Estimate effort | §9 |
| Understand chain-break accounting | §8 + PATCH_06 §34 |
| Understand the interaction with finance extraction | §10 + FINANCE_EXTRACTION_PLAN.md §8.4 |
| Reject this design and keep pruning stubbed | §11 status-quo discussion |

---

**End of design.** Doc-only. A future PATCH_08.md spec (if authorized)
would ratify the concrete field names, defaults, and field-order
canonical encoding. Until then, `sccgub-state::pruning::perform_pruning`
continues to return `PruningError::NotYetWired` and
INV-STATE-BOUNDED remains STUBBED.
