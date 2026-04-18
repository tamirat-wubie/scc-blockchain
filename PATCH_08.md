# PATCH_08 — Ceiling-Immutability Verifier (`sccgub-audit` crate)

**Status**: spec doc, not implementation. Implementation lands in a
separate PR per the established two-step discipline (spec → code).
**Resolves**: POSITIONING §11 commitment + INVARIANTS §7.1 Tier-0
DECLARED-ONLY entries (INV-CEILINGS-WRITE-ONCE,
INV-CEILINGS-NEVER-RAISED-IN-HISTORY).
**Chain version impact**: none. Patch-08 ships an **external auditor
tool**, not a chain-rule change. No new chain version, no migration,
no consensus-layer touch. The verifier reads chain state; it does not
write to it.

## §A Why this patch exists

POSITIONING.md §1 declares SCCGUB's moat:

> Constitutional ceilings are genesis-write-once and not modifiable
> by any governance path, including the governance path itself.

POSITIONING.md §11 then states the consequence:

> The §1 moat is **structurally meaningful only if it is externally
> auditable** by parties that do not trust the maintainer.

Today the property holds **by absence** — there is no code path that
writes `system/constitutional_ceilings` after genesis-commit. That
is sufficient for the property to *hold* but not for it to be
*demonstrably held* to a third party. An institution evaluating
SCCGUB for a constitutional-court use case must currently audit the
codebase to confirm the absence; that is fragile and
maintainer-dependent.

Patch-08 ships the verifier that makes the property externally
auditable without source-code review and without trust in the
maintainer.

## §B Verifier contract

```rust
pub fn verify_ceilings_unchanged_since_genesis(
    chain_state: &ChainStateView,
) -> Result<(), CeilingViolation>;
```

### §B.1 Inputs

`ChainStateView` is a read-only handle to the chain log providing:

- `genesis_block_hash() -> Hash` — the genesis block's id.
- `genesis_constitutional_ceilings() -> ConstitutionalCeilings` —
  the ceilings as committed at genesis. Read from the genesis-block
  state-root proof, NOT from any later snapshot.
- `chain_version_history() -> Vec<ChainVersionTransition>` — every
  `ChainVersionTransition` record from genesis to current tip,
  ordered ascending by `activation_height`.
- `ceilings_at_height(h: u64) -> Result<ConstitutionalCeilings,
  ChainStateError>` — the ceilings as committed at block `h`. Used
  to verify the value at each chain-version transition matches the
  genesis value.

The view abstraction is required so the verifier can be backed by:
- A live full node (operator's local mode).
- A snapshot file (institutional auditor's offline mode).
- A merkle-proof bundle (light-client mode without full chain
  storage).

### §B.2 Output semantics

- `Ok(())` — every `ChainVersionTransition` from genesis to current
  tip preserved every `ConstitutionalCeilings` field at exactly its
  genesis value. **Moat holds.**
- `Err(CeilingViolation { transition_height, ceiling_field,
  before_value, after_value })` — the **first** violation
  encountered, walking transitions in ascending-height order.
  Subsequent violations are not enumerated; the verifier short-
  circuits on first failure because any single violation breaks the
  moat.

### §B.3 `CeilingViolation` enum

```rust
pub enum CeilingViolation {
    /// A ceiling field's value at activation_height differed from
    /// its genesis value. This is the primary moat-violation case.
    FieldValueChanged {
        transition_height: u64,
        ceiling_field: CeilingFieldId,
        before_value: CeilingValue,
        after_value: CeilingValue,
    },
    /// The genesis ceilings record could not be read or
    /// deserialized. The chain has no genesis ceilings to compare
    /// against; moat is undefined for this chain.
    GenesisCeilingsUnreadable { reason: String },
    /// A `ChainVersionTransition` referenced a height at which the
    /// ceilings record could not be read. Possible incomplete
    /// snapshot or corrupted state.
    CeilingsUnreadableAtTransition {
        transition_height: u64,
        reason: String,
    },
    /// `chain_version_history` contained a transition whose
    /// activation_height predated genesis or violated monotonic
    /// ordering. Indicates corrupted history.
    HistoryStructurallyInvalid { reason: String },
}
```

### §B.4 `CeilingFieldId` enum

Enumerates every field of `ConstitutionalCeilings` (per
`crates/sccgub-types/src/constitutional_ceilings.rs`). The verifier
checks **every** field; missing a field would silently allow that
field to drift. A future PR adding a new ceiling field MUST add the
corresponding `CeilingFieldId` variant in the same PR.

### §B.5 Algorithm

```
for each transition in chain_version_history (ascending by activation_height):
    pre  := ceilings_at_height(transition.activation_height - 1)
    post := ceilings_at_height(transition.activation_height)
    for each field in CeilingFieldId::all():
        if field_value(pre, field) != field_value(genesis_ceilings, field):
            return Err(CeilingViolation::FieldValueChanged {
                transition_height: transition.activation_height,
                ceiling_field: field,
                before_value: field_value(genesis_ceilings, field),
                after_value: field_value(pre, field),
            });
        // ALSO check post against genesis to catch violations
        // introduced AT the transition height itself.
        if field_value(post, field) != field_value(genesis_ceilings, field):
            return Err(CeilingViolation::FieldValueChanged {
                transition_height: transition.activation_height,
                ceiling_field: field,
                before_value: field_value(genesis_ceilings, field),
                after_value: field_value(post, field),
            });
return Ok(())
```

**Edge case — empty history**: a chain with zero
`ChainVersionTransition` records (genesis-only chain) trivially
satisfies the property. Verifier returns `Ok(())` after the empty
loop.

**Edge case — height = 0 transition**: forbidden by
PATCH_06 §34's lead-time discipline; verifier still handles it
defensively by checking only `post` if `transition.activation_height
== 0`.

### §B.6 Purity and reproducibility

The verifier is a **pure function** over its input. Two reviewers
running the verifier against the same `ChainStateView` produce
byte-identical output. The verifier:

- Reads no wall-clock.
- Reads no environment.
- Performs no I/O outside `ChainStateView` method calls.
- Allocates only what it returns; no caches, no global state.

This is the property that makes external auditability meaningful.

## §C `sccgub-audit` crate

### §C.1 Crate boundaries

New crate `crates/sccgub-audit/`:

- **Library**: `verify_ceilings_unchanged_since_genesis`,
  `ChainStateView` trait, `CeilingViolation` enum, `CeilingFieldId`
  enum, `CeilingValue` enum.
- **Binary**: `sccgub-audit verify-ceilings --chain-state <path>` —
  loads a snapshot file, constructs a `ChainStateView`, runs the
  verifier, prints the result in human-readable and machine-readable
  (JSON) form.

### §C.2 Dependency isolation requirement

`sccgub-audit` MUST be **independently compilable** by a reviewer
who does not have the rest of the SCCGUB workspace. Concretely:

- `sccgub-audit` may depend on `sccgub-types` (for
  `ConstitutionalCeilings`, `ChainVersionTransition`,
  canonical-encoding helpers).
- `sccgub-audit` MAY depend on `sccgub-crypto` (for hash + signature
  primitives required to verify state-root proofs in light-client
  mode).
- `sccgub-audit` MUST NOT depend on `sccgub-state`, `sccgub-execution`,
  `sccgub-consensus`, `sccgub-governance`, `sccgub-network`,
  `sccgub-api`, or `sccgub-node`. The verifier exists to be checked
  by parties who do not trust the rest of the substrate; pulling in
  the substrate as a dependency defeats that property.
- External dependencies kept minimal: `serde`, `bincode`, `blake3`,
  `clap` (for CLI), `thiserror`. No async runtime, no networking, no
  HTTP framework.

The dependency boundary is **enforced by review** at PR time. A
future patch that adds an `sccgub-state` dependency to
`sccgub-audit` requires a positioning amendment under POSITIONING
§14 explaining why the verifier can credibly survive the
dependency.

### §C.3 Cross-implementation commitment

POSITIONING §11 commits to cross-implementability. Patch-08 ships
the Rust reference implementation. A follow-up patch (Patch-09 or
later) ships at least one cross-implementation in an alternative
language (Go, Python, or TypeScript) to prove the verifier semantics
are language-portable, not Rust-bound.

The cross-implementation work is **out of scope for Patch-08
itself** but is named here so future patches know the commitment
exists. Patch-08 does NOT block on cross-implementation; it does,
however, ship its specification (this document) in language-neutral
form so cross-implementers have a contract to satisfy.

### §C.4 Standalone CLI requirements

The `sccgub-audit verify-ceilings` binary must be runnable by an
external party with **no node operation, no Rust toolchain
familiarity beyond `cargo install`, no SCCGUB workspace clone**.
Concretely:

- `cargo install sccgub-audit` from crates.io installs the binary.
  (Crates.io publication is operator action, not Patch-08 scope;
  but the crate must be publishable, so no path-only or git-only
  dependencies.)
- `sccgub-audit verify-ceilings --chain-state ./snap.bin` runs the
  verifier against a snapshot file in the canonical snapshot
  format.
- `sccgub-audit verify-ceilings --chain-state ./snap.bin --json`
  produces machine-readable output suitable for CI integration by
  pilot-adopter institutions.
- Exit code 0 = `Ok(())`; exit code 1 = `CeilingViolation`; exit
  code 2 = malformed input or I/O error. Distinct exit codes let
  pilot CI pipelines distinguish "moat verified" from "moat
  violated" from "couldn't run verifier."

### §C.5 Public verification endpoint (deployment commitment, not Patch-08 scope)

POSITIONING §11 suggests a **public verification endpoint operated
by no fewer than three independent parties** as the deployment
posture for production-grade moat verification. The endpoint
periodically polls the chain log, runs the verifier, and publishes
the result. Three operators provide majority-honest assurance that
no single party can manipulate the result.

The endpoint operation is **out of scope for Patch-08**. The CLI
binary ships in Patch-08; institutional operators stand up endpoints
on their own infrastructure.

## §D Test coverage requirements

POSITIONING §11 commits to **≥ 95% test coverage on the verifier
path**, including:

### §D.1 Mandatory coverage cases

For every `CeilingFieldId` variant, at least one test case where:
- The field is preserved across all transitions → `Ok(())`.
- The field changes at a single transition → correct
  `FieldValueChanged` returned.
- The field changes at multiple transitions → first violation
  returned, subsequent ignored (short-circuit).

For every `CeilingViolation` variant: at least one positive and one
negative test case.

For the algorithm structure:
- Empty `chain_version_history` → `Ok(())`.
- Single transition → checked at both `activation_height - 1` and
  `activation_height`.
- Multiple sequential transitions → each checked.
- Transition at `activation_height = 0` (degenerate, forbidden by
  PATCH_06 §34 but defensively handled).
- `chain_version_history` not monotonically ordered → `HistoryStructurallyInvalid`.

### §D.2 Adversarial cases

- A `ChainVersionTransition` whose `activation_height` exceeds the
  current tip → handled gracefully (verifier reports the height,
  does not panic).
- A `ConstitutionalCeilings` byte-encoding that round-trips
  correctly but contains a field whose `Ord` differs by encoding
  endianness — verifier compares values, not bytes; canonical
  comparison via `PartialEq` ensures encoding-portability.
- `genesis_constitutional_ceilings()` returns an error → propagates
  as `GenesisCeilingsUnreadable`.

### §D.3 Conformance test against synthetic chains

Patch-08 ships a `sccgub-audit-conformance` test binary that
generates synthetic genesis-to-tip chain histories and verifies the
verifier's output matches an oracle implementation written
independently. The oracle uses a different code path (e.g., walks
the chain log byte-by-byte rather than using `ChainStateView`
abstraction) to catch implementation bugs that affect both paths.

## §E What Patch-08 does NOT ship

Per discipline-of-named-deferrals:

- **Cross-language implementation**: deferred per §C.3.
- **Public verification endpoint**: out of scope per §C.5.
- **CI script that runs the verifier on every push**: Patch-08
  ships the binary; integrating it into CI is operator scope, not
  Patch-08 scope. (Suggested but not required.)
- **Per-jurisdiction counsel review of the verifier as audit
  evidence**: out of scope per POSITIONING §8.5.
- **Promotion of INV-CEILINGS-WRITE-ONCE / INV-CEILINGS-NEVER-RAISED-
  IN-HISTORY from DECLARED-ONLY to HELD in `docs/INVARIANTS.md`**:
  the promotion happens in the same PR that lands the verifier
  implementation, NOT in a separate PR. Spec status (DECLARED-ONLY)
  remains until the implementation PR ships.

## §F Verification of Patch-08 itself

Patch-08 is moat-defining. The verifier code is therefore subject
to the **highest review standard in the project**:

- **Two-pass review**: spec PR (this document) and implementation
  PR are reviewed separately. Spec PR reviewed for correctness of
  the contract; implementation PR reviewed against the spec.
- **Adversarial test review**: every adversarial test case in §D.2
  must be exercised against an intentionally-broken verifier
  variant in CI to confirm the test detects the break. (Mutation
  testing in spirit, even without a mutation framework.)
- **External review preferred**: if any reviewer outside the project
  is available at the time of Patch-08 implementation PR, their
  review is preferred over maintainer self-review for at least the
  algorithm-structure portion (§B.5).

## §G Forward references

| Patch | Scope (not yet scheduled) |
|---|---|
| Patch-08 implementation PR | `sccgub-audit` crate, verifier function, CLI binary, conformance tests. Same PR promotes the two Tier-0 invariants from DECLARED-ONLY to HELD per §E. |
| Patch-09 §A | Cross-language implementation of the verifier (Go, Python, or TypeScript) to prove language-portable semantics per §C.3. |
| Patch-N (PQC) | PQC migration must NOT raise any ceiling. Verifier must explicitly recognize the PQC activation as a non-ceiling-raising chain-version transition. POSITIONING §8.6 details. |

## §H §13 compliance

This PR adds a spec doc and does **not** change runtime behavior.
Per POSITIONING §14 (renumbered §13) amendment-process discipline,
no positioning amendment is required.

The implementation PR that follows this spec PR **will** change
runtime behavior (new crate, new binary, promoted invariants) and
will carry its own positioning amendment if the implementation
diverges from this spec. If implementation matches spec exactly,
the only positioning surface affected is the INVARIANTS.md status
column flip from DECLARED-ONLY → HELD, which is a routine ledger
update, not a structural change.

## §I What this document does and does not do

**Does:**

- Specify the verifier contract per POSITIONING §11.
- Specify the `sccgub-audit` crate boundary, dependencies, and
  binary surface.
- Specify test coverage requirements.
- Name what is in scope and what is deferred.

**Does not:**

- Implement the verifier (separate PR).
- Promote INV-CEILINGS-WRITE-ONCE or
  INV-CEILINGS-NEVER-RAISED-IN-HISTORY to HELD (happens in
  implementation PR).
- Authorize cross-language implementations (Patch-09 scope).
- Stand up the public verification endpoint (operator scope).
- Solve §8.1 capital, §8.5 regulatory precedent gap, or any other
  open POSITIONING problem.

---

**End of PATCH_08 spec.** Implementation PR follows.
