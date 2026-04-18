# PATCH_09 — Cross-Language Verifier Implementations

**Status**: spec doc, not implementation. Implementation lands in
separate per-language PRs per the established two-step discipline
(spec → code).
**Resolves**: POSITIONING §11 cross-implementability commitment +
PATCH_08 §C.3 deferred-to-Patch-09 obligation.
**Chain version impact**: none. Patch-09 ships **external auditor
tools in additional languages**, not chain-rule changes.

## §A Why this patch exists

POSITIONING §11 commits to cross-implementability of the
ceiling-immutability verifier:

> Cross-implementable in alternative languages (Go, Python,
> TypeScript) to prove the verifier semantics are language-portable,
> not Rust-bound.

PATCH_08 §C.3 carried this forward as deferred-to-Patch-09 work.
PATCH_08 §F named the rationale: an institution evaluating SCCGUB
for a constitutional-court use case must verify the moat without
trusting the Rust toolchain or the Rust implementation specifically.
A Rust-only verifier still has a hidden trust assumption: "the
reviewer must read Rust well enough to confirm the verifier is
correct." Cross-language implementations remove that assumption by
proving **the verifier semantics are language-portable**, not bound
to any single implementation's quirks.

## §B Languages and ordering

| Language | Phase | Rationale |
|---|---|---|
| **Python** | §A.1 (this patch's first port) | Most accessible to non-engineering reviewers (regulators, counsel, scientists). Pure-stdlib implementation feasible (no third-party crypto deps). Broadest cross-disciplinary reach. Becomes the **reference port** for downstream language ports. |
| **Go** | §B.1 (Patch-09 §B, separate PR) | Most common language for production institutional infrastructure. Strong static-typing parity with Rust. |
| **TypeScript** | §C.1 (Patch-09 §C, separate PR) | Web-deployment access path; CI-integration friendly via npm; suitable for the public-verification-endpoint scope (POSITIONING §11). |

**This patch's scope: Python only.** Go and TypeScript are named
here so future patches know the obligation exists. The Python
implementation establishes the cross-language semantic baseline; Go
and TypeScript ports verify-against the Python and Rust outputs.

## §C Cross-language semantic baseline

All language ports MUST produce **byte-identical** verifier output
(ok/violation + violation details) for byte-identical inputs.
"Byte-identical" means:

- Same `Ok(())` vs same `CeilingViolation` variant.
- Same `transition_height`, `ceiling_field` (by canonical name),
  `before_value`, `after_value` numeric values.
- Same short-circuit behavior on first violation.
- Same handling of edge cases (empty history, `activation_height = 0`,
  non-monotonic history, missing-at-height read failure,
  unreadable-genesis read failure).

The verifier is a pure function, so cross-language equivalence is a
mathematical property, not an engineering aspiration.

## §D Python port specification

### §D.1 Package structure

```
crates/sccgub-audit-py/
    pyproject.toml             # Python packaging metadata
    README.md                  # User-facing documentation
    sccgub_audit/
        __init__.py            # Public exports
        field.py               # CeilingFieldId enum + field_value
        violation.py           # CeilingViolation dataclass
        chain_state.py         # ChainStateView protocol + JsonChainStateFixture
        verifier.py            # verify_ceilings_unchanged_since_genesis
        cli.py                 # Standalone CLI entry point
    tests/
        test_field.py
        test_violation.py
        test_chain_state.py
        test_verifier.py
        test_cross_language_conformance.py
```

The directory **lives alongside** the Rust `sccgub-audit` crate
under `crates/`, not in a separate top-level location. Rationale:
keeps the cross-language family discoverable in one place;
operators who clone the repo see all language ports together.

### §D.2 Python version requirement

**Python 3.10 or newer**. Justification:

- `match` statements (PEP 634, Python 3.10+) match the exhaustive
  `match` discipline of the Rust verifier per PATCH_08 §B.4. A
  missing `CeilingFieldId` variant produces a Python warning at
  runtime; combined with mypy strict mode (recommended) it
  surfaces at type-check time.
- Type annotations + `dataclass` + `Enum` give Rust-equivalent
  type discipline without third-party libraries.
- 3.10 is widely available in regulated-institution environments
  (RHEL, Ubuntu LTS, macOS).

### §D.3 Dependency policy

**Pure standard library only.** No `pip install` required to run
the verifier or its tests. Rationale matches PATCH_08 §C.2: the
verifier exists to be checked by parties who do not trust the rest
of the substrate; pulling in third-party Python packages
re-introduces the same kind of trust-the-supply-chain problem the
Rust verifier's dependency isolation was designed to avoid.

If `pytest` is available, tests run via `pytest`. If only stdlib
`unittest` is available, every test must also be runnable via
`python -m unittest discover`. Tests therefore use `unittest`-
compatible assertions.

### §D.4 Public API surface

Mirror the Rust public surface module-for-module:

```python
from sccgub_audit import (
    verify_ceilings_unchanged_since_genesis,
    ChainStateView,
    JsonChainStateFixture,
    ChainStateError,
    CeilingFieldId,
    CeilingValue,
    CeilingViolation,
)
```

`ChainStateView` is a `typing.Protocol` (Python's structural typing
analog to a Rust trait). `JsonChainStateFixture` is a `dataclass`.
`CeilingFieldId` is an `Enum`. `CeilingViolation` is an exception
subclass also usable as a typed result via discriminated dataclass
union (one dataclass per Rust enum variant).

### §D.5 CLI surface

Mirror the Rust CLI:

```text
python -m sccgub_audit.cli verify-ceilings --chain-state <path>
python -m sccgub_audit.cli verify-ceilings --chain-state <path> --json
```

Same exit codes as Rust (0 = ok, 1 = violation, 2 = input error)
per PATCH_08 §C.4.

For convenience, the Python package may also install a
`sccgub-audit-py` entry-point script via `pyproject.toml`'s
`[project.scripts]`. Distinguishable from Rust binary by the `-py`
suffix to avoid name collision in operator environments where
both are installed.

### §D.6 JSON fixture format

The Python port reads the **identical JSON fixture format** the
Rust port produces. Cross-language conformance depends on this:
fixtures generated by the Rust conformance harness are loaded by
the Python verifier without any format conversion.

This requires the JSON encoding of `ConstitutionalCeilings`,
`ChainVersionTransition`, and `JsonChainStateFixture` to be:

- Field-order-independent (JSON object key order doesn't matter
  for value comparison)
- Numeric-format-portable (Python `int` is unbounded but i128
  values must serialize as JSON numbers within range; Python
  reads them as `int` regardless)
- Byte-array-format-stable (Hash = `[u8; 32]` serializes as a
  32-element JSON array of integers in both languages; both
  implementations must accept this format)

Per **PATCH_07 §D.4** discipline, no canonical-encoding ambiguity
is permitted across language boundaries.

## §E Cross-language conformance harness

### §E.1 Shared fixtures directory

```
crates/sccgub-audit/conformance-fixtures/
    <case-name>.json          # JSON fixture (input)
    <case-name>.expected      # Expected verifier output (one of: ok, violation:<details>)
```

Fixtures are generated **once** by the Rust conformance binary
(`sccgub-audit-conformance` per PATCH_08 §D.3) and committed to
the repository. They are not regenerated per-test-run; the
fixture set is the **canonical conformance corpus** that all
language ports must satisfy.

A new conformance fixture requires both:

1. The Rust verifier produces the documented expected output.
2. Every language port also produces that output.

### §E.2 Shared expected-output format

```text
ok
violation:FieldValueChanged:transition_height=<u64>:ceiling_field=<name>:before_value=<int>:after_value=<int>
violation:HistoryStructurallyInvalid
violation:GenesisCeilingsUnreadable
violation:CeilingsUnreadableAtTransition:transition_height=<u64>
```

Plain text, line-oriented, easy to diff. Each language port emits
this format from its CLI for conformance comparison; the
cross-language test harness diffs language-pair outputs and
disagreement is a hard failure.

### §E.3 Test execution

A new top-level script `scripts/cross-language-conformance.sh`
(or `.ps1`/`.py` for cross-OS) executes the verifier in every
shipped language against every conformance fixture, captures
output, and asserts byte-identical agreement.

CI runs this script as a separate job after the per-language test
jobs. A disagreement fails CI.

## §F Test coverage requirements

The Python port replicates **every test case from the Rust port's
27 unit tests + 10 conformance oracle cases** with equivalent
assertions. Per-language test totals:

- Python: 37 tests minimum (27 unit + 10 conformance equivalents)
- Go (Patch-09 §B): 37 tests minimum
- TypeScript (Patch-09 §C): 37 tests minimum

A test in Rust that has no equivalent in a language port is a
specification gap that fails CI.

## §G What this patch does NOT ship

Per discipline-of-named-deferrals:

- **Go implementation**: deferred to Patch-09 §B (separate PR).
- **TypeScript implementation**: deferred to Patch-09 §C (separate
  PR).
- **Binary snapshot reader**: PATCH_08 §C.4 deferred to "Patch-09";
  re-deferred to Patch-09 §D as a fourth follow-up. Each language
  port currently reads the JSON fixture format only.
- **Public verification endpoint** (POSITIONING §11): operator
  scope, not Patch-09.
- **PyPI publication of `sccgub-audit-py`**: out of scope.
  Operators install via `pip install -e crates/sccgub-audit-py`
  from a clone, or via `python -m crates.sccgub-audit-py.sccgub_audit.cli`.
  PyPI publication can happen after at least one institutional
  pilot has reviewed the Python source.

## §H Verification of Patch-09 itself

Same review standard as PATCH_08 §F:

- **Two-pass review**: spec PR (this document) and Python
  implementation PR are reviewed separately.
- **Conformance gating**: implementation PR cannot merge unless
  every conformance fixture from `crates/sccgub-audit/
  conformance-fixtures/` produces byte-identical output between
  Rust and Python.
- **External review preferred** if any reviewer outside the
  project is available, particularly for the Python implementation
  since it's the broadest-reach reference port.

## §I §13 compliance

This PR adds a spec doc and does **not** change runtime behavior.
Per POSITIONING §14 amendment-process discipline, no positioning
amendment required.

The Python implementation PR that follows **may** require a small
POSITIONING amendment if it reveals semantic ambiguities in §11's
"cross-implementable in alternative languages" claim that need
clarification. Anticipated revisions are minor and within the
spirit of §11's commitment.

## §J Forward references

| Patch | Scope (not yet scheduled) |
|---|---|
| Patch-09 §A.1 implementation PR | Python verifier per §D, with conformance harness wiring per §E. Same PR may add the conformance-fixtures directory population step. |
| Patch-09 §B (separate spec amendment + impl) | Go verifier. Reuses the Python conformance corpus. |
| Patch-09 §C (separate spec amendment + impl) | TypeScript verifier. Reuses the Python conformance corpus. |
| Patch-09 §D | Binary snapshot reader for the CLI's `--chain-state` flag (PATCH_08 §C.4 deferral). |
| Patch-N (PQC per POSITIONING §8.6) | Verifier must explicitly recognize PQC activation as a non-ceiling-raising chain-version transition; this property must be tested in every language port's conformance corpus. |

---

**End of PATCH_09 spec.** Python implementation PR follows.
