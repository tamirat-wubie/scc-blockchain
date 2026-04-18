# sccgub-audit-py

Python port of the SCCGUB moat verifier.

**Spec:** PATCH_08.md §C (verifier contract) + PATCH_09.md §A.1 (language ordering: Python first).

**Guarantee:** Given an identical `JsonChainStateFixture`, this crate produces byte-identical conformance-format output to the Rust reference implementation in `crates/sccgub-audit`. Cross-language agreement is enforced by `scripts/cross-language-conformance.py` on every CI run.

## Why a second port exists

POSITIONING.md §11 commits SCCGUB to a *cross-language* moat commitment: the claim that "no governance path can raise a constitutional ceiling" is only as strong as the set of verifiers a third party can run to check it. A single-language verifier is a single-implementation moat. Adding language ports shifts the trust surface from "one Rust crate" to "any two independent implementations agree" — which is harder to compromise and easier for external reviewers to audit cold.

Python is the first port per PATCH_09 §B (language ordering: Python → Go → TypeScript) because (a) it has the widest audit-community reach, (b) it has zero third-party dependencies when written against the 3.10+ stdlib, and (c) dataclass + Enum + Protocol map cleanly to Rust struct + enum + trait without semantic drift.

## Scope

**In scope (§A.1):**
- `verify_ceilings_unchanged_since_genesis(chain: ChainStateView) -> Optional[CeilingViolation]`
- `JsonChainStateFixture` — CLI v1 input format, identical JSON shape to the Rust crate.
- `sccgub-audit-py` CLI binary with `verify-ceilings --chain-state <path>` subcommand; exit codes 0/1/2 per PATCH_08 §C.4; optional `--conformance` output format for cross-language diff.
- 30+ unit tests mirroring every Rust test case per PATCH_09 §F coverage requirement.

**Out of scope (deferred):**
- Binary snapshot format (PATCH_09 §D defers to future patch).
- Go and TypeScript ports (PATCH_09 §B language ordering).
- Any consensus-layer function. This crate is read-only and replay-free by design.

## Requirements

- Python **3.10+**.
- No third-party runtime dependencies. Pure stdlib per PATCH_09 §D.3.
- Optional: `pytest` for richer test output (unittest also works).

## Install (editable)

```bash
pip install -e crates/sccgub-audit-py
```

Or run without installing:

```bash
PYTHONPATH=crates/sccgub-audit-py python -m sccgub_audit.cli verify-ceilings --chain-state path/to/fixture.json
```

## Usage

### Library

```python
from sccgub_audit import (
    verify_ceilings_unchanged_since_genesis,
    load_fixture_from_json,
)

with open("fixture.json") as f:
    fixture = load_fixture_from_json(f.read())

violation = verify_ceilings_unchanged_since_genesis(fixture)
if violation is None:
    print("OK: ceilings unchanged since genesis. Moat HELD.")
else:
    print(f"VIOLATION: {violation}")
```

### CLI

```bash
sccgub-audit-py verify-ceilings --chain-state fixture.json
# OK: ceilings unchanged since genesis. Moat HELD.

sccgub-audit-py verify-ceilings --chain-state fixture.json --json
# {"result": "ok", "message": "ceilings unchanged since genesis"}

sccgub-audit-py verify-ceilings --chain-state fixture.json --conformance
# ok
```

Exit codes:

| Code | Meaning |
|------|---------|
| 0    | `Ok(())` — ceilings unchanged since genesis |
| 1    | `CeilingViolation` — a ceiling was raised, structurally invalid history, or field drift detected |
| 2    | I/O or malformed-input error |

## Running tests

```bash
cd crates/sccgub-audit-py
python -m unittest discover -s tests -v
```

Expected: 30+ tests, all pass.

## Cross-language conformance

To verify this port agrees byte-for-byte with the Rust reference implementation:

```bash
# 1. Emit canonical fixtures from the Rust conformance binary.
cargo run -p sccgub-audit --bin sccgub-audit-conformance -- \
    --emit-fixtures crates/sccgub-audit/conformance-fixtures

# 2. Run every fixture through every language port and diff against .expected.
python scripts/cross-language-conformance.py
```

A single disagreement is a hard failure (exit 1) and fails CI. PATCH_09 §C semantic baseline: **all language ports MUST produce identical output for identical input.**

## Layout

```
crates/sccgub-audit-py/
├── pyproject.toml           # setuptools, Python 3.10+, no runtime deps
├── README.md                # this file
├── sccgub_audit/
│   ├── __init__.py          # public API surface
│   ├── field.py             # CeilingFieldId enum (18 canonical fields)
│   ├── violation.py         # CeilingViolation variants + kind()
│   ├── chain_state.py       # ChainStateView Protocol, JsonChainStateFixture
│   ├── verifier.py          # verify_ceilings_unchanged_since_genesis
│   └── cli.py               # argparse-based CLI; exit codes per PATCH_08 §C.4
└── tests/
    ├── test_field.py
    ├── test_violation.py
    ├── test_chain_state.py
    └── test_verifier.py
```

## Independence discipline

Per PATCH_08.md §C.4 the verifier must be **independently compilable and runnable** by any third party with read access to the chain log. This crate:

- has zero third-party runtime dependencies;
- depends on no SCCGUB runtime crate;
- performs no I/O beyond reading the fixture passed to the CLI;
- uses no wall-clock, randomness, or environment input;
- is a pure function of its `ChainStateView` input.

These constraints are what make the verifier an external-trust anchor rather than a node-internal sanity check.

## Related documents

- **PATCH_08.md** — verifier contract, `CeilingViolation` taxonomy, fixture schema.
- **PATCH_09.md** — cross-language extension, language ordering, conformance harness.
- **POSITIONING.md §11** — why the moat commitment is cross-language.
- **PROTOCOL.md v2.0 §17** + **PATCH_05.md §29** — the `ConstitutionalCeilings` struct this verifier witnesses.
