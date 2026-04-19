# sccgub-audit-ts

TypeScript port of the SCCGUB moat verifier.

**Spec:** PATCH_08.md §C (verifier contract) + PATCH_09.md §C (third language port: TypeScript).

**Guarantee:** Given an identical `JsonChainStateFixture`, this crate produces byte-identical conformance-format output to the Rust reference implementation in `crates/sccgub-audit` and the Python implementation in `crates/sccgub-audit-py`. Cross-language agreement is enforced by `scripts/cross-language-conformance.py` on every CI run.

## Why a third port exists

POSITIONING.md §11 commits SCCGUB to a *cross-language* moat commitment: the claim that "no governance path can raise a constitutional ceiling" is only as strong as the set of verifiers a third party can run to check it.

- Single-language verifier (Rust only) → moat is one implementation deep.
- Two-language verifier (Rust + Python) → moat survives one implementation having a hidden bug.
- Three-language verifier (Rust + Python + TypeScript) → moat reaches the runtime environments most institutional reviewers actually have at hand: production Rust services, regulator-friendly Python notebooks, and JavaScript / TypeScript web tooling.

The TypeScript port is specifically the **web-deployment access path** per PATCH_09 §B — suitable for CI integration via `npm`, browser-side trust-but-verify dashboards, and the public verification endpoint scope (POSITIONING §11).

## Scope

**In scope (PATCH_09 §C):**
- `verifyCeilingsUnchangedSinceGenesis(chain: ChainStateView): CeilingViolation | null`
- `JsonChainStateFixture` — CLI v1 input format, identical JSON shape to the Rust + Python crates.
- `sccgub-audit-ts` CLI binary with `verify-ceilings --chain-state <path>` subcommand; exit codes 0 / 1 / 2 per PATCH_08 §C.4; `--conformance` output format for cross-language diff.
- 36 unit tests via Node's built-in `node:test` runner (no third-party test framework).

**Out of scope (deferred):**
- Binary snapshot format (PATCH_09 §D defers to a future patch).
- Go port (PATCH_09 §B language ordering — separately tagged).
- Browser-bundle distribution (Node-only initial release; bundling for the web is a downstream concern).
- Any consensus-layer function. This crate is read-only and replay-free by design.

## Requirements

- Node.js **22+** (for `node:test`'s built-in glob support, top-level `bigint` literals, and `import.meta.url`). Node 20 lacks `--test` glob expansion, which the test runner relies on.
- TypeScript **5.x** for compilation (dev-time only; not a runtime dep).
- No third-party **runtime** dependencies. Pure Node built-ins per PATCH_09 §D.3.
- `tsx` is used in dev workflow to run TypeScript sources directly under `node --test`; CI compiles with `tsc` and runs the output.

## Install (from this repo)

```bash
cd crates/sccgub-audit-ts
npm install
npx tsc                # produces dist/
node dist/cli.js verify-ceilings --chain-state path/to/fixture.json
```

## Usage

### Library (TypeScript)

```typescript
import {
  verifyCeilingsUnchangedSinceGenesis,
  loadFixtureFromJson,
  violationToString,
} from "sccgub-audit-ts";

const fixture = loadFixtureFromJson("fixture.json");
const violation = verifyCeilingsUnchangedSinceGenesis(fixture);
if (violation === null) {
  console.log("OK: ceilings unchanged since genesis. Moat HELD.");
} else {
  console.log(`VIOLATION: ${violationToString(violation)}`);
}
```

### CLI

```bash
sccgub-audit-ts verify-ceilings --chain-state fixture.json
# OK: ceilings unchanged since genesis. Moat HELD.

sccgub-audit-ts verify-ceilings --chain-state fixture.json --json
# {"result":"ok","message":"ceilings unchanged since genesis"}

sccgub-audit-ts verify-ceilings --chain-state fixture.json --conformance
# ok
```

Exit codes:

| Code | Meaning                                                                 |
|------|-------------------------------------------------------------------------|
| 0    | Ok — ceilings unchanged since genesis (verifier returned `null`)        |
| 1    | `CeilingViolation` — drift, structurally invalid history, etc.          |
| 2    | I/O or malformed-input error                                            |

## Running tests

```bash
npm test
```

Expected: 36 tests, all pass. The suite includes 4 explicit regression
tests for **bigint precision in JSON parse** — see `chainState.test.ts`.
This was a real bug caught during the initial port: naive `JSON.parse`
returns IEEE-754 doubles, which collapse `1e16` and `1e16 - 1` to the
same value, making drift on `min_effective_fee_floor` (default 10^16)
invisible. The fix is `parseJsonPreservingBigInts`, which wraps unsafe-
range integer literals in a sentinel string and rehydrates them as
`bigint` via the standard reviver hook.

## Cross-language conformance

To verify this port agrees byte-for-byte with the Rust reference and
Python implementations:

```bash
# 1. Emit canonical fixtures from the Rust conformance binary.
cargo run -p sccgub-audit --bin sccgub-audit-conformance -- \
    --emit-fixtures crates/sccgub-audit/conformance-fixtures

# 2. Build the TS port.
(cd crates/sccgub-audit-ts && npm install && npx tsc)

# 3. Run every fixture through every language port and diff against .expected.
python scripts/cross-language-conformance.py
```

A single disagreement is a hard failure (exit 1) and fails CI. PATCH_09
§C semantic baseline: **all language ports MUST produce identical output
for identical input.**

Current baseline: 10 fixtures × 3 language ports = **30 byte-identical
runs**.

## Layout

```
crates/sccgub-audit-ts/
├── package.json             # Pure stdlib runtime (no deps); devDeps for tsc + tsx
├── tsconfig.json            # strict mode, ES2022, NodeNext modules
├── README.md                # this file
├── src/
│   ├── index.ts             # public API barrel
│   ├── field.ts             # CeilingFieldId + ALL_CEILING_FIELDS + fieldValue
│   ├── violation.ts         # CeilingViolation discriminated union + helpers
│   ├── chainState.ts        # ChainStateView interface + JsonChainStateFixture
│   ├── verifier.ts          # verifyCeilingsUnchangedSinceGenesis
│   └── cli.ts               # argparse-equivalent CLI; exit codes per PATCH_08 §C.4
└── tests/
    ├── field.test.ts
    ├── violation.test.ts
    ├── chainState.test.ts   # includes bigint precision regression cases
    └── verifier.test.ts
```

## Independence discipline

Per PATCH_08.md §C.4 the verifier must be **independently compilable
and runnable** by any third party with read access to the chain log.
This crate:

- has zero third-party **runtime** dependencies;
- depends on no SCCGUB runtime crate;
- performs no I/O beyond reading the fixture passed to the CLI;
- uses no wall-clock, randomness, or environment input;
- is a pure function of its `ChainStateView` input.

These constraints are what make the verifier an external-trust anchor
rather than a node-internal sanity check. The TypeScript port preserves
them.

## Implementation notes

### bigint everywhere on the value path

`CeilingValue` is `bigint`, not `number`. JavaScript's `number` is
IEEE-754 double; integers above 2^53 are not exactly representable.
Several ceilings (e.g., `min_effective_fee_floor` = 10^16) exceed this
boundary, and the upcoming i128 fee-tension fields will exceed it by
several orders of magnitude. Using `bigint` end-to-end ensures
byte-identical comparison with the Rust i128 source of truth.

### Discriminated union via `kind` literal

The Python port uses dataclasses + `Union[...]`. The Rust port uses an
`enum`. The TypeScript port uses an interface union with a `kind:
"FieldValueChanged" | …` literal-string discriminator — TypeScript's
idiomatic discriminated-union pattern with full exhaustiveness checking
in `switch (v.kind)`.

### CLI entry-point detection

`if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href)`
— uses `node:url`'s `pathToFileURL` rather than a string `file://`
concat, which would be wrong on Windows (backslash paths, spaces,
percent-encoding). This was caught during initial smoke-test.

## Related documents

- **PATCH_08.md** — verifier contract, `CeilingViolation` taxonomy, fixture schema.
- **PATCH_09.md §C** — TypeScript port specification.
- **POSITIONING.md §11** — why the moat commitment is cross-language.
- **PROTOCOL.md v2.0 §17** + **PATCH_05.md §29** — the `ConstitutionalCeilings` struct this verifier witnesses.
- **`crates/sccgub-audit/`** — Rust reference implementation.
- **`crates/sccgub-audit-py/`** — Python sister port.
