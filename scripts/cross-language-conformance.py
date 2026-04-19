#!/usr/bin/env python3
"""Cross-language conformance harness per PATCH_09 §E.

Runs every shipped language port of the ceiling-immutability
verifier against every fixture in
``crates/sccgub-audit/conformance-fixtures/`` and asserts
**byte-identical** agreement with the canonical ``.expected``
output.

Per PATCH_09 §C semantic baseline, all language ports MUST
produce identical output for identical input. A disagreement is
a hard failure (exit 1) that fails CI.

Currently checks:
    - Rust port (cargo run -p sccgub-audit -- verify-ceilings ...)
    - Python port (python -m sccgub_audit.cli verify-ceilings ...)
    - TypeScript port (node crates/sccgub-audit-ts/dist/cli.js verify-ceilings ...)

Future patches add:
    - Go port (Patch-09 §B)
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
FIXTURES_DIR = REPO_ROOT / "crates" / "sccgub-audit" / "conformance-fixtures"
PY_PACKAGE_DIR = REPO_ROOT / "crates" / "sccgub-audit-py"
TS_PACKAGE_DIR = REPO_ROOT / "crates" / "sccgub-audit-ts"
TS_CLI_DIST = TS_PACKAGE_DIR / "dist" / "cli.js"


def run_rust_verifier(fixture_path: Path) -> tuple[int, str]:
    """Run the Rust port via cargo. Returns (exit_code, stdout)."""
    result = subprocess.run(
        [
            "cargo",
            "run",
            "-q",
            "-p",
            "sccgub-audit",
            "--bin",
            "sccgub-audit",
            "--",
            "verify-ceilings",
            "--chain-state",
            str(fixture_path),
            "--conformance",
        ],
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
    )
    return result.returncode, result.stdout


def run_python_verifier(fixture_path: Path) -> tuple[int, str]:
    """Run the Python port. Returns (exit_code, stdout)."""
    env = os.environ.copy()
    # Make sure Python finds the sccgub_audit package without
    # requiring a pip install.
    env["PYTHONPATH"] = str(PY_PACKAGE_DIR) + os.pathsep + env.get("PYTHONPATH", "")
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "sccgub_audit.cli",
            "verify-ceilings",
            "--chain-state",
            str(fixture_path),
            "--conformance",
        ],
        cwd=str(REPO_ROOT),
        env=env,
        capture_output=True,
        text=True,
    )
    return result.returncode, result.stdout


def run_typescript_verifier(fixture_path: Path) -> tuple[int, str]:
    """Run the TypeScript port (compiled to dist/cli.js). Returns (exit_code, stdout).

    Per PATCH_09 §D.3 the TS port is pure stdlib (Node built-ins only) and is
    consumed via `node crates/sccgub-audit-ts/dist/cli.js`. The harness
    expects `npm install && npx tsc` (or equivalent) to have produced
    `dist/cli.js` ahead of time; CI handles this via the
    `cross-language-conformance` job's build step.
    """
    if not TS_CLI_DIST.exists():
        raise FileNotFoundError(
            f"TS CLI not built: {TS_CLI_DIST} missing. "
            f"Run `npm install && npx tsc` in {TS_PACKAGE_DIR} first "
            f"(or rely on the CI job to build it)."
        )
    result = subprocess.run(
        [
            "node",
            str(TS_CLI_DIST),
            "verify-ceilings",
            "--chain-state",
            str(fixture_path),
            "--conformance",
        ],
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
    )
    return result.returncode, result.stdout


def main() -> int:
    if not FIXTURES_DIR.exists():
        print(
            f"FAIL: fixtures directory not found: {FIXTURES_DIR}\n"
            f"Run `cargo run -p sccgub-audit --bin sccgub-audit-conformance -- "
            f"--emit-fixtures {FIXTURES_DIR}` first.",
            file=sys.stderr,
        )
        return 2

    json_fixtures = sorted(FIXTURES_DIR.glob("*.json"))
    if not json_fixtures:
        print(f"FAIL: no .json fixtures in {FIXTURES_DIR}", file=sys.stderr)
        return 2

    disagreements: list[str] = []
    languages = [
        ("rust", run_rust_verifier),
        ("python", run_python_verifier),
        ("typescript", run_typescript_verifier),
    ]

    print(
        f"cross-language-conformance: {len(json_fixtures)} fixture(s) × "
        f"{len(languages)} language port(s)"
    )

    for fixture in json_fixtures:
        case_name = fixture.stem
        expected_path = fixture.with_suffix(".expected")
        if not expected_path.exists():
            print(f"  {case_name}: SKIP (no .expected file)")
            continue
        expected = expected_path.read_text(encoding="utf-8").strip()

        per_language_outputs = {}
        for lang_name, runner in languages:
            _exit, stdout = runner(fixture)
            actual = stdout.strip()
            per_language_outputs[lang_name] = actual
            if actual != expected:
                disagreements.append(
                    f"{case_name} [{lang_name}]: expected={expected!r} "
                    f"actual={actual!r}"
                )

        # Cross-language byte-identical check (in case both disagree
        # with .expected in the same way — still a violation per §C
        # semantic baseline).
        first_lang = list(per_language_outputs.keys())[0]
        first_out = per_language_outputs[first_lang]
        for lang_name, actual in per_language_outputs.items():
            if actual != first_out:
                disagreements.append(
                    f"{case_name}: language disagreement "
                    f"{first_lang}={first_out!r} vs {lang_name}={actual!r}"
                )

        status = "PASS" if all(o == expected for o in per_language_outputs.values()) else "FAIL"
        print(f"  {case_name}: {status}")

    if disagreements:
        print()
        print(f"FAILED: {len(disagreements)} disagreement(s)")
        for d in disagreements:
            print(f"  - {d}")
        return 1

    print()
    print("ALL FIXTURES AGREE — every language port matches canonical .expected")
    return 0


if __name__ == "__main__":
    sys.exit(main())
