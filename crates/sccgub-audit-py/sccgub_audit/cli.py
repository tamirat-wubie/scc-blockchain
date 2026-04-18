"""sccgub-audit-py CLI.

Mirrors the Rust binary's surface per PATCH_08 §C.4 + PATCH_09 §D.5.

Subcommand:
    verify-ceilings --chain-state <path> [--json] [--conformance]

Exit codes (matching Rust):
    0 = Ok (verifier returned None / Rust Ok(()))
    1 = CeilingViolation
    2 = malformed input or I/O error

Per §D.5 the entry-point script is `sccgub-audit-py` (the `-py`
suffix avoids name collision with the Rust binary in operator
environments where both are installed).
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Optional

from .chain_state import load_fixture_from_json
from .verifier import verify_ceilings_unchanged_since_genesis
from .violation import (
    CeilingViolation,
    CeilingsUnreadableAtTransition,
    FieldValueChanged,
    GenesisCeilingsUnreadable,
    HistoryStructurallyInvalid,
    violation_kind,
)


def main(argv: Optional[list] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="sccgub-audit-py",
        description=(
            "External moat-verifier for SCCGUB (Python port). "
            "Per PATCH_08.md and POSITIONING.md §11. "
            "Pure-stdlib, dependency-isolated by design."
        ),
    )
    sub = parser.add_subparsers(dest="command", required=True)

    verify = sub.add_parser(
        "verify-ceilings",
        help=(
            "Verify that no ConstitutionalCeilings field has been "
            "raised (or otherwise changed) since genesis."
        ),
    )
    verify.add_argument(
        "--chain-state",
        required=True,
        help="Path to a JSON-encoded JsonChainStateFixture.",
    )
    verify.add_argument(
        "--json",
        action="store_true",
        help="Emit machine-readable JSON output.",
    )
    verify.add_argument(
        "--conformance",
        action="store_true",
        help=(
            "Emit conformance-format output per PATCH_09 §E.2 "
            "(plain-text, line-oriented, easy to diff across "
            "language ports)."
        ),
    )

    args = parser.parse_args(argv)

    if args.command == "verify-ceilings":
        return _verify_ceilings(args.chain_state, args.json, args.conformance)
    return 2


def _verify_ceilings(chain_state_path: str, json_output: bool, conformance: bool) -> int:
    try:
        fixture = load_fixture_from_json(chain_state_path)
    except FileNotFoundError as e:
        _emit_input_error(json_output, conformance, str(e))
        return 2
    except (json.JSONDecodeError, KeyError, TypeError, ValueError) as e:
        _emit_input_error(json_output, conformance, f"could not parse JSON fixture: {e}")
        return 2

    result = verify_ceilings_unchanged_since_genesis(fixture)
    if result is None:
        _emit_ok(json_output, conformance)
        return 0
    _emit_violation(json_output, conformance, result)
    return 1


def _emit_ok(json_output: bool, conformance: bool) -> None:
    if conformance:
        # Per PATCH_09 §E.2 expected-output format.
        print("ok")
    elif json_output:
        payload = {"result": "ok", "message": "ceilings unchanged since genesis"}
        print(json.dumps(payload))
    else:
        print("OK: ceilings unchanged since genesis. Moat HELD.")


def _emit_violation(json_output: bool, conformance: bool, v: CeilingViolation) -> None:
    if conformance:
        # Per PATCH_09 §E.2 expected-output format.
        kind = violation_kind(v)
        if isinstance(v, FieldValueChanged):
            print(
                f"violation:{kind}:transition_height={v.transition_height}:"
                f"ceiling_field={v.ceiling_field.as_str()}:"
                f"before_value={v.before_value}:after_value={v.after_value}"
            )
        elif isinstance(v, CeilingsUnreadableAtTransition):
            print(f"violation:{kind}:transition_height={v.transition_height}")
        else:
            print(f"violation:{kind}")
    elif json_output:
        payload = {
            "result": "violation",
            "violation": _violation_to_json(v),
        }
        print(json.dumps(payload))
    else:
        print(f"VIOLATION: {v}")


def _violation_to_json(v: CeilingViolation) -> dict:
    if isinstance(v, FieldValueChanged):
        return {
            "kind": "FieldValueChanged",
            "transition_height": v.transition_height,
            "ceiling_field": v.ceiling_field.as_str(),
            "before_value": v.before_value,
            "after_value": v.after_value,
        }
    if isinstance(v, GenesisCeilingsUnreadable):
        return {"kind": "GenesisCeilingsUnreadable", "reason": v.reason}
    if isinstance(v, CeilingsUnreadableAtTransition):
        return {
            "kind": "CeilingsUnreadableAtTransition",
            "transition_height": v.transition_height,
            "reason": v.reason,
        }
    if isinstance(v, HistoryStructurallyInvalid):
        return {"kind": "HistoryStructurallyInvalid", "reason": v.reason}
    return {"kind": "unknown", "repr": repr(v)}


def _emit_input_error(json_output: bool, conformance: bool, msg: str) -> None:
    if conformance:
        # Conformance protocol does not have an explicit
        # "input-error" line; emit nothing on stdout and only
        # surface on stderr so the cross-language harness still
        # diffs cleanly. Real failures are caught via exit code 2.
        print(f"INPUT ERROR: {msg}", file=sys.stderr)
    elif json_output:
        payload = {"result": "input_error", "message": msg}
        print(json.dumps(payload), file=sys.stderr)
    else:
        print(f"INPUT ERROR: {msg}", file=sys.stderr)


if __name__ == "__main__":
    sys.exit(main())
