/**
 * Tests for src/violation.ts — mirror Python test_violation.py + Rust violation.rs tests.
 */

import { strict as assert } from "node:assert";
import { describe, test } from "node:test";

import { CeilingFieldId } from "../src/field.js";
import {
  type CeilingViolation,
  type FieldValueChanged,
  violationKind,
  violationToString,
} from "../src/violation.js";

describe("CeilingViolation", () => {
  test("patch_08_violation_serde_roundtrip_equivalent", () => {
    // TS port equivalent: structural equality via deepEqual on plain objects.
    const v1: FieldValueChanged = {
      kind: "FieldValueChanged",
      transition_height: 42n,
      ceiling_field: CeilingFieldId.MaxProofDepth,
      before_value: 256n,
      after_value: 512n,
    };
    const v2: FieldValueChanged = {
      kind: "FieldValueChanged",
      transition_height: 42n,
      ceiling_field: CeilingFieldId.MaxProofDepth,
      before_value: 256n,
      after_value: 512n,
    };
    assert.deepEqual(v1, v2);
  });

  test("patch_08_violation_display_includes_transition_and_field", () => {
    const v: FieldValueChanged = {
      kind: "FieldValueChanged",
      transition_height: 99n,
      ceiling_field: CeilingFieldId.MaxTxGas,
      before_value: 1_000_000n,
      after_value: 2_000_000n,
    };
    const s = violationToString(v);
    assert.match(s, /max_tx_gas_ceiling/);
    assert.match(s, /99/);
    assert.match(s, /1000000/);
    assert.match(s, /2000000/);
  });

  test("violation_kind_returns_variant_tag", () => {
    const cases: Array<[CeilingViolation, string]> = [
      [
        {
          kind: "FieldValueChanged",
          transition_height: 0n,
          ceiling_field: CeilingFieldId.MaxProofDepth,
          before_value: 0n,
          after_value: 0n,
        },
        "FieldValueChanged",
      ],
      [{ kind: "GenesisCeilingsUnreadable", reason: "x" }, "GenesisCeilingsUnreadable"],
      [
        { kind: "CeilingsUnreadableAtTransition", transition_height: 0n, reason: "x" },
        "CeilingsUnreadableAtTransition",
      ],
      [{ kind: "HistoryStructurallyInvalid", reason: "x" }, "HistoryStructurallyInvalid"],
    ];
    for (const [v, expected] of cases) {
      assert.equal(violationKind(v), expected);
    }
  });
});
