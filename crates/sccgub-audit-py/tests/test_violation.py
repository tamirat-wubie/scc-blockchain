"""Tests for sccgub_audit.violation — mirror Rust violation.rs tests."""

from __future__ import annotations

import unittest

from sccgub_audit.field import CeilingFieldId
from sccgub_audit.violation import (
    CeilingsUnreadableAtTransition,
    FieldValueChanged,
    GenesisCeilingsUnreadable,
    HistoryStructurallyInvalid,
    violation_kind,
)


class TestViolation(unittest.TestCase):
    def test_patch_08_violation_serde_roundtrip_equivalent(self):
        # Python equivalent of Rust patch_08_violation_serde_roundtrip.
        # Python uses dataclasses with frozen=True; equivalence test
        # is structural (two equally-constructed instances == each
        # other).
        v1 = FieldValueChanged(
            transition_height=42,
            ceiling_field=CeilingFieldId.MAX_PROOF_DEPTH,
            before_value=256,
            after_value=512,
        )
        v2 = FieldValueChanged(
            transition_height=42,
            ceiling_field=CeilingFieldId.MAX_PROOF_DEPTH,
            before_value=256,
            after_value=512,
        )
        self.assertEqual(v1, v2)

    def test_patch_08_violation_display_includes_transition_and_field(self):
        # Mirrors Rust patch_08_violation_display_includes_transition_and_field.
        v = FieldValueChanged(
            transition_height=99,
            ceiling_field=CeilingFieldId.MAX_TX_GAS,
            before_value=1_000_000,
            after_value=2_000_000,
        )
        s = str(v)
        self.assertIn("max_tx_gas_ceiling", s)
        self.assertIn("99", s)
        self.assertIn("1000000", s)
        self.assertIn("2000000", s)

    def test_violation_kind_returns_class_name(self):
        # New Python-side coverage; backs the conformance harness's
        # plain-text protocol per PATCH_09 §E.2.
        cases = [
            (FieldValueChanged(0, CeilingFieldId.MAX_PROOF_DEPTH, 0, 0), "FieldValueChanged"),
            (GenesisCeilingsUnreadable("x"), "GenesisCeilingsUnreadable"),
            (CeilingsUnreadableAtTransition(0, "x"), "CeilingsUnreadableAtTransition"),
            (HistoryStructurallyInvalid("x"), "HistoryStructurallyInvalid"),
        ]
        for v, expected in cases:
            self.assertEqual(violation_kind(v), expected)


if __name__ == "__main__":
    unittest.main()
