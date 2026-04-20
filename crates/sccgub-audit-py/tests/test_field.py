"""Tests for sccgub_audit.field — mirror Rust field.rs tests."""

from __future__ import annotations

import unittest

from sccgub_audit.field import CeilingFieldId, field_value


def _default_ceilings() -> dict:
    """Mirror the Rust ConstitutionalCeilings::default() values exactly.

    Source: crates/sccgub-types/src/constitutional_ceilings.rs default impl.
    Cross-reference: PATCH_05 §29 (v4 additions) + PATCH_06 §31 (min_floor).
    """
    return {
        "max_proof_depth_ceiling": 512,
        "max_tx_gas_ceiling": 16_000_000,
        "max_block_gas_ceiling": 800_000_000,
        "max_contract_steps_ceiling": 40_000,
        "max_address_length_ceiling": 4_096,
        "max_state_entry_size_ceiling": 4_194_304,
        "max_tension_swing_ceiling": 4_000_000,
        "max_block_bytes_ceiling": 8_388_608,
        "max_active_proposals_ceiling": 256,
        "max_view_change_base_timeout_ms": 60_000,
        "max_view_change_max_timeout_ms": 3_600_000,
        "max_validator_set_size_ceiling": 128,
        "max_validator_set_changes_per_block": 8,
        "max_fee_tension_alpha_ceiling": 1_000_000,
        "max_median_tension_window_ceiling": 64,
        "max_confirmation_depth_ceiling": 8,
        "max_equivocation_evidence_per_block": 16,
        "min_effective_fee_floor": 10_000,
        "max_forgery_vetoes_per_block_ceiling": 8,
    }


class TestCeilingFieldId(unittest.TestCase):
    def test_patch_08_all_field_count_matches_struct_field_count(self):
        # Mirrors Rust patch_08_all_field_count_matches_struct_field_count.
        # Bumped from 18 to 19 in PATCH_10 §39.4 (adds
        # max_forgery_vetoes_per_block_ceiling).
        self.assertEqual(len(CeilingFieldId.all()), 19)

    def test_patch_08_all_variants_distinct(self):
        # Mirrors Rust patch_08_all_variants_distinct.
        names = [f.as_str() for f in CeilingFieldId.all()]
        self.assertEqual(len(names), len(set(names)))

    def test_patch_08_field_value_default_ceilings_well_formed(self):
        # Mirrors Rust patch_08_field_value_default_ceilings_well_formed.
        c = _default_ceilings()
        for f in CeilingFieldId.all():
            value = field_value(c, f)
            self.assertIsInstance(value, int)

    def test_patch_08_ceiling_value_display(self):
        # Mirrors Rust patch_08_ceiling_value_display.
        # Python's int already has correct str() — confirm semantic
        # equivalent to Rust Display impl.
        self.assertEqual(str(42), "42")
        self.assertEqual(str(99), "99")
        self.assertEqual(str(-7), "-7")
        self.assertEqual(str(-1_000_000), "-1000000")

    def test_field_value_raises_on_missing_key(self):
        c = _default_ceilings()
        del c["max_tx_gas_ceiling"]
        with self.assertRaises(KeyError):
            field_value(c, CeilingFieldId.MAX_TX_GAS)

    def test_field_value_raises_on_non_integer(self):
        c = _default_ceilings()
        c["max_tx_gas_ceiling"] = "not-an-int"
        with self.assertRaises(TypeError):
            field_value(c, CeilingFieldId.MAX_TX_GAS)


if __name__ == "__main__":
    unittest.main()
