"""Tests for sccgub_audit.verifier — mirror Rust verifier.rs tests.

Every Rust test in `crates/sccgub-audit/src/verifier.rs` has an
equivalent here per PATCH_09 §F coverage requirement.
"""

from __future__ import annotations

import unittest
from typing import List, Optional, Tuple

from sccgub_audit.chain_state import (
    ChainStateError,
    CeilingsMissingAtHeight,
    ChainVersionTransition,
    JsonChainStateFixture,
    genesis_preserved_fixture,
)
from sccgub_audit.field import CeilingFieldId
from sccgub_audit.verifier import verify_ceilings_unchanged_since_genesis
from sccgub_audit.violation import (
    CeilingsUnreadableAtTransition,
    FieldValueChanged,
    GenesisCeilingsUnreadable,
    HistoryStructurallyInvalid,
)


def _default_ceilings() -> dict:
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
    }


def _t(activation: int, to_v: int) -> ChainVersionTransition:
    return ChainVersionTransition(
        activation_height=activation,
        from_version=to_v - 1,
        to_version=to_v,
        upgrade_spec_hash=[0xAA] * 32,
        proposal_id=[0xBB] * 32,
    )


def _fixture_with_drifted_field(
    history,
    drift_at_height: int,
    mutate,
) -> JsonChainStateFixture:
    """Mirror Rust verifier.rs `fixture_with_drifted_field`."""
    genesis = _default_ceilings()
    by_height: List[Tuple[int, dict]] = []
    for tr in history:
        if tr.activation_height > 0:
            by_height.append((tr.activation_height - 1, dict(genesis)))
        here = dict(genesis)
        if tr.activation_height == drift_at_height:
            mutate(here)
        by_height.append((tr.activation_height, here))
    return JsonChainStateFixture(
        genesis_block_hash=[0] * 32,
        genesis_ceilings=dict(genesis),
        chain_version_history_list=list(history),
        ceilings_by_height=by_height,
    )


class TestVerifier(unittest.TestCase):
    # ── Mandatory case 1: empty history → None (Rust Ok(())) ──

    def test_patch_08_empty_history_returns_ok(self):
        f = genesis_preserved_fixture([0] * 32, _default_ceilings(), [])
        self.assertIsNone(verify_ceilings_unchanged_since_genesis(f))

    # ── Mandatory case 2 ──

    def test_patch_08_single_transition_preserved_returns_ok(self):
        f = genesis_preserved_fixture(
            [0] * 32, _default_ceilings(), [_t(100, 5)]
        )
        self.assertIsNone(verify_ceilings_unchanged_since_genesis(f))

    # ── Mandatory case 3 ──

    def test_patch_08_multiple_transitions_preserved_returns_ok(self):
        f = genesis_preserved_fixture(
            [0] * 32,
            _default_ceilings(),
            [_t(100, 5), _t(200, 6), _t(300, 7)],
        )
        self.assertIsNone(verify_ceilings_unchanged_since_genesis(f))

    # ── Mandatory case 4: per-CeilingFieldId drift detected (3 representative) ──

    def test_patch_08_drift_in_max_proof_depth_detected(self):
        def mutate(c):
            c["max_proof_depth_ceiling"] += 1

        f = _fixture_with_drifted_field([_t(100, 5)], 100, mutate)
        r = verify_ceilings_unchanged_since_genesis(f)
        self.assertIsInstance(r, FieldValueChanged)
        assert isinstance(r, FieldValueChanged)
        self.assertEqual(r.ceiling_field, CeilingFieldId.MAX_PROOF_DEPTH)

    def test_patch_08_drift_in_max_tx_gas_detected(self):
        def mutate(c):
            c["max_tx_gas_ceiling"] += 1

        f = _fixture_with_drifted_field([_t(100, 5)], 100, mutate)
        r = verify_ceilings_unchanged_since_genesis(f)
        self.assertIsInstance(r, FieldValueChanged)
        assert isinstance(r, FieldValueChanged)
        self.assertEqual(r.ceiling_field, CeilingFieldId.MAX_TX_GAS)

    def test_patch_08_drift_in_min_effective_fee_floor_detected(self):
        # Even a DECREASE counts as drift — the moat is "unchanged",
        # not "not-raised."
        def mutate(c):
            c["min_effective_fee_floor"] -= 1

        f = _fixture_with_drifted_field([_t(100, 5)], 100, mutate)
        r = verify_ceilings_unchanged_since_genesis(f)
        self.assertIsInstance(r, FieldValueChanged)
        assert isinstance(r, FieldValueChanged)
        self.assertEqual(r.ceiling_field, CeilingFieldId.MIN_EFFECTIVE_FEE_FLOOR)

    # ── Mandatory case 5: short-circuit on first violation ──

    def test_patch_08_short_circuits_on_first_violation(self):
        history = [_t(100, 5), _t(200, 6)]
        genesis = _default_ceilings()
        by_height = []
        by_height.append((99, dict(genesis)))
        h100 = dict(genesis)
        h100["max_proof_depth_ceiling"] += 10
        by_height.append((100, h100))
        by_height.append((199, dict(genesis)))
        h200 = dict(genesis)
        h200["max_tx_gas_ceiling"] += 999
        by_height.append((200, h200))

        f = JsonChainStateFixture(
            genesis_block_hash=[0] * 32,
            genesis_ceilings=dict(genesis),
            chain_version_history_list=history,
            ceilings_by_height=by_height,
        )
        r = verify_ceilings_unchanged_since_genesis(f)
        self.assertIsInstance(r, FieldValueChanged)
        assert isinstance(r, FieldValueChanged)
        self.assertEqual(r.transition_height, 100)
        self.assertEqual(r.ceiling_field, CeilingFieldId.MAX_PROOF_DEPTH)

    # ── Mandatory case 6: degenerate activation_height = 0 ──

    def test_patch_08_degenerate_activation_height_zero_handled(self):
        genesis = _default_ceilings()
        f = JsonChainStateFixture(
            genesis_block_hash=[0] * 32,
            genesis_ceilings=dict(genesis),
            chain_version_history_list=[_t(0, 1)],
            ceilings_by_height=[(0, dict(genesis))],
        )
        self.assertIsNone(verify_ceilings_unchanged_since_genesis(f))

    # ── Mandatory case 7: HistoryStructurallyInvalid ──

    def test_patch_08_non_monotonic_history_rejected(self):
        genesis = _default_ceilings()
        f = JsonChainStateFixture(
            genesis_block_hash=[0] * 32,
            genesis_ceilings=dict(genesis),
            chain_version_history_list=[_t(200, 6), _t(100, 5)],
            ceilings_by_height=[
                (99, dict(genesis)),
                (100, dict(genesis)),
                (199, dict(genesis)),
                (200, dict(genesis)),
            ],
        )
        r = verify_ceilings_unchanged_since_genesis(f)
        self.assertIsInstance(r, HistoryStructurallyInvalid)

    # ── Mandatory case 8: GenesisCeilingsUnreadable ──

    def test_patch_08_genesis_ceilings_unreadable_returns_genesis_unreadable(self):
        class UnreadableGenesisFixture:
            def genesis_block_hash(self):
                return [0] * 32

            def genesis_constitutional_ceilings(self):
                from sccgub_audit.chain_state import GenesisCeilingsMissing

                raise GenesisCeilingsMissing("synthetic missing")

            def chain_version_history(self):
                return []

            def ceilings_at_height(self, h):
                from sccgub_audit.chain_state import ChainStateIoError

                raise ChainStateIoError("never reached")

        r = verify_ceilings_unchanged_since_genesis(UnreadableGenesisFixture())
        self.assertIsInstance(r, GenesisCeilingsUnreadable)

    # ── Mandatory case 9: CeilingsUnreadableAtTransition ──

    def test_patch_08_missing_ceilings_at_transition_returns_unreadable_at_transition(self):
        genesis = _default_ceilings()
        f = JsonChainStateFixture(
            genesis_block_hash=[0] * 32,
            genesis_ceilings=dict(genesis),
            chain_version_history_list=[_t(100, 5)],
            ceilings_by_height=[],  # missing height 99 + 100
        )
        r = verify_ceilings_unchanged_since_genesis(f)
        self.assertIsInstance(r, CeilingsUnreadableAtTransition)
        assert isinstance(r, CeilingsUnreadableAtTransition)
        self.assertEqual(r.transition_height, 100)

    # ── Adversarial case 1: pre-transition height drift ──

    def test_patch_08_pre_transition_drift_detected(self):
        genesis = _default_ceilings()
        history = [_t(100, 5)]
        tampered = dict(genesis)
        tampered["max_block_gas_ceiling"] += 1000
        f = JsonChainStateFixture(
            genesis_block_hash=[0] * 32,
            genesis_ceilings=dict(genesis),
            chain_version_history_list=history,
            ceilings_by_height=[(99, tampered), (100, dict(genesis))],
        )
        r = verify_ceilings_unchanged_since_genesis(f)
        self.assertIsInstance(r, FieldValueChanged)
        assert isinstance(r, FieldValueChanged)
        self.assertEqual(r.ceiling_field, CeilingFieldId.MAX_BLOCK_GAS)
        self.assertEqual(r.transition_height, 100)

    # ── Adversarial case 2: encoding-portability sanity ──

    def test_patch_08_value_comparison_uses_value_equality_not_bytes(self):
        # Python equivalent of the Rust serialize+deserialize test.
        # The verifier compares ints via Python equality, which is
        # value-based and unbounded — so encoding endianness or
        # padding cannot trick the comparison.
        import json as _json

        g = _default_ceilings()
        text = _json.dumps(g)
        g2 = _json.loads(text)
        f1 = genesis_preserved_fixture([0] * 32, g, [_t(50, 5)])
        f2 = genesis_preserved_fixture([0] * 32, g2, [_t(50, 5)])
        self.assertIsNone(verify_ceilings_unchanged_since_genesis(f1))
        self.assertIsNone(verify_ceilings_unchanged_since_genesis(f2))

    # ── Adversarial case 3: drift in middle of long history ──

    def test_patch_08_drift_in_middle_of_long_history(self):
        genesis = _default_ceilings()
        history = [_t(100, 5), _t(200, 6), _t(300, 7), _t(400, 8), _t(500, 9)]
        by_height = []
        for tr in history:
            by_height.append((tr.activation_height - 1, dict(genesis)))
            here = dict(genesis)
            if tr.activation_height == 300:
                here["max_validator_set_size_ceiling"] += 1
            by_height.append((tr.activation_height, here))
        f = JsonChainStateFixture(
            genesis_block_hash=[0] * 32,
            genesis_ceilings=dict(genesis),
            chain_version_history_list=history,
            ceilings_by_height=by_height,
        )
        r = verify_ceilings_unchanged_since_genesis(f)
        self.assertIsInstance(r, FieldValueChanged)
        assert isinstance(r, FieldValueChanged)
        self.assertEqual(r.transition_height, 300)
        self.assertEqual(r.ceiling_field, CeilingFieldId.MAX_VALIDATOR_SET_SIZE)

    # ── Pure-function property ──

    def test_patch_08_verifier_is_pure_over_input(self):
        f = genesis_preserved_fixture(
            [0xAB] * 32,
            _default_ceilings(),
            [_t(100, 5), _t(200, 6)],
        )
        r1 = verify_ceilings_unchanged_since_genesis(f)
        r2 = verify_ceilings_unchanged_since_genesis(f)
        self.assertEqual(r1, r2)


if __name__ == "__main__":
    unittest.main()
