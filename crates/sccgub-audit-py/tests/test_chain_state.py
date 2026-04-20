"""Tests for sccgub_audit.chain_state — mirror Rust chain_state.rs tests."""

from __future__ import annotations

import json
import unittest

from sccgub_audit.chain_state import (
    CeilingsMissingAtHeight,
    ChainVersionTransition,
    JsonChainStateFixture,
    genesis_preserved_fixture,
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
        "max_forgery_vetoes_per_block_ceiling": 8,
    }


def _t(activation: int, to_v: int) -> ChainVersionTransition:
    return ChainVersionTransition(
        activation_height=activation,
        from_version=to_v - 1,
        to_version=to_v,
        upgrade_spec_hash=[0xAA] * 32,
        proposal_id=[0xBB] * 32,
    )


class TestJsonChainStateFixture(unittest.TestCase):
    def test_patch_08_genesis_preserved_includes_pre_and_post_heights(self):
        # Mirrors Rust patch_08_genesis_preserved_includes_pre_and_post_heights.
        c = _default_ceilings()
        h = [_t(100, 5), _t(200, 6)]
        f = genesis_preserved_fixture([0xCC] * 32, c, h)
        heights = [pair[0] for pair in f.ceilings_by_height]
        self.assertIn(99, heights)
        self.assertIn(100, heights)
        self.assertIn(199, heights)
        self.assertIn(200, heights)

    def test_patch_08_genesis_preserved_returns_genesis_ceilings_at_every_queried_height(self):
        c = _default_ceilings()
        h = [_t(50, 5)]
        f = genesis_preserved_fixture([0] * 32, c, h)
        self.assertEqual(f.ceilings_at_height(49), c)
        self.assertEqual(f.ceilings_at_height(50), c)

    def test_patch_08_ceilings_missing_at_unrequested_height(self):
        c = _default_ceilings()
        h = [_t(100, 5)]
        f = genesis_preserved_fixture([0] * 32, c, h)
        with self.assertRaises(CeilingsMissingAtHeight):
            f.ceilings_at_height(500)

    def test_patch_08_empty_history_fixture_well_formed(self):
        c = _default_ceilings()
        f = genesis_preserved_fixture([0] * 32, c, [])
        self.assertEqual(len(f.chain_version_history()), 0)
        self.assertEqual(f.genesis_constitutional_ceilings(), c)

    def test_patch_08_fixture_serde_roundtrip(self):
        # Python equivalent: JSON roundtrip via from_json + serialized
        # back to the same shape.
        c = _default_ceilings()
        h = [_t(100, 5)]
        f = genesis_preserved_fixture([0xDE] * 32, c, h)
        data = {
            "genesis_block_hash": f.genesis_block_hash,
            "genesis_ceilings": f.genesis_ceilings,
            "chain_version_history": [
                {
                    "activation_height": t.activation_height,
                    "from_version": t.from_version,
                    "to_version": t.to_version,
                    "upgrade_spec_hash": t.upgrade_spec_hash,
                    "proposal_id": t.proposal_id,
                }
                for t in f.chain_version_history()
            ],
            "ceilings_by_height": [[h, c] for (h, c) in f.ceilings_by_height],
        }
        text = json.dumps(data)
        back = JsonChainStateFixture.from_json(json.loads(text))
        self.assertEqual(back.genesis_block_hash, [0xDE] * 32)

    def test_patch_08_genesis_block_hash_returned(self):
        c = _default_ceilings()
        f = genesis_preserved_fixture([0x42] * 32, c, [])
        self.assertEqual(f.genesis_block_hash, [0x42] * 32)


if __name__ == "__main__":
    unittest.main()
