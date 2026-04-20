/**
 * Tests for src/chainState.ts — mirror Python test_chain_state.py
 * + Rust chain_state.rs tests.
 */

import { strict as assert } from "node:assert";
import { describe, test } from "node:test";

import {
  type ChainVersionTransition,
  type Ceilings,
  CeilingsMissingAtHeight,
  JsonChainStateFixture,
  chainVersionTransitionFromJson,
  genesisPreservedFixture,
  loadFixtureFromJson,
  parseJsonPreservingBigInts,
} from "../src/chainState.js";

function defaultCeilings(): Record<string, number> {
  return {
    max_proof_depth_ceiling: 512,
    max_tx_gas_ceiling: 16_000_000,
    max_block_gas_ceiling: 800_000_000,
    max_contract_steps_ceiling: 40_000,
    max_address_length_ceiling: 4_096,
    max_state_entry_size_ceiling: 4_194_304,
    max_tension_swing_ceiling: 4_000_000,
    max_block_bytes_ceiling: 8_388_608,
    max_active_proposals_ceiling: 256,
    max_view_change_base_timeout_ms: 60_000,
    max_view_change_max_timeout_ms: 3_600_000,
    max_validator_set_size_ceiling: 128,
    max_validator_set_changes_per_block: 8,
    max_fee_tension_alpha_ceiling: 1_000_000,
    max_median_tension_window_ceiling: 64,
    max_confirmation_depth_ceiling: 8,
    max_equivocation_evidence_per_block: 16,
    min_effective_fee_floor: 10_000,
    max_forgery_vetoes_per_block_ceiling: 8,
  };
}

function t(activation: bigint, toV: number): ChainVersionTransition {
  return {
    activation_height: activation,
    from_version: toV - 1,
    to_version: toV,
    upgrade_spec_hash: new Array<number>(32).fill(0xaa),
    proposal_id: new Array<number>(32).fill(0xbb),
  };
}

describe("JsonChainStateFixture", () => {
  test("patch_08_genesis_preserved_includes_pre_and_post_heights", () => {
    const c = defaultCeilings();
    const h = [t(100n, 5), t(200n, 6)];
    const f = genesisPreservedFixture(new Array<number>(32).fill(0xcc), c, h);
    const heights = f.ceilings_by_height.map(([h]) => h);
    assert.ok(heights.includes(99n));
    assert.ok(heights.includes(100n));
    assert.ok(heights.includes(199n));
    assert.ok(heights.includes(200n));
  });

  test("patch_08_genesis_preserved_returns_genesis_ceilings_at_every_queried_height", () => {
    const c = defaultCeilings();
    const h = [t(50n, 5)];
    const f = genesisPreservedFixture(new Array<number>(32).fill(0), c, h);
    assert.deepEqual(f.ceilingsAtHeight(49n), c);
    assert.deepEqual(f.ceilingsAtHeight(50n), c);
  });

  test("patch_08_ceilings_missing_at_unrequested_height", () => {
    const c = defaultCeilings();
    const h = [t(100n, 5)];
    const f = genesisPreservedFixture(new Array<number>(32).fill(0), c, h);
    assert.throws(() => f.ceilingsAtHeight(500n), CeilingsMissingAtHeight);
  });

  test("patch_08_empty_history_fixture_well_formed", () => {
    const c = defaultCeilings();
    const f = genesisPreservedFixture(new Array<number>(32).fill(0), c, []);
    assert.equal(f.chainVersionHistory().length, 0);
    assert.deepEqual(f.genesisConstitutionalCeilings(), c);
  });

  test("patch_08_fixture_serde_roundtrip", () => {
    const c = defaultCeilings();
    const h = [t(100n, 5)];
    const f = genesisPreservedFixture(new Array<number>(32).fill(0xde), c, h);
    const data = {
      genesis_block_hash: f.genesis_block_hash,
      genesis_ceilings: f.genesis_ceilings,
      chain_version_history: f.chain_version_history.map((tr) => ({
        activation_height: Number(tr.activation_height),
        from_version: tr.from_version,
        to_version: tr.to_version,
        upgrade_spec_hash: tr.upgrade_spec_hash,
        proposal_id: tr.proposal_id,
      })),
      ceilings_by_height: f.ceilings_by_height.map(([h, c]) => [Number(h), c] as [number, Ceilings]),
    };
    // JSON.stringify + parse roundtrip; the test asserts that the
    // re-parsed shape matches what we expect.
    const text = JSON.stringify(data);
    const back = JsonChainStateFixture.fromJson(JSON.parse(text));
    assert.deepEqual([...back.genesis_block_hash], new Array<number>(32).fill(0xde));
  });

  test("patch_08_genesis_block_hash_returned", () => {
    const c = defaultCeilings();
    const f = genesisPreservedFixture(new Array<number>(32).fill(0x42), c, []);
    assert.deepEqual([...f.genesisBlockHash()], new Array<number>(32).fill(0x42));
  });

  test("chainVersionTransitionFromJson coerces fields correctly", () => {
    const data = {
      activation_height: 100,
      from_version: 4,
      to_version: 5,
      upgrade_spec_hash: new Array<number>(32).fill(0xaa),
      proposal_id: new Array<number>(32).fill(0xbb),
    };
    const tr = chainVersionTransitionFromJson(data);
    assert.equal(tr.activation_height, 100n);
    assert.equal(tr.from_version, 4);
    assert.equal(tr.to_version, 5);
  });

  // ── Regression: i128 precision in JSON parse ──
  // PATCH_09 §C requires byte-identical comparison across language
  // ports. Naive JSON.parse returns IEEE-754 doubles, which round
  // 1e16 and 1e16 - 1 to the same value. parseJsonPreservingBigInts
  // upgrades unsafe-range integer literals to bigint so drift on
  // min_effective_fee_floor (default 10^16) is detectable.
  test("parseJsonPreservingBigInts preserves i128 precision above 2^53", () => {
    const text = '{"v": 10000000000000000}';
    const parsed = parseJsonPreservingBigInts(text) as { v: bigint };
    assert.equal(typeof parsed.v, "bigint");
    assert.equal(parsed.v, 10_000_000_000_000_000n);

    const text2 = '{"v": 9999999999999999}';
    const parsed2 = parseJsonPreservingBigInts(text2) as { v: bigint };
    assert.equal(typeof parsed2.v, "bigint");
    assert.equal(parsed2.v, 9_999_999_999_999_999n);

    // Distinct bigint values — naive Number parse would collapse them.
    assert.notEqual(parsed.v, parsed2.v);
  });

  test("parseJsonPreservingBigInts leaves safe-range ints as Number", () => {
    const text = '{"a": 42, "b": -7, "c": 9007199254740991}'; // c = MAX_SAFE_INTEGER
    const parsed = parseJsonPreservingBigInts(text) as Record<string, unknown>;
    assert.equal(typeof parsed["a"], "number");
    assert.equal(parsed["a"], 42);
    assert.equal(typeof parsed["b"], "number");
    assert.equal(parsed["b"], -7);
    assert.equal(typeof parsed["c"], "number");
    assert.equal(parsed["c"], 9007199254740991);
  });

  test("parseJsonPreservingBigInts upgrades the boundary just above MAX_SAFE_INTEGER", () => {
    const text = '{"v": 9007199254740992}'; // MAX_SAFE_INTEGER + 1
    const parsed = parseJsonPreservingBigInts(text) as { v: unknown };
    assert.equal(typeof parsed.v, "bigint");
    assert.equal(parsed.v as bigint, 9_007_199_254_740_992n);
  });

  test("loadFixtureFromJson roundtrip preserves i128 ceiling precision", () => {
    // Synthesize a fixture with a 17-digit min_effective_fee_floor;
    // verifier should detect a one-unit drift after JSON roundtrip.
    const text = `{
      "genesis_block_hash": [${new Array<number>(32).fill(0).join(",")}],
      "genesis_ceilings": {
        "max_proof_depth_ceiling": 512,
        "max_tx_gas_ceiling": 16000000,
        "max_block_gas_ceiling": 800000000,
        "max_contract_steps_ceiling": 40000,
        "max_address_length_ceiling": 4096,
        "max_state_entry_size_ceiling": 4194304,
        "max_tension_swing_ceiling": 4000000,
        "max_block_bytes_ceiling": 8388608,
        "max_active_proposals_ceiling": 256,
        "max_view_change_base_timeout_ms": 60000,
        "max_view_change_max_timeout_ms": 3600000,
        "max_validator_set_size_ceiling": 128,
        "max_validator_set_changes_per_block": 8,
        "max_fee_tension_alpha_ceiling": 1000000,
        "max_median_tension_window_ceiling": 64,
        "max_confirmation_depth_ceiling": 8,
        "max_equivocation_evidence_per_block": 16,
        "min_effective_fee_floor": 10000000000000000,
        "max_forgery_vetoes_per_block_ceiling": 8
      },
      "chain_version_history": [],
      "ceilings_by_height": []
    }`;
    const f = loadFixtureFromJson(text);
    const fee = (f.genesis_ceilings as Record<string, unknown>)["min_effective_fee_floor"];
    assert.equal(typeof fee, "bigint");
    assert.equal(fee as bigint, 10_000_000_000_000_000n);
  });
});
