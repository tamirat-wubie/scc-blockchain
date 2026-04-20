/**
 * Tests for src/field.ts — mirror Python test_field.py + Rust field.rs tests.
 */

import { strict as assert } from "node:assert";
import { describe, test } from "node:test";

import {
  ALL_CEILING_FIELDS,
  CeilingFieldId,
  EXPECTED_FIELD_COUNT,
  fieldValue,
} from "../src/field.js";

/**
 * Mirror the Rust ConstitutionalCeilings::default() values exactly.
 * Source: crates/sccgub-types/src/constitutional_ceilings.rs default impl.
 */
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

describe("CeilingFieldId", () => {
  test("patch_08_all_field_count_matches_struct_field_count", () => {
    // Bumped from 18 to 19 in PATCH_10 §39.4 (adds
    // max_forgery_vetoes_per_block_ceiling).
    assert.equal(ALL_CEILING_FIELDS.length, EXPECTED_FIELD_COUNT);
    assert.equal(ALL_CEILING_FIELDS.length, 19);
  });

  test("patch_08_all_variants_distinct", () => {
    const names = ALL_CEILING_FIELDS.map((f) => f);
    assert.equal(new Set(names).size, names.length);
  });

  test("patch_08_field_value_default_ceilings_well_formed", () => {
    const c = defaultCeilings();
    for (const f of ALL_CEILING_FIELDS) {
      const value = fieldValue(c, f);
      assert.equal(typeof value, "bigint");
    }
  });

  test("patch_08_ceiling_value_display", () => {
    // bigint stringification is value-correct, matching Rust Display.
    assert.equal((42n).toString(), "42");
    assert.equal((99n).toString(), "99");
    assert.equal((-7n).toString(), "-7");
    assert.equal((-1_000_000n).toString(), "-1000000");
  });

  test("field_value_throws_on_missing_key", () => {
    const c = defaultCeilings() as Record<string, unknown>;
    delete c["max_tx_gas_ceiling"];
    assert.throws(() => fieldValue(c, CeilingFieldId.MaxTxGas), /missing field/);
  });

  test("field_value_throws_on_non_integer", () => {
    const c = defaultCeilings() as Record<string, unknown>;
    c["max_tx_gas_ceiling"] = { not: "an int" };
    assert.throws(() => fieldValue(c, CeilingFieldId.MaxTxGas));
  });
});
