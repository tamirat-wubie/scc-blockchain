/**
 * Tests for src/verifier.ts — mirror Python test_verifier.py + Rust verifier.rs tests.
 * Per PATCH_09 §F coverage requirement.
 */

import { strict as assert } from "node:assert";
import { describe, test } from "node:test";

import {
  type Ceilings,
  type ChainStateView,
  type ChainVersionTransition,
  ChainStateError,
  GenesisCeilingsMissing,
  ChainStateIoError,
  JsonChainStateFixture,
  genesisPreservedFixture,
} from "../src/chainState.js";
import { CeilingFieldId } from "../src/field.js";
import { verifyCeilingsUnchangedSinceGenesis } from "../src/verifier.js";
import type {
  CeilingsUnreadableAtTransition,
  FieldValueChanged,
  GenesisCeilingsUnreadable,
  HistoryStructurallyInvalid,
} from "../src/violation.js";

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

function fixtureWithDriftedField(
  history: ChainVersionTransition[],
  driftAtHeight: bigint,
  mutate: (c: Record<string, number>) => void,
): JsonChainStateFixture {
  const genesis = defaultCeilings();
  const byHeight: Array<readonly [bigint, Ceilings]> = [];
  for (const tr of history) {
    if (tr.activation_height > 0n) {
      byHeight.push([tr.activation_height - 1n, { ...genesis }] as const);
    }
    const here = { ...genesis };
    if (tr.activation_height === driftAtHeight) {
      mutate(here);
    }
    byHeight.push([tr.activation_height, here] as const);
  }
  return new JsonChainStateFixture(
    new Array<number>(32).fill(0),
    { ...genesis },
    history,
    byHeight,
  );
}

describe("verifyCeilingsUnchangedSinceGenesis", () => {
  // ── Mandatory case 1: empty history → null (Rust Ok(())) ──
  test("patch_08_empty_history_returns_ok", () => {
    const f = genesisPreservedFixture(new Array<number>(32).fill(0), defaultCeilings(), []);
    assert.equal(verifyCeilingsUnchangedSinceGenesis(f), null);
  });

  // ── Mandatory case 2 ──
  test("patch_08_single_transition_preserved_returns_ok", () => {
    const f = genesisPreservedFixture(
      new Array<number>(32).fill(0),
      defaultCeilings(),
      [t(100n, 5)],
    );
    assert.equal(verifyCeilingsUnchangedSinceGenesis(f), null);
  });

  // ── Mandatory case 3 ──
  test("patch_08_multiple_transitions_preserved_returns_ok", () => {
    const f = genesisPreservedFixture(
      new Array<number>(32).fill(0),
      defaultCeilings(),
      [t(100n, 5), t(200n, 6), t(300n, 7)],
    );
    assert.equal(verifyCeilingsUnchangedSinceGenesis(f), null);
  });

  // ── Mandatory case 4: per-CeilingFieldId drift detected (3 representative) ──
  test("patch_08_drift_in_max_proof_depth_detected", () => {
    const f = fixtureWithDriftedField([t(100n, 5)], 100n, (c) => {
      c["max_proof_depth_ceiling"]! += 1;
    });
    const r = verifyCeilingsUnchangedSinceGenesis(f);
    assert.equal(r?.kind, "FieldValueChanged");
    assert.equal((r as FieldValueChanged).ceiling_field, CeilingFieldId.MaxProofDepth);
  });

  test("patch_08_drift_in_max_tx_gas_detected", () => {
    const f = fixtureWithDriftedField([t(100n, 5)], 100n, (c) => {
      c["max_tx_gas_ceiling"]! += 1;
    });
    const r = verifyCeilingsUnchangedSinceGenesis(f);
    assert.equal(r?.kind, "FieldValueChanged");
    assert.equal((r as FieldValueChanged).ceiling_field, CeilingFieldId.MaxTxGas);
  });

  test("patch_08_drift_in_min_effective_fee_floor_detected", () => {
    // Even a DECREASE counts as drift — the moat is "unchanged",
    // not "not-raised."
    const f = fixtureWithDriftedField([t(100n, 5)], 100n, (c) => {
      c["min_effective_fee_floor"]! -= 1;
    });
    const r = verifyCeilingsUnchangedSinceGenesis(f);
    assert.equal(r?.kind, "FieldValueChanged");
    assert.equal((r as FieldValueChanged).ceiling_field, CeilingFieldId.MinEffectiveFeeFloor);
  });

  // ── Mandatory case 5: short-circuit on first violation ──
  test("patch_08_short_circuits_on_first_violation", () => {
    const history = [t(100n, 5), t(200n, 6)];
    const genesis = defaultCeilings();
    const byHeight: Array<readonly [bigint, Ceilings]> = [];
    byHeight.push([99n, { ...genesis }] as const);
    const h100 = { ...genesis };
    h100["max_proof_depth_ceiling"]! += 10;
    byHeight.push([100n, h100] as const);
    byHeight.push([199n, { ...genesis }] as const);
    const h200 = { ...genesis };
    h200["max_tx_gas_ceiling"]! += 999;
    byHeight.push([200n, h200] as const);

    const f = new JsonChainStateFixture(
      new Array<number>(32).fill(0),
      { ...genesis },
      history,
      byHeight,
    );
    const r = verifyCeilingsUnchangedSinceGenesis(f);
    assert.equal(r?.kind, "FieldValueChanged");
    assert.equal((r as FieldValueChanged).transition_height, 100n);
    assert.equal((r as FieldValueChanged).ceiling_field, CeilingFieldId.MaxProofDepth);
  });

  // ── Mandatory case 6: degenerate activation_height = 0 ──
  test("patch_08_degenerate_activation_height_zero_handled", () => {
    const genesis = defaultCeilings();
    const f = new JsonChainStateFixture(
      new Array<number>(32).fill(0),
      { ...genesis },
      [t(0n, 1)],
      [[0n, { ...genesis }] as const],
    );
    assert.equal(verifyCeilingsUnchangedSinceGenesis(f), null);
  });

  // ── Mandatory case 7: HistoryStructurallyInvalid ──
  test("patch_08_non_monotonic_history_rejected", () => {
    const genesis = defaultCeilings();
    const f = new JsonChainStateFixture(
      new Array<number>(32).fill(0),
      { ...genesis },
      [t(200n, 6), t(100n, 5)],
      [
        [99n, { ...genesis }] as const,
        [100n, { ...genesis }] as const,
        [199n, { ...genesis }] as const,
        [200n, { ...genesis }] as const,
      ],
    );
    const r = verifyCeilingsUnchangedSinceGenesis(f);
    assert.equal(r?.kind, "HistoryStructurallyInvalid");
    void (r as HistoryStructurallyInvalid).reason;
  });

  // ── Mandatory case 8: GenesisCeilingsUnreadable ──
  test("patch_08_genesis_ceilings_unreadable_returns_genesis_unreadable", () => {
    const unreadable: ChainStateView = {
      genesisBlockHash: () => new Array<number>(32).fill(0),
      genesisConstitutionalCeilings: () => {
        throw new GenesisCeilingsMissing("synthetic missing");
      },
      chainVersionHistory: () => [],
      ceilingsAtHeight: () => {
        throw new ChainStateIoError("never reached");
      },
    };
    const r = verifyCeilingsUnchangedSinceGenesis(unreadable);
    assert.equal(r?.kind, "GenesisCeilingsUnreadable");
    void (r as GenesisCeilingsUnreadable).reason;
  });

  // ── Mandatory case 9: CeilingsUnreadableAtTransition ──
  test("patch_08_missing_ceilings_at_transition_returns_unreadable_at_transition", () => {
    const genesis = defaultCeilings();
    const f = new JsonChainStateFixture(
      new Array<number>(32).fill(0),
      { ...genesis },
      [t(100n, 5)],
      [], // missing height 99 + 100
    );
    const r = verifyCeilingsUnchangedSinceGenesis(f);
    assert.equal(r?.kind, "CeilingsUnreadableAtTransition");
    assert.equal((r as CeilingsUnreadableAtTransition).transition_height, 100n);
  });

  // ── Adversarial case 1: pre-transition height drift ──
  test("patch_08_pre_transition_drift_detected", () => {
    const genesis = defaultCeilings();
    const tampered = { ...genesis };
    tampered["max_block_gas_ceiling"]! += 1000;
    const f = new JsonChainStateFixture(
      new Array<number>(32).fill(0),
      { ...genesis },
      [t(100n, 5)],
      [
        [99n, tampered] as const,
        [100n, { ...genesis }] as const,
      ],
    );
    const r = verifyCeilingsUnchangedSinceGenesis(f);
    assert.equal(r?.kind, "FieldValueChanged");
    assert.equal((r as FieldValueChanged).ceiling_field, CeilingFieldId.MaxBlockGas);
    assert.equal((r as FieldValueChanged).transition_height, 100n);
  });

  // ── Adversarial case 2: encoding-portability sanity ──
  test("patch_08_value_comparison_uses_value_equality_not_bytes", () => {
    const g = defaultCeilings();
    const text = JSON.stringify(g);
    const g2 = JSON.parse(text) as Record<string, number>;
    const f1 = genesisPreservedFixture(new Array<number>(32).fill(0), g, [t(50n, 5)]);
    const f2 = genesisPreservedFixture(new Array<number>(32).fill(0), g2, [t(50n, 5)]);
    assert.equal(verifyCeilingsUnchangedSinceGenesis(f1), null);
    assert.equal(verifyCeilingsUnchangedSinceGenesis(f2), null);
  });

  // ── Adversarial case 3: drift in middle of long history ──
  test("patch_08_drift_in_middle_of_long_history", () => {
    const genesis = defaultCeilings();
    const history = [t(100n, 5), t(200n, 6), t(300n, 7), t(400n, 8), t(500n, 9)];
    const byHeight: Array<readonly [bigint, Ceilings]> = [];
    for (const tr of history) {
      byHeight.push([tr.activation_height - 1n, { ...genesis }] as const);
      const here = { ...genesis };
      if (tr.activation_height === 300n) {
        here["max_validator_set_size_ceiling"]! += 1;
      }
      byHeight.push([tr.activation_height, here] as const);
    }
    const f = new JsonChainStateFixture(
      new Array<number>(32).fill(0),
      { ...genesis },
      history,
      byHeight,
    );
    const r = verifyCeilingsUnchangedSinceGenesis(f);
    assert.equal(r?.kind, "FieldValueChanged");
    assert.equal((r as FieldValueChanged).transition_height, 300n);
    assert.equal((r as FieldValueChanged).ceiling_field, CeilingFieldId.MaxValidatorSetSize);
  });

  // ── Pure-function property ──
  test("patch_08_verifier_is_pure_over_input", () => {
    const f = genesisPreservedFixture(
      new Array<number>(32).fill(0xab),
      defaultCeilings(),
      [t(100n, 5), t(200n, 6)],
    );
    const r1 = verifyCeilingsUnchangedSinceGenesis(f);
    const r2 = verifyCeilingsUnchangedSinceGenesis(f);
    assert.deepEqual(r1, r2);
  });

  test("ChainStateError is the base of fixture-thrown errors (sanity)", () => {
    const e = new ChainStateError("base");
    assert.equal(e instanceof ChainStateError, true);
    assert.equal(e instanceof Error, true);
  });
});
