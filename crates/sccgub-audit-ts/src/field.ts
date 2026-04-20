/**
 * Enumeration of every ConstitutionalCeilings field.
 *
 * Mirrors `crates/sccgub-audit/src/field.rs` per PATCH_08 §B.4 +
 * PATCH_09 §C.4. Same 18 variants in the same canonical order as the
 * Rust and Python ports.
 *
 * **Discipline**: every field of the Rust `ConstitutionalCeilings`
 * struct MUST have a corresponding `CeilingFieldId` value in this
 * file. A future Rust PR adding a new ceiling field MUST add the
 * matching TypeScript variant in the same PR (or its language-port
 * equivalent), or the cross-language conformance harness fails.
 */

/**
 * Identifier for a single ceiling field.
 *
 * The string value of each variant matches the Rust struct field
 * name exactly. Iteration order via {@link ALL_CEILING_FIELDS}
 * matches the Rust `CeilingFieldId::ALL` constant.
 */
export const CeilingFieldId = {
  MaxProofDepth: "max_proof_depth_ceiling",
  MaxTxGas: "max_tx_gas_ceiling",
  MaxBlockGas: "max_block_gas_ceiling",
  MaxContractSteps: "max_contract_steps_ceiling",
  MaxAddressLength: "max_address_length_ceiling",
  MaxStateEntrySize: "max_state_entry_size_ceiling",
  MaxTensionSwing: "max_tension_swing_ceiling",
  MaxBlockBytes: "max_block_bytes_ceiling",
  MaxActiveProposals: "max_active_proposals_ceiling",
  MaxViewChangeBaseTimeoutMs: "max_view_change_base_timeout_ms",
  MaxViewChangeMaxTimeoutMs: "max_view_change_max_timeout_ms",
  MaxValidatorSetSize: "max_validator_set_size_ceiling",
  MaxValidatorSetChangesPerBlock: "max_validator_set_changes_per_block",
  MaxFeeTensionAlpha: "max_fee_tension_alpha_ceiling",
  MaxMedianTensionWindow: "max_median_tension_window_ceiling",
  MaxConfirmationDepth: "max_confirmation_depth_ceiling",
  MaxEquivocationEvidencePerBlock: "max_equivocation_evidence_per_block",
  MinEffectiveFeeFloor: "min_effective_fee_floor",
  // PATCH_10 §39.4: per-block forgery-veto rate ceiling.
  MaxForgeryVetoesPerBlock: "max_forgery_vetoes_per_block_ceiling",
} as const;

/** Type of a single CeilingFieldId value (the underlying string). */
export type CeilingFieldId = (typeof CeilingFieldId)[keyof typeof CeilingFieldId];

/**
 * Canonical ordering — matches Rust `CeilingFieldId::ALL`.
 *
 * The verifier iterates this list on every transition; a missing
 * entry means the corresponding field is silently allowed to drift,
 * which would defeat the moat. The TS port asserts this list has
 * exactly 18 entries (matching the Rust struct field count) at
 * test time.
 */
export const ALL_CEILING_FIELDS: readonly CeilingFieldId[] = [
  CeilingFieldId.MaxProofDepth,
  CeilingFieldId.MaxTxGas,
  CeilingFieldId.MaxBlockGas,
  CeilingFieldId.MaxContractSteps,
  CeilingFieldId.MaxAddressLength,
  CeilingFieldId.MaxStateEntrySize,
  CeilingFieldId.MaxTensionSwing,
  CeilingFieldId.MaxBlockBytes,
  CeilingFieldId.MaxActiveProposals,
  CeilingFieldId.MaxViewChangeBaseTimeoutMs,
  CeilingFieldId.MaxViewChangeMaxTimeoutMs,
  CeilingFieldId.MaxValidatorSetSize,
  CeilingFieldId.MaxValidatorSetChangesPerBlock,
  CeilingFieldId.MaxFeeTensionAlpha,
  CeilingFieldId.MaxMedianTensionWindow,
  CeilingFieldId.MaxConfirmationDepth,
  CeilingFieldId.MaxEquivocationEvidencePerBlock,
  CeilingFieldId.MinEffectiveFeeFloor,
  CeilingFieldId.MaxForgeryVetoesPerBlock,
] as const;

/**
 * `CeilingValue` is type-erased; we use JavaScript `bigint` because
 * the underlying Rust types include i128 (which JavaScript `number`
 * cannot represent without precision loss for values > 2^53).
 *
 * Values arrive from JSON.parse as `number` for small integers and
 * we widen them to `bigint` at the boundary in {@link fieldValue}.
 * Comparison via `===` on bigints is value-based per PATCH_09 §C.
 */
export type CeilingValue = bigint;

/**
 * Extract a single ceiling field's value from a
 * ConstitutionalCeilings JSON-decoded mapping.
 *
 * Mirrors Rust `field_value` per PATCH_08 §B.5 algorithm. The TS
 * port uses a `Record<string, unknown>` (the JSON.parse result)
 * rather than a typed struct; the field-name discipline is enforced
 * by {@link CeilingFieldId} string-literal types.
 *
 * Per PATCH_09 §C, value comparison is integer equality (bigint
 * `===`), which is value-based, not byte-based, so encoding
 * endianness or padding cannot trick the comparison.
 *
 * @throws Error if the field is missing or the value is not an
 *   integer-typed primitive.
 */
export function fieldValue(
  ceilings: Readonly<Record<string, unknown>>,
  field: CeilingFieldId,
): CeilingValue {
  if (!(field in ceilings)) {
    throw new Error(
      `ceilings missing field ${field} — JSON fixture is malformed`,
    );
  }
  const raw = ceilings[field];
  if (typeof raw === "bigint") {
    return raw;
  }
  if (typeof raw === "number") {
    if (!Number.isInteger(raw)) {
      throw new Error(
        `ceiling field ${field} has non-integer numeric value ${raw}`,
      );
    }
    return BigInt(raw);
  }
  if (typeof raw === "string") {
    // JSON-decoded i128 values may arrive as strings to preserve
    // precision; accept and parse.
    try {
      return BigInt(raw);
    } catch {
      throw new Error(
        `ceiling field ${field} string value ${JSON.stringify(raw)} is not a valid integer`,
      );
    }
  }
  throw new TypeError(
    `ceiling field ${field} has non-integer value ${JSON.stringify(raw)} (type ${typeof raw})`,
  );
}

/**
 * Documents the field-count discipline. The accompanying test
 * `tests/field.test.ts` asserts that {@link ALL_CEILING_FIELDS} has
 * exactly 18 entries (matching the Rust struct field count). A
 * future Rust PR adding a 19th ceiling field MUST add the matching
 * TypeScript variant in the same PR or the cross-language
 * conformance harness fails.
 */
export const EXPECTED_FIELD_COUNT = 19;
