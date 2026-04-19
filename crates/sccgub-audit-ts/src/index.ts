/**
 * Public API barrel for sccgub-audit-ts.
 *
 * Mirrors the Python package's `sccgub_audit/__init__.py` and the
 * Rust crate's public surface. Per PATCH_09 §C.4, the public types
 * and function names are stable and consumed by both the CLI and
 * any third-party TypeScript verifier integration.
 */

export {
  ALL_CEILING_FIELDS,
  CeilingFieldId,
  EXPECTED_FIELD_COUNT,
  fieldValue,
} from "./field.js";
export type { CeilingValue } from "./field.js";

export {
  type CeilingViolation,
  type FieldValueChanged,
  type GenesisCeilingsUnreadable,
  type CeilingsUnreadableAtTransition,
  type HistoryStructurallyInvalid,
  violationKind,
  violationToString,
} from "./violation.js";

export {
  type Ceilings,
  type ChainStateView,
  type ChainVersionTransition,
  ChainStateError,
  GenesisCeilingsMissing,
  GenesisCeilingsMalformed,
  CeilingsMissingAtHeight,
  ChainStateIoError,
  JsonChainStateFixture,
  chainVersionTransitionFromJson,
  loadFixtureFromJson,
  genesisPreservedFixture,
} from "./chainState.js";

export { verifyCeilingsUnchangedSinceGenesis } from "./verifier.js";
