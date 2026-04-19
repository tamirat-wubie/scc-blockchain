/**
 * CeilingViolation — TypeScript equivalent of the Rust enum.
 *
 * Mirrors `crates/sccgub-audit/src/violation.rs` per PATCH_08 §B.3 +
 * PATCH_09 §C.4. Same 4 variants, same fields. TypeScript encodes the
 * discriminated union via a `kind` literal-string tag.
 */

import type { CeilingFieldId, CeilingValue } from "./field.js";

/**
 * A ceiling field's value at `transition_height` differed from its
 * genesis value. **The primary moat-violation case.**
 */
export interface FieldValueChanged {
  readonly kind: "FieldValueChanged";
  readonly transition_height: bigint;
  readonly ceiling_field: CeilingFieldId;
  readonly before_value: CeilingValue;
  readonly after_value: CeilingValue;
}

/**
 * The genesis ceilings record could not be read or deserialized.
 * The chain has no genesis ceilings to compare against; the moat is
 * undefined for this chain.
 */
export interface GenesisCeilingsUnreadable {
  readonly kind: "GenesisCeilingsUnreadable";
  readonly reason: string;
}

/**
 * A ChainVersionTransition referenced a height at which the ceilings
 * record could not be read.
 */
export interface CeilingsUnreadableAtTransition {
  readonly kind: "CeilingsUnreadableAtTransition";
  readonly transition_height: bigint;
  readonly reason: string;
}

/**
 * `chain_version_history` contained a transition whose
 * `activation_height` predated genesis or violated monotonic
 * ordering.
 */
export interface HistoryStructurallyInvalid {
  readonly kind: "HistoryStructurallyInvalid";
  readonly reason: string;
}

/**
 * Discriminated union — TypeScript's structural equivalent of a
 * Rust enum. The verifier returns `null` (Ok) or one of these four
 * variant objects on violation.
 */
export type CeilingViolation =
  | FieldValueChanged
  | GenesisCeilingsUnreadable
  | CeilingsUnreadableAtTransition
  | HistoryStructurallyInvalid;

/**
 * Return the variant name as a string. Used by the CLI's plain-text
 * output format per PATCH_09 §E.2.
 */
export function violationKind(v: CeilingViolation): string {
  return v.kind;
}

/** Render a CeilingViolation as a human-readable string. */
export function violationToString(v: CeilingViolation): string {
  switch (v.kind) {
    case "FieldValueChanged":
      return (
        `ceiling field ${v.ceiling_field} changed at transition height ` +
        `${v.transition_height}: genesis was ${v.before_value}, observed ${v.after_value}`
      );
    case "GenesisCeilingsUnreadable":
      return `genesis ceilings unreadable: ${v.reason}`;
    case "CeilingsUnreadableAtTransition":
      return (
        `ceilings unreadable at transition height ${v.transition_height}: ${v.reason}`
      );
    case "HistoryStructurallyInvalid":
      return `chain version history structurally invalid: ${v.reason}`;
  }
}
