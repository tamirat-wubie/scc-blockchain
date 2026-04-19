/**
 * verifyCeilingsUnchangedSinceGenesis — TypeScript port.
 *
 * Mirrors `crates/sccgub-audit/src/verifier.rs` per PATCH_08 §B.5 +
 * PATCH_09 §C semantic baseline.
 *
 * Pure function over its input (no wall-clock, no env, no I/O outside
 * the ChainStateView method calls, no caches, no global state). Two
 * reviewers running this against the same view produce identical
 * output. Same property as the Rust port; same property as the
 * Python port.
 */

import type { ChainStateView } from "./chainState.js";
import { ChainStateError } from "./chainState.js";
import { ALL_CEILING_FIELDS, fieldValue } from "./field.js";
import type { CeilingViolation } from "./violation.js";

/**
 * Verify that no ConstitutionalCeilings field has been raised (or
 * otherwise changed) since genesis.
 *
 * Returns `null` (the TypeScript equivalent of Rust's `Ok(())` and
 * Python's `None`) iff every ChainVersionTransition from genesis to
 * current tip preserved every ConstitutionalCeilings field at exactly
 * its genesis value. Returns the **first** {@link CeilingViolation}
 * encountered on failure (short-circuit per PATCH_08 §B.2).
 *
 * Algorithm matches Rust port exactly per PATCH_08 §B.5:
 *
 *     1. Read genesis ceilings (baseline).
 *     2. Read chain version history.
 *     3. Validate history monotonic by activation_height.
 *     4. Empty history → null (moat trivially holds).
 *     5. For each transition: check pre and post ceilings against
 *        genesis baseline across every field in ALL_CEILING_FIELDS.
 *
 * Edge cases:
 *   - empty history → null
 *   - activation_height = 0 → check only post (no pre at -1)
 *   - non-monotonic history → HistoryStructurallyInvalid
 */
export function verifyCeilingsUnchangedSinceGenesis(
  chain: ChainStateView,
): CeilingViolation | null {
  // 1. Read the moat-defining baseline.
  let genesis;
  try {
    genesis = chain.genesisConstitutionalCeilings();
  } catch (e) {
    return {
      kind: "GenesisCeilingsUnreadable",
      reason: errorReason(e),
    };
  }

  // 2. Read the full chain-version history.
  let history;
  try {
    history = chain.chainVersionHistory();
  } catch (e) {
    return {
      kind: "HistoryStructurallyInvalid",
      reason: errorReason(e),
    };
  }

  // 3. Validate monotonic activation_height ordering.
  for (let i = 0; i < history.length - 1; i++) {
    const a = history[i]!;
    const b = history[i + 1]!;
    if (a.activation_height > b.activation_height) {
      return {
        kind: "HistoryStructurallyInvalid",
        reason:
          `transition activation_height ${b.activation_height} ` +
          `precedes preceding transition's ${a.activation_height}`,
      };
    }
  }

  // 4. Empty history: nothing to check.
  if (history.length === 0) {
    return null;
  }

  // 5. Walk every transition; check pre and post ceilings.
  for (const transition of history) {
    const h = transition.activation_height;

    // Check pre-transition ceilings (when h > 0).
    if (h > 0n) {
      let pre;
      try {
        pre = chain.ceilingsAtHeight(h - 1n);
      } catch (e) {
        return {
          kind: "CeilingsUnreadableAtTransition",
          transition_height: h,
          reason: errorReason(e),
        };
      }
      for (const field of ALL_CEILING_FIELDS) {
        const baseline = fieldValue(genesis, field);
        const observed = fieldValue(pre, field);
        if (baseline !== observed) {
          return {
            kind: "FieldValueChanged",
            transition_height: h,
            ceiling_field: field,
            before_value: baseline,
            after_value: observed,
          };
        }
      }
    }

    // Check post-transition ceilings.
    let post;
    try {
      post = chain.ceilingsAtHeight(h);
    } catch (e) {
      return {
        kind: "CeilingsUnreadableAtTransition",
        transition_height: h,
        reason: errorReason(e),
      };
    }
    for (const field of ALL_CEILING_FIELDS) {
      const baseline = fieldValue(genesis, field);
      const observed = fieldValue(post, field);
      if (baseline !== observed) {
        return {
          kind: "FieldValueChanged",
          transition_height: h,
          ceiling_field: field,
          before_value: baseline,
          after_value: observed,
        };
      }
    }
  }

  return null;
}

function errorReason(e: unknown): string {
  if (e instanceof ChainStateError) {
    return e.message;
  }
  if (e instanceof Error) {
    return `${e.name}: ${e.message}`;
  }
  return String(e);
}
