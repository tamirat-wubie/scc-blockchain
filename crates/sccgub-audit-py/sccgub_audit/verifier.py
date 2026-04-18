"""verify_ceilings_unchanged_since_genesis — Python port.

Mirrors `crates/sccgub-audit/src/verifier.rs` per PATCH_08 §B.5 +
PATCH_09 §C semantic baseline.

Pure function over its input (no wall-clock, no env, no I/O outside
the ChainStateView method calls, no caches, no global state). Two
reviewers running this against the same view produce identical
output. Same property as the Rust port; same property as any future
language port.
"""

from __future__ import annotations

from typing import Optional

from .chain_state import (
    ChainStateError,
    CeilingsMissingAtHeight,
    ChainVersionTransition,
)
from .field import CeilingFieldId, field_value
from .violation import (
    CeilingViolation,
    CeilingsUnreadableAtTransition,
    FieldValueChanged,
    GenesisCeilingsUnreadable,
    HistoryStructurallyInvalid,
)


def verify_ceilings_unchanged_since_genesis(chain) -> Optional[CeilingViolation]:
    """Verify that no ConstitutionalCeilings field has been raised
    (or otherwise changed) since genesis.

    Returns `None` (the Python equivalent of Rust's `Ok(())`) iff
    every ChainVersionTransition from genesis to current tip
    preserved every ConstitutionalCeilings field at exactly its
    genesis value. Returns the **first** CeilingViolation
    encountered on failure (short-circuit per PATCH_08 §B.2).

    Algorithm matches Rust port exactly per PATCH_08 §B.5:

        1. Read genesis ceilings (baseline).
        2. Read chain version history.
        3. Validate history monotonic by activation_height.
        4. Empty history → None (moat trivially holds).
        5. For each transition: check pre and post ceilings against
           genesis baseline across every field in CeilingFieldId.all().

    Edge cases:
        - empty history → None
        - activation_height = 0 → check only post (no pre at -1)
        - non-monotonic history → HistoryStructurallyInvalid
    """
    # 1. Read the moat-defining baseline.
    try:
        genesis = chain.genesis_constitutional_ceilings()
    except ChainStateError as e:
        return GenesisCeilingsUnreadable(reason=str(e))
    except Exception as e:
        return GenesisCeilingsUnreadable(reason=f"{type(e).__name__}: {e}")

    # 2. Read the full chain-version history.
    try:
        history = chain.chain_version_history()
    except ChainStateError as e:
        return HistoryStructurallyInvalid(reason=str(e))
    except Exception as e:
        return HistoryStructurallyInvalid(reason=f"{type(e).__name__}: {e}")

    # 3. Validate monotonic activation_height ordering.
    for i in range(len(history) - 1):
        a = history[i]
        b = history[i + 1]
        if a.activation_height > b.activation_height:
            return HistoryStructurallyInvalid(
                reason=(
                    f"transition activation_height {b.activation_height} "
                    f"precedes preceding transition's {a.activation_height}"
                )
            )

    # 4. Empty history: nothing to check.
    if not history:
        return None

    # 5. Walk every transition; check pre and post ceilings.
    for transition in history:
        h = transition.activation_height

        # Check pre-transition ceilings (when h > 0).
        if h > 0:
            try:
                pre = chain.ceilings_at_height(h - 1)
            except ChainStateError as e:
                return CeilingsUnreadableAtTransition(
                    transition_height=h, reason=str(e)
                )
            except Exception as e:
                return CeilingsUnreadableAtTransition(
                    transition_height=h,
                    reason=f"{type(e).__name__}: {e}",
                )
            for field in CeilingFieldId.all():
                baseline = field_value(genesis, field)
                observed = field_value(pre, field)
                if baseline != observed:
                    return FieldValueChanged(
                        transition_height=h,
                        ceiling_field=field,
                        before_value=baseline,
                        after_value=observed,
                    )

        # Check post-transition ceilings.
        try:
            post = chain.ceilings_at_height(h)
        except ChainStateError as e:
            return CeilingsUnreadableAtTransition(transition_height=h, reason=str(e))
        except Exception as e:
            return CeilingsUnreadableAtTransition(
                transition_height=h,
                reason=f"{type(e).__name__}: {e}",
            )
        for field in CeilingFieldId.all():
            baseline = field_value(genesis, field)
            observed = field_value(post, field)
            if baseline != observed:
                return FieldValueChanged(
                    transition_height=h,
                    ceiling_field=field,
                    before_value=baseline,
                    after_value=observed,
                )

    return None
