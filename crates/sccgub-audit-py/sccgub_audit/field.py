"""Enumeration of every ConstitutionalCeilings field.

Mirrors `crates/sccgub-audit/src/field.rs` per PATCH_08 §B.4 +
PATCH_09 §D.4. Same 18 variants in the same canonical order.

**Discipline**: every field of the Rust `ConstitutionalCeilings`
struct MUST have a corresponding `CeilingFieldId` variant in this
file. A future Rust PR adding a new ceiling field MUST add the
matching Python variant in the same PR (or its language-port
equivalent), or the cross-language conformance harness fails.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Mapping


class CeilingFieldId(Enum):
    """Identifier for a single ceiling field.

    Order matches Rust `ConstitutionalCeilings` field declaration
    order; `ALL` slice order matches the Rust `CeilingFieldId::ALL`
    constant. Tests assert this parity.
    """

    MAX_PROOF_DEPTH = "max_proof_depth_ceiling"
    MAX_TX_GAS = "max_tx_gas_ceiling"
    MAX_BLOCK_GAS = "max_block_gas_ceiling"
    MAX_CONTRACT_STEPS = "max_contract_steps_ceiling"
    MAX_ADDRESS_LENGTH = "max_address_length_ceiling"
    MAX_STATE_ENTRY_SIZE = "max_state_entry_size_ceiling"
    MAX_TENSION_SWING = "max_tension_swing_ceiling"
    MAX_BLOCK_BYTES = "max_block_bytes_ceiling"
    MAX_ACTIVE_PROPOSALS = "max_active_proposals_ceiling"
    MAX_VIEW_CHANGE_BASE_TIMEOUT_MS = "max_view_change_base_timeout_ms"
    MAX_VIEW_CHANGE_MAX_TIMEOUT_MS = "max_view_change_max_timeout_ms"
    MAX_VALIDATOR_SET_SIZE = "max_validator_set_size_ceiling"
    MAX_VALIDATOR_SET_CHANGES_PER_BLOCK = "max_validator_set_changes_per_block"
    MAX_FEE_TENSION_ALPHA = "max_fee_tension_alpha_ceiling"
    MAX_MEDIAN_TENSION_WINDOW = "max_median_tension_window_ceiling"
    MAX_CONFIRMATION_DEPTH = "max_confirmation_depth_ceiling"
    MAX_EQUIVOCATION_EVIDENCE_PER_BLOCK = "max_equivocation_evidence_per_block"
    MIN_EFFECTIVE_FEE_FLOOR = "min_effective_fee_floor"
    # PATCH_10 §39.4: per-block forgery-veto rate ceiling.
    MAX_FORGERY_VETOES_PER_BLOCK = "max_forgery_vetoes_per_block_ceiling"

    @classmethod
    def all(cls) -> list["CeilingFieldId"]:
        """Canonical ordering — matches Rust `CeilingFieldId::ALL`.

        The verifier iterates this list on every transition; a
        missing variant means the corresponding field is silently
        allowed to drift, which would defeat the moat. The Python
        port asserts this list has exactly 18 entries (matching the
        Rust struct field count) at test time.
        """
        return [
            cls.MAX_PROOF_DEPTH,
            cls.MAX_TX_GAS,
            cls.MAX_BLOCK_GAS,
            cls.MAX_CONTRACT_STEPS,
            cls.MAX_ADDRESS_LENGTH,
            cls.MAX_STATE_ENTRY_SIZE,
            cls.MAX_TENSION_SWING,
            cls.MAX_BLOCK_BYTES,
            cls.MAX_ACTIVE_PROPOSALS,
            cls.MAX_VIEW_CHANGE_BASE_TIMEOUT_MS,
            cls.MAX_VIEW_CHANGE_MAX_TIMEOUT_MS,
            cls.MAX_VALIDATOR_SET_SIZE,
            cls.MAX_VALIDATOR_SET_CHANGES_PER_BLOCK,
            cls.MAX_FEE_TENSION_ALPHA,
            cls.MAX_MEDIAN_TENSION_WINDOW,
            cls.MAX_CONFIRMATION_DEPTH,
            cls.MAX_EQUIVOCATION_EVIDENCE_PER_BLOCK,
            cls.MIN_EFFECTIVE_FEE_FLOOR,
            cls.MAX_FORGERY_VETOES_PER_BLOCK,
        ]

    def as_str(self) -> str:
        """Human-readable name (matches Rust struct field name)."""
        return self.value


# `CeilingValue` is type-erased; in Python we use plain `int`
# (Python's int is unbounded, so it covers u32/u64/i64/i128
# without wrapping). The Rust port distinguishes these for
# encoding clarity; the Python port relies on Python's unified
# `int` type and verifies via PartialEq-equivalent value
# comparison per PATCH_09 §C semantic baseline.
CeilingValue = int


def field_value(ceilings: Mapping[str, Any], field: CeilingFieldId) -> CeilingValue:
    """Extract a single ceiling field's value from a
    ConstitutionalCeilings JSON mapping.

    Mirrors Rust `field_value` per PATCH_08 §B.5 algorithm. The
    Python port uses a `Mapping[str, Any]` (the JSON-decoded
    dict) rather than a typed struct; the field-name string
    discipline is enforced by `CeilingFieldId.as_str()`.

    Per PATCH_09 §C, value comparison is integer equality (Python
    `int.__eq__`), which is value-based, not byte-based, so
    encoding endianness or padding cannot trick the comparison.
    """
    name = field.as_str()
    if name not in ceilings:
        raise KeyError(
            f"ceilings missing field {name} — JSON fixture is malformed"
        )
    value = ceilings[name]
    if not isinstance(value, int):
        raise TypeError(
            f"ceiling field {name} has non-integer value {value!r} "
            f"(type {type(value).__name__})"
        )
    return value


@dataclass(frozen=True)
class _CompileTimeFieldCheck:
    """Documents the field-count discipline.

    The accompanying test `test_field.py::test_all_field_count_matches`
    asserts that `CeilingFieldId.all()` has exactly 18 entries
    (matching the Rust struct field count). A future Rust PR adding
    a 19th ceiling field MUST add the matching Python variant in
    the same PR or the cross-language conformance harness fails.
    """

    expected_field_count: int = 19
