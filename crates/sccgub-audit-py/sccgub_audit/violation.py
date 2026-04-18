"""CeilingViolation — Python equivalent of the Rust enum.

Mirrors `crates/sccgub-audit/src/violation.rs` per PATCH_08 §B.3 +
PATCH_09 §D.4. Same 4 variants, same fields. Python encodes the
discriminated-union as four dataclasses sharing a base type.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Union

from .field import CeilingFieldId, CeilingValue


@dataclass(frozen=True)
class FieldValueChanged:
    """A ceiling field's value at `transition_height` differed from
    its genesis value. **The primary moat-violation case.**"""

    transition_height: int
    ceiling_field: CeilingFieldId
    before_value: CeilingValue
    after_value: CeilingValue

    def __str__(self) -> str:
        return (
            f"ceiling field {self.ceiling_field.as_str()} changed at "
            f"transition height {self.transition_height}: "
            f"genesis was {self.before_value}, observed {self.after_value}"
        )


@dataclass(frozen=True)
class GenesisCeilingsUnreadable:
    """The genesis ceilings record could not be read or
    deserialized. The chain has no genesis ceilings to compare
    against; the moat is undefined for this chain."""

    reason: str

    def __str__(self) -> str:
        return f"genesis ceilings unreadable: {self.reason}"


@dataclass(frozen=True)
class CeilingsUnreadableAtTransition:
    """A ChainVersionTransition referenced a height at which the
    ceilings record could not be read."""

    transition_height: int
    reason: str

    def __str__(self) -> str:
        return (
            f"ceilings unreadable at transition height "
            f"{self.transition_height}: {self.reason}"
        )


@dataclass(frozen=True)
class HistoryStructurallyInvalid:
    """`chain_version_history` contained a transition whose
    `activation_height` predated genesis or violated monotonic
    ordering."""

    reason: str

    def __str__(self) -> str:
        return f"chain version history structurally invalid: {self.reason}"


# Discriminated union — Python's structural equivalent of a Rust
# enum. The verifier returns `None` (Ok) or one of these four
# dataclass instances on violation.
CeilingViolation = Union[
    FieldValueChanged,
    GenesisCeilingsUnreadable,
    CeilingsUnreadableAtTransition,
    HistoryStructurallyInvalid,
]


def violation_kind(v: CeilingViolation) -> str:
    """Return the variant name as a string. Used by the CLI's
    plain-text output format per PATCH_09 §E.2."""
    return type(v).__name__
