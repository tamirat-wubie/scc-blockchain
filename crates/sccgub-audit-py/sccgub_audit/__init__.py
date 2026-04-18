"""Python port of the SCCGUB ceiling-immutability verifier.

Mirrors `crates/sccgub-audit` (Rust) module-for-module per
PATCH_09.md §D.4. Pure standard library; runnable on Python 3.10+
with no `pip install` required (per §D.3).

The moat this verifies (POSITIONING §1):

    Constitutional ceilings are genesis-write-once and not
    modifiable by any governance path, including the governance
    path itself.

External auditors run this verifier against a chain log to
confirm the property without trusting the maintainer or the
substrate's internal code paths. Cross-language ports (this one
in Python; future ports in Go and TypeScript per Patch-09 §B/§C)
prove the verifier semantics are language-portable, not
Rust-bound.
"""

from .chain_state import (
    ChainStateError,
    ChainStateView,
    JsonChainStateFixture,
    load_fixture_from_json,
)
from .field import (
    CeilingFieldId,
    CeilingValue,
    field_value,
)
from .verifier import verify_ceilings_unchanged_since_genesis
from .violation import CeilingViolation

__all__ = [
    "ChainStateError",
    "ChainStateView",
    "JsonChainStateFixture",
    "load_fixture_from_json",
    "CeilingFieldId",
    "CeilingValue",
    "field_value",
    "verify_ceilings_unchanged_since_genesis",
    "CeilingViolation",
]

__version__ = "0.8.0"
