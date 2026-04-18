"""ChainStateView Protocol + JsonChainStateFixture.

Mirrors `crates/sccgub-audit/src/chain_state.rs` per PATCH_08 §B.1
+ PATCH_09 §D.4. `ChainStateView` is a `typing.Protocol` (Python's
structural-typing analog to a Rust trait); `JsonChainStateFixture`
is a `dataclass` that loads the same JSON format the Rust fixture
emits per PATCH_09 §D.6.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, List, Mapping, Optional, Protocol, Tuple


class ChainStateError(Exception):
    """Errors ChainStateView implementations may raise when the
    chain log is unreadable, corrupted, or missing required
    entries.

    Mirrors the Rust enum's variants via subclasses.
    """

    pass


class GenesisCeilingsMissing(ChainStateError):
    """The genesis ceilings record could not be located."""

    pass


class GenesisCeilingsMalformed(ChainStateError):
    """The genesis ceilings record was found but failed to
    deserialize."""

    pass


class CeilingsMissingAtHeight(ChainStateError):
    """A ChainVersionTransition referenced a height for which the
    state view has no ceilings record."""

    def __init__(self, height: int, reason: str):
        self.height = height
        self.reason = reason
        super().__init__(f"ceilings missing at height {height}: {reason}")


class ChainStateIoError(ChainStateError):
    """I/O or backend error not specific to a single height."""

    pass


# Type alias: a JSON-decoded ConstitutionalCeilings dict. Keys are
# the Rust field names exactly (per PATCH_09 §D.6).
Ceilings = Mapping[str, Any]


@dataclass(frozen=True)
class ChainVersionTransition:
    """Mirror of Rust `sccgub_types::upgrade::ChainVersionTransition`."""

    activation_height: int
    from_version: int
    to_version: int
    upgrade_spec_hash: List[int]  # 32-byte hash as JSON int array
    proposal_id: List[int]  # 32-byte hash as JSON int array

    @classmethod
    def from_json(cls, data: Mapping[str, Any]) -> "ChainVersionTransition":
        return cls(
            activation_height=int(data["activation_height"]),
            from_version=int(data["from_version"]),
            to_version=int(data["to_version"]),
            upgrade_spec_hash=list(data["upgrade_spec_hash"]),
            proposal_id=list(data["proposal_id"]),
        )


class ChainStateView(Protocol):
    """Read-only view over a chain's state required by the verifier.

    Mirrors the Rust trait. Implementations supply the three reads;
    the verifier is the only caller and uses these reads in a
    single pass.
    """

    def genesis_block_hash(self) -> List[int]:
        """The genesis block hash as a 32-byte int list."""
        ...

    def genesis_constitutional_ceilings(self) -> Ceilings:
        """The ConstitutionalCeilings as committed at genesis.

        Raises GenesisCeilingsMissing or GenesisCeilingsMalformed
        on failure.
        """
        ...

    def chain_version_history(self) -> List[ChainVersionTransition]:
        """Every ChainVersionTransition record from genesis to tip,
        ordered ascending by activation_height. Empty iff the chain
        is genesis-only."""
        ...

    def ceilings_at_height(self, height: int) -> Ceilings:
        """The ceilings record as committed at block `height`.

        Raises CeilingsMissingAtHeight if the height has no
        ceilings record in this view.
        """
        ...


# ─── JsonChainStateFixture ────────────────────────────────────────

@dataclass
class JsonChainStateFixture:
    """A ChainStateView backed by an in-memory JSON-shaped fixture.

    Designed for tests, the CLI v1 `--chain-state <path>` mode, and
    the cross-language conformance harness (PATCH_09 §E).

    Reads the **identical JSON fixture format** the Rust port
    produces, per PATCH_09 §D.6.
    """

    genesis_block_hash: List[int]
    genesis_ceilings: Ceilings
    chain_version_history_list: List[ChainVersionTransition]
    ceilings_by_height: List[Tuple[int, Ceilings]]

    def genesis_block_hash_(self) -> List[int]:
        return self.genesis_block_hash

    def genesis_constitutional_ceilings(self) -> Ceilings:
        return self.genesis_ceilings

    def chain_version_history(self) -> List[ChainVersionTransition]:
        return list(self.chain_version_history_list)

    def ceilings_at_height(self, height: int) -> Ceilings:
        for h, c in self.ceilings_by_height:
            if h == height:
                return c
        raise CeilingsMissingAtHeight(
            height,
            f"no ceilings record in fixture for height {height}",
        )

    # NOTE: Python's Protocol is structural — `genesis_block_hash`
    # is a method on the Protocol but a Python attribute access
    # would conflict with the dataclass field of the same name.
    # We expose `genesis_block_hash_` for the verifier's use
    # internally; the verifier prefers the field directly when
    # a JsonChainStateFixture is passed.

    @classmethod
    def from_json(cls, data: Mapping[str, Any]) -> "JsonChainStateFixture":
        """Load from a JSON-decoded dict.

        The JSON shape mirrors Rust serde:

            {
                "genesis_block_hash": [u8; 32 ints],
                "genesis_ceilings": { <ceiling_field>: <int>, ... },
                "chain_version_history": [ <transition>, ... ],
                "ceilings_by_height": [ [<height>, <ceilings>], ... ]
            }
        """
        return cls(
            genesis_block_hash=list(data["genesis_block_hash"]),
            genesis_ceilings=dict(data["genesis_ceilings"]),
            chain_version_history_list=[
                ChainVersionTransition.from_json(t)
                for t in data["chain_version_history"]
            ],
            ceilings_by_height=[
                (int(pair[0]), dict(pair[1]))
                for pair in data["ceilings_by_height"]
            ],
        )


def load_fixture_from_json(path_or_text: Any) -> JsonChainStateFixture:
    """Load a JsonChainStateFixture from either a filesystem path
    or a JSON string. CLI helper.
    """
    if hasattr(path_or_text, "read"):
        text = path_or_text.read()
    elif isinstance(path_or_text, str) and "\n" in path_or_text:
        # Looks like JSON content already (multi-line string).
        text = path_or_text
    elif isinstance(path_or_text, str):
        # Treat as file path.
        with open(path_or_text, "r", encoding="utf-8") as fh:
            text = fh.read()
    else:
        # Path-like object.
        with open(path_or_text, "r", encoding="utf-8") as fh:
            text = fh.read()
    data = json.loads(text)
    return JsonChainStateFixture.from_json(data)


def genesis_preserved_fixture(
    genesis_block_hash: List[int],
    genesis_ceilings: Ceilings,
    history: List[ChainVersionTransition],
) -> JsonChainStateFixture:
    """Construct a "happy path" fixture where every height retains
    the genesis ceilings exactly. Mirrors Rust
    `JsonChainStateFixture::genesis_preserved`.
    """
    by_height: List[Tuple[int, Ceilings]] = []
    for t in history:
        if t.activation_height > 0:
            by_height.append((t.activation_height - 1, dict(genesis_ceilings)))
        by_height.append((t.activation_height, dict(genesis_ceilings)))
    return JsonChainStateFixture(
        genesis_block_hash=list(genesis_block_hash),
        genesis_ceilings=dict(genesis_ceilings),
        chain_version_history_list=list(history),
        ceilings_by_height=by_height,
    )
