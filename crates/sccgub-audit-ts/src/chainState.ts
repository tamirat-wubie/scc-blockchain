/**
 * ChainStateView interface + JsonChainStateFixture.
 *
 * Mirrors `crates/sccgub-audit/src/chain_state.rs` per PATCH_08 §B.1
 * + PATCH_09 §C.4. `ChainStateView` is a TypeScript interface
 * (structural-typing analog to a Rust trait); `JsonChainStateFixture`
 * is a class that loads the same JSON format the Rust fixture emits
 * per PATCH_09 §E.
 */

import { readFileSync } from "node:fs";

/** Errors ChainStateView implementations may raise. */
export class ChainStateError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ChainStateError";
  }
}

/** The genesis ceilings record could not be located. */
export class GenesisCeilingsMissing extends ChainStateError {
  constructor(message: string) {
    super(message);
    this.name = "GenesisCeilingsMissing";
  }
}

/** The genesis ceilings record was found but failed to deserialize. */
export class GenesisCeilingsMalformed extends ChainStateError {
  constructor(message: string) {
    super(message);
    this.name = "GenesisCeilingsMalformed";
  }
}

/**
 * A ChainVersionTransition referenced a height for which the state
 * view has no ceilings record.
 */
export class CeilingsMissingAtHeight extends ChainStateError {
  readonly height: bigint;
  readonly reason: string;
  constructor(height: bigint, reason: string) {
    super(`ceilings missing at height ${height}: ${reason}`);
    this.name = "CeilingsMissingAtHeight";
    this.height = height;
    this.reason = reason;
  }
}

/** I/O or backend error not specific to a single height. */
export class ChainStateIoError extends ChainStateError {
  constructor(message: string) {
    super(message);
    this.name = "ChainStateIoError";
  }
}

/**
 * Type alias: a JSON-decoded ConstitutionalCeilings dict. Keys are
 * the Rust field names exactly (per PATCH_09 §E).
 */
export type Ceilings = Readonly<Record<string, unknown>>;

/** Mirror of Rust `sccgub_types::upgrade::ChainVersionTransition`. */
export interface ChainVersionTransition {
  readonly activation_height: bigint;
  readonly from_version: number;
  readonly to_version: number;
  readonly upgrade_spec_hash: readonly number[]; // 32 bytes
  readonly proposal_id: readonly number[]; // 32 bytes
}

/**
 * Construct a {@link ChainVersionTransition} from a JSON-decoded
 * mapping. Coerces fields to their canonical types.
 */
export function chainVersionTransitionFromJson(
  data: Readonly<Record<string, unknown>>,
): ChainVersionTransition {
  return {
    activation_height: toBigInt(data["activation_height"]),
    from_version: Number(data["from_version"]),
    to_version: Number(data["to_version"]),
    upgrade_spec_hash: toByteArray(data["upgrade_spec_hash"]),
    proposal_id: toByteArray(data["proposal_id"]),
  };
}

/**
 * Read-only view over a chain's state required by the verifier.
 *
 * Mirrors the Rust trait. Implementations supply the four reads;
 * the verifier is the only caller and uses these reads in a single
 * pass.
 */
export interface ChainStateView {
  /** The genesis block hash as a 32-byte number array. */
  genesisBlockHash(): readonly number[];

  /**
   * The ConstitutionalCeilings as committed at genesis.
   * @throws {@link GenesisCeilingsMissing} or {@link GenesisCeilingsMalformed}.
   */
  genesisConstitutionalCeilings(): Ceilings;

  /**
   * Every ChainVersionTransition record from genesis to tip,
   * ordered ascending by activation_height. Empty iff the chain is
   * genesis-only.
   */
  chainVersionHistory(): readonly ChainVersionTransition[];

  /**
   * The ceilings record as committed at block `height`.
   * @throws {@link CeilingsMissingAtHeight} if absent.
   */
  ceilingsAtHeight(height: bigint): Ceilings;
}

/**
 * A ChainStateView backed by an in-memory JSON-shaped fixture.
 *
 * Designed for tests, the CLI v1 `--chain-state <path>` mode, and
 * the cross-language conformance harness (PATCH_09 §E).
 *
 * Reads the **identical JSON fixture format** the Rust port produces,
 * per PATCH_09 §E.
 */
export class JsonChainStateFixture implements ChainStateView {
  readonly genesis_block_hash: readonly number[];
  readonly genesis_ceilings: Ceilings;
  readonly chain_version_history: readonly ChainVersionTransition[];
  readonly ceilings_by_height: ReadonlyArray<readonly [bigint, Ceilings]>;

  constructor(
    genesisBlockHash: readonly number[],
    genesisCeilings: Ceilings,
    chainVersionHistory: readonly ChainVersionTransition[],
    ceilingsByHeight: ReadonlyArray<readonly [bigint, Ceilings]>,
  ) {
    this.genesis_block_hash = genesisBlockHash;
    this.genesis_ceilings = genesisCeilings;
    this.chain_version_history = chainVersionHistory;
    this.ceilings_by_height = ceilingsByHeight;
  }

  genesisBlockHash(): readonly number[] {
    return this.genesis_block_hash;
  }

  genesisConstitutionalCeilings(): Ceilings {
    return this.genesis_ceilings;
  }

  chainVersionHistory(): readonly ChainVersionTransition[] {
    return this.chain_version_history;
  }

  ceilingsAtHeight(height: bigint): Ceilings {
    for (const [h, c] of this.ceilings_by_height) {
      if (h === height) {
        return c;
      }
    }
    throw new CeilingsMissingAtHeight(
      height,
      `no ceilings record in fixture for height ${height}`,
    );
  }

  /** Load from a JSON-decoded value matching the Rust serde shape. */
  static fromJson(data: Readonly<Record<string, unknown>>): JsonChainStateFixture {
    const ceilingsByHeightRaw = data["ceilings_by_height"];
    if (!Array.isArray(ceilingsByHeightRaw)) {
      throw new TypeError(
        "fixture.ceilings_by_height must be an array of [height, ceilings] pairs",
      );
    }
    const ceilingsByHeight: Array<readonly [bigint, Ceilings]> = [];
    for (const pair of ceilingsByHeightRaw) {
      if (!Array.isArray(pair) || pair.length !== 2) {
        throw new TypeError(
          "fixture.ceilings_by_height entries must be 2-element arrays",
        );
      }
      ceilingsByHeight.push([
        toBigInt(pair[0]),
        pair[1] as Ceilings,
      ] as const);
    }
    const historyRaw = data["chain_version_history"];
    if (!Array.isArray(historyRaw)) {
      throw new TypeError("fixture.chain_version_history must be an array");
    }
    const history = historyRaw.map((t) =>
      chainVersionTransitionFromJson(t as Record<string, unknown>),
    );
    return new JsonChainStateFixture(
      toByteArray(data["genesis_block_hash"]),
      data["genesis_ceilings"] as Ceilings,
      history,
      ceilingsByHeight,
    );
  }
}

/**
 * Load a {@link JsonChainStateFixture} from either a filesystem
 * path or a JSON string. CLI helper.
 *
 * Uses {@link parseJsonPreservingBigInts} so that integer literals
 * larger than `Number.MAX_SAFE_INTEGER` (2^53 − 1) — which include
 * `min_effective_fee_floor` (10^16) and i128-typed ceilings — are
 * preserved as `bigint` rather than truncated to IEEE-754 doubles.
 * Without this, drift on a large-value field is invisible because
 * `1e16` and `1e16 - 1` round to the same Number.
 */
export function loadFixtureFromJson(pathOrText: string): JsonChainStateFixture {
  let text: string;
  if (pathOrText.includes("\n") && pathOrText.trimStart().startsWith("{")) {
    // Looks like JSON content already (multi-line string starting with `{`).
    text = pathOrText;
  } else {
    // Treat as file path.
    text = readFileSync(pathOrText, "utf8");
  }
  const data = parseJsonPreservingBigInts(text) as Record<string, unknown>;
  return JsonChainStateFixture.fromJson(data);
}

/**
 * Parse JSON, returning `bigint` for integer literals outside the
 * IEEE-754 safe-integer range and `number` otherwise.
 *
 * Implementation: pre-process the text by wrapping unsafe integer
 * literals in a sentinel string, then parse via stdlib `JSON.parse`
 * with a reviver that converts the sentinel back to `bigint`. This
 * keeps the function pure-stdlib (PATCH_09 §D.3) while preserving
 * value-correctness for i128-typed ceiling fields per PATCH_09 §C.
 *
 * Caveat: the regex matches integer literals in JSON value position
 * only (after `:`, `[`, or `,`). It does NOT match inside object
 * keys (always strings in JSON) or fractional numbers (which would
 * be Number anyway). The pattern is conservative.
 */
export function parseJsonPreservingBigInts(text: string): unknown {
  const SAFE_DIGITS = String(Number.MAX_SAFE_INTEGER).length; // 16
  const SENTINEL = "__sccgub_bigint__";
  const wrapped = text.replace(
    /([:\[,]\s*)(-?\d+)(?=\s*[,\]}])/g,
    (match, prefix: string, num: string): string => {
      const abs = num.startsWith("-") ? num.slice(1) : num;
      // Fast path: clearly safe-range. Leave as-is so it parses to Number.
      if (abs.length < SAFE_DIGITS) return match;
      // Borderline (16 digits): compare lexicographically against the
      // string form of MAX_SAFE_INTEGER. Equal-length strings compare
      // numerically when both are positive integer strings.
      if (
        abs.length === SAFE_DIGITS &&
        abs <= String(Number.MAX_SAFE_INTEGER)
      ) {
        return match;
      }
      return `${prefix}"${SENTINEL}${num}"`;
    },
  );
  return JSON.parse(wrapped, (_key: string, value: unknown): unknown => {
    if (typeof value === "string" && value.startsWith(SENTINEL)) {
      return BigInt(value.slice(SENTINEL.length));
    }
    return value;
  });
}

/**
 * Construct a "happy path" fixture where every height retains the
 * genesis ceilings exactly. Mirrors Rust
 * `JsonChainStateFixture::genesis_preserved` and Python
 * `genesis_preserved_fixture`.
 */
export function genesisPreservedFixture(
  genesisBlockHash: readonly number[],
  genesisCeilings: Ceilings,
  history: readonly ChainVersionTransition[],
): JsonChainStateFixture {
  const byHeight: Array<readonly [bigint, Ceilings]> = [];
  for (const t of history) {
    if (t.activation_height > 0n) {
      byHeight.push([t.activation_height - 1n, { ...genesisCeilings }] as const);
    }
    byHeight.push([t.activation_height, { ...genesisCeilings }] as const);
  }
  return new JsonChainStateFixture(
    [...genesisBlockHash],
    { ...genesisCeilings },
    [...history],
    byHeight,
  );
}

// ─── Internal coercion helpers ────────────────────────────────────

function toBigInt(v: unknown): bigint {
  if (typeof v === "bigint") return v;
  if (typeof v === "number") {
    if (!Number.isInteger(v)) {
      throw new TypeError(`expected integer, got ${v}`);
    }
    return BigInt(v);
  }
  if (typeof v === "string") return BigInt(v);
  throw new TypeError(`cannot convert ${JSON.stringify(v)} to bigint`);
}

function toByteArray(v: unknown): readonly number[] {
  if (!Array.isArray(v)) {
    throw new TypeError(`expected byte array, got ${typeof v}`);
  }
  return v.map((x) => {
    if (typeof x !== "number" || !Number.isInteger(x) || x < 0 || x > 255) {
      throw new TypeError(`byte-array element out of range: ${JSON.stringify(x)}`);
    }
    return x;
  });
}
