# DCA Pre-Merge Audit — v0.8.3 Ceiling Field #19

**Date:** 2026-04-20
**Auditor:** Deterministic Causal Auditor (Claude, adversarial mode)
**Target:** uncommitted working tree on `impl/patch-10-v0.8.3` against `origin/main`
**Gate:** PATCH_10 §40.2 rule 3 — merge-blocking review
**Methodology:** structural adversarial review of implementation diff
**Bootstrap note:** Second application of PATCH_10 §40 discipline. The first was on the spec itself (`2026-04-19-dca-pre-merge-patch-10.md`); this is on the implementation of §39.4's types foundation.

---

## 1. Invariant integrity

`ConstitutionalCeilings::validate(&self, params)` is the canonical ceiling-vs-param symmetric check. The new branch at `constitutional_ceilings.rs:341–346`:

```rust
if params.max_forgery_vetoes_per_block_param > self.max_forgery_vetoes_per_block_ceiling {
    return Err(CeilingViolation::MaxForgeryVetoesPerBlock { … });
}
```

Defaults: ceiling = 8, param = 4. Ceiling strictly exceeds param. The comparison is **strictly greater-than**, matching the pre-existing pattern (e.g. the `max_equivocation_evidence_per_block` check at `:329`). Boundary case `param == ceiling` is accepted — consistent with all 17 sibling checks. **Invariant integrity holds at the ceilings layer.**

However, `validate()` on `ConsensusParams` itself (`consensus_params.rs:349`) explicitly documents that `max_forgery_vetoes_per_block_param == 0` is permitted ("disables the forgery-veto admission path"). This is a **one-way door**: once v0.8.5 lands evidence-layer ForgeryVeto admission (§39.3), a chain whose operators set this to 0 via genesis or governance will silently refuse *any* forgery-veto record — including legitimate ones the honest minority must file to escape slashing. There is no warning or invariant note at the spec layer that 0 changes the meaning of §39.3 entirely. **Flagged as forward-compatibility fracture.**

## 2. Backward compatibility

`LegacyConstitutionalCeilingsV2` (pre-PATCH_10, 18 fields) and `LegacyConsensusParamsV4` (v0.5.0–v0.8.2, 30 fields) are both byte-for-byte identical to the previous struct layouts by inspection. The cascade order is correct:

- Ceilings: current (19f) → V2 (18f) → V1 (17f) at `constitutional_ceilings.rs:220–228`.
- Params: current (31f) → V4 (30f) → V3 → V2 → V1 at `consensus_params.rs:190–202`.

No `#[serde(default)]` attributes on the new fields — so bincode will refuse a short byte sequence at the current-struct layer and correctly fall through to the legacy decoder. Roundtrip: a v0.8.2-serialized `ConsensusParams` has exactly the field count of `LegacyConsensusParamsV4`; deserialization will miss the trailing `u32` and fail `current`, succeed `V4`. Good.

**One subtle compat issue:** bincode's default config is fixed-int, no length framing between struct fields. An old V4 encoding is a strict prefix of a current encoding differing only in a trailing 4 bytes. If the raw bytes happen to have 4 trailing zero bytes on disk (e.g. from file-system padding or a buggy reader), bincode could decode it as the **current** struct with `max_forgery_vetoes_per_block_param = 0` — silently bypassing the V4 cascade and putting the chain in the "forgery-veto disabled" state of §1 above. Low probability, but **zero is not an inert default in the presence of silent padding.** Recommendation: set the param default to 4 AND add a post-deserialize invariant log-line when `max_forgery_vetoes_per_block_param == 0` is loaded from legacy bytes, so operators notice.

## 3. Canonical encoding

Appending field #19 at the END of both structs is consistent with the bincode-declared field order and matches `PATCH_10.md:129` ("field #19"). A v0.8.2 canonical digest over `ConsensusParams` or `ConstitutionalCeilings` will NOT match a v0.8.3 canonical digest of the same logical values, because the trailing `u32` changes the hash. This is expected and the fallback cascade handles replay. **No encoding fracture.**

The conformance-fixture JSONs were all updated to include the new field (28 fixture files touched). Since these are JSON (not bincode) they are order-agnostic but field-name-sensitive. Field-name spelling matches the Rust struct field name: `max_forgery_vetoes_per_block_ceiling`. Good.

## 4. Cross-port parity

Canonical position (last entry in the enum, last entry in the `ALL`/`all()` list):

- `crates/sccgub-audit/src/field.rs:57` — `MaxForgeryVetoesPerBlock` (19th variant), serialized string `"max_forgery_vetoes_per_block_ceiling"`.
- `crates/sccgub-audit-py/sccgub_audit/field.py:46` — `MAX_FORGERY_VETOES_PER_BLOCK = "max_forgery_vetoes_per_block_ceiling"`.
- `crates/sccgub-audit-ts/src/field.ts:41` — `MaxForgeryVetoesPerBlock: "max_forgery_vetoes_per_block_ceiling"`.

All three match byte-for-byte on the string value. Position in `ALL` is consistent (19th / last). **Cross-port parity holds on the audit-layer field enumeration.**

Defaults: the test fixtures in all three language ports set `max_forgery_vetoes_per_block_ceiling: 8`. Consistent.

## 5. Test count assertions

Swept the repo for any stale `== 18` assertions:

- `crates/sccgub-audit/src/field.rs:215` — updated to 19. ✓
- `crates/sccgub-audit-py/sccgub_audit/field.py:133` — `expected_field_count = 19`. ✓
- `crates/sccgub-audit-ts/src/field.ts:151` — `EXPECTED_FIELD_COUNT = 19`. ✓
- `crates/sccgub-audit-ts/tests/field.test.ts:46–48` — updated. ✓
- `crates/sccgub-audit-py/tests/test_field.py:42–44` — updated. ✓

**No stale 18-count assertions remain that would cause CI to silently pass against an incomplete port.** The remaining `18`s in the repo are dates, chapter numbers, and TensionValue decimal-places (unrelated).

## 6. Adversarial surface

**Fracture (major, merge-blocking):** `crates/sccgub-types/src/typed_params.rs:29–75` defines `ConsensusParamField`, the typed-governance enum used by `ModifyConsensusParam` proposals. It has NOT been updated to include `MaxForgeryVetoesPerBlockParam`. Consequences:

1. The comment in `consensus_params.rs:108–111` claims: *"Raising this param is a governance operation bounded by §17.8-symmetric."* **This is false as-implemented.** No governance path can mutate `max_forgery_vetoes_per_block_param` post-genesis because the typed-param enum has no variant for it. The only way to change the value is a genesis rewrite — which is not "governance".
2. The `validate()` comment at `consensus_params.rs:352–354` says "Zero is a legitimate operator choice" — but operators have no post-genesis mechanism to lift it from zero once chosen. The door is one-way.
3. This interacts adversarially with §38 (symmetric ceiling check) that v0.8.4 is supposed to introduce: a symmetric check has nothing to check against on the param side if the param cannot be changed.

This is **the Rust equivalent of the "stringly-typed bypass" fracture Patch-05 §25 was specifically designed to prevent** — namely, a tunable struct field that lacks a typed enum variant falls back to unreachable at runtime.

**Scaling note (minor):** cascade now has 5 legacy `ConsensusParams` variants (V1–V4 + current). Each deserialization attempt on a genuinely bad byte sequence tries all 5 decoders; still O(1) and ~microseconds, so irrelevant in practice but worth noting if the pattern continues — at V8 or V9 this begins to smell.

## 7. Scaling

No fracture. The cascade is bounded by constants and tries per-call only on actual ingest paths. Fixture file count grows O(N) with fields but this is a spec artifact, not a runtime cost.

## 8. Regulatory exposure

N/A for this diff, but: the one-way-door behavior of §1 combined with §6 fracture means an operator who accepts the PATCH_10 default without modification cannot later enable ForgeryVeto admission once §39.3 ships without a hard-fork + genesis rewrite. This surfaces as a potential **governance-ossification claim** under MiCA Art. 34 expectations of amendable consensus parameters. Flag for PATCH_10 §38 (v0.8.4) drafter.

## 9. Fracture ranking

**FRACTURE-V083-01 (MERGE-BLOCKING).** `crates/sccgub-types/src/typed_params.rs:74` — `ConsensusParamField` enum missing `MaxForgeryVetoesPerBlockParam`. The new `ConsensusParams` field at `consensus_params.rs:115` has no typed-governance surface, contradicting the comment on lines 108–111 and the spec's §17.8-symmetric claim. **Fix: add the variant to `ConsensusParamField`, extend the match in `apply_typed_param` (`typed_params.rs:189–234`), and add a test that `ModifyConsensusParam { field: MaxForgeryVetoesPerBlockParam, … }` roundtrips.** Without this fix the v0.8.3 "types foundation" is not actually a foundation for v0.8.4 — it's a dead-end.

**FRACTURE-V083-02 (MERGE-BLOCKING-OR-JUSTIFY).** `crates/sccgub-types/src/consensus_params.rs:349–355` — `max_forgery_vetoes_per_block_param = 0` passes `validate()` and is documented as "legitimate". Combined with FRACTURE-V083-01 this is a one-way door (set at genesis, cannot be raised later). Either: (a) require `> 0` the same way `max_equivocation_evidence_per_block_param` is required (line 349); or (b) add the typed-param variant per FRACTURE-V083-01 AND add a prominent note in PATCH_10 §39.4 that operators should not use 0 in genesis without also preparing a governance path. Recommend (a) — the "zero disables" design is a regulatory/governance trap.

**FRACTURE-V083-03 (LOW).** `crates/sccgub-types/src/constitutional_ceilings.rs:186` — the doc comment on `from_canonical_bytes` says "fee-floor default is a no-op for any chain with base_fee >= floor" but the revised comment no longer preserves this concrete guarantee for the new ceiling ("safely bounded" is vaguer). Tighten to: "ceiling default (8) is a no-op for any chain where max_forgery_vetoes_per_block_param <= 8, which includes every chain using default ConsensusParams (param = 4)." Purely documentary; not merge-blocking.

---

## Verdict

**MERGE BLOCKED** on FRACTURE-V083-01 and FRACTURE-V083-02.

The types-only slice claim in the PR description is **not actually complete as a types slice**: adding a field to `ConsensusParams` without the corresponding `ConsensusParamField` variant is exactly the structural hole Patch-05 §25 closed. Fixing both fractures is ~30 LoC in `typed_params.rs` + one test. After that, v0.8.3 is clean to merge.

Per §40.2 rule 3: this audit artifact should be saved to `docs/audits/2026-04-20-dca-pre-merge-v0.8.3-ceiling-field-19.md` and the PR description updated to reference it before re-requesting merge approval.

---

## Drafter response (applied in-PR)

All three fractures remediated before opening the PR:

| Finding | Severity | Disposition | File / line |
|---|---|---|---|
| **FRACTURE-V083-01** — typed-param variant missing | MERGE-BLOCKING | remediated-in-PR | `typed_params.rs:78` (enum variant) + `typed_params.rs:237-239` (apply branch) + 2 new tests at `typed_params.rs:424-458` (happy path + type-mismatch) |
| **FRACTURE-V083-02** — `= 0` one-way door | MERGE-BLOCKING | remediated-in-PR | `consensus_params.rs:362-380` (`validate()` rejects `= 0` with rationale block citing this audit); field doc updated to remove "zero is valid" claim |
| **FRACTURE-V083-03** — doc comment vague | LOW | remediated-in-PR | `constitutional_ceilings.rs:186-194` (tightened to "no-op for any chain where `max_forgery_vetoes_per_block_param <= 8`") |

Verification: `cargo test -p sccgub-types` → 338 tests pass (up from 336; +2 new typed_param roundtrip tests for the V083-01 closure).

This is the second application of the DCA-before-merge discipline (§40.2). The first was on the PATCH_10 spec itself (2026-04-19 artifact), which found 6 fractures. This one found 3. **In both cases, the adversarial agent found substantive issues the drafter missed.** Pattern reproducing: merge-before-review would have shipped both classes of fracture.

---

*End of pre-merge DCA audit. Gate lifted; v0.8.3 is clean to merge after fmt/lint/conformance CI.*
