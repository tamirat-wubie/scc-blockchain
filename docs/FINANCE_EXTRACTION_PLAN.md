<!--
Purpose: Concrete execution plan for the #1 audit recommendation from
docs/THESIS_AUDIT.md and docs/THESIS_AUDIT_PT2.md: extract finance-specific
state and logic from the kernel into a first domain adapter, `sccgub-adapter-
finance`. This document is a checklist and cost estimate — not a spec, not a
release plan, not a commitment to execute.

Governance scope: doc-only. Every item is a proposed change; every number is
a survey-based estimate from the v0.7.0 codebase (main @ 987039d, 1268
tests, 62,083 LOC).

Invariants: the plan preserves every HELD invariant from docs/INVARIANTS.md
and every consensus-critical property of the kernel. The extraction is a
chain-breaking change (by PATCH_06 §34 live-upgrade protocol) but does not
retract any previously-declared invariant.

Non-goals: this plan does NOT propose the full "universal truth store" or
"six primitives" thesis. It proposes exactly one concrete refactor, with
honest cost and honest risk.
-->

# Finance Extraction Plan — Patch-09 Scoping Document

**Status**: plan, not execution. No PR opened against this plan yet.
**Target**: a future Patch-09 that extracts finance-specific state and
logic from the kernel into the first reference adapter,
`sccgub-adapter-finance`.
**Chain impact**: breaking. Requires a v6 or v7 chain-version bump via
PATCH_06 §34 live-upgrade protocol.

---

## 1 · Why this plan exists

Both thesis audits (PR #33 and PR #34) identified the same single
highest-leverage refactor: extract finance from the kernel. The full
thesis proposed 4–6 months; the audits scaled that to 6–12 months
including the chain-break accounting. This document makes the real
scope legible so the decision to commit — or to defer — can be made
against actual evidence rather than aspiration.

**If and only if** the user decides to pursue the adapter thesis, this
is the concrete first step. Otherwise this document serves as an
archive of what the kernel would need to shed to become domain-neutral.

---

## 2 · What "finance" currently is in the kernel

As of v0.7.0 main (`987039d`), the following are kernel-embedded but
functionally domain-specific (transactional-truth-only) and belong in
the finance adapter:

### 2.1 · Rust modules (full-file extractions)

| File | Role | LOC (approx) | Test surface |
|---|---|---|---|
| `crates/sccgub-state/src/balances.rs` | `BalanceLedger`; per-identity balance per asset | ~400 | Yes (balance-conservation tests) |
| `crates/sccgub-state/src/treasury.rs` | `Treasury`; fee collection + epoch rewards | ~250 | Yes |
| `crates/sccgub-state/src/escrow.rs` | Escrow state (different from Patch-07 `EscrowCommitment` — this is the old finance-escrow, to be retired) | ~200 | Yes |
| `crates/sccgub-state/src/assets.rs` | Asset registry (existing; proto to Patch-07 §C AssetRegistry) | ~150 | Yes |
| `crates/sccgub-types/src/economics.rs` | `EconomicState`, `effective_fee`, `effective_fee_median` | ~400 | Yes |
| `crates/sccgub-state/src/tension_history.rs` | Tension history (keeps — tension is kernel-level, not finance) | **KEEP IN KERNEL** | n/a |
| `crates/sccgub-types/src/contract.rs` | Contract types (partially finance — split) | ~300 | Yes (partial) |

**Total direct finance modules**: ~1700 LOC to extract.

### 2.2 · Scattered touch-points across other modules

20 `.rs` files reference `BalanceLedger`, `Treasury`, or `EconomicState`
(survey on v0.7.0 main). Each requires review for adapter boundary.
Highest-churn call sites:

- `crates/sccgub-execution/src/cpog.rs` — uses `EconomicState` for
  fee computation; kernel-level today, must route through adapter API
  after extraction. **Consensus-critical**.
- `crates/sccgub-execution/src/invariants.rs` — enforces
  balance-conservation and tension-homeostasis. Must split:
  conservation moves to adapter, tension stays.
- `crates/sccgub-state/src/apply.rs` — `apply_block_economics`,
  `apply_block_transitions`. Must become `adapter.apply(...)` calls.
- `crates/sccgub-node/src/chain.rs` — holds `balances: BalanceLedger`
  and `treasury: Treasury` directly. Must become
  `adapters: AdapterRegistry` with finance adapter owning these.
- `crates/sccgub-types/src/constitutional_ceilings.rs` — contains
  finance-specific fields (`max_tx_gas_ceiling`, fee bounds). Must
  split: gas is kernel, fee composition moves to adapter.

**Estimated per-file review cost**: 1–3 days each, 20 files = 4–8
calendar weeks.

### 2.3 · Trie keys that are finance-namespaced today

Trie keys currently at top-level `system/` or domain-less that become
`finance.v1/` under extraction:

- `balance/{agent}/{asset}` → `finance.v1/balance/{agent}/{asset}`
- `treasury/current` → `finance.v1/treasury/current`
- `escrow/{id}` → `finance.v1/escrow/{id}`
- `asset_registry/{id}` → `finance.v1/assets/{id}` (or kernel-level; see §5.2)

**Chain-break consequence**: every existing chain's state root
changes on migration because the hashed key-value pairs change.
This MUST be done via PATCH_06 §34 live-upgrade with activation
height, binary registry coordination, and a replay-authoritative
migration path. See §6 below.

### 2.4 · Test migration surface

Search for `BalanceLedger`, `Treasury`, `EconomicState` in tests:

- `crates/sccgub-node/tests/integration_test.rs` — significant
  finance test coverage; split into `finance_adapter_test.rs`.
- `crates/sccgub-node/tests/adversarial_test.rs` — includes
  balance-conservation adversarial cases; split.
- `crates/sccgub-node/tests/patch_05_conformance.rs` — uses
  economic state in fee-oracle conformance; migrate.
- `crates/sccgub-node/tests/patch_06_conformance.rs` — touches
  ceiling enforcement including finance ceilings; migrate or split.
- `crates/sccgub-node/tests/pipeline_test.rs` — end-to-end; migrate.
- `crates/sccgub-node/tests/property_test.rs` — property tests on
  conservation; split cleanly.

**Estimated test migration**: 2–4 weeks to split without regressing
coverage.

---

## 3 · What the target shape looks like

After extraction, the kernel surface is:

```
sccgub-types/             (kernel types, domain-neutral)
sccgub-crypto/            (kernel crypto)
sccgub-state/             (kernel state, no BalanceLedger/Treasury)
sccgub-execution/         (kernel Φ + phase validators, no fee composition)
sccgub-consensus/         (kernel BFT)
sccgub-governance/        (kernel governance)
sccgub-network/           (kernel networking)
sccgub-api/               (kernel + admin auth only; adapter APIs layered)
sccgub-node/              (kernel node binary)
sccgub-adapter-api/       (NEW — DomainAdapter trait + registry)
sccgub-adapter-finance/   (NEW — balances, treasury, escrow, assets,
                           economics, fee composition)
```

Kernel LOC after extraction: **~60,400** (-2,700 from current 62,083).
New adapter crate: ~1,700 LOC for finance + ~400 LOC for adapter-api
infrastructure.

---

## 4 · The `DomainAdapter` trait — first-cut proposal

The audit recommended NOT freezing the trait prematurely. Finance is
the first real adapter; extracting it defines the trait empirically.
The minimum workable trait shape (to be ratified via RFC after
extraction, not before):

```rust
pub trait DomainAdapter {
    fn domain_id(&self) -> DomainId;
    fn state_schema(&self) -> StateSchema;
    fn transition_kinds(&self) -> &[TransitionKindId];
    fn invariants(&self) -> &[InvariantId];

    fn validate(&self, tx: &Transition, ctx: &KernelCtx) -> ValidationResult;
    fn apply(&self, tx: &Transition, state: &mut DomainState) -> ApplyResult;
    fn events(&self, tx: &Transition) -> Vec<DomainEvent>;

    fn cross_domain_refs(&self) -> &[DomainRefDecl];
    fn authority_bindings(&self) -> &AuthorityMap;
}
```

**Explicit non-requirements** (to keep the trait small):

- No adapter-owned messaging (goes through kernel `Message` primitive)
- No adapter-owned crypto (goes through kernel `sccgub-crypto`)
- No adapter-owned consensus (goes through kernel BFT)
- No adapter-owned storage (goes through kernel state trie via
  namespaced keys)

**Risk**: even this minimal trait freezes interfaces that the first
adapter might need to evolve. Mitigation: version the trait
(`DomainAdapterV1`) so a future `DomainAdapterV2` is possible without
breaking every existing adapter. This is a standard platform pattern
and must be committed-to at introduction.

---

## 5 · Non-obvious extraction decisions

### 5.1 · Tension stays in the kernel

`sccgub-types::tension` and `sccgub-state::tension_history` are
**NOT** finance-specific. Tension is the kernel's ontological
homeostasis metric (see PROTOCOL.md §13 / USCL `Ι, Λ, Σ, Γ, H`); every
domain contributes to and is bounded by it. `TensionValue` remains a
kernel type. Fee composition (which uses `TensionValue`) moves to the
finance adapter, but the underlying tension primitive does not.

### 5.2 · AssetRegistry placement is disputed

The Patch-07 audit documents frame `AssetRegistry` as kernel-level
(Tier 2 in the three-tier architecture). Under the reduced-commitment
plan, the answer is:

- A kernel-level **registry of registered-asset types** (what asset
  ids exist, who issued them) = kernel concern, goes under
  `system/asset_registry/`.
- Per-asset **balance accounting and transfer logic** = finance-
  adapter concern.

This split honors the "kernel stays thin" discipline while admitting
that asset IDs are universal (other adapters will issue
non-transferable certificates, credentials, cultural tokens that need
a universal namespace).

Commit decision: **kernel owns the id space; finance adapter owns
transferable-asset semantics.** Non-transferable asset types (identity
credentials, cultural attestations) belong in their own adapters when
those adapters are built.

### 5.3 · Gas metering stays in the kernel, fee composition moves

Gas is a kernel primitive (bounds execution of every phase 8 handler
regardless of domain). The fee *formula* (`base_fee * (1 + α * T_median /
T_budget)`) is finance-specific because it maps gas units to MUL or
another tradable asset. Kernel says "this tx cost N gas units"; adapter
says "charge the sender M finance-asset units in exchange for N gas."

Split:
- `sccgub-execution::gas::BlockGasMeter` — **stays kernel**.
- `sccgub-types::economics::effective_fee_*` — **moves to adapter**.
- `sccgub-execution::cpog::gas_price` usage — **routes through
  adapter** for fee, keeps gas-limit enforcement in kernel.

### 5.4 · ConstitutionalCeilings splits partially

`ConstitutionalCeilings` holds both kernel and finance values today.
The kernel-neutral fields (proof depth, state entry size, validator
set size, view-change timeouts) stay. The finance-specific fields (tx
gas ceiling, block gas ceiling, fee-tension alpha ceiling, fee floor)
move to a finance-adapter-scoped constitutional ceiling. This requires
a legacy-cascade migration: a pre-extraction chain's `ConstitutionalCeilings`
deserializes into a new `KernelCeilings` + `FinanceAdapterCeilings`
pair at activation height.

---

## 6 · Chain-break accounting

Extraction changes state-root computation and therefore is a chain
hard fork. The procedure is the one documented in PATCH_06 §34:

1. **Governance proposal** for `UpgradeProposal` with
   `target_chain_version = v7`, `upgrade_spec_hash` hashing this
   document plus the `PATCH_09.md` (TBD) spec.
2. **Minimum lead time**: `DEFAULT_MIN_UPGRADE_LEAD_TIME = 14 400`
   blocks (§34 default). Cannot shortcut; that is the safety timer.
3. **Waiting-room window**: operators upgrade binaries during
   lead-time.
4. **Activation height**: at block `h = activation_height`:
   - Old kernel state keys migrate: `balance/{agent}/{asset}` →
     `finance.v1/balance/{agent}/{asset}` (etc. for treasury, escrow).
   - `ConstitutionalCeilings` splits into `KernelCeilings` +
     `FinanceAdapterCeilings` via legacy cascade.
   - Chain version flips to 7.
   - `ChainVersionTransition` record appended to
     `system/chain_version_history` (v0.6.1 code).
   - `verify_block_version_alignment` begins rejecting v6 blocks at
     heights ≥ `h`.
5. **Replay-authoritative migration**: nodes that replay from genesis
   re-compute the migration deterministically at height `h`. The
   migration is a pure function of pre-height state; no out-of-band
   data required.

**Pre-migration state root** (height `h-1`): fixed, never changes.
**Post-migration state root** (height `h`): reflects new
namespace-scoped keys. **New state root at `h` is NOT equal to
`h-1`'s root** — that is the hard-fork definition.

**Concrete risk**: if the migration has a bug, every running node
diverges at height `h` and the chain halts. The migration needs
exhaustive property-test coverage **before** the upgrade proposal is
admitted, not after.

---

## 7 · Cost estimate (honest)

| Work phase | Lower estimate | Upper estimate |
|---|---|---|
| Trait design + RFC | 2 weeks | 4 weeks |
| `sccgub-adapter-api` crate scaffold | 1 week | 2 weeks |
| `sccgub-adapter-finance` crate scaffold | 1 week | 2 weeks |
| Extract `balances.rs` | 2 weeks | 4 weeks |
| Extract `treasury.rs` | 1 week | 2 weeks |
| Extract `escrow.rs` (old finance) | 1 week | 2 weeks |
| Extract `assets.rs` (split kernel/adapter) | 1 week | 3 weeks |
| Extract `economics.rs` (fee composition) | 2 weeks | 4 weeks |
| Split `ConstitutionalCeilings` | 1 week | 3 weeks |
| Rewire `cpog.rs` to adapter | 2 weeks | 4 weeks |
| Rewire `apply.rs` to adapter | 2 weeks | 3 weeks |
| Migration function (height-activated) | 3 weeks | 6 weeks |
| Legacy-cascade deserialization | 2 weeks | 4 weeks |
| Test migration | 2 weeks | 4 weeks |
| Migration property tests | 3 weeks | 6 weeks |
| Cross-node replay validation | 2 weeks | 4 weeks |
| Conformance test (new) | 1 week | 2 weeks |
| OpenAPI + docs | 1 week | 2 weeks |
| CI + release cycle | 1 week | 2 weeks |

**Total (sequential)**: 28–59 calendar weeks = **~7–14 months**.

At assisted-development pace (the pace demonstrated in this v0.6.0–
v0.7.0 session arc), realistic compression: **6–9 months** of focused
work. Not the 3–6 months the audits estimated for Part 1 scope, and
not the 4–6 months the refined thesis estimated. Chain-break
accounting alone adds ~3 months that neither thesis document priced.

---

## 8 · Prerequisites before starting

Do **not** begin extraction until:

1. **Capital decision**: per audit H.1, the funding plan for 6–9
   months of focused work is documented with named funders or
   committed self-funding runway.
2. **GDPR decision**: per audit H.2, which jurisdictions this
   substrate is deployable in, and which require append-only
   carve-outs (and who operates those).
3. **INV-SUPERSESSION-CLOSURE**: the semantic of references to
   superseded facts MUST be declared in spec before it becomes
   consensus-critical. Current state: DECLARED-ONLY in
   docs/INVARIANTS.md.
4. **Patch-07 §B**: the in-trie admission-history pruning resolution
   MUST be designed (not necessarily implemented) before the
   extraction, because extraction changes which namespaces are
   in-trie and therefore affects the pruning surface. Not starting
   this until the pruning-execution model is decided.
5. **Test coverage baseline**: current 1268 tests must all pass;
   the coverage baseline for conservation invariants specifically
   must be above 95% (measurement not yet done; this is a required
   precondition).

---

## 9 · What happens if we extract finance and nothing else

Even if no second adapter is ever built, the extraction yields:

- **Cleaner kernel**: domain-neutral substrate ready to host future
  adapters if the ambition is ever pursued.
- **Reduced blast radius**: a bug in finance logic does not
  automatically bring down the kernel; the adapter can be retired
  without chain halt.
- **Independent upgrade cadence**: finance-adapter schema evolution
  does not require chain-version bumps.
- **Legibility**: the code teaches future readers the intended
  architecture rather than the as-built architecture.

These are real gains. They justify the extraction on its own merits,
independent of the wider thesis. **This is the honest case for doing
the work.**

---

## 10 · What this document is not

- Not a spec. That is `PATCH_09.md` (unwritten).
- Not a release plan. No branch exists for this work.
- Not a commitment. This plan sits on a PR reviewer's desk until the
  user decides.
- Not a refutation of the refined thesis. It is the first concrete
  step **along** the path the thesis proposed — scoped honestly.

## 11 · Decision matrix for the reader

| If you want to… | Read next |
|---|---|
| Decide whether to commit to the extraction | §7 cost estimate + §8 prerequisites |
| Understand what exactly changes in the kernel | §2 (modules + touch-points) |
| Understand the chain-break mechanics | §6 + PATCH_06 §34 |
| Understand the open design questions | §5 (non-obvious decisions) |
| Write the `PATCH_09.md` spec | §4 (trait) + §5 (splits) + §6 (migration) |
| Reject the extraction and stay with the current kernel | §9 (what is lost) |

---

**End of plan.** Doc-only. Review invited. Execution not authorized by
this document; a separate PATCH_09.md spec would be the authorizing
artifact.
