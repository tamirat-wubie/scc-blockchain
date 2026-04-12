// Purpose: Canonical end-to-end demo path for the governed chain lifecycle.
// Governance scope: Demonstration steps only; no protocol changes.
// Dependencies: sccgub-node CLI, REST API, test harnesses.
// Invariants: Demo must not modify consensus rules or bypass validation.

# Canonical Governed Lifecycle Demo

This demo is designed to be repeatable and honest about what the current
runtime supports. It uses the CLI and REST API for the live path and uses
explicit test targets for governance and escrow workflows that are wired
but not yet exposed as standalone CLI commands.

## Track A: Live CLI + API Path (Transfer + Receipt)

1. Initialize the chain:

```bash
cargo run -- init
```

2. Produce a block so the chain has a live head:

```bash
cargo run -- produce --txs 1
```

3. Perform a signed transfer and produce a block:

```bash
cargo run -- transfer 250
```

4. Start the API server:

```bash
cargo run -- serve --port 3000
```

5. Query the latest status and receipt:

```bash
curl http://127.0.0.1:3000/api/v1/status
curl http://127.0.0.1:3000/api/v1/tx/<tx_id>
curl http://127.0.0.1:3000/api/v1/receipt/<tx_id>
```

Replace `<tx_id>` with the transfer transaction id printed by the CLI.

Automation helpers:

```powershell
./scripts/demo-api-surface.ps1 -Clean
```

```bash
./scripts/demo-api-surface.sh --clean
```

See `scripts/README.md` for a consolidated list of demo scripts.

## Track B: Governance Timelock Activation (CLI)

This path exercises proposal submission, voting, timelock, and activation
through the CLI and then verifies the result with the governance registry.

```bash
cargo run -- governed-propose finality.confirmation_depth 4
cargo run -- governed-status
cargo run -- governed-vote <proposal_id>
# Produce enough blocks to clear the constitutional timelock (200 blocks).
for i in {1..210}; do cargo run -- produce --txs 0; done
cargo run -- governed-status
cargo run -- governed --json
```

Windows PowerShell automation:

```powershell
./scripts/demo-governed-lifecycle.ps1 -Clean
```

POSIX shell automation:

```bash
./scripts/demo-governed-lifecycle.sh --clean
```

```bash
cargo test -p sccgub-node test_proposal_wired_into_chain_lifecycle
cargo test -p sccgub-node test_governance_parameter_update_via_transitions
```

## Track C: Escrow Lifecycle (State Module Proof Path)

The escrow subsystem is wired and tested in the state module. This path
validates escrow create and release behavior with balance conservation.
The demo command also runs a time-locked escrow release in-memory.

```bash
cargo run -- demo
```

```bash
cargo test -p sccgub-state escrow::tests::test_create_and_release
```

## Expected Outputs

1. Track A returns 200 responses for status, tx, and receipt endpoints.
2. Track B passes with the proposal activated and recorded in governance state.
3. Track C passes with escrow balances conserved.

## Notes

- Track C uses test harnesses as canonical proof paths until dedicated
  CLI subcommands or API endpoints are added for escrow lifecycle queries.
- Demo scripts assume a fresh local data directory; remove or rename `.sccgub`
  if you want a clean run.
