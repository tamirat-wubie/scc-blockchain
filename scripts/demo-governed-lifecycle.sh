#!/usr/bin/env bash
# Purpose: Canonical governed lifecycle demo (POSIX shell).
# Governance scope: Demonstration only; no protocol changes.
# Dependencies: cargo, sccgub-node CLI, curl.
# Invariants: Preserve on-chain validation; no bypasses.

set -euo pipefail

assert_ok() {
  local label="$1"
  local condition="$2"
  if [[ "$condition" != "true" ]]; then
    echo "Assertion failed: ${label}" >&2
    exit 1
  fi
}

clean="${1:-}"

echo "SCCGUB governed lifecycle demo (bash)"

if [[ "$clean" == "--clean" && -d ".sccgub" ]]; then
  echo "Cleaning .sccgub data directory"
  rm -rf ".sccgub"
fi

echo "1) Init chain"
cargo run -- init

echo "2) Produce head block"
cargo run -- produce --txs 0

echo "3) Propose governed parameter update"
cargo run -- governed-propose finality.confirmation_depth 4

echo "4) Read proposal registry"
status="$(cargo run -- governed-status)"
proposal_line="$(echo "$status" | grep -m1 "id=" || true)"
assert_ok "proposal registry line found" "$( [[ -n "$proposal_line" ]] && echo true || echo false )"
proposal_id="$(echo "$proposal_line" | sed -E 's/.*id=([0-9a-fA-F]{64}).*/\1/')"
assert_ok "proposal id parsed" "$( [[ ${#proposal_id} -eq 64 ]] && echo true || echo false )"

echo "5) Vote for proposal ${proposal_id}"
cargo run -- governed-vote "$proposal_id"

echo "6) Produce timelock blocks (210)"
for _ in $(seq 1 210); do
  cargo run -- produce --txs 0 > /dev/null
done

echo "7) Verify proposal activated and config changed"
final_status="$(cargo run -- governed-status)"
final_line="$(echo "$final_status" | grep -m1 "$proposal_id" || true)"
assert_ok "proposal still present" "$( [[ -n "$final_line" ]] && echo true || echo false )"
assert_ok "proposal activated" "$( [[ "$final_line" == *"status=Activated"* ]] && echo true || echo false )"

governed_json="$(cargo run -- governed --json)"
confirmation_depth="$(echo "$governed_json" | sed -nE 's/.*"confirmation_depth":\s*([0-9]+).*/\1/p')"
assert_ok "confirmation depth updated" "$( [[ "$confirmation_depth" -eq 4 ]] && echo true || echo false )"

echo "Governed lifecycle demo complete."
