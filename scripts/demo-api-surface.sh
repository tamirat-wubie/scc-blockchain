#!/usr/bin/env bash
# Purpose: Canonical API surface demo (POSIX shell).
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

echo "SCCGUB API surface demo (bash)"

if [[ "$clean" == "--clean" && -d ".sccgub" ]]; then
  echo "Cleaning .sccgub data directory"
  rm -rf ".sccgub"
fi

echo "1) Init chain"
cargo run -- init

echo "2) Produce head block"
cargo run -- produce --txs 0

echo "3) Transfer to create a receipt"
cargo run -- transfer 250

echo "4) Start API server (background)"
cargo run -- serve --port 3000 > /dev/null 2>&1 &
server_pid=$!
sleep 2

cleanup() {
  kill "$server_pid" >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "5) Query status"
status="$(curl -s http://127.0.0.1:3000/api/v1/status)"
assert_ok "status response ok" "$( [[ "$status" == *"\"success\":true"* ]] && echo true || echo false )"

echo "6) Query latest transaction and receipt"
latest="$(curl -s http://127.0.0.1:3000/api/v1/block/1)"
assert_ok "block response ok" "$( [[ "$latest" == *"\"success\":true"* ]] && echo true || echo false )"
tx_id="$(echo "$latest" | sed -nE 's/.*"tx_id":"([0-9a-fA-F]{64})".*/\1/p' | head -n1)"
assert_ok "tx id present" "$( [[ ${#tx_id} -eq 64 ]] && echo true || echo false )"

tx="$(curl -s http://127.0.0.1:3000/api/v1/tx/${tx_id})"
assert_ok "tx response ok" "$( [[ "$tx" == *"\"success\":true"* ]] && echo true || echo false )"

receipt="$(curl -s http://127.0.0.1:3000/api/v1/receipt/${tx_id})"
assert_ok "receipt response ok" "$( [[ "$receipt" == *"\"success\":true"* ]] && echo true || echo false )"

echo "API surface demo complete."
