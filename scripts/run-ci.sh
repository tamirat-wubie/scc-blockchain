#!/usr/bin/env bash
set -euo pipefail

TARGET_DIR="${1:-}"

if [[ -n "$TARGET_DIR" ]]; then
  export CARGO_TARGET_DIR="$TARGET_DIR"
fi

if ! command -v cargo >/dev/null 2>&1; then
  echo "Missing required command 'cargo'. Install Rust from https://rustup.rs/" >&2
  exit 1
fi

echo "== SCCGUB local CI gate =="

echo "[1/7] cargo fmt --all -- --check"
cargo fmt --all -- --check

echo "[2/7] cargo build --workspace --verbose"
cargo build --workspace --verbose

echo "[3/7] cargo test (OpenAPI artifact)"
cargo test -p sccgub-api openapi::tests::test_generated_openapi_matches_checked_in_artifact -- --exact

echo "[4/7] cargo test --workspace --verbose"
cargo test --workspace --verbose

echo "[5/7] verify-repo-truth"
pwsh ./scripts/verify-repo-truth.ps1 -TargetDir "$TARGET_DIR"

echo "[6/7] cargo clippy --workspace --all-targets -- -D warnings"
cargo clippy --workspace --all-targets -- -D warnings

if ! command -v cargo-audit >/dev/null 2>&1; then
  echo "Missing required command 'cargo-audit'. Install with: cargo install cargo-audit" >&2
  exit 1
fi

echo "[7/7] cargo audit"
cargo audit

echo "Local CI gate completed successfully."
