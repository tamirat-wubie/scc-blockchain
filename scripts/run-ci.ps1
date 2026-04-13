param(
    [string]$TargetDir
)

$ErrorActionPreference = "Stop"

function Require-Command {
    param([string]$Name, [string]$InstallHint)
    if (-not (Get-Command $Name -ErrorAction SilentlyContinue)) {
        throw "Missing required command '$Name'. $InstallHint"
    }
}

Write-Host "== SCCGUB local CI gate =="

Require-Command -Name "cargo" -InstallHint "Install Rust from https://rustup.rs/"

if ($TargetDir) {
    $env:CARGO_TARGET_DIR = $TargetDir
}

Write-Host "[1/6] cargo fmt --all -- --check"
cargo fmt --all -- --check

Write-Host "[2/6] cargo build --workspace --verbose"
cargo build --workspace --verbose

Write-Host "[3/6] cargo test (OpenAPI artifact)"
cargo test -p sccgub-api openapi::tests::test_generated_openapi_matches_checked_in_artifact -- --exact

Write-Host "[4/6] cargo test --workspace --verbose"
cargo test --workspace --verbose

Write-Host "[5/6] verify-repo-truth"
pwsh ./scripts/verify-repo-truth.ps1 -TargetDir $TargetDir

Write-Host "[6/6] cargo clippy --workspace --all-targets -- -D warnings"
cargo clippy --workspace --all-targets -- -D warnings

Require-Command -Name "cargo-audit" -InstallHint "Install with: cargo install cargo-audit"
Write-Host "[7/7] cargo audit"
cargo audit

Write-Host "Local CI gate completed successfully."
