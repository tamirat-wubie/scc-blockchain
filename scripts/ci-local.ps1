<# 
Purpose: Local CI parity runner (fmt/build/test/truth/clippy).
Governance scope: CI verification tooling.
Dependencies: cargo, pwsh, scripts/verify-repo-truth.ps1.
Invariants: fail-fast on any non-zero exit, consistent target dir usage.
#>
param(
    [string]$TargetDir
)

$ErrorActionPreference = "Stop"

function Invoke-Checked {
    param(
        [string]$Command
    )
    Write-Host ">> $Command"
    if ($IsWindows) {
        cmd /d /c $Command
    } else {
        bash -lc $Command
    }
    if ($LASTEXITCODE -ne 0) {
        throw "Command failed: $Command"
    }
}

if ($TargetDir) {
    $env:CARGO_TARGET_DIR = $TargetDir
}

Invoke-Checked "cargo fmt --all -- --check"
Invoke-Checked "cargo build --workspace --verbose"
Invoke-Checked "cargo test -p sccgub-api openapi::tests::test_generated_openapi_matches_checked_in_artifact -- --exact"
Invoke-Checked "cargo test --workspace --verbose"
Invoke-Checked "pwsh ./scripts/verify-repo-truth.ps1"
Invoke-Checked "cargo clippy --workspace --all-targets -- -D warnings"
