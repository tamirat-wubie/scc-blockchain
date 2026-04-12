# Purpose: Canonical governed lifecycle demo (Windows PowerShell).
# Governance scope: Demonstration only; no protocol changes.
# Dependencies: cargo, sccgub-node CLI, curl (Invoke-WebRequest fallback).
# Invariants: Preserve on-chain validation; no bypasses.

$ErrorActionPreference = "Stop"

function Assert-Ok {
    param(
        [string]$Label,
        [bool]$Condition
    )
    if (-not $Condition) {
        throw "Assertion failed: $Label"
    }
}

param(
    [switch]$Clean
)

Write-Host "SCCGUB governed lifecycle demo (PowerShell)"

if ($Clean -and (Test-Path ".sccgub")) {
    Write-Host "Cleaning .sccgub data directory"
    Remove-Item -Recurse -Force ".sccgub"
}

Write-Host "1) Init chain"
cargo run -- init

Write-Host "2) Produce head block"
cargo run -- produce --txs 0

Write-Host "3) Propose governed parameter update"
cargo run -- governed-propose finality.confirmation_depth 4

Write-Host "4) Read proposal registry"
$status = cargo run -- governed-status
$proposalLine = $status | Where-Object { $_ -match "id=" } | Select-Object -First 1
Assert-Ok "proposal registry line found" ($null -ne $proposalLine)
$proposalId = ($proposalLine -split "id=")[1].Split(" ")[0]
Assert-Ok "proposal id parsed" ($proposalId.Length -eq 64)

Write-Host "5) Vote for proposal $proposalId"
cargo run -- governed-vote $proposalId

Write-Host "6) Produce timelock blocks (210)"
for ($i = 1; $i -le 210; $i++) {
    cargo run -- produce --txs 0 | Out-Null
}

Write-Host "7) Verify proposal activated and config changed"
$finalStatus = cargo run -- governed-status
$finalLine = $finalStatus | Where-Object { $_ -match $proposalId } | Select-Object -First 1
Assert-Ok "proposal still present" ($null -ne $finalLine)
Assert-Ok "proposal activated" ($finalLine -match "status=Activated")

$governedJson = cargo run -- governed --json | ConvertFrom-Json
Assert-Ok "confirmation depth updated" ($governedJson.finality.confirmation_depth -eq 4)

Write-Host "Governed lifecycle demo complete."
