# Purpose: Canonical API surface demo (Windows PowerShell).
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

Write-Host "SCCGUB API surface demo (PowerShell)"

if ($Clean -and (Test-Path ".sccgub")) {
    Write-Host "Cleaning .sccgub data directory"
    Remove-Item -Recurse -Force ".sccgub"
}

Write-Host "1) Init chain"
cargo run -- init

Write-Host "2) Produce head block"
cargo run -- produce --txs 0

Write-Host "3) Transfer to create a receipt"
cargo run -- transfer 250

Write-Host "4) Start API server (background)"
$server = Start-Process -FilePath "cargo" -ArgumentList @("run","--","serve","--port","3000") -PassThru
Start-Sleep -Seconds 2

try {
    Write-Host "5) Query status"
    $status = Invoke-RestMethod -Uri "http://127.0.0.1:3000/api/v1/status" -Method Get
    Assert-Ok "status response ok" ($status.success -eq $true)

    Write-Host "6) Query latest transaction and receipt"
    $latest = Invoke-RestMethod -Uri "http://127.0.0.1:3000/api/v1/block/1" -Method Get
    Assert-Ok "block response ok" ($latest.success -eq $true)
    $txId = $latest.data.transactions[0].tx_id
    Assert-Ok "tx id present" ($txId.Length -eq 64)

    $tx = Invoke-RestMethod -Uri ("http://127.0.0.1:3000/api/v1/tx/" + $txId) -Method Get
    Assert-Ok "tx response ok" ($tx.success -eq $true)

    $receipt = Invoke-RestMethod -Uri ("http://127.0.0.1:3000/api/v1/receipt/" + $txId) -Method Get
    Assert-Ok "receipt response ok" ($receipt.success -eq $true)
} finally {
    Write-Host "7) Stop API server"
    Stop-Process -Id $server.Id -Force
}

Write-Host "API surface demo complete."
