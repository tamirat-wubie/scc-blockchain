param(
    [string]$TargetDir
)

$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot

function Get-WorkspaceVersion {
    $cargoToml = Get-Content -Path (Join-Path $repoRoot "Cargo.toml") -Raw
    $match = [regex]::Match($cargoToml, '(?m)^version\s*=\s*"([^"]+)"')
    if (-not $match.Success) {
        throw "Failed to locate workspace.package version in Cargo.toml"
    }
    $match.Groups[1].Value
}

function Get-WorkspaceCrateCount {
    $cargoToml = Get-Content -Path (Join-Path $repoRoot "Cargo.toml") -Raw
    ([regex]::Matches($cargoToml, '(?m)^\s*"crates/[^"]+"')).Count
}

function Get-CliCommandCount {
    $lines = Get-Content -Path (Join-Path $repoRoot "crates/sccgub-node/src/main.rs")
    $inEnum = $false
    $depth = 0
    $count = 0

    foreach ($line in $lines) {
        if (-not $inEnum) {
            if ($line -match '^enum Commands \{') {
                $inEnum = $true
                $depth = 1
            }
            continue
        }

        if ($depth -eq 1 -and $line -match '^\s{4}[A-Z][A-Za-z0-9_]*\s*(\{|,)') {
            $count++
        }

        $depth += ([regex]::Matches($line, '\{')).Count
        $depth -= ([regex]::Matches($line, '\}')).Count

        if ($depth -le 0) {
            break
        }
    }

    if ($count -eq 0) {
        throw "Failed to count CLI commands from crates/sccgub-node/src/main.rs"
    }

    $count
}

function Get-VersionedRouteCount {
    $router = Get-Content -Path (Join-Path $repoRoot "crates/sccgub-api/src/router.rs") -Raw
    $match = [regex]::Match(
        $router,
        '(?s)// Versioned routes \(preferred\)\.(.*?)// Legacy unversioned routes\.'
    )
    if (-not $match.Success) {
        throw "Failed to isolate versioned route block from crates/sccgub-api/src/router.rs"
    }

    $count = ([regex]::Matches($match.Groups[1].Value, '"/api/v1/')).Count
    if ($count -eq 0) {
        throw "Failed to count versioned API routes from crates/sccgub-api/src/router.rs"
    }
    $count
}

function Get-ErrorCodeCount {
    $responses = Get-Content -Path (Join-Path $repoRoot "crates/sccgub-api/src/responses.rs") -Raw
    $match = [regex]::Match($responses, '(?s)pub enum ErrorCode \{(.*?)\}')
    if (-not $match.Success) {
        throw "Failed to isolate ErrorCode enum from crates/sccgub-api/src/responses.rs"
    }

    $count = (
        $match.Groups[1].Value -split "`r?`n" |
        Where-Object { $_ -match '^\s*[A-Z][A-Za-z0-9_]*,\s*$' }
    ).Count

    if ($count -eq 0) {
        throw "Failed to count ErrorCode variants from crates/sccgub-api/src/responses.rs"
    }

    $count
}

function Get-OpenApiVersionedPathCount {
    $openApiPath = Join-Path $repoRoot "crates/sccgub-api/openapi.yaml"
    if (-not (Test-Path -LiteralPath $openApiPath)) {
        throw "Missing OpenAPI contract at crates/sccgub-api/openapi.yaml"
    }

    $spec = Get-Content -Path $openApiPath -Raw
    $count = ([regex]::Matches($spec, '(?m)^  /api/v1/')).Count
    if ($count -eq 0) {
        throw "Failed to count versioned OpenAPI paths from crates/sccgub-api/openapi.yaml"
    }
    $count
}

function Get-OpenApiErrorCodeCount {
    $openApiPath = Join-Path $repoRoot "crates/sccgub-api/openapi.yaml"
    $spec = Get-Content -Path $openApiPath -Raw
    $match = [regex]::Match($spec, '(?s)^    ErrorCode:\s+.*?^\s+enum:\s+(.*?)(?:^\s{4}[A-Z]|\z)', [System.Text.RegularExpressions.RegexOptions]::Multiline)
    if (-not $match.Success) {
        throw "Failed to isolate ErrorCode enum from crates/sccgub-api/openapi.yaml"
    }

    $count = ([regex]::Matches($match.Groups[1].Value, '(?m)^\s*-\s+[A-Za-z][A-Za-z0-9_]*\s*$')).Count
    if ($count -eq 0) {
        throw "Failed to count OpenAPI ErrorCode variants from crates/sccgub-api/openapi.yaml"
    }
    $count
}

function Assert-GeneratedOpenApiArtifactMatches {
    param(
        [string]$RequestedTargetDir
    )

    $previousTargetDir = $env:CARGO_TARGET_DIR
    $isWindowsHost = [System.Runtime.InteropServices.RuntimeInformation]::IsOSPlatform(
        [System.Runtime.InteropServices.OSPlatform]::Windows
    )

    if ($RequestedTargetDir) {
        $env:CARGO_TARGET_DIR = $RequestedTargetDir
    } elseif ($isWindowsHost -and -not $env:CARGO_TARGET_DIR) {
        $env:CARGO_TARGET_DIR = "target-windows-truth"
    }

    try {
        if ($isWindowsHost) {
            $output = cmd /d /c "cargo run -q -p sccgub-api --bin generate_openapi -- --check crates/sccgub-api/openapi.yaml 2>&1"
        } else {
            $output = & cargo run -q -p sccgub-api --bin generate_openapi -- --check crates/sccgub-api/openapi.yaml 2>&1
        }

        if ($LASTEXITCODE -ne 0) {
            throw "Generated OpenAPI artifact check failed:`n$($output -join [Environment]::NewLine)"
        }
    } finally {
        if ($null -eq $previousTargetDir) {
            Remove-Item Env:CARGO_TARGET_DIR -ErrorAction SilentlyContinue
        } else {
            $env:CARGO_TARGET_DIR = $previousTargetDir
        }
    }
}

function Get-WorkspaceTestCount {
    param(
        [string]$RequestedTargetDir
    )

    $previousTargetDir = $env:CARGO_TARGET_DIR
    $isWindowsHost = [System.Runtime.InteropServices.RuntimeInformation]::IsOSPlatform(
        [System.Runtime.InteropServices.OSPlatform]::Windows
    )

    if ($RequestedTargetDir) {
        $env:CARGO_TARGET_DIR = $RequestedTargetDir
    } elseif ($isWindowsHost -and -not $env:CARGO_TARGET_DIR) {
        $env:CARGO_TARGET_DIR = "target-windows-truth"
    }

    try {
        if ($isWindowsHost) {
            $output = cmd /d /c "cargo test -j 1 --workspace -- --list 2>&1"
        } else {
            $output = & cargo test -j 1 --workspace -- --list 2>&1
        }
        if ($LASTEXITCODE -ne 0) {
            throw "cargo test -- --list failed:`n$($output -join [Environment]::NewLine)"
        }

        $count = ($output | Where-Object { $_ -match ': test$' }).Count
        if ($count -eq 0) {
            throw "Workspace test listing produced zero tests"
        }

        $count
    } finally {
        if ($null -eq $previousTargetDir) {
            Remove-Item Env:CARGO_TARGET_DIR -ErrorAction SilentlyContinue
        } else {
            $env:CARGO_TARGET_DIR = $previousTargetDir
        }
    }
}

function Assert-Contains {
    param(
        [string]$Path,
        [string]$Needle
    )

    if (-not (Select-String -Path $Path -SimpleMatch $Needle -Quiet)) {
        throw "Expected '$Needle' in $Path"
    }
}

$version = Get-WorkspaceVersion
$crateCount = Get-WorkspaceCrateCount
$cliCount = Get-CliCommandCount
$routeCount = Get-VersionedRouteCount
$errorCodeCount = Get-ErrorCodeCount
$openApiPathCount = Get-OpenApiVersionedPathCount
$openApiErrorCodeCount = Get-OpenApiErrorCodeCount
$testCount = Get-WorkspaceTestCount -RequestedTargetDir $TargetDir

$readme = Join-Path $repoRoot "README.md"
$changelog = Join-Path $repoRoot "CHANGELOG.md"
$auditPrep = Join-Path $repoRoot "EXTERNAL_AUDIT_PREP.md"
$openApi = Join-Path $repoRoot "crates/sccgub-api/openapi.yaml"

Assert-Contains -Path $readme -Needle "v$version"
Assert-Contains -Path $readme -Needle "$testCount tests in the current workspace listing"
Assert-Contains -Path $readme -Needle "## Architecture ($crateCount crates)"
Assert-Contains -Path $readme -Needle ('| 7 | `sccgub-node` | ' + $cliCount + ' CLI commands,')
Assert-Contains -Path $readme -Needle ('| 6 | `sccgub-api` | REST API (' + $routeCount + ' versioned endpoints)')
Assert-Contains -Path $readme -Needle "## REST API ($routeCount versioned endpoints)"
Assert-Contains -Path $readme -Needle ('Structured error codes (' + $errorCodeCount + ' machine-readable `ErrorCode` variants).')
Assert-Contains -Path $readme -Needle 'OpenAPI contract: `crates/sccgub-api/openapi.yaml`.'

Assert-Contains -Path $changelog -Needle "## [v$version]"
Assert-Contains -Path $changelog -Needle "**$testCount tests, $crateCount crates, persistent block log + snapshots, all CI green.**"
Assert-Contains -Path $changelog -Needle "- $routeCount versioned REST endpoints with CORS"
Assert-Contains -Path $changelog -Needle "- $errorCodeCount machine-readable ErrorCode variants"
Assert-Contains -Path $changelog -Needle ("- OpenAPI contract for the " + $routeCount + " versioned API routes")
Assert-Contains -Path $changelog -Needle "- $testCount tests across $crateCount crates"

Assert-Contains -Path $auditPrep -Needle "**Repo:** $crateCount crates, $testCount tests, hardening-stage reference runtime with optional p2p alpha"
Assert-Contains -Path $auditPrep -Needle "sccgub-api         REST API router + handlers, structured errors, $routeCount versioned endpoints"
Assert-Contains -Path $auditPrep -Needle 'OpenAPI contract: `crates/sccgub-api/openapi.yaml`'

if ($openApiPathCount -ne $routeCount) {
    throw "OpenAPI path count ($openApiPathCount) does not match router versioned route count ($routeCount)"
}

if ($openApiErrorCodeCount -ne $errorCodeCount) {
    throw "OpenAPI ErrorCode count ($openApiErrorCodeCount) does not match responses.rs ErrorCode count ($errorCodeCount)"
}

Assert-GeneratedOpenApiArtifactMatches -RequestedTargetDir $TargetDir

Assert-Contains -Path $openApi -Needle "version: $version"

Write-Host "Repo truth verified:"
Write-Host "  Version: $version"
Write-Host "  Crates: $crateCount"
Write-Host "  CLI commands: $cliCount"
Write-Host "  Versioned routes: $routeCount"
Write-Host "  ErrorCode variants: $errorCodeCount"
Write-Host "  Workspace tests: $testCount"
