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

function Replace-Checked {
    param(
        [string]$Path,
        [string]$Pattern,
        [string]$Replacement,
        [string]$Label
    )

    $content = Get-Content -Path $Path -Raw
    if (-not [regex]::IsMatch($content, $Pattern)) {
        throw "Failed to locate $Label pattern in $Path"
    }
    $updated = [regex]::Replace($content, $Pattern, $Replacement, 1)
    if ($updated -ne $content) {
        Set-Content -Path $Path -Value $updated
    }
}

$version = Get-WorkspaceVersion
$crateCount = Get-WorkspaceCrateCount
$cliCount = Get-CliCommandCount
$routeCount = Get-VersionedRouteCount
$errorCodeCount = Get-ErrorCodeCount
$testCount = Get-WorkspaceTestCount -RequestedTargetDir $TargetDir

$readme = Join-Path $repoRoot "README.md"
$changelog = Join-Path $repoRoot "CHANGELOG.md"
$auditPrep = Join-Path $repoRoot "EXTERNAL_AUDIT_PREP.md"
$statusDoc = Join-Path $repoRoot "docs/STATUS.md"

Replace-Checked -Path $readme -Pattern 'v\d+\.\d+\.\d+' -Replacement ("v$version") -Label "README version"
Replace-Checked -Path $readme -Pattern '\d+ tests in the current workspace listing' -Replacement ("$testCount tests in the current workspace listing") -Label "README test count"
Replace-Checked -Path $readme -Pattern '## Architecture \(\d+ crates\)' -Replacement ("## Architecture ($crateCount crates)") -Label "README crate count"
Replace-Checked -Path $readme -Pattern '(?m)^\| 7 \| `sccgub-node` \| \d+ CLI commands,' -Replacement ("| 7 | ``sccgub-node`` | $cliCount CLI commands,") -Label "README CLI count"
Replace-Checked -Path $readme -Pattern '(?m)^\| 6 \| `sccgub-api` \| REST API \(\d+ versioned endpoints\),' -Replacement ("| 6 | ``sccgub-api`` | REST API ($routeCount versioned endpoints),") -Label "README route table count"
Replace-Checked -Path $readme -Pattern '- REST API with \d+ versioned endpoints' -Replacement ("- REST API with $routeCount versioned endpoints") -Label "README route bullet"
Replace-Checked -Path $readme -Pattern '## REST API \(\d+ versioned endpoints\)' -Replacement ("## REST API ($routeCount versioned endpoints)") -Label "README route header"
Replace-Checked -Path $readme -Pattern 'Structured error codes \(\d+ machine-readable `ErrorCode` variants\)\.' -Replacement ("Structured error codes ($errorCodeCount machine-readable ``ErrorCode`` variants).") -Label "README ErrorCode count"

Replace-Checked -Path $changelog -Pattern '\*\*\d+ tests, \d+ crates, persistent block log \+ snapshots, all CI green\.\*\*' -Replacement ("**$testCount tests, $crateCount crates, persistent block log + snapshots, all CI green.**") -Label "CHANGELOG summary counts"
Replace-Checked -Path $changelog -Pattern '- \d+ versioned REST endpoints with CORS' -Replacement ("- $routeCount versioned REST endpoints with CORS") -Label "CHANGELOG route count"
Replace-Checked -Path $changelog -Pattern '- \d+ machine-readable ErrorCode variants' -Replacement ("- $errorCodeCount machine-readable ErrorCode variants") -Label "CHANGELOG ErrorCode count"
Replace-Checked -Path $changelog -Pattern '- OpenAPI contract for the \d+ versioned API routes' -Replacement ("- OpenAPI contract for the $routeCount versioned API routes") -Label "CHANGELOG OpenAPI count"
Replace-Checked -Path $changelog -Pattern '- \d+ tests across \d+ crates' -Replacement ("- $testCount tests across $crateCount crates") -Label "CHANGELOG tests across crates"

Replace-Checked -Path $auditPrep -Pattern '\*\*Repo:\*\* \d+ crates, \d+ tests,' -Replacement ("**Repo:** $crateCount crates, $testCount tests,") -Label "Audit prep counts"
Replace-Checked -Path $auditPrep -Pattern 'sccgub-api\s+REST API router \+ handlers, structured errors, \d+ versioned endpoints' -Replacement ("sccgub-api         REST API router + handlers, structured errors, $routeCount versioned endpoints") -Label "Audit prep API count"

if (Test-Path -LiteralPath $statusDoc) {
    Replace-Checked -Path $statusDoc -Pattern '- REST API with \d+ versioned endpoints' -Replacement ("- REST API with $routeCount versioned endpoints") -Label "STATUS route count"
    Replace-Checked -Path $statusDoc -Pattern '- Hardening posture: \d+ tests,' -Replacement ("- Hardening posture: $testCount tests,") -Label "STATUS test count"
}

Write-Host "Repo truth updated:"
Write-Host "  Version: $version"
Write-Host "  Crates: $crateCount"
Write-Host "  CLI commands: $cliCount"
Write-Host "  Versioned routes: $routeCount"
Write-Host "  ErrorCode variants: $errorCodeCount"
Write-Host "  Tests: $testCount"
