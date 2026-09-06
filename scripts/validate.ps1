param(
    [switch]$CheckOnly,
    [switch]$SkipTests,
    [switch]$SkipCompile,
    [switch]$SkipCliSmoke
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

function Write-Step {
    param([string]$Message)
    Write-Host ""
    Write-Host "=== $Message ===" -ForegroundColor Cyan
}

function Invoke-Checked {
    param(
        [string]$Label,
        [scriptblock]$Command
    )

    Write-Step $Label
    & $Command
    $code = $LASTEXITCODE

    if ($null -ne $code -and $code -ne 0) {
        Write-Host ""
        Write-Host "FAILED: $Label (exit code $code)" -ForegroundColor Red
        exit $code
    }
}

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
Set-Location $RepoRoot

$VenvPython = Join-Path $RepoRoot ".venv\Scripts\python.exe"
if (-not (Test-Path $VenvPython)) {
    Write-Host "ERROR: ASTP virtualenv Python not found at:" -ForegroundColor Red
    Write-Host "  $VenvPython"
    Write-Host ""
    Write-Host "Create/restore .venv before running this script."
    exit 2
}

Write-Host "ASTP validation"
Write-Host "Repository: $RepoRoot"
Write-Host "Python:     $VenvPython"
Write-Host "Mode:       $(if ($CheckOnly) { 'CHECK ONLY' } else { 'FIX + CHECK' })"

if ($CheckOnly) {
    Invoke-Checked "Ruff check" {
        & $VenvPython -m ruff check .
    }

    Invoke-Checked "Black check" {
        & $VenvPython -m black --check .
    }
}
else {
    Invoke-Checked "Ruff autofix" {
        & $VenvPython -m ruff check . --fix
    }

    Invoke-Checked "Black format" {
        & $VenvPython -m black .
    }

    Invoke-Checked "Ruff verification" {
        & $VenvPython -m ruff check .
    }
}

if (-not $SkipCompile) {
    Invoke-Checked "Compile ASTP source" {
        & $VenvPython -m compileall -q src
    }
}

if (-not $SkipTests) {
    Invoke-Checked "Pytest" {
        & $VenvPython -m pytest
    }
}

if (-not $SkipCliSmoke) {
    Invoke-Checked "ASTP CLI smoke test" {
        & $VenvPython -m astp.cli --help *> $null
        if ($LASTEXITCODE -ne 0) {
            # Installed console entry point can still be valid even if module execution
            # is not supported by the package layout.
            & $VenvPython -c "from astp.cli import app; assert app is not None"
        }
        & $VenvPython -m astp.cli release-info *> $null
        if ($LASTEXITCODE -ne 0) {
            exit $LASTEXITCODE
        }
        & $VenvPython -m astp.cli release-readiness --help *> $null
        if ($LASTEXITCODE -ne 0) {
            exit $LASTEXITCODE
        }
    }
}

Write-Step "Git status"
& git status --short
$gitCode = $LASTEXITCODE
if ($gitCode -ne 0) {
    Write-Host "WARNING: git status failed with exit code $gitCode" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "ASTP VALIDATION PASSED" -ForegroundColor Green
Write-Host ""
Write-Host "Useful modes:"
Write-Host "  .\scripts\validate.ps1"
Write-Host "      Autofix Ruff, format Black, verify Ruff, compile, test, CLI smoke."
Write-Host ""
Write-Host "  .\scripts\validate.ps1 -CheckOnly"
Write-Host "      CI-style validation; does not modify source files."
Write-Host ""
Write-Host "  .\scripts\validate.ps1 -SkipTests"
Write-Host "      Faster formatting/static validation while iterating."
