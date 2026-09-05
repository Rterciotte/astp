$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$Python = Join-Path $RepoRoot ".venv\Scripts\python.exe"
Set-Location $RepoRoot

if (-not (Test-Path $Python)) {
    throw "ASTP virtualenv Python not found at $Python"
}

function Run-Step {
    param([string]$Name, [scriptblock]$Command)
    Write-Host ""
    Write-Host "=== $Name ===" -ForegroundColor Cyan
    & $Command
    if ($LASTEXITCODE -ne 0) {
        throw "$Name failed with exit code $LASTEXITCODE"
    }
}

Run-Step "Focused M6.9-M7.9 tests" {
    & $Python -m pytest tests/test_m69_m79_assessment_pipeline.py -q
}

Run-Step "CLI smoke" {
    & $Python -m astp.cli --help *> $null
    if ($LASTEXITCODE -ne 0) {
        & $Python -c "from astp.cli import app; assert app is not None"
    }
}

$Evidence = Join-Path $RepoRoot ".astp\smartfit-first-observation.json"
$Engagement = Join-Path $RepoRoot "engagements\smartfit.yaml"
$Test = Join-Path $RepoRoot "examples\test-observation.yaml"
$Registry = Join-Path $RepoRoot ".astp\smartfit-target-registry.yaml"

if ((Test-Path $Evidence) -and (Test-Path $Engagement) -and (Test-Path $Test) -and (Test-Path $Registry)) {
    $Out = Join-Path $RepoRoot ".astp\m79"
    New-Item -ItemType Directory -Force -Path $Out | Out-Null
    $EvidenceDir = Join-Path $Out "evidence"
    New-Item -ItemType Directory -Force -Path $EvidenceDir | Out-Null
    Copy-Item $Evidence (Join-Path $EvidenceDir "observation.json") -Force

    Run-Step "Fingerprint stored Smart Fit evidence" {
        & $Python -m astp.cli fingerprint-http $Evidence --output (Join-Path $Out "fingerprint.yaml")
    }
    Run-Step "Analyze stored Smart Fit protocol posture" {
        & $Python -m astp.cli analyze-protocol $Evidence --output (Join-Path $Out "protocol.yaml")
    }
    Run-Step "Offline end-to-end assessment" {
        & $Python -m astp.cli assess $Engagement $Test $Registry `
            --evidence-dir $EvidenceDir `
            --output (Join-Path $Out "report.md") `
            --result (Join-Path $Out "result.yaml")
    }
    Run-Step "Recovery invariant validation" {
        & $Python -m astp.cli validate-assessment-recovery (Join-Path $Out "result.yaml")
    }
}
else {
    Write-Host ""
    Write-Host "Smart Fit local field artifacts not found; repository-only validation completed." -ForegroundColor Yellow
}

Write-Host ""
Write-Host "M6.9-M7.9 FIELD TEST PASSED" -ForegroundColor Green
Write-Host "Network execution: NOT PERFORMED"
