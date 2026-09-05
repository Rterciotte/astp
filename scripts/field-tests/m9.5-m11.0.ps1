$ErrorActionPreference = "Stop"
$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$Python = Join-Path $RepoRoot ".venv\Scripts\python.exe"
Set-Location $RepoRoot

Write-Host "=== Focused M9.5-M11.0 tests ==="
& $Python -m pytest tests/test_m95_m110_integrity_closure.py -q
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

$Evidence = Join-Path $RepoRoot ".astp\smartfit-first-observation.json"
if (Test-Path $Evidence) {
    Write-Host "=== Derive stored transport provenance ==="
    & $Python -m astp.cli derive-network-evidence $Evidence `
        --output (Join-Path $RepoRoot ".astp\m110\network-evidence.yaml")
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}

Write-Host ""
Write-Host "M9.5-M11.0 FIELD TEST PASSED"
Write-Host "Network execution: NOT PERFORMED"
