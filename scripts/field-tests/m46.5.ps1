param()

$ErrorActionPreference = "Stop"
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "../..")).Path
$python = Join-Path $repoRoot ".venv/Scripts/python.exe"
if (-not (Test-Path $python)) {
    throw "ASTP virtualenv Python not found: $python"
}

Write-Host "ASTP M46.5 UNIFIED PROGRAM PRE-FLIGHT HARNESS"
Write-Host "This harness is offline. It does not contact BugHunt or any assessment target."

Push-Location $repoRoot
try {
    & $python -m pytest -q tests/test_m465_program_preflight.py
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
} finally {
    Pop-Location
}

Write-Host "M46.5 UNIFIED PROGRAM PRE-FLIGHT HARNESS PASSED"
Write-Host "External platform network execution: NOT PERFORMED BY HARNESS"
Write-Host "Assessment target network execution: NOT PERFORMED BY HARNESS"
Write-Host "Assessment worker launch: NOT PERFORMED BY HARNESS"
