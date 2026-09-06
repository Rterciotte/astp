$ErrorActionPreference = "Stop"
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "../..")).Path
$python = Join-Path $repoRoot ".venv/Scripts/python.exe"
if (-not (Test-Path $python)) {
    throw "ASTP virtualenv Python not found: $python"
}

Write-Host "ASTP M46.5a FIELD HARNESS"
Write-Host "Network execution: NOT PERFORMED"
Write-Host "Container execution: NOT PERFORMED"

Push-Location $repoRoot
try {
    & $python -m pytest -q tests/test_m465_program_preflight.py
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

    & $python -m compileall -q src tests
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

    Write-Host "M46.5a field harness: PASS"
} finally {
    Pop-Location
}
