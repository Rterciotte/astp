$ErrorActionPreference = "Stop"
$repo = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
Set-Location $repo
$python = Join-Path $repo ".venv\Scripts\python.exe"
if (-not (Test-Path $python)) { $python = "python" }

Write-Host "=== Focused M14.5-M16.4 tests ==="
& $python -m pytest -q tests/test_m145_m164_operational_verification.py
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host "`n=== Browser runtime status ==="
& $python -m astp.cli browser-runtime-status
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host "`n=== External adapter runtime status ==="
& $python -m astp.cli external-adapter-runtime-status
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host "`n=== Assessment coverage ==="
& $python -m astp.cli assessment-coverage
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host "`n=== Pentest readiness ==="
& $python -m astp.cli pentest-readiness
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host "`nM14.5-M16.4 FIELD TEST PASSED"
Write-Host "Network execution: NOT PERFORMED"
