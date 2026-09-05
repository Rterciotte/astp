$ErrorActionPreference = "Stop"
$python = Join-Path $PSScriptRoot "..\..\.venv\Scripts\python.exe"
if (-not (Test-Path $python)) { $python = "python" }

Write-Host "=== Focused M20.5-M22.4 tests ==="
& $python -m pytest -q tests/test_m205_m224_runtime_qualification.py
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host "`n=== Runtime specifications ==="
& $python -m astp.cli show-runtime-specs
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host "`n=== Verifier readiness ==="
& $python -m astp.cli show-verifier-readiness
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host "`n=== Completion readiness ==="
& $python -m astp.cli completion-readiness
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host "`nM20.5-M22.4 FIELD TEST PASSED"
Write-Host "Network execution: NOT PERFORMED"
