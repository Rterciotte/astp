$ErrorActionPreference = "Stop"
$python = if (Test-Path ".\.venv\Scripts\python.exe") { ".\.venv\Scripts\python.exe" } else { "python" }

Write-Host "=== Focused M24.5-M26.4 tests ==="
& $python -m pytest .\tests\test_m245_m264_executable_workers.py -q
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host ""
Write-Host "=== Runtime progress ==="
& $python -m astp.cli runtime-progress
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host ""
Write-Host "=== Pentest readiness ==="
& $python -m astp.cli pentest-readiness
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host ""
Write-Host "M24.5-M26.4 FIELD TEST PASSED"
Write-Host "Network execution: NOT PERFORMED"
