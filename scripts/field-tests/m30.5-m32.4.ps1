$ErrorActionPreference = "Stop"
$python = ".\.venv\Scripts\python.exe"

Write-Host "=== Focused M30.5-M32.4 tests ==="
& $python -m pytest -q .\tests\test_m305_m324_field_qualification.py
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host "`n=== Runtime probes ==="
& $python -m astp.cli runtime-field-probes
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host "`n=== Active verifier execution catalog ==="
& $python -m astp.cli show-active-verifiers
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host "`n=== Offline E2E rehearsal ==="
& $python -m astp.cli e2e-rehearsal
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host "`n=== V1 readiness ==="
& $python -m astp.cli v1-readiness
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host "`nM30.5-M32.4 FIELD TEST PASSED"
Write-Host "Network execution: NOT PERFORMED"
