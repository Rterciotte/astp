$ErrorActionPreference = "Stop"
$python = Join-Path $PSScriptRoot "..\..\.venv\Scripts\python.exe"
if (-not (Test-Path $python)) { $python = "python" }

Write-Host "=== Focused M28.5-M30.4 tests ==="
& $python -m pytest -q tests/test_m285_m304_runtime_candidate.py
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host ""
Write-Host "=== Runtime candidate state ==="
& $python -c "import json; from astp.runtime_enablement import candidate_runtime_enablement; print(json.dumps([x.model_dump(mode='json') | {'operational_ready': x.operational_ready} for x in candidate_runtime_enablement()], indent=2))"
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host ""
Write-Host "=== Autonomous assessment candidate ==="
& $python -c "import json; from astp.assessment_candidate import current_autonomous_assessment_candidate; print(json.dumps(current_autonomous_assessment_candidate().model_dump(mode='json'), indent=2))"
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host ""
Write-Host "M28.5-M30.4 FIELD TEST PASSED"
Write-Host "Network execution: NOT PERFORMED"
