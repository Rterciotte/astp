$ErrorActionPreference = "Stop"
Write-Host "=== ASTP M34.5-M36.4 offline field harness ==="
python -m pytest tests/test_m345_m364_physical_runtime_qualification.py -q
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
Write-Host "M34.5-M36.4 FIELD TEST PASSED"
Write-Host "Container execution: NOT PERFORMED"
Write-Host "Network execution: NOT PERFORMED"
