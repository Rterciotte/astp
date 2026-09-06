$ErrorActionPreference = "Stop"
Write-Host "M46.6a field execution outcome harness"
python -m pytest tests/test_m466a_field_execution_status.py -q
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
Write-Host "Network execution: NOT PERFORMED"
Write-Host "M46.6a FIELD HARNESS: PASS"
