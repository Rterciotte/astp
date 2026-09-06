$ErrorActionPreference = "Stop"
Write-Host "M46.6b response-backed network provenance harness"
pytest -q tests/test_m466b_field_assessment_provenance.py
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
Write-Host "Network execution: NOT PERFORMED"
Write-Host "M46.6b FIELD HARNESS: PASS"
