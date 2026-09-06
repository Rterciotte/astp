$ErrorActionPreference = "Stop"
Write-Host "M46.6 bounded field-assessment harness"
python -m pytest tests/test_m466_program_field_assessment.py -q
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
Write-Host "Network execution: NOT PERFORMED"
Write-Host "M46.6 FIELD HARNESS: PASS"
