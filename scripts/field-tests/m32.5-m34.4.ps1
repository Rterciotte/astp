$ErrorActionPreference = "Stop"
Write-Host "=== ASTP M32.5-M34.4 offline field harness ==="
python -m pytest tests/test_m325_m344_runtime_field_bridge.py -q
python -m astp.cli runtime-image-locks | Out-Host
python -m astp.cli lab-rehearsal-plan | Out-Host
python -m astp.cli field-assessment-acceptance | Out-Host
Write-Host "M32.5-M34.4 FIELD TEST PASSED"
Write-Host "Container execution: NOT PERFORMED"
Write-Host "Network execution: NOT PERFORMED"
