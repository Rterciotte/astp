$ErrorActionPreference = "Stop"

Write-Host "=== Focused M18.5-M20.4 tests ==="
python -m pytest -q tests/test_m185_m204_verification_depth.py

Write-Host "`n=== Assessment depth ==="
python -m astp.cli assessment-depth

Write-Host "`n=== Worker runtime manifests ==="
python -m astp.cli show-worker-runtime-manifests

Write-Host "`n=== Verifier catalog ==="
python -m astp.cli show-verifier-catalog

Write-Host "`n=== Pentest readiness ==="
python -m astp.cli pentest-readiness

Write-Host "`nM18.5-M20.4 FIELD TEST PASSED"
Write-Host "Network execution: NOT PERFORMED"
