$ErrorActionPreference = "Stop"
Write-Host "=== Focused M16.5-M18.4 tests ==="
python -m pytest -q tests/test_m165_m184_execution_boundaries.py
Write-Host "`n=== Verifier catalog ==="
python -m astp.cli show-verifier-catalog
Write-Host "`n=== Capability matrix ==="
python -m astp.cli show-capability-matrix
Write-Host "`n=== Runtime isolation ==="
python -m astp.cli show-runtime-isolation
Write-Host "`n=== Assessment coverage ==="
python -m astp.cli assessment-coverage
Write-Host "`n=== Pentest readiness ==="
python -m astp.cli pentest-readiness
Write-Host "`nM16.5-M18.4 FIELD TEST PASSED"
Write-Host "Network execution: NOT PERFORMED"
