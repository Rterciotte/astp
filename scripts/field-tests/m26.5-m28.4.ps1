$ErrorActionPreference = "Stop"

Write-Host "=== Focused M26.5-M28.4 tests ==="
python -m pytest -q tests/test_m265_m284_qualification_coordinator.py

Write-Host "`n=== Runtime progress ==="
astp runtime-progress

Write-Host "`n=== Adaptive coordinator loop ==="
astp evaluate-adaptive-loop --new-signals 1 --action-budget-remaining 2

Write-Host "`n=== Full pentest acceptance ==="
astp full-pentest-acceptance

Write-Host "`nM26.5-M28.4 FIELD TEST PASSED"
Write-Host "Network execution: NOT PERFORMED"
