$ErrorActionPreference = "Stop"
python -m pytest -q tests/test_m425_m444_physical_adaptive_assessment.py
Write-Host "M42.5-M44.4 PHYSICAL ADAPTIVE ASSESSMENT HARNESS PASSED"
Write-Host "Container execution: NOT PERFORMED BY HARNESS"
Write-Host "Network execution: NOT PERFORMED BY HARNESS"
Write-Host "Use scripts/runtime-qualification/run-physical-adaptive-assessment.ps1 for the explicit authorized local-lab physical run."
