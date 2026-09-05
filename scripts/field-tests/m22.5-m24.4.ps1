$ErrorActionPreference = "Stop"
$python = if (Test-Path ".\.venv\Scripts\python.exe") { ".\.venv\Scripts\python.exe" } else { "python" }

Write-Host "=== Focused M22.5-M24.4 tests ==="
& $python -m pytest -q tests/test_m225_m244_runtime_packaging.py

Write-Host "`n=== Runtime bundle projection ==="
& $python -c "from astp.runtime_bundle import planned_runtime_bundle; from astp.runtime_readiness_projection import project_runtime_readiness; print(project_runtime_readiness(planned_runtime_bundle()).model_dump_json(indent=2))"

Write-Host "`n=== Qualification plan ==="
& $python -c "from astp.runtime_bundle import planned_runtime_bundle; from astp.runtime_qualification_plan import build_runtime_qualification_plan; print(build_runtime_qualification_plan(planned_runtime_bundle()).model_dump_json(indent=2))"

Write-Host "`nM22.5-M24.4 FIELD TEST PASSED"
Write-Host "Network execution: NOT PERFORMED"
