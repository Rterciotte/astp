$ErrorActionPreference = "Stop"
$repo = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$python = Join-Path $repo ".venv\Scripts\python.exe"
Push-Location $repo
try {
    & $python -m pytest -q tests/test_m404a_immutable_qualification_evidence.py tests/test_m385_m404_multi_runtime_physical_qualification.py
    if ($LASTEXITCODE -ne 0) { throw "M40.4a focused regression failed" }
    Write-Host "M40.4a IMMUTABLE EVIDENCE HARNESS PASSED"
    Write-Host "Container execution: NOT PERFORMED BY HARNESS"
    Write-Host "Network execution: NOT PERFORMED BY HARNESS"
}
finally {
    Pop-Location
}
