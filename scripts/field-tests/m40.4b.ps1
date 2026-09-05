$ErrorActionPreference = "Stop"
$repo = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$python = Join-Path $repo ".venv\Scripts\python.exe"

& $python -m pytest `
    (Join-Path $repo "tests\test_m404b_deterministic_bounded_output.py") `
    -q
if ($LASTEXITCODE -ne 0) { throw "M40.4b offline field harness failed" }

Write-Host "M40.4b DETERMINISTIC BOUNDED-OUTPUT HARNESS PASSED"
Write-Host "Container execution: NOT PERFORMED BY HARNESS"
Write-Host "Network execution: NOT PERFORMED BY HARNESS"
