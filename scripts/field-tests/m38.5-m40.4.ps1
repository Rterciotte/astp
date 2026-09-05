$ErrorActionPreference = "Stop"
$repo = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$python = Join-Path $repo ".venv\Scripts\python.exe"
Push-Location $repo
try {
  & $python -m pytest -q tests/test_m385_m404_multi_runtime_physical_qualification.py
  if ($LASTEXITCODE -ne 0) { throw "M38.5-M40.4 field harness failed" }
  Write-Host "M38.5-M40.4 OFFLINE FIELD HARNESS PASSED"
  Write-Host "Container execution: NOT PERFORMED BY HARNESS"
  Write-Host "Network execution: NOT PERFORMED BY HARNESS"
} finally { Pop-Location }
