$ErrorActionPreference = "Stop"
$Root = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
Push-Location $Root
try {
    python -m pytest tests/test_m365_m384_physical_execution_bridge.py -q
    if ($LASTEXITCODE -ne 0) { throw "M36.5-M38.4 focused tests failed" }
}
finally { Pop-Location }
Write-Host "M36.5-M38.4 FIELD HARNESS PASSED"
Write-Host "Container execution: NOT PERFORMED"
Write-Host "Network execution: NOT PERFORMED"
