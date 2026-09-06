$ErrorActionPreference = "Stop"
$root = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
Push-Location $root
try {
    Write-Host "M46.7 permit-gated redirect continuation harness"
    pytest .\tests\test_m467_field_redirect_continuation.py -q
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    Write-Host "Network execution: NOT PERFORMED"
    Write-Host "M46.7 FIELD HARNESS: PASS"
}
finally { Pop-Location }
