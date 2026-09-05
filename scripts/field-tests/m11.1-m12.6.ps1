$ErrorActionPreference = "Stop"

$Repo = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$Python = Join-Path $Repo ".venv\Scripts\python.exe"
if (-not (Test-Path $Python)) {
    throw "ASTP venv Python not found: $Python"
}

Push-Location $Repo
try {
    Write-Host "=== Focused M11.1-M12.6 tests ==="
    & $Python -m pytest tests/test_m111_m126_multicapability_execution.py
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

    Write-Host "`n=== Safe assessment profile ==="
    & $Python -m astp.cli show-safe-assessment-profile
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

    Write-Host "`n=== Pentest readiness ==="
    & $Python -m astp.cli pentest-readiness
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

    Write-Host "`nM11.1-M12.6 FIELD TEST PASSED"
    Write-Host "Network execution: NOT PERFORMED"
}
finally {
    Pop-Location
}
