$ErrorActionPreference = "Stop"

$Repo = Resolve-Path (Join-Path $PSScriptRoot "..\..")
$Python = Join-Path $Repo ".venv\Scripts\python.exe"
if (-not (Test-Path $Python)) {
    throw "Python venv not found: $Python"
}

Push-Location $Repo
try {
    Write-Host "=== Focused M12.7-M14.4 tests ==="
    & $Python -m pytest -q tests/test_m127_m144_authenticated_execution.py
    if ($LASTEXITCODE -ne 0) { throw "Focused tests failed" }

    Write-Host "`n=== Assessment coverage ==="
    & $Python -m astp.cli assessment-coverage
    if ($LASTEXITCODE -ne 0) { throw "Coverage command failed" }

    Write-Host "`n=== Browser worker ceiling ==="
    & $Python -m astp.cli show-browser-worker-contract
    if ($LASTEXITCODE -ne 0) { throw "Browser contract command failed" }

    Write-Host "`n=== External adapter ceilings ==="
    & $Python -m astp.cli show-external-adapter-contracts
    if ($LASTEXITCODE -ne 0) { throw "External adapter contract command failed" }

    Write-Host "`n=== Pentest readiness ==="
    & $Python -m astp.cli pentest-readiness
    if ($LASTEXITCODE -ne 0) { throw "Pentest readiness command failed" }

    Write-Host "`n=== Explicit completion status ==="
    & $Python -m astp.cli pentest-completion
    if ($LASTEXITCODE -ne 0) { throw "Pentest completion command failed" }

    Write-Host "`nM12.7-M14.4 FIELD TEST PASSED"
    Write-Host "Network execution: NOT PERFORMED"
}
finally {
    Pop-Location
}
