$ErrorActionPreference = "Stop"
$repo = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$python = Join-Path $repo ".venv\Scripts\python.exe"

& $python -m pytest -q tests/test_m405_m424_adaptive_verification_e2e.py
if ($LASTEXITCODE -ne 0) { throw "M40.5-M42.4 field harness failed" }

$result = & $python -c "from astp.adaptive_verification_e2e import run_offline_adaptive_rehearsal; import json; print(json.dumps(run_offline_adaptive_rehearsal().model_dump(mode='json'), sort_keys=True))"
if ($LASTEXITCODE -ne 0) { throw "Adaptive rehearsal failed" }
$result | Write-Host
if (($result -join "`n") -notmatch '"state_change_without_approval_blocked": true') {
    throw "State-changing no-approval block was not demonstrated"
}
Write-Host "M40.5-M42.4 ADAPTIVE VERIFICATION E2E HARNESS PASSED"
Write-Host "Container execution: NOT PERFORMED BY HARNESS"
Write-Host "Network execution: NOT PERFORMED BY HARNESS"
