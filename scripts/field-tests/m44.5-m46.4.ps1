$ErrorActionPreference = "Stop"
$repo = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$python = Join-Path $repo ".venv\Scripts\python.exe"

Write-Host "ASTP M44.5-M46.4 FULL-PENTEST READINESS CLOSURE HARNESS"
Write-Host "This harness is offline and does not claim readiness from synthetic evidence."

& $python -m pytest tests/test_m445_m464_full_pentest_readiness.py -q
if ($LASTEXITCODE -ne 0) { throw "M44.5-M46.4 readiness regression tests failed" }

@'
from astp.full_pentest_readiness import evaluate_completion_gate

checks = [
    evaluate_completion_gate(new_evidence=False, new_hypotheses=False, untested_surface=False,
                             budget_remaining=True, policy_allowed=True, attestation_fresh=True).decision == "stop",
    evaluate_completion_gate(new_evidence=True, new_hypotheses=True, untested_surface=True,
                             budget_remaining=False, policy_allowed=True, attestation_fresh=True).decision == "stop",
    evaluate_completion_gate(new_evidence=True, new_hypotheses=True, untested_surface=True,
                             budget_remaining=True, policy_allowed=False, attestation_fresh=True).decision == "stop",
]
assert all(checks)
print("M44.5-M46.4 FULL-PENTEST READINESS CLOSURE HARNESS PASSED")
print("Container execution: NOT PERFORMED BY HARNESS")
print("Network execution: NOT PERFORMED BY HARNESS")
print("Readiness certification: NOT PERFORMED BY HARNESS")
'@ | & $python -
if ($LASTEXITCODE -ne 0) { throw "M44.5-M46.4 offline harness failed" }
