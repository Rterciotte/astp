param(
    [string]$Root = (Get-Location).Path
)

$ErrorActionPreference = "Stop"
if (-not $env:ASTP_PERMIT_KEY) {
    throw "ASTP_PERMIT_KEY is required."
}

Write-Host "ASTP M42.5-M44.4 authorized local physical adaptive assessment"
Write-Host "This script performs TWO bounded local-lab network actions, serially:"
Write-Host "  1. qualified Playwright observation"
Write-Host "  2. qualified ZAP passive verification with a fresh permit"
Write-Host "Target: isolated ASTP qualification lab only"

@'
import json
import os
from pathlib import Path
from astp.physical_adaptive_assessment import run_authorized_local_physical_adaptive_assessment

root = Path.cwd().resolve()
trace, path = run_authorized_local_physical_adaptive_assessment(
    root,
    signing_key=os.environ["ASTP_PERMIT_KEY"],
)
print(json.dumps({
    "trace_hash": trace.trace_hash,
    "observation_permit": trace.observation.permit_id,
    "verification_permit": trace.verification.permit_id,
    "fresh_permit": trace.replan_gate.fresh_permit,
    "coordinator_decision": trace.replan_gate.decision,
    "state_change_without_approval_blocked": (
        not trace.state_change_without_approval.executable
        and trace.state_change_without_approval.zero_worker_launch
        and trace.state_change_without_approval.zero_network_io
    ),
    "finding_count": trace.finding_count,
    "operator_review_required": trace.operator_review_required,
    "closure_ready": trace.closure_ready,
    "trace_path": str(path),
}, sort_keys=True, indent=2))
'@ | python -
