param(
    [string]$ProgramId = "bughunt-grupo-smart-fit-bug-bounty-p-blico-400f88b1c5",
    [int]$Port = 8765,
    [int]$TimeoutSeconds = 180
)

$ErrorActionPreference = "Stop"

$root = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$python = Join-Path $root ".venv\Scripts\python.exe"

$oldRun = Join-Path $root `
    ".astp\field-assessments\bughunt-grupo-smart-fit-bug-bounty-p-blico-400f88b1c5-20260906T153820Z"

if (-not (Test-Path $python)) {
    throw "ASTP virtualenv Python not found: $python"
}

if (-not (Test-Path $oldRun)) {
    throw "Previous assessment not found: $oldRun"
}

Push-Location $root

try {
    Write-Host ""
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host " SMART FIT M46.7a - AUTHORIZATION CONTINUATION" -ForegroundColor Cyan
    Write-Host "============================================================"
    Write-Host ""
    Write-Host "Previous assessment:"
    Write-Host "  $oldRun"
    Write-Host ""
    Write-Host "This script will:"
    Write-Host "  1. refresh BugHunt operational pre-flight"
    Write-Host "  2. prepare a NEW assessment"
    Write-Host "  3. NOT execute the homepage"
    Write-Host "  4. create the bounded operational lease"
    Write-Host "  5. carry forward discovered surface"
    Write-Host "  6. re-evaluate policy"
    Write-Host "  7. stop BEFORE permit/network execution"
    Write-Host ""

    # ------------------------------------------------------------
    # 1. Fresh authenticated operational pre-flight
    #
    # This is the only browser/manual refresh in this continuation.
    # It does NOT perform the Smart Fit target GET.
    # ------------------------------------------------------------

    Write-Host "=== 1. FRESH PROGRAM PRE-FLIGHT ===" -ForegroundColor Cyan

    & powershell -ExecutionPolicy Bypass `
        -File ".\scripts\programs\run-program-preflight.ps1" `
        -ProgramId $ProgramId `
        -Mode live `
        -Port $Port `
        -TimeoutSeconds $TimeoutSeconds

    if ($LASTEXITCODE -ne 0) {
        throw "Fresh live pre-flight did not become execution eligible."
    }

    $preflight = Get-ChildItem ".\.astp\preflight\$ProgramId\preflight-*.json" |
        Sort-Object LastWriteTime -Descending |
        Select-Object -First 1

    if (-not $preflight) {
        throw "Fresh pre-flight report not found."
    }

    Write-Host ""
    Write-Host "Fresh pre-flight:"
    Write-Host "  $($preflight.FullName)" -ForegroundColor Green

    # ------------------------------------------------------------
    # 2. Prepare a NEW assessment.
    #
    # IMPORTANT:
    # program_field_assessment only prepares artifacts.
    # We deliberately DO NOT invoke run-observation-session.
    # Therefore there is no Smart Fit HTTP request here.
    # ------------------------------------------------------------

    Write-Host ""
    Write-Host "=== 2. PREPARE NEW ASSESSMENT — NO TARGET EXECUTION ===" `
        -ForegroundColor Cyan

    $prepareOutput = & $python -m astp.program_field_assessment `
        --root $root `
        --preflight $preflight.FullName `
        --target "https://www.smartfit.com.br/" `
        2>&1

    $prepareExit = $LASTEXITCODE

    $prepareOutput | ForEach-Object {
        Write-Host $_
    }

    if ($prepareExit -ne 0) {
        throw "New bounded assessment preparation was blocked."
    }

    # Find preparation created after the new pre-flight.
    $newPrepFile = Get-ChildItem ".\.astp\field-assessments\*\preparation-*.json" |
        Where-Object {
            $_.LastWriteTimeUtc -ge $preflight.LastWriteTimeUtc.AddSeconds(-5)
        } |
        Sort-Object LastWriteTimeUtc -Descending |
        Select-Object -First 1

    if (-not $newPrepFile) {
        throw "Could not identify the newly prepared assessment."
    }

    $newPrep = Get-Content $newPrepFile.FullName -Raw |
        ConvertFrom-Json

    $newRun = Split-Path $newPrepFile.FullName

    if ((Resolve-Path $newRun).Path -eq (Resolve-Path $oldRun).Path) {
        throw "New assessment unexpectedly resolved to previous assessment."
    }

    Write-Host ""
    Write-Host "New assessment:"
    Write-Host "  $newRun" -ForegroundColor Green

    Write-Host ""
    Write-Host "Network execution so far: NOT PERFORMED"

    # ------------------------------------------------------------
    # 3. Create/recover M46.7a operational lease immediately.
    # ------------------------------------------------------------

    Write-Host ""
    Write-Host "=== 3. CREATE ASSESSMENT OPERATIONAL LEASE ===" `
        -ForegroundColor Cyan

    $leaseOutput = & $python -m astp.assessment_operational_lease `
        --preparation $newPrepFile.FullName `
        2>&1

    $leaseExit = $LASTEXITCODE

    $leaseOutput | ForEach-Object {
        Write-Host $_
    }

    if ($leaseExit -ne 0) {
        throw "Operational lease creation failed. See ASTP reason above."
    }

    $leaseFile = Get-ChildItem $newRun -Filter "operational-lease-*.yaml" |
        Sort-Object LastWriteTimeUtc -Descending |
        Select-Object -First 1

    if (-not $leaseFile) {
        throw "Operational lease artifact not found."
    }

    Write-Host ""
    Write-Host "Lease:"
    Write-Host "  $($leaseFile.FullName)" -ForegroundColor Green

    # ------------------------------------------------------------
    # 4. Carry forward DISCOVERY STATE only.
    #
    # No permit, execution trace, runtime DB, rate state, or old
    # execution authorization is copied.
    # ------------------------------------------------------------

    Write-Host ""
    Write-Host "=== 4. CARRY FORWARD DISCOVERED SURFACE ===" `
        -ForegroundColor Cyan

    $carryFiles = @(
        "target-registry.yaml",
        "javascript-inventory.yaml",
        "javascript-fetch-plan.yaml"
    )

    foreach ($name in $carryFiles) {

        $source = Join-Path $oldRun $name
        $dest   = Join-Path $newRun $name

        if (Test-Path $source) {
            Copy-Item $source $dest -Force
            Write-Host "Carried forward: $name"
        }
        else {
            Write-Host "Not present, skipped: $name" `
                -ForegroundColor Yellow
        }
    }

    if (-not (Test-Path (Join-Path $newRun "target-registry.yaml"))) {
        throw "No target registry available for continuation."
    }

    Write-Host ""
    Write-Host "No old permit/runtime/authorization state was copied."

    # ------------------------------------------------------------
    # 5. Resolve current policy inputs from NEW preparation.
    # ------------------------------------------------------------

    $engagement  = $newPrep.engagement_path
    $test        = $newPrep.test_path
    $attestation = $newPrep.attestation_path
    $rps         = [double]$newPrep.requested_rps
    $semantic    = @($newPrep.semantic_exclusion_clear_ids)

    # ------------------------------------------------------------
    # 6. Re-prioritize under M46.7a.
    # ------------------------------------------------------------

    Write-Host ""
    Write-Host "=== 5. REPRIORITIZE DISCOVERED TARGETS ===" `
        -ForegroundColor Cyan

    $priorityPath = Join-Path $newRun "target-priorities-m46.7a.yaml"

    & $python -m astp.cli prioritize-targets `
        (Join-Path $newRun "target-registry.yaml") `
        --output $priorityPath

    if ($LASTEXITCODE -ne 0) {
        throw "Target prioritization failed."
    }

    # ------------------------------------------------------------
    # 7. Rebuild frontier.
    # ------------------------------------------------------------

    Write-Host ""
    Write-Host "=== 6. REBUILD FRONTIER ===" -ForegroundColor Cyan

    $frontierPath = Join-Path $newRun "crawl-frontier-m46.7a.yaml"

    & $python -m astp.cli build-frontier `
        (Join-Path $newRun "target-registry.yaml") `
        --output $frontierPath `
        --max-depth 2

    if ($LASTEXITCODE -ne 0) {
        throw "Frontier generation failed."
    }

    # ------------------------------------------------------------
    # 8. Re-evaluate every carried-forward candidate against
    #    CURRENT engagement + CURRENT attestation + NEW lease.
    # ------------------------------------------------------------

    Write-Host ""
    Write-Host "=== 7. POLICY REPLAN WITH OPERATIONAL LEASE ===" `
        -ForegroundColor Cyan

    $planPath = Join-Path $newRun "observation-plan-m46.7a.yaml"

    $planArgs = @(
        "-m", "astp.cli",
        "plan-observations",
        (Join-Path $newRun "target-registry.yaml"),
        $engagement,
        $test,
        "--output", $planPath,
        "--program-status-attestation", $attestation,
        "--program-status-lease", $leaseFile.FullName,
        "--rps", [string]$rps
    )

    foreach ($id in $semantic) {
        $planArgs += @("--semantic-clear", $id)
    }

    & $python @planArgs

    if ($LASTEXITCODE -ne 0) {
        throw "Observation replanning failed."
    }

    # ------------------------------------------------------------
    # 9. Parse YAML with ASTP/Python rather than PowerShell regex.
    # ------------------------------------------------------------

    Write-Host ""
    Write-Host "=== 8. POLICY SUMMARY ===" -ForegroundColor Cyan

    $summaryCode = @'
import sys
from pathlib import Path
import yaml

path = Path(sys.argv[1])
data = yaml.safe_load(path.read_text(encoding="utf-8"))

items = data.get("items", [])

for item in items:
    print(
        f"{item.get('id')} | "
        f"{item.get('status')} | "
        f"{item.get('authorization_decision')} | "
        f"{item.get('target')} | "
        f"{item.get('reason')}"
    )

auth = [x for x in items if x.get("status") == "authorizable"]

print()
print(f"TOTAL={len(items)}")
print(f"AUTHORIZABLE={len(auth)}")

if not auth:
    sys.exit(2)
'@

    $summaryCode | & $python - $planPath
    $summaryExit = $LASTEXITCODE

    if ($summaryExit -eq 2) {
        Write-Host ""
        Write-Host "No authorizable target." -ForegroundColor Yellow
        Write-Host "STOP: no permit and no network execution."
        exit 2
    }

    if ($summaryExit -ne 0) {
        throw "Could not parse observation plan."
    }

    # ------------------------------------------------------------
    # IMPORTANT:
    # Do not call build-work-queue automatically yet.
    #
    # The historical queue builder may preserve registry order
    # rather than M46.7a priority order. We first inspect which
    # JS target became highest priority.
    # ------------------------------------------------------------

    Write-Host ""
    Write-Host "=== 9. TOP PRIORITIES ===" -ForegroundColor Cyan
    Get-Content $priorityPath |
        Select-Object -First 100

    Write-Host ""
    Write-Host "============================================================" `
        -ForegroundColor Green
    Write-Host " CONTROL-PLANE CONTINUATION COMPLETE" `
        -ForegroundColor Green
    Write-Host "============================================================" `
        -ForegroundColor Green

    Write-Host ""
    Write-Host "Fresh pre-flight:      YES"
    Write-Host "New assessment:        YES"
    Write-Host "Operational lease:     YES"
    Write-Host "Old discovery carried: YES"
    Write-Host "Policy re-evaluated:   YES"
    Write-Host "Permit issued:         NO"
    Write-Host "Smart Fit GET:         NOT PERFORMED"
    Write-Host "Network execution:     NOT PERFORMED"
    Write-Host ""
    Write-Host "New assessment directory:"
    Write-Host "  $newRun"
    Write-Host ""
    Write-Host "STOP before permit issuance."
}
finally {
    Pop-Location
}
