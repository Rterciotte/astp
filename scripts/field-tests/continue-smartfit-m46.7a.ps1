$ErrorActionPreference = "Stop"

$run = ".\.astp\field-assessments\bughunt-grupo-smart-fit-bug-bounty-p-blico-400f88b1c5-20260906T131714Z"

Write-Host "`n=== M46.7a — CONTINUE SMART FIT ASSESSMENT ===" -ForegroundColor Cyan
Write-Host "Assessment: $run"

# ----------------------------------------------------------------------
# 1. Locate immutable preparation
# ----------------------------------------------------------------------

$prepFile = Get-ChildItem $run -Filter "preparation-*.json" |
    Sort-Object LastWriteTime -Descending |
    Select-Object -First 1

if (-not $prepFile) {
    throw "Preparation artifact not found in $run"
}

$prep = Get-Content $prepFile.FullName -Raw | ConvertFrom-Json

$engagement  = $prep.engagement_path
$test        = $prep.test_path
$attestation = $prep.attestation_path
$rps         = [double]$prep.requested_rps
$semantic    = @($prep.semantic_exclusion_clear_ids)

Write-Host "`nPreparation: $($prepFile.FullName)"
Write-Host "Engagement:  $engagement"
Write-Host "Test:        $test"
Write-Host "Attestation: $attestation"
Write-Host "RPS:         $rps"
Write-Host "Semantic clears: $($semantic -join ', ')"

# ----------------------------------------------------------------------
# 2. Recover bounded operational lease
#
# This performs NO network execution.
# ----------------------------------------------------------------------

Write-Host "`n=== RECOVER OPERATIONAL LEASE ===" -ForegroundColor Cyan

$leaseOutput = & python -m astp.assessment_operational_lease `
    --preparation $prepFile.FullName 2>&1

$leaseExitCode = $LASTEXITCODE

$leaseOutput | ForEach-Object {
    Write-Host $_
}

if ($leaseExitCode -ne 0) {
    throw "Operational lease recovery failed. See ASTP reason above."
}

# Locate the immutable lease created/recovered by the command.
$leaseFile = Get-ChildItem $run -Filter "operational-lease-*.yaml" |
    Sort-Object LastWriteTime -Descending |
    Select-Object -First 1

if (-not $leaseFile) {
    throw "Operational lease artifact was not created."
}

$lease = $leaseFile.FullName

Write-Host "`nOperational lease: $lease" -ForegroundColor Green

# ----------------------------------------------------------------------
# 3. Rebuild policy-evaluated observation plan using the lease
#
# Still NO permit issuance and NO network execution.
# ----------------------------------------------------------------------

Write-Host "`n=== REPLAN OBSERVATIONS ===" -ForegroundColor Cyan

$planPath = "$run\observation-plan-m46.7a.yaml"

$planArgs = @(
    "-m", "astp.cli",
    "plan-observations",
    "$run\target-registry.yaml",
    $engagement,
    $test,
    "--output", $planPath,
    "--program-status-attestation", $attestation,
    "--program-status-lease", $lease,
    "--rps", "$rps"
)

foreach ($id in $semantic) {
    $planArgs += @("--semantic-clear", $id)
}

python @planArgs

if ($LASTEXITCODE -ne 0) {
    throw "Observation planning failed."
}

# ----------------------------------------------------------------------
# 4. Show policy result
# ----------------------------------------------------------------------

Write-Host "`n=== OBSERVATION PLAN ===" -ForegroundColor Cyan

Get-Content $planPath

# ----------------------------------------------------------------------
# 5. Check that at least one target became authorizable
# ----------------------------------------------------------------------

$planText = Get-Content $planPath -Raw

if ($planText -notmatch "status:\s*authorizable") {
    Write-Host "`nNo AUTHORIzABLE action was produced." -ForegroundColor Yellow
    Write-Host "STOP: do not issue a permit and do not perform network I/O."
    exit 2
}

Write-Host "`nPolicy produced at least one AUTHORIzABLE action." -ForegroundColor Green

# ----------------------------------------------------------------------
# 6. Re-run deterministic prioritization after M46.7a scoring fix
# ----------------------------------------------------------------------

Write-Host "`n=== REPRIORITIZE TARGETS ===" -ForegroundColor Cyan

$priorityPath = "$run\target-priorities-m46.7a.yaml"

python -m astp.cli prioritize-targets `
    "$run\target-registry.yaml" `
    --output $priorityPath

if ($LASTEXITCODE -ne 0) {
    throw "Target prioritization failed."
}

Get-Content $priorityPath

# ----------------------------------------------------------------------
# 7. Rebuild frontier after M46.7a out-of-scope filtering fix
# ----------------------------------------------------------------------

Write-Host "`n=== REBUILD FRONTIER ===" -ForegroundColor Cyan

$frontierPath = "$run\crawl-frontier-m46.7a.yaml"

python -m astp.cli build-frontier `
    "$run\target-registry.yaml" `
    --output $frontierPath `
    --max-depth 2

if ($LASTEXITCODE -ne 0) {
    throw "Frontier generation failed."
}

Get-Content $frontierPath

# ----------------------------------------------------------------------
# 8. Build bounded work queue
#
# max-items=1 is deliberate. We want exactly one candidate entering the
# permit broker during this field-test continuation.
#
# Still NO permit and NO network execution.
# ----------------------------------------------------------------------

Write-Host "`n=== BUILD SINGLE-ITEM WORK QUEUE ===" -ForegroundColor Cyan

$queuePath = "$run\queue-m46.7a.yaml"

python -m astp.cli build-work-queue `
    $planPath `
    --output $queuePath `
    --max-active-programs 1 `
    --max-items 1

if ($LASTEXITCODE -ne 0) {
    throw "Work queue generation failed."
}

Write-Host "`n=== WORK QUEUE ==="
Get-Content $queuePath

# ----------------------------------------------------------------------
# STOP BEFORE NETWORK
# ----------------------------------------------------------------------

Write-Host ""
Write-Host "============================================================" -ForegroundColor Green
Write-Host " M46.7a CONTROL-PLANE CONTINUATION COMPLETE" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Green
Write-Host ""
Write-Host "Operational lease: recovered"
Write-Host "Policy:             re-evaluated"
Write-Host "Priorities:         rebuilt"
Write-Host "Frontier:           rebuilt"
Write-Host "Queue:              max 1 item"
Write-Host "Permit issued:      NO"
Write-Host "Network execution:  NOT PERFORMED"
Write-Host ""
Write-Host "STOP here and review the queue before broker-permit."