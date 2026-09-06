param(
    [string]$ProgramId = "bughunt-grupo-smart-fit-bug-bounty-p-blico-400f88b1c5",
    [string]$Target = "https://smartfit.com/",
    [int]$Port = 8765,
    [int]$TimeoutSeconds = 180
)

$ErrorActionPreference = "Stop"
$root = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
Push-Location $root
try {
    Write-Host "ASTP SMART FIT BOUNDED FIELD ASSESSMENT"
    Write-Host "Program: $ProgramId"
    Write-Host "Target:  $Target"
    Write-Host "Ceiling: one GET, one fresh permit, <= reviewed rate, no state change"
    Write-Host ""

    & powershell -ExecutionPolicy Bypass -File ".\scripts\programs\run-program-preflight.ps1" `
        -ProgramId $ProgramId -Mode live -Port $Port -TimeoutSeconds $TimeoutSeconds
    if ($LASTEXITCODE -ne 0) { throw "Fresh live preflight did not become execution eligible." }

    $preflight = Get-ChildItem ".\.astp\preflight\$ProgramId\preflight-*.json" |
        Sort-Object LastWriteTime -Descending |
        Select-Object -First 1
    if (-not $preflight) { throw "No preflight report found." }

    $prepOutput = & python -m astp.program_field_assessment `
        --root $root --preflight $preflight.FullName --target $Target 2>&1
    $prepExit = $LASTEXITCODE
    $prepOutput | ForEach-Object { Write-Host $_ }
    if ($prepExit -ne 0) { throw "Bounded field assessment preparation was blocked." }

    $prep = Get-ChildItem ".\.astp\field-assessments\*\preparation-*.json" |
        Sort-Object LastWriteTime -Descending |
        Select-Object -First 1 |
        Get-Content -Raw |
        ConvertFrom-Json

    $base = Split-Path $prep.test_path
    $trace = Join-Path $base "execution-trace.jsonl"
    $manifest = Join-Path $base "evidence-manifest.jsonl"
    $ledger = Join-Path $base "session-ledger.db"

    $semanticArgs = @()
    foreach ($id in $prep.semantic_exclusion_clear_ids) {
        $semanticArgs += "--semantic-clear"
        $semanticArgs += $id
    }

    Write-Host ""
    Write-Host "Executing exactly one permit-gated GET..."
    $runArgs = @(
        "run-observation-session",
        $prep.queue_path,
        $prep.engagement_path,
        $prep.test_path,
        "--program-status-attestation", $prep.attestation_path,
        "--execute",
        "--rps", [string]$prep.requested_rps,
        "--max-actions", "1",
        "--max-requests", "1",
        "--max-errors", "1",
        "--max-actions-per-origin", "1",
        "--session-id", $prep.assessment_id,
        "--ledger-db", $ledger,
        "--trace", $trace,
        "--evidence-dir", $prep.evidence_dir,
        "--manifest", $manifest
    ) + $semanticArgs
    & astp @runArgs
    $sessionExit = $LASTEXITCODE

    # M46.6's legacy session command can return 0 even when its sole action failed.
    # Do not trust process exit status alone: classify the immutable trace/evidence.
    Write-Host ""
    Write-Host "Classifying response-backed execution evidence..."
    & python -m astp.field_execution_status `
        --session-id $prep.assessment_id `
        --trace $trace `
        --evidence-dir $prep.evidence_dir `
        --output-dir $base
    $statusExit = $LASTEXITCODE

    if ($sessionExit -ne 0 -or $statusExit -ne 0) {
        Write-Host ""
        Write-Host "SMART_FIT_BOUNDED_ASSESSMENT: EXECUTION_FAILED"
        Write-Host "Assessment directory: $base"
        Write-Host "No successful HTTP assessment/report is claimed."
        Write-Host "Operator review required before any retry."
        exit 3
    }

    Write-Host ""
    Write-Host "Building offline evidence report..."
    $assessArgs = @(
        "assess",
        $prep.engagement_path,
        $prep.test_path,
        $prep.registry_path,
        "--evidence-dir", $prep.evidence_dir,
        "--output", $prep.report_path,
        "--result", $prep.result_path,
        "--session-id", $prep.assessment_id,
        "--program-status-attestation", $prep.attestation_path,
        "--rps", [string]$prep.requested_rps
    ) + $semanticArgs
    $assessOutput = & astp @assessArgs 2>&1
    $assessExit = $LASTEXITCODE
    $assessOutput | ForEach-Object {
        if ([string]$_ -eq "Network execution: NOT PERFORMED") {
            Write-Host "Assessment analysis phase network I/O: NOT PERFORMED"
        }
        else {
            Write-Host $_
        }
    }
    if ($assessExit -ne 0) { throw "Offline assessment/report pipeline failed." }

    $statusFile = Get-ChildItem (Join-Path $base "execution-status-*.json") |
        Sort-Object LastWriteTime -Descending |
        Select-Object -First 1
    if (-not $statusFile) { throw "No execution status artifact found for provenance binding." }

    Write-Host ""
    Write-Host "Binding response-backed network provenance into assessment result/report..."
    & python -m astp.field_assessment_provenance `
        --status $statusFile.FullName `
        --evidence-dir $prep.evidence_dir `
        --result $prep.result_path `
        --report $prep.report_path `
        --output-dir $base
    if ($LASTEXITCODE -ne 0) { throw "Response-backed network provenance binding failed closed." }

    Write-Host ""
    Write-Host "SMART_FIT_BOUNDED_ASSESSMENT: COMPLETE"
    Write-Host "Report: $($prep.report_path)"
    Write-Host "Structured result: $($prep.result_path)"
    Write-Host "Network ceiling observed by wrapper: exactly one GET action"
    Write-Host "Operator review remains required."
}
finally {
    Pop-Location
}
