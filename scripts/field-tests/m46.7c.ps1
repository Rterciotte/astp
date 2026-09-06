param(
    [string]$Run = ".\.astp\field-assessments\bughunt-grupo-smart-fit-bug-bounty-p-blico-400f88b1c5-20260906T131714Z"
)
$ErrorActionPreference = "Stop"

$plan = Join-Path $Run "observation-plan.yaml"
$priorities = Join-Path $Run "target-priorities.yaml"
$output = Join-Path $Run "priority-work-queue.yaml"

foreach ($path in @($plan, $priorities)) {
    if (-not (Test-Path $path)) { throw "Required artifact missing: $path" }
}

python -m astp.priority_work_queue --plan $plan --priorities $priorities --output $output --max-items 1
if ($LASTEXITCODE -ne 0) { throw "Priority-aware queue build failed." }

$raw = Get-Content $output -Raw
if ($raw -notmatch '\.js(?:\?|$)') {
    throw "Fail closed: selected queue item is not JavaScript."
}

Write-Host "`n=== SELECTED QUEUE ==="
Get-Content $output
Write-Host "`nM46.7C: OFFLINE_SELECTION_READY"
Write-Host "Permits issued: 0"
Write-Host "Network execution: NOT PERFORMED"
