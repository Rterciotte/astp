param(
    [Parameter(Mandatory = $true)]
    [string]$SourceAssessment,
    [string]$ProgramId = "bughunt-grupo-smart-fit-bug-bounty-p-blico-400f88b1c5",
    [int]$Port = 8765,
    [int]$TimeoutSeconds = 180
)

$ErrorActionPreference = "Stop"
$root = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
Push-Location $root
try {
    $source = (Resolve-Path $SourceAssessment).Path
    Write-Host "ASTP M46.7 PERMIT-GATED REDIRECT CONTINUATION"
    Write-Host "Source assessment: $source"
    Write-Host ""

    $candidateOutput = & python -m astp.field_redirect_continuation `
        --source-assessment $source 2>&1
    $candidateExit = $LASTEXITCODE
    $candidateOutput | ForEach-Object { Write-Host $_ }
    if ($candidateExit -ne 0) { throw "Redirect continuation candidate was blocked." }

    $candidateFile = Get-ChildItem $source -Filter "redirect-candidate-*.json" |
        Sort-Object LastWriteTime -Descending |
        Select-Object -First 1
    if (-not $candidateFile) { throw "No immutable redirect candidate artifact found." }
    $candidate = Get-Content $candidateFile.FullName -Raw | ConvertFrom-Json

    if ($candidate.requires_new_permit -ne $true) { throw "Redirect candidate does not require a new permit." }
    if ($candidate.automatic_redirect_follow -ne $false) { throw "Automatic redirect following is forbidden." }
    if ($candidate.state_changing -ne $false -or $candidate.broad_scanning -ne $false) {
        throw "Redirect candidate exceeds M46.7 safety ceiling."
    }

    Write-Host ""
    Write-Host "Candidate accepted for fresh authorization cycle: $($candidate.redirect_target)"
    Write-Host "The next wrapper performs a NEW live preflight and brokers a NEW permit."
    Write-Host "No redirect is automatically followed."
    Write-Host ""

    & powershell -ExecutionPolicy Bypass -File ".\scripts\programs\run-smartfit-bounded-assessment.ps1" `
        -ProgramId $ProgramId `
        -Target $candidate.redirect_target `
        -Port $Port `
        -TimeoutSeconds $TimeoutSeconds
    if ($LASTEXITCODE -ne 0) { throw "Fresh permit-gated redirect continuation assessment failed or blocked." }

    Write-Host ""
    Write-Host "M46.7_REDIRECT_CONTINUATION: COMPLETE"
    Write-Host "Source candidate: $($candidateFile.FullName)"
    Write-Host "Operator review remains required before any further continuation."
}
finally {
    Pop-Location
}
