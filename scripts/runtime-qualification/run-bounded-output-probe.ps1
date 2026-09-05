param(
    [ValidateSet("security-tools", "playwright", "zap")]
    [string]$Runtime = "playwright"
)
$ErrorActionPreference = "Stop"
$repo = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$python = Join-Path $repo ".venv\Scripts\python.exe"
if (-not $env:ASTP_PERMIT_KEY) { throw "ASTP_PERMIT_KEY is required" }
$path = if ($Runtime -eq "playwright") { "/large" } else { "/health" }
$limit = 1024
Write-Host "=== Permit-gated bounded-output probe: $Runtime ==="
$probeArgs = @(
    "-m", "astp.physical_qualification_runner",
    "--root", $repo,
    "--runtime", $Runtime,
    "--path", $path,
    "--max-output-bytes", $limit
)
if ($Runtime -ne "playwright") {
    $probeArgs += @("--qualification-probe", "bounded-output-v1")
}
$output = & $python @probeArgs
if ($LASTEXITCODE -ne 0) { throw "Bounded-output probe failed" }
$output | Write-Host
$joined = $output -join "`n"
if ($joined -notmatch '"output_truncated": true') { throw "Expected physical output truncation was not observed" }
Write-Host "PASS: physical bounded-output truncation observed"
Write-Host "PASS: bounded-output probe persisted by the permit-gated runner"
if ($Runtime -eq "playwright") {
    Write-Host "Network execution: PERFORMED against AUTHORIZED LOCAL LAB"
} else {
    Write-Host "Network execution: NOT PERFORMED BY BOUNDED-OUTPUT PROBE"
    Write-Host "Container launch remained bound to the authorized local-lab qualification context"
}
