param(
    [ValidateSet("security-tools", "playwright", "zap")]
    [string]$Runtime = "security-tools"
)
$ErrorActionPreference = "Stop"
$repo = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$python = Join-Path $repo ".venv\Scripts\python.exe"
if (-not (Test-Path $python)) { throw "ASTP virtualenv Python not found: $python" }
if (-not $env:ASTP_PERMIT_KEY) { throw "ASTP_PERMIT_KEY is required" }
Write-Host "=== ASTP authorized local qualification: $Runtime ==="
Write-Host "Permit path: policy -> broker -> signed permit -> lifecycle consume -> worker"
& $python -m astp.physical_qualification_runner --root $repo --runtime $Runtime
if ($LASTEXITCODE -ne 0) { throw "Authorized local qualification failed" }
Write-Host ""
Write-Host "AUTHORIZED LOCAL QUALIFICATION PASSED"
Write-Host "Container execution: PERFORMED"
Write-Host "Network execution: PERFORMED"
Write-Host "Target class: AUTHORIZED LOCAL LAB"
