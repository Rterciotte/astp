param(
    [ValidateSet("security-tools")]
    [string]$Runtime = "security-tools"
)

$ErrorActionPreference = "Stop"
$Root = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path

if (-not $env:ASTP_PERMIT_KEY) {
    throw "ASTP_PERMIT_KEY is not set in this PowerShell session. Refusing to issue a qualification permit."
}

if ($Runtime -ne "security-tools") {
    throw "Only security-tools is enabled for the first permit-gated qualification run."
}

Push-Location $Root
try {
    Write-Host "=== ASTP authorized local qualification: $Runtime ==="
    Write-Host "Target: astp-qualification-lab (isolated internal Docker network)"
    Write-Host "Permit path: policy -> broker -> signed permit -> lifecycle consume -> worker"
    Write-Host ""

    & .\.venv\Scripts\python.exe -m astp.physical_qualification_runner --root $Root
    if ($LASTEXITCODE -ne 0) {
        throw "Permit-gated local qualification failed"
    }
}
finally {
    Pop-Location
}

Write-Host ""
Write-Host "AUTHORIZED LOCAL QUALIFICATION PASSED"
Write-Host "Container execution: PERFORMED"
Write-Host "Network execution: PERFORMED"
Write-Host "Target class: AUTHORIZED LOCAL LAB"
