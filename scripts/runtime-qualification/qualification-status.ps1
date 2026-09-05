param(
    [ValidateSet("security-tools", "playwright", "zap", "all")]
    [string]$Runtime = "all"
)
$ErrorActionPreference = "Stop"
$repo = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$python = Join-Path $repo ".venv\Scripts\python.exe"
$runtimes = if ($Runtime -eq "all") { @("security-tools", "playwright", "zap") } else { @($Runtime) }
foreach ($item in $runtimes) {
    Write-Host "=== Qualification status: $item ==="
    & $python -m astp.physical_probe_evaluator status --root $repo --runtime $item
    if ($LASTEXITCODE -ne 0) { throw "Qualification status failed for $item" }
}
