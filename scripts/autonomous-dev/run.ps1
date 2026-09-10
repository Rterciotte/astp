param(
    [ValidateRange(60, 86400)][int]$CodexTimeoutSeconds = 3600,
    [switch]$ValidateEnvironmentOnly
)
$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
$Repo = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$Command = if ($ValidateEnvironmentOnly) { "environment" } else { "run" }
& (Join-Path $Repo ".venv\Scripts\python.exe") (Join-Path $PSScriptRoot "autonomous_dev.py") $Command --repo $Repo --codex-timeout $CodexTimeoutSeconds
exit $LASTEXITCODE
