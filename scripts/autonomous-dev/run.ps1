param([ValidateRange(60, 86400)][int]$CodexTimeoutSeconds = 3600)
$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
$Repo = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
& (Join-Path $Repo ".venv\Scripts\python.exe") (Join-Path $PSScriptRoot "autonomous_dev.py") run --repo $Repo --codex-timeout $CodexTimeoutSeconds
exit $LASTEXITCODE
