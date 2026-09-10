$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
$Repo = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
& (Join-Path $Repo ".venv\Scripts\python.exe") (Join-Path $PSScriptRoot "autonomous_dev.py") initialize --repo $Repo
exit $LASTEXITCODE
