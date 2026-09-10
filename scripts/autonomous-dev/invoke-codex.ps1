param(
    [Parameter(Mandatory)][string]$PromptPath,
    [Parameter(Mandatory)][string]$StdoutPath,
    [Parameter(Mandatory)][string]$StderrPath
)
$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
$Repo = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$Codex = "C:\Program Files\nodejs\codex.cmd"
if (-not (Test-Path -LiteralPath $Codex)) { throw "Independent Codex CLI not found: $Codex" }
$Prompt = Get-Content -Raw -LiteralPath $PromptPath
$Output = $Prompt | & $Codex exec - -C $Repo --sandbox workspace-write --ask-for-approval never --ephemeral --color never 2>&1
$Code = $LASTEXITCODE
$Output | Set-Content -LiteralPath $StdoutPath -Encoding utf8
"exit_code=$Code" | Set-Content -LiteralPath $StderrPath -Encoding utf8
exit $Code
