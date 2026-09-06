param(
    [Parameter(Mandatory = $true)]
    [string]$ProgramId,

    [ValidateSet("live", "cached")]
    [string]$Mode = "live",

    [string]$Platform = "bughunt",
    [string]$Catalog = ".astp/program-catalog.yaml",
    [int]$Port = 8765,
    [int]$TimeoutSeconds = 180,
    [int]$FreshnessSeconds = 300
)

$ErrorActionPreference = "Stop"
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "../..")).Path
$python = Join-Path $repoRoot ".venv/Scripts/python.exe"
if (-not (Test-Path $python)) {
    throw "ASTP virtualenv Python not found: $python"
}

Write-Host "ASTP PROGRAM PRE-FLIGHT"
Write-Host "Program: $ProgramId"
Write-Host "Mode:    $Mode"
Write-Host ""

& $python -m astp.program_preflight `
    --root $repoRoot `
    --program-id $ProgramId `
    --catalog $Catalog `
    --platform $Platform `
    --mode $Mode `
    --port $Port `
    --timeout-seconds $TimeoutSeconds `
    --freshness-seconds $FreshnessSeconds

exit $LASTEXITCODE
