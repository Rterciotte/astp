$ErrorActionPreference = "Stop"
$repo = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$current = Join-Path $repo ".astp\qualification"
$archiveRoot = Join-Path $repo ".astp\qualification-archive"
if (-not (Test-Path $current)) {
    Write-Host "No existing qualification state to archive."
    exit 0
}
$stamp = [DateTime]::UtcNow.ToString("yyyyMMddTHHmmssfffZ")
$destination = Join-Path $archiveRoot $stamp
New-Item -ItemType Directory -Force -Path $archiveRoot | Out-Null
Move-Item -Path $current -Destination $destination
New-Item -ItemType Directory -Force -Path $current | Out-Null
Write-Host "Archived previous qualification state: $destination"
Write-Host "Created fresh qualification root: $current"
Write-Host "Historical evidence was preserved; no old manifest entry was rewritten."
