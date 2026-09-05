param(
    [ValidateSet("security-tools", "playwright", "zap", "all")]
    [string]$Runtime = "all"
)
$ErrorActionPreference = "Stop"
$repo = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$python = Join-Path $repo ".venv\Scripts\python.exe"
$evidence = Join-Path $repo ".astp\qualification\evidence"
New-Item -ItemType Directory -Force -Path $evidence | Out-Null
$map = @{
  "security-tools" = "astp/security-tools-worker:qualification"
  "playwright" = "astp/playwright-worker:qualification"
  "zap" = "astp/zap-worker:qualification"
}
$runtimes = if ($Runtime -eq "all") { @("security-tools", "playwright", "zap") } else { @($Runtime) }
foreach ($item in $runtimes) {
    $image = $map[$item]
    $envJson = docker image inspect $image --format '{{json .Config.Env}}'
    if ($LASTEXITCODE -ne 0) { throw "Image inspect failed for $item" }
    if ($envJson -match 'ASTP_PERMIT_KEY|ASTP_PERMIT_SECRET|ASTP_SIGNING') { throw "Signing-key material/name found in $item worker image configuration" }
    $source = Join-Path $evidence "$item-signing-key-absence.json"
    @{
        runtime = $item
        image = $image
        config_env = ($envJson | ConvertFrom-Json)
        signing_key_variables_present = $false
    } | ConvertTo-Json -Depth 10 | Set-Content -Encoding UTF8 $source
    & $python -m astp.physical_probe_evaluator record `
        --root $repo `
        --runtime $item `
        --probe signing-keys-absent `
        --passed `
        --source-ref $source *> $null
    if ($LASTEXITCODE -ne 0) { throw "Could not persist signing-key absence probe for $item" }
    Write-Host "PASS: no ASTP signing-key variables embedded in $item image configuration"
    Write-Host "PASS: signing-key absence persisted as immutable qualification evidence"
}
Write-Host "Note: network-capable worker launches pass only ASTP_ALLOWED_TARGET, never ASTP_PERMIT_KEY."
