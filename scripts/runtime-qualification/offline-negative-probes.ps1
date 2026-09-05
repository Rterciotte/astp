param(
    [ValidateSet("security-tools", "playwright", "zap", "all")]
    [string]$Runtime = "security-tools"
)

$ErrorActionPreference = "Stop"
$Root = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$Tmp = Join-Path $Root ".astp\qualification\tmp"
$Evidence = Join-Path $Root ".astp\qualification\evidence"
New-Item -ItemType Directory -Force -Path $Tmp, $Evidence | Out-Null

$items = @(
    @{ Name = "security-tools"; Tag = "astp/security-tools-worker:qualification"; Memory = "256m"; Cpus = "0.5"; Pids = "96" },
    @{ Name = "playwright"; Tag = "astp/playwright-worker:qualification"; Memory = "768m"; Cpus = "1"; Pids = "192" },
    @{ Name = "zap"; Tag = "astp/zap-worker:qualification"; Memory = "1024m"; Cpus = "1"; Pids = "256" }
)
if ($Runtime -ne "all") { $items = @($items | Where-Object { $_.Name -eq $Runtime }) }

foreach ($item in $items) {
    Write-Host "=== Offline negative probes: $($item.Name) ==="
    docker image inspect $item.Tag *> $null
    if ($LASTEXITCODE -ne 0) { throw "Image not built: $($item.Tag). Run build-images.ps1 first." }

    $request = Join-Path $Tmp "$($item.Name)-rejected.json"
    '{"operation":"astp.qualification.unknown","target":"not-authorized"}' | Set-Content -Encoding ascii $request

    $output = & docker run --rm --read-only `
        --security-opt no-new-privileges:true `
        --cap-drop ALL `
        --network none `
        --cpus $item.Cpus `
        --memory $item.Memory `
        --pids-limit $item.Pids `
        --tmpfs /tmp:rw,noexec,nosuid,size=64m `
        --mount "type=bind,src=$request,dst=/run/astp/request.json,readonly" `
        $item.Tag 2>&1
    $exit = $LASTEXITCODE
    $output | Set-Content -Encoding UTF8 (Join-Path $Evidence "$($item.Name)-unknown-operation.txt")
    if ($exit -eq 0) { throw "Unknown operation was unexpectedly accepted by $($item.Name)" }
    if (($output -join "`n") -notmatch "operation rejected") {
        throw "Worker rejected the request for an unexpected reason: $($output -join ' ')"
    }

    $inspect = docker image inspect $item.Tag | ConvertFrom-Json
    $inspect | ConvertTo-Json -Depth 20 | Set-Content -Encoding UTF8 (Join-Path $Evidence "$($item.Name)-image-inspect.json")

    Write-Host "PASS: unknown operation rejected"
    Write-Host "PASS: launch used --network none"
    Write-Host "PASS: launch used --read-only / no-new-privileges / cap-drop ALL"
    Write-Host ""
}

Write-Host "OFFLINE NEGATIVE PROBES PASSED"
Write-Host "Network execution: NOT PERFORMED"
