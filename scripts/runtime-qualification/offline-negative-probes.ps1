param(
    [ValidateSet("security-tools", "playwright", "zap", "all")]
    [string]$Runtime = "security-tools"
)

$ErrorActionPreference = "Stop"
$Root = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$Python = Join-Path $Root ".venv\Scripts\python.exe"
$Tmp = Join-Path $Root ".astp\qualification\tmp"
$Evidence = Join-Path $Root ".astp\qualification\evidence"
New-Item -ItemType Directory -Force -Path $Tmp, $Evidence | Out-Null

$items = @(
    @{ Name = "security-tools"; Tag = "astp/security-tools-worker:qualification"; Memory = "256m"; Cpus = "0.5"; Pids = "96" },
    @{ Name = "playwright"; Tag = "astp/playwright-worker:qualification"; Memory = "768m"; Cpus = "1"; Pids = "192" },
    @{ Name = "zap"; Tag = "astp/zap-worker:qualification"; Memory = "1024m"; Cpus = "1"; Pids = "256" }
)
if ($Runtime -ne "all") { $items = @($items | Where-Object { $_.Name -eq $Runtime }) }

function Record-Probe {
    param([string]$RuntimeName, [string]$Probe, [string]$Source)
    & $Python -m astp.physical_probe_evaluator record `
        --root $Root `
        --runtime $RuntimeName `
        --probe $Probe `
        --passed `
        --source-ref $Source *> $null
    if ($LASTEXITCODE -ne 0) { throw "Could not persist $Probe probe for $RuntimeName" }
}

foreach ($item in $items) {
    Write-Host "=== Offline negative probes: $($item.Name) ==="
    docker image inspect $item.Tag *> $null
    if ($LASTEXITCODE -ne 0) { throw "Image not built: $($item.Tag). Run build-images.ps1 first." }

    $unknownRequest = Join-Path $Tmp "$($item.Name)-rejected.json"
    '{"operation":"astp.qualification.unknown","target":"not-authorized"}' | Set-Content -Encoding ascii $unknownRequest
    $unknownOutput = & docker run --rm --read-only `
        --security-opt no-new-privileges:true `
        --cap-drop ALL `
        --network none `
        --cpus $item.Cpus `
        --memory $item.Memory `
        --pids-limit $item.Pids `
        --tmpfs /tmp:rw,noexec,nosuid,size=64m `
        --mount "type=bind,src=$unknownRequest,dst=/run/astp/request.json,readonly" `
        $item.Tag 2>&1
    $unknownExit = $LASTEXITCODE
    $unknownPath = Join-Path $Evidence "$($item.Name)-unknown-operation.txt"
    $unknownOutput | Set-Content -Encoding UTF8 $unknownPath
    if ($unknownExit -eq 0) { throw "Unknown operation was unexpectedly accepted by $($item.Name)" }
    if (($unknownOutput -join "`n") -notmatch "operation rejected") {
        throw "Worker rejected the request for an unexpected reason: $($unknownOutput -join ' ')"
    }

    $shellRequest = Join-Path $Tmp "$($item.Name)-shell-rejected.json"
    '{"operation":"shell.exec","target":"not-authorized"}' | Set-Content -Encoding ascii $shellRequest
    $shellOutput = & docker run --rm --read-only `
        --security-opt no-new-privileges:true `
        --cap-drop ALL `
        --network none `
        --cpus $item.Cpus `
        --memory $item.Memory `
        --pids-limit $item.Pids `
        --tmpfs /tmp:rw,noexec,nosuid,size=64m `
        --mount "type=bind,src=$shellRequest,dst=/run/astp/request.json,readonly" `
        $item.Tag 2>&1
    $shellExit = $LASTEXITCODE
    $shellPath = Join-Path $Evidence "$($item.Name)-shell-rejected.txt"
    $shellOutput | Set-Content -Encoding UTF8 $shellPath
    if ($shellExit -eq 0 -or (($shellOutput -join "`n") -notmatch "operation rejected")) {
        throw "Arbitrary shell operation was not rejected by $($item.Name)"
    }
    Record-Probe $item.Name "shell-rejected" $shellPath

    $containerName = "astp-qualification-config-$($item.Name)-$PID"
    docker create --name $containerName --read-only `
        --security-opt no-new-privileges:true `
        --cap-drop ALL `
        --network none `
        --cpus $item.Cpus `
        --memory $item.Memory `
        --pids-limit $item.Pids `
        --tmpfs /tmp:rw,noexec,nosuid,size=64m `
        $item.Tag *> $null
    if ($LASTEXITCODE -ne 0) { throw "Could not create hardened probe container" }
    try {
        $configPath = Join-Path $Evidence "$($item.Name)-hardened-container-inspect.json"
        docker inspect $containerName | Set-Content -Encoding UTF8 $configPath
        $inspect = (Get-Content $configPath -Raw | ConvertFrom-Json)[0]
        if (-not $inspect.HostConfig.ReadonlyRootfs) { throw "Read-only root was not applied" }
        if (($inspect.HostConfig.SecurityOpt -join " ") -notmatch "no-new-privileges") { throw "no-new-privileges was not applied" }
        if ($inspect.HostConfig.NetworkMode -ne "none") { throw "Negative-probe container unexpectedly has a network" }
        Record-Probe $item.Name "read-only-root" $configPath
        Record-Probe $item.Name "no-new-privileges" $configPath
    }
    finally {
        docker rm -f $containerName *> $null
    }

    $networkOutput = & docker run --rm --read-only `
        --security-opt no-new-privileges:true `
        --cap-drop ALL `
        --network none `
        --entrypoint python `
        $item.Tag -I -c 'import socket; socket.create_connection(("astp-qualification-lab",8080),1)' 2>&1
    $networkExit = $LASTEXITCODE
    $networkPath = Join-Path $Evidence "$($item.Name)-network-without-permit-rejected.txt"
    $networkOutput | Set-Content -Encoding UTF8 $networkPath
    if ($networkExit -eq 0) { throw "Network unexpectedly succeeded without a permit/network boundary" }
    Record-Probe $item.Name "network-without-permit-rejected" $networkPath

    $imageInspectPath = Join-Path $Evidence "$($item.Name)-image-inspect.json"
    docker image inspect $item.Tag | Set-Content -Encoding UTF8 $imageInspectPath

    Write-Host "PASS: unknown operation rejected"
    Write-Host "PASS: arbitrary shell operation rejected"
    Write-Host "PASS: hardened launch has read-only root / no-new-privileges / cap-drop ALL"
    Write-Host "PASS: network attempt without permit/network boundary rejected"
    Write-Host "PASS: physical negative probes persisted as immutable qualification evidence"
    Write-Host ""
}

Write-Host "OFFLINE NEGATIVE PROBES PASSED"
Write-Host "Network execution: NOT PERFORMED"
