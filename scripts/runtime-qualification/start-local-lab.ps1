$ErrorActionPreference = "Stop"
$Root = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$Network = "astp-qualification-net"
$Container = "astp-qualification-lab"
$Image = "astp/qualification-lab:local"

Push-Location $Root
try {
    docker network inspect $Network *> $null
    if ($LASTEXITCODE -ne 0) {
        docker network create --internal $Network | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "Could not create isolated qualification network" }
    }

    docker build --pull --file labs/qualification-http/Dockerfile --tag $Image .
    if ($LASTEXITCODE -ne 0) { throw "Qualification lab build failed" }

    docker rm -f $Container *> $null
    docker run -d --rm --name $Container `
        --network $Network `
        --read-only `
        --security-opt no-new-privileges:true `
        --cap-drop ALL `
        --memory 128m `
        --cpus 0.25 `
        --pids-limit 64 `
        --tmpfs /tmp:rw,noexec,nosuid,size=16m `
        $Image | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Qualification lab failed to start" }
}
finally { Pop-Location }

Write-Host "Authorized local qualification lab started."
Write-Host "Docker network: $Network (internal)"
Write-Host "Service: ${Container}:8080"
Write-Host "No host port is published."
