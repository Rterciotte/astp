param(
    [ValidateSet("security-tools", "playwright", "zap", "all")]
    [string]$Runtime = "security-tools"
)

$ErrorActionPreference = "Stop"
$Root = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$Out = Join-Path $Root ".astp\qualification\images"
New-Item -ItemType Directory -Force -Path $Out | Out-Null

$items = @(
    @{ Name = "security-tools"; RuntimeId = "security-tools.isolated.v1"; Tag = "astp/security-tools-worker:qualification"; Dockerfile = "workers/security-tools/Dockerfile" },
    @{ Name = "playwright"; RuntimeId = "playwright.isolated.v1"; Tag = "astp/playwright-worker:qualification"; Dockerfile = "workers/playwright/Dockerfile" },
    @{ Name = "zap"; RuntimeId = "zap.isolated.v1"; Tag = "astp/zap-worker:qualification"; Dockerfile = "workers/zap/Dockerfile" }
)

if ($Runtime -ne "all") {
    $items = @($items | Where-Object { $_.Name -eq $Runtime })
}

Push-Location $Root
try {
    foreach ($item in $items) {
        Write-Host "=== Building $($item.RuntimeId) ==="
        docker build --pull --file $item.Dockerfile --tag $item.Tag .
        if ($LASTEXITCODE -ne 0) { throw "Docker build failed for $($item.RuntimeId)" }

        $imageId = (docker image inspect --format '{{.Id}}' $item.Tag).Trim()
        if ($LASTEXITCODE -ne 0 -or -not $imageId.StartsWith("sha256:")) {
            throw "Could not capture immutable image ID for $($item.RuntimeId)"
        }
        $repoDigestsRaw = (docker image inspect --format '{{json .RepoDigests}}' $item.Tag).Trim()
        $record = [ordered]@{
            runtime_id = $item.RuntimeId
            image_tag = $item.Tag
            image_id = $imageId
            repo_digests = $repoDigestsRaw
            dockerfile = $item.Dockerfile
            built_at_utc = [DateTime]::UtcNow.ToString("o")
        }
        $path = Join-Path $Out "$($item.Name).json"
        $record | ConvertTo-Json -Depth 6 | Set-Content -Encoding UTF8 $path
        Write-Host "Image ID: $imageId"
        Write-Host "Provenance: $path"
        Write-Host ""
    }
}
finally {
    Pop-Location
}

Write-Host "Build complete. No assessment target was contacted by ASTP."
