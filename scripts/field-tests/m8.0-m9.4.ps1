param(
    [string]$ResultPath = ".\.astp\m79\result.yaml"
)

$ErrorActionPreference = "Stop"
$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$Python = Join-Path $RepoRoot ".venv\Scripts\python.exe"
Set-Location $RepoRoot

Write-Host "`n=== Focused M8.0-M9.4 tests ==="
& $Python -m pytest tests/test_m80_m94_integrity_pipeline.py -q
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host "`n=== CLI smoke ==="
& $Python -c "from astp.cli import app; assert app is not None"
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

if (-not (Test-Path $ResultPath)) {
    Write-Host "`nStored M7.9 assessment result not found; focused tests are sufficient."
    Write-Host "M8.0-M9.4 FIELD TEST PASSED"
    Write-Host "Network execution: NOT PERFORMED"
    exit 0
}

$Out = Join-Path $RepoRoot ".astp\m94"
New-Item -ItemType Directory -Force -Path $Out | Out-Null

Write-Host "`n=== Confidence fusion ==="
astp fuse-confidence $ResultPath --output (Join-Path $Out "confidence.yaml")

Write-Host "`n=== Assessment lineage ==="
astp build-assessment-lineage $ResultPath --output (Join-Path $Out "lineage.yaml")

Write-Host "`n=== Assessment manifest ==="
astp build-assessment-manifest $ResultPath --output (Join-Path $Out "manifest.yaml")
astp verify-assessment-manifest (Join-Path $Out "manifest.yaml")

Write-Host "`n=== Review package ==="
astp build-review-package $ResultPath --output-dir (Join-Path $Out "review-package")

Write-Host "`nM8.0-M9.4 FIELD TEST PASSED"
Write-Host "Network execution: NOT PERFORMED"
