param(
    [switch]$SkipFetch,
    [switch]$NoRelease,
    [string]$FscanPath = ""
)

$ErrorActionPreference = "Stop"
$Root = Split-Path $PSScriptRoot -Parent
Set-Location $Root

$fscan = $FscanPath
if (-not $fscan) {
    if (-not $SkipFetch -and -not (Test-Path "tools\fscan.exe")) {
        python scripts\fetch_fscan.py
    }
    $fscan = Join-Path $Root "tools\fscan.exe"
}

if (-not (Test-Path $fscan)) {
    throw "fscan.exe not found: $fscan. Run: python scripts\fetch_fscan.py"
}
$fscan = (Resolve-Path $fscan).Path

python -m PyInstaller `
    --noconfirm `
    --clean `
    --onefile `
    --windowed `
    --name FScanDesk `
    --icon "assets\app.ico" `
    --version-file "assets\version_info.txt" `
    --add-data "web;web" `
    --add-binary "$fscan;." `
    --exclude-module tkinter `
    --exclude-module unittest `
    --exclude-module pydoc `
    "run.py"

if (-not (Test-Path "dist\FScanDesk.exe")) {
    throw "Build failed: dist\FScanDesk.exe not found"
}

Write-Host ""
Write-Host "Built: dist\FScanDesk.exe" -ForegroundColor Green

if (-not $NoRelease) {
    python scripts\package_release.py
}
