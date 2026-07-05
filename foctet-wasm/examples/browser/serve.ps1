# Build the foctet-wasm web target and serve the in-browser harness.
# No Python required (uses a tiny Node static server).
#
# Usage: ./examples/browser/serve.ps1 [-Port 8011]
#   $env:FOCTET_OPEN=1; ./examples/browser/serve.ps1   # also open the default browser
param(
    [int]$Port = 8011
)

$ErrorActionPreference = "Stop"

# Resolve the foctet-wasm crate root (this script lives in examples/browser/).
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$CrateDir = Resolve-Path (Join-Path $ScriptDir "..\..")

Set-Location $CrateDir

Write-Host "Building pkg-web (wasm-pack)..."
wasm-pack build --target web --out-dir pkg-web

Write-Host "Starting static server on port $Port..."
node examples/browser/serve.mjs $Port
