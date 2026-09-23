$ErrorActionPreference = "Stop"

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
$demoRoot = Join-Path $repoRoot "examples\\vulnerable-app"

Write-Host "Using demo app at: $demoRoot"
Set-Location $demoRoot

if (-not (Test-Path "package.json")) {
  throw "Demo app is missing package.json at $demoRoot"
}

$demoConfig = Join-Path $demoRoot "audit-config.json"
$demoConfigTemplate = Join-Path $demoRoot "audit-config.example.json"
if (-not (Test-Path $demoConfig) -and (Test-Path $demoConfigTemplate)) {
  Copy-Item $demoConfigTemplate $demoConfig
}

Write-Host "Installing demo app dependencies..."
npm install --no-fund --no-audit

Write-Host "Starting interactive audit demo..."
node "$repoRoot\\dist\\index.js" -i --config $demoConfig
