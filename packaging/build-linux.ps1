# Build Linux binaries from Windows for EC2.
# Usage:
#   powershell -File packaging/build-linux.ps1
#   powershell -File packaging/build-linux.ps1 arm64
$ErrorActionPreference = "Stop"

$Arch = if ($args.Count -ge 1 -and $args[0]) { $args[0] } else { "amd64" }
$Version = if ($env:VERSION) { $env:VERSION } else { "0.3.0" }
$Root = Split-Path -Parent $PSScriptRoot
if (-not $Root) { $Root = (Get-Location).Path }

New-Item -ItemType Directory -Force -Path (Join-Path $Root "build") | Out-Null

$env:GOOS = "linux"
$env:GOARCH = $Arch
$env:CGO_ENABLED = "0"

$AgentOut = Join-Path $Root "build\observability-agent-linux-$Arch"
$IntakeOut = Join-Path $Root "build\obsagent-intake-linux-$Arch"
$Ldflags = "-s -w -X main.version=$Version"

Write-Host "building $AgentOut"
Push-Location $Root
try {
    go build -trimpath -ldflags $Ldflags -o $AgentOut ./cmd/observability-agent
    go build -trimpath -ldflags $Ldflags -o $IntakeOut ./cmd/obsagent-intake
} finally {
    Pop-Location
}

Write-Host "ok"
Write-Host "  agent:  $AgentOut"
Write-Host "  intake: $IntakeOut"
Write-Host "Copy the agent to EC2, then: sudo packaging/install.sh ./observability-agent-linux-$Arch https://INTAKE:8080"
