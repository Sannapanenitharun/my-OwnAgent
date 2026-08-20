# Build agent binaries for all supported OS/arch pairs (CGO-free).
# Usage: powershell -File packaging/build-all.ps1
$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
$Version = if ($env:VERSION) { $env:VERSION } else { "0.4.0" }
$OutDir = Join-Path $Root "build"
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

$Targets = @(
    @{ GOOS = "linux";   GOARCH = "amd64"; Ext = "" },
    @{ GOOS = "linux";   GOARCH = "arm64"; Ext = "" },
    @{ GOOS = "darwin";  GOARCH = "amd64"; Ext = "" },
    @{ GOOS = "darwin";  GOARCH = "arm64"; Ext = "" },
    @{ GOOS = "windows"; GOARCH = "amd64"; Ext = ".exe" },
    @{ GOOS = "windows"; GOARCH = "arm64"; Ext = ".exe" }
)

$env:CGO_ENABLED = "0"
$Ldflags = "-s -w -X main.version=$Version"

Push-Location $Root
try {
    foreach ($t in $Targets) {
        $env:GOOS = $t.GOOS
        $env:GOARCH = $t.GOARCH
        $name = "observability-agent-$($t.GOOS)-$($t.GOARCH)$($t.Ext)"
        $out = Join-Path $OutDir $name
        Write-Host "building $name"
        go build -trimpath -ldflags $Ldflags -o $out ./cmd/observability-agent
    }
} finally {
    Remove-Item Env:GOOS -ErrorAction SilentlyContinue
    Remove-Item Env:GOARCH -ErrorAction SilentlyContinue
    Pop-Location
}

Write-Host "ok - binaries in $OutDir"
