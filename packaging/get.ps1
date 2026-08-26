#Requires -RunAsAdministrator
<#
.SYNOPSIS
  Auto-detect Windows arch, download observability-agent, install as a Windows service.

.DESCRIPTION
  Assets are pulled straight from the release download URL — never from a branch
  and never through api.github.com — so the script and the binary it installs
  cannot drift apart, and the unauthenticated API rate limit never applies.

.EXAMPLE
  irm https://github.com/Sannapanenitharun/my-OwnAgent/releases/latest/download/get.ps1 | iex

.EXAMPLE
  With an explicit intake URL:
  & ([scriptblock]::Create((irm https://github.com/Sannapanenitharun/my-OwnAgent/releases/latest/download/get.ps1))) -Endpoint http://intake.example.com:8090
#>
param(
    [Parameter(Mandatory = $false)]
    [string]$Endpoint = $env:OBSAGENT_EXPORT_ENDPOINT,

    [string]$Repo = $(if ($env:OBSAGENT_REPO) { $env:OBSAGENT_REPO } else { "Sannapanenitharun/my-OwnAgent" }),
    [string]$Version = $(if ($env:OBSAGENT_VERSION) { $env:OBSAGENT_VERSION } else { "latest" })
)

$ErrorActionPreference = "Stop"

$arch = switch ($env:PROCESSOR_ARCHITECTURE) {
    "AMD64" { "amd64" }
    "ARM64" { "arm64" }
    default { throw "unsupported arch: $env:PROCESSOR_ARCHITECTURE" }
}
$asset = "observability-agent-windows-$arch.exe"

if ($Version -eq "latest") {
    $dl = "https://github.com/$Repo/releases/latest/download"
} else {
    $dl = "https://github.com/$Repo/releases/download/$Version"
}
Write-Host "detected windows/$arch, installing $Version from $dl"

$root = Join-Path $env:ProgramFiles "observability-agent"
$bin = Join-Path $root "observability-agent.exe"
$cfg = Join-Path $root "agent.json"
New-Item -ItemType Directory -Force -Path $root | Out-Null

Write-Host "downloading $dl/$asset"
Invoke-WebRequest -Uri "$dl/$asset" -OutFile $bin -UseBasicParsing

# Config ships in the same release, so it always matches the binary. An existing
# agent.json is left alone: re-running the installer must not discard local edits.
if (-not (Test-Path $cfg)) {
    try {
        Invoke-WebRequest -Uri "$dl/agent.example.json" -OutFile $cfg -UseBasicParsing
    } catch {
        '{"schema_version":1,"modules":{"host":{"enabled":true},"process":{"enabled":true},"logs":{"enabled":true},"otel-engine":{"enabled":true},"discovery":{"enabled":true}},"export":{"native":{"endpoint":""}}}' |
            Set-Content -Path $cfg -Encoding utf8
    }
}

$svcName = "observability-agent"
$existing = Get-Service -Name $svcName -ErrorAction SilentlyContinue
if ($existing) {
    Stop-Service $svcName -Force -ErrorAction SilentlyContinue
    sc.exe delete $svcName | Out-Null
    Start-Sleep -Seconds 1
}

$binPath = "`"$bin`" --config `"$cfg`""
sc.exe create $svcName binPath= $binPath start= auto DisplayName= "observability-agent" | Out-Null
sc.exe description $svcName "Host observability agent (metrics, logs, OTLP)" | Out-Null

# The endpoint travels as an environment variable: the config loader treats
# OBSAGENT_EXPORT_ENDPOINT as an override, so the JSON needs no rewriting.
if ($Endpoint) {
    [Environment]::SetEnvironmentVariable("OBSAGENT_EXPORT_ENDPOINT", $Endpoint, "Machine")
}
Start-Service $svcName

if ($Endpoint) {
    Write-Host "installed $bin -> exporting to $Endpoint (Windows service)"
} else {
    Write-Host "installed $bin -> collecting locally; dashboard on http://127.0.0.1:8181/"
    Write-Host "to ship data later, re-run with -Endpoint URL"
}
& $bin --check --config $cfg
