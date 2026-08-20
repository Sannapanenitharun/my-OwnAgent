#Requires -RunAsAdministrator
<#
.SYNOPSIS
  Auto-detect Windows arch, download observability-agent, install as a Windows service.

.EXAMPLE
  irm https://raw.githubusercontent.com/Sannapanenitharun/my-OwnAgent/main/packaging/get.ps1 | iex

  Or with an explicit intake URL:
  & ([scriptblock]::Create((irm https://raw.githubusercontent.com/Sannapanenitharun/my-OwnAgent/main/packaging/get.ps1))) -Endpoint https://intake.example.com:8080
#>
param(
    [Parameter(Mandatory = $false)]
    [string]$Endpoint = $env:OBSAGENT_EXPORT_ENDPOINT,

    [string]$Repo = $(if ($env:OBSAGENT_REPO) { $env:OBSAGENT_REPO } else { "Sannapanenitharun/my-OwnAgent" }),
    [string]$Version = $(if ($env:OBSAGENT_VERSION) { $env:OBSAGENT_VERSION } else { "latest" })
)

$ErrorActionPreference = "Stop"

if (-not $Endpoint) {
    Write-Host "Enter native intake URL (e.g. https://intake.example.com:8080):"
    $Endpoint = Read-Host
}
if (-not $Endpoint) {
    throw "Endpoint is required (OBSAGENT_EXPORT_ENDPOINT or -Endpoint)"
}

$arch = switch ($env:PROCESSOR_ARCHITECTURE) {
    "AMD64" { "amd64" }
    "ARM64" { "arm64" }
    default { throw "unsupported arch: $env:PROCESSOR_ARCHITECTURE" }
}
$asset = "observability-agent-windows-$arch.exe"
Write-Host "detected windows/$arch"

if ($Version -eq "latest") {
    $api = "https://api.github.com/repos/$Repo/releases/latest"
} else {
    $api = "https://api.github.com/repos/$Repo/releases/tags/$Version"
}

Write-Host "resolving release from $api"
$release = Invoke-RestMethod -Uri $api -Headers @{ "User-Agent" = "obsagent-get" }
$assetMeta = $release.assets | Where-Object { $_.name -eq $asset } | Select-Object -First 1
if (-not $assetMeta) {
    throw "could not find $asset in release assets"
}

$root = Join-Path $env:ProgramFiles "observability-agent"
$bin = Join-Path $root "observability-agent.exe"
$cfg = Join-Path $root "agent.json"
New-Item -ItemType Directory -Force -Path $root | Out-Null

Write-Host "downloading $($assetMeta.browser_download_url)"
Invoke-WebRequest -Uri $assetMeta.browser_download_url -OutFile $bin -UseBasicParsing

$exampleUrl = "https://raw.githubusercontent.com/$Repo/main/agent.example.json"
try {
    Invoke-WebRequest -Uri $exampleUrl -OutFile $cfg -UseBasicParsing
} catch {
    '{"schema_version":1,"modules":{"host":{"enabled":true},"process":{"enabled":true},"logs":{"enabled":true},"otel-engine":{"enabled":true},"discovery":{"enabled":true}},"export":{"native":{"endpoint":""}}}' |
        Set-Content -Path $cfg -Encoding utf8
}

$json = Get-Content $cfg -Raw | ConvertFrom-Json
if (-not $json.export) { $json | Add-Member -NotePropertyName export -NotePropertyValue ([pscustomobject]@{}) }
if (-not $json.export.native) { $json.export | Add-Member -NotePropertyName native -NotePropertyValue ([pscustomobject]@{}) }
$json.export.native.endpoint = $Endpoint
($json | ConvertTo-Json -Depth 30) | Set-Content -Path $cfg -Encoding utf8

$svcName = "observability-agent"
$existing = Get-Service -Name $svcName -ErrorAction SilentlyContinue
if ($existing) {
    Stop-Service $svcName -Force -ErrorAction SilentlyContinue
    sc.exe delete $svcName | Out-Null
    Start-Sleep -Seconds 1
}

$binPath = "`"$bin`" --config `"$cfg`""
sc.exe create $svcName binPath= $binPath start= auto DisplayName= "observability-agent" | Out-Null
# Persist intake for the service process as well.
[Environment]::SetEnvironmentVariable("OBSAGENT_EXPORT_ENDPOINT", $Endpoint, "Machine")
sc.exe description $svcName "Host observability agent (metrics, logs, OTLP)" | Out-Null
Start-Service $svcName

Write-Host "installed $bin → $Endpoint (Windows service)"
& $bin --check --config $cfg
