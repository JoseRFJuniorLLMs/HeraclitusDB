<#
.SYNOPSIS
  Executa instalação/update/probe dentro do isolador fornecido e valida relatório zero-egress.

.DESCRIPTION
  O programa de isolamento (container --network none, hypervisor ou laboratório)
  deve produzir um relatório JSON contendo attempted_egress. O harness não
  considera ausência de conexão bem sucedida como prova de zero egress.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string]$BundleDirectory,
    [Parameter(Mandatory)] [string]$IsolationProgram,
    [Parameter(Mandatory)] [string[]]$IsolationArguments,
    [Parameter(Mandatory)] [string]$MonitorReport,
    [Parameter(Mandatory)] [string]$EvidenceDirectory
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repo = (Resolve-Path (Join-Path $PSScriptRoot '..\..\..')).Path
$bundle = (Resolve-Path -LiteralPath $BundleDirectory).Path
$evidence = [IO.Path]::GetFullPath($EvidenceDirectory)
if (Test-Path -LiteralPath $evidence) { throw "evidência já existe: $evidence" }
New-Item -ItemType Directory -Path $evidence | Out-Null
& (Join-Path $PSScriptRoot 'Test-OfflineBundle.ps1') -BundleDirectory $bundle

$stdout = Join-Path $evidence 'isolation.stdout.log'
$stderr = Join-Path $evidence 'isolation.stderr.log'
$arguments = @($IsolationArguments | ForEach-Object {
    $_.Replace('{bundle}', $bundle).Replace('{repo}', $repo)
})
& $IsolationProgram @arguments 1> $stdout 2> $stderr
$isolationExit = [int]$LASTEXITCODE
if (-not (Test-Path -LiteralPath $MonitorReport -PathType Leaf)) {
    throw "isolador não produziu relatório de egress: $MonitorReport"
}
$monitor = Get-Content -LiteralPath $MonitorReport -Raw | ConvertFrom-Json
if ($null -eq $monitor.attempted_egress) {
    throw 'relatório não possui attempted_egress'
}
Copy-Item -LiteralPath $MonitorReport -Destination (Join-Path $evidence 'egress-monitor.json')
$passed = $isolationExit -eq 0 -and [int64]$monitor.attempted_egress -eq 0
[ordered]@{
    schema_version = 1
    status = if ($passed) { 'Passed' } else { 'Failed' }
    isolation_exit_code = $isolationExit
    attempted_egress = [int64]$monitor.attempted_egress
    monitor_sha256 = (Get-FileHash -LiteralPath $MonitorReport -Algorithm SHA256).Hash.ToLowerInvariant()
} | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $evidence 'airgap-result.json') -Encoding UTF8

if (-not $passed) {
    throw "AIRGAP_FAILED isolation_exit=$isolationExit attempted_egress=$($monitor.attempted_egress)"
}
Write-Host "AIRGAP_PASS attempted_egress=0 evidence=$evidence" -ForegroundColor Green
