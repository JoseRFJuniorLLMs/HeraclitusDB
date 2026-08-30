<#
.SYNOPSIS
  Verifica integralmente SHA256SUMS de um bundle sem acessar a rede.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string]$BundleDirectory
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$bundle = (Resolve-Path -LiteralPath $BundleDirectory).Path
$sumPath = Join-Path $bundle 'SHA256SUMS'
if (-not (Test-Path -LiteralPath $sumPath -PathType Leaf)) {
    throw "SHA256SUMS ausente: $sumPath"
}
$verified = 0
foreach ($line in Get-Content -LiteralPath $sumPath) {
    if ($line -notmatch '^([0-9a-fA-F]{64})  (.+)$') {
        throw "linha inválida em SHA256SUMS: $line"
    }
    $expected = $Matches[1].ToLowerInvariant()
    $relative = $Matches[2].Replace('/', '\')
    if ($relative.Contains('..')) { throw "caminho inseguro em SHA256SUMS: $relative" }
    $path = Join-Path $bundle $relative
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "arquivo ausente no bundle: $relative"
    }
    $actual = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actual -ne $expected) { throw "digest diverge: $relative" }
    $verified++
}
Write-Host "OFFLINE_BUNDLE_OK files=$verified path=$bundle" -ForegroundColor Green
