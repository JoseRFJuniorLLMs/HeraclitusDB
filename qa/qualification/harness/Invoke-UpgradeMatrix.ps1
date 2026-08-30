<#
.SYNOPSIS
  Executa o preflight automatizado de compatibilidade e migração da SPEC-0049.

.DESCRIPTION
  Este preflight não substitui o ensaio N-1 -> N com binários reais. Ele prova
  leitura dos formatos legados, migração v6 e recusa de estados inválidos. O
  gate RC/Government continua exigindo uma atestação assinada do ensaio real.
#>
[CmdletBinding()]
param(
    [string]$Cargo = 'cargo'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repo = (Resolve-Path (Join-Path $PSScriptRoot '..\..\..')).Path

function Invoke-CargoGate {
    param([string]$Name, [string[]]$Arguments)
    Write-Host "UPGRADE_PREFLIGHT_START $Name" -ForegroundColor Cyan
    & $Cargo @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "upgrade preflight failed: $Name (exit=$LASTEXITCODE)"
    }
    Write-Host "UPGRADE_PREFLIGHT_PASS $Name" -ForegroundColor Green
}

$oldOffline = $env:CARGO_NET_OFFLINE
try {
    $env:CARGO_NET_OFFLINE = 'true'
    Push-Location $repo
    try {
        Invoke-CargoGate 'legacy-format-matrix' @(
            'test', '--offline', '--locked', '-p', 'heraclitus-log',
            '--test', 'compat_matrix_v1_v5', '--', '--nocapture'
        )
        Invoke-CargoGate 'v2-v4-read-path' @(
            'test', '--offline', '--locked', '-p', 'heraclitus-log',
            '--test', 'v2_compat', '--', '--nocapture'
        )
        Invoke-CargoGate 'v6-database-migration' @(
            'test', '--offline', '--locked', '-p', 'heraclitus-log',
            '--test', 'hrkl_v6_migrate_database', '--', '--nocapture'
        )
    }
    finally {
        Pop-Location
    }
}
finally {
    if ($null -eq $oldOffline) {
        Remove-Item Env:CARGO_NET_OFFLINE -ErrorAction SilentlyContinue
    }
    else {
        $env:CARGO_NET_OFFLINE = $oldOffline
    }
}

Write-Host 'UPGRADE_PREFLIGHT_PASS all' -ForegroundColor Green
