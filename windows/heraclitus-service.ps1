<#
.SYNOPSIS
    Gere o HeraclitusDB como serviço do Windows (Service Control Manager).

.DESCRIPTION
    Embrulha o binário heraclitus-service.exe. Auto-eleva (pede UAC uma vez)
    para as operações que precisam de Administrador (install/uninstall/start/stop).
    O serviço aparece no Gerenciador de Tarefas -> Serviços e em services.msc,
    arranca automaticamente no boot e escreve o log de execução em
    %ProgramData%\HeraclitusDB\logs.

.PARAMETER Action
    install   | regista o serviço (auto-start) e arranca-o
    uninstall | para e remove o serviço
    start     | arranca o serviço
    stop      | para o serviço
    status    | mostra o estado
    logs      | segue o log de execução em tempo real (Ctrl+C para sair)

.EXAMPLE
    .\heraclitus-service.ps1 install
    .\heraclitus-service.ps1 logs
#>
[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [ValidateSet('install', 'uninstall', 'start', 'stop', 'status', 'logs')]
    [string]$Action = 'status'
)

$ErrorActionPreference = 'Stop'
$ServiceName = 'HeraclitusDB'
$Bin = Join-Path $PSScriptRoot '..\target\release\heraclitus-service.exe' | Resolve-Path -ErrorAction SilentlyContinue
$LogDir = Join-Path $env:ProgramData 'HeraclitusDB\logs'

function Test-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Re-launch this script elevated for actions that touch the SCM.
function Invoke-Elevated([string]$act) {
    if (Test-Admin) { return $false }
    Write-Host "A pedir elevação (UAC) para '$act'..." -ForegroundColor Yellow
    $psi = "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" $act"
    Start-Process -FilePath 'powershell.exe' -ArgumentList $psi -Verb RunAs -Wait
    return $true
}

if (-not $Bin) {
    Write-Error "Binário não encontrado. Compile primeiro:`n" +
                "  cargo +stable-x86_64-pc-windows-msvc build --release --locked " +
                "-p heraclitus-server --bin heraclitus-service"
    exit 1
}

switch ($Action) {
    'install' {
        if (Invoke-Elevated 'install') { break }
        & $Bin install
        Write-Host "A arrancar o serviço..." -ForegroundColor Cyan
        Start-Service $ServiceName
        Get-Service $ServiceName | Format-Table -Auto
        Write-Host "Log: $LogDir" -ForegroundColor Green
    }
    'uninstall' {
        if (Invoke-Elevated 'uninstall') { break }
        & $Bin uninstall
    }
    'start' {
        if (Invoke-Elevated 'start') { break }
        Start-Service $ServiceName
        Get-Service $ServiceName | Format-Table -Auto
    }
    'stop' {
        if (Invoke-Elevated 'stop') { break }
        Stop-Service $ServiceName
        Get-Service $ServiceName | Format-Table -Auto
    }
    'status' {
        $svc = Get-Service $ServiceName -ErrorAction SilentlyContinue
        if ($svc) {
            $svc | Format-Table Name, Status, StartType -Auto
            try {
                $p = Get-CimInstance Win32_Service -Filter "Name='$ServiceName'"
                if ($p.ProcessId -gt 0) { Write-Host "PID: $($p.ProcessId)" -ForegroundColor Green }
            } catch {}
        } else {
            Write-Host "Serviço '$ServiceName' não instalado. Corre: .\heraclitus-service.ps1 install"
        }
        Write-Host "Log: $LogDir"
    }
    'logs' {
        $latest = Get-ChildItem $LogDir -Filter *.log -ErrorAction SilentlyContinue |
                  Sort-Object LastWriteTime -Descending | Select-Object -First 1
        if (-not $latest) { Write-Host "Sem logs ainda em $LogDir"; break }
        Write-Host "A seguir $($latest.FullName) (Ctrl+C para sair)`n" -ForegroundColor Cyan
        Get-Content $latest.FullName -Wait -Tail 30
    }
}
