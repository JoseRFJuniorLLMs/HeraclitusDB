<#
.SYNOPSIS
    Backup, verificação e restore não destrutivo do data-dir do HeraclitusDB.

.DESCRIPTION
    Backup consistente por parada graciosa do serviço, cópia integral e
    manifesto SHA-256. Restore só aceita um destino que ainda não existe; este
    script nunca apaga nem sobrescreve o data-dir ativo.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory, Position = 0)]
    [ValidateSet('backup', 'verify', 'restore')]
    [string]$Action,

    [string]$Source,
    [string]$BackupRoot,
    [string]$BackupPath,
    [string]$Destination,
    [string]$ServiceName = 'HeraclitusDB',
    [string]$HeraclitusCli,
    [switch]$Offline
)

$ErrorActionPreference = 'Stop'

function Test-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not $Offline -and $Action -in @('backup', 'restore') -and -not (Test-Administrator)) {
    throw 'backup/restore com controlo do serviço exige PowerShell como Administrador; use -Offline somente com o serviço já parado'
}

function Get-AbsolutePath([string]$Path) {
    if ([string]::IsNullOrWhiteSpace($Path)) { throw 'caminho vazio' }
    [IO.Path]::GetFullPath($Path)
}

function Assert-NotVolumeRoot([string]$Path, [string]$Label) {
    $full = Get-AbsolutePath $Path
    $root = [IO.Path]::GetPathRoot($full)
    if ($full.TrimEnd('\') -eq $root.TrimEnd('\')) {
        throw "$Label não pode ser a raiz do volume: $full"
    }
    $full
}

function Test-IsWithin([string]$Child, [string]$Parent) {
    $childFull = (Get-AbsolutePath $Child).TrimEnd('\') + '\'
    $parentFull = (Get-AbsolutePath $Parent).TrimEnd('\') + '\'
    $childFull.StartsWith($parentFull, [StringComparison]::OrdinalIgnoreCase)
}

function Get-Manifest([string]$Payload) {
    $payloadFull = Get-AbsolutePath $Payload
    @(
        Get-ChildItem -LiteralPath $payloadFull -Recurse -File | Sort-Object FullName | ForEach-Object {
            [pscustomobject]@{
                path = [IO.Path]::GetRelativePath($payloadFull, $_.FullName).Replace('\', '/')
                length = $_.Length
                sha256 = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
            }
        }
    )
}

function Assert-Manifest([string]$Path) {
    $backup = Assert-NotVolumeRoot $Path 'backup'
    $manifestPath = Join-Path $backup 'manifest.json'
    $payload = Join-Path $backup 'data'
    if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) {
        throw "manifesto ausente: $manifestPath"
    }
    if (-not (Test-Path -LiteralPath $payload -PathType Container)) {
        throw "payload ausente: $payload"
    }
    $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
    $actual = Get-Manifest $payload
    if ($manifest.files.Count -ne $actual.Count) {
        throw "quantidade de arquivos diverge: manifesto=$($manifest.files.Count) atual=$($actual.Count)"
    }
    $expectedByPath = @{}
    foreach ($file in $manifest.files) { $expectedByPath[$file.path] = $file }
    foreach ($file in $actual) {
        $expected = $expectedByPath[$file.path]
        if (-not $expected) { throw "arquivo inesperado no backup: $($file.path)" }
        if ([int64]$expected.length -ne [int64]$file.length -or $expected.sha256 -ne $file.sha256) {
            throw "hash/tamanho divergente: $($file.path)"
        }
    }
    if ($HeraclitusCli) {
        $logDir = Join-Path $payload 'log'
        & $HeraclitusCli verify $logDir
        if ($LASTEXITCODE -ne 0) { throw "verificação Merkle/CRC falhou em $logDir" }
    }
    Write-Host "BACKUP_OK arquivos=$($actual.Count) path=$backup" -ForegroundColor Green
    $backup
}

function Invoke-WithServiceStopped([scriptblock]$Operation) {
    if ($Offline) { & $Operation; return }
    $service = Get-Service -Name $ServiceName -ErrorAction Stop
    $wasRunning = $service.Status -eq 'Running'
    try {
        if ($wasRunning) {
            Stop-Service -Name $ServiceName
            $service.WaitForStatus('Stopped', '00:00:30')
        }
        & $Operation
    } finally {
        if ($wasRunning) {
            Start-Service -Name $ServiceName
            (Get-Service -Name $ServiceName).WaitForStatus('Running', '00:00:30')
        }
    }
}

switch ($Action) {
    'backup' {
        if (-not $Source) {
            $Source = [Environment]::GetEnvironmentVariable('HERACLITUS_DATA_DIR', 'Machine')
        }
        if (-not $Source) { $Source = Join-Path $env:ProgramData 'HeraclitusDB\data' }
        if (-not $BackupRoot) { throw '-BackupRoot é obrigatório para backup' }
        $sourceFull = Assert-NotVolumeRoot $Source 'origem'
        $rootFull = Assert-NotVolumeRoot $BackupRoot 'raiz de backups'
        if (-not (Test-Path -LiteralPath $sourceFull -PathType Container)) {
            throw "origem inexistente: $sourceFull"
        }
        if ((Test-IsWithin $rootFull $sourceFull) -or (Test-IsWithin $sourceFull $rootFull)) {
            throw 'origem e raiz de backups não podem conter uma à outra'
        }
        New-Item -ItemType Directory -Path $rootFull -Force | Out-Null
        $stamp = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ')
        $backup = Join-Path $rootFull "heraclitus-backup-$stamp"
        if (Test-Path -LiteralPath $backup) { throw "backup já existe: $backup" }

        Invoke-WithServiceStopped {
            New-Item -ItemType Directory -Path $backup | Out-Null
            $payload = Join-Path $backup 'data'
            Copy-Item -LiteralPath $sourceFull -Destination $payload -Recurse
            $files = Get-Manifest $payload
            $manifest = [ordered]@{
                format = 'heraclitus-backup/1'
                created_utc = (Get-Date).ToUniversalTime().ToString('o')
                source = $sourceFull
                files = $files
            }
            $manifest | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $backup 'manifest.json') -Encoding utf8
        }
        Assert-Manifest $backup | Out-Null
        Write-Host "BACKUP_CREATED $backup" -ForegroundColor Cyan
    }
    'verify' {
        if (-not $BackupPath) { throw '-BackupPath é obrigatório para verify' }
        Assert-Manifest $BackupPath | Out-Null
    }
    'restore' {
        if (-not $BackupPath -or -not $Destination) {
            throw '-BackupPath e -Destination são obrigatórios para restore'
        }
        $backup = Assert-Manifest $BackupPath
        $destinationFull = Assert-NotVolumeRoot $Destination 'destino'
        if (Test-Path -LiteralPath $destinationFull) {
            throw "destino já existe; restore nunca sobrescreve: $destinationFull"
        }
        $payload = Join-Path $backup 'data'
        if ((Test-IsWithin $destinationFull $backup) -or (Test-IsWithin $backup $destinationFull)) {
            throw 'backup e destino não podem conter um ao outro'
        }
        Invoke-WithServiceStopped {
            Copy-Item -LiteralPath $payload -Destination $destinationFull -Recurse
        }
        Write-Host "RESTORE_CREATED $destinationFull" -ForegroundColor Green
    }
}
