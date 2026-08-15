<#
.SYNOPSIS
    Atualiza uma instalação local para o perfil seguro de homologação.

.DESCRIPTION
    Executa uma migração não destrutiva do data-dir, troca transacional do
    binário do serviço, aplica RBAC/cifra/fsync/meta-auditoria e prova backup,
    restore e restart. A origem e o binário anterior são preservados para
    rollback; nenhum diretório existente é sobrescrito.
#>
[CmdletBinding()]
param(
    [string]$SourceDataDir = 'D:\HeraclitusDB\data',
    [string]$DestinationDataDir = 'D:\HeraclitusDB\data-encrypted-v1',
    [string]$SecretsDir = 'D:\HeraclitusDB\secrets-v1',
    [string]$BackupRoot = 'D:\HeraclitusDB\backups',
    [string]$RestoreDestination,
    [string]$HeraclitusCli = (Join-Path $PSScriptRoot '..\target\release\heraclitus.exe'),
    [string]$StagedServiceBinary = (Join-Path $PSScriptRoot '..\target-deploy\release\heraclitus-service.exe'),
    [string]$InstalledServiceBinary = (Join-Path $PSScriptRoot '..\target\release\heraclitus-service.exe'),
    [string]$ServiceName = 'HeraclitusDB'
)

$ErrorActionPreference = 'Stop'
$stamp = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ')
if (-not $RestoreDestination) {
    $RestoreDestination = "D:\HeraclitusDB\restore-drill-$stamp"
}

function Test-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-SafeFullPath([string]$Path, [string]$Label) {
    if ([string]::IsNullOrWhiteSpace($Path)) { throw "$Label não informado" }
    $full = [IO.Path]::GetFullPath($Path)
    if ($full.TrimEnd('\') -eq [IO.Path]::GetPathRoot($full).TrimEnd('\')) {
        throw "$Label não pode ser a raiz do volume: $full"
    }
    $full
}

function Invoke-Native([string]$Executable, [string[]]$Arguments) {
    & $Executable @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "comando falhou ($LASTEXITCODE): $Executable $($Arguments -join ' ')"
    }
}

function Set-MachineEnv([string]$Name, [AllowNull()][string]$Value) {
    [Environment]::SetEnvironmentVariable($Name, $Value, 'Machine')
}

function Set-RestrictedAcl([string]$Path) {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent().Name
    & icacls.exe $Path '/inheritance:r' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "falha ao remover herança de ACL: $Path" }
    & icacls.exe $Path '/grant:r' `
        "$currentUser`:(OI)(CI)F" `
        '*S-1-5-32-544:(OI)(CI)F' `
        '*S-1-5-18:(OI)(CI)F' '/T' '/C' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "falha ao restringir ACL: $Path" }
}

if (-not (Test-Administrator)) {
    throw 'execute este script em PowerShell como Administrador'
}

$source = Get-SafeFullPath $SourceDataDir 'data-dir de origem'
$destination = Get-SafeFullPath $DestinationDataDir 'data-dir de destino'
$secrets = Get-SafeFullPath $SecretsDir 'diretório de segredos'
$backupRootFull = Get-SafeFullPath $BackupRoot 'raiz de backups'
$restore = Get-SafeFullPath $RestoreDestination 'destino do restore'
$cli = [IO.Path]::GetFullPath($HeraclitusCli)
$stagedBinary = [IO.Path]::GetFullPath($StagedServiceBinary)
$installedBinary = [IO.Path]::GetFullPath($InstalledServiceBinary)
$backupScript = Join-Path $PSScriptRoot 'heraclitus-backup.ps1'
$profileScript = Join-Path $PSScriptRoot 'heraclitus-production.ps1'

if (-not (Test-Path -LiteralPath $source -PathType Container)) {
    throw "data-dir de origem inexistente: $source"
}
foreach ($newPath in @($destination, $secrets, $restore)) {
    if (Test-Path -LiteralPath $newPath) {
        throw "destino deve ser novo e não pode ser sobrescrito: $newPath"
    }
}
foreach ($requiredFile in @($cli, $stagedBinary, $installedBinary, $backupScript, $profileScript)) {
    if (-not (Test-Path -LiteralPath $requiredFile -PathType Leaf)) {
        throw "arquivo obrigatório ausente: $requiredFile"
    }
}
if ($source -eq $destination) { throw 'origem e destino precisam ser diferentes' }

$service = Get-Service -Name $ServiceName -ErrorAction Stop
$serviceInfo = Get-CimInstance Win32_Service -Filter "Name='$ServiceName'" -ErrorAction Stop
$wasRunning = $service.Status -eq 'Running'
$previousAccount = $serviceInfo.StartName
$registeredMatch = [regex]::Match($serviceInfo.PathName, '^(?:"([^"]+\.exe)"|(.+?\.exe))(?:\s|$)')
if (-not $registeredMatch.Success) {
    throw "não foi possível resolver o binário registrado: $($serviceInfo.PathName)"
}
$registeredBinary = if ($registeredMatch.Groups[1].Success) {
    $registeredMatch.Groups[1].Value
} else {
    $registeredMatch.Groups[2].Value
}
if ([IO.Path]::GetFullPath($registeredBinary) -ne $installedBinary) {
    throw "binário informado não é o registrado no serviço: $registeredBinary"
}
if ($previousAccount -notmatch '^(LocalSystem|NT AUTHORITY\\(LocalService|NetworkService)|NT SERVICE\\.+)$') {
    throw "rollback automático não suporta conta de serviço personalizada: $previousAccount"
}

$machineEnvNames = @(
    'HERACLITUS_DATA_DIR', 'HERACLITUS_GRPC_ADDR', 'HERACLITUS_REST_ADDR',
    'HERACLITUS_FSYNC', 'HERACLITUS_CREDENTIALS_FILE',
    'HERACLITUS_AUDIT_QUERIES', 'HERACLITUS_ENCRYPTION',
    'HERACLITUS_PRODUCTION', 'HERACLITUS_REST_AUTH',
    'HERACLITUS_REST_AUTH_FILE', 'HERACLITUS_COMPLIANCE',
    'HERACLITUS_COMPLIANCE_TSA_URL', 'HERACLITUS_COMPLIANCE_TSA_POLICY'
)
$previousEnv = @{}
foreach ($name in $machineEnvNames) {
    $previousEnv[$name] = [Environment]::GetEnvironmentVariable($name, 'Machine')
}
$previousUserToken = [Environment]::GetEnvironmentVariable('HERACLITUS_TOKEN_FILE', 'User')
$binaryBackup = "$installedBinary.pre-$stamp"
$binaryWasReplaced = $false

try {
    if ($wasRunning) {
        Stop-Service -Name $ServiceName
        (Get-Service -Name $ServiceName).WaitForStatus('Stopped', '00:00:30')
    }

    Invoke-Native $cli @('verify', (Join-Path $source 'log'))
    Invoke-Native $cli @('migrate-encrypt', $source, $destination)
    Invoke-Native $cli @('verify', (Join-Path $destination 'log'))
    Invoke-Native $cli @('init-credentials', $secrets)

    Copy-Item -LiteralPath $installedBinary -Destination $binaryBackup
    Copy-Item -LiteralPath $stagedBinary -Destination $installedBinary -Force
    $binaryWasReplaced = $true
    $stagedHash = (Get-FileHash -LiteralPath $stagedBinary -Algorithm SHA256).Hash
    $installedHash = (Get-FileHash -LiteralPath $installedBinary -Algorithm SHA256).Hash
    if ($stagedHash -ne $installedHash) { throw 'hash do binário instalado diverge do staged' }

    & $profileScript apply -Profile homologation -DataDir $destination -SecretsDir $secrets

    $running = Get-Service -Name $ServiceName
    $running.WaitForStatus('Running', '00:00:30')
    Invoke-Native $cli @('verify', (Join-Path $destination 'log'))

    $beforeBackups = @(
        Get-ChildItem -LiteralPath $backupRootFull -Directory -ErrorAction SilentlyContinue |
            Select-Object -ExpandProperty FullName
    )
    & $backupScript backup -Source $destination -BackupRoot $backupRootFull `
        -ServiceName $ServiceName -HeraclitusCli $cli
    $newBackups = @(
        Get-ChildItem -LiteralPath $backupRootFull -Directory |
            Where-Object FullName -NotIn $beforeBackups
    )
    if ($newBackups.Count -ne 1) {
        throw "era esperado exatamente um backup novo; encontrados=$($newBackups.Count)"
    }
    $backupPath = $newBackups[0].FullName
    & $backupScript verify -BackupPath $backupPath -HeraclitusCli $cli
    & $backupScript restore -BackupPath $backupPath -Destination $restore `
        -ServiceName $ServiceName -HeraclitusCli $cli
    Invoke-Native $cli @('verify', (Join-Path $restore 'log'))

    Restart-Service -Name $ServiceName
    (Get-Service -Name $ServiceName).WaitForStatus('Running', '00:00:30')
    Invoke-Native $cli @('verify', (Join-Path $destination 'log'))

    Set-RestrictedAcl $source
    Set-RestrictedAcl $backupRootFull
    Set-RestrictedAcl $restore

    Write-Host "DEPLOYMENT_OK profile=homologation data=$destination" -ForegroundColor Green
    Write-Host "BACKUP_OK path=$backupPath restore=$restore" -ForegroundColor Green
    Write-Host "BINARY_SHA256 $installedHash" -ForegroundColor Green
    Write-Host "ROLLBACK_PRESERVED data=$source binary=$binaryBackup" -ForegroundColor Cyan
} catch {
    $failure = $_
    $current = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($current -and $current.Status -eq 'Running') {
        Stop-Service -Name $ServiceName -ErrorAction SilentlyContinue
        $current.WaitForStatus('Stopped', '00:00:30')
    }
    foreach ($name in $machineEnvNames) { Set-MachineEnv $name $previousEnv[$name] }
    [Environment]::SetEnvironmentVariable('HERACLITUS_TOKEN_FILE', $previousUserToken, 'User')
    & sc.exe config $ServiceName obj= $previousAccount | Out-Null
    if ($binaryWasReplaced -and (Test-Path -LiteralPath $binaryBackup -PathType Leaf)) {
        Copy-Item -LiteralPath $binaryBackup -Destination $installedBinary -Force
    }
    if ($wasRunning) {
        Start-Service -Name $ServiceName
        (Get-Service -Name $ServiceName).WaitForStatus('Running', '00:00:30')
    }
    throw $failure
}
