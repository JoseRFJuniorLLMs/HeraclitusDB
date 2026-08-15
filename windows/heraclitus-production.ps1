<#
.SYNOPSIS
    Aplica o perfil seguro do serviço Windows sem colocar segredos no Git.

.DESCRIPTION
    Configura conta virtual de menor privilégio, ACLs, variáveis de máquina e
    token-file do utilizador. O perfil `homologation` ativa cifra, RBAC, fsync e
    meta-auditoria em loopback. `production` acrescenta os gates fail-closed do
    servidor e exige TSA HTTP e credencial REST fornecida por arquivo.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory, Position = 0)]
    [ValidateSet('apply', 'status')]
    [string]$Action,

    [ValidateSet('homologation', 'production')]
    [string]$Profile = 'homologation',
    [string]$DataDir,
    [string]$SecretsDir,
    [string]$LogDir = "$env:ProgramData\HeraclitusDB\logs",
    [string]$TsaUrl,
    [string]$TsaPolicy = 'ICP-Brasil-RFC3161',
    [string]$RestAuthFile,
    [string]$ServiceName = 'HeraclitusDB'
)

$ErrorActionPreference = 'Stop'
$serviceAccount = "NT SERVICE\$ServiceName"
$currentUser = [Security.Principal.WindowsIdentity]::GetCurrent().Name

function Test-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Set-MachineEnv([string]$Name, [AllowNull()][string]$Value) {
    [Environment]::SetEnvironmentVariable($Name, $Value, 'Machine')
}

function Assert-SafeDirectory([string]$Path, [string]$Label) {
    if ([string]::IsNullOrWhiteSpace($Path)) { throw "$Label não informado" }
    $full = [IO.Path]::GetFullPath($Path)
    $root = [IO.Path]::GetPathRoot($full)
    if ($full.TrimEnd('\') -eq $root.TrimEnd('\')) {
        throw "$Label não pode ser raiz do volume: $full"
    }
    if (-not (Test-Path -LiteralPath $full -PathType Container)) {
        throw "$Label inexistente: $full"
    }
    $full
}

function Invoke-Icacls([string[]]$Arguments) {
    & icacls.exe @Arguments | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "icacls falhou: $($Arguments -join ' ')" }
}

if ($Action -eq 'status') {
    sc.exe qc $ServiceName
    $names = @(
        'HERACLITUS_DATA_DIR', 'HERACLITUS_FSYNC', 'HERACLITUS_PRODUCTION',
        'HERACLITUS_CREDENTIALS_FILE', 'HERACLITUS_AUDIT_QUERIES',
        'HERACLITUS_ENCRYPTION', 'HERACLITUS_COMPLIANCE',
        'HERACLITUS_COMPLIANCE_TSA_URL', 'HERACLITUS_REST_AUTH_FILE',
        'HERACLITUS_TOKEN_FILE'
    )
    foreach ($name in $names) {
        $scope = if ($name -eq 'HERACLITUS_TOKEN_FILE') { 'User' } else { 'Machine' }
        $value = [Environment]::GetEnvironmentVariable($name, $scope)
        if (-not $value) { $value = '<unset>' }
        Write-Host "$scope $name=$value"
    }
    exit 0
}

if (-not (Test-Administrator)) {
    throw 'apply exige PowerShell executado como Administrador'
}

$data = Assert-SafeDirectory $DataDir 'data-dir'
$secrets = Assert-SafeDirectory $SecretsDir 'secrets-dir'
$logs = [IO.Path]::GetFullPath($LogDir)
New-Item -ItemType Directory -Path $logs -Force | Out-Null
$credentials = Join-Path $secrets 'credentials.json'
$writerToken = Join-Path $secrets 'writer.token'
$adminToken = Join-Path $secrets 'admin.token'
foreach ($required in @($credentials, $writerToken, $adminToken)) {
    if (-not (Test-Path -LiteralPath $required -PathType Leaf)) {
        throw "arquivo obrigatório ausente: $required"
    }
}

$restAuthPath = $null
if ($Profile -eq 'production') {
    if ([string]::IsNullOrWhiteSpace($TsaUrl) -or -not $TsaUrl.StartsWith('https://')) {
        throw 'production exige -TsaUrl HTTPS de uma TSA RFC3161 homologada'
    }
    if (-not $RestAuthFile -or -not (Test-Path -LiteralPath $RestAuthFile -PathType Leaf)) {
        throw 'production exige -RestAuthFile protegido contendo user:senha'
    }
    $restAuthPath = [IO.Path]::GetFullPath($RestAuthFile)
    $secretsPrefix = $secrets.TrimEnd('\') + '\'
    if (-not $restAuthPath.StartsWith($secretsPrefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'RestAuthFile deve ficar dentro de SecretsDir para receber ACL restritiva'
    }
    $restAuth = (Get-Content -LiteralPath $restAuthPath -Raw).Trim()
    if ($restAuth.Contains("`r") -or $restAuth.Contains("`n") -or
        $restAuth -notmatch '^[^:]+:.{16,}$') {
        throw 'RestAuthFile deve conter uma única linha user:senha forte'
    }
}

# Diretórios operacionais: somente administradores, SYSTEM e a conta virtual.
foreach ($dir in @($data, $logs)) {
    Invoke-Icacls @($dir, '/inheritance:r')
    Invoke-Icacls @(
        $dir, '/grant:r',
        "$currentUser`:(OI)(CI)F",
        '*S-1-5-32-544:(OI)(CI)F',
        '*S-1-5-18:(OI)(CI)F',
        "$serviceAccount`:(OI)(CI)M",
        '/T', '/C'
    )
}

# O serviço lê somente o hash; não recebe writer/admin.token.
Invoke-Icacls @($secrets, '/inheritance:r')
Invoke-Icacls @(
    $secrets, '/grant:r',
    "$currentUser`:(OI)(CI)F",
    '*S-1-5-32-544:(OI)(CI)F',
    '*S-1-5-18:(OI)(CI)F'
)
Invoke-Icacls @($secrets, '/grant', "$serviceAccount`:(RX)")
Invoke-Icacls @($credentials, '/grant:r', "$serviceAccount`:(R)")
Invoke-Icacls @(
    $writerToken, '/inheritance:r', '/grant:r',
    "$currentUser`:(R)", '*S-1-5-32-544:(F)', '*S-1-5-18:(F)'
)
Invoke-Icacls @(
    $adminToken, '/inheritance:r', '/grant:r',
    "$currentUser`:(R)", '*S-1-5-32-544:(F)', '*S-1-5-18:(F)'
)

if ($restAuthPath) {
    Invoke-Icacls @(
        $restAuthPath, '/inheritance:r', '/grant:r',
        "$currentUser`:(R)", '*S-1-5-32-544:(F)', '*S-1-5-18:(F)',
        "$serviceAccount`:(R)"
    )
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
$serviceInfo = Get-CimInstance Win32_Service -Filter "Name='$ServiceName'" -ErrorAction Stop
$previousAccount = $serviceInfo.StartName
$service = Get-Service -Name $ServiceName -ErrorAction Stop
$wasRunning = $service.Status -eq 'Running'

try {
    Set-MachineEnv 'HERACLITUS_DATA_DIR' $data
    Set-MachineEnv 'HERACLITUS_GRPC_ADDR' '127.0.0.1:7474'
    Set-MachineEnv 'HERACLITUS_REST_ADDR' '127.0.0.1:7475'
    Set-MachineEnv 'HERACLITUS_FSYNC' 'always'
    Set-MachineEnv 'HERACLITUS_CREDENTIALS_FILE' $credentials
    Set-MachineEnv 'HERACLITUS_AUDIT_QUERIES' 'true'
    Set-MachineEnv 'HERACLITUS_ENCRYPTION' 'true'
    [Environment]::SetEnvironmentVariable('HERACLITUS_TOKEN_FILE', $writerToken, 'User')

    if ($Profile -eq 'production') {
        Set-MachineEnv 'HERACLITUS_PRODUCTION' 'true'
        Set-MachineEnv 'HERACLITUS_REST_AUTH' $null
        Set-MachineEnv 'HERACLITUS_REST_AUTH_FILE' $restAuthPath
        Set-MachineEnv 'HERACLITUS_COMPLIANCE' 'true'
        Set-MachineEnv 'HERACLITUS_COMPLIANCE_TSA_URL' $TsaUrl
        Set-MachineEnv 'HERACLITUS_COMPLIANCE_TSA_POLICY' $TsaPolicy
    } else {
        Set-MachineEnv 'HERACLITUS_PRODUCTION' 'false'
        Set-MachineEnv 'HERACLITUS_REST_AUTH' $null
        Set-MachineEnv 'HERACLITUS_REST_AUTH_FILE' $null
        Set-MachineEnv 'HERACLITUS_COMPLIANCE' 'false'
        Set-MachineEnv 'HERACLITUS_COMPLIANCE_TSA_URL' $null
        Set-MachineEnv 'HERACLITUS_COMPLIANCE_TSA_POLICY' $null
    }

    if ($wasRunning) {
        Stop-Service -Name $ServiceName
        $service.WaitForStatus('Stopped', '00:00:30')
    }
    sc.exe config $ServiceName obj= $serviceAccount | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'não foi possível aplicar a conta virtual ao serviço' }
    Start-Service -Name $ServiceName
    (Get-Service -Name $ServiceName).WaitForStatus('Running', '00:00:30')
} catch {
    $failure = $_
    foreach ($name in $machineEnvNames) {
        Set-MachineEnv $name $previousEnv[$name]
    }
    [Environment]::SetEnvironmentVariable('HERACLITUS_TOKEN_FILE', $previousUserToken, 'User')
    $current = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($current -and $current.Status -eq 'Running') {
        Stop-Service -Name $ServiceName -ErrorAction SilentlyContinue
        $current.WaitForStatus('Stopped', '00:00:30')
    }
    sc.exe config $ServiceName obj= $previousAccount | Out-Null
    if ($wasRunning) {
        Start-Service -Name $ServiceName
        (Get-Service -Name $ServiceName).WaitForStatus('Running', '00:00:30')
    }
    throw $failure
}

Write-Host "PROFILE_APPLIED profile=$Profile data=$data account=$serviceAccount" -ForegroundColor Green
Write-Host 'O token não foi exibido. Abra um novo terminal para HERACLITUS_TOKEN_FILE entrar no ambiente.'
