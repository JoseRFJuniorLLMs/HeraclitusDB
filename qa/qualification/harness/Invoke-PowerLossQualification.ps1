<#
.SYNOPSIS
  Arma e conclui um ensaio de power-loss real sem fingir que kill -9 é equivalente.

.DESCRIPTION
  Prepare inicia a carga e grava o estado pré-corte. O corte deve ser feito por
  PDU ou hypervisor externo. Recover roda após o boot, exige a evidência do
  controlador externo, executa a verificação e grava o estado pós-corte.

  O script NUNCA desliga a própria máquina e nunca marca a release como
  qualificada. O resultado deve ser assinado pelo laboratório e consumido como
  attestation pelo heraclitus-qualifier.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateSet('Prepare', 'Recover')]
    [string]$Phase,

    [Parameter(Mandatory)] [string]$EvidenceDirectory,
    [Parameter(Mandatory)] [string]$DataDirectory,

    [string]$WorkloadProgram,
    [string[]]$WorkloadArguments = @(),
    [string]$WorkingDirectory,

    [string]$VerifyProgram,
    [string[]]$VerifyArguments = @(),
    [string]$ControllerAttestation
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$evidence = [IO.Path]::GetFullPath($EvidenceDirectory)
$data = (Resolve-Path -LiteralPath $DataDirectory).Path

function Get-DataManifest {
    param([string]$Root)
    @(
        Get-ChildItem -LiteralPath $Root -Recurse -File | Sort-Object FullName | ForEach-Object {
            [pscustomobject]@{
                path = $_.FullName.Substring($Root.TrimEnd('\').Length).TrimStart('\').Replace('\', '/')
                size = $_.Length
                sha256 = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
            }
        }
    )
}

if ($Phase -eq 'Prepare') {
    if (Test-Path -LiteralPath $evidence) {
        throw "evidência já existe; não será sobrescrita: $evidence"
    }
    if ([string]::IsNullOrWhiteSpace($WorkloadProgram)) {
        throw '-WorkloadProgram é obrigatório em Prepare'
    }
    New-Item -ItemType Directory -Path $evidence | Out-Null
    $before = Get-DataManifest $data
    $workdir = if ([string]::IsNullOrWhiteSpace($WorkingDirectory)) {
        (Get-Location).Path
    } else {
        (Resolve-Path -LiteralPath $WorkingDirectory).Path
    }
    $process = Start-Process -FilePath $WorkloadProgram -ArgumentList $WorkloadArguments `
        -WorkingDirectory $workdir -WindowStyle Hidden -PassThru
    [ordered]@{
        schema_version = 1
        phase = 'Armed'
        armed_at_utc = [DateTimeOffset]::UtcNow.ToString('o')
        machine = [Environment]::MachineName
        workload_pid = $process.Id
        workload_program = $WorkloadProgram
        workload_arguments = $WorkloadArguments
        data_directory = $data
        files_before = $before
        required_external_action = 'Remove power through independent PDU or hypervisor controller while writes are active.'
    } | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath (Join-Path $evidence 'armed.json') -Encoding UTF8
    Write-Host "POWER_LOSS_ARMED pid=$($process.Id) evidence=$evidence" -ForegroundColor Yellow
    Write-Host 'Execute o corte por controlador EXTERNO; não use Stop-Process nem shutdown local.' -ForegroundColor Yellow
    exit 75
}

$armedPath = Join-Path $evidence 'armed.json'
$recoveryPath = Join-Path $evidence 'recovery.json'
if (-not (Test-Path -LiteralPath $armedPath -PathType Leaf)) {
    throw "estado Armed ausente: $armedPath"
}
if (Test-Path -LiteralPath $recoveryPath) {
    throw "recovery já foi registrado; não será sobrescrito: $recoveryPath"
}
if ([string]::IsNullOrWhiteSpace($VerifyProgram)) {
    throw '-VerifyProgram é obrigatório em Recover'
}
if ([string]::IsNullOrWhiteSpace($ControllerAttestation) -or
    -not (Test-Path -LiteralPath $ControllerAttestation -PathType Leaf)) {
    throw 'Recover exige -ControllerAttestation produzido pelo PDU/hypervisor externo'
}

$controllerCopy = Join-Path $evidence 'controller-attestation.bin'
Copy-Item -LiteralPath $ControllerAttestation -Destination $controllerCopy
$stdout = Join-Path $evidence 'verify.stdout.log'
$stderr = Join-Path $evidence 'verify.stderr.log'
$started = [DateTimeOffset]::UtcNow
& $VerifyProgram @VerifyArguments 1> $stdout 2> $stderr
$verifyExit = [int]$LASTEXITCODE
$finished = [DateTimeOffset]::UtcNow
$after = Get-DataManifest $data
$status = if ($verifyExit -eq 0) { 'Passed' } else { 'Failed' }

[ordered]@{
    schema_version = 1
    phase = 'Recovered'
    status = $status
    recovered_at_utc = $finished.ToString('o')
    verification_started_at_utc = $started.ToString('o')
    recovery_verification_ms = [math]::Round(($finished - $started).TotalMilliseconds)
    verifier_exit_code = $verifyExit
    controller_attestation_sha256 = (Get-FileHash -LiteralPath $controllerCopy -Algorithm SHA256).Hash.ToLowerInvariant()
    files_after = $after
} | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $recoveryPath -Encoding UTF8

if ($verifyExit -ne 0) {
    throw "POWER_LOSS_RECOVERY_FAILED exit=$verifyExit evidence=$evidence"
}
Write-Host "POWER_LOSS_RECOVERY_PASS evidence=$evidence" -ForegroundColor Green
