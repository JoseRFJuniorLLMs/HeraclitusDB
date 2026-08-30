<#
.SYNOPSIS
  Automatiza backup, verify e restore para um diretório vazio e mede o RTO.

.DESCRIPTION
  O destino deve não existir. O probe fornecido pelo laboratório deve abrir o
  banco restaurado, servir uma leitura e terminar com zero. A assinatura e o
  ambiente vazio continuam sendo responsabilidade do ensaio de laboratório.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string]$SourceDataDirectory,
    [Parameter(Mandatory)] [string]$BackupRoot,
    [Parameter(Mandatory)] [string]$RestoreDestination,
    [Parameter(Mandatory)] [string]$HeraclitusCli,
    [Parameter(Mandatory)] [string]$ServeProbeProgram,
    [string[]]$ServeProbeArguments = @('{restore}'),
    [Parameter(Mandatory)] [string]$EvidenceDirectory
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repo = (Resolve-Path (Join-Path $PSScriptRoot '..\..\..')).Path
$backupScript = Join-Path $repo 'windows\heraclitus-backup.ps1'
$source = (Resolve-Path -LiteralPath $SourceDataDirectory).Path
$backupRootFull = [IO.Path]::GetFullPath($BackupRoot)
$restore = [IO.Path]::GetFullPath($RestoreDestination)
$evidence = [IO.Path]::GetFullPath($EvidenceDirectory)
foreach ($newPath in @($restore, $evidence)) {
    if (Test-Path -LiteralPath $newPath) {
        throw "destino deve ser novo e não será sobrescrito: $newPath"
    }
}
New-Item -ItemType Directory -Path $evidence | Out-Null
New-Item -ItemType Directory -Path $backupRootFull -Force | Out-Null
$before = @(Get-ChildItem -LiteralPath $backupRootFull -Directory | Select-Object -ExpandProperty FullName)

$started = [DateTimeOffset]::UtcNow
& $backupScript backup -Source $source -BackupRoot $backupRootFull -Offline -HeraclitusCli $HeraclitusCli
if ($LASTEXITCODE -ne 0) { throw "backup falhou: exit=$LASTEXITCODE" }
$after = @(Get-ChildItem -LiteralPath $backupRootFull -Directory | Select-Object -ExpandProperty FullName)
$backup = @($after | Where-Object { $_ -notin $before })
if ($backup.Count -ne 1) { throw "esperado exatamente um backup novo; encontrados=$($backup.Count)" }
& $backupScript verify -BackupPath $backup[0] -Offline -HeraclitusCli $HeraclitusCli
if ($LASTEXITCODE -ne 0) { throw "verify de backup falhou: exit=$LASTEXITCODE" }
& $backupScript restore -BackupPath $backup[0] -Destination $restore -Offline -HeraclitusCli $HeraclitusCli
if ($LASTEXITCODE -ne 0) { throw "restore falhou: exit=$LASTEXITCODE" }
& $HeraclitusCli verify (Join-Path $restore 'log')
if ($LASTEXITCODE -ne 0) { throw "verify do restore falhou: exit=$LASTEXITCODE" }

$probeArgs = @($ServeProbeArguments | ForEach-Object { $_.Replace('{restore}', $restore) })
$probeOut = Join-Path $evidence 'serve-probe.stdout.log'
$probeErr = Join-Path $evidence 'serve-probe.stderr.log'
& $ServeProbeProgram @probeArgs 1> $probeOut 2> $probeErr
$probeExit = [int]$LASTEXITCODE
$finished = [DateTimeOffset]::UtcNow

[ordered]@{
    schema_version = 1
    status = if ($probeExit -eq 0) { 'Passed' } else { 'Failed' }
    source = $source
    backup = $backup[0]
    restore = $restore
    started_at_utc = $started.ToString('o')
    finished_at_utc = $finished.ToString('o')
    rto_ms = [math]::Round(($finished - $started).TotalMilliseconds)
    serve_probe_exit_code = $probeExit
    backup_manifest_sha256 = (Get-FileHash -LiteralPath (Join-Path $backup[0] 'manifest.json') -Algorithm SHA256).Hash.ToLowerInvariant()
} | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $evidence 'q6-result.json') -Encoding UTF8

if ($probeExit -ne 0) { throw "Q6_SERVE_PROBE_FAILED exit=$probeExit" }
Write-Host "Q6_RESTORE_PASS rto_ms=$([math]::Round(($finished - $started).TotalMilliseconds)) evidence=$evidence" -ForegroundColor Green
