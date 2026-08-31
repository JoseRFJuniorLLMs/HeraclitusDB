<#
.SYNOPSIS
  Produz a evidência reproduzível do gate de interoperabilidade RFC 3161.

.DESCRIPTION
  Executa o binário entregue de `heraclitus verify-token` contra um token real
  de uma ACT credenciada. O gate exige, sem defaults silenciosos: conteúdo
  conhecido (`Imprint`), política esperada (`PolicyOid`), âncoras instaladas e
  CRLs. O relatório liga o resultado aos hashes do servidor, da CLI, do token
  e de cada ficheiro de confiança usado.

  Este script produz o artefacto; não se auto-atesta. O laboratório ainda tem
  de incluir o JSON numa `act_interoperability.json`, ligá-la ao hash do
  servidor e assiná-la com a chave externa configurada no plano.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string]$HeraclitusCli,
    [Parameter(Mandatory)] [string]$ServerBinary,
    [Parameter(Mandatory)] [string]$Token,
    [Parameter(Mandatory)] [string]$TrustStore,
    [Parameter(Mandatory)] [string]$CrlDirectory,
    [Parameter(Mandatory)] [ValidatePattern('^[0-9a-fA-F]{64}$')] [string]$Imprint,
    [Parameter(Mandatory)] [ValidatePattern('^[0-2](?:\.[0-9]+)+$')] [string]$PolicyOid,
    [Parameter(Mandatory)] [string]$Output
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$cli = (Resolve-Path -LiteralPath $HeraclitusCli).Path
$server = (Resolve-Path -LiteralPath $ServerBinary).Path
$tokenPath = (Resolve-Path -LiteralPath $Token).Path
$anchors = (Resolve-Path -LiteralPath $TrustStore).Path
$crls = (Resolve-Path -LiteralPath $CrlDirectory).Path
$outputPath = [IO.Path]::GetFullPath($Output)
if (Test-Path -LiteralPath $outputPath) {
    throw "evidência já existe: $outputPath"
}
if (-not (Test-Path -LiteralPath $anchors -PathType Container)) {
    throw "trust store não é uma pasta: $anchors"
}
if (-not (Test-Path -LiteralPath $crls -PathType Container)) {
    throw "pasta de CRLs não existe: $crls"
}

function Get-MaterialDigest([string]$Directory) {
    @(
        Get-ChildItem -LiteralPath $Directory -File |
            Sort-Object -Property Name |
            ForEach-Object {
                [ordered]@{
                    name = $_.Name
                    bytes = [int64]$_.Length
                    sha256 = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
                }
            }
    )
}

$anchorFiles = @(Get-MaterialDigest $anchors)
$crlFiles = @(Get-MaterialDigest $crls)
if ($anchorFiles.Count -eq 0) { throw 'trust store vazio' }
if ($crlFiles.Count -eq 0) { throw 'pasta de CRLs vazia' }

$verifyArgs = @(
    'verify-token', $tokenPath,
    '--trust-store', $anchors,
    '--crl-dir', $crls,
    '--imprint', $Imprint.ToLowerInvariant(),
    '--policy-oid', $PolicyOid
)
$verifyOutput = (& $cli @verifyArgs 2>&1 | Out-String).Trim()
$verifyExit = [int]$LASTEXITCODE

$trustOutput = (& $cli 'trust-store' $anchors 2>&1 | Out-String).Trim()
$trustExit = [int]$LASTEXITCODE
$passed = $verifyExit -eq 0 -and $trustExit -eq 0

$parent = Split-Path -Parent $outputPath
if ($parent -and -not (Test-Path -LiteralPath $parent)) {
    New-Item -ItemType Directory -Path $parent | Out-Null
}
[ordered]@{
    schema_version = 1
    gate_id = 'act_interoperability'
    status = if ($passed) { 'Passed' } else { 'Failed' }
    executed_at_unix = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    subject_server_binary_sha256 = (Get-FileHash -LiteralPath $server -Algorithm SHA256).Hash.ToLowerInvariant()
    verifier_cli_sha256 = (Get-FileHash -LiteralPath $cli -Algorithm SHA256).Hash.ToLowerInvariant()
    token_sha256 = (Get-FileHash -LiteralPath $tokenPath -Algorithm SHA256).Hash.ToLowerInvariant()
    expected_imprint_sha256 = $Imprint.ToLowerInvariant()
    expected_policy_oid = $PolicyOid
    trust_anchors = $anchorFiles
    crls = $crlFiles
    verify_exit_code = $verifyExit
    trust_store_exit_code = $trustExit
    verify_output = $verifyOutput
    trust_store_output = $trustOutput
} | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $outputPath -Encoding UTF8

if (-not $passed) {
    throw "ACT_INTEROPERABILITY_FAILED verify_exit=$verifyExit trust_exit=$trustExit evidence=$outputPath"
}
Write-Host "ACT_INTEROPERABILITY_PASS evidence=$outputPath" -ForegroundColor Green
