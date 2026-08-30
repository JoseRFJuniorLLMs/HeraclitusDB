<#
.SYNOPSIS
  Monta um bundle offline novo, produz SBOM/proveniência/digests e assina sujeitos críticos.

.DESCRIPTION
  O output deve não existir. O signer é externo (HSM, cosign ou política do
  laboratório) e recebe argumentos com os tokens {file} e {signature}. O
  script falha se qualquer assinatura esperada não for criada.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string]$ServerBinary,
    [Parameter(Mandatory)] [string]$QualifierBinary,
    [Parameter(Mandatory)] [string]$OutputDirectory,
    [Parameter(Mandatory)] [string]$ReleaseVersion,
    [Parameter(Mandatory)] [string]$SignProgram,
    [Parameter(Mandatory)] [string[]]$SignArguments
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repo = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$server = (Resolve-Path -LiteralPath $ServerBinary).Path
$qualifier = (Resolve-Path -LiteralPath $QualifierBinary).Path
$out = [IO.Path]::GetFullPath($OutputDirectory)
if (Test-Path -LiteralPath $out) {
    throw "bundle já existe; não será sobrescrito: $out"
}

function Copy-New {
    param([string]$Source, [string]$Destination)
    if (Test-Path -LiteralPath $Destination) { throw "destino já existe: $Destination" }
    $parent = Split-Path -Parent $Destination
    New-Item -ItemType Directory -Path $parent -Force | Out-Null
    Copy-Item -LiteralPath $Source -Destination $Destination
}

function Get-RelativePath {
    param([string]$Base, [string]$Child)
    $prefix = [IO.Path]::GetFullPath($Base).TrimEnd('\') + '\'
    $full = [IO.Path]::GetFullPath($Child)
    if (-not $full.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw "arquivo fora do bundle: $full"
    }
    $full.Substring($prefix.Length).Replace('\', '/')
}

New-Item -ItemType Directory -Path $out | Out-Null
$serverName = if ([IO.Path]::GetExtension($server)) { 'heraclitus-server.exe' } else { 'heraclitus-server' }
$qualifierName = if ([IO.Path]::GetExtension($qualifier)) { 'heraclitus-qualifier.exe' } else { 'heraclitus-qualifier' }
$serverDest = Join-Path $out "bin\$serverName"
$qualifierDest = Join-Path $out "bin\$qualifierName"
Copy-New $server $serverDest
Copy-New $qualifier $qualifierDest

foreach ($relative in @(
    'windows\heraclitus-service.ps1',
    'windows\heraclitus-production.ps1',
    'windows\heraclitus-backup.ps1',
    'SECURITY.md',
    'docs\security\vulnerability-response.md',
    'docs\qualification\README.md',
    'Cargo.lock',
    'LICENSE'
)) {
    $source = Join-Path $repo $relative
    if (Test-Path -LiteralPath $source -PathType Leaf) {
        Copy-New $source (Join-Path $out $relative)
    }
}

$sbom = Join-Path $out 'sbom\bom.cdx.json'
New-Item -ItemType Directory -Path (Split-Path -Parent $sbom) -Force | Out-Null
Push-Location $repo
try {
    & $qualifier sbom --out $sbom
    if ($LASTEXITCODE -ne 0) { throw "SBOM generation failed: exit=$LASTEXITCODE" }
}
finally {
    Pop-Location
}

$gitCommit = (& git -C $repo rev-parse HEAD 2>$null) -join ''
$gitStatus = (& git -C $repo status --porcelain 2>$null) -join "`n"
$provenancePath = Join-Path $out 'provenance\build-provenance.json'
New-Item -ItemType Directory -Path (Split-Path -Parent $provenancePath) -Force | Out-Null
[ordered]@{
    schema_version = 1
    release_version = $ReleaseVersion
    source_repository = 'https://github.com/JoseRFJuniorLLMs/HeraclitusDB'
    git_commit = $gitCommit.Trim()
    repository_dirty = -not [string]::IsNullOrWhiteSpace($gitStatus)
    server_sha256 = (Get-FileHash -LiteralPath $serverDest -Algorithm SHA256).Hash.ToLowerInvariant()
    qualifier_sha256 = (Get-FileHash -LiteralPath $qualifierDest -Algorithm SHA256).Hash.ToLowerInvariant()
    cargo_lock_sha256 = (Get-FileHash -LiteralPath (Join-Path $repo 'Cargo.lock') -Algorithm SHA256).Hash.ToLowerInvariant()
    rustc = ((& rustc -Vv 2>$null) -join "`n")
    cargo = ((& cargo -V 2>$null) -join "`n")
    builder = [Environment]::MachineName
    created_at_utc = [DateTimeOffset]::UtcNow.ToString('o')
} | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $provenancePath -Encoding UTF8

$coreFiles = @($serverDest, $qualifierDest, $sbom, $provenancePath)
$manifestPath = Join-Path $out 'bundle-manifest.json'
[ordered]@{
    schema_version = 1
    format = 'heraclitus-offline-bundle/1'
    release_version = $ReleaseVersion
    server = "bin/$serverName"
    qualifier = "bin/$qualifierName"
    sbom = 'sbom/bom.cdx.json'
    provenance = 'provenance/build-provenance.json'
    signed_subjects = @($coreFiles | ForEach-Object { Get-RelativePath $out $_ })
} | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $manifestPath -Encoding UTF8
$coreFiles += $manifestPath

$signatureDir = Join-Path $out 'signatures'
New-Item -ItemType Directory -Path $signatureDir | Out-Null
foreach ($subject in $coreFiles) {
    $relative = (Get-RelativePath $out $subject).Replace('/', '_')
    $signature = Join-Path $signatureDir "$relative.sig"
    $arguments = @($SignArguments | ForEach-Object {
        $_.Replace('{file}', $subject).Replace('{signature}', $signature)
    })
    & $SignProgram @arguments
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $signature -PathType Leaf)) {
        throw "signature failed for $subject (exit=$LASTEXITCODE)"
    }
}

$sumPath = Join-Path $out 'SHA256SUMS'
$lines = @(
    Get-ChildItem -LiteralPath $out -Recurse -File | Where-Object {
        $_.FullName -ne $sumPath
    } | Sort-Object FullName | ForEach-Object {
        $hash = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        "$hash  $(Get-RelativePath $out $_.FullName)"
    }
)
[IO.File]::WriteAllLines($sumPath, $lines, [Text.UTF8Encoding]::new($false))

$sumSignature = Join-Path $signatureDir 'SHA256SUMS.sig'
$sumArgs = @($SignArguments | ForEach-Object {
    $_.Replace('{file}', $sumPath).Replace('{signature}', $sumSignature)
})
& $SignProgram @sumArgs
if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $sumSignature -PathType Leaf)) {
    throw "signature failed for SHA256SUMS (exit=$LASTEXITCODE)"
}

Write-Host "OFFLINE_BUNDLE_CREATED release=$ReleaseVersion path=$out" -ForegroundColor Green
