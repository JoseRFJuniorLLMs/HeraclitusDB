<#
.SYNOPSIS
  Injeta cinco classes determinísticas de corrupção numa cópia e exige fail-closed.

.DESCRIPTION
  O input nunca é alterado. Cada mutante é novo e deve ser recusado pelo
  verificador fornecido. Um exit code zero significa corrupção silenciosamente
  aceita e falha imediatamente o ensaio.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string]$Input,
    [Parameter(Mandatory)] [string]$OutputDirectory,
    [Parameter(Mandatory)] [string]$QualifierPath,
    [Parameter(Mandatory)] [string]$VerifyProgram,
    [Parameter(Mandatory)] [string[]]$VerifyArguments,
    [uint64]$Seed = 428931
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$inputPath = (Resolve-Path -LiteralPath $Input).Path
$out = [IO.Path]::GetFullPath($OutputDirectory)
if (Test-Path -LiteralPath $out) {
    throw "diretório de corrupção já existe; não será sobrescrito: $out"
}
New-Item -ItemType Directory -Path $out | Out-Null

$modes = @('flip-bit', 'truncate', 'zero-range', 'duplicate-range', 'remove-range')
$results = @()
foreach ($mode in $modes) {
    $mutant = Join-Path $out "$mode.bin"
    & $QualifierPath corrupt --input $inputPath --output $mutant --mode $mode --seed $Seed
    if ($LASTEXITCODE -ne 0) {
        throw "injeção falhou: $mode (exit=$LASTEXITCODE)"
    }
    $arguments = @($VerifyArguments | ForEach-Object { $_.Replace('{file}', $mutant) })
    $stdout = Join-Path $out "$mode.verify.stdout.log"
    $stderr = Join-Path $out "$mode.verify.stderr.log"
    & $VerifyProgram @arguments 1> $stdout 2> $stderr
    $exitCode = [int]$LASTEXITCODE
    $rejected = $exitCode -ne 0
    $results += [pscustomobject]@{
        mode = $mode
        mutant = [IO.Path]::GetFileName($mutant)
        mutant_sha256 = (Get-FileHash -LiteralPath $mutant -Algorithm SHA256).Hash.ToLowerInvariant()
        verifier_exit_code = $exitCode
        corruption_rejected = $rejected
    }
    if (-not $rejected) {
        $results | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $out 'result.json') -Encoding UTF8
        throw "CORRUPTION_ACCEPTED mode=$mode file=$mutant"
    }
}

[ordered]@{
    schema_version = 1
    input_sha256 = (Get-FileHash -LiteralPath $inputPath -Algorithm SHA256).Hash.ToLowerInvariant()
    seed = $Seed
    status = 'Passed'
    trials = $results
} | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $out 'result.json') -Encoding UTF8

Write-Host "CORRUPTION_MATRIX_PASS modes=$($modes.Count) evidence=$out" -ForegroundColor Green
