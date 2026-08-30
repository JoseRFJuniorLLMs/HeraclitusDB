<#
.SYNOPSIS
  Injetor de referência para exercitar Invoke-RaftFailureMatrix.ps1. NÃO injeta falhas.

.DESCRIPTION
  Existe por uma razão precisa: o harness da matriz Raft julga métricas que um
  laboratório produz, e sem um produtor não havia como saber se o julgamento
  está certo. Este script emite métricas sintéticas no formato do contrato, para
  que os gates duros possam ser testados — incluindo por MUTAÇÃO, forçando cada
  violação e exigindo que o harness reprove.

  NÃO é um injetor de falhas. Não mata processos, não corta rede, não pára
  discos. Um laboratório substitui-o por um injetor real com a mesma interface;
  usar este numa qualificação a sério produziria evidência fabricada, que é
  exatamente o que a §112 e a §113 proíbem.

  Mutações via ambiente, uma de cada vez:
    REFERENCE_INJECT_SPLIT_BRAIN=1     split_brain = $true
    REFERENCE_INJECT_ENTRY_LOSS=1      committed_entry_loss > 0
    REFERENCE_INJECT_DIVERGENCE=1      divergent_history > 0
    REFERENCE_INJECT_DUPLICATES=1      duplicate_effects > 0
    REFERENCE_INJECT_QUORUM_LIE=1      quorum_available invertido
    REFERENCE_INJECT_MISSING_METRIC=1  omite election_ms
    REFERENCE_INJECT_NO_REPORT=1       não escreve relatório nenhum
    REFERENCE_INJECT_EXIT=<n>          termina com esse código
#>
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# O contrato é `--scenario X --topology N --out P`, com duplo hífen, porque um
# injetor real tanto pode ser PowerShell como Python, Go ou um binário do
# fabricante do hipervisor. `param()` do PowerShell não aceita nomes com duplo
# hífen, por isso este script parseia $args à mão — que é precisamente o que
# qualquer injetor não-PowerShell faria.
$Scenario = $null; $Topology = $null; $Out = $null
for ($i = 0; $i -lt $args.Count; $i++) {
    switch ($args[$i]) {
        '--scenario' { $Scenario = $args[++$i] }
        '--topology' { $Topology = [int]$args[++$i] }
        '--out'      { $Out = $args[++$i] }
        default      { throw "argumento desconhecido: $($args[$i])" }
    }
}
if (-not $Scenario -or -not $Out) { throw 'faltam --scenario e/ou --out' }

if ($env:REFERENCE_INJECT_EXIT) { exit [int]$env:REFERENCE_INJECT_EXIT }
if ($env:REFERENCE_INJECT_NO_REPORT) { exit 0 }

# Um cenário que destrói a maioria não deve reportar quórum disponível.
$quorum = -not ($Scenario -eq 'quorum_partition')
if ($env:REFERENCE_INJECT_QUORUM_LIE) { $quorum = -not $quorum }

$metrics = [ordered]@{
    scenario                = $Scenario
    topology                = $Topology
    leader_loss_detect_ms   = 350
    election_ms             = 640
    write_unavailable_ms    = 1200
    catchup_ms              = 4800
    duplicate_effects       = if ($env:REFERENCE_INJECT_DUPLICATES) { 2 } else { 0 }
    committed_entry_loss    = if ($env:REFERENCE_INJECT_ENTRY_LOSS) { 7 } else { 0 }
    divergent_history       = if ($env:REFERENCE_INJECT_DIVERGENCE) { 1 } else { 0 }
    split_brain             = [bool]$env:REFERENCE_INJECT_SPLIT_BRAIN
    quorum_available        = $quorum
    injector                = 'reference (no real fault injected)'
}
if ($env:REFERENCE_INJECT_MISSING_METRIC) { $metrics.Remove('election_ms') }

$parent = Split-Path -Parent $Out
if ($parent -and -not (Test-Path -LiteralPath $parent)) {
    New-Item -ItemType Directory -Path $parent -Force | Out-Null
}
$metrics | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $Out -Encoding UTF8
exit 0
