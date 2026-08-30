<#
.SYNOPSIS
  Valida por MUTAÇÃO os gates duros de Invoke-RaftFailureMatrix.ps1.

.DESCRIPTION
  Um harness que reprova tudo e um harness que aprova tudo passam igualmente no
  teste "corre sem erro". O que distingue os dois é forçar cada violação, uma de
  cada vez, e exigir que o veredicto mude — a mesma disciplina que a SPEC-0050
  usou para validar a Fase 6.

  Cada mutação é injetada no injetor de REFERÊNCIA, nunca no harness. O que se
  testa é o julgamento, não a instrumentação.

  Sem argumentos, usa um diretório temporário e limpa-o no fim.
#>
[CmdletBinding()]
param(
    [string]$OutputRoot
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$harness = Join-Path (Split-Path -Parent $here) 'Invoke-RaftFailureMatrix.ps1'
$injector = Join-Path $here 'Invoke-ReferenceFaultInjector.ps1'
$matrix = Join-Path (Split-Path -Parent (Split-Path -Parent $here)) 'matrices/raft-failure-matrix.json'

$temporary = -not $OutputRoot
if ($temporary) {
    $OutputRoot = Join-Path ([IO.Path]::GetTempPath()) ("raft-gate-selftest-" + [Guid]::NewGuid().ToString('N'))
}
New-Item -ItemType Directory -Path $OutputRoot -Force | Out-Null

function Invoke-Case {
    param([string]$Name, [string]$Mutation, [string]$Scenario = 'leader_process_loss')

    $directory = Join-Path $OutputRoot $Name
    if ($Mutation) { Set-Item -Path "Env:\$Mutation" -Value '1' }
    try {
        & $harness -Matrix $matrix -Injector $injector -OutputDirectory $directory `
            -Topologies 3 -OnlyScenarios $Scenario 2>&1 | Out-Null
    }
    catch {
        # O harness sinaliza reprovação por `throw`; o relatório já foi escrito.
    }
    finally {
        if ($Mutation) { Remove-Item -Path "Env:\$Mutation" -ErrorAction SilentlyContinue }
    }

    $report = Join-Path $directory 'result.json'
    if (-not (Test-Path -LiteralPath $report)) {
        return [pscustomobject]@{ case = $Name; status = 'NO_REPORT'; failures = 'o harness não escreveu relatório' }
    }
    $parsed = Get-Content -LiteralPath $report -Raw | ConvertFrom-Json
    [pscustomobject]@{ case = $Name; status = $parsed.status; failures = ($parsed.results[0].failures -join '; ') }
}

# nome                  mutação                            veredicto exigido
$cases = @(
    @{ n = 'clean';            m = $null;                              want = 'Passed' }
    @{ n = 'split_brain';      m = 'REFERENCE_INJECT_SPLIT_BRAIN';     want = 'Failed' }
    @{ n = 'entry_loss';       m = 'REFERENCE_INJECT_ENTRY_LOSS';      want = 'Failed' }
    @{ n = 'divergence';       m = 'REFERENCE_INJECT_DIVERGENCE';      want = 'Failed' }
    @{ n = 'duplicate_effects';m = 'REFERENCE_INJECT_DUPLICATES';      want = 'Failed' }
    @{ n = 'quorum_lie';       m = 'REFERENCE_INJECT_QUORUM_LIE';      want = 'Failed' }
    # Métrica em falta não é falha provada: é medição ausente, e a §107 diz que
    # Inconclusive nunca é Passed.
    @{ n = 'missing_metric';   m = 'REFERENCE_INJECT_MISSING_METRIC';  want = 'Inconclusive' }
    @{ n = 'no_report';        m = 'REFERENCE_INJECT_NO_REPORT';       want = 'Inconclusive' }
)

$problems = @()
foreach ($case in $cases) {
    $observed = Invoke-Case -Name $case.n -Mutation $case.m
    $ok = $observed.status -eq $case.want
    if (-not $ok) { $problems += "$($case.n): esperado $($case.want), obtido $($observed.status)" }
    "{0,-20} esperado={1,-13} obtido={2,-13} {3} {4}" -f `
        $case.n, $case.want, $observed.status, $(if ($ok) { 'OK' } else { 'ERRO' }), $observed.failures
}

# O caso `quorum_lie` merece uma nota: a mutação inverte quorum_available, por
# isso num cenário que a maioria deve sobreviver ela reporta quórum perdido.
# Ambas as direções são reprovação, e é isso que a §55 quer.

if ($temporary) { Remove-Item -Recurse -Force $OutputRoot -ErrorAction SilentlyContinue }

if ($problems.Count -gt 0) {
    throw "GATE_SELFTEST_FAILED`n$($problems -join "`n")"
}
Write-Host "RAFT_GATE_SELFTEST_PASS cases=$($cases.Count)" -ForegroundColor Green
