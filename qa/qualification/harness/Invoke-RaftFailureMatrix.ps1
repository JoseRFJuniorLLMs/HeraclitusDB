<#
.SYNOPSIS
  Percorre a matriz de falhas Raft (SPEC-0049 §51-§57) e aplica os gates duros.

.DESCRIPTION
  A matriz em qa/qualification/matrices/raft-failure-matrix.json enumera os
  cenários; este harness executa cada um através de um injetor fornecido pelo
  laboratório e recolhe as métricas obrigatórias.

  O injetor é externo por uma razão que não é preguiça: perder um HOST, cortar
  a rede ou parar um disco não são coisas que um processo possa fazer a si
  próprio de forma credível. Quem consegue fazê-las é o hipervisor, o switch ou
  a PDU. O harness define o contrato, executa a matriz e julga o resultado; a
  falha real vem de fora.

  Contrato do injetor: recebe --scenario, --topology e --out, e escreve nesse
  caminho um JSON com as chaves de required_metrics mais split_brain (bool) e
  quorum_available (bool). Exit code diferente de zero aborta o cenário.

  Um cenário sem métrica obrigatória fica Inconclusive, nunca Passed (PQ17).

.EXAMPLE
  ./Invoke-RaftFailureMatrix.ps1 -Matrix ../matrices/raft-failure-matrix.json `
      -Injector ./lab-fault-injector.ps1 -OutputDirectory ../../../qa-evidence/q5
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string]$Matrix,
    [Parameter(Mandatory)] [string]$Injector,
    [Parameter(Mandatory)] [string]$OutputDirectory,
    [string[]]$InjectorArguments = @(),
    [int[]]$Topologies,
    [string[]]$OnlyScenarios
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$matrixPath = (Resolve-Path -LiteralPath $Matrix).Path
$injectorPath = (Resolve-Path -LiteralPath $Injector).Path
$out = [IO.Path]::GetFullPath($OutputDirectory)
if (Test-Path -LiteralPath $out) {
    throw "diretório de evidência já existe; não será sobrescrito: $out"
}
New-Item -ItemType Directory -Path $out | Out-Null

$spec = Get-Content -LiteralPath $matrixPath -Raw | ConvertFrom-Json
if ($spec.schema_version -ne 1) {
    throw "schema de matriz não suportado: $($spec.schema_version)"
}

$targetTopologies = if ($Topologies) { $Topologies } else { $spec.topologies }
$scenarios = $spec.scenarios
if ($OnlyScenarios) {
    $scenarios = @($scenarios | Where-Object { $OnlyScenarios -contains $_.id })
    if ($scenarios.Count -ne $OnlyScenarios.Count) {
        throw '-OnlyScenarios refere um cenário que não existe na matriz'
    }
}

$results = @()
$blocking = @()

foreach ($topology in $targetTopologies) {
    foreach ($scenario in $scenarios) {
        $label = "$($scenario.id)-n$topology"
        $reportPath = Join-Path $out "$label.json"
        $stdout = Join-Path $out "$label.stdout.log"
        $stderr = Join-Path $out "$label.stderr.log"

        $arguments = @($InjectorArguments) + @(
            '--scenario', $scenario.id,
            '--topology', "$topology",
            '--out', $reportPath
        )
        & $injectorPath @arguments 1> $stdout 2> $stderr
        $injectorExit = [int]$LASTEXITCODE

        $status = 'Passed'
        $failures = @()
        $metrics = $null

        if ($injectorExit -ne 0) {
            $status = 'Failed'
            $failures += "injetor terminou com exit=$injectorExit"
        }
        elseif (-not (Test-Path -LiteralPath $reportPath)) {
            # Sem relatório não há medição. Isso não prova que o cenário passou.
            $status = 'Inconclusive'
            $failures += 'o injetor não escreveu relatório'
        }
        else {
            $metrics = Get-Content -LiteralPath $reportPath -Raw | ConvertFrom-Json
            # `Set-StrictMode -Version Latest` faz LANÇAR o acesso a uma
            # propriedade inexistente. Escrever `$metrics.$required` rebentava
            # exatamente no caso que esta verificação existe para detetar: a
            # métrica em falta. Perguntar pelo nome não tem esse problema.
            $present = @($metrics.PSObject.Properties.Name)
            foreach ($required in $spec.required_metrics) {
                if ($present -notcontains $required -or $null -eq $metrics.$required) {
                    $status = 'Inconclusive'
                    $failures += "métrica obrigatória ausente: $required"
                }
            }

            # §53 e §114 — os gates que reprovam a release inteira.
            if ($metrics.committed_entry_loss -and [int64]$metrics.committed_entry_loss -ne 0) {
                $status = 'Failed'
                $failures += "committed_entry_loss=$($metrics.committed_entry_loss)"
            }
            if ($metrics.divergent_history -and [int64]$metrics.divergent_history -ne 0) {
                $status = 'Failed'
                $failures += "divergent_history=$($metrics.divergent_history)"
            }
            if ($metrics.split_brain -eq $true) {
                $status = 'Failed'
                $failures += 'split_brain observado'
            }
            # §57 — trocar de líder não pode reexecutar a ação externa.
            if ($metrics.duplicate_effects -and [int64]$metrics.duplicate_effects -ne 0) {
                $status = 'Failed'
                $failures += "duplicate_effects=$($metrics.duplicate_effects)"
            }
            # §55 — sem quórum, recusar escrever é o comportamento correto.
            if ($scenario.quorum_expected -eq $false -and $metrics.quorum_available -eq $true) {
                $status = 'Failed'
                $failures += 'quórum reportado como disponível num cenário que o destrói'
            }
            if ($scenario.quorum_expected -eq $true -and $metrics.quorum_available -eq $false) {
                $status = 'Failed'
                $failures += 'quórum perdido num cenário que a maioria deveria sobreviver'
            }
        }

        if ($status -ne 'Passed') { $blocking += "$label : $($failures -join '; ')" }

        $results += [pscustomobject]@{
            scenario = $scenario.id
            topology = $topology
            fault = $scenario.fault
            quorum_expected = $scenario.quorum_expected
            injector_exit_code = $injectorExit
            status = $status
            failures = $failures
            report = [IO.Path]::GetFileName($reportPath)
            metrics = $metrics
        }
        Write-Host ("{0,-34} n={1} {2}" -f $scenario.id, $topology, $status)
    }
}

# §107 — Inconclusive e Failed NÃO são a mesma coisa. Um cenário reprovado
# significa que se provou o defeito e a release está bloqueada; um cenário
# inconclusivo significa que a medição não se fez, e o que é preciso é repetir
# o ensaio. Colapsar os dois num só "Failed" apaga essa diferença justamente
# quando ela decide o que fazer a seguir. Nenhum dos dois é Passed.
$failed = @($results | Where-Object { $_.status -eq 'Failed' })
$inconclusive = @($results | Where-Object { $_.status -eq 'Inconclusive' })
$overall = if ($failed.Count -gt 0) { 'Failed' }
           elseif ($inconclusive.Count -gt 0) { 'Inconclusive' }
           else { 'Passed' }
[ordered]@{
    schema_version = 1
    generator = 'Invoke-RaftFailureMatrix.ps1'
    matrix_sha256 = (Get-FileHash -LiteralPath $matrixPath -Algorithm SHA256).Hash.ToLowerInvariant()
    injector = $injectorPath
    topologies = $targetTopologies
    scenarios_run = $results.Count
    scenarios_failed = $failed.Count
    scenarios_inconclusive = $inconclusive.Count
    hard_gates = $spec.hard_gates
    status = $overall
    failures = $blocking
    results = $results
} | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath (Join-Path $out 'result.json') -Encoding UTF8

if ($overall -ne 'Passed') {
    throw "RAFT_MATRIX_$($overall.ToUpperInvariant()) scenarios=$($results.Count) failed=$($failed.Count) inconclusive=$($inconclusive.Count)`n$($blocking -join "`n")"
}
Write-Host "RAFT_MATRIX_PASS scenarios=$($results.Count) evidence=$out" -ForegroundColor Green
