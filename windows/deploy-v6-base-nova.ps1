# Deploy do HeraclitusDB novo (HRKL v6) com base LIMPA.
#
# CORRER ELEVADO (o SCM exige Administrador).
#
# APAGA a base antiga. Nao a arquiva, nao a renomeia para sempre: apaga.
#
# ## A ordem das operacoes
#
#   1. para o servico e ESPERA pela paragem a serio
#   2. backup dos binarios (para rollback)
#   3. renomeia a base antiga        <- instantaneo
#   4. cria base vazia + copia binarios novos
#   5. arranca e VERIFICA que subiu, que ficou de pe, e que e v6
#   6. APAGA a base antiga           <- so depois de o passo 5 passar
#
# O passo 3 e o 6 estao separados de proposito: apagar 15 GB entre o stop e o
# start punha esse tempo todo em downtime. Renomear e instantaneo, o servico
# volta em segundos, e a remocao corre com o banco ja a servir. O estado final
# e o mesmo — a base antiga desaparece nesta mesma execucao.
#
# Efeito util de os separar: se o passo 5 falhar, a base antiga ainda existe e
# o rollback repoe-a.
#
# ## Duas licoes de um deploy que correu mal (2026-08-25)
#
# Este script derrubou o servico e nao deu por isso. As duas causas, e o que
# mudou:
#
# 1. `Stop-Service -Force` DESISTIU ao fim de ~3 s. Com 10 milhoes de
#    registos, fechar as views e fazer flush demora bem mais. O erro caiu no
#    catch, o rollback correu, e a paragem completou-se DEPOIS — deixando o
#    servico em baixo com o script a reportar sucesso.
#    => Agora o stop e assincrono e esperamos pelo estado `Stopped` a serio,
#       com um teto generoso (`-StopTimeout`, default 300 s).
#
# 2. O rollback leu `(Get-Service $svc).Status` e viu `Running` quando o SCM
#    ja dizia `STOPPED`. O objecto do `Get-Service` guarda o estado do momento
#    em que foi criado; se nao se lhe chamar `.Refresh()`, mente.
#    => Agora todo o estado vem de `Get-CimInstance Win32_Service`, que
#       reinterroga o SCM em cada leitura, e o arranque so e dado por bom
#       depois de o endpoint HTTP responder E o servico continuar de pe.
#
# ## As memorias do Claude
#
# Exporta-as ANTES (o script nao o faz por ti; a base vai desaparecer):
#   cd D:\DEV\scripts\hera_mem
#   python restore_memories.py <backup.jsonl>    # depois do deploy

[CmdletBinding()]
param(
    # Quanto esperar pela paragem. Cresce com o tamanho da base: sao as views
    # e o flush que demoram, nao o SCM.
    [int]$StopTimeout = 300,
    [int]$StartTimeout = 120
)

$ErrorActionPreference = 'Stop'
$svc     = 'HeraclitusDB'
$bin     = 'D:\HeraclitusDB\bin'
$src     = 'D:\cargo-target\release'
$data    = 'D:\HeraclitusDB\data'
$stamp   = Get-Date -Format 'yyyyMMdd-HHmmss'
$dataOld = "$data.apagar-$stamp"
$log     = "D:\tmp\hera_deploy_v6_$stamp.log"
$exes    = @('heraclitus-service.exe', 'heraclitus-server.exe', 'heraclitus.exe')

function Log($m) {
    $linha = "[$(Get-Date -Format HH:mm:ss)] $m"
    Write-Output $linha
    $linha | Out-File $log -Append -Encoding utf8
}

# Estado do SCM, reinterrogado. NUNCA usar um objecto de `Get-Service` guardado:
# ele congela o estado do momento em que foi criado.
function Estado {
    (Get-CimInstance Win32_Service -Filter "Name='$svc'").State
}

# Espera por um estado terminal, sondando o SCM. Devolve $true/$false em vez de
# lancar, para quem chama decidir.
function Esperar($alvo, $segundos) {
    $fim = (Get-Date).AddSeconds($segundos)
    while ((Get-Date) -lt $fim) {
        $e = Estado
        if ($e -eq $alvo) { return $true }
        Start-Sleep -Milliseconds 500
    }
    return $false
}

# Um arranque so conta quando o banco RESPONDE e CONTINUA de pe. Confirmar so
# o estado do SCM aceitaria um processo que sobe e morre a seguir — que foi
# exactamente o modo de falha que este script teve.
function Arranque-Confirmado {
    $porta = $env:HERACLITUS_REST_ADDR
    if (-not $porta) { $porta = '127.0.0.1:7475' }
    $fim = (Get-Date).AddSeconds(30)
    $stats = $null
    while ((Get-Date) -lt $fim) {
        try {
            $stats = Invoke-RestMethod "http://$porta/stats" -TimeoutSec 5
            break
        } catch {
            Start-Sleep -Seconds 2
        }
    }
    if (-not $stats) { return $null }
    # Ainda de pe cinco segundos depois? (apanha o sobe-e-morre)
    Start-Sleep -Seconds 5
    if ((Estado) -ne 'Running') { return $null }
    return $stats
}

foreach ($exe in $exes) {
    if (-not (Test-Path (Join-Path $src $exe))) {
        throw "binario em falta: $src\$exe -- corre primeiro: cargo build --release -p heraclitus-server -p heraclitus-cli"
    }
}

Log "=== deploy HRKL v6, base nova ==="
$gb = [math]::Round(((Get-ChildItem $data -Recurse -File -ErrorAction SilentlyContinue |
                      Measure-Object -Property Length -Sum).Sum / 1GB), 2)
Log "base antiga: $gb GB (vai ser APAGADA)"

try {
    Log "a parar $svc (ate $StopTimeout s)"
    # `-NoWait`: o cmdlet nao impoe o seu proprio teto curto; a espera e nossa.
    Stop-Service $svc -Force -NoWait -ErrorAction SilentlyContinue
    if (-not (Esperar 'Stopped' $StopTimeout)) {
        throw "o servico nao parou em $StopTimeout s (estado: $(Estado)). Aumenta -StopTimeout ou investiga o processo."
    }
    Log "parado"

    foreach ($exe in $exes) {
        $alvo = Join-Path $bin $exe
        if (Test-Path $alvo) {
            Copy-Item $alvo "$alvo.bak-$stamp" -Force
            Log "backup: $exe"
        }
    }

    if (Test-Path $data) {
        Rename-Item $data $dataOld
        Log "base antiga de lado: $dataOld"
    }
    New-Item -ItemType Directory -Path $data -Force | Out-Null

    foreach ($exe in $exes) {
        Copy-Item (Join-Path $src $exe) (Join-Path $bin $exe) -Force
        Log "copiado: $exe ($((Get-Item (Join-Path $bin $exe)).Length) bytes)"
    }

    Log "a arrancar $svc"
    Start-Service $svc
    if (-not (Esperar 'Running' $StartTimeout)) {
        throw "o servico nao arrancou em $StartTimeout s (estado: $(Estado))"
    }
    $stats = Arranque-Confirmado
    if (-not $stats) {
        throw "o servico arrancou mas nao confirmou: sem resposta HTTP, ou caiu logo a seguir"
    }
    Log "head=$($stats.head)  storage_format=$($stats.storage_format)"
    if ($stats.storage_format -ne 'v6') {
        throw "o servico subiu em '$($stats.storage_format)' e nao em v6"
    }

    # --- ponto sem retorno: confirmado de pe e em v6 ---
    Log "a apagar a base antiga ($gb GB)"
    $t0 = Get-Date
    Remove-Item $dataOld -Recurse -Force
    Log "base antiga APAGADA em $([math]::Round(((Get-Date)-$t0).TotalSeconds,1))s"

    Log "DEPLOY OK -- HRKL v6, base vazia. Livre em D: $([math]::Round((Get-PSDrive D).Free/1GB,1)) GB"
    Write-Output ""
    Write-Output "Falta restaurar as memorias:"
    Write-Output "  cd D:\DEV\scripts\hera_mem"
    Write-Output "  python restore_memories.py <backup.jsonl>"
    Write-Output ""
    exit 0

} catch {
    Log ("ERRO: " + $_.Exception.Message)
    Log "ROLLBACK"

    # Antes de tocar em nada, esperar que o SCM assente. Arrancar sobre um
    # STOP_PENDING foi o que deixou o servico em baixo da ultima vez.
    $e = Estado
    if ($e -eq 'Stop Pending' -or $e -eq 'Start Pending') {
        Log "SCM em '$e'; a aguardar que assente"
        $null = Esperar 'Stopped' 120
        Log "estado agora: $(Estado)"
    }

    foreach ($exe in $exes) {
        $bak = Join-Path $bin "$exe.bak-$stamp"
        if (Test-Path $bak) { Copy-Item $bak (Join-Path $bin $exe) -Force }
    }
    # A base antiga so e apagada depois do arranque confirmado; se chegamos
    # aqui, ela ainda existe.
    if ((Test-Path $dataOld) -and (Test-Path $data)) {
        $vazia = -not (Get-ChildItem $data -Recurse -File -ErrorAction SilentlyContinue)
        if ($vazia) {
            Remove-Item $data -Recurse -Force
            Rename-Item $dataOld $data
            Log "base antiga reposta"
        } else {
            Log "AVISO: $data nao esta vazia; a base antiga ficou em $dataOld"
        }
    }

    if ((Estado) -ne 'Running') {
        try {
            Start-Service $svc
            $null = Esperar 'Running' $StartTimeout
        } catch {
            Log "Start-Service falhou: $($_.Exception.Message)"
        }
    }
    # Reportar o que o SCM diz AGORA, nao um estado guardado.
    $final = Estado
    Log "ROLLBACK terminado, estado=$final"
    if ($final -ne 'Running') {
        Log "!!! O SERVICO FICOU EM BAIXO. Arranca-o a mao: Start-Service $svc"
    }
    exit 1
}
