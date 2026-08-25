# Deploy do HeraclitusDB novo (HRKL v6) com base LIMPA.
#
# CORRER ELEVADO (o SCM exige Administrador).
#
# APAGA a base antiga. Nao a arquiva, nao a renomeia para sempre: apaga.
#
# ## A ordem das operacoes
#
#   1. para o servico
#   2. backup dos binarios (para rollback)
#   3. renomeia a base antiga        <- instantaneo
#   4. cria base vazia + copia binarios novos
#   5. arranca e VERIFICA que subiu em v6
#   6. APAGA a base antiga           <- so depois de o servico estar de pe
#
# O passo 3 e o 6 estao separados de proposito, e nao por timidez: apagar
# 15 GB leva perto de um minuto, e faze-lo entre o stop e o start punha esse
# minuto todo em downtime. Renomear e instantaneo, o servico volta em segundos,
# e a remocao corre com o banco ja a servir. O estado final e exactamente o
# mesmo — a base antiga desaparece nesta mesma execucao, sem passo manual.
#
# O efeito util de os separar: se o passo 5 falhar, a base antiga ainda existe
# e o script repoe-a junto com os binarios. Depois de o passo 5 passar, ja nao
# ha nada para reverter e a base vai-se embora.
#
# ## As memorias do Claude
#
# 167 memorias (8 projectos) foram exportadas para
# D:\HeraclitusDB\claude_mem_backup_2026-08-25.jsonl. Depois do deploy:
#
#   cd D:\DEV\scripts\hera_mem
#   python restore_memories.py D:\HeraclitusDB\claude_mem_backup_2026-08-25.jsonl

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

# Guarda-costas: sem os binarios novos nao se mexe em nada.
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
    Log "a parar $svc"
    Stop-Service $svc -Force
    (Get-Service $svc).WaitForStatus('Stopped', '00:01:00')

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
    (Get-Service $svc).WaitForStatus('Running', '00:01:00')

    # Verificar o FORMATO, nao so o estado do SCM. Um deploy que confirma que o
    # servico subiu mas nao em que formato passaria por bom um arranque errado.
    Start-Sleep -Seconds 5
    $porta = $env:HERACLITUS_REST_ADDR
    if (-not $porta) { $porta = '127.0.0.1:7475' }
    $stats = Invoke-RestMethod "http://$porta/stats" -TimeoutSec 15
    Log "head=$($stats.head)  storage_format=$($stats.storage_format)"
    if ($stats.storage_format -ne 'v6') {
        throw "o servico subiu em '$($stats.storage_format)' e nao em v6"
    }

    # --- ponto sem retorno: o servico esta de pe, a base antiga e lixo ---
    Log "a apagar a base antiga ($gb GB); pode demorar"
    Remove-Item $dataOld -Recurse -Force
    Log "base antiga APAGADA"

    $livre = [math]::Round((Get-PSDrive D).Free / 1GB, 1)
    Log "DEPLOY OK -- HRKL v6, base vazia, servico a correr. Livre em D: $livre GB"
    Write-Output ""
    Write-Output "Falta so restaurar as memorias:"
    Write-Output "  cd D:\DEV\scripts\hera_mem"
    Write-Output "  python restore_memories.py D:\HeraclitusDB\claude_mem_backup_2026-08-25.jsonl"
    Write-Output ""
    exit 0

} catch {
    Log ("ERRO: " + $_.Exception.Message)
    Log "ROLLBACK"
    foreach ($exe in $exes) {
        $bak = Join-Path $bin "$exe.bak-$stamp"
        if (Test-Path $bak) { Copy-Item $bak (Join-Path $bin $exe) -Force }
    }
    # A base antiga so e apagada DEPOIS do arranque verificado, portanto se
    # chegamos aqui ela ainda existe e volta ao sitio.
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
    try {
        Start-Service $svc
        (Get-Service $svc).WaitForStatus('Running', '00:01:00')
        Log ("ROLLBACK concluido, status=" + (Get-Service $svc).Status)
    } catch {
        Log "NAO CONSEGUIU REARRANCAR -- ver $log"
    }
    exit 1
}
