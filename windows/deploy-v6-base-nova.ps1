# Deploy do HeraclitusDB novo (HRKL v6) com base LIMPA.
#
# CORRER ELEVADO (o SCM e as env de máquina exigem Administrador).
#
# O que faz, por ordem:
#   1. pára o serviço;
#   2. faz backup dos binários actuais;
#   3. RENOMEIA a base legada (não apaga — ver nota abaixo);
#   4. copia os binários novos;
#   5. arranca o serviço, que cria uma base HRKL v6 vazia;
#   6. verifica que subiu e que o formato é mesmo v6.
#
# ## Porque RENOMEIA em vez de apagar
#
# São 13,2 GB e a operação é irreversível. Renomear é instantâneo e deixa-te
# desfazer se algo correr mal no arranque; apagar não deixa. O script imprime
# no fim o comando exacto para a apagares quando estiveres satisfeito — um
# passo teu, deliberado, e não um efeito colateral de um deploy.
#
# ## As memórias do Claude
#
# Foram exportadas para D:\HeraclitusDB\claude_mem_backup_2026-08-25.jsonl
# (166 memórias, 8 projetos). Depois de o serviço subir, restaura-as com:
#
#   cd D:\DEV\scripts\hera_mem
#   python restore_memories.py D:\HeraclitusDB\claude_mem_backup_2026-08-25.jsonl
#
# Se falhar o arranque, o script faz rollback dos binários sozinho; a base
# antiga fica no diretório renomeado e volta com um Rename-Item.

$ErrorActionPreference = 'Stop'
$svc    = 'HeraclitusDB'
$bin    = 'D:\HeraclitusDB\bin'
$src    = 'D:\cargo-target\release'
$data   = 'D:\HeraclitusDB\data'
$stamp  = Get-Date -Format 'yyyyMMdd-HHmmss'
$dataOld = "$data.legacy-$stamp"
$log    = "D:\tmp\hera_deploy_v6_$stamp.log"

function Log($m) {
    $linha = "[$(Get-Date -Format HH:mm:ss)] $m"
    Write-Output $linha
    $linha | Out-File $log -Append -Encoding utf8
}

# Guarda-costas: sem os binários novos não se mexe em nada.
foreach ($exe in 'heraclitus-service.exe', 'heraclitus-server.exe', 'heraclitus.exe') {
    if (-not (Test-Path (Join-Path $src $exe))) {
        throw "binário em falta: $src\$exe — corre primeiro: cargo build --release -p heraclitus-server -p heraclitus-cli"
    }
}

Log "=== deploy HRKL v6, base nova ==="
Log "binários de: $src"

try {
    Log "a parar $svc"
    Stop-Service $svc -Force
    (Get-Service $svc).WaitForStatus('Stopped', '00:01:00')

    # --- backup dos binários (rollback) ---
    foreach ($exe in 'heraclitus-service.exe', 'heraclitus-server.exe', 'heraclitus.exe') {
        $alvo = Join-Path $bin $exe
        if (Test-Path $alvo) {
            Copy-Item $alvo "$alvo.bak-$stamp" -Force
            Log "backup: $exe -> $exe.bak-$stamp"
        }
    }

    # --- base legada de lado ---
    if (Test-Path $data) {
        $gb = [math]::Round(((Get-ChildItem $data -Recurse -File -ErrorAction SilentlyContinue |
                              Measure-Object -Property Length -Sum).Sum / 1GB), 2)
        Rename-Item $data $dataOld
        Log "base legada ($gb GB) renomeada -> $dataOld"
    }
    New-Item -ItemType Directory -Path $data -Force | Out-Null
    Log "base nova vazia: $data"

    # --- binários novos ---
    foreach ($exe in 'heraclitus-service.exe', 'heraclitus-server.exe', 'heraclitus.exe') {
        Copy-Item (Join-Path $src $exe) (Join-Path $bin $exe) -Force
        Log "copiado: $exe ($((Get-Item (Join-Path $bin $exe)).Length) bytes)"
    }

    Log "a arrancar $svc"
    Start-Service $svc
    (Get-Service $svc).WaitForStatus('Running', '00:01:00')

    # --- verificação: subiu E está em v6 ---
    Start-Sleep -Seconds 5
    $porta = $env:HERACLITUS_REST_ADDR
    if (-not $porta) { $porta = '127.0.0.1:7475' }
    $stats = Invoke-RestMethod "http://$porta/stats" -TimeoutSec 15
    Log "head=$($stats.head)  storage_format=$($stats.storage_format)"
    if ($stats.storage_format -ne 'v6') {
        throw "o serviço subiu em '$($stats.storage_format)' e não em v6"
    }
    if ($stats.head -ne 0) {
        Log "AVISO: head=$($stats.head) numa base que devia estar vazia"
    }

    Log "DEPLOY OK — HRKL v6, base vazia, serviço a correr"
    Write-Output ""
    Write-Output "Proximos dois passos, por esta ordem:"
    Write-Output ""
    Write-Output "  1. restaurar as 166 memorias:"
    Write-Output "       cd D:\DEV\scripts\hera_mem"
    Write-Output "       python restore_memories.py D:\HeraclitusDB\claude_mem_backup_2026-08-25.jsonl"
    Write-Output ""
    Write-Output "  2. quando estiveres satisfeito, apagar a base antiga (IRREVERSIVEL):"
    Write-Output "       Remove-Item -Recurse -Force '$dataOld'"
    Write-Output ""
    exit 0

} catch {
    Log ("ERRO: " + $_.Exception.Message)
    Log "ROLLBACK dos binarios"
    foreach ($exe in 'heraclitus-service.exe', 'heraclitus-server.exe', 'heraclitus.exe') {
        $bak = Join-Path $bin "$exe.bak-$stamp"
        if (Test-Path $bak) { Copy-Item $bak (Join-Path $bin $exe) -Force }
    }
    # A base antiga volta ao sítio, para o binário antigo a encontrar.
    if ((Test-Path $dataOld) -and (Test-Path $data)) {
        $vazia = -not (Get-ChildItem $data -Recurse -File -ErrorAction SilentlyContinue)
        if ($vazia) {
            Remove-Item $data -Recurse -Force
            Rename-Item $dataOld $data
            Log "base legada reposta em $data"
        } else {
            Log "AVISO: $data nao esta vazia; a base antiga fica em $dataOld"
        }
    }
    try {
        Start-Service $svc
        (Get-Service $svc).WaitForStatus('Running', '00:01:00')
        Log ("ROLLBACK concluido, status=" + (Get-Service $svc).Status)
    } catch {
        Log "NAO CONSEGUIU REARRANCAR — ver $log"
    }
    exit 1
}
