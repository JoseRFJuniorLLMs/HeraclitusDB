# reset-e-carga.ps1 - RESET + ingestao de dados abertos do governo federal
#
# Pipeline 100% Rust (o ingestor Node.js legado deixou de ser usado):
#   1. cargo build --release (server, CLI, ingestor, edge-builder)
#   2. Parar o servico Windows HeraclitusDB + qualquer servidor solto
#   3. Backup + apagar log/views/raw/receipts do data-dir
#   4. Arrancar o servidor
#   5. ingestor      - carrega D:\dados-governo (nos: Servidor, Contrato, ...)
#   6. edge-builder  - entity resolution + arestas do grafo
#   7. Snapshot (sela o segmento activo)
#   8. heraclitus verify - prova de integridade do log
#
# AVISO: o passo 3 e IRREVERSIVEL (o log e append-only, nao ha undo). O default
# -DataDir D:\HeraclitusDB\data e o mesmo diretorio que o servico Windows usa.
# O script copia o log actual para backups\pre-carga-<timestamp> antes de
# apagar - barata (segmentos pequenos) e a unica rede de seguranca que existe.
#
# NOTA DE CODIFICACAO: este ficheiro e deliberadamente ASCII puro. O PowerShell
# 5.1 le .ps1 sem BOM como ANSI, e um travessao ou acento em UTF-8 vira bytes
# que o parser interpreta como aspas - o script anterior morria com
# "The string is missing the terminator" antes de executar uma unica linha.

[CmdletBinding()]
param(
    [string] $DataDir = "D:\HeraclitusDB\data",
    [int]    $GrpcPort = 7474,
    [int]    $RestPort = 7475,
    [string] $DadosDir = "D:\dados-governo",
    [int]    $Batch = 8000,
    # Ficheiro com o bearer token RBAC. Sem ele, um servidor com credenciais
    # configuradas recusa TODOS os appends ("missing or invalid bearer token")
    # e a carga morre no primeiro evento.
    [string] $TokenFile = "D:\HeraclitusDB\secrets-v1\writer.token",
    # Appends concorrentes. O gargalo do caminho gRPC e LATENCIA (cada append
    # espera a sua janela de fsync), nao saturacao - por isso o debito escala
    # quase linearmente com este numero. Medido a 2026-08-19 sobre esta carga:
    #     1 -> 86 ev/s (28 h) | 16 -> 274 (9 h) | 64 -> 748 (3.3 h) | 256 -> 1760 (1.4 h)
    [int]    $InFlight = 256,
    # Numero de repeticoes/passadas da carga para multiplicar o volume de dados acumulado na base
    [int]    $Repeticoes = 1,
    # Meta em GB para acumulação de dados no banco (ex: -AlvoGB 20)
    [int]    $AlvoGB = 0,
    [switch] $SkipBuild,
    [switch] $SkipEdges,
    [switch] $DryRun,
    [switch] $SemBackup,
    # Nao para o servico, nao apaga nada, nao arranca servidor: carrega POR CIMA
    # do que ja esta no servidor em execucao. E o modo que funciona sem
    # privilegios de administrador (parar o servico Windows exige elevacao).
    # O log e append-only, portanto acrescentar dados e a operacao natural -
    # o que este modo NAO faz e comecar do zero.
    [switch] $SemReset
)

$ErrorActionPreference = "Stop"
$HeraDir = "D:\DEV\HeraclitusDB"
Set-Location $HeraDir

function Esperar-Porta {
    param([int] $Porta, [int] $Tentativas = 30)
    for ($i = 0; $i -lt $Tentativas; $i++) {
        try {
            $c = New-Object System.Net.Sockets.TcpClient("127.0.0.1", $Porta)
            $c.Close(); return $true
        } catch { Start-Sleep -Seconds 2 }
    }
    return $false
}

Write-Host ""
Write-Host "=== HeraclitusDB - RESET + CARGA DE DADOS GOVERNAMENTAIS ===" -ForegroundColor Cyan
Write-Host "  data-dir : $DataDir"
Write-Host "  gRPC     : 127.0.0.1:$GrpcPort   REST: 127.0.0.1:$RestPort"
Write-Host "  dados    : $DadosDir"
if ($DryRun) { Write-Host "  MODO DRY-RUN - nada e apagado nem gravado" -ForegroundColor Yellow }
Write-Host ""

if (-not (Test-Path $DadosDir)) { throw "Diretorio de dados nao encontrado: $DadosDir" }

# --- 1. BUILD --------------------------------------------------------------
if (-not $SkipBuild) {
    Write-Host "[1/8] Compilando (release)..." -ForegroundColor Green
    cargo build --release -p heraclitus-server -p heraclitus-cli -p heraclitus-ingestor
    if ($LASTEXITCODE -ne 0) { throw "cargo build falhou" }
} else {
    Write-Host "[1/8] Build saltado (-SkipBuild)" -ForegroundColor DarkGray
}

# Os binarios vao para $env:CARGO_TARGET_DIR quando essa variavel existe - o
# caminho fixo 'target\release' dava "binario nao encontrado" nesta maquina.
$TargetDir = if ($env:CARGO_TARGET_DIR) { $env:CARGO_TARGET_DIR } else { Join-Path $HeraDir "target" }
$BinServer = Join-Path $TargetDir "release\heraclitus-server.exe"
$BinCli    = Join-Path $TargetDir "release\heraclitus.exe"
$BinIngest = Join-Path $TargetDir "release\ingestor.exe"
$BinEdges  = Join-Path $TargetDir "release\edge-builder.exe"
foreach ($b in @($BinServer, $BinCli, $BinIngest, $BinEdges)) {
    if (-not (Test-Path $b)) { throw "Binario nao encontrado: $b (corra sem -SkipBuild)" }
}

# --- 2. PARAR TUDO O QUE SEGURA O DATA-DIR ---------------------------------
# O servico Windows mantem os segmentos abertos: sem o parar, o Remove-Item do
# passo 3 falha com "ficheiro em uso" e o servidor novo colidiria na porta.
if ($SemReset) {
    Write-Host "[2/8] -SemReset: servico e dados intactos, carga por cima" -ForegroundColor DarkGray
} else {
    Write-Host "[2/8] Parando servico e servidores..." -ForegroundColor Green
    $svc = Get-Service -Name "HeraclitusDB" -ErrorAction SilentlyContinue
    if ($svc -and $svc.Status -eq "Running") {
        Write-Host "      parando servico Windows HeraclitusDB"
        try {
            Stop-Service -Name "HeraclitusDB" -Force -ErrorAction Stop
            (Get-Service -Name "HeraclitusDB").WaitForStatus("Stopped", [TimeSpan]::FromSeconds(30))
        } catch {
            # Parar um servico exige elevacao. Sem ela, apagar o data-dir vai
            # falhar de qualquer forma (o servico mantem os segmentos abertos),
            # por isso e melhor dizer o que fazer do que rebentar 40 linhas
            # depois com "ficheiro em uso".
            throw @"
Nao foi possivel parar o servico HeraclitusDB: $($_.Exception.Message)

Parar um servico Windows exige PowerShell ELEVADO. Escolha uma:
  a) Numa consola como Administrador:  Stop-Service HeraclitusDB
     e depois volte a correr este script.
  b) Carregue SEM reset (o log e append-only, os dados novos juntam-se
     aos que la estao):
        .\reset-e-carga.ps1 -SkipBuild -SemReset
"@
        }
    }
    Get-Process -Name "heraclitus-server", "heraclitus-service", "heraclitus" -ErrorAction SilentlyContinue |
        ForEach-Object { Write-Host "      parando PID $($_.Id) ($($_.Name))"; Stop-Process -Id $_.Id -Force }
    Start-Sleep -Seconds 3
}

# --- 3. BACKUP + RESET -----------------------------------------------------
if ($DryRun -or $SemReset) {
    Write-Host "[3/8] Data-dir intacto (dry-run ou -SemReset)" -ForegroundColor DarkGray
} else {
    if (-not $SemBackup -and (Test-Path (Join-Path $DataDir "log"))) {
        $stamp = Get-Date -Format "yyyyMMdd-HHmmss"
        $bkp   = Join-Path "D:\HeraclitusDB\backups" "pre-carga-$stamp"
        Write-Host "[3/8] Backup do log actual -> $bkp" -ForegroundColor Yellow
        New-Item -ItemType Directory -Path $bkp -Force | Out-Null
        Copy-Item -Recurse -Force (Join-Path $DataDir "log") $bkp
        if (Test-Path (Join-Path $DataDir "keys")) {
            Copy-Item -Recurse -Force (Join-Path $DataDir "keys") $bkp
        }
    }
    Write-Host "[3/8] Apagando dados..." -ForegroundColor Yellow
    foreach ($sub in @("log", "raw", "views", "receipts", "attr")) {
        $p = Join-Path $DataDir $sub
        if (Test-Path $p) { Remove-Item -Recurse -Force $p }
        New-Item -ItemType Directory -Path $p -Force | Out-Null
    }
    foreach ($ckpt in @("$HeraDir\data\etl_flat_ckpt.json", "$DataDir\etl_flat_ckpt.json")) {
        if (Test-Path $ckpt) { Remove-Item -Force $ckpt }
    }
}

# --- 4. CONFIG + ARRANQUE --------------------------------------------------
# Config propria da carga. SEM auth_token: o `ingestor` liga com
# Client::connect sem credenciais (nao tem flag de token), por isso um token no
# config faria TODOS os appends devolverem Unauthenticated. Bind em loopback.
# Sem cifra em repouso: sao dados publicos, e cifrar custa escrita sem ganho.
$CfgPath = Join-Path $HeraDir "config.carga.toml"
$dataDirToml = $DataDir -replace '\\', '/'
@"
# GERADO POR reset-e-carga.ps1 - perfil de CARGA (dados governamentais).
data_dir  = "$dataDirToml"
grpc_addr = "127.0.0.1:$GrpcPort"
rest_addr = "127.0.0.1:$RestPort"

# 8 MiB: recomendacao medida em docs/md/auditorias/append-lento-com-o-crescimento.md
# (a 256 MiB o append degrada ~60x no volume alvo).
segment_max_bytes = 8388608
fsync = { mode = "group_commit", interval_ms = 50 }

encryption_at_rest = false
checkpoint_interval_secs = 300
"@ | Set-Content -Encoding ascii $CfgPath

if ($DryRun -or $SemReset) {
    Write-Host "[4/8] Servidor ja em execucao (dry-run ou -SemReset)" -ForegroundColor DarkGray
    if ($SemReset -and -not (Esperar-Porta -Porta $GrpcPort -Tentativas 3)) {
        throw "Nada a responder em 127.0.0.1:$GrpcPort - com -SemReset o servidor tem de estar ja a correr"
    }
} else {
    Write-Host "[4/8] Arrancando servidor..." -ForegroundColor Green
    $logOut = Join-Path $HeraDir "carga-server.out.log"
    $logErr = Join-Path $HeraDir "carga-server.err.log"
    Start-Process -FilePath $BinServer -ArgumentList "`"$CfgPath`"" `
        -WorkingDirectory $HeraDir -WindowStyle Minimized `
        -RedirectStandardOutput $logOut -RedirectStandardError $logErr | Out-Null
    if (-not (Esperar-Porta -Porta $GrpcPort)) {
        Write-Host "--- carga-server.err.log ---" -ForegroundColor Red
        if (Test-Path $logErr) { Get-Content $logErr -Tail 40 }
        throw "Servidor nao respondeu em 127.0.0.1:$GrpcPort"
    }
    Write-Host "      servidor a responder em 127.0.0.1:$GrpcPort" -ForegroundColor Green
}

$Servidor = "http://127.0.0.1:$GrpcPort"
$tInicio = Get-Date

# --- 5. INGESTOR (nos) -----------------------------------------------------
Write-Host "[5/8] Ingestor Rust - carregando nos ($InFlight appends em voo | $Repeticoes repeticoes)..." -ForegroundColor Green
$env:HERACLITUS_INGEST_INFLIGHT = "$InFlight"
$argsIngest = @("--server", $Servidor, "--dir", $DadosDir, "--batch", "$Batch")
if (Test-Path $TokenFile) {
    $argsIngest += @("--token-file", $TokenFile)
} else {
    Write-Host "      aviso: $TokenFile nao existe - a tentar sem auth" -ForegroundColor Yellow
}
if ($DryRun) { $argsIngest += "--dry-run" }

if ($AlvoGB -gt 0) {
    Write-Host "      --> MODO META EM VOLUME ATIVO: Alvo de $AlvoGB GB..." -ForegroundColor Yellow
    $AlvoBytes = [int64]$AlvoGB * 1GB
    $passada = 1
    while ($true) {
        $logPath = Join-Path $DataDir "log"
        $tamanhoAtual = 0
        if (Test-Path $logPath) {
            $tamanhoAtual = (Get-ChildItem -Path $logPath -Recurse -File -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum
        }
        $tamanhoGB = [math]::Round($tamanhoAtual / 1GB, 2)
        Write-Host "      --> Passada ${passada}: Tamanho atual do log em disco = $tamanhoGB GB / $AlvoGB GB..." -ForegroundColor Cyan
        if ($tamanhoAtual -ge $AlvoBytes) {
            Write-Host "      ✅ Meta de $AlvoGB GB atingida! ($tamanhoGB GB acumulados)" -ForegroundColor Green
            break
        }
        & $BinIngest @argsIngest
        if ($LASTEXITCODE -ne 0) { throw "ingestor falhou na passada $passada com exit $LASTEXITCODE" }
        $passada++
    }
} else {
    for ($r = 1; $r -le $Repeticoes; $r++) {
        Write-Host "      --> Iniciando repeticao $r de $Repeticoes..." -ForegroundColor Cyan
        & $BinIngest @argsIngest
        if ($LASTEXITCODE -ne 0) { throw "ingestor falhou na repeticao $r com exit $LASTEXITCODE" }
    }
}

# --- 6. EDGE-BUILDER (arestas + entity resolution) -------------------------
if ($SkipEdges) {
    Write-Host "[6/8] Arestas saltadas (-SkipEdges)" -ForegroundColor DarkGray
} else {
    Write-Host "[6/8] Edge-builder Rust - arestas e entity resolution..." -ForegroundColor Green
    $argsEdges = @("--server", $Servidor)
    if (Test-Path $TokenFile) { $argsEdges += @("--token-file", $TokenFile) }
    if ($DryRun) { $argsEdges += "--dry-run" }
    & $BinEdges @argsEdges
    if ($LASTEXITCODE -ne 0) { throw "edge-builder falhou com exit $LASTEXITCODE" }
}

# --- 7. SNAPSHOT -----------------------------------------------------------
if (-not $DryRun) {
    Write-Host "[7/8] Snapshot (sela o segmento activo)..." -ForegroundColor Green
    try {
        $r = Invoke-RestMethod -Uri "http://127.0.0.1:$RestPort/snapshot" -Method Post -TimeoutSec 60
        Write-Host "      snapshot em LSN $($r.lsn)"
    } catch {
        Write-Host "      snapshot falhou: $_" -ForegroundColor Yellow
    }
} else {
    Write-Host "[7/8] DRY-RUN: sem snapshot" -ForegroundColor DarkGray
}

# --- 8. VERIFICACAO DE INTEGRIDADE -----------------------------------------
if (-not $DryRun) {
    Write-Host "[8/8] Verificando integridade do log..." -ForegroundColor Green
    & $BinCli verify (Join-Path $DataDir "log")
    if ($LASTEXITCODE -ne 0) { throw "VERIFY FALHOU - integridade comprometida" }

    try {
        $stats = Invoke-RestMethod -Uri "http://127.0.0.1:$RestPort/stats" -Method Get -TimeoutSec 60
        Write-Host ""
        Write-Host "=== ESTADO FINAL ===" -ForegroundColor Cyan
        $stats | ConvertTo-Json -Depth 4
    } catch {
        Write-Host "      /stats indisponivel: $_" -ForegroundColor Yellow
    }
} else {
    Write-Host "[8/8] DRY-RUN: sem verify" -ForegroundColor DarkGray
}

$dur = (Get-Date) - $tInicio
Write-Host ""
Write-Host ("CARGA CONCLUIDA em {0:hh\:mm\:ss}" -f $dur) -ForegroundColor Cyan
Write-Host "  gRPC : $Servidor"
Write-Host "  REST : http://127.0.0.1:$RestPort"
Write-Host "  dados: $DataDir"
Write-Host ""
Write-Host "  Para devolver o diretorio ao servico Windows: Start-Service HeraclitusDB" -ForegroundColor DarkGray
Write-Host "  (pare antes o servidor de carga, senao a porta $GrpcPort fica ocupada)" -ForegroundColor DarkGray
Write-Host ""
