# reset-e-carga.ps1
# 1. Parar HeraclitusDB
# 2. Apagar dados do banco
# 3. Iniciar servidor usando binario pre-compilado
# 4. Executar o ingestor em Node.js com os dados do governo
# 5. Selar e verificar

$HeraDir  = "D:\DEV\HeraclitusDB"
$DataDir  = "D:\HeraclitusDB\data"
$DadosDir = "D:\dados-governo"

Set-Location $HeraDir
$ErrorActionPreference = "Stop"

Write-Host "--- HeraclitusDB RESET + CARGA ---"

# PASSO 1: Parar servidor
Write-Host "[1/7] Parando HeraclitusDB..."
$procs = Get-Process -Name "heraclitus-server","heraclitus" -ErrorAction SilentlyContinue
if ($procs) {
    $procs | Stop-Process -Force
    Start-Sleep -Seconds 2
    Write-Host "      Servidor parado"
}

# PASSO 2: Apagar dados e recriar pastas base
Write-Host "[2/7] Apagando dados..."
foreach ($subdir in @("log", "raw", "views", "receipts")) {
    $path = Join-Path $DataDir $subdir
    if (Test-Path $path) { Remove-Item -Recurse -Force $path }
    New-Item -ItemType Directory -Path $path -Force | Out-Null
}
foreach ($ckpt in @("$HeraDir\data\etl_flat_ckpt.json","$DataDir\etl_flat_ckpt.json")) {
    if (Test-Path $ckpt) { Remove-Item -Force $ckpt }
}
foreach ($p in @("$HeraDir\data\log","$HeraDir\data\views","$HeraDir\data\raw")) {
    if (Test-Path $p) { Remove-Item -Recurse -Force $p }
}

# PASSO 3: Validar binario
Write-Host "[3/7] Verificando binario..."
if (-not (Test-Path "target\release\heraclitus-server.exe")) {
    throw "heraclitus-server.exe nao encontrado"
}

# PASSO 4: Iniciar servidor
Write-Host "[4/7] Iniciando HeraclitusDB..."
$serverProc = Start-Process -FilePath "target\release\heraclitus-server.exe" -ArgumentList "--config config.local.toml" -WorkingDirectory $HeraDir -PassThru -WindowStyle Minimized
$tentativas = 0
do {
    Start-Sleep -Seconds 2
    $tentativas++
    try {
        $conn = New-Object System.Net.Sockets.TcpClient("127.0.0.1", 7474)
        $conn.Close()
        break
    } catch { }
} while ($tentativas -lt 15)

if ($tentativas -ge 15) { throw "Servidor nao respondeu" }

# PASSO 5: Executar ingestor Node
Write-Host "[5/7] Executando ingestor Node.js..."
Set-Location "tools"
node ingestor.js --server "127.0.0.1:7474" --dir "$DadosDir"
if ($LASTEXITCODE -ne 0) { throw "Ingestor Node falhou" }
Set-Location $HeraDir

# PASSO 6: Snapshot
Write-Host "[6/7] Snapshot REST..."
try {
    $resp = Invoke-RestMethod -Uri "http://127.0.0.1:7475/snapshot" -Method Post -TimeoutSec 10
} catch {
    Write-Host "Snapshot falhou, ignorando."
}

# PASSO 7: Verificar integridade
Write-Host "[7/7] Verificando log com o CLI..."
target\release\heraclitus.exe verify "$DataDir\log"

Write-Host "CARGA CONCLUIDA"
