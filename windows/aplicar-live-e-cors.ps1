# Aplica ao servico HeraclitusDB o binario novo (/live/events + CORS) e a
# variavel de ambiente que autoriza o painel forense.
#
# PRECISA DE ELEVACAO: escrever variaveis de maquina e parar/arrancar um
# servico exigem administrador. Correr numa consola "Executar como
# administrador".
#
# E reversivel: o binario antigo fica guardado com data e hora, e o script
# repoe-o sozinho se o servico nao subir.
#
# Ficheiro em ASCII puro e sem BOM-dependencia por uma razao aprendida a
# custo: um .ps1 gravado em UTF-8 sem BOM da erro de parse, sai com codigo 1 e
# sem mensagem nenhuma — o que se parece exatamente com uma recusa de UAC.

$ErrorActionPreference = 'Stop'

$servico = 'HeraclitusDB'
$destino = 'D:\HeraclitusDB\bin\heraclitus-service.exe'
$origem  = 'D:\cargo-target\release\heraclitus-service.exe'
$origens = 'http://localhost:9337,http://127.0.0.1:9337'

function Passo($t) { Write-Host "`n== $t" -ForegroundColor Cyan }

# --- 0. Verificacoes antes de mexer em nada -------------------------------
Passo '0. Verificacoes'
$id = [Security.Principal.WindowsIdentity]::GetCurrent()
$p  = New-Object Security.Principal.WindowsPrincipal($id)
if (-not $p.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) {
  Write-Host 'ERRO: sem elevacao. Abrir a consola como administrador.' -ForegroundColor Red
  exit 1
}
if (-not (Test-Path $origem)) {
  Write-Host "ERRO: binario novo nao existe em $origem" -ForegroundColor Red
  Write-Host 'Correr primeiro: cargo build --release -p heraclitus-server' -ForegroundColor Yellow
  exit 1
}
"  binario novo : {0:N0} bytes  {1}" -f (Get-Item $origem).Length, (Get-Item $origem).LastWriteTime
"  instalado    : {0:N0} bytes  {1}" -f (Get-Item $destino).Length, (Get-Item $destino).LastWriteTime

# --- 1. Autorizar a origem do painel --------------------------------------
Passo '1. CORS'
[Environment]::SetEnvironmentVariable('HERACLITUS_REST_CORS_ORIGINS', $origens, 'Machine')
"  HERACLITUS_REST_CORS_ORIGINS = $origens"
Write-Host '  (lista explicita; o servidor RECUSA `*` nesta superficie, por ter rotas de escrita)' -ForegroundColor DarkGray

# --- 2. Parar, guardar, trocar --------------------------------------------
Passo '2. Trocar o binario'
$copia = "$destino.bak-$(Get-Date -Format yyyyMMdd-HHmmss)"
Copy-Item $destino $copia -Force
"  copia de seguranca: $copia"

Stop-Service $servico -Force
(Get-Service $servico).WaitForStatus('Stopped', '00:00:30')
'  servico parado'

Copy-Item $origem $destino -Force
'  binario substituido'

# --- 3. Arrancar e verificar ----------------------------------------------
Passo '3. Arrancar'
try {
  Start-Service $servico
  (Get-Service $servico).WaitForStatus('Running', '00:00:30')
  Start-Sleep -Seconds 3
  $saude = Invoke-RestMethod 'http://127.0.0.1:7475/healthz' -TimeoutSec 8
  "  healthz: $saude"
} catch {
  Write-Host "  FALHOU: $($_.Exception.Message)" -ForegroundColor Red
  Write-Host '  A repor o binario anterior...' -ForegroundColor Yellow
  try { Stop-Service $servico -Force -ErrorAction SilentlyContinue } catch {}
  Copy-Item $copia $destino -Force
  Start-Service $servico
  Write-Host '  Reposto. O servico voltou a versao anterior.' -ForegroundColor Yellow
  exit 1
}

# --- 4. Provar que o que se queria ficou la -------------------------------
Passo '4. Verificacao'
$stats = Invoke-RestMethod 'http://127.0.0.1:7475/stats' -TimeoutSec 8
"  registos no log: $($stats.head)"

$verify = Invoke-RestMethod 'http://127.0.0.1:7475/verify' -TimeoutSec 120
if ($null -ne $verify.sealed) {
  "  /verify: contrato NOVO ok (segments=$($verify.segments) sealed=$($verify.sealed) merkle_ok=$($verify.merkle_ok))"
} else {
  Write-Host '  /verify ainda sem o campo `sealed` — binario antigo?' -ForegroundColor Yellow
}

$live = (Invoke-WebRequest 'http://127.0.0.1:7475/live/events' -TimeoutSec 5 -UseBasicParsing).StatusCode
"  /live/events: HTTP $live  (200 = ativo)"

$cors = (Invoke-WebRequest 'http://127.0.0.1:7475/stats' -Headers @{Origin='http://localhost:9337'} -TimeoutSec 8 -UseBasicParsing).Headers['Access-Control-Allow-Origin']
if ($cors) { "  CORS: $cors" } else { Write-Host '  CORS ausente — a variavel so e lida no ARRANQUE do servico; reiniciar de novo.' -ForegroundColor Yellow }

Write-Host "`nFeito. Painel em http://localhost:9337 apontado a http://127.0.0.1:7475" -ForegroundColor Green
Write-Host "Reverter: Copy-Item '$copia' '$destino' -Force ; Restart-Service $servico" -ForegroundColor DarkGray
