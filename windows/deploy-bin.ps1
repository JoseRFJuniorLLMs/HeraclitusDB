# Troca o binario do servico HeraclitusDB pelo que esta em D:\cargo-target,
# e mais nada. Nao apaga a base, nao mexe em variaveis de ambiente, nao muda
# configuracao.
#
# PRECISA DE ELEVACAO: parar e arrancar um servico exige administrador.
# Correr numa consola "Executar como administrador".
#
# Substituiu quatro scripts que faziam ou de menos ou de mais, apagados em
# 2026-08-30 (recuperaveis do git, se alguma vez fizerem falta):
#
#   deploy.ps1            compilava com a toolchain GNU (nao ha gcc nesta
#                         maquina) e assumia que o servico corre do target do
#                         cargo — corre de D:\HeraclitusDB\bin.
#   deploy-msvc.ps1       copiava para <repo>\target\release, que nao e o
#                         destino do cargo (CARGO_TARGET_DIR=D:\cargo-target)
#                         nem de onde o servico arranca: trocava um ficheiro
#                         que ninguem executa.
#   aplicar-live-e-cors   trocava o binario CERTO, mas tambem escrevia
#                         HERACLITUS_REST_CORS_ORIGINS na maquina — efeito
#                         lateral de uma tarefa de 2026-08-18.
#   deploy-v6-base-nova   trocava o binario e APAGAVA A BASE.
#
# Os que ficaram tem dono e referencias: heraclitus-{service,production,
# backup}.ps1 sao usados pelo CI, pelos runbooks e pelo bundle offline, e o
# deploy-local-homologation.ps1 e outra coisa (homologacao, nao producao).
#
# E reversivel: o binario antigo fica guardado com data e hora, e o script
# repoe-o sozinho se o servico nao subir.

$ErrorActionPreference = 'Stop'
$servico = 'HeraclitusDB'
$destino = 'D:\HeraclitusDB\bin\heraclitus-service.exe'
$origem  = 'D:\cargo-target\release\heraclitus-service.exe'

function Passo($t) { Write-Host "`n== $t ==" -ForegroundColor Cyan }

Passo '0. Verificacoes'
$id = [Security.Principal.WindowsIdentity]::GetCurrent()
$p  = New-Object Security.Principal.WindowsPrincipal($id)
if (-not $p.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) {
  Write-Host 'ERRO: sem elevacao. Abrir a consola como administrador.' -ForegroundColor Red
  exit 1
}
if (-not (Test-Path $origem)) {
  Write-Host "ERRO: binario novo nao existe em $origem" -ForegroundColor Red
  Write-Host 'Correr primeiro:' -ForegroundColor Yellow
  Write-Host '  cargo build --release -p heraclitus-server --bin heraclitus-service' -ForegroundColor Yellow
  exit 1
}
if (-not (Test-Path $destino)) {
  Write-Host "ERRO: o servico nao esta instalado em $destino" -ForegroundColor Red
  exit 1
}
"  binario novo : {0:N0} bytes  {1}" -f (Get-Item $origem).Length, (Get-Item $origem).LastWriteTime
"  instalado    : {0:N0} bytes  {1}" -f (Get-Item $destino).Length, (Get-Item $destino).LastWriteTime

Passo '1. Parar, guardar, trocar'
$copia = "$destino.bak-$(Get-Date -Format yyyyMMdd-HHmmss)"
Copy-Item $destino $copia -Force
"  copia de seguranca: $copia"

Stop-Service $servico -Force
(Get-Service $servico).WaitForStatus('Stopped', '00:01:00')
'  servico parado'

Copy-Item $origem $destino -Force
'  binario substituido'

Passo '2. Arrancar e verificar'
try {
  Start-Service $servico
  (Get-Service $servico).WaitForStatus('Running', '00:01:00')
} catch {
  Write-Host "  NAO SUBIU: $($_.Exception.Message)" -ForegroundColor Red
  Write-Host '  a repor o binario anterior...' -ForegroundColor Yellow
  Copy-Item $copia $destino -Force
  Start-Service $servico
  (Get-Service $servico).WaitForStatus('Running', '00:01:00')
  Write-Host '  reposto; o servico esta a correr com o binario ANTIGO.' -ForegroundColor Yellow
  exit 1
}
"  status: $((Get-Service $servico).Status)"

# Uma prova de vida que nao depende do servico dizer que arrancou: o gRPC tem
# de aceitar ligacao. Um processo que sobe e morre a seguir passaria no
# WaitForStatus e falharia aqui.
Passo '3. Prova de vida'
$ok = $false
foreach ($i in 1..20) {
  try {
    $c = New-Object Net.Sockets.TcpClient
    $c.Connect('127.0.0.1', 7474)
    $c.Close()
    $ok = $true
    break
  } catch { Start-Sleep -Milliseconds 500 }
}
if ($ok) {
  Write-Host '  gRPC 127.0.0.1:7474 aceita ligacao' -ForegroundColor Green
  Write-Host "`nDEPLOY OK" -ForegroundColor Green
  Write-Host "Reverter: Copy-Item '$copia' '$destino' -Force ; Restart-Service $servico" -ForegroundColor DarkGray
} else {
  Write-Host '  gRPC nao respondeu em 10s' -ForegroundColor Red
  Write-Host "Reverter: Copy-Item '$copia' '$destino' -Force ; Restart-Service $servico" -ForegroundColor Yellow
  exit 1
}
