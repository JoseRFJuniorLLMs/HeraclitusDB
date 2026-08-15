# Deploy do HeraclitusDB como serviço — toolchain MSVC (a gnu está partida).
# Robusto contra o quirk do cargo no Windows (não repõe o exe canónico após um
# link cujo destino estava bloqueado): pega o caminho REAL do exe compilado via
# --message-format=json e copia-o à mão. Backup + rollback se algo falhar.
# Correr ELEVADO (o SCM exige Administrador).
$ErrorActionPreference = 'Stop'
$svc   = 'HeraclitusDB'
$log   = 'D:\tmp\hera_deploy_msvc.log'
$jlog  = 'D:\tmp\hera_deploy_msvc.jsonl'
$elog  = 'D:\tmp\hera_deploy_msvc.err'
$root  = 'D:\DEV\HeraclitusDB'
$exe   = Join-Path $root 'target\release\heraclitus-service.exe'
$bak   = "$exe.bak"
$env:PATH = "$env:USERPROFILE\.cargo\bin;$env:PATH"

function Log($m) { "[$(Get-Date -Format HH:mm:ss)] $m" | Out-File $log -Append -Encoding utf8 }

"=== deploy msvc $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') ===" | Out-File $log -Encoding utf8
try {
    Log "stopping $svc"
    Stop-Service $svc -Force
    (Get-Service $svc).WaitForStatus('Stopped', '00:00:30')

    if (Test-Path $exe) { Copy-Item $exe $bak -Force; Log "backup -> $bak" }

    Set-Location $root
    # clean força o rebuild real (senão o fingerprint acha-se atual e não relinka)
    Log "cargo clean -p heraclitus-server"
    cmd /c "cargo clean -p heraclitus-server --release >> `"$log`" 2>&1"

    Log "a compilar (msvc, --message-format=json)"
    $tc = 'cargo +stable-x86_64-pc-windows-msvc build --release -p heraclitus-server --bin heraclitus-service --message-format=json'
    cmd /c "$tc > `"$jlog`" 2>`"$elog`""
    $code = $LASTEXITCODE
    Log "cargo exit=$code"

    # Extrai o caminho REAL do exe emitido (campo executable do compiler-artifact).
    $exePath = $null
    foreach ($line in Get-Content $jlog -ErrorAction SilentlyContinue) {
        if ($line -notmatch '"executable"') { continue }
        try { $o = $line | ConvertFrom-Json } catch { continue }
        if ($o.reason -eq 'compiler-artifact' -and $o.target.name -eq 'heraclitus-service' -and $o.executable) {
            $exePath = $o.executable
        }
    }
    Log "exe compilado: $exePath"

    if ($code -eq 0 -and $exePath -and (Test-Path $exePath)) {
        Copy-Item $exePath $exe -Force
        Log "copiado -> $exe ($((Get-Item $exe).LastWriteTime), $((Get-Item $exe).Length) bytes)"
        Start-Service $svc
        (Get-Service $svc).WaitForStatus('Running', '00:00:30')
        Log ("DEPLOYED status=" + (Get-Service $svc).Status)
        exit 0
    } else {
        Log "BUILD FALHOU (exit=$code exePath=$exePath) -> ROLLBACK; erros em $elog"
        Get-Content $elog -ErrorAction SilentlyContinue | Select-Object -Last 15 | ForEach-Object { Log "  cargo> $_" }
        if (Test-Path $bak) { Copy-Item $bak $exe -Force }
        Start-Service $svc
        (Get-Service $svc).WaitForStatus('Running', '00:00:30')
        Log ("ROLLED-BACK status=" + (Get-Service $svc).Status)
        exit 1
    }
} catch {
    Log ("ERRO: " + $_.Exception.Message)
    if ((Test-Path $bak) -and -not (Test-Path $exe)) { Copy-Item $bak $exe -Force }
    try { Start-Service $svc } catch { Log "não conseguiu rearrancar" }
    exit 2
}
