$ErrorActionPreference = 'Stop'
$svc = 'HeraclitusDB'
$log = 'D:\tmp\hera_deploy.log'
$env:PATH = 'D:\DEV\tools\as-only;' + $env:PATH

"[start $(Get-Date -Format HH:mm:ss)] deploy" | Out-File $log -Encoding utf8
try {
    "stopping $svc" | Out-File $log -Append -Encoding utf8
    Stop-Service $svc -Force
    (Get-Service $svc).WaitForStatus('Stopped', '00:00:30')
    Set-Location 'D:\DEV\HeraclitusDB'
    "building service binary" | Out-File $log -Append -Encoding utf8
    # Let cmd own the redirection: in PS 5.1, redirecting a native command's
    # stderr through PS (*>>, 2>&1) wraps each progress line as an ErrorRecord
    # and, with EAP=Stop, throws on cargo's first "Compiling..." line.
    $build = 'cargo +stable-x86_64-pc-windows-gnu build --release -p heraclitus-server --bin heraclitus-service'
    cmd /c "$build >> `"$log`" 2>&1"
    $code = $LASTEXITCODE
    if ($code -ne 0) {
        "BUILD FAILED (exit $code) - rolling back to old binary" | Out-File $log -Append -Encoding utf8
        Start-Service $svc
        exit 1
    }
    "build ok; starting $svc" | Out-File $log -Append -Encoding utf8
    Start-Service $svc
    (Get-Service $svc).WaitForStatus('Running', '00:00:30')
    ("DEPLOYED status=" + (Get-Service $svc).Status) | Out-File $log -Append -Encoding utf8
    exit 0
} catch {
    ("ERROR: " + $_.Exception.Message) | Out-File $log -Append -Encoding utf8
    try { Start-Service $svc } catch { "could not restart" | Out-File $log -Append -Encoding utf8 }
    exit 2
}
