<#
.SYNOPSIS
  Gera evidência de desenvolvimento para a SPEC-0049.

.DESCRIPTION
  O qualificador ainda não certifica uma release. Nesta primeira fatia ele
  executa somente Q2 (crash loop já existente) e produz um manifesto imutável
  com ambiente, comando, hashes e o resultado explícito de Q1–Q6. Qualquer
  estado Inconclusive/Skipped mantém o resultado global UNQUALIFIED.
#>
[CmdletBinding()]
param(
    [ValidateSet("q2-crash-loop")]
    [string]$QualificationCommand = "q2-crash-loop",

    [ValidateRange(1, 100000)]
    [int]$Iterations = 25,

    [string]$Out,

    [string]$Cargo = "cargo",

    [switch]$SelfTest
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Get-OverallStatus {
    param([object[]]$Trials)

    $statuses = @($Trials | ForEach-Object { $_.status })
    if ($statuses -contains "Failed") {
        return "FAILED"
    }
    # This is the central qualification invariant: partial evidence never
    # becomes a production pass merely because the one executed trial passed.
    if ($statuses -contains "Inconclusive" -or $statuses -contains "Skipped") {
        return "UNQUALIFIED"
    }
    if ($statuses.Count -eq 6 -and (@($statuses | Where-Object { $_ -ne "Passed" }).Count -eq 0)) {
        return "PASSED"
    }
    return "UNQUALIFIED"
}

function Get-NativeText {
    param(
        [string]$Executable,
        [string[]]$Arguments
    )

    try {
        $output = & $Executable @Arguments 2>$null
        if ($LASTEXITCODE -eq 0) {
            return (($output -join "`n").Trim())
        }
    }
    catch {
        # Environment capture is evidence enrichment, not a reason to turn a
        # completed crash trial into a false result.
    }
    return $null
}

function Get-FileSha256 {
    param([string]$Path)

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return $null
    }
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Write-Utf8NoBom {
    param(
        [string]$Path,
        [string]$Content
    )

    [System.IO.File]::WriteAllText(
        $Path,
        $Content,
        [System.Text.UTF8Encoding]::new($false)
    )
}

if ($SelfTest) {
    $partial = @(
        [pscustomobject]@{ status = "Passed" },
        [pscustomobject]@{ status = "Inconclusive" }
    )
    if ((Get-OverallStatus $partial) -ne "UNQUALIFIED") {
        throw "invariante quebrado: Inconclusive não pode produzir PASSED"
    }
    $complete = @(1..6 | ForEach-Object { [pscustomobject]@{ status = "Passed" } })
    if ((Get-OverallStatus $complete) -ne "PASSED") {
        throw "invariante quebrado: seis trials Passed devem produzir PASSED"
    }
    Write-Output "heraclitus-qualifier self-test: OK"
    exit 0
}

if ([string]::IsNullOrWhiteSpace($Out)) {
    throw "-Out é obrigatório e deve apontar para um diretório novo de evidência"
}

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$outPath = [System.IO.Path]::GetFullPath($Out)
if (Test-Path -LiteralPath $outPath) {
    throw "diretório de evidência já existe: $outPath (a ferramenta não sobrescreve evidências)"
}

New-Item -ItemType Directory -Path $outPath -ErrorAction Stop | Out-Null
$stdoutPath = Join-Path $outPath "q2.stdout.log"
$stderrPath = Join-Path $outPath "q2.stderr.log"
$startedAt = [DateTimeOffset]::UtcNow

$gitCommit = Get-NativeText "git" @("-C", $repoRoot, "rev-parse", "HEAD")
$gitStatus = Get-NativeText "git" @("-C", $repoRoot, "status", "--porcelain")
$rustcVersion = Get-NativeText "rustc" @("-Vv")
$cargoVersion = Get-NativeText $Cargo @("-V")
$targetDir = Join-Path $repoRoot "target"
$metadataText = Get-NativeText $Cargo @("metadata", "--offline", "--format-version", "1", "--no-deps")
if ($metadataText) {
    try {
        $targetDir = (($metadataText | ConvertFrom-Json).target_directory)
    }
    catch {
        # Keep the conventional target path in the evidence when metadata is
        # unavailable; the trial result remains authoritative.
    }
}

$cargoArgs = @(
    "test", "--offline", "-p", "heraclitus-log", "--test", "crash_injection", "--", "--nocapture"
)
$oldCrashIters = $env:CRASH_ITERS
$oldCargoOffline = $env:CARGO_NET_OFFLINE
$exitCode = 127
try {
    $env:CRASH_ITERS = $Iterations.ToString([System.Globalization.CultureInfo]::InvariantCulture)
    # crash_injection invokes `cargo build` for its helper binary internally;
    # propagate offline mode to that child command as well.
    $env:CARGO_NET_OFFLINE = "true"
    Push-Location $repoRoot
    try {
        & $Cargo @cargoArgs 1> $stdoutPath 2> $stderrPath
        if ($null -ne $LASTEXITCODE) {
            $exitCode = [int]$LASTEXITCODE
        }
    }
    finally {
        Pop-Location
    }
}
catch {
    $_ | Out-String | Add-Content -LiteralPath $stderrPath -Encoding utf8
}
finally {
    if ($null -eq $oldCrashIters) {
        Remove-Item Env:CRASH_ITERS -ErrorAction SilentlyContinue
    }
    else {
        $env:CRASH_ITERS = $oldCrashIters
    }
    if ($null -eq $oldCargoOffline) {
        Remove-Item Env:CARGO_NET_OFFLINE -ErrorAction SilentlyContinue
    }
    else {
        $env:CARGO_NET_OFFLINE = $oldCargoOffline
    }
}

$finishedAt = [DateTimeOffset]::UtcNow
$exeSuffix = if ([System.Runtime.InteropServices.RuntimeInformation]::IsOSPlatform(
        [System.Runtime.InteropServices.OSPlatform]::Windows
    )) {
    ".exe"
}
else {
    ""
}
$binaryPath = Join-Path (Join-Path (Join-Path $targetDir "debug") "examples") ("crash_writer" + $exeSuffix)

$q2Status = if ($exitCode -eq 0) { "Passed" } else { "Failed" }
$q1 = [pscustomobject]@{
    trial = "Q1-load"; status = "Inconclusive"; reason = "workload/soak/telemetria de servidor ainda não qualificados"
}
$q2 = [pscustomobject]@{
    trial = "Q2-crash-loop"
    status = $q2Status
    started_at = $startedAt.ToString("o")
    finished_at = $finishedAt.ToString("o")
    iterations = $Iterations
    command = (@($Cargo) + $cargoArgs) -join " "
    exit_code = $exitCode
    evidence = @(
        [pscustomobject]@{ path = "q2.stdout.log"; sha256 = Get-FileSha256 $stdoutPath },
        [pscustomobject]@{ path = "q2.stderr.log"; sha256 = Get-FileSha256 $stderrPath }
    )
}
$q3 = [pscustomobject]@{
    trial = "Q3-attack"; status = "Inconclusive"; reason = "fuzz/CI existentes não formam campanha de qualificação"
}
$q4 = [pscustomobject]@{
    trial = "Q4-upgrade"; status = "Inconclusive"; reason = "não existe matriz N-1 para N/rollback"
}
$q5 = [pscustomobject]@{
    trial = "Q5-node-loss"; status = "Inconclusive"; reason = "testes Raft não são qualificação de infraestrutura"
}
$q6 = [pscustomobject]@{
    trial = "Q6-restore"; status = "Inconclusive"; reason = "restore de banco real vazio/serve não foi qualificado"
}
$trials = @($q1, $q2, $q3, $q4, $q5, $q6)
$overallStatus = Get-OverallStatus $trials

$manifest = [ordered]@{
    schema_version = 1
    qualification_id = "dev-q2-" + $startedAt.ToString("yyyyMMddTHHmmssZ")
    qualification_level = "DevelopmentEvidence"
    overall_status = $overallStatus
    production_qualified = $false
    repository = [ordered]@{
        path = $repoRoot
        git_commit = $gitCommit
        dirty_status = $gitStatus
    }
    environment = [ordered]@{
        operating_system = [System.Runtime.InteropServices.RuntimeInformation]::OSDescription
        process_architecture = [System.Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture.ToString()
        logical_cpus = [Environment]::ProcessorCount
        rustc = $rustcVersion
        cargo = $cargoVersion
    }
    binary = [ordered]@{
        path = $binaryPath
        sha256 = Get-FileSha256 $binaryPath
    }
    trials = $trials
    known_limitations = @(
        "Q1/Q3/Q4/Q5/Q6 permanecem Inconclusive; este artefato nunca é certificação de produção.",
        "Q2 cobre kill/reopen/verify de processo local; não simula power-loss físico.",
        "O manifesto é evidência de desenvolvimento e precisa de retenção externa para cadeia de custódia."
    )
}

$manifestPath = Join-Path $outPath "manifest.json"
Write-Utf8NoBom $manifestPath ($manifest | ConvertTo-Json -Depth 12)
$manifestHash = Get-FileSha256 $manifestPath
Write-Utf8NoBom (Join-Path $outPath "manifest.sha256") ("$manifestHash  manifest.json`n")

Write-Output "evidência escrita em $outPath"
Write-Output "Q2: $q2Status; resultado global: $overallStatus (production_qualified=false)"
if ($q2Status -eq "Failed") {
    exit 1
}
