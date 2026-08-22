<#
.SYNOPSIS
    Verifica, compila, testa e faz merge do trabalho da SPEC-0050 (Fases 0-3).

.DESCRIPTION
    A ordem aqui e deliberada e diferente da pedida: BUILD ANTES DE COMMIT.

    O modulo v6 foi desenvolvido num ambiente sem acesso ao crates.io, por isso
    o `zstd` e o `lz4_flex` foram exercitados contra stubs com as assinaturas
    publicas reais. Toda a logica esta verificada (169 testes), mas as quatro
    chamadas as bibliotecas verdadeiras -- isoladas em
    crates/heraclitus-log/src/v6/compress.rs -- nunca correram contra elas.

    Este script trata esse facto como um portao: se a compilacao ou os testes
    falharem, NAO ha commit e NAO ha merge. Commitar codigo partido para main
    e pior do que nao commitar nada.

    Nao faz deploy. O deploy tem o seu proprio script, ja existente, e exige
    PowerShell elevado -- ver o fim da saida.

.PARAMETER Repo
    Raiz do repositorio. Default: D:\DEV\HeraclitusDB

.PARAMETER Branch
    Nome do ramo de trabalho a criar. Default: feat/spec-0050-fases-0-3

.PARAMETER SkipMerge
    Compila, testa e commita no ramo, mas nao faz merge para main.

.EXAMPLE
    .\spec-0050-build-e-merge.ps1

.EXAMPLE
    .\spec-0050-build-e-merge.ps1 -SkipMerge
#>

[CmdletBinding()]
param(
    [string] $Repo = 'D:\DEV\HeraclitusDB',
    [string] $Branch = 'feat/spec-0050-fases-0-3',
    [switch] $SkipMerge
)

$ErrorActionPreference = 'Stop'

function Write-Etapa {
    param([string] $Texto)
    Write-Host ''
    Write-Host ('=' * 72) -ForegroundColor DarkGray
    Write-Host "  $Texto" -ForegroundColor Cyan
    Write-Host ('=' * 72) -ForegroundColor DarkGray
}

function Invoke-Passo {
    param(
        [string]   $Nome,
        [string]   $Comando,
        [string[]] $Args
    )
    Write-Host "> $Nome" -ForegroundColor Yellow
    Write-Host "  $Comando $($Args -join ' ')" -ForegroundColor DarkGray
    & $Comando @Args
    if ($LASTEXITCODE -ne 0) {
        throw "$Nome falhou (exit $LASTEXITCODE). Nada foi commitado nem merged."
    }
    Write-Host "  OK" -ForegroundColor Green
}

Set-Location -LiteralPath $Repo

# ---------------------------------------------------------------------------
Write-Etapa '1/6  Estado do repositorio'
# ---------------------------------------------------------------------------

$ramoActual = (git rev-parse --abbrev-ref HEAD).Trim()
Write-Host "  Ramo actual : $ramoActual"
Write-Host "  HEAD        : $((git rev-parse --short HEAD).Trim())"

git fetch origin --quiet 2>$null
$local  = (git rev-parse main 2>$null).Trim()
$remoto = (git rev-parse origin/main 2>$null).Trim()
if ($local -eq $remoto) {
    Write-Host "  main == origin/main ($($local.Substring(0,8)))" -ForegroundColor Green
} else {
    Write-Host "  main  : $local" -ForegroundColor Yellow
    Write-Host "  origin: $remoto" -ForegroundColor Yellow
    Write-Host "  AVISO: main divergiu de origin/main. Resolve isso antes de continuar." -ForegroundColor Red
}

Write-Host ''
Write-Host '  Alteracoes por commitar:'
git status --short

Write-Host ''
Write-Host '  Ramos locais ainda NAO merged em main:'
$naoMerged = git branch --no-merged main --format='%(refname:short)'
if ($naoMerged) { $naoMerged | ForEach-Object { Write-Host "    - $_" } }
else            { Write-Host '    (nenhum)' -ForegroundColor Green }

# ---------------------------------------------------------------------------
Write-Etapa '2/6  Build -- o portao. Regenera o Cargo.lock com zstd/lz4_flex/ulid'
# ---------------------------------------------------------------------------
# Sem --locked: o lock TEM de ser regenerado, as dependencias sao novas.
# E aqui que o v6 compila pela primeira vez contra o zstd e o lz4_flex reais.

Invoke-Passo 'cargo build (workspace, debug)' 'cargo' @('build', '--workspace')

# ---------------------------------------------------------------------------
Write-Etapa '3/6  Testes'
# ---------------------------------------------------------------------------

Invoke-Passo 'cargo test (workspace)' 'cargo' @('test', '--workspace')

Write-Host ''
Write-Host '  Suites novas da SPEC-0050:' -ForegroundColor Cyan
Invoke-Passo 'golden vectors'  'cargo' @('test', '-p', 'heraclitus-log', '--test', 'hrkl_v6_golden')
Invoke-Passo 'property tests'  'cargo' @('test', '-p', 'heraclitus-log', '--test', 'hrkl_v6_props')
Invoke-Passo 'manifesto/GC'    'cargo' @('test', '-p', 'heraclitus-log', '--test', 'hrkl_v6_manifest')

# ---------------------------------------------------------------------------
Write-Etapa '4/6  Lint -- os mesmos gates que o CI corre'
# ---------------------------------------------------------------------------

Invoke-Passo 'cargo fmt --check' 'cargo' @('fmt', '--all', '--check')
Invoke-Passo 'cargo clippy'      'cargo' @('clippy', '--workspace', '--all-targets', '--', '-D', 'warnings')

# ---------------------------------------------------------------------------
Write-Etapa '5/6  Commit no ramo de trabalho'
# ---------------------------------------------------------------------------

$mensagem = @'
feat(storage): SPEC-0050 HRKL v6 -- Fases 0 a 3

Formato canonico, segmentos PACKED, catalogo .hrkm e politica de GC.

Fase 0 (SS197) -- CanonicalRecordCodecV1 com codec manual (sem serde nem
repr(C)), tags permanentes de EventKind, varint canonico e
MerkleAccumulatorV1 em streaming com provas de inclusao. A raiz logica nao
depende da divisao fisica em blocos: e o que autoriza substituir RAW por
PACKED sem perder identidade.

Fase 1 (SS198) -- FileHeaderV6 (64 B), FooterV6 (128 B), registo RAW com
CRC-32C e recuperacao de cauda rasgada apenas no segmento activo.

Fase 2 (SS199) -- blocos de 256 KiB com Zstd/LZ4 e RAW fallback, delta de
HLC, eliminacao de LSN em modo contiguo, restart points, block directory,
e a transaccao de packing de SS88 com verificacao da raiz antes de publicar.

Fase 3 (SS200) -- o catalogo v2 evolui o DatabaseManifest em vez de criar um
segundo catalogo (SS69); .hrkm com snapshots numerados e CURRENT trocado por
rename; maquina de estados de geracoes; GC com pins, grace period, LegalHold
e politica de replicas, com o invariante de SS91 verificado por codigo escrito
independentemente da decisao.

Gates medidos: 3,66 B de metadados por registo (SS156 pede <=9,6), um unico
bloco descomprimido por point lookup (SS157), <25% dos bytes lidos num range
selectivo (SS158).

Dependencias novas: zstd, lz4_flex, ulid (dev). O modulo v6 e aditivo -- o
caminho v5 fica intacto ate a Fase 4 ligar o writer.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>
'@

$existe = git rev-parse --verify --quiet "refs/heads/$Branch"
if ($existe) {
    Write-Host "  Ramo '$Branch' ja existe; a reutilizar." -ForegroundColor Yellow
    git checkout $Branch
} else {
    git checkout -b $Branch
}
if ($LASTEXITCODE -ne 0) { throw 'checkout falhou.' }

git add -A
if ($LASTEXITCODE -ne 0) { throw 'git add falhou.' }

$staged = git diff --cached --name-only
if (-not $staged) {
    Write-Host '  Nada para commitar.' -ForegroundColor Yellow
} else {
    Write-Host "  $((@($staged)).Count) ficheiros staged."
    $tmp = [System.IO.Path]::GetTempFileName()
    Set-Content -LiteralPath $tmp -Value $mensagem -Encoding UTF8
    git commit --file $tmp
    Remove-Item -LiteralPath $tmp -Force
    if ($LASTEXITCODE -ne 0) { throw 'git commit falhou.' }
    Write-Host "  Commit: $((git rev-parse --short HEAD).Trim())" -ForegroundColor Green
}

# ---------------------------------------------------------------------------
Write-Etapa '6/6  Merge para main'
# ---------------------------------------------------------------------------

if ($SkipMerge) {
    Write-Host "  -SkipMerge activo. Ficaste em '$Branch'." -ForegroundColor Yellow
} else {
    git checkout main
    if ($LASTEXITCODE -ne 0) { throw 'checkout main falhou.' }
    # --no-ff mantem o ramo visivel no historico: a Fase 0-3 foi um trabalho,
    # nao uma sequencia de commits soltos.
    git merge --no-ff $Branch -m "merge: SPEC-0050 Fases 0-3 (HRKL v6)"
    if ($LASTEXITCODE -ne 0) { throw 'merge falhou.' }
    Write-Host "  main agora em $((git rev-parse --short HEAD).Trim())" -ForegroundColor Green
    Write-Host '  Nao foi feito push. Corre `git push origin main` quando quiseres.' -ForegroundColor Yellow
}

# ---------------------------------------------------------------------------
Write-Etapa 'Feito -- e o que falta'
# ---------------------------------------------------------------------------

Write-Host @'
  O deploy NAO faz parte deste script. Precisa de PowerShell ELEVADO e tem
  o seu proprio fluxo transaccional, que preserva o binario e o data-dir
  anteriores e faz rollback em caso de falha:

      # binarios de release
      cargo +stable-x86_64-pc-windows-msvc build --release `
        -p heraclitus-server --bin heraclitus-service --locked
      cargo +stable-x86_64-pc-windows-msvc build --release `
        -p heraclitus-cli --bin heraclitus --locked

      # upgrade local completo (elevado)
      .\windows\deploy-local-homologation.ps1

  Antes de tratar isto como producao, tem em conta que a SPEC-0050 esta a
  meio: as Fases 4 a 8 (sidecar .hrki, object storage, lakehouse,
  PackedEpisodeV1, indexacao avancada) nao existem, e o motor ainda escreve
  segmentos v5 -- o modulo v6 e aditivo e nenhum caminho quente lhe chama
  ainda. O que este merge traz e a fundacao verificada, nao a troca do
  formato em producao.
'@ -ForegroundColor Gray

Write-Host ''
