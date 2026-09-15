#!/usr/bin/env bash
# reset-e-carga.sh  —  RESET + ingestao de dados abertos do governo federal
# 100% Linux/WSL.  NAO usa PowerShell nem binarios .exe do Windows.
#
# Uso: ./reset-e-carga.sh [opcoes]
#
# Opcoes:
#   --skip-build     Pular compilacao (binarios ja existentes)
#   --skip-edges     Pular edge-builder
#   --dry-run        Mostrar o que faria, sem modificar nada
#   --sem-backup     Nao fazer backup antes de apagar
#   --sem-reset      Nao apagar dados; carrega por cima do estado actual
#   --in-flight N    Appends concorrentes (padrao: 256)
#   --repeticoes N   Passadas da carga (padrao: 1)
#   --alvo-gb N      Acumular ate N GB no log (repeticoes dinamicas)
#   --dados-dir DIR  CSVs de entrada (padrao: /mnt/d/dados-governo)
#   --data-dir  DIR  Data-dir do banco (padrao: /mnt/d/HeraclitusDB/data)
#   --grpc-port N    Porta gRPC (padrao: 7474)
#   --rest-port N    Porta REST (padrao: 7475)

set -euo pipefail

# ── cores estilo Red Hat / Fedora ─────────────────────────────────────────────
RED=$'\033[0;31m';  GREEN=$'\033[0;32m';  YELLOW=$'\033[1;33m'
CYAN=$'\033[0;36m'; BOLD=$'\033[1m';      NC=$'\033[0m'
ok()   { printf "  [\033[0;32m  OK  \033[0m] %s\n" "$*"; }
fail() { printf "  [\033[0;31m FAIL \033[0m] %s\n" "$*" >&2; exit 1; }
warn() { printf "  [\033[1;33m WARN \033[0m] %s\n" "$*"; }
info() { printf "         %s\n" "$*"; }

# ── defaults ──────────────────────────────────────────────────────────────────
HERA_DIR=/mnt/d/DEV/HeraclitusDB
DATA_DIR=/mnt/d/HeraclitusDB/data
DADOS_DIR=/mnt/d/dados-governo
TOKEN_FILE=/mnt/d/HeraclitusDB/secrets-v1/writer.token
GRPC_PORT=7474
REST_PORT=7475
BATCH=8000
IN_FLIGHT=256
REPETICOES=1
ALVO_GB=0
SKIP_BUILD=false
SKIP_EDGES=false
DRY_RUN=false
SEM_BACKUP=false
SEM_RESET=false

# ── parse args ────────────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
  case "$1" in
    --skip-build)  SKIP_BUILD=true ;;
    --skip-edges)  SKIP_EDGES=true ;;
    --dry-run)     DRY_RUN=true ;;
    --sem-backup)  SEM_BACKUP=true ;;
    --sem-reset)   SEM_RESET=true ;;
    --in-flight)   IN_FLIGHT="$2"; shift ;;
    --repeticoes)  REPETICOES="$2"; shift ;;
    --alvo-gb)     ALVO_GB="$2"; shift ;;
    --dados-dir)   DADOS_DIR="$2"; shift ;;
    --data-dir)    DATA_DIR="$2"; shift ;;
    --grpc-port)   GRPC_PORT="$2"; shift ;;
    --rest-port)   REST_PORT="$2"; shift ;;
    *) fail "Opcao desconhecida: $1" ;;
  esac
  shift
done

TARGET=$HERA_DIR/target/release
BIN_SERVER=$TARGET/heraclitus-server
BIN_CLI=$TARGET/heraclitus
BIN_INGEST=$TARGET/ingestor
BIN_EDGES=$TARGET/edge-builder
SERVIDOR=http://127.0.0.1:$GRPC_PORT
CFG=$HERA_DIR/config.carga.toml

esperar_porta() {
  local p=$1 n=${2:-30}
  for ((i=0;i<n;i++)); do
    bash -c "echo >/dev/tcp/127.0.0.1/$p" 2>/dev/null && return 0
    sleep 2
  done
  return 1
}

# ── banner ────────────────────────────────────────────────────────────────────
printf "\n"
printf "\033[0;36m\033[1m%s\033[0m\n" "================================================="
printf "\033[0;36m\033[1m%s\033[0m\n" "  HeraclitusDB  —  RESET + CARGA  [Linux / WSL]"
printf "\033[0;36m\033[1m%s\033[0m\n" "================================================="
printf "\n"
info "data-dir : $DATA_DIR"
info "gRPC     : 127.0.0.1:$GRPC_PORT   REST: 127.0.0.1:$REST_PORT"
info "dados    : $DADOS_DIR"
info "in-flight: $IN_FLIGHT   batch: $BATCH   repeticoes: $REPETICOES"
[[ $DRY_RUN == true ]] && warn "DRY-RUN ativo — nada sera modificado"
printf "\n"
[[ -d $DADOS_DIR ]] || fail "Dados nao encontrados: $DADOS_DIR"

# ════════════════════════════════════════════════════════════════════════════════
# [1/8] BUILD
# ════════════════════════════════════════════════════════════════════════════════
printf "\033[1m%s\033[0m\n" "[1/8] Compilando (release)..."
if [[ $SKIP_BUILD == false ]]; then
  cd "$HERA_DIR"
  cargo build --release \
    -p heraclitus-server \
    -p heraclitus-cli \
    -p heraclitus-ingestor \
    || fail "cargo build falhou"
  ok "Build concluido"
else
  info "Build saltado (--skip-build)"
fi
for b in "$BIN_SERVER" "$BIN_CLI" "$BIN_INGEST" "$BIN_EDGES"; do
  [[ -x "$b" ]] || fail "Binario nao encontrado: $b"
done
ok "Binarios verificados"

# ════════════════════════════════════════════════════════════════════════════════
# [2/8] PARAR
# ════════════════════════════════════════════════════════════════════════════════
printf "\n"
printf "\033[1m%s\033[0m\n" "[2/8] Parando servicos e processos..."
if [[ $SEM_RESET == false ]]; then
  sudo systemctl stop heraclitus-dev heraclitus-soc 2>/dev/null || true
  pkill -f heraclitus-server 2>/dev/null || true
  pkill -f ingestor          2>/dev/null || true
  pkill -f edge-builder      2>/dev/null || true
  sleep 2
  ok "Servicos parados"
else
  info "--sem-reset: sem parar servicos, carga por cima"
fi

# ════════════════════════════════════════════════════════════════════════════════
# [3/8] BACKUP + RESET
# ════════════════════════════════════════════════════════════════════════════════
printf "\n"
printf "\033[1m%s\033[0m\n" "[3/8] Reset do data-dir..."
if [[ $DRY_RUN == true || $SEM_RESET == true ]]; then
  info "Data-dir intacto (dry-run ou --sem-reset)"
else
  if [[ $SEM_BACKUP == false && -d "$DATA_DIR/log" ]]; then
    STAMP=$(date +%Y%m%d-%H%M%S)
    BKP=/mnt/d/HeraclitusDB/backups/pre-carga-$STAMP
    warn "Backup do log -> $BKP"
    mkdir -p "$BKP"
    cp -r "$DATA_DIR/log" "$BKP/"
    [[ -d "$DATA_DIR/keys" ]] && cp -r "$DATA_DIR/keys" "$BKP/" || true
    ok "Backup concluido"
  fi
  warn "Apagando dados..."
  for sub in log raw views receipts attr; do
    rm -rf "${DATA_DIR:?}/$sub"
    mkdir -p "$DATA_DIR/$sub"
  done
  rm -f "$HERA_DIR/data/etl_flat_ckpt.json" "$DATA_DIR/etl_flat_ckpt.json" 2>/dev/null || true
  ok "Dados apagados"
fi

# ════════════════════════════════════════════════════════════════════════════════
# [4/8] CONFIG + SERVIDOR
# ════════════════════════════════════════════════════════════════════════════════
printf "\n"
printf "\033[1m%s\033[0m\n" "[4/8] Configurando e arrancando servidor..."
cat > "$CFG" <<TOMLEOF
data_dir  = "$DATA_DIR"
grpc_addr = "127.0.0.1:$GRPC_PORT"
rest_addr = "127.0.0.1:$REST_PORT"
segment_max_bytes = 8388608
fsync = { mode = "group_commit", interval_ms = 50 }
encryption_at_rest = false
checkpoint_interval_secs = 300
TOMLEOF

if [[ $DRY_RUN == true || $SEM_RESET == true ]]; then
  info "Servidor ja em execucao"
  esperar_porta "$GRPC_PORT" 3 || fail "Servidor nao responde em 127.0.0.1:$GRPC_PORT"
else
  "$BIN_SERVER" "$CFG" \
    > "$HERA_DIR/carga-server.out.log" \
    2>"$HERA_DIR/carga-server.err.log" &
  SRV_PID=$!
  info "Servidor PID $SRV_PID — aguardando porta $GRPC_PORT..."
  if ! esperar_porta "$GRPC_PORT" 30; then
    tail -40 "$HERA_DIR/carga-server.err.log"
    fail "Servidor nao subiu em 127.0.0.1:$GRPC_PORT"
  fi
  ok "Servidor na porta $GRPC_PORT (PID $SRV_PID)"
fi
T0=$(date +%s)

# ════════════════════════════════════════════════════════════════════════════════
# [5/8] INGESTOR
# ════════════════════════════════════════════════════════════════════════════════
printf "\n"
printf "\033[1m%s\033[0m\n" "[5/8] Ingestor Rust — $IN_FLIGHT appends em voo..."
export HERACLITUS_INGEST_INFLIGHT=$IN_FLIGHT
IARGS=(--server "$SERVIDOR" --dir "$DADOS_DIR" --batch "$BATCH")
if [[ -f "$TOKEN_FILE" ]]; then
  IARGS+=(--token-file "$TOKEN_FILE")
else
  warn "Token nao encontrado em $TOKEN_FILE — tentando sem auth"
fi
[[ $DRY_RUN == true ]] && IARGS+=(--dry-run)

if [[ $ALVO_GB -gt 0 ]]; then
  ALVO_BYTES=$(( ALVO_GB * 1073741824 ))
  warn "MODO META: acumulando ate ${ALVO_GB} GB..."
  P=1
  while true; do
    SZ=$(du -sb "$DATA_DIR/log" 2>/dev/null | awk '{print $1}' || echo 0)
    GB=$(awk "BEGIN{printf \"%.2f\",$SZ/1073741824}")
    info "Passada $P: ${GB} GB acumulados / ${ALVO_GB} GB alvo"
    [[ $SZ -ge $ALVO_BYTES ]] && { ok "Meta ${ALVO_GB} GB atingida"; break; }
    "$BIN_INGEST" "${IARGS[@]}" || fail "Ingestor falhou na passada $P"
    (( P++ ))
  done
else
  for ((r=1; r<=REPETICOES; r++)); do
    info "-> Passada $r de $REPETICOES"
    "$BIN_INGEST" "${IARGS[@]}" || fail "Ingestor falhou na passada $r"
  done
fi
ok "Ingestao concluida"

# ════════════════════════════════════════════════════════════════════════════════
# [6/8] EDGE-BUILDER
# ════════════════════════════════════════════════════════════════════════════════
printf "\n"
printf "\033[1m%s\033[0m\n" "[6/8] Edge-builder — arestas e entity resolution..."
if [[ $SKIP_EDGES == false ]]; then
  EARGS=(--server "$SERVIDOR")
  [[ -f "$TOKEN_FILE" ]] && EARGS+=(--token-file "$TOKEN_FILE")
  [[ $DRY_RUN == true ]] && EARGS+=(--dry-run)
  "$BIN_EDGES" "${EARGS[@]}" || fail "Edge-builder falhou"
  ok "Arestas concluidas"
else
  info "Edges saltadas (--skip-edges)"
fi

# ════════════════════════════════════════════════════════════════════════════════
# [7/8] SNAPSHOT
# ════════════════════════════════════════════════════════════════════════════════
printf "\n"
printf "\033[1m%s\033[0m\n" "[7/8] Snapshot..."
if [[ $DRY_RUN == false ]]; then
  LSN=$(curl -sf -X POST "http://127.0.0.1:$REST_PORT/snapshot" \
        | grep -o '"lsn":[0-9]*' | grep -o '[0-9]*' || echo '?')
  ok "Snapshot em LSN $LSN"
else
  info "DRY-RUN: sem snapshot"
fi

# ════════════════════════════════════════════════════════════════════════════════
# [8/8] VERIFICACAO
# ════════════════════════════════════════════════════════════════════════════════
printf "\n"
printf "\033[1m%s\033[0m\n" "[8/8] Verificacao de integridade..."
if [[ $DRY_RUN == false ]]; then
  "$BIN_CLI" verify "$DATA_DIR/log" || fail "VERIFY FALHOU — integridade comprometida"
  ok "Integridade verificada"
  STATS=$(curl -sf "http://127.0.0.1:$REST_PORT/stats" 2>/dev/null || echo '{}')
  if [[ "$STATS" != '{}' ]]; then
    printf "\n"
    printf "\033[0;36m\033[1m%s\033[0m\n" "=== ESTADO FINAL ==="
    echo "$STATS" | python3 -m json.tool || echo "$STATS"
  fi
else
  info "DRY-RUN: sem verify"
fi

# ── resumo ────────────────────────────────────────────────────────────────────
DUR=$(( $(date +%s) - T0 ))
H=$((DUR/3600)); M=$(((DUR%3600)/60)); S=$((DUR%60))
printf "\n"
printf "\033[0;36m\033[1m%s\033[0m\n" "================================================="
printf "\033[0;36m\033[1m  CARGA CONCLUIDA em %02d:%02d:%02d\033[0m\n" "$H" "$M" "$S"
printf "\033[0;36m\033[1m%s\033[0m\n" "================================================="
printf "\n"
info "gRPC  : http://127.0.0.1:$GRPC_PORT"
info "REST  : http://127.0.0.1:$REST_PORT"
info "dados : $DATA_DIR"
printf "\n"
info "Para religar o servico: sudo systemctl start heraclitus-dev"
printf "\n"
