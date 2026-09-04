#!/usr/bin/env bash
# SPEC-0072 §37 — Gate Linux L7: qualificacao de escala.
#
# Os gates L0-L6 (scripts/linux-gates.sh) provam CORRECCAO e correm por PR. Este
# prova ESCALA e pertence ao nightly: enche uma base, encadeia os cinco cenarios
# de restart da §37 sobre o MESMO directorio persistente, e mede o que a spec
# manda medir.
#
# O que a §37 pede e o que este script entrega:
#
#   pedido                              entregue
#   ------------------------------      ------------------------------------
#   dataset >= 20.000.000 eventos       HERACLITUS_L7_EVENTOS (default 200.000)
#   storage ext4/xfs, sem tmpfs         verificado, e ABORTA se for tmpfs
#   5 cenarios de restart encadeados    todos os cinco
#   wall_time, cpu_time, peak_rss       de /proc, por arranque
#   io_bytes_read / io_bytes_written    de /proc/[pid]/io
#   events_scanned ~ T (nunca N)        assertado nos warm boots
#   tail_size exacto                    do BootReport
#
# A DIFERENCA DE DATASET E DELIBERADA E NAO E SILENCIOSA. 20M eventos num runner
# de CI sao horas de ingestao por gRPC unario; o default corre em minutos e
# prova as MESMAS relacoes (warm boot le a cauda, nao a base). Para a corrida de
# qualificacao a serio:
#
#   HERACLITUS_L7_EVENTOS=20000000 scripts/linux-gate-l7.sh
#
# O script imprime, no fim, qual dos dois correu.
set -uo pipefail

RAIZ="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
EVENTOS="${HERACLITUS_L7_EVENTOS:-200000}"
DIR_DADOS="${HERACLITUS_L7_DIR:-}"
FALHAS=0
SERVIDOR_PID=""
MED_WALL=""; MED_CPU=""; MED_PICO=""; MED_LER=""; MED_ESCREVER=""

REST_PORT=18100
GRPC_PORT=18101

vermelho() { printf '\033[31m%s\033[0m\n' "$*"; }
verde()    { printf '\033[32m%s\033[0m\n' "$*"; }
cinza()    { printf '\033[2m%s\033[0m\n' "$*"; }
ok()    { verde "  [ OK ] $1"; }
falha() { vermelho "  [FALHA] $1"; FALHAS=$((FALHAS + 1)); }

if [[ -z "$DIR_DADOS" ]]; then
  DIR_DADOS="$(mktemp -d)"
  LIMPAR_DIR=1
fi

limpar() {
  [[ -n "${SERVIDOR_PID:-}" ]] && kill -9 "$SERVIDOR_PID" 2>/dev/null
  [[ "${LIMPAR_DIR:-0}" == "1" ]] && rm -rf "$DIR_DADOS"
}
trap limpar EXIT

# ── storage persistente, nao tmpfs ───────────────────────────────────────────

echo "=== L7 — pre-condicoes ==="
FS=$(df -PT "$DIR_DADOS" 2>/dev/null | awk 'NR==2{print $2}')
cinza "  $DIR_DADOS  ->  $FS"
case "$FS" in
  tmpfs|ramfs)
    falha "storage e $FS. A §37 exige particao persistente (ext4/xfs) com fsync activo."
    vermelho "  Medir replay em RAM nao mede replay: define HERACLITUS_L7_DIR."
    exit 1
    ;;
  ext4|xfs|btrfs|overlay|ext3)
    ok "storage persistente ($FS)"
    ;;
  *)
    cinza "  aviso: sistema de ficheiros '$FS' nao reconhecido; a continuar"
    ;;
esac

# ── infra ────────────────────────────────────────────────────────────────────

escrever_config() {
  local extra="${1:-}"
  mkdir -p "$DIR_DADOS/data"
  cat > "$DIR_DADOS/heraclitus.toml" <<TOML
data_dir = "$DIR_DADOS/data"
rest_addr = "127.0.0.1:$REST_PORT"
grpc_addr = "127.0.0.1:$GRPC_PORT"
fsync = { mode = "group_commit", interval_ms = 5 }

[sentinel]
enabled = true
mode = "observe"
worker_threads = 2
$extra
TOML
}

campo() {
  local onde="${2:-status}"
  curl -sf "http://127.0.0.1:$REST_PORT/sentinel/status" 2>/dev/null | python3 -c "
import json,sys
try:
    d = json.load(sys.stdin)
except Exception:
    print(''); raise SystemExit
s = d.get('status') or {}
alvo = (s.get('boot') or {}) if '$onde' == 'boot' else s
print(alvo.get('$1', ''))
" 2>/dev/null
}

# Arranca e mede, deixando o resultado em MED_*.
#
# NAO devolve por stdout, e a razao custou uma corrida inteira a descobrir:
# `M=$(arrancar_medindo)` corre a funcao numa SUBSHELL, portanto o
# `SERVIDOR_PID` que ela atribui morre com a subshell. O `parar` do processo
# principal via a variavel vazia, nao parava nada, e o servidor do primeiro
# cenario ficava vivo o tempo todo. Os arranques seguintes falhavam a ligar-se
# ao porto, mas o `healthz` respondia — era o PRIMEIRO servidor a responder — e
# o gate media cinco vezes o mesmo processo, com wall=5ms e o mesmo
# `rebuild_canonical` em todos os cenarios. Verde nenhum, mas quase.
arrancar_medindo() {
  local prazo="${1:-900}"
  local t0 t1
  MED_WALL=""; MED_CPU=""; MED_PICO=""; MED_LER=""; MED_ESCREVER=""
  t0=$(date +%s%3N)
  "$RAIZ/target/release/heraclitus-server" "$DIR_DADOS/heraclitus.toml" \
    > "$DIR_DADOS/stdout.log" 2> "$DIR_DADOS/stderr.log" &
  SERVIDOR_PID=$!
  local fim=$((SECONDS + prazo))
  while (( SECONDS < fim )); do
    kill -0 "$SERVIDOR_PID" 2>/dev/null || return 1
    if curl -sf "http://127.0.0.1:$REST_PORT/healthz" >/dev/null 2>&1; then
      t1=$(date +%s%3N)
      local hz
      hz=$(getconf CLK_TCK 2>/dev/null || echo 100)
      MED_WALL=$((t1 - t0))
      MED_CPU=$(awk -v hz="$hz" '{print int(($14 + $15) * 1000 / hz)}' \
        "/proc/$SERVIDOR_PID/stat" 2>/dev/null)
      MED_PICO=$(awk '/^VmHWM:/{print $2}' "/proc/$SERVIDOR_PID/status" 2>/dev/null)
      MED_LER=$(awk '/^read_bytes:/{print $2}' "/proc/$SERVIDOR_PID/io" 2>/dev/null)
      MED_ESCREVER=$(awk '/^write_bytes:/{print $2}' "/proc/$SERVIDOR_PID/io" 2>/dev/null)
      return 0
    fi
    sleep 0.1
  done
  return 1
}

parar() {
  [[ -z "${SERVIDOR_PID:-}" ]] && return 0
  kill -TERM "$SERVIDOR_PID" 2>/dev/null
  local fim=$((SECONDS + 300))
  while (( SECONDS < fim )); do
    kill -0 "$SERVIDOR_PID" 2>/dev/null || { SERVIDOR_PID=""; return 0; }
    sleep 0.2
  done
  kill -9 "$SERVIDOR_PID" 2>/dev/null; SERVIDOR_PID=""; return 1
}

esperar_catchup() {
  local prazo="${1:-900}"
  local fim=$((SECONDS + prazo))
  local n h
  while (( SECONDS < fim )); do
    n=$(campo next_lsn status); h=$(campo head_lsn status)
    [[ -n "$n" && -n "$h" && "$n" -ge "$h" ]] && return 0
    sleep 1
  done
  return 1
}

relatar() {
  local nome="$1"
  local resultado cauda lidos wm
  resultado=$(campo outcome boot); cauda=$(campo tail_events boot)
  lidos=$(campo events_scanned_total boot); wm=$(campo watermark_lsn boot)
  printf '  %-18s wall=%sms cpu=%sms pico_rss=%sKiB io_r=%s io_w=%s\n' \
    "$nome" "${MED_WALL:-?}" "${MED_CPU:-0}" "${MED_PICO:-0}" \
    "${MED_LER:-0}" "${MED_ESCREVER:-0}"
  printf '  %-18s outcome=%s tail=%s lidos=%s watermark=%s\n' \
    "" "$resultado" "$cauda" "$lidos" "$wm"
  ULTIMO_RESULTADO="$resultado"; ULTIMA_CAUDA="$cauda"; ULTIMOS_LIDOS="$lidos"
}

# ── build ────────────────────────────────────────────────────────────────────

echo
echo "=== L7 — build ==="
# Dois comandos e nao um: o `probe_grpc` vive no `heraclitus-ingestor`, e
# `-p heraclitus-server --bin probe_grpc` falha com "no bin target named
# probe_grpc in heraclitus-server".
(cd "$RAIZ" && cargo build --release -p heraclitus-server --locked) || exit 1
(cd "$RAIZ" && cargo build --release --bin probe_grpc --locked) || exit 1
SONDA="$RAIZ/target/release/probe_grpc"
ok "binarios prontos"

# ── cenario 1 — cold boot ────────────────────────────────────────────────────

echo
echo "=== Cenario 1 — cold boot (sem snapshot) ==="
escrever_config
arrancar_medindo || { falha "cold boot nao arrancou"; exit 1; }
relatar "cold"
[[ "$ULTIMO_RESULTADO" == "rebuild_canonical" ]] \
  && ok "primeiro arranque reconstroi do log" \
  || falha "esperava rebuild_canonical, veio '$ULTIMO_RESULTADO'"

# ── populacao ────────────────────────────────────────────────────────────────

echo
echo "=== Populacao (~$EVENTOS eventos) ==="
POR_MODO=$(( EVENTOS / 3 ))
"$SONDA" --server "http://127.0.0.1:$GRPC_PORT" --n "$POR_MODO" --conc 16 >/dev/null 2>&1 \
  || falha "ingestao falhou"
esperar_catchup || falha "o Sentinel nao apanhou a cauda"
BASE=$(campo head_lsn status)
ok "base com $BASE episodios (inclui derivados do Sentinel)"

# ── cenario 2 — warm clean boot ──────────────────────────────────────────────

echo
echo "=== Cenario 2 — warm clean boot (cauda zero) ==="
parar || falha "SIGTERM nao desligou"
arrancar_medindo || { falha "warm clean nao arrancou"; exit 1; }
relatar "warm-clean"
[[ "$ULTIMO_RESULTADO" == "synchronized" || "$ULTIMO_RESULTADO" == "catch_up_tail" ]] \
  && ok "arranque a quente" \
  || falha "esperava synchronized/catch_up_tail, veio '$ULTIMO_RESULTADO'"
TECTO=$(( BASE / 10 + 5 ))
if [[ -n "$ULTIMOS_LIDOS" && "$ULTIMOS_LIDOS" -le "$TECTO" ]]; then
  ok "events_scanned=$ULTIMOS_LIDOS <= $TECTO (base $BASE) — le a cauda, nao a base"
else
  falha "events_scanned=$ULTIMOS_LIDOS de uma base de $BASE: voltou a varrer"
fi

# ── cenario 3 — warm dirty boot ──────────────────────────────────────────────

echo
echo "=== Cenario 3 — warm dirty boot (cauda pendente) ==="
"$SONDA" --server "http://127.0.0.1:$GRPC_PORT" --n 334 --conc 4 >/dev/null 2>&1
# De proposito SEM esperar catch-up: e o que faz a cauda existir.
parar
ANTES=$(( BASE ))
arrancar_medindo || { falha "warm dirty nao arrancou"; exit 1; }
relatar "warm-dirty"
[[ "$ULTIMO_RESULTADO" == "catch_up_tail" || "$ULTIMO_RESULTADO" == "synchronized" ]] \
  && ok "cauda pendente reproduzida" \
  || falha "veio '$ULTIMO_RESULTADO'"
esperar_catchup || falha "nao apanhou a cauda depois do warm dirty"
NOVA_BASE=$(campo head_lsn status)

# ── cenario 4 — crash boot ───────────────────────────────────────────────────

echo
echo "=== Cenario 4 — crash boot (SIGKILL durante ingestao) ==="
"$SONDA" --server "http://127.0.0.1:$GRPC_PORT" --n 334 --conc 16 >/dev/null 2>&1 &
SONDA_PID=$!
sleep 2
kill -9 "$SERVIDOR_PID" 2>/dev/null; wait "$SERVIDOR_PID" 2>/dev/null; SERVIDOR_PID=""
kill -9 "$SONDA_PID" 2>/dev/null; wait "$SONDA_PID" 2>/dev/null
ok "servidor morto com SIGKILL a meio da ingestao"
arrancar_medindo || { falha "nao recuperou do SIGKILL"; exit 1; }
relatar "crash"
HEAD=$(campo head_lsn status); WM=$(campo watermark_lsn boot)
[[ -n "$WM" && -n "$HEAD" && "$WM" -le "$HEAD" ]] \
  && ok "watermark=$WM <= head=$HEAD" \
  || falha "watermark=$WM head=$HEAD viola o invariante"
esperar_catchup || falha "nao apanhou a cauda depois do crash"

# ── cenario 5 — divergent boot ───────────────────────────────────────────────

echo
echo "=== Cenario 5 — divergent boot (cursor > head) ==="
parar
CURSOR="$DIR_DADOS/data/log/sentinel/cursor.json"
if [[ -f "$CURSOR" ]]; then
  printf '{"next_lsn": 999999999, "pipeline_version": 1}' > "$CURSOR"
  arrancar_medindo || { falha "nao arrancou com cursor divergente"; exit 1; }
  relatar "divergent"
  DIV=$(campo divergence_total boot)
  [[ "$ULTIMO_RESULTADO" == "rebuild_canonical" ]] \
    && ok "divergencia reconstroi" || falha "veio '$ULTIMO_RESULTADO'"
  [[ "$DIV" == "1" ]] && ok "divergencia contada" || falha "divergence_total=$DIV"
  ls "$DIR_DADOS"/data/log/sentinel/cursor.divergent.*.json >/dev/null 2>&1 \
    && ok "cursor divergente preservado" || falha "artefacto divergente ausente"
  parar
else
  falha "nao ha cursor.json em $CURSOR"
fi

# ── veredicto ────────────────────────────────────────────────────────────────

echo
echo "=== L7 — veredicto ==="
cinza "  dataset: $EVENTOS eventos pedidos (a §37 pede 20.000.000 para a"
cinza "  qualificacao formal; sobe HERACLITUS_L7_EVENTOS para a correr)"
cinza "  base final: ${NOVA_BASE:-?} episodios em $FS"
if (( FALHAS == 0 )); then
  verde "L7 PASSOU"
  exit 0
fi
vermelho "$FALHAS verificacao(oes) falharam"
exit 1
