#!/usr/bin/env bash
# SPEC-0073 §21 — benchmark A/B do allocator (system vs jemalloc).
#
# A §20 introduz `linux-jemalloc` como EXPERIMENTAL, e a §21 diz o que e preciso
# para ele deixar de o ser: "jemalloc torna-se default Linux somente se houver
# ganho comprovado". O invariante I-5 e mais duro ainda — nenhum fast path se
# torna default "apenas por ser teoricamente mais sofisticado".
#
# Este script produz a comparacao. NAO decide nada: imprime os numeros e o
# veredicto segundo o criterio, e a promocao continua a ser uma decisao humana
# registada num commit.
#
# Ja aconteceu uma vez neste repositorio: o mmap foi implementado, medido,
# perdeu, e ficou deliberadamente desligado (heraclitus-log/src/mmap.rs). E o
# precedente que este script existe para repetir.
#
# Uso: scripts/allocator-ab.sh [eventos-por-modo] [concorrencia]
set -uo pipefail

RAIZ="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
N="${1:-20000}"
CONC="${2:-64}"
TRABALHO="$(mktemp -d)"

REST_PORT=18090
GRPC_PORT=18091

vermelho() { printf '\033[31m%s\033[0m\n' "$*"; }
verde()    { printf '\033[32m%s\033[0m\n' "$*"; }
cinza()    { printf '\033[2m%s\033[0m\n' "$*"; }

limpar() {
  [[ -n "${SERVIDOR_PID:-}" ]] && kill -9 "$SERVIDOR_PID" 2>/dev/null
  rm -rf "$TRABALHO"
}
trap limpar EXIT

if [[ "$(uname -s)" != "Linux" ]]; then
  vermelho "Este benchmark so faz sentido em Linux: o jemalloc so esta ligado la."
  exit 1
fi

# ── infra ────────────────────────────────────────────────────────────────────

config() {
  local dir="$1"
  mkdir -p "$dir/data"
  cat > "$dir/heraclitus.toml" <<TOML
data_dir = "$dir/data"
rest_addr = "127.0.0.1:$REST_PORT"
grpc_addr = "127.0.0.1:$GRPC_PORT"
fsync = { mode = "group_commit", interval_ms = 5 }

[sentinel]
enabled = true
mode = "observe"
worker_threads = 2
TOML
}

arrancar() {
  local bin="$1" dir="$2"
  "$bin" "$dir/heraclitus.toml" > "$dir/stdout.log" 2> "$dir/stderr.log" &
  SERVIDOR_PID=$!
  local fim=$((SECONDS + 120))
  while (( SECONDS < fim )); do
    kill -0 "$SERVIDOR_PID" 2>/dev/null || return 1
    curl -sf "http://127.0.0.1:$REST_PORT/healthz" >/dev/null 2>&1 && return 0
    sleep 0.2
  done
  return 1
}

parar() {
  [[ -z "${SERVIDOR_PID:-}" ]] && return 0
  kill -TERM "$SERVIDOR_PID" 2>/dev/null
  local fim=$((SECONDS + 60))
  while (( SECONDS < fim )); do
    kill -0 "$SERVIDOR_PID" 2>/dev/null || { SERVIDOR_PID=""; return 0; }
    sleep 0.2
  done
  kill -9 "$SERVIDOR_PID" 2>/dev/null
  SERVIDOR_PID=""
}

# RSS em KiB, lido de /proc — a §21 pede RSS e RSS de pico.
rss_kib()      { awk '/^VmRSS:/{print $2}'  "/proc/$SERVIDOR_PID/status" 2>/dev/null; }
rss_pico_kib() { awk '/^VmHWM:/{print $2}'  "/proc/$SERVIDOR_PID/status" 2>/dev/null; }
cpu_ms() {
  # utime+stime em jiffies -> ms.
  local jiffies hz
  jiffies=$(awk '{print $14 + $15}' "/proc/$SERVIDOR_PID/stat" 2>/dev/null)
  hz=$(getconf CLK_TCK 2>/dev/null || echo 100)
  [[ -n "$jiffies" ]] && echo $(( jiffies * 1000 / hz ))
}

# Corre um perfil e imprime "eventos_s rss_kib rss_pico_kib cpu_ms residente_idle_kib".
medir() {
  local bin="$1" etiqueta="$2"
  local dir="$TRABALHO/$etiqueta"
  config "$dir"
  arrancar "$bin" "$dir" || { vermelho "  $etiqueta: nao arrancou"; return 1; }

  local t0 t1 saida
  t0=$(date +%s.%N)
  saida=$("$SONDA" --server "http://127.0.0.1:$GRPC_PORT" --n "$N" --conc "$CONC" 2>&1)
  t1=$(date +%s.%N)

  local rss pico cpu
  rss=$(rss_kib); pico=$(rss_pico_kib); cpu=$(cpu_ms)

  # Residente-apos-idle: a §21 pede-o explicitamente. E onde um allocator que
  # nao devolve memoria ao SO se distingue de um que devolve.
  sleep 10
  local idle
  idle=$(rss_kib)

  local segundos
  segundos=$(echo "$t1 - $t0" | bc -l)
  local eventos_s
  eventos_s=$(echo "3 * $N / $segundos" | bc -l)

  parar
  printf '%.0f %s %s %s %s\n' "$eventos_s" "${rss:-0}" "${pico:-0}" "${cpu:-0}" "${idle:-0}"
}

# ── builds ───────────────────────────────────────────────────────────────────

echo "=== A construir os dois perfis ==="
(cd "$RAIZ" && cargo build --release -p heraclitus-server --locked) || exit 1
cp "$RAIZ/target/release/heraclitus-server" "$TRABALHO/servidor-system"
(cd "$RAIZ" && cargo build --release -p heraclitus-server --features linux-jemalloc --locked) || exit 1
cp "$RAIZ/target/release/heraclitus-server" "$TRABALHO/servidor-jemalloc"
(cd "$RAIZ" && cargo build --release --bin probe_grpc --locked) || exit 1
SONDA="$RAIZ/target/release/probe_grpc"

verde "  dois binarios prontos"

# ── medicao ──────────────────────────────────────────────────────────────────

echo
echo "=== Medicao (n=$N por modo da sonda, concorrencia=$CONC) ==="
LEITURA_SYSTEM=$(medir "$TRABALHO/servidor-system" system) || exit 1
cinza "  system   : $LEITURA_SYSTEM"
LEITURA_JEMALLOC=$(medir "$TRABALHO/servidor-jemalloc" jemalloc) || exit 1
cinza "  jemalloc : $LEITURA_JEMALLOC"

read -r EV_S RSS_S PICO_S CPU_S IDLE_S <<< "$LEITURA_SYSTEM"
read -r EV_J RSS_J PICO_J CPU_J IDLE_J <<< "$LEITURA_JEMALLOC"

echo
printf '%-22s %14s %14s\n' "métrica" "system" "jemalloc"
printf '%-22s %14s %14s\n' "eventos/s"           "$EV_S"   "$EV_J"
printf '%-22s %14s %14s\n' "RSS (KiB)"           "$RSS_S"  "$RSS_J"
printf '%-22s %14s %14s\n' "RSS pico (KiB)"      "$PICO_S" "$PICO_J"
printf '%-22s %14s %14s\n' "CPU (ms)"            "$CPU_S"  "$CPU_J"
printf '%-22s %14s %14s\n' "residente idle (KiB)" "$IDLE_S" "$IDLE_J"

# ── veredicto ────────────────────────────────────────────────────────────────

echo
echo "=== Veredicto segundo a §21 ==="
GANHO=$(echo "scale=4; $EV_J / $EV_S" | bc -l 2>/dev/null || echo 0)
RSS_RACIO=$(echo "scale=4; ${RSS_J:-1} / ${RSS_S:-1}" | bc -l 2>/dev/null || echo 0)
cinza "  throughput jemalloc/system = $GANHO"
cinza "  RSS jemalloc/system        = $RSS_RACIO"

# O mesmo criterio que a §11 usa para o io_uring, aplicado aqui: um ganho
# abaixo do ruido experimental nao justifica complexidade operacional.
if (( $(echo "$GANHO >= 1.10" | bc -l) )) && (( $(echo "$RSS_RACIO <= 1.10" | bc -l) )); then
  verde "  jemalloc GANHA (>=1.10x throughput sem inflar RSS acima de 1.10x)."
  echo "  A promocao a default continua a ser uma decisao HUMANA, registada num"
  echo "  commit que cite estes numeros. Este script nao promove nada."
  exit 0
fi
vermelho "  jemalloc NAO justifica a promocao com estes numeros."
echo "  Fica experimental, como o mmap ficou. Um ganho abaixo do ruido nao paga"
echo "  a complexidade operacional de um segundo allocator em producao."
exit 0
