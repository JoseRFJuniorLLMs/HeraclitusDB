#!/usr/bin/env bash
# SPEC-0072 §29-§36 — qualificacao OPERACIONAL do arranque em Linux.
#
# A §29 diz-o em uma linha: "CI Linux existente nao e qualificacao operacional".
# O `cargo test` prova a logica; nao prova que um PROCESSO arranca, serve,
# recebe SIGTERM, morre de SIGKILL e volta. Sao coisas diferentes, e so a
# segunda apanha um `TimeoutStartSec` mal posto, um cursor que nao sobrevive ao
# reinicio, ou um snapshot que nunca chega a ser lido.
#
# Gates: L0 build, L1 smoke, L2 persisted restart, L3 SIGKILL, L4 stale cursor,
#        L5 corrupt cursor, L6 corrupt snapshot.
#
# Uso: scripts/linux-gates.sh [caminho-do-binario]
# Sem argumento, compila em release.
set -uo pipefail

RAIZ="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TRABALHO="$(mktemp -d)"
BIN="${1:-}"
FALHAS=0
GATE_ACTUAL="(nenhum)"

vermelho() { printf '\033[31m%s\033[0m\n' "$*"; }
verde()    { printf '\033[32m%s\033[0m\n' "$*"; }
cinza()    { printf '\033[2m%s\033[0m\n' "$*"; }

gate() { GATE_ACTUAL="$1"; printf '\n=== %s ===\n' "$1"; }

ok()   { verde   "  [ OK ] $1"; }
falha() { vermelho "  [FALHA] $GATE_ACTUAL: $1"; FALHAS=$((FALHAS + 1)); }

limpar() {
  # Nao deixar servidores vivos se o script morrer a meio.
  [[ -n "${SERVIDOR_PID:-}" ]] && kill -9 "$SERVIDOR_PID" 2>/dev/null
  rm -rf "$TRABALHO"
}
trap limpar EXIT

# ── infra ────────────────────────────────────────────────────────────────────

REST_PORT=18080
GRPC_PORT=18081

escrever_config() {
  local dir="$1" extra="${2:-}"
  cat > "$dir/heraclitus.toml" <<TOML
data_dir = "$dir/data"
rest_addr = "127.0.0.1:$REST_PORT"
grpc_addr = "127.0.0.1:$GRPC_PORT"
fsync = "always"

[sentinel]
enabled = true
mode = "observe"
worker_threads = 1
$extra
TOML
}

# Arranca o servidor e espera que o REST responda. Devolve 1 se nao arrancar.
arrancar() {
  local dir="$1" prazo="${2:-60}"
  "$BIN" "$dir/heraclitus.toml" > "$dir/stdout.log" 2> "$dir/stderr.log" &
  SERVIDOR_PID=$!
  local fim=$((SECONDS + prazo))
  while (( SECONDS < fim )); do
    if ! kill -0 "$SERVIDOR_PID" 2>/dev/null; then
      return 1
    fi
    if curl -sf "http://127.0.0.1:$REST_PORT/healthz" >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.2
  done
  return 1
}

# Para com SIGTERM e espera. Devolve 1 se nao morrer a tempo.
parar() {
  local prazo="${1:-30}"
  [[ -z "${SERVIDOR_PID:-}" ]] && return 0
  kill -TERM "$SERVIDOR_PID" 2>/dev/null
  local fim=$((SECONDS + prazo))
  while (( SECONDS < fim )); do
    kill -0 "$SERVIDOR_PID" 2>/dev/null || { SERVIDOR_PID=""; return 0; }
    sleep 0.2
  done
  kill -9 "$SERVIDOR_PID" 2>/dev/null
  SERVIDOR_PID=""
  return 1
}

matar() {
  [[ -z "${SERVIDOR_PID:-}" ]] && return 0
  kill -9 "$SERVIDOR_PID" 2>/dev/null
  wait "$SERVIDOR_PID" 2>/dev/null
  SERVIDOR_PID=""
}

# Os appends vao por gRPC porque nao ha rota REST de escrita, e inventar uma
# so para o teste mediria um caminho que producao nao usa. A sonda faz tres
# passagens de `--n` eventos cada, portanto entram ~3n.
appendar() {
  local n="$1"
  "$SONDA" --server "http://127.0.0.1:$GRPC_PORT" --n "$n" >/dev/null 2>&1
}

boot_json() { curl -sf "http://127.0.0.1:$REST_PORT/sentinel/status" 2>/dev/null; }

campo_boot() {
  # $1 = nome do campo dentro de `boot`. Sem jq: o CI nao o garante.
  boot_json | python3 -c "
import json,sys
try:
    d = json.load(sys.stdin)
except Exception:
    print(''); raise SystemExit
b = d.get('boot') or {}
print(b.get('$1', ''))
" 2>/dev/null
}

# ── L0 — build ───────────────────────────────────────────────────────────────

gate "L0 — build release"
if [[ -z "$BIN" ]]; then
  if (cd "$RAIZ" && cargo build --release -p heraclitus-server --locked); then
    BIN="$RAIZ/target/release/heraclitus-server"
    ok "servidor compilado"
  else
    falha "cargo build --release falhou"
    echo; vermelho "L0 falhou; os restantes gates dependem do binario."; exit 1
  fi
else
  ok "binario fornecido: $BIN"
fi
[[ -x "$BIN" ]] || { falha "binario nao executavel: $BIN"; exit 1; }

# A sonda gRPC e o unico escritor disponivel: nao ha rota REST de append.
SONDA="$RAIZ/target/release/probe_grpc"
if [[ ! -x "$SONDA" ]]; then
  if (cd "$RAIZ" && cargo build --release --bin probe_grpc --locked); then
    ok "sonda gRPC compilada"
  else
    falha "nao foi possivel compilar a sonda gRPC (probe_grpc)"
    echo
    vermelho "Sem escritor nao ha como pôr eventos no log, e os gates L2-L6"
    vermelho "passariam sobre uma base VAZIA — verdes e sem significado."
    exit 1
  fi
fi

# ── L1 — smoke ───────────────────────────────────────────────────────────────

gate "L1 — server smoke"
D1="$TRABALHO/l1"; mkdir -p "$D1/data"; escrever_config "$D1"
if arrancar "$D1"; then
  ok "processo vivo e REST responde"
  if appendar 3; then ok "append por gRPC funciona"; else falha "append falhou"; fi
  if curl -sf "http://127.0.0.1:$REST_PORT/sentinel/status" >/dev/null; then
    ok "query de estado funciona"
  else
    falha "/sentinel/status nao responde"
  fi
  if parar; then ok "SIGTERM desliga graciosamente"; else falha "SIGTERM nao desligou dentro do prazo"; fi
  if arrancar "$D1"; then ok "reinicio funciona"; parar; else falha "nao reiniciou"; fi
else
  falha "nao arrancou"
  cinza "$(tail -20 "$D1/stderr.log" 2>/dev/null)"
fi

# ── L2 — persisted restart ───────────────────────────────────────────────────

gate "L2 — persisted restart (INV-5)"
D2="$TRABALHO/l2"; mkdir -p "$D2/data"; escrever_config "$D2"
if arrancar "$D2"; then
  appendar 70 || falha "appends falharam"   # ~210 eventos
  sleep 2   # deixa o Sentinel apanhar a cauda
  TOTAL=$(campo_boot head_at_boot_lsn)
  parar || falha "SIGTERM nao desligou"
  if arrancar "$D2"; then
    LIDOS=$(campo_boot events_scanned_total)
    RESULTADO=$(campo_boot outcome)
    cinza "  segundo arranque: outcome=$RESULTADO lidos=$LIDOS (base tinha >=200)"
    if [[ -n "$LIDOS" && "$LIDOS" -lt 200 ]]; then
      ok "second_boot_events_scanned << total_events ($LIDOS < 200)"
    else
      falha "o segundo arranque leu $LIDOS episodios; devia ler a cauda, nao a base"
    fi
    parar
  else
    falha "nao reiniciou"
  fi
else
  falha "nao arrancou"
fi

# ── L3 — SIGKILL ─────────────────────────────────────────────────────────────

gate "L3 — SIGKILL e recuperacao"
D3="$TRABALHO/l3"; mkdir -p "$D3/data"; escrever_config "$D3"
if arrancar "$D3"; then
  appendar 20 || falha "appends falharam"   # ~60 eventos
  matar
  ok "processo morto com SIGKILL"
  if arrancar "$D3"; then
    ok "arranca depois do SIGKILL"
    HEAD=$(campo_boot head_at_boot_lsn)
    WM=$(campo_boot watermark_lsn)
    if [[ -n "$HEAD" && -n "$WM" && "$WM" -le "$HEAD" ]]; then
      ok "cursor/watermark <= head apos recovery ($WM <= $HEAD)"
    else
      falha "watermark=$WM head=$HEAD viola o invariante"
    fi
    parar
  else
    falha "nao recuperou de um SIGKILL"
    cinza "$(tail -20 "$D3/stderr.log" 2>/dev/null)"
  fi
else
  falha "nao arrancou"
fi

# ── L4 — stale cursor ────────────────────────────────────────────────────────

gate "L4 — cursor alem do head"
D4="$TRABALHO/l4"; mkdir -p "$D4/data"; escrever_config "$D4"
if arrancar "$D4"; then
  appendar 10 || falha "appends falharam"
  sleep 1
  parar
  CURSOR="$D4/data/sentinel/cursor.json"
  if [[ -f "$CURSOR" ]]; then
    printf '{"next_lsn": 100000, "pipeline_version": 1}' > "$CURSOR"
    if arrancar "$D4"; then
      RESULTADO=$(campo_boot outcome)
      DIVERG=$(campo_boot divergence_total)
      AHEAD=$(campo_boot cursor_ahead_total)
      cinza "  outcome=$RESULTADO divergencias=$DIVERG cursor_ahead=$AHEAD"
      [[ "$RESULTADO" == "rebuild_canonical" ]] \
        && ok "sob 'rebuild' a divergencia reconstroi" \
        || falha "esperava rebuild_canonical, veio '$RESULTADO'"
      [[ "$DIVERG" == "1" ]] && ok "divergencia contada" || falha "divergence_total=$DIVERG"
      [[ "$AHEAD" == "1" ]] && ok "cursor_ahead contado" || falha "cursor_ahead_total=$AHEAD"
      ls "$D4"/data/sentinel/cursor.divergent.*.json >/dev/null 2>&1 \
        && ok "artefacto divergente preservado" \
        || falha "o cursor divergente nao foi preservado"
      parar
    else
      falha "nao arrancou sob a politica 'rebuild' (o default)"
    fi

    # A mesma divergencia sob `strict` tem de RECUSAR.
    printf '{"next_lsn": 100000, "pipeline_version": 1}' > "$CURSOR"
    escrever_config "$D4" "
[sentinel.recovery]
cursor_policy = \"strict\""
    if arrancar "$D4" 20; then
      falha "sob 'strict' o arranque devia ter sido recusado"
      parar
    else
      ok "sob 'strict' o arranque e recusado"
    fi
  else
    falha "nao ha cursor.json para adulterar em $CURSOR"
  fi
else
  falha "nao arrancou"
fi

# ── L5/L6 — artefactos corrompidos ───────────────────────────────────────────

gate "L5/L6 — cursor e snapshot corrompidos"
D5="$TRABALHO/l5"; mkdir -p "$D5/data"; escrever_config "$D5"
if arrancar "$D5"; then
  appendar 10 || falha "appends falharam"
  sleep 1
  parar
  CURSOR="$D5/data/sentinel/cursor.json"
  SNAP="$D5/data/sentinel/state.snapshot"

  for caso in vazio truncado invalido mismatch; do
    case "$caso" in
      vazio)     : > "$CURSOR" ;;
      truncado)  printf '{"next_lsn": 4, "pipeline_ver' > "$CURSOR" ;;
      invalido)  printf 'isto nao e json' > "$CURSOR" ;;
      mismatch)  printf '{"next_lsn": 4, "pipeline_version": 99}' > "$CURSOR" ;;
    esac
    if arrancar "$D5" 30; then
      ok "cursor $caso: arranca sem inventar estado"
      parar
    else
      falha "cursor $caso: o servidor nao arrancou"
    fi
  done

  if [[ -f "$SNAP" ]]; then
    # Um byte trocado no fim do corpo: digest invalido.
    printf '\xff' | dd of="$SNAP" bs=1 seek=$(( $(stat -c%s "$SNAP") - 1 )) conv=notrunc status=none
    if arrancar "$D5" 60; then
      RESULTADO=$(campo_boot outcome)
      CORRUPTOS=$(campo_boot snapshot_corrupt_total)
      cinza "  outcome=$RESULTADO snapshot_corrupt=$CORRUPTOS"
      [[ "$RESULTADO" == "rebuild_canonical" ]] \
        && ok "snapshot corrompido -> rebuild canonico" \
        || falha "esperava rebuild_canonical, veio '$RESULTADO'"
      [[ "$CORRUPTOS" == "1" ]] && ok "corrupcao contada" || falha "snapshot_corrupt_total=$CORRUPTOS"
      parar
    else
      falha "um snapshot corrompido impediu o arranque; devia ser descartado"
    fi
  else
    falha "nao ha state.snapshot para corromper — o snapshot nunca foi publicado"
  fi
else
  falha "nao arrancou"
fi

# ── veredicto ────────────────────────────────────────────────────────────────

echo
if (( FALHAS == 0 )); then
  verde "TODOS OS GATES LINUX PASSARAM"
  exit 0
fi
vermelho "$FALHAS verificacao(oes) falharam"
exit 1
