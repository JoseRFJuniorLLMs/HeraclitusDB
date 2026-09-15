#!/usr/bin/env bash
# black-box-in-action.md §22 — testa o Agent Gateway SEM o Claude Code e SEM o
# Codex.
#
# # Porque é que este script existe antes dos testes manuais
#
# Quando uma demonstração falha com um cliente real à frente, há três suspeitos:
# o cliente, o gateway e o upstream. Sem forma de os separar, descobre-se qual
# foi por eliminação, ao vivo, com alguém a olhar. Este script elimina dois
# deles de antemão.
#
# Por omissão corre contra o stub local (`scripts/mcp-upstream-stub.py`), porque
# um teste cuja primeira condição é "um serviço de terceiros tem de estar de pé"
# não é um teste. Com `--upstream` aponta-se a um servidor MCP real.
#
#     scripts/test-agent-black-box-mcp.sh
#     scripts/test-agent-black-box-mcp.sh --gateway http://127.0.0.1:8787 \
#                                         --api http://127.0.0.1:8080
#
# Só faz LEITURAS e chamadas de ferramentas sem efeitos colaterais. Não arranca
# nem pára serviços: o que ele testa tem de já estar de pé.

set -uo pipefail

GATEWAY="${GATEWAY:-http://127.0.0.1:8787}"
API="${API:-http://127.0.0.1:8080}"
UPSTREAM_DIAG=""        # URL do stub, para perguntar se o upstream foi tocado
TOOL="lookup_vendor"
ARGS='{"vendor":"acme"}'

while [ $# -gt 0 ]; do
  case "$1" in
    --gateway) GATEWAY="$2"; shift 2 ;;
    --api)     API="$2"; shift 2 ;;
    --stub)    UPSTREAM_DIAG="$2"; shift 2 ;;
    --tool)    TOOL="$2"; shift 2 ;;
    --args)    ARGS="$2"; shift 2 ;;
    -h|--help) sed -n '2,25p' "$0"; exit 0 ;;
    *) echo "argumento desconhecido: $1" >&2; exit 2 ;;
  esac
done

PASSOU=0
FALHOU=0
SALTOU=0

ok()      { printf '  \033[32mOK\033[0m    %s\n' "$1"; PASSOU=$((PASSOU+1)); }
falhou()  { printf '  \033[31mFALHA\033[0m %s\n' "$1"; FALHOU=$((FALHOU+1)); }
saltou()  { printf '  \033[33m--\033[0m    %s\n' "$1"; SALTOU=$((SALTOU+1)); }
seccao()  { printf '\n\033[1m%s\033[0m\n' "$1"; }

# Um POST JSON-RPC pelo gateway, com os cabeçalhos de correlação do §5.
# O `Accept` leva os DOIS tipos: o MCP Streamable HTTP exige-o, e um servidor
# real devolve 406 se só pedirmos `application/json`.
mcp() {
  local agente="$1" corpo="$2"
  curl -sS --max-time 60 -X POST "$GATEWAY/mcp" \
    -H 'Content-Type: application/json' \
    -H 'Accept: application/json, text/event-stream' \
    -H "X-Heraclitus-Agent: $agente" \
    -H "X-Heraclitus-Run: run-$agente-$$" \
    -H 'X-Heraclitus-User: teste' \
    -H 'X-Heraclitus-Environment: development' \
    -d "$corpo" 2>/dev/null
}

# O corpo pode vir em JSON puro OU enquadrado em SSE. É a mesma dualidade que o
# extractor do Heraclitus tem de aguentar, por isso o teste não pode assumir uma.
payload() { sed -n 's/^data: //p' | head -1; }
corpo_util() {
  local cru; cru="$(cat)"
  case "$cru" in
    event:*|data:*|:*) printf '%s' "$cru" | payload ;;
    *) printf '%s' "$cru" ;;
  esac
}

contar_evidencias() {
  curl -sS --max-time 30 "$API/api/v1/agent/tool-calls" 2>/dev/null \
    | grep -o '"tool_call_id"' | wc -l | tr -d ' '
}

hits_do_stub() {
  [ -n "$UPSTREAM_DIAG" ] || return 1
  curl -sS --max-time 10 "$UPSTREAM_DIAG/__hits" 2>/dev/null
}

# ── 0. está tudo de pé? ─────────────────────────────────────────────────────
seccao "0. pré-requisitos"

ESTADO="$(curl -sS --max-time 15 "$API/api/v1/agent/status" 2>/dev/null)"
if [ -z "$ESTADO" ]; then
  falhou "a API de evidência não responde em $API — nada mais faz sentido testar"
  echo; echo "Resumo: $PASSOU ok, $FALHOU falhas, $SALTOU saltados"
  exit 1
fi
ok "a API de evidência responde em $API"

MODO="$(printf '%s' "$ESTADO" | grep -o '"mcp_gateway":"[^"]*"' | cut -d'"' -f4)"
CAPTURA="$(printf '%s' "$ESTADO" | grep -o '"mode":"[^"]*"' | head -1 | cut -d'"' -f4)"
ok "gateway em modo ${MODO:-?} · captura ${CAPTURA:-?}"

if [ "$MODO" = "DISABLED" ]; then
  falhou "o gateway está desligado: ponha [agent_gateway] enabled = true"
  echo; echo "Resumo: $PASSOU ok, $FALHOU falhas, $SALTOU saltados"
  exit 1
fi

# ── 1. handshake ────────────────────────────────────────────────────────────
seccao "1. handshake MCP através do gateway"

INIT="$(mcp probe '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"heraclitus-selftest","version":"1"}}}' | corpo_util)"
case "$INIT" in
  *'"protocolVersion"'*) ok "initialize atravessou o gateway até ao upstream" ;;
  "") falhou "initialize não devolveu nada — o gateway ou o upstream estão em baixo" ;;
  *) falhou "initialize devolveu algo inesperado: $(printf '%s' "$INIT" | head -c 160)" ;;
esac

LISTA="$(mcp probe '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' | corpo_util)"
case "$LISTA" in
  *'"tools"'*) ok "tools/list devolveu o catálogo do upstream" ;;
  *) falhou "tools/list falhou: $(printf '%s' "$LISTA" | head -c 160)" ;;
esac

if printf '%s' "$LISTA" | grep -q "\"$TOOL\""; then
  ok "a tool de teste \`$TOOL\` existe no upstream"
else
  saltou "a tool \`$TOOL\` NÃO está no tools/list — use --tool com um nome real"
fi

# ── 2. o que NÃO deve virar evidência (§7) ──────────────────────────────────
seccao "2. tráfego de protocolo não polui a evidência (§7)"

ANTES="$(contar_evidencias)"
mcp probe '{"jsonrpc":"2.0","id":3,"method":"ping"}' >/dev/null
mcp probe '{"jsonrpc":"2.0","id":4,"method":"tools/list"}' >/dev/null
sleep 1
DEPOIS="$(contar_evidencias)"
if [ "$ANTES" = "$DEPOIS" ]; then
  ok "ping e tools/list não geraram evidência (continua em $DEPOIS)"
else
  falhou "o ruído de protocolo entrou na evidência: $ANTES -> $DEPOIS"
fi

# ── 3. o que DEVE virar evidência ───────────────────────────────────────────
seccao "3. tools/call gera evidência (§10, §14)"

ANTES="$DEPOIS"
CHAMADA="$(mcp selftest "{\"jsonrpc\":\"2.0\",\"id\":\"sf-$$\",\"method\":\"tools/call\",\"params\":{\"name\":\"$TOOL\",\"arguments\":$ARGS}}" | corpo_util)"
sleep 1
DEPOIS="$(contar_evidencias)"
if [ "$DEPOIS" -gt "$ANTES" ]; then
  ok "a tool call ficou registada ($ANTES -> $DEPOIS)"
else
  falhou "a tool call NÃO deixou evidência ($ANTES -> $DEPOIS): $(printf '%s' "$CHAMADA" | head -c 200)"
fi

case "$CHAMADA" in
  *'"result"'*) ok "o upstream respondeu e a semântica MCP foi preservada" ;;
  *'"error"'*)  saltou "o upstream devolveu erro JSON-RPC (pode ser esperado): $(printf '%s' "$CHAMADA" | head -c 160)" ;;
  *) falhou "resposta irreconhecível: $(printf '%s' "$CHAMADA" | head -c 160)" ;;
esac

# ── 4. LSN real (§14) ───────────────────────────────────────────────────────
seccao "4. a evidência tem LSN real do HRKL (§14)"

ULTIMO="$(curl -sS --max-time 30 "$API/api/v1/agent/tool-calls" 2>/dev/null \
  | grep -o '01[A-Z0-9]\{24\}' | tail -1)"
if [ -n "$ULTIMO" ]; then
  DETALHE="$(curl -sS --max-time 30 "$API/api/v1/agent/evidence/$ULTIMO" 2>/dev/null)"
  if printf '%s' "$DETALHE" | grep -q '"lsn"'; then
    LSN="$(printf '%s' "$DETALHE" | grep -o '"lsn":[0-9]*' | head -1 | cut -d: -f2)"
    ok "evidência $ULTIMO gravada no LSN $LSN"
  else
    falhou "a evidência $ULTIMO não tem LSN — não foi persistida no log"
  fi
  PROVA="$(printf '%s' "$DETALHE" | grep -o '"state":"[^"]*"' | head -1 | cut -d'"' -f4)"
  case "$PROVA" in
    available)    ok "prova de inclusão disponível" ;;
    pending_seal) ok "prova PENDENTE de selagem — correcto enquanto o segmento estiver activo" ;;
    *)            saltou "estado da prova: ${PROVA:-?}" ;;
  esac
else
  falhou "não consegui ler nenhum id de evidência da API"
fi

# ── 5. segredos não são persistidos (§19) ───────────────────────────────────
seccao "5. um segredo nos argumentos não chega ao log (§19)"

CANARIO="sk-live-CANARIO-$$-NAO-PODE-FICAR"
mcp selftest "{\"jsonrpc\":\"2.0\",\"id\":\"sec-$$\",\"method\":\"tools/call\",\"params\":{\"name\":\"$TOOL\",\"arguments\":{\"api_key\":\"$CANARIO\"}}}" >/dev/null
sleep 1
FUGA=0
for id in $(curl -sS --max-time 30 "$API/api/v1/agent/tool-calls" 2>/dev/null | grep -o '01[A-Z0-9]\{24\}' | sort -u); do
  if curl -sS --max-time 15 "$API/api/v1/agent/evidence/$id" 2>/dev/null | grep -qF "$CANARIO"; then
    FUGA=1
    break
  fi
done
if [ "$FUGA" = "0" ]; then
  ok "o canário não aparece em nenhuma evidência"
else
  falhou "FUGA: o valor de \`api_key\` foi persistido num log append-only"
fi

# ── 6. enforce + deny não toca no upstream (§13) ────────────────────────────
seccao "6. enforce: um deny nunca chega ao upstream (§13)"

if [ "$MODO" != "ENFORCE" ]; then
  saltou "gateway em $MODO — este teste só é conclusivo em enforce"
elif [ -z "$UPSTREAM_DIAG" ]; then
  saltou "sem --stub não há como PROVAR que o upstream não foi tocado"
else
  curl -sS --max-time 10 "$UPSTREAM_DIAG/__reset" >/dev/null 2>&1
  NEGADA="$(mcp selftest "{\"jsonrpc\":\"2.0\",\"id\":\"dn-$$\",\"method\":\"tools/call\",\"params\":{\"name\":\"apagar_tudo\",\"arguments\":{}}}" | corpo_util)"
  case "$NEGADA" in
    *'"error"'*) ok "o cliente recebeu um erro JSON-RPC válido" ;;
    *) falhou "um deny devia devolver erro JSON-RPC: $(printf '%s' "$NEGADA" | head -c 160)" ;;
  esac
  HITS="$(hits_do_stub)"
  if printf '%s' "$HITS" | grep -q 'tools/call'; then
    falhou "o upstream FOI contactado apesar do deny: $HITS"
  else
    ok "o upstream não foi contactado (hits: ${HITS:-{}})"
  fi
fi

# ── 7. o ciclo pericial (§15, §16) ──────────────────────────────────────────
seccao "7. Evidence Bundle: exportar, verificar, adulterar (§15, §16)"

EXPORT="$(curl -sS --max-time 120 -X POST "$API/api/v1/agent/evidence/export" \
  -H 'Content-Type: application/json' -d '{}' 2>/dev/null)"
FICHEIRO="$(printf '%s' "$EXPORT" | grep -o '"file":"[^"]*"' | cut -d'"' -f4)"
if [ -n "$FICHEIRO" ]; then
  REGISTOS="$(printf '%s' "$EXPORT" | grep -o '"records":[0-9]*' | cut -d: -f2)"
  ok "bundle exportado: $FICHEIRO ($REGISTOS registos)"
  echo "        verifique-o com:  heraclitus agent verify <caminho>/$FICHEIRO"
  echo "        e adultere-o com: printf 'X' | dd of=<copia> bs=1 seek=900 conv=notrunc"
  echo "        o verify TEM de recusar (INVALID_BUNDLE/2 ou DIGEST_MISMATCH/3)"
else
  falhou "a exportação falhou: $(printf '%s' "$EXPORT" | head -c 200)"
fi

# ── resumo ──────────────────────────────────────────────────────────────────
printf '\n\033[1mResumo:\033[0m %d ok, %d falhas, %d saltados\n' "$PASSOU" "$FALHOU" "$SALTOU"
[ "$FALHOU" -eq 0 ] || exit 1
exit 0
