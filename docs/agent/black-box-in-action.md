# Agent Black Box em acção — runbook

O guião operacional de `black-box-in-action.md`, com o que foi **medido** em
2026-09-14 e não apenas planeado.

> **O que este teste prova, e o que não prova.** Prova que o Heraclitus captura,
> regista e pode controlar as **chamadas de ferramentas MCP** que atravessam o
> Agent Gateway. Não prova captura da actividade interna do Claude Code ou do
> Codex — `Read`, `Edit`, `Write`, `Bash`, `shell` não passam pelo MCP e não são
> capturados. O claim correcto é o primeiro, não o segundo.

---

## 1. O upstream

Verificado ao vivo (§3 manda verificar antes de concluir seja o que for):

| | |
|---|---|
| endpoint | `https://mcp.context7.com/mcp` |
| servidor | Context7 v4.1.1 |
| autenticação | **nenhuma** para `initialize`, `tools/list` e `tools/call` |
| transporte | MCP Streamable HTTP, *stateless* (sem `Mcp-Session-Id`) |
| tools | `resolve-library-id`, `query-docs` — ambas `readOnlyHint: true` |

Duas coisas que mudam o guião:

**O `Accept` tem de levar os dois tipos.** Com `Accept: application/json` apenas,
o Context7 devolve **406**. O cabeçalho correcto é
`Accept: application/json, text/event-stream`.

**Todas as respostas vêm em SSE**, não em JSON:

```text
event: message
data: {"jsonrpc":"2.0","id":1,"result":{...}}
```

Isto não é uma particularidade do Context7 — o DeepWiki, o Cloudflare docs e o
GitMCP fazem o mesmo. Não há upstream MCP HTTP público que responda JSON puro.

## 2. Ligar o gateway

```toml
[agent_black_box]
enabled = true
capture_mode = "metadata_only"      # §19

[agent_black_box.console]
enabled = true
addr = "127.0.0.1:8080"

[agent_gateway]
enabled = true
mode = "observe"                    # observe -> shadow -> enforce, por esta ordem
listen_addr = "127.0.0.1:8787"
upstream_url = "https://mcp.context7.com"

[agent_gateway.policy]
active = "examples/agent-black-box/agent-policy.yaml"
default_decision = "deny"
```

> `upstream_url` é **obrigatório em todos os modos**, `observe` incluído. Antes
> não era, e o resultado era um gateway que arrancava, aceitava ligações, passava
> no healthcheck — e respondia 502 a tudo.

## 3. Testar o gateway sozinho, antes dos clientes

```bash
scripts/test-agent-black-box-mcp.sh --api http://127.0.0.1:8080 \
                                    --gateway http://127.0.0.1:8787 \
                                    --tool resolve-library-id \
                                    --args '{"libraryName":"Express","query":"routing"}'
```

Quando uma demonstração falha com um cliente à frente há três suspeitos — o
cliente, o gateway e o upstream. Este script elimina dois deles antes de alguém
estar a olhar.

Para provar que um `deny` em `enforce` **não toca no upstream** é preciso um
upstream que saiba contar visitas. É para isso que existe
`scripts/mcp-upstream-stub.py`:

```bash
python3 scripts/mcp-upstream-stub.py --port 9911
scripts/test-agent-black-box-mcp.sh --stub http://127.0.0.1:9911 ...
```

O Context7 não tem como responder à pergunta "foste chamado?"; o stub tem
(`/__hits`).

## 4. Os cabeçalhos de correlação

```text
X-Heraclitus-Agent        claude-code | codex      -> agent.agent_id
X-Heraclitus-User         jose                     -> human.subject_id
X-Heraclitus-Server       context7                 -> subject.server_id
X-Heraclitus-Run          run-claude-001           -> run_id
X-Heraclitus-Trace        trace-001                -> trace_id
X-Heraclitus-Environment  development              -> só policy e ecrã de aprovação
```

> **O `X-Heraclitus-Run` não é opcional na prática.** Sem ele (ou sem `-Trace`),
> `effective_run_id()` é `None`, a projecção descarta a evidência, e o ecrã
> **Runs** da Consola fica vazio — mesmo com as tool calls gravadas no log. As
> chamadas continuam a aparecer em `/api/v1/agent/tool-calls`.
>
> E **use um valor diferente por agente**. A chave de deduplicação não inclui o
> `agent_id`: dois agentes com o mesmo `server_id` que reciclem o mesmo `id`
> JSON-RPC — coisa que os clientes MCP fazem, é um contador por sessão —
> produzem a mesma chave, e a evidência do segundo é recusada como `Conflict`.
> A recusa está certa (não se reescreve evidência registada); o que não pode é
> passar despercebida, e por isso agora conta em `evidence_errors` e, em
> `enforce`, faz a chamada falhar com `EVIDENCE_NOT_RECORDED`.

Os `X-Heraclitus-*` **param no gateway** e não seguem para o upstream. Antes
seguiam, e diziam a um terceiro na Internet o nome do utilizador humano.

## 5. Configurar o Claude Code

```bash
claude mcp add --transport http --scope project \
  --header "X-Heraclitus-Agent: claude-code" \
  --header "X-Heraclitus-User: jose" \
  --header "X-Heraclitus-Server: context7" \
  --header "X-Heraclitus-Run: run-claude-001" \
  --header "X-Heraclitus-Environment: development" \
  heraclitus-context7 http://127.0.0.1:8787/mcp

claude mcp list
claude mcp get heraclitus-context7
```

Depois, um prompt que force o uso:

```text
Usa obrigatoriamente o servidor MCP heraclitus-context7 para consultar
documentação actual. Não respondas só com conhecimento interno.
```

> **Não verificado nesta máquina.** O CLI `claude` não está no PATH aqui — só a
> aplicação de desktop, em `AppData\Local\AnthropicClaude`. A sintaxe acima é a
> do `claude mcp add`; confirme-a contra a versão que tiver instalada antes de a
> dar por boa.

## 6. Configurar o Codex

Versão instalada e confirmada aqui: **codex-cli 0.142.0**, com configuração em
`~/.codex/config.toml`, no formato `[mcp_servers.<nome>]`.

```toml
[mcp_servers.heraclitus_context7]
url = "http://127.0.0.1:8787/mcp"

[mcp_servers.heraclitus_context7.http_headers]
"X-Heraclitus-Agent" = "codex"
"X-Heraclitus-User" = "jose"
"X-Heraclitus-Server" = "context7"
"X-Heraclitus-Run" = "run-codex-001"
"X-Heraclitus-Environment" = "development"
```

> **Não aplicado.** O `~/.codex/config.toml` desta máquina é um ficheiro vivo,
> com servidores MCP já configurados. Acrescentar o bloco é decisão do dono da
> máquina, não deste runbook.

## 7. As três fases

```text
observe   não avalia policy, não bloqueia
          evidência: ToolRequested -> ToolInvocationStarted -> ToolInvocationFinished

shadow    avalia, regista, NÃO bloqueia
          acrescenta PolicyEvaluated com `enforced: false`
          um `deny` aparece como decision=deny + enforced=false (é o "would deny")

enforce   avalia e bloqueia
          deny -> ToolDenied + HTTP 403 JSON-RPC, upstream nunca contactado
```

Três coisas que o guião original assume e não se confirmam:

- **Não existe `ToolAuthorized` num `allow` simples.** Só nasce no caminho
  `require_approval`, depois de a aprovação ser consumida. Não o procure na
  demonstração do caso permitido.
- **Não existem rótulos `would_deny`.** O que se lê é `decision: "deny"` com
  `enforced: false`, mais o contador `agent_gateway_shadow_deny_total`.
- **Sem política carregada o default é `deny_all`.** Em `shadow` isso regista
  tudo como negado e deixa passar; em `enforce` bloqueia tudo. É o comportamento
  correcto (fail-closed) e tem de ser dito no relatório, senão parece avaria.

## 8. O ciclo pericial

Com o servidor **a correr**, exportar pela API — a CLI abre o log directamente e
o HRKL não tem trinco entre processos:

```bash
curl -X POST http://localhost:8080/api/v1/agent/evidence/export \
  -H 'Content-Type: application/json' -d '{}'

heraclitus agent verify <bundle>.zip        # 0 VERIFIED · 6 PARTIAL
cp <bundle>.zip adulterado.zip
printf 'X' | dd of=adulterado.zip bs=1 seek=900 conv=notrunc
heraclitus agent verify adulterado.zip      # tem de RECUSAR
```

Medido:

```text
export   9 registos, LSN 0..8, 15 175 bytes
verify   VERDICT: PARTIAL        exit 6   (9 sem prova de inclusão)
tamper   VERDICT: INVALID_BUNDLE exit 2   ("CRC do ZIP não bate")
```

> O §16 esperava `DIGEST_MISMATCH` (3). O que sai é `INVALID_BUNDLE` (2), porque
> o CRC por entrada do ZIP falha **antes** de se chegar aos digests do manifesto.
> A cláusula do §16 admite "outro erro de integridade equivalente" — a
> adulteração é detectada, noutra camada. Para obter literalmente
> `DIGEST_MISMATCH` seria preciso reempacotar o ZIP com um ficheiro editado e o
> CRC recalculado, deixando só o digest do manifesto por bater.

**`PARTIAL` é o resultado correcto e esperado**, não uma avaria: os registos
ainda estão no segmento activo, que não foi selado, e uma prova de inclusão
contra uma raiz que ainda muda não provaria nada. Não existe mecanismo suportado
para forçar a selagem — nem rota HTTP, nem subcomando. O único caminho
não-hack é configurar `segment_max_bytes` pequeno na instância de teste, e mesmo
assim o último registo fica sempre na cauda activa.

## 9. Privacidade

Testado com um canário nos argumentos e no cabeçalho:

```text
Authorization: Bearer sk-ant-...      -> ausente do log
argumento api_key: "sk-live-..."      -> ausente do log
argumento password: "debian23"        -> ausente do log
argumentos libraryName / query        -> presentes (não são segredos)
nome do campo `api_key`               -> presente, com o valor substituído
```

O nome do campo fica de propósito: diz a uma auditoria *"aqui passou um
segredo"* sem o guardar.

## 10. Limites conhecidos

| | |
|---|---|
| Lotes JSON-RPC (array no corpo) | não são reconhecidos: passam sem policy e sem evidência |
| `resources/read`, `prompts/get` | fora da captura — o critério é literalmente `tools/call` |
| Streaming verdadeiro | o gateway bufferiza a resposta inteira; funciona com upstreams que fecham o stream (todos os medidos), não com um que o mantenha aberto |
| `RateLimit` em `enforce` | devolve 429 mas **não** grava `ToolDenied` |
| Corpo > 2 MiB | 413 em texto simples, não erro JSON-RPC, e sem evidência |
| Binding da aprovação | inclui `issued_at`/`expires_at` regenerados a cada pedido: o retry só é aceite no mesmo segundo UNIX |
| `id` JSON-RPC | é sempre devolvido como string; um cliente com ids numéricos recebe `"3"` em vez de `3` |
