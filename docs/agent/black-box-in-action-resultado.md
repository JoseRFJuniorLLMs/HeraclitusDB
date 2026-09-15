# black-box-in-action — resultado da execução

Execução de `black-box-in-action.md` em **2026-09-14**, na máquina de
desenvolvimento (Windows 11, instância isolada nas portas 18080/18787/19474).

O §25 pede comandos exactos, versões, run ids, LSNs e limitações. Está tudo
abaixo, incluindo o que **não** foi feito.

---

## 1. Veredicto

O plano encontrou **dois defeitos sérios no produto**. Ambos corrigidos, com
testes de regressão, e verificados contra um servidor MCP real.

| | |
|---|---|
| Upstream real | `https://mcp.context7.com/mcp` — Context7 v4.1.1, sem autenticação |
| Upstream local | `scripts/mcp-upstream-stub.py` — para contar visitas |
| Codex CLI | 0.142.0 (instalado, **não** configurado) |
| Claude Code CLI | **não está no PATH** desta máquina |

---

## 2. Os dois defeitos

### 2.1 Argumentos de `tools/call` persistidos em claro

`gateway.rs` inseria os argumentos directamente em `content.fields`, **sem
passar pelo portão de privacidade** — em qualquer `capture_mode`, incluindo
`metadata_only` — enquanto o envelope declarava `redaction_applied: false`.

O contraste que revela o erro: o *preview* da tela de aprovação, que é efémero,
**passava** pelo portão (`preview_fields`). O permanente ficava em claro e o
efémero protegido, ao contrário. E propagava para o Evidence Bundle exportado.

Num log append-only, um `api_key` ali não sai: corrige-se acrescentando, e a
versão anterior fica.

**Correcção:** `argumentos_para_persistir()`, com nome, para tornar visível qual
é o caminho de escrita. O `canonical_content_hash` continua a ser calculado
sobre os argumentos **crus** — é ele que liga uma aprovação a uma execução
exacta, e redigir o que se mostra não pode mudar aquilo a que a autorização se
vincula.

**Testes:** `crates/heraclitus-agent-gateway/tests/mcp_privacy.rs` (3).

### 2.2 `protocol_status: "ok"` numa chamada que falhou

`mcp::extract_facts` fazia `serde_json::from_slice` dentro de um `if let Ok`. Um
corpo que não fosse JSON puro falhava o parse **em silêncio**: `is_error` ficava
`false`, e uma tool call recusada pelo upstream era gravada como sucesso.

Não é um caso de canto. O MCP Streamable HTTP permite responder em
`text/event-stream`, e **nenhum** dos servidores MCP HTTP públicos testados
responde outra coisa:

```text
Context7          text/event-stream
DeepWiki          text/event-stream
Cloudflare docs   text/event-stream
GitMCP            text/event-stream
```

Ou seja: contra qualquer upstream real, o black box registava fracassos como
sucessos. Para um produto cuja frase é *"saiba exactamente o que o seu agente
fez"*, é a pior falha possível — não perde o registo, escreve o contrário.

**Correcção:** `payload_jsonrpc()` lê os dois enquadramentos (JSON puro e SSE,
com CRLF, múltiplos eventos e comentários de keep-alive). Um corpo ilegível não
inventa erro nenhum.

**Testes:** 6 em `crates/heraclitus-agent/src/mcp.rs`, com enquadramentos
medidos nos servidores reais.

Verificado ao vivo, através do gateway, contra o Context7:

```text
tool=resolve-library-id     status=ok      run=run-claude-001
tool=tool-que-nao-existe    status=error   run=run-codex-001    <- dizia "ok"
```

---

## 3. Mais quatro correcções

| | |
|---|---|
| `X-Heraclitus-*` iam para o upstream | diziam `X-Heraclitus-User: jose` a um terceiro na Internet. Agora param no gateway. |
| `observe` sem `upstream_url` | arrancava, aceitava ligações, passava no healthcheck e dava 502 a tudo. Agora é erro de arranque em qualquer modo. |
| Falha a gravar evidência era silenciosa | ia para um contador partilhado com erros de policy, a evidência desaparecia, **e a chamada seguia para o upstream**. |
| `evidence_errors` | contador próprio, exposto em `/api/v1/agent/status`. |

### Fail-closed em `enforce`

O produto promete que nada acontece sem ficar registado. Executar uma acção cujo
registo falhou desmente exactamente essa promessa. Agora, em `enforce`, uma
evidência que não grava faz a chamada falhar com `EVIDENCE_NOT_RECORDED`.

`observe` e `shadow` prometem o contrário — nunca bloquear — por isso aí a falha
é ruidosa (log + contador + `/status`) mas não trava nada. **Silenciosa é que
não pode ser em modo nenhum.**

Medido:

```text
tentativa 1   HTTP 200   upstream tocado 1x, 4 eventos gravados
tentativa 2   HTTP 500   -32003, upstream NÃO tocado
tentativa 3   HTTP 500   -32003, upstream NÃO tocado
evidence_errors: 2   conflicts: 2   events: 4
```

Antes: as tentativas 2 e 3 davam 200, chamavam o upstream de novo, e a evidência
desaparecia sem deixar rasto.

---

## 4. Checklist do §24

| § | item | estado |
|---|---|---|
| 24 | Heraclitus inicia com Agent Gateway habilitado | **OK** |
| 24 | `:8787` aceita MCP HTTP | **OK** |
| 24 | upstream MCP real funciona através do proxy | **OK** — Context7 |
| 24 | Claude Code usa o upstream através do Heraclitus | **não feito** — CLI ausente |
| 24 | Codex usa o upstream através do Heraclitus | **não feito** — config não aplicada |
| 24 | chamadas aparecem como `agent=claude-code` | **OK** — simulado por cabeçalho |
| 24 | chamadas aparecem como `agent=codex` | **OK** — simulado por cabeçalho |
| 24 | `tools/call` gera evidência persistida no HRKL | **OK** — LSN real |
| 24 | `initialize`/`tools/list`/`ping` não poluem | **OK** |
| 24 | observe regista e não bloqueia | **OK** |
| 24 | shadow avalia e não bloqueia | **OK** — `decision=deny`, `enforced=false`, upstream tocado |
| 24 | enforce permite uma acção autorizada | **OK** — 200, upstream tocado 1x |
| 24 | enforce bloqueia uma acção negada | **OK** — 403, upstream **não** tocado |
| 24 | argumentos/digest conforme capture mode | **OK** (depois da correcção 2.1) |
| 24 | tokens/segredos não aparecem na evidência | **OK** (depois da correcção 2.1) |
| 24 | LSN real é atribuído | **OK** |
| 24 | Evidence Bundle é exportável | **OK** |
| 24 | bundle válido passa no verifier | **PARCIAL** — `PARTIAL`, ver §6 |
| 24 | bundle adulterado falha no verifier | **OK** — `INVALID_BUNDLE` |
| 24 | sem regressão nos testes existentes | **OK** |

### O script do §22

`scripts/test-agent-black-box-mcp.sh`, em `enforce`:

```text
14 ok, 0 falhas, 0 saltados
```

---

## 5. O que os agentes fizeram (§10, §17)

```text
STARTED       AGENT         USER   TOOLS  APPROVALS  DENIED  STATUS    INTEGRITY
03:04:43 PM   codex         jose   1      0          0       running   UNVERIFIED
03:04:41 PM   claude-code   jose   2      0          0       running   UNVERIFIED
```

Run ids: `run-claude-001`, `run-codex-001`. Bundle exportado:
`evidence-01M2GHGTEWEH2Y8NFQ9TEQ97GG.zip`, 9 registos, LSN 0..8, 15 175 bytes.

---

## 6. Onde o plano não bate certo com a realidade

Nenhum destes é defeito — são pressupostos do documento que o código não
partilha, e a demonstração tem de os conhecer.

**`Duplicate` é inalcançável pelo gateway MCP (§18).** O hash canónico inclui o
`evidence_id` (ULID novo) e `observed_at_unix_nanos`, por isso um retry idêntico
dá sempre `Conflict`, nunca `Duplicate`. O comportamento que o §18 descreve só se
observa no caminho OTLP. O espírito — não reescrever evidência em silêncio — está
satisfeito, e agora é ruidoso.

**A `dedupe_key` não inclui o `agent_id`.** Dois agentes com o mesmo `server_id`
que reciclem o mesmo `id` JSON-RPC produzem a mesma chave, e a evidência do
segundo é recusada. Acrescentar `agent_id` seria o correcto, mas muda uma
identidade canónica publicada na v2.0.0 (quebra os golden vectors e muda os
`evidence_id` do caminho OTLP), por isso **não foi feito**. A mitigação é mandar
um `X-Heraclitus-Run` distinto por agente — e a colisão, que antes desaparecia
em silêncio, passou a contar em `evidence_errors` e a falhar em `enforce`.

**Não existe `ToolAuthorized` num `allow` simples (§13).** Só nasce no caminho
`require_approval`, depois de a aprovação ser consumida.

**Não existem rótulos `would_deny` (§11).** Lê-se `decision: "deny"` com
`enforced: false`.

**O bundle intacto dá `PARTIAL`, não `VERIFIED` (§15).** Os registos estão no
segmento activo, que não foi selado, e uma prova de inclusão contra uma raiz que
ainda muda não provaria nada. **Não existe mecanismo suportado para forçar a
selagem** — nem rota HTTP, nem subcomando, nem no encerramento. O §15 aceita
este resultado; o guião da demonstração tem de o dizer em voz alta.

**O bundle adulterado dá `INVALID_BUNDLE` (2), não `DIGEST_MISMATCH` (3) (§16).**
O CRC por entrada do ZIP falha antes de se chegar aos digests do manifesto. A
adulteração é detectada — noutra camada. O §16 admite "outro erro de integridade
equivalente".

**O binding da aprovação humana é praticamente inutilizável (§13).** Inclui
`issued_at`/`expires_at`, que o gateway regenera a cada pedido, e ambos entram no
`subject_hash`. Um retry com argumentos idênticos produz um hash diferente e
falha com `APPROVAL_BINDING_MISMATCH` — salvo se cair no **mesmo segundo UNIX**.
**Não corrigido**, e a demonstração de `REQUIRE_APPROVAL` não deve ser feita
antes disso.

---

## 7. O que NÃO foi feito

- **§6 / §7 — Claude Code.** O CLI `claude` não está no PATH desta máquina (só a
  aplicação de desktop). A configuração está escrita em
  `docs/agent/black-box-in-action.md` §5, por confirmar contra a versão instalada.
- **§8 / §9 — Codex.** Codex CLI 0.142.0 está instalado, mas
  `~/.codex/config.toml` é um ficheiro vivo com servidores MCP já configurados.
  O bloco está escrito; aplicá-lo é decisão do dono da máquina.
- **§13 — aprovação humana.** Bloqueado pelo binding acima.
- **§21 — captura nativa dos coding agents.** Fora do âmbito, como o próprio
  documento diz.

O §20 continua a valer, e é o claim honesto:

> O Heraclitus captura, regista e pode controlar as chamadas de ferramentas MCP
> que passam pelo Agent Gateway.

Não "captura total do agente". `Read`, `Edit`, `Write`, `Bash` e o `shell` do
Codex não passam pelo MCP e não são capturados.

---

## 8. Limites conhecidos, herdados

| | |
|---|---|
| Lotes JSON-RPC (array no corpo) | não reconhecidos: passam sem policy e sem evidência |
| `resources/read`, `prompts/get` | fora da captura — o critério é literalmente `tools/call` |
| Streaming verdadeiro | a resposta é bufferizada inteira; funciona com upstreams que fecham o stream |
| `RateLimit` em `enforce` | devolve 429 sem gravar `ToolDenied` |
| Corpo > 2 MiB | 413 em texto simples, não erro JSON-RPC, sem evidência |
| `id` JSON-RPC | devolvido sempre como string |
