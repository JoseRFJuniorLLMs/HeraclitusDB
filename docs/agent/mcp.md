# MCP — captura e gateway

SPEC-0074 §13 e SPEC-0075 §5.

Compatível com o core do Model Context Protocol `2026-07-28`, HTTP.

## Dois modos

```text
observe   o host emite metadados; o Heraclitus normaliza
proxy     Agent -> Heraclitus MCP Gateway -> MCP Server
```

Na SPEC-0074 o proxy existe **para evidência**. Bloquear pertence à SPEC-0075 e
acontece no mesmo proxy, quando o gateway está em `enforce`.

## Ligar

```toml
[agent_gateway]
enabled = true
mode = "shadow"                       # observe -> shadow -> enforce
listen_addr = "0.0.0.0:8787"
upstream_url = "http://mcp-finance.interno:9000"

[agent_gateway.policy]
active = "/etc/heraclitus/agent-policy.yaml"
```

Depois aponte o agente a `http://heraclitus:8787` em vez de ao servidor MCP.

## O que é capturado

```text
Mcp-Method    Mcp-Name    Mcp-Session-Id    Mcp-Protocol-Version
request id    tool name   server identity   duration   result status
```

E, do corpo JSON-RPC: o nome da ferramenta, os argumentos tipados e, da
resposta, `isError` e os identificadores de efeito externo.

**Nunca** o bearer token. Os cabeçalhos passam pelo mesmo portão de privacidade
que tudo o resto (ver [`privacy.md`](privacy.md)).

## Correlação

Cada chamada produz o trio, correlacionado por `tool_call_id`:

```text
ToolRequested
    -> ToolInvocationStarted
        -> ToolInvocationFinished
```

Sem essa correlação a Consola mostraria três linhas soltas e o utilizador teria
de as juntar com os olhos.

Com o gateway a avaliar policy, entram também `PolicyEvaluated`,
`HumanApprovalRequested`, `HumanApprovalGranted`/`Denied`, `ToolAuthorized` ou
`ToolDenied`, e `ExternalEffectObserved` quando a resposta traz um identificador
reconhecido.

## Tráfego de protocolo não vira evidência

`initialize`, `tools/list`, `ping` passam sem policy e sem evidência.
Registá-los encheria a timeline de ruído de protocolo e esconderia as acções que
interessam.

## Efeito externo

A resposta do upstream é examinada por uma **allowlist** de campos:

```text
payment_id  transaction_id  ticket_id  commit_sha  deployment_id  order_id
```

(e as variantes em `camelCase`). É uma allowlist e não um heurístico: mapear
qualquer campo que pareça um identificador transformaria dados do upstream em
afirmações do produto.

## Cabeçalhos de correlação

O agente pode enriquecer a evidência sem falar com nenhuma API nossa:

| cabeçalho | efeito |
|---|---|
| `X-Heraclitus-Agent` | o subject do agente |
| `X-Heraclitus-Run` | agrupa a timeline por run |
| `X-Heraclitus-Trace` | liga ao trace OpenTelemetry |
| `X-Heraclitus-User` | a pessoa em nome de quem o agente age |
| `X-Heraclitus-Server` | o servidor lógico da ferramenta |
| `X-Heraclitus-Environment` | `production`, `staging` — entra na policy |

## O que a recusa parece do lado do agente

Um corpo JSON-RPC bem formado, não um `403` nu — para que o agente perceba que a
ferramenta foi recusada em vez de tratar a recusa como falha de rede e tentar
outra vez:

```json
{
  "jsonrpc": "2.0",
  "id": "call-1",
  "error": {
    "code": -32003,
    "message": "APPROVAL_PENDING: esta acção precisa de aprovação de [cfo]",
    "data": {
      "heraclitus": {
        "reason_code": "APPROVAL_PENDING",
        "approval_id": "01J...",
        "expires_at": 1757900180,
        "argument_digest": "d91f..."
      }
    }
  }
}
```

| situação | HTTP |
|---|---:|
| `deny` | 403 |
| aprovação pendente | 202 |
| aprovação inválida para esta acção exacta | 403 |
| rate limit | 429 |
| upstream em baixo | 502 |

## O que o proxy NÃO faz

- **Não segue redireccionamentos.** O upstream poderia mandar a chamada
  autorizada para outro lado, e a autorização ficou ligada ao recurso.
- **Não guarda cookies.** Seriam credenciais guardadas por nós.
- **Não repete pedidos automaticamente.** Uma tool call não idempotente
  executada duas vezes é um pagamento a dobrar.

Cabeçalhos hop-by-hop (`Connection`, `Transfer-Encoding`, `Proxy-Authorization`,
`Host`, …) não atravessam em nenhuma direcção.

## Bypass protection

O gateway não controla nada se o agente puder chamar o upstream directamente.
Isso é **topologia**, não código:

```text
as credenciais das ferramentas só existem no gateway
o egress da rede impede o acesso directo ao upstream
o servidor MCP aceita a identidade do gateway/delegada
o agente não consegue ler os segredos do upstream
```

Quando isso estiver garantido, declare-o:

```toml
[agent_gateway]
bypass_protection_configured = true
```

A Consola mostra `BYPASS PROTECTION: CONFIGURED` ou `UNKNOWN`. Em produção, o
modo `enforce` **recusa arrancar** sem esta declaração: mostrar "bloqueado" a
quem pode simplesmente contornar o gateway seria falso.

## Idempotência

Um retry com a mesma acção e os mesmos argumentos não cria nova aprovação. Mas o
produto **não promete exactly-once** sobre sistemas externos: se o upstream não
provar idempotência, a matriz de caos (SPEC-0075 §33) documenta o estado externo
possível para cada ponto de falha, em vez de fingir que não existe.
