# OpenTelemetry — o que entra e o que fica de fora

SPEC-0074 §12.

## O contrato

```text
POST http://<host>:4318/v1/traces
Content-Type: application/x-protobuf   (o default do exporter OTel)
Content-Type: application/json         (também aceite)
```

Os dois caminhos descem à **mesma** normalização e produzem os mesmos bytes
canónicos. Não há um caminho "rápido" e um "completo".

```bash
export OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4318
```

## Nem todo o span é evidência de agente

Um span sem marca GenAI **não** entra no log de evidência. A marca é a presença
de qualquer atributo `gen_ai.*` ou `heraclitus.agent.*`.

Sem esta regra, um serviço com tracing HTTP normal despejaria a aplicação
inteira no histórico de evidência, e o próprio Heraclitus — se exportasse a sua
telemetria para si mesmo — entraria no ciclo `OTEL → ingest → OTEL`
(SPEC-0076 §34).

Os spans ignorados são contados e aparecem em `/api/v1/agent/status` como
`ingest.ignored_spans`. Não são erro.

## O mapeamento

| `gen_ai.operation.name` | evidência produzida |
|---|---|
| `execute_tool`, `tool` | `ToolInvocationStarted` + `ToolInvocationFinished` |
| `chat`, `text_completion`, `generate_content`, `embeddings` | `ModelInvocationStarted` + `ModelInvocationFinished` |
| `invoke_agent`, `create_agent` | `RunStarted` + `RunFinished` |
| ausente, com `gen_ai.tool.name` | tool invocation |
| ausente, span raiz | run |
| ausente, span filho | model invocation |

Um span com `status.code = ERROR` ou com `error.type` produz **também** um
`ErrorObserved`. Uma timeline que mostra "tool executada" e esconde "tool
falhou" é pior do que não ter timeline.

### Atributos conhecidos

| atributo OTel | campo canónico |
|---|---|
| `gen_ai.agent.id` | `agent.agent_id` |
| `gen_ai.agent.name` | `agent.agent_name` |
| `gen_ai.system` | `subject.model_provider` |
| `gen_ai.request.model` / `gen_ai.response.model` | `subject.model_id` |
| `gen_ai.tool.name` | `subject.tool_name` |
| `gen_ai.tool.call.id` | `subject.tool_call_id` |
| `gen_ai.conversation.id` | `session_id` |
| `error.type` | `outcome.error_code` |
| `service.name` (resource) | `agent.agent_id` (queda de recurso) |
| `service.version` (resource) | `agent.code_revision` |
| `service.instance.id` (resource) | `agent.deployment_id` |

### Atributos próprios (opcionais)

Servem para enriquecer a evidência sem falar com nenhuma API nossa:

| atributo | efeito |
|---|---|
| `heraclitus.agent.run_id` | agrupa a timeline por run em vez de por trace |
| `heraclitus.agent.tenant` | sobrepõe o inquilino configurado |
| `heraclitus.agent.human.subject` | liga a acção a uma pessoa |
| `heraclitus.agent.human.issuer` | o emissor dessa identidade |
| `heraclitus.agent.server` | o servidor da ferramenta (`finance`, `github`) |
| `heraclitus.agent.external_effect_id` | o identificador do efeito no mundo |

Atributos desconhecidos **não derrubam o lote**: vão para um mapa de extensões
com tecto, e não alteram nenhum campo canónico existente.

## Sem `run_id`, o trace serve de run

Um exporter OTel genérico não emite `run_id` nenhum — o que tem é o trace. Sem
uma queda de recurso explícita, metade da timeline de um agente instrumentado só
com OpenTelemetry ficaria órfã. Por isso:

```text
run efectivo = run_id, se existir; senão trace_id
```

## Retransmissão não duplica

Um exporter retransmite quando o `POST` falha ou expira. Isso é normal e não se
desliga. O Heraclitus calcula uma chave lógica:

```text
H(tenant + source_kind + source_instance + trace_id + span_id
  + event_kind + source_sequence + tool_call_id)
```

e o `evidence_id` é **derivado** dessa chave, não aleatório. O tempo de
observação é o do próprio span, não o relógio da ingestão. Resultado: o mesmo
lote retransmitido produz bytes canónicos idênticos e é descartado em silêncio.

A mesma chave com conteúdo **diferente** falha explicitamente — aceitar seria
deixar reescrever evidência já registada.

Para ver isto:

```bash
python sample-python-agent/sample.py --retransmit
```

```text
run run-abc: 8 evidências aceites, 0 duplicadas, 1 spans ignorados
  retransmissão: 0 aceites, 8 duplicadas
```

## Limites

Todos configuráveis em `[agent_black_box.limits]`:

| limite | default |
|---|---:|
| `max_attributes` | 128 |
| `max_attribute_key_bytes` | 256 |
| `max_attribute_value_bytes` | 4096 |
| `max_events_per_batch` | 10 000 |
| `max_body_bytes` | 4 MiB |
| `max_queue_depth` | 65 536 |

Um lote acima de `max_body_bytes` recebe `413`. Spans recusados por tecto de
lote aparecem em `partialSuccess.rejectedSpans`, que é o que o protocolo OTLP
define para "aceitei uma parte" — e o que faz o exporter parar de retransmitir o
lote inteiro.

## OTLP/gRPC

Serve `opentelemetry.proto.collector.trace.v1.TraceService/Export`:

```toml
[agent_black_box.otlp]
http_addr = "0.0.0.0:4318"
grpc_addr = "0.0.0.0:4317"
```

```bash
export OTEL_EXPORTER_OTLP_PROTOCOL=grpc
export OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4317
```

Vazio por omissão, e isso não é uma lacuna: o exporter OpenTelemetry apontado a
`http://host:4318` usa `http/protobuf`, que o `http_addr` já serve. O gRPC
existe para quem tem o exporter fixado nesse transporte.

### Um transporte, uma normalização

Os dois caminhos descem ao **mesmo** normalizador, ao mesmo portão de
privacidade e à mesma deduplicação. Consequências práticas:

- o mesmo lote enviado por gRPC e por HTTP produz evidência idêntica byte a
  byte;
- o segundo é **deduplicado** — apontar metade da frota a cada transporte não
  duplica a história;
- o tecto de `max_body_bytes` aplica-se aos dois (no gRPC como
  `max_decoding_message_size`, em vez do default de 4 MiB do tonic).

As três afirmações têm teste: `cargo test -p heraclitus-agent-gateway --test otlp_grpc`.

Um método que não servimos (por exemplo `MetricsService/Export`) responde
`Unimplemented`, que é o que o protocolo manda — e não um erro de transporte
que o exporter interpretaria como falha de rede.

## Métricas e logs

`/v1/metrics` e `/v1/logs` respondem `200` e descartam. O produto ingere
**traces**; recusar faria o exporter da aplicação entrar em retry infinito por
causa de um sinal que não pedimos.
