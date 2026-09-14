# SPEC-0074 — Heraclitus Agent Black Box: Tamper-Evident Agent Evidence Plane

**Status:** IMPLEMENTADA em v2.0.0 — `crates/heraclitus-agent`, `crates/heraclitus-agent-gateway`, `heraclitus agent *`
**OTLP/gRPC:** implementado (`opentelemetry.proto.collector.trace.v1.TraceService`); não houve adiamento para a 0074.1.  
**Status original:** PROPOSED — PRODUCT PIVOT / P0  
**Prioridade:** P0 — antes de novas funcionalidades de SOC  
**Baseline auditado:** `JoseRFJuniorLLMs/HeraclitusDB @ 74f921f1ad25cf27c399522c5c0d27c8ec084009`  
**Produto exposto:** **Heraclitus Agent Black Box**  
**Motor interno:** HeraclitusDB / HRKL v6  
**Dependências:** `heraclitus-core`, `heraclitus-log`, `heraclitus-compliance`, `heraclitus-server`  

---

## 0. Decisão de produto

Esta SPEC muda o eixo comercial do HeraclitusDB.

O produto **não será apresentado primeiro como banco de dados, SIEM, SOC, grafo, HTAP, motor vetorial ou plataforma autônoma de defesa**.

O primeiro produto vendável passa a ser:

> **Uma caixa-preta verificável para agentes de IA: registra o que um agente fez, com qual identidade, quais ferramentas acionou, quais autorizações existiam e permite provar depois que o histórico não foi adulterado.**

HeraclitusDB continua sendo o motor de armazenamento, replay, prova e proveniência. O comprador não precisa entender HRKL, Merkle, B-tree, DataFusion ou Raft para obter o primeiro valor.

### 0.1 Regra comercial

Uma instalação deve entregar valor sem exigir:

- migração de banco;
- troca do framework de agentes;
- adoção do Sentinel SOC;
- GPU;
- cluster;
- linguagem de consulta própria;
- conhecimento interno do HeraclitusDB.

O primeiro fluxo deve ser:

```bash
docker compose up -d
export OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4318
```

Se a aplicação já exporta OpenTelemetry, o primeiro run deve aparecer sem outra dependência obrigatória.

---

## 1. Problema

Agentes podem:

- escolher ferramentas;
- encadear ferramentas;
- agir em nome de uma pessoa;
- usar credenciais delegadas;
- alterar estado externo;
- repetir ações após timeout;
- pedir aprovação humana;
- operar sobre conteúdo potencialmente hostil.

Observabilidade tradicional responde apenas parcialmente:

```text
o que aconteceu?
```

O produto precisa responder:

```text
quem iniciou?
qual agente executou?
em nome de quem?
qual modelo participou?
qual ferramenta foi chamada?
quais argumentos efetivos foram usados?
qual política estava vigente?
houve aprovação humana?
qual foi o efeito externo?
o histórico foi alterado depois?
consigo verificar isso offline?
```

---

## 2. Interoperabilidade

A implementação deve aproveitar padrões existentes.

Referências:

1. OpenTelemetry Semantic Conventions for Generative AI.
2. Model Context Protocol, versão `2026-07-28`.
3. OWASP Agent Control Standard, 2026.
4. NIST/NCCoE Software and AI Agent Identity and Authorization, 2026.
5. RFC 3161 quando ancoragem temporal estiver configurada.

Nenhuma referência acima autoriza alegar certificação.

---

## 3. Escopo do MVP

O MVP contém exatamente seis capacidades:

```text
1. ingestão OTLP
2. captura MCP
3. modelo canônico de evidência de agente
4. persistência tamper-evident em HRKL v6
5. verificação determinística
6. exportação de Evidence Bundle
```

---

## 4. Não objetivos

Esta SPEC não implementa:

- SIEM geral;
- UEBA;
- threat intelligence;
- ATT&CK coverage;
- SOAR genérico;
- autonomous investigation swarm;
- digital twin;
- novo vector DB;
- novo banco relacional;
- novo protocolo de tracing;
- LLM para “explicar” os logs;
- captura irrestrita de prompts por default.

O roadmap SOC permanece no repositório, mas deixa de ser prioridade comercial P0.

---

## 5. Arquitetura

```text
                       Application / AI Agent
                                │
                 ┌──────────────┴───────────────┐
                 │                              │
               OTLP                           MCP
                 │                              │
                 ▼                              ▼
        OTLP Ingest                     MCP Capture/Proxy
                 └──────────────┬───────────────┘
                                ▼
                    Agent Evidence Normalizer
                                │
                                ▼
                     Privacy / Redaction Gate
                                │
                                ▼
                      HRKL v6 Canonical Log
                                │
              ┌─────────────────┼──────────────────┐
              ▼                 ▼                  ▼
        Timeline API        prove_lsn        Evidence Bundle
                                                   │
                                                   ▼
                                            Offline Verifier
```

---

## 6. Reuso obrigatório

### `heraclitus-log`

Reutilizar:

- HRKL v6;
- canonical record;
- logical roots;
- Merkle proof;
- `prove_lsn`;
- verify;
- crash recovery;
- append-only semantics.

### `heraclitus-compliance`

Reutilizar:

- RFC 3161 quando configurado;
- material de atestação;
- verificação offline existente quando aplicável.

### `heraclitus-server`

Reutilizar:

- Axum;
- Tonic;
- lifecycle;
- health;
- packaging;
- autenticação/configuração já existentes onde fizer sentido.

### `heraclitus-sentinel`

Pode fornecer ideias/tipos genéricos de:

- `EvidenceRef`;
- aprovação humana;
- policy provenance;
- append-only decision log.

Tipos específicos de incidente SOC não devem contaminar o modelo de agente.

---

## 7. Novos componentes

### 7.1 `crates/heraclitus-agent`

Responsabilidades:

```text
canonical agent evidence model
normalization
privacy/redaction
deduplication identity
run/timeline projection
evidence bundle model
```

Não abre sockets.

### 7.2 `crates/heraclitus-agent-ingest`

Criar somente se separar ingestão realmente simplificar o servidor.

Responsabilidades:

```text
OTLP HTTP/gRPC
MCP capture
bounded queues
backpressure
mapping -> AgentEvidenceV1
metrics
```

### 7.3 CLI

Preferir subcomandos da CLI já existente:

```bash
heraclitus agent verify evidence.zip
heraclitus agent inspect evidence.zip
heraclitus agent export ...
```

Não criar binário novo sem necessidade.

---

## 8. Modelo canônico

```rust
pub struct AgentEvidenceV1 {
    pub schema_version: u16,
    pub evidence_id: String,
    pub observed_at_unix_nanos: u64,

    pub tenant_id: String,

    pub trace_id: Option<String>,
    pub span_id: Option<String>,
    pub parent_span_id: Option<String>,

    pub run_id: Option<String>,
    pub session_id: Option<String>,

    pub agent: AgentIdentityV1,
    pub human: Option<HumanIdentityRefV1>,
    pub delegation: Option<DelegationRefV1>,

    pub kind: AgentEvidenceKindV1,
    pub subject: EvidenceSubjectV1,
    pub content: EvidenceContentV1,
    pub source: EvidenceSourceV1,
    pub privacy: PrivacyEnvelopeV1,

    pub parents: Vec<String>,
    pub dedupe_key: String,
}
```

A implementação pode ajustar nomes Rust, mas deve preservar a semântica.

---

## 9. Tipos mínimos de evento

`AgentEvidenceKindV1`:

```text
RunStarted
RunFinished
ModelInvocationStarted
ModelInvocationFinished
ToolRequested
ToolAuthorized
ToolDenied
ToolInvocationStarted
ToolInvocationFinished
HumanApprovalRequested
HumanApprovalGranted
HumanApprovalDenied
PolicyEvaluated
AgentOutputProduced
ExternalEffectObserved
ErrorObserved
ArtifactReferenced
```

Não reutilizar `SecurityEvent` apenas para encaixar o novo produto na arquitetura antiga.

---

## 10. Identidade

### 10.1 Agent

```rust
pub struct AgentIdentityV1 {
    pub agent_id: String,
    pub agent_name: Option<String>,
    pub framework: Option<String>,
    pub framework_version: Option<String>,
    pub deployment_id: Option<String>,
    pub code_revision: Option<String>,
}
```

### 10.2 Humano

```rust
pub struct HumanIdentityRefV1 {
    pub subject_id: String,
    pub issuer: Option<String>,
    pub display_hint: Option<String>,
}
```

### 10.3 Delegação

```rust
pub struct DelegationRefV1 {
    pub delegation_id: String,
    pub on_behalf_of: String,
    pub authority_scope_hash: Option<String>,
}
```

A semântica completa de autorização entra na SPEC-0075.

---

## 11. Privacidade e conteúdo

Princípio:

> **Observabilidade não pode virar vazamento de segredo.**

Default:

```text
prompts completos         = OFF
completions completas     = OFF
tool arguments completos  = REDACTED/BUDGETED
tool results completos    = REDACTED/BUDGETED
OAuth/JWT/API keys        = NEVER STORE
Authorization header      = NEVER STORE
Cookie                    = NEVER STORE
```

Modos:

```text
METADATA_ONLY
HASH_ONLY
REDACTED
FULL_EXPLICIT
```

Default:

```text
METADATA_ONLY
```

`FULL_EXPLICIT` exige configuração administrativa explícita.

Quando bytes não forem persistidos, registrar apenas o necessário:

```text
content_length
content_type
canonical_content_hash
redaction_applied
redaction_profile_id
```

---

## 12. Ingestão OpenTelemetry

Suportar:

```text
OTLP/HTTP
OTLP/gRPC
```

Prioridade:

```text
1. OTLP/HTTP
2. OTLP/gRPC
```

Mapeamento:

```text
known GenAI fields -> typed canonical fields
unknown fields     -> bounded extension map
```

Um atributo opcional desconhecido não derruba o lote.

Limites obrigatórios:

```text
max_attributes
max_attribute_key_bytes
max_attribute_value_bytes
max_events_per_batch
max_body_bytes
max_queue_depth
```

Sem alocação sem limite.

---

## 13. Captura MCP

Dois modos:

### `observe`

Captura metadados emitidos pelo host.

### `proxy`

```text
Agent -> Heraclitus MCP Proxy -> MCP Server
```

Na SPEC-0074 o proxy existe principalmente para evidência. Bloqueio de ação pertence à SPEC-0075.

Compatibilidade inicial:

```text
MCP 2026-07-28 HTTP/stateless
```

Quando presentes, registrar:

```text
Mcp-Method
Mcp-Name
request id
task id
tool name
server identity
duration
result status
```

Nunca persistir bearer token.

Cada chamada deve correlacionar:

```text
ToolRequested
    ↓
ToolInvocationStarted
    ↓
ToolInvocationFinished
```

por `tool_call_id`.

---

## 14. Deduplicação

Retries de exporter são normais.

Criar chave lógica estável, conceitualmente:

```text
H(
  tenant
  + source_kind
  + source_instance
  + trace_id
  + span_id
  + event_kind
  + source_sequence_if_present
)
```

Repetir o mesmo lote não gera nova evidência lógica.

Mesmo `dedupe_key` com conteúdo semanticamente diferente deve falhar explicitamente.

---

## 15. Persistência no HRKL

Cada `AgentEvidenceV1` é serializado de forma canônica e anexado ao HRKL.

`parents` representa proveniência lógica:

```text
RunStarted
   ├── ModelInvocation
   │       └── ToolRequested
   │             └── ToolInvocation
   └── AgentOutput
```

LSN/Merkle representa integridade do armazenamento.

Não confundir as duas coisas.

---

## 16. Provas

### 16.1 Storage proof

Reutilizar `prove_lsn` para fornecer:

```text
record hash
Merkle inclusion proof
logical root
segment/generation identity
optional timestamp receipt
```

### 16.2 Workflow proof

Provar relações auditáveis:

```text
tool call T
was requested by run R
evaluated under policy P
approved by principal H
executed with argument hash A
returned result hash B
```

Uma Merkle proof válida prova inclusão/integridade, não que a decisão foi correta.

---

## 17. Evidence Bundle v1

Layout:

```text
evidence-<bundle-id>.zip
├── manifest.json
├── timeline.ndjson
├── identities.json
├── tool-calls.json
├── approvals.json
├── policy-decisions.json
├── roots.json
├── proofs/
│   └── <evidence-id>.json
├── attestations/
│   └── ...
├── SHA256SUMS
└── README.txt
```

Manifest:

```rust
pub struct EvidenceBundleManifestV1 {
    pub format_version: u16,
    pub bundle_id: String,
    pub created_at: String,
    pub tenant_id: String,

    pub selection: BundleSelectionV1,

    pub first_lsn: u64,
    pub last_lsn: u64,

    pub logical_roots: Vec<String>,
    pub files: Vec<BundleFileDigestV1>,

    pub privacy_profile: String,
    pub verifier_min_version: String,
}
```

Bundle interrompido deve usar temp + atomic rename e nunca aparecer como concluído.

---

## 18. Verificador offline

Comando:

```bash
heraclitus agent verify evidence.zip
```

Saída humana:

```text
Bundle:           01J...
Records:          1847
LSN range:        9981..11827
File digests:     VALID
Merkle proofs:    VALID
Logical roots:    VALID
Timestamp proofs: 3 VALID
Missing records:  0
Broken parents:   0
Policy links:     17 VALID
Approvals:        2 VALID

VERDICT: VERIFIED
```

Automação:

```bash
heraclitus agent verify evidence.zip --json
```

Exit codes:

```text
0 VERIFIED
2 INVALID_BUNDLE
3 DIGEST_MISMATCH
4 PROOF_FAILURE
5 UNSUPPORTED_VERSION
6 INCOMPLETE_SELECTION
7 ATTESTATION_FAILURE
```

---

## 19. API mínima

```text
GET  /api/v1/agent/runs
GET  /api/v1/agent/runs/:id
GET  /api/v1/agent/runs/:id/timeline
GET  /api/v1/agent/evidence/:id
GET  /api/v1/agent/evidence/:id/proof
POST /api/v1/agent/evidence/export
GET  /api/v1/agent/status
```

OTLP:

```text
POST /v1/traces
gRPC TraceService
```

A API pode retornar LSN na seção `integrity`, mas usuário não deve precisar entender LSN para operar o produto.

---

## 20. Views derivadas

Criar projeções simples:

```text
RunSummary
RunTimelineEntry
ToolCallSummary
ApprovalSummary
EvidenceIntegritySummary
```

A UI não deve consultar diretamente o grafo/vector engine genérico.

---

## 21. Métricas

```text
agent_ingest_events_total
agent_ingest_rejected_total
agent_ingest_duplicates_total
agent_ingest_queue_depth
agent_ingest_lag_seconds
agent_redactions_total
agent_runs_total
agent_tool_calls_total
agent_bundle_exports_total
agent_bundle_verify_failures_total
```

Histogramas:

```text
agent_ingest_latency_seconds
agent_bundle_build_seconds
agent_proof_build_seconds
```

---

## 22. Configuração

```toml
[agent_black_box]
enabled = true
capture_mode = "metadata_only"
max_body_bytes = 4194304

[agent_black_box.otlp]
http_addr = "0.0.0.0:4318"
grpc_addr = "0.0.0.0:4317"

[agent_black_box.mcp]
enabled = false
listen_addr = "127.0.0.1:8787"

[agent_black_box.redaction]
profile = "default"
deny_headers = ["authorization", "cookie", "set-cookie", "x-api-key"]

[agent_black_box.evidence]
rfc3161 = false
```

---

## 23. Segurança

Se ingest remoto fizer bind não-loopback em perfil production:

- TLS;
- autenticação;
- body limits;
- rate limits;
- timeout;
- proteção contra decompression bomb;
- parser fail-safe.

Testes negativos de segredo:

```text
Bearer ...
sk-...
private keys
AWS-like secrets
Cookie
Set-Cookie
```

O produto não promete detectar todo segredo possível.

---

## 24. Crash/restart

Após crash:

- registros confirmados permanecem verificáveis;
- lote retransmitido é deduplicado;
- nenhuma prova aponta para registro não durável;
- cursor volta a estado consistente;
- bundle interrompido não aparece concluído.

Teste:

```text
append
kill -9
restart
retransmit same OTLP batch
export
verify
```

Resultado: zero duplicação lógica.

---

## 25. Testes obrigatórios

### Unit

- canonicalization;
- dedupe;
- redaction;
- size limits;
- mapping;
- parent validation;
- manifest validation.

### Golden

Vetores para:

```text
GenAI model span
MCP tools/call
MCP result
human approval reference
tool error
redacted arguments
```

### Property

- ordem de atributos não muda canonical hash;
- retransmissão não duplica;
- mudar 1 byte invalida digest/proof;
- remover record obrigatório invalida bundle;
- unknown fields não mudam fields canônicos existentes.

### Integration

```text
sample agent
 -> model span
 -> tool call
 -> result
 -> export
 -> tamper copy
 -> verify original PASS
 -> verify tampered FAIL
```

---

## 26. Benchmark

Medir:

```text
OTLP ingest events/s
p50/p95/p99 ingest latency
bytes/evidence record
bundle generation throughput
verification throughput
MCP proxy added latency
```

Gates:

1. `METADATA_ONLY` não bloqueia o thread do agente esperando fsync do exporter.
2. Backpressure é explícito.
3. Memória é limitada por configuração.
4. Benchmark de durabilidade não pode esconder fsync.

Não publicar números antes de medir.

---

## 27. First-run experience

Adicionar:

```text
examples/agent-black-box/
├── docker-compose.yml
├── sample-python-agent/
├── README.md
└── expected/
```

Fluxo:

```bash
docker compose up -d
python sample.py
```

Resultado:

```text
Open http://localhost:8080
Run visible
Tool call visible
Integrity: VERIFIED
```

Gate de produto:

```text
< 5 minutos até o primeiro run visível
```

para desenvolvedor com Docker já instalado.

---

## 28. Nome e narrativa

Externamente:

```text
Heraclitus Agent Black Box
```

Internamente:

```text
HeraclitusDB
```

Não é necessário renomear o repositório.

README deve começar com o problema e o quickstart, não com a arquitetura do banco.

---

## 29. Relação com Sentinel

Sentinel é opcional.

```text
Agent Evidence
      │
      ├── Evidence Console
      ├── Policy Gateway
      └── optional Sentinel analytics
```

Nunca:

```text
Agent Evidence -> SecurityEvent obrigatório -> produto
```

---

## 30. Definition of Done

A SPEC-0074 está DONE somente quando:

- [ ] OTLP/HTTP recebe traces.
- [ ] OTLP/gRPC recebe traces ou adiamento 0074.1 está documentado.
- [ ] GenAI spans são normalizados deterministicamente.
- [ ] MCP tool calls podem ser capturados.
- [ ] tokens/Authorization headers nunca são persistidos.
- [ ] `AgentEvidenceV1` possui golden vectors.
- [ ] evidência é persistida em HRKL v6.
- [ ] `prove_lsn` está no caminho real de prova.
- [ ] timeline de run existe via API.
- [ ] Evidence Bundle v1 é exportado.
- [ ] verificador offline existe.
- [ ] alteração de 1 byte falha verificação.
- [ ] crash/retransmit não duplica eventos.
- [ ] exemplo Docker produz primeiro run em menos de 5 minutos.
- [ ] README vende Agent Black Box antes de vender o banco.
- [ ] nenhuma capacidade P0 depende de GPU/SOC/LLM.

---

## 31. Critério de fracasso comercial

Esta SPEC falhou se o usuário precisar:

1. entender HRKL para começar;
2. migrar seu banco;
3. configurar um SOC;
4. escrever query proprietária;
5. estudar a arquitetura por horas antes do demo.

---

## 32. Ordem de implementação

```text
P0.1 AgentEvidenceV1 + golden canonicalization
P0.2 redaction gate
P0.3 append/replay HRKL
P0.4 OTLP/HTTP ingest
P0.5 RunSummary/timeline projection
P0.6 prove_lsn integration
P0.7 bundle builder + offline verifier
P0.8 MCP capture/proxy
P0.9 restart/dedupe qualification
P0.10 sample app + docker compose + README pivot
```

Não iniciar a parte complexa da SPEC-0075 antes de P0.1–P0.7 fecharem ponta a ponta.

---

## 33. Frase de aceitação

Quando esta SPEC terminar, deve ser verdadeiro dizer:

> **Conecte o OpenTelemetry do seu agente ao Heraclitus. Ele registra cada execução relevante em um histórico append-only verificável, liga tool calls às suas evidências e exporta um pacote que pode ser conferido offline depois, sem trocar o banco ou framework da aplicação.**
