# SPEC-0075 — Heraclitus Agent Policy Gateway: Runtime Authorization, Delegation & Human Approval

**Status:** IMPLEMENTADA em v2.0.0 — `heraclitus-agent::policy/action/identity`, proxy MCP em `heraclitus-agent-gateway::gateway`
**Fora do MVP, como §36 permite:** OPA/Rego, Cedar, plugins WASM, sandbox universal, SSH/SQL proxy, EDR.  
**Status original:** PROPOSED — PRODUCT PIVOT / P0  
**Prioridade:** P0 — após o vertical slice verificável da SPEC-0074  
**Baseline auditado:** `JoseRFJuniorLLMs/HeraclitusDB @ 74f921f1ad25cf27c399522c5c0d27c8ec084009`  
**Produto exposto:** **Heraclitus Agent Policy Gateway**  
**Depende de:** SPEC-0074  
**Reutiliza:** `heraclitus-sentinel::policy` por extração/generalização, não por acoplamento a incidentes SOC  
**Alinhamento:** MCP 2026-07-28, OAuth/OIDC, OWASP ACS 2026, NIST Agent Identity & Authorization 2026  

---

## 0. Decisão

A SPEC-0074 prova:

```text
o que o agente fez
```

A SPEC-0075 adiciona:

```text
o que o agente PODE fazer
```

O gateway fica entre o agente e ferramentas externas:

```text
Agent
  │
  ▼
Heraclitus Agent Policy Gateway
  │
  ├── ALLOW
  ├── DENY
  ├── REQUIRE_APPROVAL
  ├── REDACT
  ├── RATE_LIMIT
  └── SANDBOX_HINT
  │
  ▼
MCP Server / API / Tool
```

O objetivo não é criar outro framework de agentes. É oferecer uma fronteira de autorização e evidência independente do framework.

---

## 1. Problema

Um agente pode receber instruções não confiáveis e ainda possuir credenciais reais.

Portanto:

```text
"o modelo decidiu chamar a ferramenta"
```

não equivale a:

```text
"a organização autorizou esta ação"
```

O produto precisa separar:

```text
INTENT
REQUEST
AUTHORIZATION
APPROVAL
EXECUTION
RESULT
```

Cada etapa deve ser registrada como evidência da SPEC-0074.

---

## 2. Princípios

### 2.1 Policy is code, model output is data

Nenhum texto produzido por LLM altera policy diretamente.

### 2.2 Fail closed

Se uma ação é protegida e o gateway não consegue avaliar a policy:

```text
DENY
```

Nunca:

```text
ALLOW because policy service unavailable
```

### 2.3 Aprovação é ligada ao conteúdo

Uma aprovação para:

```text
send_payment(amount=5000, account=A)
```

não autoriza:

```text
send_payment(amount=50000, account=B)
```

### 2.4 Tokens não são evidência

Bearer tokens, refresh tokens, API keys e cookies nunca entram no HRKL.

### 2.5 Não construir IdP

Heraclitus valida identidades emitidas por sistemas existentes. Não vira provedor corporativo de identidade.

---

## 3. Reuso do código atual

O repositório já possui conceitos relevantes:

```text
DeterministicPolicyEngine
PolicyDecision::Deny
PolicyDecision::Approve
PolicyDecision::RequireHumanApproval
ExecutionConstraints
HumanApproval
AuthorizedAction
```

Essas ideias devem ser reaproveitadas.

O acoplamento atual a:

```text
SecurityIncident
RiskAssessment
ActionProposal
```

não deve ser levado para o produto de agentes.

A implementação deve extrair uma camada genérica apenas se isso reduzir dependência e duplicação de verdade.

Possíveis destinos:

```text
heraclitus-policy-core
```

ou um módulo genérico em:

```text
heraclitus-agent
```

Regra:

> **não manter dois policy engines determinísticos independentes.**

---

## 4. Arquitetura

```text
               Agent / Agent Runtime
                        │
                        ▼
              Gateway Request Capture
                        │
                        ▼
              Identity / Delegation
                   validation
                        │
                        ▼
              Deterministic Policy
                     Engine
                 ┌──────┼──────┐
                 │      │      │
               DENY   ALLOW  REQUIRE_APPROVAL
                               │
                               ▼
                      Human Approval Service
                               │
                               ▼
                      Upstream Tool Execution
                               │
                               ▼
                      SPEC-0074 Evidence Log
```

---

## 5. Primeira superfície protegida: MCP

O primeiro gateway suporta:

```text
MCP over HTTP
```

compatível com o core vigente do MCP `2026-07-28`.

Razões:

- tool calls possuem nome explícito;
- protocolo já é usado por stacks agentic;
- headers `Mcp-Method` e `Mcp-Name` permitem classificação precoce;
- autorização usa padrões OAuth/OIDC;
- evita criar uma API proprietária como primeira integração.

REST genérico fica para fase posterior.

---

## 6. Modelo de ação

```rust
pub struct AgentActionRequestV1 {
    pub request_id: String,

    pub tenant_id: String,

    pub trace_id: Option<String>,
    pub run_id: Option<String>,
    pub session_id: Option<String>,

    pub agent: AgentPrincipalV1,
    pub human: Option<HumanPrincipalV1>,
    pub delegation: Option<DelegationContextV1>,

    pub resource: ToolResourceV1,

    pub action: String,

    pub argument_digest: String,
    pub arguments_for_policy: BTreeMap<String, PolicyValueV1>,

    pub requested_at_unix_nanos: u64,
}
```

A policy não recebe necessariamente o payload bruto. Ela recebe campos explicitamente permitidos para decisão.

---

## 7. Identidade

### 7.1 Agent principal

```rust
pub struct AgentPrincipalV1 {
    pub subject: String,
    pub issuer: String,
    pub deployment_id: Option<String>,
    pub workload_id: Option<String>,
    pub auth_strength: AuthStrengthV1,
}
```

### 7.2 Human principal

```rust
pub struct HumanPrincipalV1 {
    pub subject: String,
    pub issuer: String,
    pub roles: Vec<String>,
    pub auth_time: Option<u64>,
}
```

Roles só são confiáveis dentro do issuer configurado.

### 7.3 Delegation

```rust
pub struct DelegationContextV1 {
    pub delegation_id: String,

    pub human_subject: Option<String>,
    pub agent_subject: String,

    pub allowed_scopes: Vec<String>,

    pub issued_at: u64,
    pub expires_at: u64,

    pub source_credential_fingerprint: Option<String>,
}
```

Nunca persistir a credencial.

---

## 8. Autenticação

### 8.1 DEV_LOCAL

Pode aceitar:

- loopback;
- chave local gerada no init;
- banner explícito de perfil de desenvolvimento.

### 8.2 PRODUCTION

Deve oferecer pelo menos:

```text
OIDC/JWT validation
```

com:

```text
issuer allowlist
audience validation
exp
nbf
signature
kid/JWKS
algorithm allowlist
clock skew bound
```

O gateway não precisa operar seu próprio authorization server.

---

## 9. Token handling

Nunca persistir:

```text
Authorization
Cookie
Set-Cookie
access_token
refresh_token
client_secret
api_key
```

Quando gateway precisa autenticar no upstream, usa referência segura:

```text
CredentialRef
```

A referência pode apontar para secret manager, arquivo protegido ou provider configurado. Material secreto nunca vira policy nem Evidence Bundle.

---

## 10. Resource model

```rust
pub struct ToolResourceV1 {
    pub protocol: String,
    pub server_id: String,
    pub tool_name: String,
    pub tool_version: Option<String>,
    pub environment: Option<String>,
    pub sensitivity: Option<String>,
}
```

Identidades conceituais:

```text
mcp://finance/send_payment
mcp://github/merge_pull_request
mcp://prod-db/execute_sql
mcp://email/send_message
mcp://filesystem/write_file
```

---

## 11. Policy format

Não criar uma linguagem completa.

O MVP usa documento declarativo versionado em YAML/JSON.

```yaml
version: "agent-policy-v1"

defaults:
  decision: deny

rules:
  - id: finance-small
    match:
      server: finance
      tool: send_payment
      conditions:
        - field: amount
          op: lte
          value: 5000
    decision: require_approval
    approval:
      roles: ["finance-operator"]
      ttl_seconds: 300

  - id: finance-large
    match:
      server: finance
      tool: send_payment
      conditions:
        - field: amount
          op: gt
          value: 5000
    decision: require_approval
    approval:
      roles: ["cfo"]
      ttl_seconds: 180

  - id: destructive-shell
    match:
      server: shell
      tool: exec
      conditions:
        - field: command_class
          op: eq
          value: destructive
    decision: deny
```

---

## 12. Operadores do MVP

Somente:

```text
eq
neq
lt
lte
gt
gte
in
not_in
prefix
suffix
contains
exists
```

Tipos:

```text
string
integer
decimal-safe representation
boolean
string set
```

Evitar regex arbitrária no primeiro MVP. Se regex for indispensável, engine e limites precisam ser fixados para não introduzir comportamento imprevisível/DoS.

---

## 13. Decisões

```rust
pub enum AgentPolicyDecisionV1 {
    Allow {
        authorization: ActionAuthorizationV1,
    },

    Deny {
        reason_code: String,
        rule_id: Option<String>,
    },

    RequireApproval {
        request: ApprovalRequestV1,
    },

    Redact {
        profile_id: String,
    },

    RateLimit {
        bucket_id: String,
        retry_after_ms: u64,
    },

    SandboxHint {
        profile_id: String,
    },
}
```

MVP bloqueante real:

```text
ALLOW
DENY
REQUIRE_APPROVAL
```

`REDACT` pode atuar sobre entrada/resultado.

`RATE_LIMIT` é P0.5.

`SANDBOX_HINT` não implementa um hipervisor universal.

---

## 14. Authorization binding

```rust
pub struct ActionAuthorizationV1 {
    pub authorization_id: String,

    pub policy_id: String,
    pub policy_version: String,
    pub policy_hash: String,
    pub rule_id: String,

    pub agent_subject: String,
    pub human_subject: Option<String>,

    pub resource_id: String,
    pub action: String,

    pub argument_digest: String,

    pub issued_at: u64,
    pub expires_at: u64,

    pub nonce: String,
}
```

Se mudar:

```text
tool
server
arguments
agent
human
policy
expiry
```

a autorização deixa de valer.

---

## 15. Human approval

### 15.1 ApprovalRequest

```rust
pub struct ApprovalRequestV1 {
    pub approval_id: String,
    pub authorization_subject_hash: String,
    pub requested_roles: Vec<String>,
    pub reason: String,
    pub preview: ApprovalPreviewV1,
    pub requested_at: u64,
    pub expires_at: u64,
}
```

### 15.2 ApprovalDecision

```rust
pub struct ApprovalDecisionV1 {
    pub approval_id: String,
    pub approver_subject: String,
    pub approver_issuer: String,
    pub approved: bool,
    pub authorization_subject_hash: String,
    pub decided_at: u64,
    pub comment: Option<String>,
}
```

`authorization_subject_hash` impede alteração dos argumentos após a aprovação.

### 15.3 Single-use

Default:

```text
approval -> one execution
```

Sem aprovação reutilizável no MVP.

---

## 16. Fluxo

```text
Agent calls send_payment
        │
        ▼
Gateway canonicalizes action
        │
        ▼
Policy => REQUIRE_APPROVAL
        │
        ├── ToolRequested evidence
        ├── PolicyEvaluated evidence
        └── HumanApprovalRequested evidence
        │
        ▼
Human approves
        │
        ▼
ApprovalDecision appended
        │
        ▼
Gateway checks exact argument digest
        │
        ▼
AuthorizedAction
        │
        ▼
Tool call
        │
        ▼
Tool result evidence
```

A adaptação ao lifecycle MCP deve seguir o protocolo vigente. Não inventar status/resposta incompatível.

---

## 17. Determinismo

Mesmos inputs canônicos + mesma policy version => mesma decisão.

A avaliação não pode depender de:

- ordem de mapas;
- locale;
- timezone implícito;
- thread;
- restart;
- ordem de HashMap;
- random.

Tempo, quando necessário, entra como input explícito.

---

## 18. Policy provenance

Cada decisão persistida pela SPEC-0074 contém:

```text
policy_id
policy_version
policy_hash
rule_id
decision
reason_code
input_projection_hash
authorization_id / approval_id
```

Não persistir segredo.

---

## 19. Prompt injection

O gateway não tenta resolver segurança com “detecção perfeita de prompt injection”.

O desenho assume:

```text
agent reasoning may be compromised
```

Logo a policy usa:

```text
authenticated identity
tool identity
typed fields
declared resource
environment
organizational rules
human approval
```

e não:

```text
"LLM said it is safe"
```

Classificador/LLM pode virar sinal adicional no futuro, nunca autoridade exclusiva para ação crítica.

---

## 20. Bypass protection

Gateway não controla nada se o agente puder chamar upstream diretamente.

Deploy production deve orientar:

```text
tool credentials only available to gateway
network egress restrict direct upstream access
MCP server accepts gateway/delegated identity
agent cannot read upstream secrets
```

A UI deve mostrar estado:

```text
BYPASS PROTECTION: CONFIGURED / UNKNOWN
```

Nunca afirmar enforcement quando a topologia não o garante.

---

## 21. Policy API

```text
GET  /api/v1/agent/policies
POST /api/v1/agent/policies/validate
POST /api/v1/agent/policies/simulate
POST /api/v1/agent/policies/activate
GET  /api/v1/agent/policies/:version

GET  /api/v1/agent/approvals
GET  /api/v1/agent/approvals/:id
POST /api/v1/agent/approvals/:id/approve
POST /api/v1/agent/approvals/:id/deny
```

Ativação de policy é operação administrativa auditada.

---

## 22. Policy lifecycle

```text
DRAFT
  ↓
VALIDATED
  ↓
SIMULATED
  ↓
ACTIVE
  ↓
RETIRED
```

Policy ACTIVE é imutável. Alteração gera nova versão/hash.

---

## 23. Simulação histórica

Antes de ativar:

```bash
heraclitus agent policy simulate policy.yaml \
  --from 2026-09-01 \
  --to 2026-09-07
```

Saída:

```text
historical tool calls: 18,442
ALLOW:               17,912
DENY:                   183
REQUIRE_APPROVAL:        347
changed vs active:        81
```

Isso reaproveita o histórico da SPEC-0074.

---

## 24. Shadow mode

Modo essencial para adoção:

```toml
[agent_gateway]
mode = "shadow"
```

Em `shadow`:

- policy é avaliada;
- decisão é registrada;
- ação não é bloqueada;
- UI mostra `would deny` / `would require approval`.

Caminho:

```text
observe -> shadow -> enforce
```

Erros de autenticação do próprio gateway continuam erros reais.

---

## 25. Tool results e efeitos externos

Registrar separadamente:

```text
transport_status
protocol_status
tool_result_digest
external_effect_id when available
duration
retry_count
```

Se upstream retorna:

```text
payment_id
ticket_id
commit_sha
deployment_id
```

pode mapear para `external_effect_id` por allowlist.

---

## 26. Retry e idempotência

Criar `action_request_id`.

Retry com mesma ação e mesmos argumentos:

- não cria nova aprovação;
- não executa duas vezes automaticamente se upstream não prova idempotência;
- retorna estado anterior quando seguro.

Ferramentas não idempotentes exigem cautela explícita.

Nunca prometer exactly-once universal sobre sistemas externos.

---

## 27. Rate limiting

P0.5.

Limites por:

```text
tenant
agent
human
server
tool
rule
```

Algoritmo documentado e deterministicamente testável.

---

## 28. Redaction

Policy pode declarar:

```yaml
result:
  redact_fields:
    - password
    - token
    - secret
  max_bytes: 8192
```

Redação ocorre antes do append em HRKL.

---

## 29. Configuração

```toml
[agent_gateway]
enabled = true
mode = "shadow"
listen_addr = "0.0.0.0:8787"

[agent_gateway.identity]
mode = "oidc"
issuer = "https://id.example.gov"
audience = "heraclitus-agent-gateway"

[agent_gateway.policy]
active = "/etc/heraclitus/agent-policy.yaml"
default_decision = "deny"

[agent_gateway.approval]
default_ttl_seconds = 300
```

O endereço é exemplo, não dependência do produto.

---

## 30. Métricas

```text
agent_gateway_requests_total
agent_gateway_allow_total
agent_gateway_deny_total
agent_gateway_require_approval_total
agent_gateway_shadow_deny_total
agent_gateway_approval_pending
agent_gateway_approval_expired_total
agent_gateway_approval_replay_rejected_total
agent_gateway_policy_errors_total
agent_gateway_upstream_errors_total
```

Latências:

```text
policy_evaluation_seconds
approval_wait_seconds
gateway_added_latency_seconds
upstream_tool_latency_seconds
```

---

## 31. Segurança da policy

Policy file:

- tamanho máximo;
- parse estrito;
- canonical hash;
- atomic activate;
- rollback explícito;
- sem includes remotos no MVP;
- sem execução de shell;
- sem JavaScript/Lua embutido;
- sem template eval arbitrário.

Policy declarativa deve continuar dados, não virar mecanismo de RCE.

---

## 32. Testes obrigatórios

### Identidade

```text
wrong issuer -> reject
wrong audience -> reject
expired -> reject
nbf future -> reject
unsupported alg -> reject
missing identity in production -> reject
```

### Policy

- default deny;
- exact tool match;
- numeric threshold;
- role approval;
- policy hash stable;
- map order stable;
- restart stable.

### Approval binding

Teste obrigatório:

```text
request amount=5000
approve
mutate amount=5001
execute
=> DENY APPROVAL_BINDING_MISMATCH
```

Também recusar:

```text
change account
change tool
change agent
expired approval
replayed approval
```

### Shadow

- decisão logada;
- request encaminhada;
- `enforced=false`.

### Enforce

- deny nunca chega ao upstream;
- pending approval nunca chega ao upstream;
- approved exact action chega ao upstream uma vez.

### Secrets

Nenhum segredo aparece em:

```text
HRKL
logs
metrics labels
bundle
errors
```

---

## 33. Chaos/restart

Testar:

```text
crash after policy decision before append
crash after append before upstream
crash after upstream response before result append
crash while approval pending
restart after approval granted
duplicate client retry
```

Para cada cenário, documentar estado externo possível.

---

## 34. UX de aprovação

Tela:

```text
Agent: procurement-agent
Tool:  send_payment
Environment: production

Amount: R$ 75.000
Destination: vendor-8832

Policy:
payments > R$ 50.000 require CFO approval

Arguments digest:
d91f...

[DENY] [APPROVE]
```

Alterar argumento após aprovação invalida a decisão.

---

## 35. Definition of Done

SPEC-0075 está DONE quando:

- [ ] MCP HTTP passa pelo gateway.
- [ ] modos observe/shadow/enforce existem.
- [ ] identidade de agente é representada.
- [ ] identidade humana pode ser ligada à ação.
- [ ] validação OIDC/JWT production existe ou adapter equivalente está documentado.
- [ ] default deny existe.
- [ ] policies são versionadas e hashadas.
- [ ] ALLOW/DENY/REQUIRE_APPROVAL estão implementados.
- [ ] approval é ligado ao hash exato da ação.
- [ ] approval é single-use.
- [ ] approval expira.
- [ ] replay de approval falha.
- [ ] policy decision vira `AgentEvidenceV1`.
- [ ] tool execution/result vira `AgentEvidenceV1`.
- [ ] shadow mode funciona.
- [ ] simulate contra histórico existe.
- [ ] secrets não vazam.
- [ ] crash matrix cobre efeito externo ambíguo.
- [ ] exemplo real bloqueia uma ação e aprova outra.

---

## 36. Fora do DoD

Não bloquear o MVP esperando:

- suporte a todo IdP;
- todo framework;
- visual policy builder;
- OPA/Rego;
- Cedar;
- WASM policy plugins;
- sandbox universal;
- browser extension;
- SSH proxy;
- SQL proxy;
- EDR.

---

## 37. Ordem de implementação

```text
P0.1 generic action/policy types
P0.2 extract/reuse deterministic policy evaluator
P0.3 MCP reverse proxy pass-through
P0.4 typed tool request canonicalization
P0.5 shadow evaluation + evidence
P0.6 enforce ALLOW/DENY
P0.7 approval model + API
P0.8 action-binding + single-use
P0.9 OIDC/JWT validator
P0.10 historical policy simulation
P0.11 chaos/restart qualification
P0.12 sample finance/github/filesystem tool
```

---

## 38. Frase de aceitação

Quando concluída, deve ser verdadeiro dizer:

> **Coloque o Heraclitus na frente dos seus servidores MCP. Ele identifica agente e usuário, aplica uma policy determinística, exige aprovação humana para ações sensíveis e registra uma evidência verificável da decisão e da execução.**
