# SPEC-0076 — Heraclitus Agent Evidence Console, Packaging & Productization

> **GLOBAL HOME / PRODUCT PIVOT SUPERSEDED BY SPEC-0077.**
>
> A Agent Evidence Console continua suportada, **sob `/agent`**. Deixou de
> ser a consola por omissão do HeraclitusDB: a raiz (`/`) é a Platform
> Console. Caducaram as disposições "Agent Console = home global",
> "Agent Black Box = nome do produto", "AI Agent Evidence & Control =
> produto default", e o README/quickstart principais centrados em agentes.
>
> Os quatro estados honestos de integridade, o RBAC com `approver` e
> `policy_admin` separados (§28) e o empacotamento mantêm-se válidos.

**Status:** IMPLEMENTADA em v2.0.0 — Consola embutida em `ui/agent-console`, quickstart em `examples/agent-black-box`, README pivotado
**Por medir:** o teste de onboarding humano de §45 (três pessoas, ambiente limpo) e os gates de adopção de §42 são medições de campo, não de código.  
**Status original:** PROPOSED — PRODUCT PIVOT / P0  
**Prioridade:** P0 — transformar SPEC-0074/0075 em produto instalável  
**Baseline auditado:** `JoseRFJuniorLLMs/HeraclitusDB @ 74f921f1ad25cf27c399522c5c0d27c8ec084009`  
**Depende de:** SPEC-0074; integra SPEC-0075 quando disponível  
**Objetivo:** superfície de produto pequena, compreensível e demonstrável em menos de cinco minutos  

---

## 0. Decisão

O Heraclitus já possui mais capacidade interna do que sua apresentação comercial consegue explicar.

Esta SPEC resolve o problema inverso:

```text
menos superfície
mais clareza
```

O produto default deixa de parecer:

```text
database + SIEM + SOC + graph + vector + AI + compliance + GPU
```

e passa a parecer:

```text
AI Agent Evidence & Control
```

A complexidade continua por baixo.

---

## 1. Nome de produto

Nome de trabalho:

```text
Heraclitus Agent Black Box
```

Quando SPEC-0075 estiver ativa:

```text
Heraclitus Agent Control
```

O motor continua:

```text
HeraclitusDB
```

A UI não usa “DB” como conceito principal.

---

## 2. Proposta de valor

A primeira dobra do README/site precisa comunicar em menos de 10 segundos:

> **Know exactly what your AI agent did. Prove who authorized it. Detect if the history was changed.**

Versão portuguesa:

> **Saiba exatamente o que seu agente de IA fez. Prove quem autorizou. Detecte qualquer alteração posterior no histórico.**

A primeira dobra não contém:

- HTAP;
- Bε-tree;
- manifold;
- HNSW;
- ACT-R;
- DataFusion;
- WGSL;
- Raft;
- número de crates;
- “military grade”;
- comparação com PostgreSQL.

Esses detalhes permanecem na documentação técnica.

---

## 3. Usuário-alvo inicial

Usuário inicial:

```text
AI engineer / platform engineer
que possui agentes com tool calls
e precisa saber/controlar o que eles fazem
```

Compradores posteriores:

```text
security engineering
compliance
risk
internal audit
CISO
```

A adoção começa pelo desenvolvedor, não por uma licitação nacional de três anos.

---

## 4. Jobs to be Done

A UI atende cinco tarefas.

### JTBD-1 — Ver uma execução

```text
What did the agent do?
```

### JTBD-2 — Entender uma ação

```text
Under which observable evidence and authorization did this tool run?
```

“Why” significa:

```text
observable evidence
policy
tool call lineage
approved inputs
```

Não significa expor chain-of-thought privado do modelo.

### JTBD-3 — Aprovar/negar

Com SPEC-0075:

```text
Should this action be allowed?
```

### JTBD-4 — Verificar integridade

```text
Has this evidence been altered?
```

### JTBD-5 — Exportar

```text
Give me a package I can hand to audit/forensics.
```

Toda tela fora desses cinco fluxos precisa justificar sua existência.

---

## 5. Navegação

MVP com gateway:

```text
Runs
Approvals
Policies
Evidence
Settings
```

Sem gateway:

```text
Runs
Evidence
Settings
```

Menu SOC não aparece por default.

---

## 6. Home / Runs

Layout conceitual:

```text
┌─────────────────────────────────────────────────────────────┐
│ Heraclitus Agent Black Box                   ● VERIFIED     │
├─────────────────────────────────────────────────────────────┤
│ Runs                                                        │
│                                                             │
│ 08:41  procurement-agent   7 tools   1 approval   success  │
│ 08:37  support-agent       2 tools   0 approval   success  │
│ 08:31  coding-agent        9 tools   2 denied     failed   │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

Filtros mínimos:

```text
time
agent
status
tool
policy decision
human approver
```

Sem visual query builder no MVP.

---

## 7. Run detail

Tela principal do produto:

```text
Run 01J...
Agent: procurement-agent
User:  jose@example
Started: 08:41:02
Status: SUCCESS
Integrity: VERIFIED

Timeline
──────────────────────────────────────────
08:41:02 Run started
08:41:03 Model invocation
08:41:04 Tool requested: lookup_vendor
08:41:04 Policy: ALLOW
08:41:04 Tool result
08:41:07 Tool requested: send_payment
08:41:07 Policy: REQUIRE_APPROVAL
08:41:19 Approved by finance-cfo
08:41:20 Tool executed
08:41:21 External effect: payment 84723
08:41:22 Agent output
```

Cada linha expandida mostra:

```text
correlation ids
safe metadata
hashes
policy reference
approval reference
proof status
```

---

## 8. Estados de integridade

Mostrar apenas:

```text
VERIFIED
UNVERIFIED
BROKEN
PARTIAL
```

### VERIFIED

Tudo exigido pelo contrato de verificação passou.

### UNVERIFIED

Verificação necessária ainda não foi executada.

### BROKEN

Digest/proof/root falhou.

### PARTIAL

Seleção contém evidência válida, porém faltam artefatos opcionais ou o pacote é propositalmente parcial.

Nunca transformar “não verificado” em “válido” só porque a UI gosta de verde.

---

## 9. Evidence detail

```text
Evidence #E-99128

Type: ToolInvocationFinished
Tool: send_payment

Record hash:
8af...

HRKL LSN:
918223

Logical root:
00ab...

Merkle proof:
VALID

RFC3161:
NOT CONFIGURED

Policy:
agent-policy-v17 / finance-large

Approval:
A-771 / VALID

[VERIFY AGAIN]
[EXPORT EVIDENCE]
```

---

## 10. Approval inbox

Quando gateway estiver ativo:

```text
Pending approvals (3)

HIGH
procurement-agent
send_payment
R$ 75,000
policy: finance-large
expires in 02:31

[Review]
```

Não criar “Approve all”.

---

## 11. Policy page

MVP não precisa de drag-and-drop.

Mostrar:

```text
ACTIVE agent-policy-v17
hash ...
activated by ...
activated at ...

[View]
[Simulate new policy]
```

Editor opcional:

```text
YAML
validate
simulate
activate
```

Ativação exige permissão administrativa.

---

## 12. Evidence export

Botão:

```text
Export Evidence Bundle
```

Escopos:

```text
this run
time window
selected evidence
```

Futuramente:

```text
case / incident
```

O resultado usa SPEC-0074.

Mostrar comando:

```bash
heraclitus agent verify evidence-01J....zip
```

---

## 13. Dashboard: o que NÃO fazer

Não recriar um SOC dashboard com 30 cards.

Home pode ter somente:

```text
Runs (24h)
Tool calls (24h)
Denied actions
Pending approvals
Evidence integrity
```

e lista de runs recentes.

Evitar:

- mapa mundi;
- gauge decorativo;
- gráfico 3D;
- ATT&CK matrix default;
- threat feed;
- risk score sem ação;
- CPU/RAM na home;
- dezenas de charts.

Operação técnica fica em `/admin` e `/metrics`.

---

## 14. Distribuição

Primeira instalação:

```bash
docker compose up -d
```

ou:

```bash
docker run ...
```

Modo local precisa de uma única imagem principal.

Persistência:

```text
/var/lib/heraclitus
```

Portas sugeridas:

```text
8080  Console/API
4318  OTLP HTTP
4317  OTLP gRPC
8787  MCP Gateway optional
```

Portas internas históricas podem continuar, mas não lideram o quickstart.

---

## 15. Single-binary preference

O servidor Rust pode embutir assets estáticos da Console.

Objetivo:

```text
one container
one volume
no Node runtime in production
```

Build frontend separado é aceitável.

Se o dashboard SOC existente tiver componentes úteis, reutilizar componentes visuais, não a arquitetura mental inteira do SOC.

---

## 16. Layout de repositório

Alvo:

```text
crates/
  heraclitus-agent/
  heraclitus-agent-ingest/       # somente se necessário
  heraclitus-agent-gateway/      # SPEC-0075

ui/
  agent-console/

examples/
  agent-black-box/

docs/
  agent/
    quickstart.md
    otel.md
    mcp.md
    privacy.md
    evidence.md
    policy.md
```

Adaptar diretórios equivalentes existentes em vez de duplicar.

---

## 17. Surface boundaries

Produto default:

```text
agent evidence
```

Opcional:

```text
agent gateway
sentinel
gpu
analytics
```

Não é obrigatório criar uma feature flag Cargo para tudo. A obrigação é separar superfície de produto e dependências, não cultivar uma floresta de `#[cfg]`.

---

## 18. Legacy SOC

A funcionalidade atual não é apagada.

Porém:

1. não aparece no quickstart;
2. não é home;
3. não é necessária para Agent Black Box;
4. recebe status advanced/legacy/research para fins comerciais;
5. roadmap SOC deixa de governar P0.

Endpoints `/sentinel/*` permanecem compatíveis enquanto possível.

---

## 19. README novo

Ordem obrigatória:

```text
1. problema em uma frase
2. GIF/screenshot
3. 5-minute quickstart
4. what gets captured
5. verify evidence demo
6. policy gateway demo
7. privacy
8. architecture
9. benchmarks
10. internals
```

Não começar com manifesto, matemática ou lista de crates.

---

## 20. Quickstart

```bash
git clone ...
cd HeraclitusDB/examples/agent-black-box
docker compose up -d
python sample.py
```

Depois:

```text
http://localhost:8080
```

Tela esperada:

```text
1 run
3 tool calls
integrity VERIFIED
```

---

## 21. Demo canônico

Criar demo que qualquer pessoa entende.

`procurement-agent`:

```text
1. pesquisa fornecedor
2. lê preço
3. tenta pagamento pequeno
4. tenta pagamento grande
```

Com gateway:

```text
small -> REQUIRE finance-operator
large -> REQUIRE cfo
```

ou:

```text
unknown vendor -> DENY
```

No fim:

```text
export evidence bundle
verify bundle
tamper one byte
verify must fail
```

---

## 22. `heraclitus agent demo`

Adicionar, se não inflar a CLI:

```bash
heraclitus agent demo
```

Demo deve funcionar sem API key externa e sem serviço pago.

Output:

```text
Demo run created: 01J...
Console: http://localhost:8080/runs/01J...
Evidence integrity: VERIFIED
```

---

## 23. `heraclitus agent doctor`

Verifica:

```text
data directory writable
HRKL opens
current integrity
OTLP listener
console
gateway mode
TLS production requirements
active policy
identity provider reachability if configured
clock
disk space
```

Saída orientada a ação.

---

## 24. Setup wizard

Primeira execução:

```text
How do you want to start?

[ Connect OpenTelemetry ]
[ Put Heraclitus in front of MCP ]
[ Run local demo ]
```

Não perguntar sobre:

```text
manifold dimensions
tiering policy
threat feeds
GPU
```

no onboarding.

---

## 25. Privacy UX

Settings mostra claramente:

```text
Capture mode: METADATA_ONLY
Prompt bodies: OFF
Completion bodies: OFF
Tool args: REDACTED
Tool results: REDACTED
Known secret filters: ON
```

Troca para `FULL_EXPLICIT` exige warning e confirmação administrativa.

---

## 26. Status do produto

Mostrar:

```text
Evidence log: HEALTHY
Last verified root: ...
OTLP ingest: HEALTHY
MCP gateway: SHADOW / ENFORCE / DISABLED
Policy: v17
Pending approvals: 3
RFC3161: DISABLED / HEALTHY / DEGRADED
```

Não misturar com centenas de métricas de infraestrutura.

---

## 27. Multi-tenancy

MVP local pode ser single-tenant por instalação.

Tipos continuam carregando `tenant_id`.

Não lançar SaaS multi-tenant antes de isolamento estar qualificado.

---

## 28. Auth da Console

### DEV_LOCAL

- loopback;
- bootstrap credential;
- banner explícito.

### PRODUCTION

- OIDC;
- RBAC mínimo.

Roles:

```text
viewer
auditor
approver
policy_admin
system_admin
```

`approver` e `policy_admin` precisam ser separados.

---

## 29. RBAC

| Operação | viewer | auditor | approver | policy_admin | system_admin |
|---|---:|---:|---:|---:|---:|
| Ver runs | ✓ | ✓ | ✓ | ✓ | ✓ |
| Ver provas | ✓ | ✓ | ✓ | ✓ | ✓ |
| Exportar bundle |  | ✓ |  | ✓ | ✓ |
| Aprovar ação |  |  | ✓ |  | ✓ |
| Simular policy |  |  |  | ✓ | ✓ |
| Ativar policy |  |  |  | ✓ | ✓ |
| Alterar captura |  |  |  |  | ✓ |

Detalhes podem variar, mas o modelo não pode ser “admin ou nada”.

---

## 30. Search

MVP:

```text
run id
agent id/name
tool name
human subject
external effect id
policy decision
time
status
```

Sem linguagem proprietária.

Full text de prompt não é requisito porque prompt completo está OFF por default.

---

## 31. Performance da UI

Usar paginação/cursor.

Nunca carregar no browser:

```text
all runs
all evidence
all tool results
```

Timeline grande:

```text
virtualized list
bounded page fetch
```

---

## 32. Error design

Erros importantes são estados de produto:

```text
EVIDENCE_VERIFY_FAILED
INGEST_BACKPRESSURE
MCP_UPSTREAM_UNAVAILABLE
POLICY_INVALID
APPROVAL_EXPIRED
IDENTITY_VALIDATION_FAILED
CAPTURE_REDACTED
```

UI precisa dizer:

```text
what failed
what was affected
whether action executed
what operator should do
```

Não apenas `500`.

---

## 33. Integrity failure banner

Se verificação falhar:

```text
INTEGRITY FAILURE

Evidence in LSN range 918220–918240 could not be verified.

Agent execution data remains available for inspection,
but must not be represented as cryptographically verified.
```

O produto deve falhar honestamente.

---

## 34. Telemetria do próprio Heraclitus

Pode exportar OpenTelemetry, mas não ingerir recursivamente a própria telemetria como agent evidence sem namespace/filtro explícito.

Evitar:

```text
Heraclitus OTEL
 -> Heraclitus ingest
 -> Heraclitus OTEL
 -> ...
```

Teste obrigatório.

---

## 35. Packaging

Release inclui:

```text
heraclitus server binary
embedded console assets
default safe config
agent quickstart
offline verifier
SBOM
checksums
signature/provenance já suportadas
```

Manter controles de supply chain já existentes.

---

## 36. Docker image

Requisitos:

- non-root quando viável;
- writable data volume explícito;
- healthcheck;
- graceful SIGTERM;
- nenhuma secret embutida;
- versão visível;
- OCI labels;
- SBOM no processo de release.

Read-only rootfs deve ser suportável quando configuração não exigir escrita fora do volume.

---

## 37. Upgrade

Evidence format e policy history precisam sobreviver.

Teste:

```text
N-1 data
 -> start N
 -> read runs
 -> verify old evidence
 -> export bundle
```

Tornar provas antigas ilegíveis é regressão crítica.

---

## 38. Backup/restore

Documentar:

```text
backup data volume
restore
verify roots
start
```

Reutilizar tooling da SPEC-0049 quando aplicável.

Não criar segundo mecanismo de backup.

---

## 39. Analytics

P0 precisa somente:

```text
runs/time
tool calls/time
deny/time
approval/time
integrity status
top agents/tools
```

DataFusion pode continuar interno. Não é dependência cognitiva do produto.

---

## 40. Sem chatbot na Console do MVP

Não colocar LLM para explicar o próprio LLM antes de a timeline básica ser boa.

Se vier futuramente:

```text
derived
non-authoritative
linked to evidence
```

Nunca substitui evidência primária.

---

## 41. Mensagem comercial

Duas mensagens possíveis para teste:

A:

```text
Tamper-evident observability for AI agents
```

B:

```text
Authorization and forensic evidence for AI agents
```

O código não muda por causa do slogan.

---

## 42. Gate de adoção

Antes de iniciar novo megaprojeto comercial:

```text
>= 5 instalações externas independentes
>= 3 usuários retornando após a primeira semana
>= 1 integração feita por alguém que não é o autor
```

Esses números são gates de foco de produto, não métricas de vaidade.

---

## 43. Congelar como prioridade

Até atingir os gates acima, não priorizar comercialmente:

```text
Autonomous Investigation Swarm
Adversarial SOC Digital Twin
novo graph UI
novo vector engine
nova geometria
novo JIT
novo protocolo distribuído
novo dashboard SOC
```

Nada disso é apagado.

---

## 44. E2E

Automação deve provar:

```text
open console
run appears
open run
timeline loads
open tool call
integrity status loads
export bundle
approval flow when enabled
```

Preferir framework de browser já usado no repo, se houver.

---

## 45. Teste de onboarding humano

Pessoa com:

```text
Docker
Git
Python
```

e sem conhecimento do Heraclitus.

Objetivo:

```text
clone -> run -> see evidence < 5 min
```

Registrar:

```text
tempo
erros
passos que exigiram documentação extra
```

Se três pessoas travarem no mesmo passo, corrigir o produto, não criar mais 40 páginas de FAQ.

---

## 46. Definition of Done

SPEC-0076 está DONE quando:

- [ ] Console default é Agent Black Box, não SOC.
- [ ] Runs page existe.
- [ ] Run timeline existe.
- [ ] Evidence detail existe.
- [ ] Integrity states são honestos.
- [ ] Evidence export existe.
- [ ] Approval inbox aparece quando gateway ativo.
- [ ] Policy page permite pelo menos view/validate/simulate/activate no recorte implementado.
- [ ] Settings expõe capture/privacy mode.
- [ ] quickstart Docker existe.
- [ ] demo sem API key externa existe.
- [ ] doctor existe.
- [ ] single-container local install funciona.
- [ ] README segue a ordem desta SPEC.
- [ ] SOC não aparece como fluxo principal.
- [ ] release mantém SBOM/checksum/provenance.
- [ ] upgrade mantém verificação de evidência anterior.
- [ ] E2E cobre fluxo central.
- [ ] onboarding medido fica abaixo de 5 minutos em ambiente limpo razoável.

---

## 47. Roadmap pós-pivot

### P1

```text
SDK wrappers para frameworks sem OTEL adequado
GitHub/GitLab agent tool adapters
cloud IAM actions
signed approval receipts
OPA/Cedar adapter se houver demanda
retention policies
enterprise SSO
```

### P2

```text
cross-agent causal graph
forensic comparison
policy regression laboratory
compliance templates
organization-wide agent inventory
```

### P3

Reavaliar partes do roadmap SOC somente se usuários do Agent Black Box realmente pedirem.

---

## 48. Relação entre as SPECs

```text
SPEC-0074
CAPTURE + PROVE
        │
        ▼
SPEC-0075
CONTROL + APPROVE
        │
        ▼
SPEC-0076
INSTALL + UNDERSTAND + ADOPT
```

Sem 0074:

```text
0075 = gateway sem memória verificável
```

Sem 0075:

```text
0074 ainda é produto útil
```

Sem 0076:

```text
0074 + 0075 = ótima infraestrutura que ninguém descobre
```

---

## 49. Demo de dois minutos

O produto final precisa demonstrar:

```text
1. agente tenta usar ferramenta
2. Heraclitus registra intenção
3. policy exige aprovação
4. humano aprova
5. ferramenta executa
6. resultado é registrado
7. timeline mostra tudo
8. bundle é exportado
9. um byte é adulterado
10. verifier recusa o bundle adulterado
```

Essa é a demo.

Não o número de crates.

Não o benchmark isolado.

Não a quantidade de SPECs.

> **O produto é a cadeia verificável entre intenção, autorização e efeito.**
