# SPEC-0077 — HeraclitusDB Platform Restoration & Modular Product Surfaces

**Status:** PROPOSED — CORRECTIVE / PRODUCT ARCHITECTURE  
**Prioridade:** P0  
**Natureza:** correção de posicionamento, navegação, empacotamento e superfície de produto  
**Produto principal:** **HeraclitusDB**  
**Módulo afetado:** Agent Black Box / Agent Evidence & Control  
**Relacionadas:** SPEC-0074, SPEC-0075, SPEC-0076  
**Regra de precedência:** esta SPEC substitui as decisões de posicionamento comercial, home, onboarding e produto default das SPEC-0074/0075/0076. As funcionalidades técnicas dessas SPECs permanecem válidas.

---

# 0. DECISÃO EXECUTIVA

As SPEC-0074, SPEC-0075 e SPEC-0076 introduziram capacidades tecnicamente úteis para agentes de IA, mas produziram uma consequência arquitetural e comercial indesejada:

```text
HeraclitusDB
    ↓
foi apresentado como
    ↓
Heraclitus Agent Black Box
```

Essa decisão está REVOGADA.

A partir desta SPEC:

```text
HeraclitusDB
```

volta a ser:

> **a plataforma principal de armazenamento temporal verificável, inteligência sobre dados, proveniência, auditoria, investigação, analytics e segurança.**

`Agent Black Box` deixa de ser a identidade do produto.

Passa a ser apenas um dos módulos disponíveis:

```text
HeraclitusDB
│
├── Data Platform
├── Gov Intelligence
├── Investigations
├── Analytics
├── Sentinel
└── Agent Evidence & Control
```

Portanto:

```text
Agent Black Box != HeraclitusDB
Agent Black Box = módulo do HeraclitusDB
```

Nenhuma funcionalidade implementada pelas SPEC-0074/75/76 deve ser apagada apenas por causa desta mudança.

O objetivo é **corrigir a hierarquia do produto**, não destruir código funcional.

---

# 1. PROBLEMA QUE ESTA SPEC CORRIGE

O HeraclitusDB possui capacidades muito mais amplas que observabilidade de agentes:

```text
HRKL v6
append-only canonical log
Merkle proofs
AS OF LSN
AS OF TIMESTAMP
bitemporalidade
grafo
HNSW
BM25
índices de atributos
DataFusion
Arrow
proveniência
replay determinístico
RFC 3161
compliance
Raft
tiering
Sentinel
investigação
analytics
```

Entretanto, após as SPEC-0074/75/76, a superfície principal passou a comunicar apenas:

```text
Runs
Agents
Tool calls
Approvals
Policies
Evidence
```

Isso reduz um sistema de dados e inteligência inteiro a um caso de uso específico.

É conceitualmente equivalente a transformar PostgreSQL inteiro numa interface para logs de chatbot porque alguém adicionou uma extensão.

Esta SPEC elimina essa inversão.

---

# 2. REGRA DE PRECEDÊNCIA SOBRE AS SPECS 0074–0076

As três SPECs permanecem válidas **somente para seus módulos técnicos**.

## SPEC-0074

Continua válida para:

```text
AgentEvidenceV1
OTLP ingest
MCP capture
Evidence Bundle
offline verifier
evidência de agentes
```

Deixa de valer onde disser ou implicar:

```text
"product pivot"
"first product"
"produto exposto = Agent Black Box"
"não apresentar Heraclitus como database/platform"
```

---

## SPEC-0075

Continua válida para:

```text
Agent Policy Gateway
ALLOW
DENY
REQUIRE_APPROVAL
delegation
authorization binding
MCP gateway
```

Nada disso define a identidade global do HeraclitusDB.

É um módulo.

---

## SPEC-0076

Continua válida apenas para:

```text
Agent Console
Runs
Approvals
Policies
Agent Evidence
Agent Settings
```

Está REVOGADA qualquer disposição que determine:

```text
Agent Console = home global
Agent Black Box = nome do produto
AI Agent Evidence & Control = produto default
README principal centrado em agentes
quickstart principal centrado em agentes
```

A Agent Console passa a residir sob superfície própria.

---

# 3. IDENTIDADE OFICIAL DO PRODUTO

Nome principal:

```text
HeraclitusDB
```

Descrição curta recomendada:

> **Temporal, Verifiable Data & Intelligence Platform**

Versão portuguesa:

> **Plataforma temporal e verificável de dados, inteligência e auditoria.**

Uma versão mais técnica pode usar:

> **Banco de dados multimodelo temporal e plataforma de inteligência com proveniência verificável.**

Não usar como título principal:

```text
Heraclitus Agent Black Box
Heraclitus Agent Control
AI Agent Evidence Platform
```

Esses nomes podem existir dentro do módulo de agentes.

---

# 4. ARQUITETURA DE PRODUTO

A arquitetura visual e conceitual passa a ser:

```text
                         HERACLITUSDB
                              │
        ┌─────────────────────┼─────────────────────┐
        │                     │                     │
        ▼                     ▼                     ▼
   DATA PLATFORM       GOV INTELLIGENCE         ANALYTICS
        │                     │                     │
        │                     │                     │
        ├──────────────┬──────┴──────────┬──────────┤
                       │                 │
                       ▼                 ▼
                  SENTINEL         AGENT EVIDENCE
                                       &
                                    CONTROL
```

Internamente todos reutilizam:

```text
HRKL
temporal engine
indices
query
provenance
Merkle
compliance
storage
```

---

# 5. SUPERFÍCIES DE PRODUTO

O produto deve apresentar pelo menos quatro categorias conceituais.

## 5.1 Data Platform

Capacidades:

```text
datasets
ingestion
query
search
timeline
graph
indexes
storage
integrity
provenance
```

Esta é a superfície base.

---

## 5.2 Intelligence

Voltada a:

```text
dados públicos
auditoria
fraude
compliance
investigações
correlação de entidades
relações
eventos históricos
análise temporal
```

Não deve ficar limitada a governo.

O módulo precisa funcionar também para:

```text
financeiro
seguros
saúde
telecom
indústria
compliance corporativo
pesquisa
```

---

## 5.3 Sentinel

Permanece módulo de:

```text
SOC
cybersecurity
Sigma
correlação
threat intelligence
investigation
incident response
```

Não é a home default.

---

## 5.4 Agent Evidence & Control

Agrupa:

```text
Agent Black Box
Agent Policy Gateway
Agent Evidence Console
OTLP GenAI
MCP capture
approvals
policy
Evidence Bundles
```

É uma aplicação especializada do mesmo motor temporal e verificável.

---

# 6. REGRA FUNDAMENTAL DA UI

Ao abrir:

```text
http://localhost:8080/
```

o usuário NÃO deve cair em:

```text
Agent Black Box
Runs
procurement-agent
support-agent
Approvals
Policies
```

O `/` pertence ao **HeraclitusDB Platform Console**.

A Agent Console deverá ficar em:

```text
/agent
```

ou:

```text
/modules/agent
```

Preferência desta SPEC:

```text
/agent
```

---

# 7. NOVA ESTRUTURA DE UI

Criar:

```text
ui/
├── platform-console/
└── agent-console/
```

`ui/agent-console` existente deve ser preservado.

Não renomear nem destruir sem necessidade.

O novo:

```text
ui/platform-console/
```

torna-se a superfície principal.

Estrutura mínima:

```text
ui/platform-console/
├── index.html
├── console.js
└── console.css
```

Se a arquitetura existente justificar componentes compartilhados:

```text
ui/shared/
```

pode ser criado.

Não introduzir React/Vue/Svelte ou uma nova toolchain somente para realizar esta SPEC se a UI atual é estática e suficiente.

---

# 8. HOME DO HERACLITUSDB

A home deve representar **o sistema inteiro**.

Modelo conceitual:

```text
┌──────────────────────────────────────────────────────────────┐
│ HERACLITUSDB                              ● HEALTHY         │
│ Temporal Verifiable Data & Intelligence Platform            │
├──────────────────────────────────────────────────────────────┤
│                                                              │
│ DATA                                                         │
│  Events             82,441,932                               │
│  Datasets                   12                               │
│  Sources                     8                               │
│  Last LSN           82,441,932                               │
│                                                              │
│ INTEGRITY                                                    │
│  HRKL                 VERIFIED                               │
│  Merkle               VERIFIED                               │
│  RFC3161            CONFIGURED / DISABLED                    │
│                                                              │
│ STORAGE                                                      │
│  Hot                     ...                                 │
│  Warm                    ...                                 │
│  Cold                    ...                                 │
│                                                              │
├──────────────────────────────────────────────────────────────┤
│ Recent datasets / recent events / investigations             │
└──────────────────────────────────────────────────────────────┘
```

Esses valores devem vir de APIs reais.

**É proibido inventar métricas falsas apenas para deixar a tela bonita.**

Se determinada informação ainda não possuir endpoint:

```text
N/A
Unavailable
Not configured
```

é melhor que dado fictício.

---

# 9. NAVEGAÇÃO PRINCIPAL

A navegação alvo:

```text
Overview
Data
Explore
Timeline
Graph
Investigations
Analytics
Integrity
Modules
Admin
```

Não é obrigatório implementar toda funcionalidade nova nesta SPEC.

A regra é:

> uma página só deve ser adicionada se houver backend funcional correspondente ou se estiver explicitamente marcada como indisponível.

Nunca criar dashboard decorativo.

---

# 10. OVERVIEW

A home deve responder imediatamente:

```text
O banco está saudável?
Quantos dados existem?
Quais fontes estão carregadas?
Qual o estado da integridade?
Qual o último LSN?
Existe atividade recente?
Quais módulos estão ativos?
```

Não deve responder prioritariamente:

```text
quantos agentes executaram hoje?
quantas tools um agente chamou?
```

Essas perguntas pertencem a `/agent`.

---

# 11. DATA

A seção Data representa dados persistidos no Heraclitus.

Conceitos possíveis:

```text
Datasets
Sources
Events
Schemas
Ingestion
Storage
```

Exemplo:

```text
Dataset                  Records        Updated
---------------------------------------------------
compras-publicas          18.2M          10:42
contratos                  7.8M          10:41
fornecedores               2.7M          10:37
pagamentos                42.1M          10:33
```

Esses nomes são exemplo, não devem ser hardcoded.

O sistema deve listar dados reais carregados pelo usuário.

---

# 12. EXPLORE

A área de exploração deve permitir acessar as capacidades existentes do Heraclitus:

```text
texto
atributos
vetor
grafo
query
```

Uma busca deve poder retornar:

```text
eventos
entidades
documentos
relações
```

conforme os índices disponíveis.

A UI não precisa recriar um IDE de banco completo nesta SPEC.

Um explorador funcional simples é preferível a vinte widgets falsos.

---

# 13. TIMELINE

A temporalidade é uma das capacidades distintivas do Heraclitus.

Ela deve ganhar uma superfície explícita.

Conceitos:

```text
AS OF LSN
AS OF TIMESTAMP
VALID AT
history
changes
```

Exemplo visual:

```text
2024                 2025                 2026

●────────────────────●──────────●──────────●

contract_created
supplier_changed
payment
sanction
```

O usuário deve poder selecionar um ponto temporal quando as APIs existentes permitirem.

---

# 14. GRAPH

A UI deve reconhecer que o Heraclitus possui capacidades de grafo.

Representar:

```text
entities
relationships
paths
causal/provenance edges
```

Não é requisito desta SPEC criar um renderizador 3D absurdo consumindo metade da GPU para mostrar seis círculos saltando pela tela.

Uma visualização 2D funcional basta.

Se ainda não houver biblioteca apropriada, entregar primeiro tabela + adjacency/path view.

---

# 15. INTEGRITY

Esta é uma das superfícies centrais do produto.

Mostrar:

```text
HRKL status
last verified LSN
logical root
Merkle state
segment state
verification status
RFC3161 status
compliance status
```

Estados devem ser honestos:

```text
VERIFIED
UNVERIFIED
PARTIAL
BROKEN
NOT CONFIGURED
```

A mesma filosofia correta criada na SPEC-0076 deve ser reaproveitada aqui.

---

# 16. PROVENIÊNCIA

Para registros suportados:

```text
record
↓
source
↓
ingestion
↓
event
↓
LSN
↓
parents
↓
Merkle proof
```

Deve ser possível navegar da informação até sua origem verificável.

Este é um diferencial global do Heraclitus, não algo exclusivo de agentes.

---

# 17. INVESTIGAÇÕES

Criar conceito de investigação/case na superfície geral somente se houver suporte real suficiente.

Objetivo futuro:

```text
investigation
├── entities
├── events
├── queries
├── evidence
├── notes
└── exports
```

Agent Evidence pode futuramente ser anexado a uma investigação, mas não define a investigação inteira.

---

# 18. MODULES

Criar página:

```text
/modules
```

ou item de menu `Modules`.

Mostrar:

```text
Agent Evidence & Control
Sentinel
Analytics
GPU
Compliance
```

Cada módulo deve informar:

```text
ENABLED
DISABLED
DEGRADED
NOT CONFIGURED
```

Exemplo:

```text
Agent Evidence & Control
Capture and control AI-agent activity.

Status: DISABLED

[Configure]
```

Isso é onde Agent Black Box deve aparecer.

---

# 19. AGENT BLACK BOX COMO MÓDULO

Nome recomendado no menu:

```text
Agent Evidence
```

Nome interno/marketing secundário:

```text
Agent Black Box
```

Rota:

```text
/agent
```

Subrotas conceituais:

```text
/agent/runs
/agent/approvals
/agent/policies
/agent/evidence
/agent/settings
```

Se a Console atual é single-page, pode continuar usando roteamento interno equivalente.

O essencial é:

```text
/
```

não ser a Agent Console.

---

# 20. FUNCIONALIDADE DO AGENT BLACK BOX

Nada desta SPEC deve quebrar:

```text
OTLP HTTP
OTLP gRPC
MCP capture
MCP proxy
AgentEvidenceV1
Evidence Bundles
offline verify
policy engine
human approval
OIDC/JWT
Agent Console
```

Todas continuam existindo.

Mudança:

```text
antes:
Agent Black Box = produto

depois:
Agent Black Box = módulo
```

---

# 21. ATIVAÇÃO DO MÓDULO DE AGENTE

A inicialização do HeraclitusDB não deve depender do módulo de agente.

Configuração alvo:

```toml
[modules.agent]
enabled = false
```

ou equivalente à configuração atual.

Quando:

```text
enabled = false
```

não é necessário iniciar:

```text
OTLP :4317
OTLP :4318
MCP Gateway :8787
```

Quando:

```text
enabled = true
```

as superfícies específicas podem ser ativadas.

Se quebrar compatibilidade deixar `enabled=true` como default temporário, documentar a decisão.

Mas mesmo nesse caso:

```text
default UI != Agent Console
```

---

# 22. CLI

O namespace já criado deve continuar:

```bash
heraclitus agent ...
```

Isso é correto.

Não promover:

```bash
heraclitus agent ...
```

como se fosse a única função do binário.

O help principal deve apresentar primeiro capacidades gerais:

```text
server
query
inspect
verify
prove
ingest
analytics
agent
sentinel
```

conforme comandos realmente existentes.

Não listar comandos inexistentes.

---

# 23. README PRINCIPAL

O README deve voltar a começar com:

```text
HeraclitusDB
```

e não:

```text
Heraclitus Agent Black Box
```

Primeira dobra sugerida:

```markdown
# HeraclitusDB

Temporal, Verifiable Data & Intelligence Platform

An append-only multimodel data platform for temporal queries,
graph/vector/text retrieval, auditable provenance and
cryptographically verifiable history.
```

Depois:

```text
Why HeraclitusDB
Architecture
Quickstart
Core capabilities
Use cases
Modules
Benchmarks
Security/compliance
Agent Evidence
Sentinel
Internals
```

Agent Evidence deve aparecer como uma seção.

Não como título.

---

# 24. CASOS DE USO NO README

Apresentar pelo menos:

```text
Public-data intelligence
Fraud & compliance
Audit & provenance
Temporal analytics
AI/knowledge retrieval
Cybersecurity/SOC
AI-agent evidence
```

Nenhum desses deve ser apresentado como a identidade exclusiva do produto.

---

# 25. DADOS PÚBLICOS

Restaurar explicitamente o caso de uso de dados públicos.

Exemplos de classe de dados:

```text
contratos
compras
pagamentos
fornecedores
empresas
servidores
sanções
transferências
processos
publicações
```

O README pode mencionar fontes brasileiras quando houver integração ou exemplo real correspondente.

Não afirmar suporte nativo a uma fonte específica se não existir ingestor para ela.

---

# 26. NOVO QUICKSTART PRINCIPAL

O quickstart principal deve demonstrar o **HeraclitusDB**.

Ele não pode exigir agente de IA.

Deve haver um fluxo equivalente a:

```text
1. iniciar servidor
2. inserir dataset/eventos
3. executar consulta
4. consultar histórico
5. verificar integridade
```

Meta:

```text
clone
start
load sample
query
verify
```

em poucos minutos.

---

# 27. EXEMPLO PRINCIPAL

Hoje existe:

```text
examples/agent-black-box
```

Preservar.

Adicionar:

```text
examples/data-platform
```

ou:

```text
examples/public-data
```

Preferência:

```text
examples/data-platform
```

O exemplo deve funcionar offline com fixtures pequenas incluídas no repositório.

Não fazer o quickstart principal depender de:

```text
Portal da Transparência online
API externa
token
LLM
OpenAI
Anthropic
internet
```

O exemplo deve ser reproduzível.

---

# 28. DEMO CANÔNICO DA PLATAFORMA

Criar dataset pequeno conceitualmente parecido com:

```text
organizations
suppliers
contracts
payments
sanctions
```

Exemplo:

```text
Org A
   │
   ├── contract -> Company X
   │                  │
   │                  └── owner -> Person Y
   │
   └── payment -> Company X
```

Demonstrar:

```text
ingest
query
graph relation
AS OF
provenance
verify
```

Isso comunica o HeraclitusDB em minutos.

---

# 29. LANDING PAGE DE MÓDULOS

Exemplo:

```text
HERACLITUS MODULES

┌─────────────────────────────┐
│ Agent Evidence & Control    │
│ AI-agent audit and policy   │
│ DISABLED                    │
└─────────────────────────────┘

┌─────────────────────────────┐
│ Sentinel                    │
│ Security analytics / SOC    │
│ ENABLED                     │
└─────────────────────────────┘

┌─────────────────────────────┐
│ Analytics                   │
│ SQL / Arrow / DataFusion    │
│ ENABLED                     │
└─────────────────────────────┘

┌─────────────────────────────┐
│ Compliance                  │
│ RFC3161 / evidence          │
│ CONFIGURED                  │
└─────────────────────────────┘
```

Novamente:

**somente estados reais.**

---

# 30. SERVIDOR WEB

Alterar o servidor que atualmente entrega a Agent Console como superfície principal.

Target:

```text
GET /                 -> Platform Console
GET /agent            -> Agent Console
GET /agent/*          -> Agent Console assets/routes
```

APIs existentes:

```text
/api/v1/agent/*
```

devem permanecer compatíveis.

Não renomear API apenas por estética.

---

# 31. ASSETS

A incorporação de assets deve distinguir:

```text
PLATFORM_ASSETS
AGENT_ASSETS
```

ou abstração equivalente.

Não copiar HTML inteiro dentro de constantes Rust gigantes se já existe mecanismo de include/embedding adequado.

Evitar duplicação.

---

# 32. DESIGN

A Platform Console deve reutilizar linguagem visual do projeto, mas não precisa parecer a Agent Console.

Características:

```text
dark/light legível
tipografia técnica
densidade de informação razoável
timeline clara
integrity state evidente
tables úteis
graph funcional
```

Evitar:

```text
mapa-múndi inútil
gauges decorativos
3D
glassmorphism em excesso
30 cards sem função
animações sem significado
"AI powered" piscando
```

O software já é complicado o suficiente sem uma feira de PowerPoint no navegador.

---

# 33. NÃO CRIAR DADOS FALSOS

Regra absoluta.

É proibido colocar na produção:

```text
82M events
12 datasets
427 anomalies
99.99% integrity
```

como valores fictícios.

Mocks são permitidos apenas em:

```text
tests
fixtures
demo explicitamente identificado
```

---

# 34. DOCUMENTAÇÃO

Estrutura desejada:

```text
docs/
├── getting-started/
├── data/
├── query/
├── temporal/
├── graph/
├── provenance/
├── compliance/
├── sentinel/
└── agent/
```

Não é obrigatório reorganizar toda documentação nesta SPEC se causar churn desnecessário.

Obrigatório:

1. README principal corrigido.
2. Agent docs continuam sob `docs/agent`.
3. Agent não domina a documentação raiz.
4. criar quickstart da plataforma.
5. documentar arquitetura modular.

---

# 35. MARCAÇÃO DAS SPECS ANTIGAS

Editar cabeçalho das três SPECs.

## SPEC-0074

Adicionar:

```text
PRODUCT POSITIONING SUPERSEDED BY SPEC-0077.

Technical implementation remains active as the
HeraclitusDB Agent Evidence module.
```

## SPEC-0075

Adicionar:

```text
Product-wide positioning superseded by SPEC-0077.
This specification defines the optional Agent Policy Gateway module.
```

## SPEC-0076

Adicionar explicitamente:

```text
GLOBAL HOME / PRODUCT PIVOT SUPERSEDED BY SPEC-0077.

The Agent Evidence Console remains supported under /agent.
It is no longer the HeraclitusDB default console.
```

Não apagar histórico das SPECs.

Uma SPEC é registro de decisão técnica, não quadro-negro de escola.

---

# 36. COMPATIBILIDADE

É obrigatório preservar:

```text
heraclitus agent demo
heraclitus agent verify
heraclitus agent export
Agent Evidence API
Evidence Bundle format
AgentEvidenceV1
Policy formats
MCP proxy behavior
OTLP ingest
```

Breaking changes só são permitidas quando inevitáveis e documentadas.

Esta SPEC é predominantemente:

```text
routing
surface
branding
product composition
onboarding
configuration
documentation
```

não redesign do Agent Evidence Engine.

---

# 37. BACKEND DA PLATFORM CONSOLE

Antes de criar APIs novas, auditar as existentes.

Reutilizar:

```text
health
metrics
log status
LSN
verification
query
analytics
graph
storage
```

quando existentes.

Criar endpoints novos apenas quando a UI realmente precisar.

Preferir:

```text
/api/v1/platform/summary
```

para agregação leve, se isso evitar 15 requests.

Possível formato:

```json
{
  "status": "healthy",
  "last_lsn": 123456,
  "integrity": {
    "state": "verified"
  },
  "storage": {},
  "modules": {}
}
```

O formato final deve refletir tipos reais existentes.

---

# 38. MÓDULOS COMO CAPABILITIES

O servidor deve conhecer capabilities reais.

Exemplo conceitual:

```text
Capability::Analytics
Capability::Sentinel
Capability::AgentEvidence
Capability::Compliance
Capability::Gpu
```

A UI pode usar isso para decidir o que mostrar.

Não inferir disponibilidade somente porque uma rota respondeu 404.

---

# 39. AGENT CONSOLE NÃO PODE VAZAR PARA HOME

Teste obrigatório:

```text
GET /
```

não pode conter como heading principal:

```text
Agent Black Box
```

Teste equivalente deve validar:

```text
HeraclitusDB
```

na home.

Outro teste:

```text
GET /agent
```

deve continuar contendo a Agent Console quando módulo habilitado.

---

# 40. PORTAS

Porta principal:

```text
8080
```

pode continuar servindo console/API conforme arquitetura implementada.

Portas de agente:

```text
4317
4318
8787
```

são relacionadas ao módulo.

Elas não devem aparecer como essência do quickstart principal.

---

# 41. ONBOARDING

Ao iniciar pela primeira vez:

```text
Welcome to HeraclitusDB
```

e não:

```text
Welcome to Agent Black Box
```

Fluxos possíveis:

```text
[Load sample dataset]
[Connect a data source]
[Explore existing data]
[Configure modules]
```

Dentro de Modules:

```text
[Enable Agent Evidence]
[Enable Sentinel]
```

---

# 42. ADMIN

Admin deve conter:

```text
server
storage
modules
auth
compliance
resources
diagnostics
```

Configuração específica do agente permanece em:

```text
/agent/settings
```

ou subseção modular equivalente.

---

# 43. POSICIONAMENTO GOV

O HeraclitusDB pode voltar a apresentar fortemente:

```text
auditoria pública
proveniência
dados governamentais
inteligência contra fraude
integridade histórica
compliance
```

Mas o core do produto não deve depender da palavra `government`.

Estrutura:

```text
general platform
        ↓
government vertical
```

e não:

```text
government-only database
```

---

# 44. PRODUCT TAXONOMY

Taxonomia oficial:

```text
HeraclitusDB
│
├── Heraclitus Data Platform
│
├── Heraclitus Gov Intelligence
│
├── Heraclitus Analytics
│
├── Heraclitus Sentinel
│
└── Heraclitus Agent Evidence & Control
       ├── Agent Black Box
       └── Agent Policy Gateway
```

`Agent Black Box` pode continuar sendo nome reconhecível da funcionalidade de evidência.

Não deve ser o nome do repositório ou produto inteiro.

---

# 45. REPOSITÓRIO

Estrutura alvo:

```text
ui/
├── platform-console/
└── agent-console/

examples/
├── data-platform/
└── agent-black-box/

docs/
├── ...
└── agent/

crates/
├── heraclitus-agent/
├── heraclitus-agent-gateway/
├── heraclitus-sentinel/
└── ...
```

Nenhuma crate Agent precisa ser removida.

---

# 46. README: ORDEM OBRIGATÓRIA

O README principal deve seguir:

```text
1. HeraclitusDB
2. proposta de valor
3. quickstart do banco/plataforma
4. por que append-only/temporal/verificável
5. dados / query / graph / vector / analytics
6. provenance / integrity
7. use cases
8. modules
9. Agent Evidence
10. Sentinel
11. benchmarks
12. architecture
13. compliance
14. build/development
15. license
```

Agent não pode ocupar os primeiros cinco blocos.

---

# 47. O QUE NÃO FAZER

Esta SPEC NÃO autoriza:

```text
remover heraclitus-agent
remover gateway
remover OTLP
remover MCP
remover Evidence Bundle
remover Agent Console
remover policy engine
remover Sentinel
```

Também NÃO autoriza voltar ao erro oposto:

```text
colocar 28 crates na primeira dobra
mostrar matemática inteira no onboarding
transformar home em documentação da arquitetura
```

A home deve explicar o produto.

Não o código-fonte inteiro.

---

# 48. TESTES

Adicionar testes para:

### Routing

```text
/                   => Platform Console
/agent              => Agent Console
/api/v1/agent/*     => preserved
```

### Module disabled

```text
Agent module disabled
→ platform still boots
→ core server still works
→ platform console works
```

### Module enabled

```text
Agent module enabled
→ OTLP works
→ MCP gateway works when configured
→ /agent works
```

### Branding

Teste simples contra assets produzidos:

```text
root page contains HeraclitusDB
root page does not identify entire product as Agent Black Box
```

### Existing regression

Executar toda suíte das:

```text
SPEC-0074
SPEC-0075
SPEC-0076
```

Nenhuma regressão funcional.

---

# 49. CI

A implementação deve passar:

```bash
cargo fmt --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
```

Além dos gates específicos já existentes no repositório.

Se frontend possuir testes próprios, executá-los também.

---

# 50. MIGRAÇÃO

Implementação em etapas.

## Fase 1

```text
corrigir branding
corrigir README
montar /agent
restaurar /
```

## Fase 2

```text
Platform Console mínima
health
LSN
integrity
modules
```

## Fase 3

```text
Data
Explore
Timeline
Graph
```

usando capacidades já existentes.

## Fase 4

```text
data-platform example
quickstart
docs
```

---

# 51. NÃO BLOQUEAR A CORREÇÃO POR UI PERFEITA

A restauração da identidade do produto não deve esperar meses por uma console perfeita.

Versão mínima aceitável:

```text
/
  HeraclitusDB
  health
  LSN
  integrity
  modules
  links para query/docs

/agent
  console existente
```

Depois a Platform Console pode evoluir.

O erro de produto precisa ser corrigido imediatamente.

---

# 52. DEFINITION OF DONE

Esta SPEC só está concluída quando todos forem verdadeiros:

```text
[ ] README começa com HeraclitusDB.
[ ] README não apresenta Agent Black Box como produto principal.
[ ] / abre HeraclitusDB Platform Console.
[ ] /agent abre Agent Evidence Console.
[ ] Agent module continua funcional.
[ ] SPEC-0074 continua funcional.
[ ] SPEC-0075 continua funcional.
[ ] SPEC-0076 continua funcional como módulo.
[ ] SPECs 0074/75/76 apontam para a supersessão pela 0077.
[ ] existe ui/platform-console.
[ ] ui/agent-console continua existindo.
[ ] existe quickstart não dependente de agentes.
[ ] existe exemplo data-platform reproduzível.
[ ] módulos aparecem como capabilities opcionais.
[ ] Agent não é requisito para iniciar o core.
[ ] nenhuma métrica fictícia aparece na UI.
[ ] testes de routing foram adicionados.
[ ] testes de regressão do Agent passam.
[ ] cargo fmt passa.
[ ] clippy passa.
[ ] workspace tests passam.
```

---

# 53. TESTE HUMANO DE ACEITAÇÃO

Mostrar o projeto a uma pessoa que nunca viu o Heraclitus.

Pergunta:

> “O que este software é?”

Resposta aceitável:

> “Uma plataforma/banco de dados temporal verificável para armazenar, investigar e analisar dados, com módulos de segurança e agentes.”

Resposta INACEITÁVEL:

> “É uma ferramenta para monitorar agentes de IA.”

Se a segunda resposta ocorrer, esta SPEC não foi implementada corretamente.

---

# 54. CRITÉRIO DE PRODUTO

O usuário deve conseguir usar HeraclitusDB durante meses sem:

```text
configurar agente
usar LLM
instalar MCP
enviar OTLP GenAI
aprovar tool call
```

e ainda obter o valor integral de:

```text
storage
query
temporal
graph
retrieval
analytics
integrity
provenance
compliance
```

Da mesma forma, quem precisar de agentes pode habilitar o módulo e receber todo o trabalho das SPEC-0074/75/76.

Essa é a composição correta.

---

# 55. INVARIANTE FINAL

A partir desta SPEC:

```text
HERACLITUSDB IS THE PRODUCT.
```

Seus módulos são:

```text
Data
Intelligence
Analytics
Sentinel
Agent Evidence
```

Portanto:

```text
Agent Black Box
```

é:

```text
uma aplicação especializada do HeraclitusDB
```

e nunca mais:

```text
a identidade global do HeraclitusDB.
```

---

# 56. INSTRUÇÃO FINAL AO AGENTE IMPLEMENTADOR

Não interpretar esta SPEC como solicitação para apagar as SPEC-0074/75/76.

O trabalho correto é:

```text
KEEP THE CAPABILITY
REMOVE THE PRODUCT PIVOT
RESTORE THE PLATFORM
ISOLATE THE AGENT SURFACE
```

Antes de alterar código:

1. localizar onde `ui/agent-console` é embutido;
2. localizar a rota atual `/`;
3. localizar inicialização OTLP/MCP;
4. localizar README e documentação Agent;
5. localizar configurações de módulo;
6. mapear APIs existentes que já podem alimentar a Platform Console.

Depois implementar na menor quantidade razoável de mudanças, preservando compatibilidade.

Não implementar mocks de produção.

Não inventar APIs desnecessárias.

Não reescrever o banco.

Não remover funcionalidades funcionais.

Não fazer outro pivô de produto.

**O objetivo desta SPEC é restaurar o HeraclitusDB como plataforma principal e manter Agent Black Box exatamente onde deveria ter estado desde o começo: como um módulo poderoso, opcional e especializado.**