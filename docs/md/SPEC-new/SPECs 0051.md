# Roadmap Pós-SPEC-0050 — Heraclitus Security Platform Beyond SIEM

## Objetivo

As SPECs 0051+ transformam o Heraclitus de:

```text
Temporal Multimodal Database
        +
SIEM/SOAR
```

em:

```text
Sovereign Security Intelligence Platform

        ┌─────────────────────┐
        │ Autonomous Defense  │
        ├─────────────────────┤
        │ SOC Operations      │
        ├─────────────────────┤
        │ Detection Science   │
        ├─────────────────────┤
        │ Security Graph      │
        ├─────────────────────┤
        │ Security Data Fabric│
        ├─────────────────────┤
        │ HeraclitusDB        │
        └─────────────────────┘
```

A estratégia possui duas fases:

```text
P0 = alcançar/parar de perder para Splunk/Sentinel

P1 = usar propriedades exclusivas do Heraclitus
     para ultrapassar o modelo tradicional de SIEM
```

---

# SPEC-0051 — Heraclitus Security Canonical Model

**Prioridade:** P0 — Crítica

### Objetivo

Criar uma camada semântica universal para eventos de segurança.

Equivalente conceitualmente a:

```text
Splunk CIM
+
OCSF
+
Heraclitus provenance
```

### Componentes

Criar:

```text
heraclitus-security-schema
```

com entidades canônicas:

```text
AuthenticationEvent
NetworkEvent
DnsEvent
HttpEvent
ProcessEvent
FileEvent
RegistryEvent
EndpointEvent
CloudEvent
IdentityEvent
ThreatIntelEvent
VulnerabilityEvent
EmailEvent
DataAccessEvent
PrivilegeEvent
AlertEvent
FindingEvent
IncidentEvent
```

### Invariante

O evento original nunca é destruído.

```text
Raw Event
   │
   ├──────────────► HRKL canonical raw evidence
   │
   ▼
Normalization
   │
   ▼
SecurityEvent
```

Toda normalização mantém:

```text
source_lsn
source_event_id
parser_id
parser_version
schema_version
normalization_timestamp
```

### Compatibilidade

Suportar mappings:

```text
OCSF
ECS
Splunk CIM
CEF
LEEF
OpenTelemetry
STIX
Windows Event
Syslog
```

### Diferencial Heraclitus

Permitir responder:

```text
qual evento bruto originou esta entidade normalizada?
```

com prova de proveniência.

---

# SPEC-0052 — Connector Fabric & Sovereign Edge Collector

**Prioridade:** P0 — Crítica

### Objetivo

Criar o equivalente Heraclitus dos Technology Add-ons, forwarders e connectors dos grandes SIEMs.

### Novo componente

```text
heraclitus-collector
```

### Inputs

Baseline:

```text
Syslog TCP/UDP
Syslog TLS
CEF
LEEF
JSON
NDJSON
OTLP
Windows Event Log
journald
auditd
eBPF telemetry
Kafka
HTTP Webhook
S3/Object Storage
SQL databases
REST polling
STIX/TAXII
```

### Pipeline

```text
Source
  ↓
Collector
  ↓
Parser
  ↓
Normalizer
  ↓
Security Canonical Model
  ↓
HRKL
```

### Requisitos

* backpressure;
* checkpoint;
* exactly-once quando possível;
* at-least-once com idempotência quando necessário;
* buffer offline;
* reconexão;
* TLS/mTLS;
* credential isolation;
* metrics;
* rate limiting;
* dead-letter queue;
* clock-skew detection.

### Air-gap

Collectors devem poder ser distribuídos e atualizados via pacotes offline assinados.

---

# SPEC-0053 — Heraclitus Security Content Hub

**Prioridade:** P0

### Objetivo

Criar um ecossistema distribuível de conteúdo de segurança.

Um pacote:

```text
.hrkp
Heraclitus Security Pack
```

poderá conter:

```text
Connector
Parser
Schema Mapping
Detection Rules
Threat Hunts
Dashboards
Playbooks
MITRE mappings
Threat Intel transforms
ML models
Documentation
Tests
```

### Exemplo

```text
windows-security.hrkp

├── connector
├── parser
├── normalization
├── detections
├── hunts
├── dashboards
├── playbooks
├── tests
└── manifest
```

### Segurança

Cada pacote deve possuir:

```text
publisher
version
dependencies
SBOM
content hash
digital signature
minimum Heraclitus version
permissions requested
```

### Modos

```text
ONLINE MARKETPLACE

ou

OFFLINE SOVEREIGN REPOSITORY
```

### Diferencial

Um órgão federal pode operar um Content Hub completamente desconectado da Internet.

---

# SPEC-0054 — Detection Engineering & Detection-as-Code

**Prioridade:** P0 — Crítica

### Objetivo

Transformar regras de detecção em software versionado e testável.

Cada detecção passa a possuir:

```text
Detection {
    id
    version
    author
    query
    severity
    confidence
    attack_mapping
    required_telemetry
    false_positive_notes
    tests
}
```

### Lifecycle

```text
Draft
  ↓
Unit Test
  ↓
Historical Replay
  ↓
Shadow
  ↓
Canary
  ↓
Production
  ↓
Monitor
```

### Recursos

* versionamento;
* diff;
* rollback;
* dependency tracking;
* Git integration;
* test datasets;
* synthetic events;
* performance budget;
* false-positive tracking;
* detection health;
* telemetry dependency validation.

### Regra importante

Nenhuma regra deve ir para produção apenas porque:

```text
query compilou
```

Ela deve provar que:

```text
detecta o positivo
não dispara no negativo
cabe no orçamento
possui telemetria disponível
```

---

# SPEC-0055 — Entity Risk Ledger & Risk-Based Alerting

**Prioridade:** P0 — Muito alta

### Objetivo

Não tratar cada alerta como incidente independente.

Criar:

```text
EntityRiskLedger
```

para:

```text
User
Host
Workload
ServiceAccount
Application
IP
Device
CloudResource
DataAsset
```

### Exemplo

```text
03:01 failed login       +5
03:07 unusual country    +8
03:12 MFA reset         +15
03:20 credential dump   +35
03:28 lateral movement  +40
                         ───
Risk                    103
```

Separadamente talvez fossem ruído.

Juntos representam:

```text
Account Takeover
```

### Score

Considerar:

```text
severity
confidence
asset criticality
identity privilege
source diversity
ATT&CK techniques
temporal proximity
novelty
behavior anomaly
threat intelligence
```

### Decay

Risk poderá decair temporalmente de forma determinística.

### Diferencial Heraclitus

O risco será temporal.

Será possível executar:

```text
SHOW RISK user:X AS OF LSN 99123
```

e saber exatamente por que o score era 83 naquele momento.

---

# SPEC-0056 — UEBA & Behavioral Baseline Engine

**Prioridade:** P0

### Objetivo

Criar User and Entity Behavior Analytics nativo.

### Entidades

```text
users
hosts
services
applications
devices
workloads
network segments
```

### Baselines

Aprender:

```text
login hours
countries
devices
process trees
network peers
data access volume
privilege use
resource usage
cloud API patterns
```

### Modelos

Primeira geração deve preferir modelos explicáveis:

```text
EWMA
robust z-score
quantiles
seasonality
change-point detection
peer-group models
frequency models
Markov transitions
```

Não enfiar um LLM em cada login porque a humanidade merece alguma economia de GPU.

### Output

```text
BehaviorFinding {
    entity
    feature
    expected
    observed
    deviation
    confidence
    baseline_window
}
```

---

# SPEC-0057 — Temporal Security Knowledge Graph

**Prioridade:** P0/P1

### Objetivo

Transformar o grafo genérico já existente em um grafo formal de segurança.

### Entidades

```text
Identity
User
Group
Role
Device
Host
Process
Service
Application
CloudResource
Secret
Credential
Vulnerability
Network
DataAsset
ThreatActor
IOC
Finding
Incident
```

### Relações

```text
AUTHENTICATED_TO

CAN_ACCESS

MEMBER_OF

ASSUMED_ROLE

COMMUNICATED_WITH

EXECUTED

OWNS

DEPENDS_ON

CONTAINS_SECRET

VULNERABLE_TO

OBSERVED_ON

TARGETED_BY
```

### Consultas

```text
What can this identity reach?

Which crown-jewel systems are reachable
from this compromised endpoint?

Which credentials connect these systems?

What was the attack path at LSN X?
```

### Diferencial

O grafo é temporal.

Portanto:

```text
attack path NOW
```

e:

```text
attack path WHEN THE INCIDENT HAPPENED
```

podem ser diferentes.

---

# SPEC-0058 — Attack Path, Blast Radius & Crown Jewels

**Prioridade:** P1

### Objetivo

Usar o Security Graph para análise preventiva.

### Recursos

```text
AttackPathFinder

BlastRadiusAnalyzer

PrivilegeEscalationGraph

LateralMovementGraph

CrownJewelReachability
```

### Exemplo

```text
Compromised Laptop
      │
      ▼
Cached Credential
      │
      ▼
Developer Account
      │
      ▼
CI Runner
      │
      ▼
Cloud Role
      │
      ▼
Production Database
```

### Score

Cada caminho recebe:

```text
probability
cost
required privileges
exploitability
asset impact
observed evidence
```

Não se limita a shortest-path.

---

# SPEC-0059 — Mission Control & Incident Case Management

**Prioridade:** P0

### Objetivo

Criar a superfície operacional do SOC.

### Nova abstração

```text
Finding
   ↓
Finding Group
   ↓
Investigation
   ↓
Incident
   ↓
Case
```

### Analyst Queue

Campos:

```text
priority
risk
status
owner
SLA
MITRE stage
affected entities
recommended action
```

### Investigation Timeline

```text
13:42 event
13:43 detection
13:44 enrichment
13:45 analyst note
13:47 Sentinel AI analysis
13:50 containment proposed
13:52 manager approved
13:53 playbook executed
```

Tudo vinculado a LSN.

### Colaboração

* owner;
* comments;
* mentions;
* evidence;
* tasks;
* handoff;
* review;
* escalation;
* incident merge;
* incident split.

---

# SPEC-0060 — Threat Hunting Workbench

**Prioridade:** P1

### Objetivo

Dar ao threat hunter uma bancada de investigação completa.

### Superfícies

```text
SQL
GQL
HUME
Python
Jupyter
Saved Hunts
Visual Query Builder
```

### Notebook

Todo notebook poderá ser pinado:

```text
snapshot_lsn = X
```

garantindo reprodução futura.

### Hunt → Detection

Um hunt validado poderá ser promovido para:

```text
Detection Rule
```

mantendo histórico e testes.

---

# SPEC-0061 — Federated Security Search

**Prioridade:** P1

### Objetivo

Consultar dados externos sem obrigatoriamente copiá-los para HRKL.

### Fontes

```text
S3
Iceberg
Delta
Parquet
PostgreSQL
Elastic
OpenSearch
other SQL engines
```

### Fluxo

```text
Heraclitus Query
       │
       ▼
Federated Planner
       │
       ├── Local HRKL
       ├── Iceberg
       ├── S3
       └── Remote SQL
```

### Pushdown

Enviar quando possível:

```text
projection
predicate
time range
limit
```

à fonte externa.

### Proveniência

Resultados externos recebem:

```text
source
query
timestamp
snapshot/version
hash
```

quando disponível.

---

# SPEC-0062 — Security Data Quality & Sensor Trust

**Prioridade:** P0

### Objetivo

O SIEM deve saber quando está cego.

Criar:

```text
TelemetryHealthGraph
```

### Detectar

```text
missing logs
parser errors
clock skew
duplicate storms
event gaps
collector outage
unexpected volume drop
schema drift
field disappearance
sensor tampering
```

### Score

Cada datasource recebe:

```text
Coverage
Freshness
Completeness
Integrity
Trust
```

### Exemplo

Não mostrar:

```text
"No attacks detected."
```

quando a realidade é:

```text
"Domain Controller stopped sending logs
43 minutes ago."
```

Uma distinção surpreendentemente importante.

---

# SPEC-0063 — ATT&CK Coverage & Continuous Detection Validation

**Prioridade:** P1

### Objetivo

Responder:

```text
Contra quais técnicas estamos realmente protegidos?
```

e não apenas:

```text
Quantas regras temos?
```

### Coverage Graph

```text
ATT&CK Technique
       │
       ├── required telemetry
       ├── detections
       ├── tests
       ├── historical hits
       ├── false positives
       └── validation status
```

### Estados

```text
COVERED
PARTIAL
BLIND
DEGRADED
UNTESTED
```

### Continuous Validation

Executar eventos sintéticos defensivos seguros para verificar que:

```text
sensor
→ ingestion
→ parser
→ rule
→ finding
→ incident
```

continua funcionando.

---

# SPEC-0064 — Temporal Security Replay & Counterfactual SOC

**Prioridade:** P1 — DIFERENCIAL ESTRATÉGICO

### Objetivo

Explorar uma propriedade que SIEMs tradicionais não possuem de forma tão natural:

```text
replay do estado histórico canônico
```

### Operações

```text
REPLAY INCIDENT <id>

REPLAY FROM LSN X TO Y

REPLAY WITH DETECTIONS VERSION 42
```

### Perguntas

```text
A regra atual teria detectado
o ataque de três meses atrás?

Quanto antes teria detectado?

Qual alerta faltava?

Este novo playbook teria funcionado?

A nova política teria bloqueado
uma ação legítima?
```

### Counterfactual

```text
Historical Events
      │
      ├── Detection Set A
      │
      └── Detection Set B
             │
             ▼
      compare outcomes
```

### Resultado

```text
Detection A:
time-to-detect = 47 min

Detection B:
time-to-detect = 3 min
```

Isso transforma todo histórico do SOC em laboratório de regressão.

---

# SPEC-0065 — Cryptographic Detection & Decision Provenance

**Prioridade:** P1 — MOAT

### Objetivo

Fazer cada finding, decisão de IA e resposta operacional ser verificável.

### FindingReceipt

```text
FindingReceipt {
    finding_id,

    source_lsns,

    detection_id,
    detection_version,
    detection_hash,

    data_snapshot_lsn,

    enrichment_versions,

    model_id?,
    model_hash?,

    policy_version,

    output_hash,

    created_lsn
}
```

### Pergunta

```text
Por que este alerta foi gerado?
```

Resposta:

```text
Events
  17771
  17779
  17784

Rule:
  credential_access_v17

Rule hash:
  ...

Risk model:
  v6

Snapshot:
  LSN 17790

Finding:
  F9281

Merkle proof:
  VERIFIED
```

### AI

Uma decisão do Sentinel AI deverá registrar:

```text
model
model version/hash
retrieved evidence
prompt template hash
tool calls
policy decision
output
```

sem necessariamente persistir segredos não autorizados.

### Diferencial

Não apenas:

```text
AI said X
```

mas:

```text
AI said X
because of A+B+C
under policy P
using model M
at LSN L
and this can be verified.
```

---

# SPEC-0066 — SOC Learning Loop

**Prioridade:** P1

### Objetivo

Fazer o SOC aprender continuamente com o trabalho dos analistas.

### Feedback

```text
True Positive
False Positive
Benign Positive
Expected Activity
Duplicate
Insufficient Evidence
Escalated
```

### Pipeline

```text
Analyst Verdict
      │
      ▼
Feedback Log
      │
      ▼
Evaluation Engine
      │
      ├── Risk tuning proposal
      ├── Rule tuning proposal
      ├── New feature proposal
      └── Suppression proposal
```

### Regra fundamental

O sistema pode:

```text
PROPOSE
SIMULATE
BENCHMARK
```

mas uma alteração de detecção relevante deve respeitar policy e aprovação configurada.

### Validação

Antes de sugerir promoção:

```text
new rule
   ↓
historical replay
   ↓
TP/FP comparison
   ↓
performance comparison
   ↓
coverage comparison
```

---

# SPEC-0067 — Multi-Tenant Sovereign SOC

**Prioridade:** P1 / Enterprise

### Objetivo

Permitir:

```text
órgão
agência
unidade
tenant
cliente MSSP
```

com isolamento forte.

### Isolamento

```text
storage namespace
encryption keys
RBAC/ABAC
quotas
retention
models
detections
playbooks
AI context
```

### Cross-Tenant

Proibido por default.

Permitido apenas por política explícita.

---

# SPEC-0068 — Security Exposure Fusion

**Prioridade:** P1

### Objetivo

Unificar:

```text
vulnerability
identity privilege
asset criticality
attack path
threat intelligence
active exploitation
behavior anomalies
```

em uma visão única de exposição.

### Exemplo

CVE isoladamente:

```text
CVSS = 9.8
```

não significa necessariamente risco máximo.

Heraclitus poderá calcular:

```text
Exploitability
×
Reachability
×
Asset Criticality
×
Threat Activity
×
Identity Exposure
```

### Resultado

Priorizar o que realmente cria um caminho para ativos críticos.

---

# SPEC-0069 — Autonomous Investigation Swarm

**Prioridade:** P2

### Objetivo

Evoluir o Sentinel L0-L4 para agentes especializados.

```text
Incident Supervisor
       │
 ┌─────┼──────────┬──────────┐
 ▼     ▼          ▼          ▼
Identity Network Endpoint ThreatIntel
Agent    Agent     Agent      Agent
 └─────┬──────────┴──────────┘
       ▼
Evidence Synthesizer
       ▼
Policy Engine
       ▼
Human / Approved Action
```

### Regra

Agentes não executam comandos arbitrários diretamente.

Produzem:

```text
typed findings
typed evidence
typed proposed actions
```

A PolicyEngine continua sendo a fronteira de segurança.

---

# SPEC-0070 — Adversarial SOC Digital Twin

**Prioridade:** P2 — DIFERENCIAL FUTURO

### Objetivo

Construir uma representação simulável da postura de defesa.

Usar:

```text
Security Graph
+
Attack Paths
+
Telemetry Coverage
+
Detection Coverage
+
Playbooks
+
Risk Model
```

para testar cenários defensivos.

### Digital Twin

```text
Actual Environment
       │
       ▼
Temporal Security Graph
       │
       ▼
Simulation Copy
       │
       ├── hypothetical compromise
       ├── credential loss
       ├── sensor failure
       ├── network change
       └── policy change
```

### Perguntas

```text
Se esta identidade for comprometida,
qual é o blast radius?

Se este EDR parar,
quais técnicas ficam invisíveis?

Se esta regra for desabilitada,
qual cobertura ATT&CK desaparece?

Se isolarmos este servidor,
quais serviços críticos quebram?
```

Nenhuma ação é executada no ambiente real.

---

# Arquitetura Final 0051–0070

```text
┌────────────────────────────────────────────────────────┐
│              AUTONOMOUS DEFENSE                        │
│                                                        │
│  Sentinel AI     Agent Swarm     Digital Twin          │
│  SPEC-0045       SPEC-0069       SPEC-0070             │
├────────────────────────────────────────────────────────┤
│              SOC OPERATIONS                            │
│                                                        │
│ Mission Control  Hunting   SOAR   Case Mgmt            │
│ SPEC-0059        0060      0048                        │
├────────────────────────────────────────────────────────┤
│              SECURITY SCIENCE                          │
│                                                        │
│ Detection-as-Code     UEBA      Risk      ATT&CK       │
│ SPEC-0054             0056      0055      0063         │
│                                                        │
│ Replay / Counterfactual          Learning Loop          │
│ SPEC-0064                       SPEC-0066               │
├────────────────────────────────────────────────────────┤
│              SECURITY KNOWLEDGE                        │
│                                                        │
│ Temporal Graph   Attack Paths   Exposure Fusion        │
│ SPEC-0057        SPEC-0058      SPEC-0068              │
├────────────────────────────────────────────────────────┤
│              SECURITY DATA FABRIC                      │
│                                                        │
│ Canonical Model Connectors Content Hub Data Quality    │
│ SPEC-0051       0052       0053        0062            │
│                                                        │
│ Federated Search       Multi-Tenant                    │
│ SPEC-0061              SPEC-0067                       │
├────────────────────────────────────────────────────────┤
│              TRUST / PROVENANCE                        │
│                                                        │
│ Decision Provenance   Forensics    Compliance          │
│ SPEC-0065             0048         0046                │
├────────────────────────────────────────────────────────┤
│                    HERACLITUSDB                        │
│                                                        │
│ HRKL │ HLC │ LSN │ Raft │ Graph │ HNSW │ BM25         │
│      │ DataFusion │ HUME │ HRKI │ Iceberg │ Delta     │
│                                                        │
│ SPEC-0001 ───────────────────────────────── SPEC-0050  │
└────────────────────────────────────────────────────────┘
```

# Priorização

## P0 — Para competir seriamente com Splunk/Sentinel

Implementar primeiro:

```text
0051 Security Canonical Model
0052 Connector Fabric
0053 Security Content Hub
0054 Detection Engineering
0055 Entity Risk Ledger
0056 UEBA
0057 Security Knowledge Graph
0059 Mission Control
0062 Data Quality
```

Sem isso, Heraclitus pode ter um storage tecnicamente melhor e ainda perder a compra porque o analista pergunta:

```text
"onde está meu conector para Palo Alto?"
```

e todos contemplam o Merkle tree em silêncio.

---

# P1 — Para começar a ultrapassar o modelo tradicional de SIEM

```text
0058 Attack Path & Blast Radius
0060 Hunting Workbench
0061 Federated Search
0063 Continuous Detection Validation
0064 Temporal Security Replay
0065 Cryptographic Decision Provenance
0066 SOC Learning Loop
0067 Multi-Tenant SOC
0068 Exposure Fusion
```

---

# P2 — Para criar uma categoria diferente

```text
0069 Autonomous Investigation Swarm

0070 Adversarial SOC Digital Twin
```

---

# As cinco SPECs com maior valor estratégico

Se for necessário reduzir tudo a cinco iniciativas, a ordem recomendada é:

```text
SPEC-0051
Security Canonical Model
        ↓
faz qualquer dado falar a mesma língua


SPEC-0052
Connector Fabric
        ↓
faz o mundo entrar no Heraclitus


SPEC-0055
Entity Risk Ledger
        ↓
transforma alertas em risco contextual


SPEC-0064
Temporal Security Replay
        ↓
transforma todo histórico em laboratório


SPEC-0065
Cryptographic Decision Provenance
        ↓
faz cada conclusão ser auditável e reproduzível
```

As duas últimas são particularmente importantes porque exploram propriedades que já pertencem ao DNA do Heraclitus:

```text
LSN
+
HLC
+
append-only history
+
Merkle
+
AS OF
+
replay
```

Em vez de simplesmente reproduzir Splunk dentro de outra interface.

# Tese de Produto Após SPEC-0070

O resultado não deve ser vendido como:

```text
SIEM melhor
```

mas como:

> **Heraclitus Sovereign Security Intelligence Platform**

Um sistema no qual:

```text
data
→ evidence
→ detection
→ risk
→ investigation
→ decision
→ action
→ forensic proof
```

faz parte de uma única história temporal verificável.

O salto estratégico está em deixar de perguntar apenas:

```text
"What happened?"
```

e conseguir responder também:

```text
What did we know at that time?

Why did we believe it?

Which evidence supported it?

What was the risk at that exact state?

Would today's detection have caught it?

What would have happened under another policy?

Which action was authorized?

Can the entire decision chain be reproduced?

Can it be cryptographically verified?
```

É aí que o Heraclitus deixa de tentar ser outro Splunk e passa a ocupar uma arquitetura própria.
