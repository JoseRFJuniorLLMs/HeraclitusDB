# SPEC-DASH-0001

# Heraclitus Temporal Reconstruction Workbench

**Status:** PROPOSTA DE IMPLEMENTAÇÃO
**Classe:** Produto / UI / API Temporal / Forense
**Repositórios-alvo:**

* `JoseRFJuniorLLMs/Heraclitus-Dashboard`
* `JoseRFJuniorLLMs/crates`, quando forem necessários novos contratos REST

**Objetivo:** substituir o atual dashboard fragmentado por uma interface operacional que represente corretamente a arquitetura do HeraclitusDB.

---

# 1. VISÃO DO PRODUTO

O Heraclitus Temporal Reconstruction Workbench não é um SOC tradicional, não é um dashboard de KPIs e não é uma coleção de telas administrativas.

É uma interface para navegar, reconstruir, comparar, explicar e provar a evolução temporal de uma base HeraclitusDB.

A pergunta fundamental da interface deve ser:

> **“Como o estado chegou até aqui?”**

A interface deve permitir responder, de forma verificável:

1. O que existia no LSN X?
2. O que existia em determinado instante?
3. O que mudou entre A e B?
4. Qual evento provocou essa mudança?
5. De onde esse evento veio?
6. Quais entidades e fatos dependem dele?
7. Qual era o estado considerado válido naquela data?
8. Qual era o estado conhecido pelo sistema naquela data?
9. O estado pode ser reconstruído determinísticamente?
10. A história utilizada nessa reconstrução continua criptograficamente íntegra?

O produto deve transformar a principal propriedade do HeraclitusDB em experiência visual:

```text
LOG CANÔNICO
    ↓
LSN
    ↓
HISTÓRIA
    ↓
REPLAY
    ↓
ESTADO
    ↓
DIFF
    ↓
CAUSALIDADE
    ↓
PROVENIÊNCIA
    ↓
PROVA
```

---

# 2. DECISÃO ARQUITETURAL FUNDAMENTAL

## 2.1 O tempo é a navegação principal

Toda a aplicação deve compartilhar um único estado temporal global.

Não deve existir uma Timeline independente de um Replay independente de um Grafo independente de um Diff.

Todas as telas devem observar o mesmo:

```typescript
TemporalContext
```

O contexto temporal controla:

```typescript
interface TemporalPoint {
    lsn?: bigint;
    hlc?: bigint;
    systemTimeMs?: number;
    validTime?: string;
}

interface TemporalRange {
    a: TemporalPoint;
    b: TemporalPoint;
}

interface TemporalContext {
    mode:
        | "HEAD"
        | "AS_OF_LSN"
        | "AS_OF_SYSTEM_TIME"
        | "VALID_TIME"
        | "COMPARE"
        | "REPLAY";

    cursor: TemporalPoint;
    range?: TemporalRange;

    axis:
        | "LSN"
        | "SYSTEM_TIME"
        | "VALID_TIME";

    filters: TemporalFilters;
}
```

Qualquer alteração do cursor temporal deve atualizar todas as áreas da aplicação.

---

# 3. NÃO OBJETIVOS

O agente NÃO deve reconstruir outro Splunk.

O agente NÃO deve criar:

* home dominada por alertas;
* gauges decorativos;
* mapa de rede fictício;
* números sintéticos quando a API falhar;
* percentual de integridade inventado;
* painel “SOC” como entrada padrão;
* widgets simplesmente porque “dashboard normalmente tem widgets”;
* gráficos sem capacidade de investigação;
* telas independentes que representem tempos diferentes sem indicar isso;
* dados de orçamento codificados no frontend;
* portarias, ministérios ou terminologia de uma demo específica;
* eventos falsos usados automaticamente quando a API estiver indisponível;
* causalidade inferida somente pela proximidade temporal;
* afirmações de integridade antes de uma verificação real;
* afirmações de determinismo antes de executar replay e comparar hashes.

---

# 4. IDENTIDADE DO PRODUTO

Nome recomendado:

**Heraclitus Temporal Reconstruction Workbench**

Nome curto:

**Heraclitus Workbench**

Subtítulo:

**Temporal reconstruction · Provenance · Deterministic replay · Verifiable history**

Alternativa em português institucional:

**Heraclitus — Reconstrução Temporal e Proveniência Verificável**

---

# 5. NOVA HIERARQUIA DE NAVEGAÇÃO

A navegação principal deverá ser:

```text
▣ Temporal Explorer
    Timeline
    State Explorer
    Compare A ↔ B

◎ Investigation
    Provenance
    Causality
    Entity History
    Query Lab

▶ Reconstruction
    Replay
    Determinism
    Checkpoints

◆ Evidence
    Integrity
    Merkle
    Timestamps
    Chain of Custody

◇ Data
    Sources
    Views
    Schema / Attributes
    Storage

⚡ Sentinel
    Incidents
    Detection
    Actions

⚙ System
    Health
    Replication
    Configuration
```

**Timeline deverá ser a home.**

Nunca `SOC`.

---

# 6. TEMPORAL SPINE

Criar uma barra temporal persistente.

Ela deverá permanecer visível em qualquer área da aplicação.

Layout conceitual:

```text
HEAD 18,492,102
────────────────────────────────────────────────────────────────

[ LSN ] [ System time ] [ Valid time ]

◀◀  ◀   ▶   ▶▶

A #18,200,000 ──────────────●──────────●──────── HEAD
                             B

2026-08-21 13:40:12.418

[ LIVE ] [ AS OF ] [ COMPARE ] [ REPLAY ]

Speed: 1x
```

Elementos obrigatórios:

* HEAD atual;
* cursor AS OF;
* LSN;
* HLC;
* timestamp físico;
* valid time, quando aplicável;
* ponto A;
* ponto B;
* voltar ao HEAD;
* step anterior;
* step seguinte;
* play;
* pause;
* velocidade;
* escolha de eixo temporal;
* zoom temporal;
* deep link.

O estado deverá ser serializável na URL.

Exemplo:

```text
/?view=timeline
&mode=compare
&a=18200000
&b=18492102
&axis=lsn
&source=forge
```

Recarregar a página deverá restaurar exatamente a investigação.

---

# 7. HOME — TEMPORAL EXPLORER

A primeira tela deverá responder visualmente:

> **“O que aconteceu nesta base e quando?”**

Ela possuirá quatro regiões principais.

---

# 8. CAMADA 1 — ACTIVITY CALENDAR

Restaurar e promover o calendário estilo GitHub.

Não deve ser apenas uma decoração.

Ele será chamado:

**Temporal Activity Map**

Exibir inicialmente 52 semanas.

Cada célula representa um bucket temporal.

### Métrica configurável

O operador poderá trocar:

```text
Events
Bytes
Entities changed
Facts changed
Incidents
Sources active
View lag
Anchors
Integrity failures
```

Default:

```text
Events
```

### Interação

* hover mostra valores;
* click seleciona o dia;
* shift+click cria intervalo;
* double click executa zoom;
* arrastar seleciona intervalo;
* scroll modifica zoom;
* seleção atual sincroniza Timeline, tabela, Diff e Grafo.

### Não usar cores de segurança para densidade

Uma célula intensa não significa “ruim”.

Portanto densidade deverá usar escala sequencial neutra.

Vermelho será reservado para estados que semanticamente significam falha.

---

# 9. CAMADA 2 — HISTORY RIVER

A visualização temporal principal deverá substituir o atual gráfico genérico.

Nome:

**History River**

Ela deverá apresentar lanes horizontais sincronizadas.

Exemplo:

```text
             12:00          13:00          14:00

Canonical   ━━━●━━━●━━━━●━━━━━━━━●━━━━━━━━━━━━━━
Log

Sources     API ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
            ERP ━━━━━━━   ━━━━━━━━━━━━━━━━━━━━━━━
            IAM ━━━━━━━━━━━━━━━━━━━  ━━━━━━━━━━━━

Entities    user:123 ━━━[ACTIVE]━━[CHANGED]━━━━━━
            doc:991  ━━━━━━━[CREATED]━━[VALID]━━━

Views       graph  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
            vector ━━━━━━ lag ━━━━━━━━━━━━━━━━━━━

Sentinel             ▲ INC-00014
                             └───────────────┐

Proofs       ◆ seal          ◆ timestamp     ◆ seal
```

---

# 10. LANES NATIVAS

Implementar inicialmente:

### Canonical Log

Mostra:

* eventos;
* checkpoints;
* mudanças de segmento;
* seals;
* gaps;
* saltos de SSE;
* HEAD.

### Sources

Uma lane por fonte.

Mostrar:

* atividade;
* silêncio;
* mudança de ritmo;
* reinício;
* primeiro evento;
* último evento.

### Event Kind

Agrupável por tipo de evento.

### Entities

Somente entidades filtradas ou relevantes à investigação.

### Derived Views

Mostrar:

* watermark;
* head;
* atraso;
* checkpoint;
* rebuild;
* disponibilidade.

### Sentinel

Mostrar incidentes como intervalos ou markers.

### Integrity

Mostrar:

* segment seal;
* Merkle verification;
* RFC3161;
* receipt;
* falha de verificação.

---

# 11. ESCALAS TEMPORAIS

A visualização deverá suportar zoom progressivo:

```text
anos
meses
semanas
dias
horas
minutos
segundos
LSNs
eventos individuais
```

O sistema não deverá tentar desenhar um milhão de elementos SVG.

Implementar level-of-detail.

Quando afastado:

```text
bucket aggregation
```

Quando aproximado:

```text
individual events
```

---

# 12. STATE EXPLORER

Criar uma tela especificamente dedicada à pergunta:

> **“Como era o banco neste momento?”**

Cabeçalho:

```text
STATE AS OF
LSN 18,234,991
2026-09-08 22:14:09.152
```

Mostrar:

* state hash;
* head conhecido naquele instante;
* número de entidades;
* número de relações;
* índices disponíveis;
* fontes existentes;
* watermarks;
* segmentos aplicáveis;
* views reconstruídas.

A tela deverá permitir consultas temporais.

Exemplo:

```text
MATCH (p:Person)-[r]->(x)
AS OF LSN 18234991
RETURN p, r, x
```

ou:

```text
AS OF SYSTEM TIME
```

---

# 13. SISTEMA TIME VS VALID TIME

O frontend deve expor visualmente a bitemporalidade.

Nunca reduzir tudo a “Data”.

Apresentar explicitamente:

```text
SYSTEM TIME
Quando o Heraclitus passou a conhecer o fato.

VALID TIME
Quando o fato era considerado verdadeiro no domínio.
```

Exemplo visual:

```text
              VALID TIME
          Jan     Feb     Mar     Apr

Fact A    ━━━━━━━━━━━━━━━━━
                     ↑
              System learned
                 15/Mar
```

O operador deverá conseguir perguntar:

```text
O que acreditávamos em março
sobre o que era válido em janeiro?
```

Essa é uma das interfaces que melhor diferenciará o Heraclitus de dashboards tradicionais.

---

# 14. COMPARE A ↔ B

Transformar `Diff` numa função central.

Layout:

```text
┌──────────────────────────┬──────────────────────────┐
│ STATE A                  │ STATE B                  │
│ LSN 18,200,000           │ LSN 18,492,102           │
│ hash abc...              │ hash def...              │
└──────────────────────────┴──────────────────────────┘

                     CHANGES

 + 184 created
 ~  91 changed
 -  12 semantically removed
 !   3 validity changes
 ↳  27 relationship changes
```

---

# 15. SEMÂNTICA DE REMOÇÃO

Não confundir:

```text
append-only log
```

com:

```text
state cannot remove things
```

O log físico nunca perde história.

Mas o estado derivado pode possuir:

* tombstone;
* validity expiration;
* revoked relation;
* superseded fact;
* crypto-shredded value;
* entity no longer active.

Portanto o Diff deve distinguir:

```text
PHYSICAL DELETE
impossível no log canônico

SEMANTIC REMOVAL
estado deixou de considerar algo ativo

VALIDITY END
fato deixou de ser válido

SUPERSEDED
fato substituído por fato posterior

CRYPTO-SHRED
registro permanece, conteúdo não está mais recuperável
```

---

# 16. WHY DID THIS CHANGE?

Toda diferença relevante deverá possuir:

```text
[ Why? ]
```

Ao clicar:

```text
Entity field changed

LSN 18,311,491
         ↓
Event EVT-...
         ↓
Fact ...
         ↓
Rule / relation
         ↓
Derived state
```

O resultado deverá apontar para eventos reais.

---

# 17. EVENT INSPECTOR

Selecionar qualquer ponto da Timeline abre um drawer lateral.

Exemplo:

```text
EVENT

LSN
18,441,029

EVENT ID
evt_...

HLC
117223814...

PHYSICAL TIME
2026-09-08 14:31:44.091

KIND
EntityResolved

SOURCE
forge

PARENTS
3

ATTRIBUTES
17

CONTENT
[ protected / available / shredded ]

PROVENANCE
7 ancestors

MERKLE
segment verified
```

Ações:

```text
Open history
Set AS OF here
Set A
Set B
Compare with previous
Show provenance
Show descendants
Show WHY
Show Merkle proof
Copy canonical reference
```

---

# 18. CANONICAL REFERENCE

Todo objeto investigável deve possuir endereço canônico copiável.

Exemplo:

```text
hera://database/namespace/event/evt_abc
?lsn=18441029
```

Também oferecer representação textual:

```text
HeraclitusDB
Event evt_abc
LSN 18,441,029
State hash ...
```

Isso facilita relatórios, perícias e auditorias.

---

# 19. ENTITY HISTORY

Criar uma tela:

**Entity History**

Ao selecionar uma entidade:

```text
CPF:...
process:...
document:...
server:...
account:...
```

mostrar toda a vida conhecida da entidade.

Exemplo:

```text
CREATE
  │
  ├─ attribute changed
  │
  ├─ relationship added
  │
  ├─ fact superseded
  │
  ├─ validity changed
  │
  └─ current state
```

Também exibir:

```text
System-time history
Valid-time history
```

separadamente.

---

# 20. PROVENANCE EXPLORER

O atual “Attack Graph” não deve ser o grafo principal.

Criar:

**Provenance Explorer**

Tipos de nós:

```text
Event
Fact
Entity
Source
View
Incident
Action
Checkpoint
Receipt
```

Tipos de aresta:

```text
PARENT
DERIVED_FROM
PRODUCED_BY
RESOLVED_TO
DEPENDS_ON
WHY
CAUSED_BY
SUPPORTED_BY
VALID_DURING
```

O grafo deve obedecer ao cursor temporal global.

Se:

```text
AS OF LSN 1000
```

nenhum elemento futuro deverá aparecer.

---

# 21. CAUSAL WATERFALL

Além do grafo, criar visualização linear para relações causais.

Inspirada em trace waterfalls, mas aplicada ao log.

Exemplo:

```text
Event 1120  █
              └ Event 1131 ███
                            └ Resolution █
                                         └ Fact █
                                                └ Incident ███
```

Objetivo:

tornar relações profundas compreensíveis sem precisar navegar num grafo de centenas de nós.

---

# 22. REPLAY LAB

Replay não será simplesmente um botão.

Criar:

**Replay Lab**

O operador define:

```text
FROM LSN
TO LSN

ou

FROM TIME
TO TIME
```

Controles:

```text
|<  <  PLAY  >  >|
0.25x
1x
10x
100x
MAX
```

Durante replay mostrar:

```text
Current LSN
Events replayed
Elapsed
View watermark
State hash
Expected hash
Memory
Rate
```

---

# 23. STEP REPLAY

Implementar:

```text
Step one event
Step one transaction
Step one checkpoint
Step one second
Step until condition
```

Exemplos de condição:

```text
pause when entity "x" changes
pause when incident begins
pause when event.kind == "Delete"
pause when graph edge appears
```

---

# 24. DETERMINISM VERIFICATION

Criar ação explícita:

```text
VERIFY DETERMINISTIC RECONSTRUCTION
```

Fluxo:

```text
state before
    ↓
hash A
    ↓
replay canonical log
    ↓
state after
    ↓
hash B
```

Somente se:

```text
A == B
```

mostrar:

```text
DETERMINISTIC
```

Caso contrário:

```text
RECONSTRUCTION DIVERGENCE
```

com diferença exibida.

Nunca deixar um badge verde permanente sem execução real.

---

# 25. CHECKPOINTS

Adicionar checkpoints na Timeline.

Visual:

```text
────────◆────────────◆──────────◆────────
       CP-01         CP-02      CP-03
```

Hover:

```text
LSN
state hash
timestamp
view watermarks
version
```

Replay poderá iniciar a partir do checkpoint válido mais próximo, mantendo a possibilidade de validação desde LSN 0.

---

# 26. INTEGRITY EXPLORER

Substituir pequenos cards Merkle por uma interface temporal de integridade.

Exemplo:

```text
SEGMENTS

000001 █████████ VERIFIED
000002 █████████ VERIFIED
000003 █████████ VERIFIED + RFC3161
000004 █████████ NOT CHECKED
000005 ▒▒▒▒▒▒▒▒▒ ACTIVE
```

Selecionar segmento mostra:

```text
base LSN
last LSN
records
bytes
format
compression
Merkle root
manifest hash
timestamp receipt
verification state
last verification time
```

---

# 27. VERIFY É UMA OPERAÇÃO, NÃO UM KPI

`/verify` completo não deverá rodar automaticamente.

Exibir:

```text
Last verified:
2026-09-08 17:41

Coverage:
segments 1..124

Current active segment:
not sealable / not included
```

A distinção entre:

```text
verified
not verified
nothing to verify
verification failed
```

é obrigatória.

---

# 28. PROVA POR EVENTO

Adicionar suporte backend, se ainda inexistente, para:

```text
GET /temporal/proof/:lsn
```

Resposta deverá permitir construir ou apresentar prova de inclusão do evento no segmento.

Contrato sugerido:

```json
{
  "lsn": "18441029",
  "segment": 124,
  "record_hash": "...",
  "merkle_root": "...",
  "path": [
    {"side":"left","hash":"..."},
    {"side":"right","hash":"..."}
  ],
  "verified": true
}
```

O frontend deverá disponibilizar:

```text
Verify locally
Copy proof
Download proof
```

---

# 29. RFC 3161 / ICP-BRASIL

Quando existir receipt:

mostrar visualmente:

```text
EVENT
 ↓
MERKLE ROOT
 ↓
RFC3161 IMPRINT
 ↓
TSA RESPONSE
 ↓
CERTIFICATE CHAIN
 ↓
ICP-BRASIL
```

Separar claramente:

```text
Integrity
```

de:

```text
External timestamp evidence
```

São propriedades diferentes.

---

# 30. SENTINEL DEIXA DE SER O PRODUTO

Sentinel continua importante.

Porém será uma **lens temporal**.

Adicionar botão:

```text
[ Overlay Sentinel ]
```

Ativado, incidentes aparecem na History River.

Exemplo:

```text
Log       ━━━━━━━━━━━━━━━━━━━━━━━━━━━

Sentinel          ▲─────────────▲
                INC-19        action
```

Selecionar incidente deverá abrir:

```text
incident details
evidence
WHY
related entities
action history
approval history
```

Os endpoints Sentinel já existentes deverão ser utilizados.

---

# 31. LIVE MODE

O equivalente ao atual SOC deverá existir como:

**LIVE**

e não como home.

Ao clicar:

```text
LIVE
```

o cursor acompanha HEAD.

Mostrar:

```text
events/s
head
lag
sources
active incidents
view watermarks
```

A Timeline continua sendo a interface.

A diferença é que o cursor segue o presente.

---

# 32. VOLTANDO AO PASSADO

Quando o usuário mover o cursor para trás, mostrar claramente:

```text
YOU ARE VIEWING HISTORY
LSN 18,200,000

HEAD IS 18,492,102
+292,102 events ahead
```

O presente pode aparecer como ghost marker à direita.

A interface não deve confundir estado histórico com estado atual.

---

# 33. QUERY WORKBENCH

Adicionar query bar global.

Aceitar inicialmente:

```text
LSN
event id
entity id
kind
source
attribute
text
```

e consultas Heraclitus.

Exemplo:

```text
MATCH (p)-[:TRANSFER]->(x)
AS OF LSN 18200000
```

Resultado deve poder ser:

```text
Table
Timeline
Graph
JSON
```

---

# 34. COMMAND PALETTE

Adicionar `Ctrl+K`.

Comandos:

```text
Go to LSN 18441029
AS OF 18441029
Compare 18000000..18441029
Open event evt_...
Open entity ...
Replay 1000..5000
Verify segment 124
Return to HEAD
```

---

# 35. INVESTIGATION WORKSPACES

Permitir salvar uma investigação.

Estrutura:

```typescript
interface Investigation {
    id: string;
    title: string;
    createdAt: string;

    temporalContext: TemporalContext;

    query?: string;

    selectedEntities: string[];
    selectedEvents: string[];

    bookmarks: InvestigationBookmark[];

    notes: InvestigationNote[];
}
```

Salvar:

* range temporal;
* filtros;
* queries;
* eventos;
* entidades;
* bookmarks;
* notas.

---

# 36. BOOKMARKS TEMPORAIS

O usuário poderá marcar:

```text
★ Before anomaly
★ First suspicious event
★ Incident begins
★ State after correction
```

Bookmarks aparecem na Timeline.

---

# 37. EXPORTAÇÃO DA INVESTIGAÇÃO

Suportar inicialmente JSON.

```json
{
  "database": "...",
  "head_at_export": "...",
  "range": {},
  "events": [],
  "entities": [],
  "queries": [],
  "state_hashes": {},
  "proofs": []
}
```

Depois poderá existir pacote de evidência assinado.

---

# 38. IA FORENSE

Remover o conceito de chatbot genérico.

Criar:

**Forensic Copilot**

Ações contextuais:

```text
Explain this event
Why did this state exist?
What changed A → B?
Find earliest causal ancestor
Summarize this provenance chain
Explain this Merkle proof
Find events supporting this conclusion
```

---

# 39. REGRA DE OURO DA IA

Toda conclusão factual da IA deverá apontar para evidências.

Formato:

```text
A relação passou a existir em LSN 18,231,199
após o evento evt_abc.

Evidence:
• LSN 18,231,199
• evt_abc
• relation ...
```

Nunca:

```text
"provavelmente aconteceu..."
```

sem marca explícita de inferência.

---

# 40. CANONICAL VS INFERRED

A interface deve usar terminologia consistente.

```text
CANONICAL
veio diretamente do log

DERIVED
reconstruído deterministicamente

INFERRED
resultado de modelo/regra/heurística

SIMULATED
contrafactual não pertencente à história real
```

Usar badges diferentes.

Nunca misturar.

---

# 41. CONTRAFACTUAL

Se `SIMULATE` estiver disponível, criar:

**Counterfactual Lab**

Exemplo:

```text
SIMULATE REMOVE EDGE E17
THEN ...
```

A UI deve mudar de contexto para:

```text
SIMULATION
```

com moldura clara.

Nada produzido pela simulação poderá parecer parte do histórico canônico.

---

# 42. VIEW WATERMARKS

Watermarks são fundamentais no Heraclitus.

Criar painel sincronizado:

```text
HEAD             18,492,102

Graph            18,492,102 ✓
Text             18,492,102 ✓
Vector           18,491,884 -218
Activation       18,492,102 ✓
Attributes       18,492,101 -1
```

Visualmente:

```text
HEAD      │
graph     │
text      │
vector  │
attr      │
```

Assim o operador enxerga se uma consulta histórica ou atual utiliza view atrasada.

---

# 43. VIEW REBUILD

Quando houver rebuild:

mostrar como evento temporal.

```text
VECTOR VIEW

───────╳ rebuilding ╳────────
```

Não mostrar resultado velho como se fosse current silenciosamente.

---

# 44. SOURCE HEALTH

Fontes não devem ficar isoladas num simples painel.

Adicionar à Timeline.

Uma fonte silenciosa aparece como gap.

Exemplo:

```text
source A █████████████████████
source B ████████        █████
                    ↑
                  gap
```

Selecionar gap:

```text
Last event
Expected cadence
Observed silence
Affected range
```

---

# 45. STORAGE HISTORY

Adicionar visão opcional:

```text
Active
Sealed
Packed
Cold tier
Restored
```

Segmentos poderão aparecer na própria linha do tempo.

Isso torna o lifecycle físico dos dados auditável.

---

# 46. EVENT TABLE

A tabela inferior deverá ser completamente genérica.

Colunas default:

```text
LSN
System time
Valid time
Kind
Source
Entity
Event ID
Parents
Bytes
Integrity
```

Remover definitivamente:

```text
Portaria
Órgão Beneficiário
Tipo Legal
Valor R$
```

---

# 47. COLUNAS DINÂMICAS

Permitir adicionar attributes como colunas.

Exemplo:

```text
+ Add column
```

buscar:

```text
actor
cpf
process_id
source_ip
...
```

---

# 48. EVENT TABLE VIRTUALIZADA

Nunca desenhar milhares de `<tr>`.

Usar virtualização.

Objetivo:

```text
1,000,000 resultados
```

sem 1,000,000 nós DOM.

---

# 49. TECNOLOGIA FRONTEND

Migrar o projeto atual de HTML/JS modular manual para:

```text
TypeScript
React
Vite
```

Arquitetura recomendada:

```text
src/
  app/
  api/
  auth/
  components/
  temporal/
  timeline/
  investigation/
  provenance/
  replay/
  integrity/
  sentinel/
  data/
  workers/
  state/
  types/
  utils/
  tests/
```

Não portar o código atual linha por linha.

Reescrever em torno do modelo temporal.

---

# 50. ESTADO GLOBAL

Usar store pequena e explícita.

Exemplo:

```text
TemporalStore
ConnectionStore
InvestigationStore
PreferencesStore
```

Não colocar toda a aplicação numa store monolítica.

---

# 51. DATA FETCHING

Implementar:

* request cancellation;
* stale request protection;
* cache por LSN/range;
* retry somente quando apropriado;
* timeouts;
* runtime schema validation;
* loading state;
* empty state;
* error state.

Nunca transformar erro em zero.

---

# 52. VALIDAÇÃO DE CONTRATOS

Toda resposta REST deve ser validada.

Não confiar que o JSON possui a estrutura esperada.

Usar schemas TypeScript/runtime.

Exemplo:

```typescript
const StatsSchema = z.object({
    head: LsnSchema,
    ...
});
```

---

# 53. LSN E HLC

Nunca tratar LSN/HLC arbitrariamente grandes como JavaScript `Number`.

Representação de transporte:

```text
string
```

Representação interna:

```text
BigInt
```

Nunca:

```javascript
Number(hlc)
```

quando puder perder precisão.

---

# 54. RENDERIZAÇÃO DA TIMELINE

Não utilizar milhares de elementos SVG para eventos.

Arquitetura recomendada:

```text
D3
apenas para scales/brush/axes

Canvas
para rendering massivo da timeline
```

Opcionalmente WebGL em datasets extremos.

SVG poderá ser usado para:

* eixos;
* labels;
* cursores;
* elementos acessíveis em pequena quantidade.

---

# 55. GRAFO

Para grafos grandes utilizar renderização WebGL.

Não tentar renderizar dezenas de milhares de nós como elementos SVG.

Implementar progressive disclosure:

```text
selected node
parents
children
neighborhood depth 1
expand
```

---

# 56. AGREGAÇÃO TEMPORAL

O navegador não deverá receber dezenas de milhões de eventos para desenhar um ano.

Criar API agregada.

Novo endpoint recomendado:

```text
GET /temporal/buckets
```

Parâmetros:

```text
axis
from
to
bucket
group_by
filters
```

Exemplo:

```text
GET /temporal/buckets
?axis=system_time
&from=...
&to=...
&bucket=1h
&group_by=kind
```

Resposta:

```json
{
  "axis": "system_time",
  "bucket": "1h",
  "from_lsn": "1000",
  "to_lsn": "2000",
  "series": [
    {
      "key": "EntityResolved",
      "buckets": [
        {
          "start": "...",
          "end": "...",
          "count": 91,
          "bytes": 18302
        }
      ]
    }
  ]
}
```

---

# 57. EVENT PAGINATION API

Adicionar ou padronizar:

```text
GET /temporal/events
```

Parâmetros:

```text
from_lsn
to_lsn
cursor
limit
kind
source
entity
```

Usar cursor pagination.

Nunca offset sobre milhões de eventos.

---

# 58. SNAPSHOT API

Criar contrato para estado histórico.

```text
GET /temporal/snapshot?as_of_lsn=...
```

Resposta de metadata:

```json
{
  "as_of_lsn": "18441029",
  "state_hash": "...",
  "watermarks": {},
  "entities": 0,
  "graph_nodes": 0,
  "graph_edges": 0,
  "views": []
}
```

Consultas detalhadas podem continuar no mecanismo GQL/SQL apropriado.

---

# 59. ENTITY HISTORY API

Adicionar:

```text
GET /temporal/entity/:id/history
```

Parâmetros:

```text
from_lsn
to_lsn
include_relations
```

Resposta ordenada por LSN.

---

# 60. PROVENANCE API

Criar superfície read-only:

```text
GET /temporal/event/:id/provenance
```

Parâmetros:

```text
direction=ancestors|descendants|both
depth=3
as_of_lsn=...
```

---

# 61. BACKEND EXISTENTE A REUTILIZAR

Não duplicar contratos já implementados.

Reutilizar:

```text
GET /healthz
GET /stats
GET /metrics
GET /state

GET /verify
GET /verify/:segment

GET /live/events

GET /replay
GET /fontes
GET /fontes/:id
GET /atributos
GET /diff

GET /telemetry/health

GET /sentinel/status
GET /sentinel/incidents
GET /sentinel/incidents/:id
GET /sentinel/incidents/:id/evidence
GET /sentinel/incidents/:id/why
GET /sentinel/actions
```

A API nova deve complementar a atual, não criar uma segunda implementação da mesma lógica.

---

# 62. SSE

`/live/events` deverá alimentar LIVE mode.

Eventos devem entrar numa fila client-side.

Nunca redesenhar toda a interface para cada evento.

Fluxo:

```text
SSE
 ↓
buffer
 ↓
coalesce
 ↓
temporal store
 ↓
render frame
```

---

# 63. LAG DO SSE

Se o servidor informar:

```json
{"saltados": 200000}
```

mostrar um gap real:

```text
LIVE STREAM GAP
200,000 metadata events were skipped.
```

Não desenhar continuidade falsa.

A Timeline histórica poderá posteriormente carregar o intervalo perdido pela API paginada.

---

# 64. NÃO TER FALLBACK SILENCIOSO

Remover:

```text
window.EVENTOS_FALLBACK
```

do caminho normal.

Demo somente deve existir quando explicitamente ativada:

```text
?demo=1
```

e a interface inteira deve apresentar:

```text
DEMONSTRATION DATA
```

de maneira impossível de confundir.

---

# 65. GOLDEN DEMO DATASET

Criar dataset de demonstração determinístico.

Não utilizar números aleatórios.

O dataset deve demonstrar:

1. evento inicial;
2. alteração de entidade;
3. relação causal;
4. correção posterior;
5. evento com valid time retroativo;
6. source gap;
7. incidente Sentinel;
8. checkpoint;
9. segmento selado;
10. proof;
11. estado A;
12. estado B;
13. replay determinístico.

Esse dataset passa a ser utilizado também em testes E2E.

---

# 66. SEGURANÇA DA INTERFACE

Preferir produção same-origin:

```text
browser
   ↓ HTTPS
Heraclitus Gateway
   ├─ UI
   └─ API
```

Evitar expor credenciais administrativas a JavaScript quando não necessário.

Para produção:

* HTTPS;
* CSP;
* same-origin;
* cookie HttpOnly quando disponível;
* autenticação forte;
* read-only por padrão;
* operações mutáveis separadas.

---

# 67. READ-ONLY DEFAULT

O Workbench deverá iniciar como ferramenta read-only.

Operações que alterem estado:

```text
Sentinel approve
Sentinel deny
erasure
HVM write
```

não pertencem ao fluxo normal da investigação.

Quando expostas:

* exigir autorização específica;
* confirmação;
* identidade autenticada;
* auditoria;
* feedback inequívoco.

---

# 68. AIR-GAPPED

A interface não poderá depender de:

* Google Fonts;
* CDN;
* scripts externos;
* analytics externo;
* ícones carregados da internet.

Todos os assets necessários devem ser empacotados localmente.

---

# 69. DESIGN VISUAL

Não copiar aparência de SOC genérico.

Direção:

**temporal / forensic / evidence-oriented**

Elementos principais:

* timeline ocupando largura;
* tipografia numérica forte para LSN;
* evidência criptográfica em mono;
* poucos KPIs;
* alta densidade informacional;
* drawers contextuais;
* breadcrumbs temporais;
* estado temporal sempre visível.

---

# 70. DARK / LIGHT

Implementar ambos.

Dark deve funcionar bem para investigação prolongada.

Light deve continuar apropriado para:

* governo;
* relatórios;
* projeção;
* acessibilidade.

Persistir preferência.

---

# 71. CORES SEMÂNTICAS

Cores devem ter significado estável.

Exemplo:

```text
azul     seleção / canonical
violeta  derived
verde    verified
vermelho verification failure
laranja  warning / lag
cinza    unknown / unchecked
ciano    simulation
```

Não usar verde como decoração.

---

# 72. ACCESSIBILITY

Meta mínima:

```text
WCAG 2.2 AA
```

Implementar:

* keyboard navigation;
* focus visible;
* ARIA apropriado;
* contraste;
* labels;
* não depender exclusivamente de cor;
* textual fallback para visualizações;
* reduced motion;
* zoom 200%.

---

# 73. KEYBOARD FIRST

Atalhos recomendados:

```text
← / →      step event
Shift ←/→  step checkpoint
Space      play/pause
H          HEAD
A          set point A
B          set point B
D          compare
P          provenance
R          replay
V          verify
Ctrl+K     command palette
```

---

# 74. PERFORMANCE TARGETS

Metas de frontend:

```text
Timeline pan/zoom:
60 FPS em carga normal

Initial shell:
< 2 s em hardware moderno

Interactions locais:
< 100 ms

Cursor temporal:
feedback visual imediato

Table:
virtualizada

Memory:
sem crescimento ilimitado durante LIVE
```

---

# 75. TEMPORAL LOD

Para intervalos grandes:

```text
10M eventos
```

nunca baixar 10M eventos.

Servidor retorna buckets.

Ao aproximar:

```text
10k eventos
```

baixar eventos detalhados.

Ao aproximar novamente:

```text
event-level
```

mostrar individualmente.

---

# 76. CACHE POR RANGE

Cache recomendado:

```text
bucket:<axis>:<from>:<to>:<resolution>:<filters>
```

Movimentar a Timeline ligeiramente não deve refazer toda a consulta.

---

# 77. WEB WORKERS

Mover cálculos pesados para worker:

* bucket client-side pequeno;
* layouts;
* parsing grande;
* diff visual;
* graph preprocessing.

Não bloquear main thread.

---

# 78. OBSERVABILIDADE DO PRÓPRIO WORKBENCH

Em desenvolvimento permitir painel técnico com:

```text
requests
latency
cache hit
render FPS
event buffer
SSE lag
memory estimate
```

Nunca ativado por padrão em produção.

---

# 79. ERROR STATES

Cada erro deverá dizer:

```text
what failed
which endpoint
which temporal range
whether displayed data remains valid
```

Exemplo:

```text
Could not load provenance for LSN 18,441,029.

The currently displayed snapshot remains valid.
Only the provenance panel is unavailable.
```

---

# 80. DATA FRESHNESS

Todo painel que representa dados atuais deve indicar:

```text
observed at
```

ou:

```text
as of
```

Exemplo:

```text
AS OF LSN 18,441,029
```

não apenas:

```text
18,441,029 events
```

---

# 81. SEARCH HISTORY

Queries executadas devem aparecer no workspace.

```text
13:41 query...
13:44 AS OF...
13:47 WHY...
```

Isso ajuda na reprodutibilidade da investigação.

---

# 82. REPRODUCIBLE INVESTIGATION

Uma investigação exportada deve permitir reproduzir:

```text
database version
head
LSNs
queries
filters
state hashes
proofs
```

O produto deverá favorecer:

```text
"reexecute"
```

em vez de:

```text
"trust screenshot"
```

---

# 83. NO SCREENSHOT AS PROOF

A UI não deve apresentar screenshot como evidência forte.

O elemento primário é:

```text
event id
LSN
state hash
Merkle proof
timestamp receipt
query
```

Screenshot é apenas apresentação.

---

# 84. TESTES UNITÁRIOS

Cobrir no mínimo:

* parsing LSN;
* parsing HLC;
* BigInt serialization;
* cursor temporal;
* A <= B;
* zoom;
* buckets;
* filters;
* URL serialization;
* replay controls;
* proof validation state;
* gap handling.

---

# 85. TESTES PROPERTY-BASED

Invariantes importantes:

```text
A <= B

HEAD nunca pertence ao futuro da própria sessão

LSN cursor não perde precisão

zoom não muda seleção temporal

alterar visualização não altera AS OF

canonical events futuros não aparecem em snapshot passado
```

---

# 86. TESTES E2E

Usar Playwright.

Cenários obrigatórios:

### E2E-01

Abrir → Timeline é home.

### E2E-02

Selecionar célula no Activity Map → Timeline ajusta range.

### E2E-03

Selecionar evento → Inspector abre.

### E2E-04

“Set A” + “Set B” → Compare.

### E2E-05

AS OF LSN → elementos futuros desaparecem.

### E2E-06

Replay → cursor progride.

### E2E-07

Replay determinístico → hashes iguais.

### E2E-08

Merkle inválido → UI vermelha.

### E2E-09

Endpoint indisponível → nenhum número inventado.

### E2E-10

SSE Lagged → gap mostrado.

### E2E-11

Demo → banner DEMONSTRATION sempre visível.

### E2E-12

Dark/light.

### E2E-13

Deep link restaura investigação.

---

# 87. VISUAL REGRESSION

Criar screenshots de referência para:

```text
Timeline
Compare
Provenance
Replay
Integrity
Sentinel overlay
Dark
Light
```

---

# 88. BACKEND TESTS

Novos endpoints temporais deverão possuir:

* unit tests;
* pagination tests;
* range boundaries;
* empty log;
* sparse LSN;
* cold tier;
* active segment;
* corrupted segment;
* very large LSN;
* concurrent append while querying.

---

# 89. FASE 0 — AUDITORIA E LIMPEZA

Antes de implementar UI nova:

1. mapear componentes existentes;
2. mapear endpoints consumidos;
3. mapear endpoints existentes em `heraclitus-server`;
4. identificar código real reaproveitável;
5. identificar demo;
6. remover conceitos específicos de orçamento;
7. documentar o contrato temporal.

Não deletar o TimeMachine antes de extrair:

* heatmap;
* dual slider;
* playback;
* escalas;
* interação existente.

---

# 90. FASE 1 — FUNDAÇÃO

Implementar:

```text
React + TypeScript + Vite
routing
theme
TemporalStore
ConnectionStore
API schemas
error boundary
global temporal spine
```

Critério:

mudar LSN global atualiza URL e todos os consumidores.

---

# 91. FASE 2 — TEMPORAL EXPLORER

Implementar:

```text
Activity Map
History River
dual cursor
zoom
pan
event inspector
virtual event table
LIVE
```

Esta fase deve substituir a home atual.

---

# 92. FASE 3 — AS OF + DIFF

Implementar:

```text
State Explorer
A ↔ B
system time
valid time
entity changes
relationship changes
WHY change
```

---

# 93. FASE 4 — PROVENANCE

Implementar:

```text
Provenance Explorer
causal waterfall
ancestor traversal
descendant traversal
entity history
```

---

# 94. FASE 5 — REPLAY

Implementar:

```text
Replay Lab
step
speed
pause condition
checkpoint visualization
determinism verification
```

---

# 95. FASE 6 — PROVAS

Implementar:

```text
segment timeline
Merkle
per-event proof
RFC3161
receipts
chain of custody
```

---

# 96. FASE 7 — SENTINEL

Integrar Sentinel como overlay.

Implementar:

```text
incident markers
severity
WHY
evidence
actions
approval chain
```

SOC poderá existir como preset:

```text
Preset: Live Security Operations
```

mas não como identidade da aplicação.

---

# 97. FASE 8 — INVESTIGATIONS + IA

Implementar:

```text
saved investigations
bookmarks
notes
export
Forensic Copilot
evidence references
```

---

# 98. DEFINITION OF DONE — PRODUTO

A SPEC somente estará concluída quando uma pessoa puder executar esta sequência:

```text
1. abrir Heraclitus Workbench

2. ver imediatamente a história da base

3. selecionar uma região do calendário

4. aproximar a Timeline

5. clicar num evento

6. viajar para aquele LSN

7. visualizar o estado naquele instante

8. selecionar ponto A

9. selecionar ponto B

10. ver exatamente o que mudou

11. clicar "Why?"

12. seguir a cadeia de proveniência

13. reproduzir os eventos A → B

14. comparar state hash reconstruído

15. verificar o segmento Merkle

16. exportar referência/prova da investigação
```

Se essa sequência exigir alternar entre cinco produtos mentalmente independentes, a arquitetura ainda está errada.

---

# 99. CRITÉRIO DE IDENTIDADE

Ao observar uma screenshot da tela principal, uma pessoa técnica deve conseguir concluir:

```text
"isso é uma ferramenta para navegar e reconstruir a história de um banco"
```

e não:

```text
"isso é outro SIEM"
```

---

# 100. PRINCÍPIO FINAL

A experiência inteira deverá materializar quatro operações:

```text
WHEN
Quando isso existiu?

WHAT CHANGED
O que mudou?

WHY
Por que mudou?

PROVE IT
Como provar?
```

Essas quatro perguntas são a navegação conceitual do produto.

O HeraclitusDB não precisa competir com Splunk tentando possuir mais dashboards que Splunk.

Seu diferencial visual deverá ser algo que Splunk, Grafana ou um banco tradicional não conseguem simplesmente imitar acrescentando mais um gráfico:

```text
PAST STATE
     ↓
AS OF
     ↓
DIFF
     ↓
PROVENANCE
     ↓
DETERMINISTIC REPLAY
     ↓
CRYPTOGRAPHIC PROOF
```

Essa cadeia deverá ser o produto.
