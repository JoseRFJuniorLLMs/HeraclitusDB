# SPEC-0051 — Heraclitus Security Normalization Contract

**Status:** Proposed / Implementation Contract
**Prioridade:** P0 — mas ver §14, *Quando implementar*
**Classe:** Security Schema / Normalization / Provenance / External Interop
**Autor:** Heraclitus Core & Security Team
**Data:** Agosto de 2026
**Alvo primário:** `heraclitus-security-schema` (crate novo)
**Baseline externo:** OCSF **1.9.0** (03-08-2026, Linux Foundation)
**Toolchain:** Rust Stable

**Depende de:**

* SPEC-0045 §9–§11 (define o `SecurityEvent`; esta SPEC **não o redefine**)
* SPEC-0050 (identidade canónica `CanonicalRecordV1`, `prove_lsn`)

**Princípio:**
*A normalização é uma derivação auditável, não uma conversão. Quem não consegue
dizer que código produziu um campo, e reproduzi-lo, não normalizou — reescreveu.*

---

# 0. Decisão Arquitetural

## 0.1 Esta SPEC não define um modelo de evento de segurança

O roadmap `SPECs 0051.md` pedia um "Heraclitus Security Canonical Model" com 18
entidades canónicas. **Esse pedido é retirado**, por uma razão verificável: a
SPEC-0045 §9.3 já define o `SecurityEvent` canónico, com `category`, `activity`,
`outcome`, `severity`, `observed_at`, `raw_event_id` e `attributes`; a §9.4 já
decide persistí-lo como `EventKind::Custom("SecurityEvent")`; e a §10 já fixa a
preservação do evento bruto via `parents` e `attrs["sentinel.source_lsn"]`.

Dois documentos normativos a definir o mesmo `struct` de formas diferentes são
piores que um só. Quando divergirem — e divergem sempre — o código fica sem
árbitro.

Esta SPEC ocupa a lacuna real: **o contrato de normalização**. Isto é, tudo o que
está entre o byte que chega do coletor e o `SecurityEvent` que a SPEC-0045
consome:

```text
   evidência bruta                     SPEC-0050 (HRKL v6)
        │                              o registo canónico e a sua prova
        ▼
   ┌─────────────────────────────────────────────┐
   │  SPEC-0051 — contrato de normalização       │   ← esta SPEC
   │  · identidade e versão do parser            │
   │  · reprodutibilidade da derivação           │
   │  · classificação indexável/evidência        │
   │  · emissão e ingestão de padrões externos   │
   └─────────────────────────────────────────────┘
        │
        ▼
   SecurityEvent                       SPEC-0045 §9.3
        │
        ▼
   detecção, risco, resposta           SPEC-0045 §12+
```

## 0.2 Emendas normativas à SPEC-0045

Esta SPEC **emenda** a SPEC-0045 em três pontos, com justificação verificável:

| SPEC-0045 diz | Emenda | Porquê |
|---|---|---|
| "Baseline OCSF: 1.8.x" | Baseline OCSF **1.9.0** | 1.8.0 é de 18-03-2026; 1.9.0 saiu a 03-08-2026. A cadência é de ~2 minors/ano e há depreciações *dentro* de minors. |
| `SecurityEvent.category: SecurityCategory` + `activity: String` | Acrescentar `type_uid: u64` (§4) | A identidade de um evento em OCSF é **aritmética**, não textual. Sem o inteiro, o emissor OCSF inventa UIDs em runtime. |
| `schema_version: u16` | Manter, e acrescentar `parser_id` + `parser_version` (§5) | `schema_version` diz qual era o contrato; não diz que código o aplicou. |

Onde esta SPEC e a SPEC-0045 colidirem noutro ponto, **prevalece a SPEC-0045** —
ela é a dona do tipo. Esta é dona do processo que o produz.

---

# 1. Objetivo

Especificar como uma evidência bruta se torna um `SecurityEvent`, de forma que
três perguntas tenham resposta mecânica:

1. **Que código produziu este campo?** (`parser_id`, `parser_version`)
2. **De que evidência bruta veio, e prove-o.** (`parents`, `source_lsn`, `prove_lsn`)
3. **Se eu voltar a correr o mesmo parser sobre o mesmo bruto, dá o mesmo?**
   (§6, determinismo)

E especificar a interoperabilidade com os modelos externos **sem mentir sobre
ela** (§10).

# 2. Não objetivos

* Redefinir `SecurityEvent` — é da SPEC-0045.
* Definir detectores, risco, UEBA ou resposta — SPEC-0045, 0055, 0056.
* Definir coletores e transportes — SPEC-0052.
* Definir o formato de armazenamento — SPEC-0050.
* Escrever um validador OCSF de raiz. Já existem `ocsf-validator`,
  `ocsf-schema-compiler` e `ocsf-lib-py`, todos Apache-2.0, e o schema é JSON
  compilável. Reimplementá-lo em Rust é assumir a manutenção de uma taxonomia
  de terceiros que muda duas vezes por ano.

---

# 3. O que já existe e NÃO se reinventa

Auditado no código a 2026-08-21. Uma SPEC que ignore isto produz duplicação.

| Necessidade da normalização | Já existe | Onde |
|---|---|---|
| Ligar o evento derivado ao bruto | `Episode.parents: Vec<EventId>` | `heraclitus-core/src/event.rs:87` |
| Precedente vivo desse padrão | `ev.parents = provenance` no distill | `heraclitus-distill/src/lib.rs:143` |
| Arestas de grafo a partir da proveniência | `GraphIndex::apply` cria `out`/`inn` por parent | `heraclitus-index-graph/src/lib.rs:215` |
| Tempo do mundo vs tempo de gravação | `valid_from`/`valid_to` nativos | `heraclitus-core/src/event.rs:92` |
| Identidade criptográfica do registo | `canonical_record_hash` | `heraclitus-log/src/v6/canonical.rs:318` |
| Prova de inclusão por LSN | `prove_lsn` / `LsnProof` | `heraclitus-log/src/v6/verify.rs:250` |
| Kind novo sem mexer no enum | `EventKind::Custom(String)` + `label()` | `heraclitus-core/src/event.rs:33` |
| Busca por tipo de evento | pseudo-atributo `_kind` indexado | `heraclitus-index-attr/src/lib.rs:600` |

**Consequência gratuita e importante:** `canonical_record_hash` inclui `parents`
**e** `attrs` na região autenticada (`canonical.rs:235-282`). Portanto, mudar de
que evento bruto um `SecurityEvent` deriva, ou mudar o `parser_version` gravado,
**muda a raiz de Merkle do segmento**. A proveniência fica cripto-selada sem
código novo.

**E uma armadilha que daí decorre:** a ordem de `parents` é significativa para o
hash (§13 da SPEC-0050 — "nunca reordenados"). Esta SPEC fixa a ordem em §7.3.

---

# 4. Identidade canónica: o triplo aritmético

## 4.1 O problema com nomes

O roadmap propunha 18 entidades nomeadas (`AuthenticationEvent`, `DnsEvent`, …).
Isso não sobrevive ao contacto com OCSF, e a razão é estrutural, não estética.

Em OCSF a identidade de um evento é **aritmética**:

```text
class_uid = category_uid * 1000 + uid_da_classe
type_uid  = class_uid * 100 + activity_id
```

Verificado: `events/iam/authentication.json` tem `uid: 2`, estende `iam`
(categoria 3), e resolve para `class_uid = 3002`. O `activity_id` é um enum
**por classe** (Authentication: 1 Logon, 2 Logoff, 3 Authentication Ticket,
4 Service Ticket Request, 5 Service Ticket Renew, 6 Preauth, 7 Account Switch,
99 Other).

Se o canónico for apenas um nome de `struct` Rust, o emissor OCSF fica a inventar
UIDs em tempo de execução — e a inventá-los de forma diferente em cada
implementação.

## 4.2 Requisito

Todo `SecurityEvent` **MUST** carregar:

```rust
/// OCSF type_uid = class_uid * 100 + activity_id.
/// Derivado, nunca recebido do exterior sem validação.
pub type_uid: u64,
```

e **MUST** gravá-lo em `attrs["sec.type_uid"]` como decimal, porque o índice de
atributos só aceita `String` (§8.1).

`category_uid`, `class_uid` e `activity_id` **MUST** ser deriváveis de `type_uid`
por aritmética, e não armazenados em triplicado.

## 4.3 As 18 entidades do roadmap não sobrevivem

Divergências concretas, verificadas contra `schema.ocsf.io/api/categories`:

* OCSF tem **8 categorias**, não 18 entidades.
* `AlertEvent`, `FindingEvent`, `IncidentEvent` e `VulnerabilityEvent` são
  **quatro classes da mesma categoria 2 (Findings)** — o roadmap separa-as como
  entidades de topo.
* `EmailEvent` explode em **três** classes OCSF (Email Activity, Email File
  Activity, Email URL Activity), todas na categoria **4 (Network)**.
* `CloudEvent` **não é uma classe** — `cloud` é um *profile* transversal.
* `RegistryEvent` é da **extensão Windows**, não do core.

A taxonomia canónica **MUST** ser `(class_uid, activity_id)`, com nomes humanos
como rótulo derivado — nunca como chave.

---

# 5. Identidade do parser

Este é o contributo central desta SPEC, e o que a SPEC-0045 não tem.

## 5.1 Requisito

Todo `SecurityEvent` derivado **MUST** carregar em `attrs`:

| Chave | Tipo | Obrigatório | Significado |
|---|---|---|---|
| `sec.parser_id` | string ≤ 64 B | sim | identificador estável do parser (ex.: `windows.security.4624`) |
| `sec.parser_version` | SemVer | sim | versão do parser que produziu **este** evento |
| `sec.schema_version` | SemVer | sim | versão do OCSF alvo (ex.: `1.9.0`) |
| `sec.normalized_at` | u64 ms | sim | quando a normalização correu |
| `sec.source_lsn` | u64 | sim quando aplicável | LSN do evento bruto |
| `sec.mapping_fidelity` | enum | sim | ver §5.3 |

`sec.parser_id` e `sec.parser_version` **MUST** ser separados. Concatená-los num
só campo impede procurar "todos os eventos produzidos por qualquer versão deste
parser", que é a pergunta que se faz quando um parser se revela errado.

## 5.2 Porquê versão por evento, e não global

Porque um parser errado é descoberto **depois**. Quando se descobre que
`windows.security.4624@2.1.0` classificava mal o `logon_type`, a pergunta
operacional é: *quais dos meus eventos foram produzidos por essa versão?* Com a
versão por evento e o `_kind` indexado, é uma consulta. Sem ela, é um scan do log
inteiro — e a §8.2 explica porque isso não é viável.

## 5.3 Fidelidade declarada

O parser **MUST** declarar o que conseguiu fazer:

```text
exact       todos os campos obrigatórios da classe foram mapeados de origem
derived     algum campo obrigatório foi inferido (documentar em sec.derived_fields)
partial     a classe foi identificada mas faltam campos recomendados
unmapped    não foi possível classificar; o bruto está preservado, nada é inventado
```

`unmapped` **MUST** ser um resultado legítimo e frequente, não um erro. Um
pipeline de segurança que nunca produz `unmapped` está a inventar classificações.

## 5.4 O que NÃO fazer

Um `SecurityEvent` **MUST NOT** ser emitido com campos obrigatórios da classe
OCSF preenchidos por valores-sentinela (`0`, `"unknown"`, `""`) só para passar
validação. Nesse caso emite-se `unmapped` com o bruto preservado.

---

# 6. Reprodutibilidade

## 6.1 Requisito

Para todo `SecurityEvent` `E` derivado do bruto `R` por `parser_id@version`,
correr o mesmo parser sobre o mesmo `R` **MUST** produzir um `SecurityEvent`
byte-idêntico em todos os campos **exceto**:

* `id` (o `EventId` é novo por construção),
* `ts_hlc` (carimbado pelo log),
* `sec.normalized_at`.

## 6.2 Como se prova

Um teste de conformidade por parser: um corpus de brutos com o resultado
esperado, e a asserção de igualdade sobre a projeção que exclui os três campos
acima. Um parser sem corpus de conformidade **MUST NOT** ser registado.

## 6.3 Consequência para o desenho do parser

Um parser **MUST NOT** depender de:

* relógio de parede (exceto para `sec.normalized_at`),
* ordem de iteração de `HashMap`,
* resolução de DNS, GeoIP ou qualquer consulta de rede em linha,
* estado acumulado de eventos anteriores.

Enriquecimento que exija estado externo (GeoIP, threat intel, resolução de
identidade) **MUST** ser um evento derivado *separado*, com o seu próprio
`parents` — não um campo escondido dentro da normalização. Caso contrário
"reprocessar o log" deixa de ser determinístico, e a SPEC-0050 §167
(reprodutibilidade) deixa de valer para esta camada.

---

# 7. Proveniência

## 7.1 O mecanismo já existe

Não se cria tabela de mapeamento nem campo `source_ref`. Usa-se `parents`, como o
`heraclitus-distill` já faz (`distill/src/lib.rs:143`).

```rust
normalizado.parents = vec![raw_event_id];
normalizado.attrs.insert("sec.source_lsn".into(), lsn.to_string());
```

## 7.2 A prova

A pergunta do roadmap — *"qual evento bruto originou esta entidade normalizada?"*
com prova — resolve-se com duas peças **já implementadas**:

* `parents` dá o ponteiro (`EventId`);
* `prove_lsn(source_lsn)` (`v6/verify.rs:250`) dá a prova de inclusão desse
  evento bruto exato na raiz de Merkle do segmento selado.

Não é preciso especificar um mecanismo novo. **MUST** usar-se este.

Nota: `parents` guarda `EventId` (ULID), não `Lsn`. Por isso `sec.source_lsn`
continua necessário — é ele que indexa a prova.

## 7.3 Ordem de `parents` (normativo)

Como a ordem entra no `canonical_record_hash` e nunca é reordenada
(SPEC-0050 §13), fixa-se:

```text
parents[0]  = evento bruto de origem            (sempre)
parents[1..] = contexto adicional, por ordem lexicográfica do EventId
```

Um parser que emita a mesma proveniência por ordem diferente produz um hash
diferente para o mesmo facto. Esta regra torna isso impossível.

## 7.4 Prevenção de ciclos

Herdado da SPEC-0045 §11: eventos derivados **MUST** marcar
`attrs["sentinel.generated"] = "true"` e **MUST NOT** reentrar no pipeline de
normalização. Esta SPEC acrescenta que a marca **MUST** ser verificada pelo
normalizador na entrada, não apenas na saída.

---

# 8. Limites do motor (normativo)

Uma SPEC de esquema que ignore estes limites promete buscas que o motor não
serve. Todos verificados no código.

## 8.1 `MAX_VALUE_LEN = 80 bytes` — descarte silencioso

`heraclitus-index-attr/src/lib.rs:76`. Em `apply` (:606), um valor com
`len() > 80` faz `continue`: não entra no índice exato nem no numérico. **Sem
erro, sem log, sem contador.** E `len()` são **bytes** — acentos e CJK esgotam o
limite mais cedo.

| Cabe (≤80 B) | Não cabe |
|---|---|
| SHA-256 hex (64), SHA-1 (40), MD5 (32) | SHA-512 hex (128) |
| ULID (26), UUID (36) | linha de comando |
| IPv4, IPv6, hostname curto, porto, PID | URL com query string |
| JA3 (32) | User-Agent, JWT, subject DN, syslog cru |

### Requisito

Todo campo canónico **MUST** ser classificado:

```text
INDEXABLE   garantido ≤ 80 B pelo parser; pesquisável por igualdade
EVIDENCE    pode exceder; vive em `content`; NUNCA prometido para busca exata
```

Para todo campo `EVIDENCE` de valor operacional, a SPEC **MUST** definir um
derivado curto e indexável:

| Campo evidência | Derivado indexável |
|---|---|
| `process.command_line` | `sec.cmdline_sha256` (64 B) |
| `http.url` | `sec.url_registrable_domain` |
| `http.user_agent` | `sec.ua_product` (primeiro token) |
| `tls.subject_dn` | `sec.tls_subject_cn` |
| `file.path` | `sec.file_name` + `sec.file_sha256` |

O parser **MUST** produzir o derivado; não é o índice que o infere.

## 8.2 `SKIP_VALUES` — os booleanos são invisíveis

`heraclitus-index-attr/src/lib.rs:72`:

```rust
const SKIP_VALUES: &[&str] = &["", "0", "-1", "nao", "sim", "true", "false", "null", "none"];
```

Um campo `sec.mfa_used = "false"` **não é indexado**. A consulta "todas as
autenticações sem MFA" — que é uma das mais feitas num SOC — não é servida.

### Requisito

Campos booleanos canónicos **MUST NOT** ser gravados como `"true"`/`"false"`.
**MUST** usar-se um valor discriminante:

```text
sec.mfa = "mfa_yes" | "mfa_no" | "mfa_unknown"
sec.outcome = "success" | "failure" | "unknown"
```

Isto é feio e é deliberado: é a forma de o esquema não prometer uma busca que o
motor engole em silêncio. Em alternativa, alterar `SKIP_VALUES` — mas isso é uma
mudança ao índice, fora do âmbito desta SPEC, e obriga a rebuild por replay.

## 8.3 `QUERY_SCAN_CAP = 250 000`

`heraclitus-query/src/backend.rs:115`. Uma query que caia no varrimento vê os
**250 mil eventos mais antigos** e trunca — sem erro.

### Requisito

Todo campo de que se espere filtragem em volume **MUST** ser `INDEXABLE`, para
que o planner use `attr_lookup` em vez do scan. Um esquema de segurança cujos
campos discriminantes caiam no scan é inútil acima de 250 mil eventos, que é
menos de uma hora de telemetria de um órgão médio.

## 8.4 Custo por evento

Medido a 2026-08-19 sobre 10 093 386 eventos reais: **~2 KB de RAM por evento**
com as views ligadas. Um esquema que multiplique o número de `attrs` por evento
multiplica esse custo.

### Requisito

O conjunto `INDEXABLE` por classe **MUST** ser fechado e documentado, com um
teto explícito. Recomendação: **≤ 24 attrs indexáveis por evento**. Tudo o resto
vive em `content`.

---

# 9. Os três relógios

Um evento de segurança tem três tempos, e confundi-los é a causa mais comum de
investigações erradas.

| Tempo | Onde vive | Significado |
|---|---|---|
| **do mundo** | `valid_from` (nativo) | quando o login/DNS/processo aconteceu na fonte |
| **de ingestão** | `ts_hlc` / LSN | quando o Heraclitus o gravou |
| **de normalização** | `attrs["sec.normalized_at"]` | quando o parser correu |

Os dois primeiros já são nativos (`event.rs:88`, e o planner implementa
`VALID AT t` em `plan.rs:503`). O terceiro não tem campo nativo e **MUST** ir
para `attrs`.

### Requisito

O parser **MUST** preencher `valid_from` com o timestamp da fonte quando o
souber, e **MUST NOT** preenchê-lo com a hora de ingestão quando não souber —
nesse caso deixa `None` e declara `sec.mapping_fidelity = partial`.

Isto é o que torna `VALID AT t` (o que era verdade) e `AS OF LSN n` (o que
sabíamos) perguntas separadas e ambas respondíveis. É a propriedade que nenhum
SIEM tradicional tem, e perde-se com um único parser preguiçoso.

---

# 10. Compatibilidade externa

## 10.1 Regra

Nenhuma tabela de mapeamento nesta SPEC **MUST** ser apresentada como 1:1 sem
que o seja. Onde a correspondência for N:M ou com perda, a perda **MUST** ser
documentada nas duas direções.

## 10.2 Estado real dos padrões (Agosto de 2026)

| Padrão | Versão | Mantido por | Natureza |
|---|---|---|---|
| **OCSF** | **1.9.0** (03-08-2026) | Linux Foundation | taxonomia + schema de eventos |
| ECS | 9.5.0 (04-08-2026) | Elastic — **não congelado** | schema de campos, 4 eixos multivalor |
| Splunk CIM | 8.5.0 (02-04-2026) | Splunk | **não é formato de evento** — é modelo de pesquisa |
| CEF | — | OpenText/ArcSight | cabeçalho de 8 campos, **sem taxonomia** |
| LEEF | 1.0 / 2.0 | IBM/QRadar | ecossistema em erosão pós-venda do QRadar |
| STIX | 2.1 (2021, OASIS) | OASIS | **grafo de conhecimento**, não log |
| OTel semconv | 1.44.0 (04-08-2026) | CNCF | transporte + convenções, **sem taxonomia de segurança** |

## 10.3 Decisão

**OCSF 1.9.0 é o núcleo.** ECS e CIM são *projeções de saída*. OTLP é
*transporte de entrada*. STIX não é um formato de evento e **MUST NOT** ser
tratado como tal — é o modelo do SPEC-0047 (threat intel), que é outra coisa.

Justificação: OCSF é o único com governação neutra (Linux Foundation),
taxonomia real e ferramentas de validação abertas. ECS é de um fornecedor; CIM
não é um formato; CEF e LEEF não têm taxonomia; OTel não tem semântica de
segurança.

## 10.4 Versão gravada por evento, não assumida

OCSF **quebra compatibilidade dentro de minors** (há depreciações em releases
minor). Portanto `sec.schema_version` **MUST** ser gravado por evento e **MUST
NOT** ser inferido da configuração no momento da leitura. Um evento normalizado
em 1.8.0 continua a ser um evento 1.8.0 para sempre.

## 10.5 Três níveis de validação

A validação OCSF **MUST NOT** ser tratada como "campos obrigatórios do struct".
São três níveis:

1. **required** — 7 no `base_event` (`activity_id`, `category_uid`, `class_uid`,
   `metadata`, `severity_id`, `time`, `type_uid`) + 2 em `metadata`
   (`product`, `version`);
2. **at_least_one** — constraints por classe (ex.: Authentication exige
   `service` **ou** `dst_endpoint`);
3. **profile-gated** — blocos de atributos ativados por profile (`cloud`,
   `host`, `datetime`, `osint`, `record_integrity`, `security_control`).

Um emissor que só valide o nível 1 produz eventos que o `ocsf-validator`
rejeita.

## 10.6 O mapeamento é gerado, não escrito à mão

O `ocsf-schema` é JSON compilável e tem `ocsf-schema-compiler`. O mapeamento
**MUST** ser gerado a partir do schema numa etapa de build, com a versão fixada
no `Cargo.toml`. Escrever as classes à mão em Rust é assumir a manutenção de uma
taxonomia de terceiros que muda duas vezes por ano.

---

# 11. `record_integrity` — a colisão que tem de ser dita

O OCSF 1.9.0 introduziu o profile **`record_integrity`** e o objeto
**`prev_event`**: uma cadeia de hash por registo, com atestação.

Isto colide de frente com o argumento de venda do Heraclitus. O que era
"só nós temos prova criptográfica de integridade" passa a ser, em 2026, um
profile de um padrão aberto que qualquer SIEM pode emitir.

## 11.1 Decisão

O Heraclitus **MUST** emitir o profile `record_integrity`, não competir com ele.
A posição defensável não é "temos hash chain"; é **onde** a prova vive:

| `record_integrity` do OCSF | Heraclitus |
|---|---|
| cadeia ao nível do **registo emitido** | raiz de Merkle ao nível do **segmento selado** |
| o produtor atesta-se a si próprio | `prove_lsn` prova inclusão contra uma raiz **carimbada por ACT RFC 3161** |
| não responde "o que sabia o sistema no instante T" | `AS OF LSN` reconstrói o estado exato |

## 11.2 Requisito

O emissor OCSF **MUST** preencher `record_integrity` a partir do
`canonical_record_hash` (SPEC-0050 §15) e **MUST** documentar, na saída, que a
verificação forte exige o log — não apenas o evento exportado. Emitir a cadeia e
insinuar que ela é a prova completa seria vender a prova fraca.

---

# 12. Crate e módulos

```text
heraclitus-security-schema/
  src/
    lib.rs            contrato público, sem dependências do plano Sentinel
    ident.rs          type_uid, class_uid, activity_id e a sua aritmética
    parser.rs         trait Parser, ParserId, ParserVersion, Fidelity
    provenance.rs     construção de parents + sec.* (usa heraclitus-core)
    fields.rs         classificação INDEXABLE/EVIDENCE e os derivados curtos
    ocsf/
      generated.rs    gerado do ocsf-schema no build (não editar à mão)
      emit.rs         SecurityEvent -> OCSF, com os 3 níveis de validação
      ingest.rs       OCSF -> SecurityEvent
    projections/
      ecs.rs          saída ECS 9.x
      cim.rs          saída CIM 8.5
  tests/
    conformidade/     corpus por parser (§6.2)
```

### Dependências permitidas

`heraclitus-core` (para `Episode`, `EventKind`, `EventId`).
**MUST NOT** depender de `heraclitus-sentinel`, `heraclitus-server`,
`heraclitus-query` nem de qualquer motor. O esquema tem de ser utilizável por um
coletor que não embeba a base de dados.

---

# 13. Gates de aceitação

| Gate | Critério |
|---|---|
| **SEC-A — Determinismo** | Para todo parser registado, reprocessar o corpus produz eventos idênticos exceto `id`, `ts_hlc`, `sec.normalized_at`. |
| **SEC-B — Proveniência** | Para todo `SecurityEvent` do corpus, `parents[0]` resolve para o bruto e `prove_lsn(sec.source_lsn)` verifica contra a raiz do segmento. |
| **SEC-C — Indexabilidade** | Nenhum campo declarado `INDEXABLE` excede 80 bytes em todo o corpus; nenhum está em `SKIP_VALUES`. Falha o gate se algum for descartado pelo índice. |
| **SEC-D — Validação OCSF** | 100 % dos eventos com fidelidade `exact` ou `derived` passam no `ocsf-validator` oficial, nos 3 níveis. |
| **SEC-E — Honestidade** | Nenhum campo obrigatório preenchido com sentinela. Um evento não classificável sai como `unmapped`, com o bruto intacto. |
| **SEC-F — Round-trip** | OCSF → `SecurityEvent` → OCSF preserva os campos `required`; a perda em `recommended` está documentada campo a campo. |
| **SEC-G — Teto de attrs** | Nenhuma classe excede 24 attrs indexáveis. |

Um gate que não corra em CI não é um gate.

---

# 14. Quando implementar

**Não agora.** O `SPEC-RESUMO.md` de 2026-08-21 fixa a ordem de execução:

1. fechar a integração segura da SPEC-0050 (resolver canónico, prova,
   verificação lógica, writer/reopen, matriz v1–v5);
2. concluir a qualificação mensurável da SPEC-0049;
3. só então abrir plataformas SOC grandes.

Esta SPEC é uma plataforma SOC grande. Escrevê-la agora é correto — o desenho
custa pouco e evita que a 0052 e a 0054 sejam construídas sobre um contrato
inexistente. **Implementá-la** antes dos pontos 1 e 2 seria construir a camada
semântica sobre um motor cujo formato de escrita ainda está a mudar.

### Pré-condições verificáveis

* SPEC-0050: `FORMAT_VERSION` do caminho vivo em v6, matriz de compatibilidade
  v1–v5 verde, crash-injection v6 em CI. *(A suite de crash-injection v6 existe
  desde 2026-08-21 e passa; o writer ainda gera v5.)*
* SPEC-0049: qualificação mensurável concluída.
* Uma decisão sobre `SKIP_VALUES` (§8.2) — ou o esquema adota os valores
  discriminantes, ou o índice muda. Não se pode adiar as duas.

---

# 15. O que NÃO fazer

**Não** redefinir `SecurityEvent`. É da SPEC-0045.

**Não** criar variantes novas no `enum EventKind`. O comentário em
`event.rs:47` é explícito: as variantes serializam por discriminante posicional,
e uma inserção a meio quebra a desserialização de dados já escritos.

**Não** atribuir tags novos no codec canónico v6 (`canonical.rs:74`). São
permanentes; mudá-los muda a identidade lógica de todos os registos.

**Não** escrever um validador OCSF de raiz.

**Não** prometer busca por igualdade em campos de texto livre. O índice
descarta-os em silêncio (§8.1) e a promessa só se descobre falsa em produção.

**Não** enriquecer dentro da normalização. Enriquecimento é derivação separada
com o seu próprio `parents` (§6.3).

**Não** apresentar o mapeamento externo como 1:1. Não é (§4.3, §10.1).

**Não** vender `record_integrity` como prova completa (§11.2).

---

# 16. Conclusão normativa

O que o roadmap pedia — um modelo canónico de evento de segurança — já existe na
SPEC-0045 e, na parte que interessa ao exterior, já existe em OCSF. Escrever
outro seria produzir um terceiro dialecto.

O que falta, e que nenhum dos dois tem, é o **contrato de derivação**: dizer que
código produziu cada campo, com que versão, a partir de que evidência, e
prová-lo. É essa a matéria desta SPEC.

E vale registar a parte desconfortável: com o `record_integrity` do OCSF 1.9.0, a
integridade criptográfica deixou de ser um diferencial e passou a ser uma
*commodity de formato*. O que continua a não ser commodity é o `source_lsn`
ligado a um log append-only com `AS OF` — a prova ao nível da **base de dados**,
não do documento. Uma SPEC que não diga isto está a preparar uma demonstração
comercial que o cliente vai desmontar.
