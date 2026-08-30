# SPEC-RESUMO — inventário verificado do HeraclitusDB

**Auditado em:** 2026-08-21 · **Atualizado em:** 2026-08-29 (auditoria completa contra o codigo; o GC do v6 nunca corre - ver STATUS.md)
**Regra de leitura:** uma SPEC só é “feita” quando há evidência de código, testes
executados e integração declarada. RFC, módulo de referência e decisão de
arquitetura não são sinónimos de implementação completa.

## Divergências corrigidas neste resumo

1. Não existem ficheiros individuais `SPEC-0001.md` a `SPEC-0035.md` em
   `SPEC-new/`. Há apenas registos parciais em `STATUS.md` e
   `PLANO-SPECS.md`.
2. A SPEC-0050 existe no disco como `SPEC-HRKL-0050.md`, não
   `SPEC-0050.md`.
3. `SPECs 0051.md` contém o roadmap SPEC-0051 a SPEC-0070 e não constava do
   resumo anterior.
4. Os documentos `SPEC-new/` são propostas/RFCs salvo quando o código e os
   testes abaixo demonstram um recorte implementado.

**Correção de auditoria — 2026-08-29 (SPEC-0045):** desde a auditoria acima,
os níveis L0–L6 foram ligados ao runtime e revalidados: o adaptador L2 transforma
`SecurityEvent` em features determinísticas com replay e snapshot AS-OF; o
worker funde sinais L1/L2 e persiste `SecurityRiskAssessment`; há filtro de
incidentes, incidente/grafo/baseline comportamental AS-OF, investigação L4 com
auditoria persistida, policy/approval append-only, executor reversível e APIs
REST/gRPC. O circuit breaker está ligado ao provider; governança de
modelo/ruleset e feedback são eventos append-only; as métricas L0–L4/ações são
expostas. A linha 0045 abaixo substitui o registro histórico da auditoria
anterior. O DoD v1 está fechado; credenciais/adaptadores externos e a
qualificação para `autonomous` continuam pertencendo ao host/laboratório por
desenho normativo.

## Estado por grupo

| SPEC | Estado verificado | Observação |
| --- | --- | --- |
| 0000, 0036–0041 | RFC / proposta | Não tratar como implementação completa. O plano só aprova extrações pequenas e compatíveis; HQL, JIT/MLIR e a premissa de 10B linhas continuam rejeitados. |
| 0001–0035 | Inventário incompleto | Os documentos-fonte não estão nesta pasta. `STATUS.md` registra módulos 009–035 com estados diferentes de integração; SPEC-023 foi rejeitada por design. |
| 0042 | **Concluída como decisão** | O Marco 0 mediu HUME versus DataFusion e decidiu manter DataFusion como motor vivo; HUME permanece em pausa. |
| 0043 | Parcial / draft normativo | Há fundações relacionadas, mas o documento não está concluído nem libera um router HUME. |
| 0044 | Pendente | Otimização de microarquitetura ainda é proposta; AVX explícito depende de benchmark real. |
| 0045 | **Concluída — DoD v1 fechado; produção/autonomia condicionadas** | `heraclitus-sentinel` fornece configuração desabilitável, tail real, fila limitada/catch-up por LSN, normalização, Sigma L1, baseline L2, grafo/incidentes/fusão L3 e checkpoints append-only. L4 aceita apenas `IncidentContext` bounded/redigido, invoca `ModelBackend` do host, valida/persiste investigação e auditoria; policy persiste propostas, decisões e aprovações humanas. Guards incluem epoch/lease, ação idempotente, circuit breaker vivo e `MemoryReversibleExecutor`; governança de modelo/ruleset e feedback são append-only. O servidor expõe REST de incidentes, evidência, WHY, ações, aprovar/negar, dashboard e checkpoint, além de operações administrativas gRPC com RBAC. Em Raft, somente o líder vigente executa L4/respostas. Adaptadores/credenciais de produção e atestações laboratoriais são responsabilidades externas explícitas; `autonomous` permanece fail-closed até serem fornecidas. |
| 0046 | Parcial | `heraclitus-compliance` cobre âncora/recibos RFC 3161 e passou a correr **também em HRKL v6**, ancorando pela raiz lógica canónica (§7.2) — que, ao contrário da raiz física legada, sobrevive a um repack sem invalidar recibos já emitidos. Ainda faltam StrictAirGap, cadeia ICP-Brasil validada e o plano regulatório completo. |
| 0047 | **Marcos 0, 1 e 4 implementados; 2, 3, 5–7 pendentes** | `heraclitus-sentinel::threat` existe (9 módulos): IR canónico com proveniência e ciclo de vida, canonicalização §21, índices exatos com Bloom só como prefilter, trust da fonte e gate de admissão, importador STIX 2.1 com os limites de §14, versionamento/rollback de feed, TLP 2.0 e sanitizador com gate de fuga. Gates T0/T3/T4/T5 cobertos por testes com esses nomes. **Sem** TAXII (§18–§19), MISP (§20), CTIR (§28–§32), bundles air-gap (§33–§35) e dashboard (§42) — todos precisam de rede, de fixtures reais, de uma API não publicada ou do servidor; T1/T2/T6/T7 por abrir. Detalhe em [STATUS.md](STATUS.md). |
| 0048 | Pendente | Não há orquestrador, playbooks tipados, motor de aprovação ou plano forense completo. |
| 0049 | **Definition of Done fechada; qualificação externa pendente por desenho** | Os 35 itens da §143 estão implementados — ver a secção dedicada abaixo. `heraclitus-qualifier` cobre manifests, workloads determinísticos, carga Q1, **crash-loop contra o binário de release**, **soak com o gate de fuga da §20**, corrupção, restore Q6, **monitor de egress**, **histórico append-only**, **compromisso criptográfico**, **doctor de configuração**, **regressão/golden**, **contrato do painel**, SBOM e supply-chain. Os gates que exigem laboratório (power-loss físico, perda de host, red team independente, soak de 168 h, DR, air-gap, runbooks executados por terceiros) continuam a produzir `Unqualified` — **isto é o comportamento correto**, não uma lacuna da implementação: a suíte recusa-se a auto-certificar o que a §35 e a §110 mandam vir de fora. |
| 0050 | **Fases 0–6 concluídas; 7 condicionada, 8 opcional** | HRKL v6 tem RAW, PACKED, manifesto `.hrkm`, gerações, GC, sidecar `.hrki`, object storage e **projecção lakehouse ligada ao caminho vivo** (Parquet v2 → Iceberg v2 → Delta → watermark → HRKM), com worker de background no servidor, `heraclitus export`/`manifest show` no CLI e 7 testes de integração ponta-a-ponta. A Fase 7 (`PackedEpisodeV1`) é condicionada por §204 a um benchmark; a Fase 8 é declarada opcional por §205. Raft, compliance e o resto passaram a funcionar em v6, que é agora o `storage_format` por omissão. |
| 0051–0070 | Propostas | Roadmap de segurança pós-0050 em `SPECs 0051.md`; não há estado de implementação individual confirmado nesta auditoria. |
## SPEC-0050 — progresso confirmado nesta auditoria

- Fases 0–3 estão presentes em `crates/heraclitus-log/src/v6/`:
  codec canónico/Merkle, RAW, PACKED, manifesto `.hrkm` e política de GC.
- O vetor dourado do manifesto HRKM foi corrigido para os bytes efetivamente
  produzidos pelo formato atual.
- A CLI fornece `heraclitus inspect`, `verify` (legado e v6, físico e
  `--logical`) e `prove --lsn`, todos sobre o resolvedor canónico oficial
  `heraclitus_log::canonical_hash_storage_payload_v6`.

## SPEC-0050 — integração no caminho vivo (2026-08-24)

- `HeraclitusConfig::storage_format` seleciona `legacy|v6`; omitir mantém o
  legado. Valor de ambiente inválido é erro de configuração, não fallback.
- `heraclitus_log::{EpisodeLog, AnyLog}` fornece o data plane comum a `Log` e
  `V6Log`: append (incluindo episódio carimbado), read/scan, tail, flush,
  append replicado e manifesto.
- `Engine`, views, H-VM, retrieval, query e analytics deixaram de exigir o
  tipo concreto legado. O planner mantém o skip-scan legado e, em v6, faz
  fallback conservador sem falsos negativos.
- O servidor abre, escreve, consulta, verifica e reabre uma base v6. O estado
  operacional declara `storage_format`, e a verificação/segmentos usam a
  semântica física própria de cada formato.
- As raízes são isoladas nos dois sentidos: abrir layout v6 como legado ou
  layout legado como v6 falha antes de escrever. Trocar a opção nunca move nem
  converte bytes.
- Capabilities ainda presas ao modelo físico v1–v5 falham fechadas em v6:
  compliance, Raft e demotion/compaction do cold tier v1. Não se fabrica um
  `SegmentMeta` legado para fingir compatibilidade.

## SPEC-0050 Fase 4 — sidecar `.hrki` (fechada em 2026-08-22)

`crates/heraclitus-log/src/v6/hrki.rs`: zone maps por bloco, Bloom filter,
bitmap de `EventKind` e política de confidencialidade por campo. O pruning
elimina blocos antes da leitura, com a propriedade assimétrica testada nos dois
sentidos (nunca podar um bloco que interessa).

## SPEC-0050 Fase 5 — object storage (fechada em 2026-08-23)

Vive em `crates/heraclitus-tier/`, **não** no crate do log: o `heraclitus-log`
não conhece `object_store` nem `async`. O que ele expõe é a fronteira
`v6::packed::BlockSource`, e o tier implementa-a por cima de range GETs.

| § | entrega | onde |
|---|---|---|
| §82–§83 | chaves de geração imutáveis `canonical/<ns>/segment-<id>/<logical-root>/generation-N.hrkl` | `generation.rs` |
| §85 | cold range reads (footer/directory → pruning → range GET) | `object_source.rs` |
| §86 | `DemotionReceiptV2` com raiz lógica + digest físico + geração | `receipts_v2.rs` |
| §84 | verificação pela autoridade do Heraclitus, nunca pelo `ETag` | `demotion.rs` |

Decisões que vale a pena registar (e as objeções que levantaram):

- **A origem esparsa é síncrona, o planeamento é assíncrono.** Envolver
  `BlockSource::read_at` num `block_on` para falar com o `object_store` seria
  pôr uma chamada bloqueante dentro de um executor assíncrono — o padrão que já
  causou o deadlock do handler `query` no wiring do consenso (STATUS.md,
  2026-07-10). Em vez disso decide-se **antes** que blocos interessam,
  descarregam-se só esses, e o leitor PACKED abre sobre eles. Um byte não
  planeado devolve **erro**, nunca zeros.
- **`verify_packed_reader` é partilhado.** O `verify_packed` local foi tornado
  genérico sobre `BlockSource` para que o tier frio não tivesse uma segunda
  implementação de verificação. Duas implementações divergiriam, e a que
  divergisse seria a do caminho menos exercitado.
- **Republicar bytes diferentes na mesma chave é erro duro**, não um `PUT`
  (`PutMode::Create` + comparação de digest). Republicar os *mesmos* bytes é
  idempotente, porque um retry de rede não pode virar falha operacional.
- **Publicar não é verificar.** O recibo nasce `Active`; só
  `verify_generation` em nível `LOGICAL` promove a `Verified`, e uma falha
  manda a geração para `Quarantined`.
- **Contra-argumento que ficou por resolver:** a Fase 5 ainda não está ligada ao
  endpoint do servidor. O writer/reopen v6 já está no caminho vivo, portanto o
  próximo passo é ligar ali o `ColdTierV6`; até isso acontecer, demotion v1 em
  uma base v6 é recusado explicitamente. `Engine::demotion_receipts` passou a discriminar a
  versão pelo campo `receipt_version` em vez de tentar desserializar; antes, um
  recibo v2 falhava o `serde` do v1 e **desaparecia da listagem em silêncio**,
  o que faria um segmento demotado parecer nunca ter sido demotado.

Números medidos no teste de integração (objeto PACKED de 2 404 338 B, 286
blocos de 8 KiB):

| operação | pedidos | bytes transferidos | blocos podados |
|---|---|---|---|
| abrir | 2 | ~64 KiB (2,7%) | — |
| point lookup (1 LSN) | 3 | ~3% do objeto | 285 de 286 |
| recall de 20 LSN | 3 | 90 672 B (3,8%) | 283 de 286 |

## Validações executadas

- Integração viva em 2026-08-24: `cargo test --offline -p heraclitus-server
  --lib` — **31 testes, 0 falhas**, incluindo append + GQL + restart em v6.
- Fase 6 em 2026-08-24: `heraclitus-server --features tier` — **39 testes**;
  `heraclitus-tier` — 62 unitários + 6 (Fase 5) + **7 (Fase 6)**;
  `heraclitus-compliance` — 18 unitários + **4 de ancoragem em v6**.
- Gates de §207 medidos (`cargo bench --bench hrkl_v6_ab`, 60k eventos × 5
  corridas): §153 PASS (v6 não regride face ao v5), §154 PASS (`packed/raw` =
  21.95%), §155 PASS (expansão 0 em dados incompressíveis).
- `cargo check --offline -p heraclitus-server` e `cargo clippy --offline -p
  heraclitus-server --lib --tests -- -D warnings` — passaram.
- `heraclitus-log`: **181 testes unitários + todas as suítes de integração e
  crash**, e Clippy `-D warnings`; `heraclitus-query`: **53 testes** e Clippy
  `-D warnings`.

- `cargo test --offline --workspace` — **742 testes, 0 falhas** (exit 0), depois
  de corrigir dois testes que nem sequer compilavam (`heraclitus-retrieval` e
  `heraclitus-views` tinham referências a `Log` deixadas para trás na migração
  para `EpisodeLog`/`AnyLog`; o workspace não passava `--all-targets`).
- `cargo test --offline -p heraclitus-tier` — 28 unitários + 6 de integração
  (`spec0050_fase5_object_storage.rs`), incluindo objeto adulterado, chave
  reescrita e recibo v2 a atravessar o log como episódio.
- `cargo clippy --offline -p heraclitus-tier --all-targets -- -D warnings` —
  passou. Corrigidos de passagem dois lints pré-existentes em
  `heraclitus-log` (`v6/hrki.rs`, `v6/raw.rs`) que bloqueavam este comando.
- **Fechado em 2026-08-24:** o Clippy de `heraclitus-log --all-targets -- -D
  warnings` passa. Os avisos pré-existentes dos benchmarks `carga_real_1m`,
  `carga_real_20m`, `otim_leitura` e `append_scaling` foram corrigidos, e mais
  quatro na própria lib (`type_complexity`, `field_reassign_with_default`,
  `too_many_arguments`).
- `heraclitus-compliance`, `heraclitus-cli`, `heraclitus-core`,
  `heraclitus-views`, `heraclitus-retrieval` e `heraclitus-server --features
  tier` também passam Clippy `-D warnings`.
- Os testes da Fase 6 foram validados por **mutação deliberada**, não só por
  passarem: um `attach_parquet_projection` transformado em no-op derruba 3 dos
  7; um exportador que perde 1 em cada 7 linhas derruba 6 dos 7; remover o
  filtro novo do GC derruba o teste de §176.

## SPEC-0050 Fase 6 — lakehouse (fechada em 2026-08-24)

Os exportadores já existiam e estavam testados em unidade; o manifesto já sabia
registar a projecção. O que faltava era a **ligação** — e a sua ausência era
mensurável: `parquet_export_lag_lsn` crescia para sempre porque media um
pipeline que nunca corria.

| entrega | onde |
|---|---|
| `V6Log::lakehouse_pending()` + `attach_parquet_projection()` | `log/src/v6/engine.rs` |
| `LakehouseWorker` (fila → Parquet → Iceberg → Delta → watermark → HRKM) | `tier/src/lakehouse/worker.rs` |
| task de background + `v6_lakehouse_{interval_secs,path,table}` | `server/src/lib.rs`, `core/src/config.rs` |
| `heraclitus export` e `heraclitus manifest show` (§120) | `cli/` |
| `STALE_PARQUET_PROJECTION` no `storage doctor` (§210) | `log/src/v6/doctor.rs` |
| §176: o GC do HRKL desliga o Parquet mas não o apaga | `log/src/v6/gc.rs` |

A Definition of Done de §209 é verificada item a item em
`tier/tests/spec0050_fase6_lakehouse.rs` (7 testes), incluindo o que mais
importa — *"nenhuma projecção lakehouse participa da durabilidade do append"*:
com o destino inutilizável, o append continua e o watermark não avança.

Decisões que vale a pena registar (e as objeções que levantaram):

- **O carimbo temporal vem dos dados, não do relógio.** §105 exige que um retry
  não duplique e §167 exige bytes reprodutíveis; um `SystemTime::now()` no
  commit Delta/Iceberg violaria os dois. O carimbo sai do `max_hlc` do próprio
  segmento, imutável depois do selo.
- **O HRKM é o último passo, não o primeiro.** Um Parquet publicado que o HRKM
  ainda não conhece é reexportado e o `PutMode::Create` torna isso idempotente;
  um HRKM que declarasse a projecção antes de ela existir faria o watermark
  avançar sobre bytes ausentes.
- **O `table_uuid` do Iceberg é o `storage_namespace_id` do banco**, não um UUID
  novo — gerar um faria cada reinício publicar metadata de outra tabela.
- **Contra-argumento que ficou por resolver:** o worker exporta segmento a
  segmento e não faz compactação de ficheiros Parquet pequenos (§175). Num
  banco com segmentos de 8 MiB isso produz muitos ficheiros pequenos, que é
  precisamente o que degrada uma tabela Iceberg com o tempo. §175 existe e não
  foi implementada; a alternativa — agrupar segmentos por exportação — foi
  rejeitada porque quebraria a correspondência 1:1 entre projecção e segmento
  que o `attach_parquet` valida.

## SPEC-0050 Fases 7 e 8 — porque não estão feitas

Não é dívida por falta de tempo; é o que a spec manda.

- **§204, Fase 7 (`PackedEpisodeV1`):** *"Somente após benchmarks demonstrarem
  benefício além de Zstd."* A pré-condição é uma medição, e ela foi feita em
  2026-08-24: o Zstd `Balanced` deixa **21.95%** dos bytes RAW (4.56× de
  compressão) num corpus operacional real. **O gate não abre.** Veredicto,
  ressalvas e o que o reabriria em
  [`resultados/SPEC-0050-fase7-GATE.md`](resultados/SPEC-0050-fase7-GATE.md).
- **§205, Fase 8 (indexação avançada):** o texto abre com **"Opcional:"**.

Implementar qualquer uma delas sem satisfazer a condição seria contrariar a
spec que se diz estar a cumprir.

## SPEC-0050 §129–§133 — migração v1–v5 → v6 (fechada em 2026-08-24)

Terceira vez que o mesmo padrão aparece nesta spec, e vale a pena nomeá-lo: o
`v6::migrate` tinha 9 testes a passar, tratava cada versão do formato, o
`opaque_meta`, a cauda rasgada — e **zero chamadores**. Nada migrava uma base
inteira, não havia comando, e `storage_format` continua a ter `legacy` por
omissão. Consequência prática: tudo o que as Fases 0–6 construíram estava
inalcançável para quem já tem dados.

| entrega | onde |
|---|---|
| `migrate_database()` — driver de base completa | `log/src/v6/migrate.rs` |
| persistência do `LegacyMigrationReceipt` (§132) | `log/src/v6/receipts.rs` |
| `heraclitus migrate-v6 <origem> <destino> [--no-verify]` | `cli/` |

Garantias que o driver faz cumprir mecanicamente:

1. **A origem fica byte a byte intacta** (§133) — pode haver um carimbo RFC
   3161, uma assinatura ou uma perícia a apontar para o hash antigo. Apagar o
   legado é decisão do operador, depois de verificar os recibos.
2. **O destino tem de não existir** (§83) — migrar para dentro de um banco
   povoado misturaria duas histórias.
3. **A identidade v6 é recomputada, nunca herdada** (§131) — cada segmento deixa
   um recibo persistido com a raiz legada e a raiz lógica v6 **lado a lado**,
   sem as confundir.
4. **A contiguidade de LSN é verificada, não assumida** (§5) — um buraco entre
   segmentos é erro duro.
5. **A cauda activa sai selada** (§130) — nunca se continua a appendar v6 num
   ficheiro legado.

Decisões e objeções registadas:

- **Uma cauda rasgada recusa migrar em vez de migrar metade.** §130 manda
  "recover according to legacy rules", mas essa recuperação é destrutiva
  (trunca o registo parcial) e violaria a garantia 1. O caminho é o operador
  abrir a base uma vez com o motor legado e voltar a correr.
- **`verify` é ligado por omissão.** A migração recomputa a identidade
  canónica do zero, portanto um erro no codec produziria um segmento v6
  *plausível* e errado, que só se descobriria quando alguém tentasse provar um
  LSN meses depois. `--no-verify` troca minutos de CPU por uma classe inteira de
  falhas silenciosas.
- **Um banco migrado é um banco novo**, com namespace próprio (§20). Reutilizar
  o do original faria duas bases reclamarem a mesma identidade de storage. A
  raiz lógica por segmento, essa, é idêntica entre duas migrações da mesma
  origem — provado em `o_banco_migrado_tem_um_namespace_proprio`.
- **Inconsistência pré-existente encontrada, não corrigida:** o backend legado
  grava `cumulative_watermark = head` (último LSN + 1) e o v6 grava
  `= max_lsn` (último LSN). Não causa bug hoje (os consumidores são internos a
  cada formato, e a ancoragem de compliance lê `last_lsn` dos segmentos, não
  este campo), mas o `EpisodeLog::manifest()` passou a ser genérico e é uma
  armadilha à espera. Corrigir mexe no significado de bytes já em disco
  (`cumulative_watermark` está no header do `.hrkm`), portanto fica sinalizado
  em vez de silenciosamente alterado.

Testes: 6 de integração em `log/tests/hrkl_v6_migrate_database.rs` (com uma base
escrita pelo `Log` de produção, não bytes fabricados) e 1 no CLI que percorre o
ciclo do operador — migrar → `manifest show` → `storage doctor` → abrir e usar.
Validados por mutação: desligar a verificação de contiguidade ou a detecção da
cauda activa derruba o teste respectivo.

**O que continua a faltar para o v6 ser o default:** o `storage_format` continua
`legacy` por omissão, e mudá-lo é uma decisão de produto, não de código —
implica que uma instalação que actualize o binário sem migrar veja o motor a
recusar abrir a sua base (as raízes são isoladas nos dois sentidos, de
propósito). O comando existe; a decisão de virar o default não foi tomada.

## HRKL v6 é o formato por omissão (2026-08-24)

`storage_format` passou a ter `v6` por omissão, e **nenhuma capability recusa
arrancar nele**.

**Correcção a este documento:** dizia-se aqui que o Raft assentava no modelo
físico legado. Não assenta. Em todo o crate `heraclitus-raft` os únicos métodos
do log usados são `append_replicated`, `head` e `scan`, os três já no
`EpisodeLog` — o acoplamento era uma assinatura de tipo (`Arc<Log>`), não uma
dependência. Trocada por `Arc<AnyLog>`; a suíte de consenso corre agora contra os
dois formatos (`HERACLITUS_RAFT_TEST_FORMAT=legacy` para o outro) e passa 18/18
em ambos: eleição, quórum, failover, snapshot, restart durável, TCP e gRPC.

| capability | antes em v6 | agora |
| --- | --- | --- |
| Raft | recusava o boot | **funciona**, 18 testes em v6 e 18 em legado |
| Compliance | recusava o boot | **funciona**, e a raiz lógica sobrevive a repack |
| Cold tier v1 | recusava o boot | arranca; a task **não é iniciada** e o boot avisa que é inerte (recibos v1 vs v2) |

`cluster_v6_replica_empacota_e_ancora_ao_mesmo_tempo` prova as peças a
funcionarem **juntas** na configuração por omissão: 3 nós, consenso por TCP, 60
escritas replicadas e indexadas, ancoragem, packing, e o recibo continua a
verificar depois de os bytes físicos mudarem.

O erro que um operador vê ao actualizar sem migrar deixou de ser um beco: nomeia
o ficheiro legado encontrado e dá as duas saídas (`heraclitus migrate-v6` ou
`storage_format = "legacy"`).

**Não ligado por omissão, deliberadamente:** a projecção lakehouse
(`v6_lakehouse_interval_secs = 0`). Packing e HRKI são compressão e índices —
poupam espaço. O lakehouse é uma cópia dos dados noutro formato; ligá-la por
omissão duplicaria o disco de toda a gente sem pedir licença.

**Continua a não existir:** compaction do cold tier para recibos v2. A v1 é
inerte em v6 e o boot di-lo; implementar a v2 é trabalho a sério, não um
adaptador.

## SPEC-0049 — Definition of Done fechada (2026-08-29)

Os 35 itens da §143 estão implementados. O que **não** está — e não pode estar —
é a qualificação em si: os gates que exigem um laboratório continuam a produzir
`Unqualified`, e isso é a suíte a funcionar, não a falhar.

### O que passou a existir

| §143 | onde | nota |
|---|---|---|
| soak suite | `qa/qualification/soak/{6h,24h,72h,168h}.json` + `qualifier soak` | o gate de fuga da §20 ignora a janela de aquecimento e ajusta a reta só ao troço estabilizado |
| crash loop, `kill -9` | `qualifier crash-loop` | mata o **binário de release**, não um writer dentro do harness |
| Q2 automatizado | idem | relê **todos** os appends confirmados; acima de 4096 amostra e di-lo |
| Q5 automatizado | `Invoke-RaftFailureMatrix.ps1` | define o contrato do injetor e julga os gates duros; a falha real vem do hipervisor |
| zero-egress implementado | `qualifier egress-monitor` | prova egress; **não** prova a ausência dele |
| histórico preservado | `qualifier history` | append-only, sem comando de apagar — a ausência é a funcionalidade |
| relatório vinculado ao binário | `qualification-commitment.json` + `verify --binary` | §121 vira erro, não promessa |
| release de emergência | `.github/workflows/security-release.yml` | exige ramo `security/*` e teste de regressão nomeado ou justificação escrita |
| runbooks §117 | `docs/runbooks/` (11) | `qualifier runbooks` verifica presença e substância |
| fuzz §39/§41 | `fuzz/{config_parse,rfc3161_decode}.rs`, `fuzz/README.md` | política de corpus: cresce, não encolhe |
| `heraclitus doctor` §138–§140 | `qualifier doctor` | lê TOML em **bruto** de propósito |
| regressão / golden §126–§129 | `qualifier regression` + `regression-budgets.json` | métrica sem orçamento fica `Undetermined`, nunca passa em silêncio |
| painel §108 | `qualifier dashboard` | métrica não medida sai `null`, para o painel distinguir §135 |
| modo independente §110 | `run --profile` | terceiro corre a suíte sem editar código |

### Quatro correções que a implementação forçou

0. **O ambiente da máquina sobrepõe-se ao ficheiro de configuração, e apontava
   para a base VIVA.** `HeraclitusConfig::load` aplica os `HERACLITUS_*`
   **depois** do ficheiro; nesta máquina o ambiente tem `HERACLITUS_DATA_DIR =
   D:\HeraclitusDB\data`. Um ensaio de crash teria matado à martelada um
   servidor montado sobre dados de produção. O supervisor limpa agora todas as
   `HERACLITUS_*` do filho e lista-as no relatório.

0b. **O próprio soak tinha uma fuga de memória.** Acumulava toda a amostra de
   latências da execução — num soak de 168 h, milhares de milhões de valores.
   O detetor de fugas crescia sem limite e reprovaria a execução que estava a
   medir. Passou a reservatório determinístico com decimação (teto de 262 144,
   sem RNG); os percentis por janela, que são os que mostram deriva, continuam
   exatos.

1. **`source_digest` cobria ficheiros não versionados.** Um clone do commit
   contém apenas os versionados, por isso o digest era irreprodutível por
   qualquer terceiro — o oposto do que a §111 pede. Nesta árvore, com 48 635
   ficheiros não versionados contra 1 640 versionados, também fazia cada
   execução hashear uma pasta de build inteira: a suíte de testes do qualifier
   passou de **mais de 28 minutos pendurada** para 38 s. O estado não versionado
   deixou de entrar no hash e passou a ser **reportado** (`untracked_files`) e a
   virar limitação declarada acima de Development.

2. **`percentil` no bench `hume_vs_datafusion`** falhava `clippy -D warnings`,
   o que reprovava o gate `lint` de **todos** os planos antes de qualquer outra
   coisa correr.

### O que continua por fazer, e porquê

Nada disto é dívida técnica; é a §35 e a §110 a funcionar:

- **power-loss físico** — cortar energia é do hipervisor ou da PDU (§25). O
  `crash-loop` declara no próprio relatório que não é equivalente;
- **perda de host, partição, disco parado** (Q5) — o harness julga, o
  laboratório provoca;
- **red team independente** — §35 quer equipa diferente da que implementou;
- **soak de 168 h, DR, air-gap, assinatura** — tempo real e infraestrutura;
- **runbooks validados** — §118: executados por quem não os escreveu. Enquanto
  isso não acontecer são procedimentos *propostos*.

## Tier frio em v6 — repack e recolha (2026-08-29)

**Correção a este documento.** O item nº 1 da ordem de execução dizia
«compaction do cold tier para recibos v2 — a única funcionalidade que o legado
tem e o v6 não». O que o legado tem é o `compact_cold(… is_deleted …)`, que
reescreve o segmento **omitindo registos**. §96 nomeia isso como *projection
compaction* e §97 diz que um output com outras `CanonicalRecord`s tem outra raiz
lógica e **não substitui** o segmento canónico. Portar essa função para recibos
v2 seria implementar o que a spec proíbe — e passaria despercebido, porque o
recibo v2 resultante seria internamente consistente e verificaria.

O que faltava mesmo era o ciclo de vida das gerações frias:

| entrega | onde |
|---|---|
| `ColdTierV6::repack_generation` (§189/§190) — outro codec/block size, mesma raiz | `tier/src/compaction.rs` |
| `ColdTierV6::collect_cold_locations` — remoção física idempotente no bucket | `tier/src/compaction.rs` |
| `GcExecution::cold_detached` — o GC do log deixa de tentar `remove_file` numa chave de bucket | `log/src/v6/gc.rs` |
| `is_object_store_location` — o vocabulário partilhado que evita a divergência | `core/src/runtime.rs` |

**O bug latente que isto fecha.** `PhysicalGeneration::location` tanto pode ser
`segments/…` como `canonical/…/generation-N.hrkl`. O `commit_gc` mandava as duas
para `resolve_gc_path`, que canonicaliza o pai contra a raiz local — inexistente
para uma chave de bucket. O `?` devolvia `Err` **antes** do commit, portanto uma
única geração fria superseded travava o GC do banco inteiro, gerações locais
incluídas. Reproduzido em `hrkl_v6_manifest.rs` e validado por mutação.

**Contra-argumento que ficou por resolver:** publicar uma geração fria não a
cataloga no HRKM — não existe `record_cold_generation`. As duas modelações
possíveis (cópia fria = geração N+1 nova, ou = outra `location` da mesma
geração) têm custos diferentes e a segunda muda o formato do `.hrkm`. Fica
sinalizado em vez de escolhido em silêncio. Consequência: o `plan_gc`
nunca vê uma geração fria, e o `repack_generation`/`collect_cold_locations` ficam
sem chamador. O resto do `ColdTierV6` **tem** chamador: `Engine::demote`
publica a geração, `verify_demotion_v2` verifica-a e `recall` lê-a por
intervalos.

Validação: `cargo test --offline --workspace` — **896 testes, 0 falhas**;
clippy `-D warnings` em `tier`, `log` e `core`. Detalhe e decisões em
[STATUS.md](STATUS.md).

## Ordem de execução atual

Ordenada por custo medido, não por número de SPEC. Os três primeiros itens da
lista de 2026-08-29 foram fechados em 2026-08-30 — ver as notas em
[STATUS.md](STATUS.md).

### Feito

- ~~**Ligar o GC do HRKL v6.**~~ `V6Log::collect_garbage`, task de fundo
  (`v6_gc_interval_secs`, 300 s por omissão), `heraclitus gc --dry-run` e a API
  de retenção que a §93/§94 exigia e não tinha superfície. Em produção desde
  2026-08-30.
- ~~**O "flaky" do `hrkl_v6_crash`.**~~ Não era flakiness: o
  `RawSegmentWriter::create` não sincronizava o header, e um crash nessa janela
  deixava a base impossível de abrir. Corrigido na origem (fsync do header e da
  entrada de directório) e na recuperação (um activo sem header completo é um
  toco de crash, e sai).
- ~~**Raft invisível na suíte por omissão.**~~ O comentário que justificava o
  off-by-default estava obsoleto; a lacuna passou a ser visível pelo nome de um
  teste, já que o output do `cargo test` imprime sempre os nomes.

### A fazer

1. **SPEC-0046** (P0, em curso) — `StrictAirGap` não existe no crate e a cadeia
   ICP-Brasil continua por validar, com o dizê-lo escrito no próprio código
   (`receipt.rs:16`, `verify.rs:41`, `tsa.rs:117`, `signer.rs:211`).
2. **Reduzir a pilha do "implementado, testado, nunca chamado"** antes de a
   aumentar. É o padrão que esta base repete e que a auditoria nomeou; e a
   SPEC-0047 acrescentou-lhe um caso meu. Por ordem de facilidade:
   - **dar consumidor ao plano de threat intel** — o módulo `threat` não é
     referenciado fora de si próprio: nenhum feed é ingerido e nenhum
     `SecurityEvent` é correlacionado contra o `IocIndex`. É wiring, sem decisão
     de formato pelo meio;
   - **catalogar gerações frias no HRKM** — precisa de uma **decisão de modelo**
     e por isso está parado à espera dela, não de código. Ver a nota do tier
     frio: ou a cópia fria é uma geração nova (N+1) com a mesma raiz lógica, que
     cabe no formato actual mas gasta um número de geração por movimento de tier
     e faz o `physical_digest` deixar de ser único; ou é outra `location` da
     mesma geração, que é o que o conceito pede mas implica mudar o `.hrkm`.
     Enquanto não for decidida, o `plan_gc` nunca vê uma geração fria e o
     `repack_generation`/`collect_cold_locations` ficam sem chamador.
3. **SPEC-0048** (P1) — a última SPEC completamente vazia:
   `heraclitus-orchestrator` e `heraclitus-forensic` não existem.
4. **§175 (compactação lakehouse)** — à luz do §96, o nome próprio da
   «compaction que o legado tinha»: opera sobre a projecção, regenerável por
   definição (§100). Hoje é limitação declarada, não defeito.
5. **Correr `lab-preflight.toml`** e marcar tempo de laboratório para os gates
   da SPEC-0049 que exigem infraestrutura; a suíte já não é o bloqueio.
6. **SPEC-0047, o resto** — TAXII e MISP são transporte por cima da fronteira
   `ThreatImporter` e pertencem ao servidor; o renderizador CTIR pode ser feito
   já (é lógica pura), o transporte não (§30: a API não se presume); os bundles
   air-gap devem esperar pela 0046 para não haver duas verificações de bundle
   assinado.
7. **Roadmap 0051–0070 por dependência.** A SPEC-0051 continua travada pelo seu
   §14 — mas a pré-condição nº 1 («o writer ainda gera v5») está desactualizada
   desde 2026-08-24: o `storage_format` é `v6` por omissão. Restam a
   qualificação externa da 0049 e a decisão sobre `SKIP_VALUES` (§8.2).
8. **Não fazer:** recuperar espaço de tombstones reescrevendo HRKL. §95 e §96
   proíbem-no; o mecanismo para dado irrecuperável é o crypto-shredding de §98,
   no `heraclitus-compliance`.
