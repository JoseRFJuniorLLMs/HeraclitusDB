# SPEC-RESUMO — inventário verificado do HeraclitusDB

**Auditado em:** 2026-08-21 · **Atualizado em:** 2026-08-24 (Fase 6 fechada; compliance em v6)  
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

## Estado por grupo

| SPEC | Estado verificado | Observação |
| --- | --- | --- |
| 0000, 0036–0041 | RFC / proposta | Não tratar como implementação completa. O plano só aprova extrações pequenas e compatíveis; HQL, JIT/MLIR e a premissa de 10B linhas continuam rejeitados. |
| 0001–0035 | Inventário incompleto | Os documentos-fonte não estão nesta pasta. `STATUS.md` registra módulos 009–035 com estados diferentes de integração; SPEC-023 foi rejeitada por design. |
| 0042 | **Concluída como decisão** | O Marco 0 mediu HUME versus DataFusion e decidiu manter DataFusion como motor vivo; HUME permanece em pausa. |
| 0043 | Parcial / draft normativo | Há fundações relacionadas, mas o documento não está concluído nem libera um router HUME. |
| 0044 | Pendente | Otimização de microarquitetura ainda é proposta; AVX explícito depende de benchmark real. |
| 0045 | Pendente | Não há crate Sentinel, funil SOC ou IR de detecção implementados. |
| 0046 | Parcial | `heraclitus-compliance` cobre âncora/recibos RFC 3161 e passou a correr **também em HRKL v6**, ancorando pela raiz lógica canónica (§7.2) — que, ao contrário da raiz física legada, sobrevive a um repack sem invalidar recibos já emitidos. Ainda faltam StrictAirGap, cadeia ICP-Brasil validada e o plano regulatório completo. |
| 0047 | Pendente | Não há integração STIX/TAXII/MISP ou Threat-Sync. |
| 0048 | Pendente | Não há orquestrador, playbooks tipados, motor de aprovação ou plano forense completo. |
| 0049 | Parcial | CI, fuzz e testes existem; Q1–Q6, qualificador, restauro, red-team e matrizes operacionais continuam pendentes. |
| 0050 | **Fases 0–6 concluídas; 7 condicionada, 8 opcional** | HRKL v6 tem RAW, PACKED, manifesto `.hrkm`, gerações, GC, sidecar `.hrki`, object storage e **projecção lakehouse ligada ao caminho vivo** (Parquet v2 → Iceberg v2 → Delta → watermark → HRKM), com worker de background no servidor, `heraclitus export`/`manifest show` no CLI e 7 testes de integração ponta-a-ponta. A Fase 7 (`PackedEpisodeV1`) é condicionada por §204 a um benchmark; a Fase 8 é declarada opcional por §205. Raft em v6 continua recusado no boot (§184 coloca a política de réplicas fora desta spec). |
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

- `cargo test --offline --workspace` — **735 testes, 0 falhas** (exit 0), depois
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

## Ordem de execução atual

1. **Raft sobre v6.** É a última capability que falha fechada no boot em
   `storage_format = "v6"`. Ao contrário do compliance — que só precisava de ler
   o `DatabaseManifest` em vez do `Log` concreto — a state machine, os snapshots
   e o `install_snapshot` do openraft assentam no modelo físico legado. §184
   coloca a política de durabilidade de réplicas fora desta spec, portanto é
   trabalho da camada de replicação, não da 0050.
2. **§175 (compactação lakehouse)** se e quando o número de ficheiros por tabela
   começar a doer; hoje é uma limitação declarada, não um defeito.
3. Concluir a qualificação mensurável da SPEC-0049 antes de abrir plataformas
   SOC grandes; depois seguir o roadmap 0051–0070 por dependência.
