# SPEC-new/STATUS.md — Estado real dos documentos SPEC-new

**Gerado:** 2026-07-08/09 · **Método:** auditoria automatizada multi-agente
(extração de afirmações + verificação adversarial), cada afirmação verificada
com grep/leitura contra o código real em `crates/*/src`. `graphify-out/`
excluído (é cache, dá falsos positivos).

> **TL;DR:** os documentos em `SPEC-new/` são **PROPOSTAS (RFCs), não
> implementação**. Vários vendem como "código real", "auditado", "CONGELADO" ou
> "APROVADO" componentes que **não existem em nenhum crate**. Este ficheiro lista
> cada afirmação falsa/enganosa com a evidência. O estado real da plataforma e o
> roteiro estão em [../PLANO-SPECS.md](../PLANO-SPECS.md).

## ATUALIZAÇÃO 2026-07-09 — SPEC-009-035 implementados (módulos reais)

A pedido, os SPEC-009 a 035 foram **implementados como módulos Rust reais, que
compilam e passam testes** (workspace: 206 → **254 testes, 0 falhas**), adaptados
aos tipos reais do código (`Lsn`/`SegmentId` são `u64`, não newtypes; nada do
código v3.2.0 verbatim, que não compilava).

> **Distinção honesta:** "✅ módulo" = tipo/trait/lógica implementados **e
> testados** em unidade. **Wired = ❌** significa que o módulo existe e funciona,
> mas **ainda não está ligado ao caminho vivo** (planner/servidor/gRPC) — isso é
> trabalho de integração, não de implementação. Nenhum destes é "engine de
> produção completo"; são o **contrato + implementação de referência** que os
> specs descrevem.

| SPEC | Módulo real | Testado | Wired ao motor vivo |
|---|---|---|---|
| 009 | `core::canonical::CanonicalKeyCodec` · `index_graph::dense_map` | ✅ | ✅ **completo**: codec no `index-attr` (bug −0.0/+0.0 corrigido) + `DenseEntityMap` é agora o mapa denso interno do `GraphIndex` |
| 010 | `zone_map::ZoneMap` (lsn/ts/agent/session/attrs) + `skip_scan::SkipScanner` (+ sidecar `.zmap`) + pushdown GQL `scan_builtin_eq` | ✅ | ✅ **ponta-a-ponta**: query `WHERE agent_id/session_id=…` → planner → skip por zone map → sidecar persistente (cold-boot). Salta segmentos, nunca perde match. |
| 011 | `core::runtime` (StorageEngine, DatabaseManifest, DerivedExecutionArtifact, budgets) · `txn::SnapshotManager` | ✅ | ✅ `Log::manifest()` produz o `DatabaseManifest` real (segmentos+watermark, Merkle nos selados); `StorageEngine` trait fica p/ backend alternativo. **(P3, 2026-07-16:** `txn::SnapshotManager` e `DerivedExecutionArtifact` são **referência** — `heraclitus-txn` é órfão e `DerivedExecutionArtifact` tem 0 callers; ver 019 + `../DECISAO-P3-isolation-txn.md`.**)** |
| 012/013 | `core::ir` · `core::cost` · **`analytics::vectorized`** (motor Arrow real) | ✅ | ❌ **REFERÊNCIA (decisão P1, 2026-07-16)**: `SelectivityOptimizer`→`VecExecutor` existe e passa testes (Gate C), mas **nenhum handler o invoca** e `heraclitus-analytics` é `optional`/off-by-default. A via de agregação **ligada** passou a ser o `LogAnalytics` (DataFusion) em `POST /sql` — não duplica o DataFusion (I4). Ver [`../DECISAO-P1-motor-analitico.md`](../DECISAO-P1-motor-analitico.md). |
| 014 | `index_graph::provenance::ProvenanceEngine` · `core::dispatcher` · query `WHY(…) UNTIL "cause"` (minimal chain) | ✅ | ✅ **WHY UNTIL wired na GQL** (gramática→AST→plan→backend); minimal causal chain, shortest path testado. **(Correção 2026-07-16:** o caminho vivo do `WHY` é `trace_causes` sobre o mapa `parents` do `GraphIndex` (`query/backend.rs:1632`), **não** o `ProvenanceEngine` — este tem 0 callers fora do próprio ficheiro (**referência**). O `dispatcher`/`ReplaySink` idem — ver 024.**)** |
| 016 | `core::flight` · `analytics::flight` (IPC) · **`server::flight_grpc` (protocolo REAL)** | ✅ | 🟡 **PARTIAL (correção 2026-07-16; antes dizia "COMPLETO")**: servidor `arrow.flight.protocol` real (arrow-flight 58 + tonic 0.14, listener próprio `flight_addr`) — **`FlightClient` oficial testado ponta-a-ponta** (DoGet 2500 linhas, `as_of`, GetSchema, erro limpo) + data plane IPC + rota REST. MAS é opt-in atrás da feature `analytics` (**off por default**) e os restantes RPCs (`Handshake`/`ListFlights`/`GetFlightInfo`/`PollFlightInfo`/`DoPut`/`DoAction`/`ListActions`/`DoExchange`) devolvem `Unimplemented` (`flight_grpc.rs:99-146`). |
| 019 | `core::consistency::IsolationLevel` | ✅ | 🟢 **capacidade ligada / enum de REFERÊNCIA (correção P3, 2026-07-16)**: o `AS OF` (≡ `HistoricalSnapshot`) está ligado ponta-a-ponta pelo `as_of: Option<Lsn>` de todos os métodos do `QueryBackend` (resolvido do GQL `AS OF LSN|SNAPSHOT`). O enum `IsolationLevel` + `TxnManager::begin_with` **NÃO** estão no caminho vivo (`heraclitus-txn` é órfão); os níveis não-Historical degeneram no log single-writer. Ver [`../DECISAO-P3-isolation-txn.md`](../DECISAO-P3-isolation-txn.md). |
| 022 | `core::streaming::StreamSubscriber` | ✅ | ✅ **wired**: `log::subscribe::attach_subscriber` liga ao `tail_subscribe` real (on_append por evento; overflow → catch-up LSN) |
| 023 | **HQL — REJEITADO por design** (mantém GQL) | — | — |
| 024 | `core::contracts` (Planner/Optimizer/TaskScheduler/SegmentCatalog) | ✅ | ✅ **os 6 contratos com impl viva**: `StorageEngine`+`SegmentCatalog` no `Log` real, `Optimizer`/`TaskScheduler` no motor vetorizado (012/013), `ReplaySink` no dispatcher, e agora **`Planner` = `analytics::planner::AnalyticalPlanner`** (query string → `LogicalPlan`). `run_analytical` corre Planner→Optimizer→Executor ponta-a-ponta a partir de texto (Gate C testado). **Nota P1 (2026-07-16):** o trio Planner/Optimizer/TaskScheduler vive no motor vetorizado de **referência** (não ligado — ver 012/013 e [`../DECISAO-P1-motor-analitico.md`](../DECISAO-P1-motor-analitico.md)). **(Correção 2026-07-16 — a frase antiga "os contratos de storage estão no caminho vivo" era falsa:** `SegmentCatalog` tem impl real no `Log` (`log/lib.rs:1316`) mas só é invocado por teste de integração (`log/tests/manifest.rs`); `StorageEngine` **não** tem impl no `Log` — só o `MemStore` local de teste (fica p/ backend alternativo, ver 011); `ReplaySink`/`dispatcher` têm 0 callers fora do teste do próprio módulo = **referência**.**)** |
| 025 | `core::plugin` (HeraclitusPlugin + PluginHost) | ✅ | ❌ **REFERÊNCIA (correção P4, 2026-07-16)**: `heraclitus-wasm` é órfão e o `PluginHost` só **cataloga nomes** de operadores — **nada** no query/executor **invoca** um operador `wasm:<nome>`. Ligar plugins = feature real (superfície GQL p/ UDF + dispatch no executor + ABI a sério, não o `(i64,i64)->i64` de brinquedo) + decisão I2 (o próprio `plugin.rs` admite a tensão). Ver [`../DECISAO-P4-plugins-wasm.md`](../DECISAO-P4-plugins-wasm.md). |
| 026 | `core::capability::CapabilityCatalog` (detect real) | ✅ | ❌ **REFERÊNCIA (correção P1/P4, 2026-07-16)**: o único consumidor é o `VecExecutor`, que é **referência** (nenhum handler o invoca — ver 012/013). O catálogo não é consultado no caminho vivo. |
| 027 | `EventKind::SystemMetric` · `core::telemetry` | ✅ | ✅ **wired**: `Engine::emit_telemetry` + task periódica no server (`telemetry_interval_secs`, opt-in); self-query GQL testado |
| 028/031 | `core::artifact_registry` (registry + evicção em cascata) | ✅ | ✅ **wired**: `LogBackend` mantém um `SkipScanner` persistente; cada zone map é catalogado (fingerprint/segmento) e a evicção LRU do registry despeja o cache do scanner |
| 029 | `core::format_version::StorageFormatVersion` (negociação) | ✅ | ✅ **wired**: o decode do header do segmento negoceia via SPEC-029 (major novo = rejeição dura); bytes no disco intocados; `v2_compat` verde |
| 030 | `index_graph::GraphIndex::state_hash` + trait `View` | ✅ | ✅ |
| 032 | `core::cost::EmaCalibrator` | ✅ | ✅ **wired**: o `LogBackend` mede cada skip-scan e, se o EMA disser que é >20% mais lento que o window-scan, o planner cai de volta (adaptativo, testado nos dois sentidos) |
| 033 | `core::numa` (política) + **pinning real (`core_affinity`)** | ✅ | ❌ **REFERÊNCIA (correção P1/P4, 2026-07-16)**: `pin_workers` vive no `VecExecutor` (referência, não ligado — ver 012/013) e `core::numa` tem 0 callers externos. Nenhuma thread do caminho vivo é pinned por aqui. |
| 034 | `core::ebr::Versioned<T>` (reclamação por Arc) | ✅ | ✅ **satisfeito por equivalente superior**: o `SnapshotBundle` do backend já faz blue-green via `ArcSwap` (lock-free no load); `Versioned<T>` fica como utilitário p/ novos usos |
| 035 | `core::sandbox::run_sandboxed` · **`heraclitus-wasm` (wasmtime 31)** | ✅ | 🟡 **sandbox real EM UNIDADE / NÃO ligada (correção P4, 2026-07-16)**: o isolamento WASM (memória, fuel metering, traps contidos, módulo inválido rejeitado) é real e testado no crate, MAS `heraclitus-wasm` é órfão e `run_sandboxed` tem **0 callers** — nada no caminho vivo o alcança. Ver [`../DECISAO-P4-plugins-wasm.md`](../DECISAO-P4-plugins-wasm.md). |
| 015/021 | `raft` log-shipping v0 + hardening **+ consenso openraft real (feature `replication`)** | ✅ | 🟡→✅ **consenso provado in-process** (`raft::consensus`, openraft 0.9.24): eleição+aplicação idêntica+`state_hash` bit-idêntico, **failover** (líder morto → maioria elege → writes continuam → heal → convergência), minoria isolada não faz falso ack + reintegra limpa, redirect `ForwardToLeader`, duplo failover, snapshot (round-trip **e transferência real**: líder purga o log → seguidor atrasado apanha via `install_snapshot`), **raft-log DURÁVEL em disco (`FileRaftLog`) com restart de processo provado (sem duplicar/perder), e transporte de rede TCP real (`net`: eleição/replicação/failover sobre sockets)**. Só bytes de episódios viajam (`AppData` = bincode do `Episode`). Endurecido por revisão adversarial (corrigido 1 bug real de TOCTOU no `build_snapshot`). **Wrapper gRPC/tonic FEITO (2026-07-16, P2):** `heraclitus-raft::grpc` (serviço `RaftTransport` + `GrpcNetworkFactory`) sobre os mesmos tipos serde; o servidor escolhe TCP ou gRPC via `ReplicationConfig.transport` (default `tcp`). Testado: cluster elege+replica por gRPC (raft) e 3 servidores replicam+indexam por gRPC (server). |
| 020 | crash recovery (torn-write) — **já existia** no log | ✅ | ✅ |

**Próximo nível (o que realmente falta):** o *wiring* dos módulos ao caminho vivo
está **feito** (ver coluna "Wired" — a maioria ✅; este parágrafo antigo dizia o
contrário e ficou desatualizado). O que genuinamente resta é de outra ordem de
grandeza e está deliberadamente adiado:

- **SPEC-015/021 — consenso Raft real** — **fechado em 2026-07-10** (ver linha
  015/021 da tabela): openraft 0.9 atrás da feature `replication`, com eleição,
  quórum, failover e **raft-log durável + restart de processo** provados por
  testes de cluster in-process (30× sem flake), endurecidos por revisão
  adversarial multi-agente. Corre também sobre **transporte de rede TCP real**
  (não só o router in-process) **e agora sobre gRPC/tonic** (`heraclitus-raft::grpc`,
  toggle `ReplicationConfig.transport`, feito 2026-07-16 no P2 — testado). O wrapper
  gRPC deixou de ser o passo cosmético pendente.
- **Itens "referência, não produção" já com impl real mas a endurecer:** NUMA
  node-local pleno (multi-socket; hoje só pinning round-robin), kernels AVX
  explícitos (hoje os kernels Arrow já são SIMD por baixo), quórum distribuído.

## ATUALIZAÇÃO 2026-07-10 — SPEC-024 fechado (o 6.º contrato: `Planner`)

Dos seis contratos de subsistema da SPEC-024, cinco já tinham impl viva; faltava
o **`Planner`** (query string → `LogicalPlan`, o front-end do Compiler 1).
Implementado como `heraclitus-analytics::planner::AnalyticalPlanner` — uma
gramática analítica mínima (`SELECT [WHERE …] [GROUP BY … [SUM …]]`) sobre o
schema `events`, **sem inventar linguagem de grafo** (invariante #4: GQL continua
a única linguagem da superfície de grafo/temporal). `run_analytical` liga
Planner (024) → `SelectivityOptimizer` (012) → `VecExecutor` (013) ponta-a-ponta a
partir de texto. +5 testes (parsing, erros sem pânico, e2e vs força bruta, Gate C
a partir de string). Workspace continua verde.

## ATUALIZAÇÃO 2026-07-10 — SPEC-015/021 fechado (consenso Raft real)

`heraclitus-raft` ganha `consensus` (openraft 0.9.24) atrás da feature
`replication`, cumprindo a promessa antiga do header do crate: **eleição de
líder + commit por quórum + failover automático**. Peças: `MemRaftLog` (raft-log
em memória), `EpisodeStateMachine` (apply = `append_replicated` no log local,
LSN denso), `Router` in-process com links cortáveis. Tese SPEC-015 preservada:
só bytes de `Episode` (bincode) viajam; cada nó hidrata as suas views localmente.

**Endurecido por revisão adversarial multi-agente** (4 dimensões; 2 completaram
antes do limite de sessão e produziram 8 findings — verificados à mão contra o
source real do openraft). Achado principal, **bug real** que os testes verdes
escondiam: `build_snapshot` (que o openraft corre *spawnado em paralelo* com o
`apply`) lia o log e o `applied` sem lock comum ⇒ par rasgado. Corrigido com um
lock de consistência partilhado. Também: `no_quorum` reescrito (o antigo tinha
uma cauda vácua com claim falso), `wait_leader` simplificado (era código morto),
e +3 testes novos (redirect `ForwardToLeader`, duplo failover, round-trip de
snapshot). 6 testes de cluster, 30× sem flake; workspace verde.

## ATUALIZAÇÃO 2026-07-10 — raft-log durável + restart de processo

Fechada a maior lacuna de produção do consenso: **durabilidade**.
- `crate::durable::FileRaftLog` — raft-log durável (WAL append-only com
  `Insert`/`Truncate`/`Purge`, `fsync` ANTES do ack de quórum, meta atómica para
  voto/committed, cauda torn descartada no `open`). O voto durável é a garantia
  anti-split-brain (um nó reiniciado não vota duas vezes no mesmo termo).
- `EpisodeStateMachine::open_durable` — recupera `applied`/membership de um
  sidecar e usa `skip_normals = head − normals` para NÃO re-aplicar (duplicar) os
  episódios que já estavam em disco quando o openraft re-envia
  `[applied+1, committed)` no arranque. Ordem de escrita: episódios primeiro
  (fsync), meta depois ⇒ o meta nunca fica à frente (nunca se perde um episódio).
- Teste `durable_node_survives_restart_without_dup_or_loss`: um nó durável
  encerra, reabre do disco, re-lidera com o voto durável, mantém `head`
  inalterado (sem dup/perda) e continua a comitar. +4 testes (3 de `FileRaftLog`
  + 1 e2e). 15 testes com a feature, 30× sem flake; workspace verde.

## ATUALIZAÇÃO 2026-07-10 — transporte de rede TCP real

`crate::net` — o consenso deixa de viver só no router in-process e passa a
correr sobre **sockets TCP reais**. `serve()` liga um servidor TCP por nó que
despacha RPCs (`AppendEntries`/`Vote`/`InstallSnapshot`, enquadrados por
comprimento + bincode) para o `Raft` local; `TcpNetworkFactory`/`TcpConnection`
implementam o `RaftNetwork` do openraft ligando ao `BasicNode.addr` que viaja na
membership. `spawn_node_tcp` liga um listener efémero e serve.

2 testes de integração (portas efémeras em `127.0.0.1`): (1) 3 nós elegem líder
e replicam 20 writes com os 3 logs byte-equivalentes — tudo pela rede; (2)
**failover sobre TCP**: o líder morre (`raft.shutdown()`), os 2 sobreviventes
elegem novo líder pela rede e continuam a comitar. Honestidade: é TCP puro, não
gRPC literal — um wrapper tonic sobre os mesmos tipos serde é o passo cosmético
que resta. 18 testes com a feature, 25× sem flake; clippy limpo; workspace verde.

## ATUALIZAÇÃO 2026-07-10 — consenso LIGADO ao servidor (o wiring final)

O consenso deixa de ser um módulo testado à parte e passa a ser um **modo do
`heraclitus-server`** (feature `replication` + `config.replication`):
- **Config**: `ReplicationConfig` em `heraclitus-core` (`node_id`, `raft_addr`,
  `peers`, `bootstrap`, `raft_dir`, `sm_dir`) — TOML retrocompatível
  (`replication` ausente = nó único, o caminho normal, intocado).
- **`server::cluster`**: arranca o nó de cluster sobre o log do `Engine`
  (raft-log durável `FileRaftLog` + transporte TCP + state machine durável) com
  um **hook de apply** que indexa cada episódio replicado nas views locais
  (`Engine::index_applied`, `Weak` p/ evitar ciclo) — read-your-writes
  preservado em TODOS os nós.
- **`Engine::append` roteia pelo consenso** quando ativo: o líder submete via
  `client_write` (ack só por quórum); um não-líder devolve erro com hint do
  líder. O caminho de nó único não muda uma linha de comportamento.
- **`heraclitus-raft`** ganhou a API de alto nível (`submit_episode`,
  `initialize_cluster`, `node_status`, `production_config`,
  `spawn_node_tcp_on`) e o hook `with_apply_hook` (dispara só em appends
  genuínos, nunca nas re-aplicações de restart).

Teste de integração `three_server_cluster_replicates_writes_and_indexes`:
3 servidores in-process (portas efémeras) formam o cluster, 8 escritas passam
pelo `Engine::append` do líder, os 3 nós replicam o log **e a query GQL devolve
os dados em todos** (a prova de indexação); um seguidor recusa a escrita com
hint; `state()` expõe papel/líder. 23 testes no server com a feature; suites
raft (21) e default intocadas.

**Endurecido por revisão adversarial multi-agente** (o wiring novo tinha 3
defeitos reais que testes verdes + clippy esconderam):
- **telemetria contornava o consenso** — `emit_telemetry` fazia `log.append`
  direto ⇒ com replicação divergiria/derrubaria o nó (o `append_replicated` do
  raft colide, `CasConflict`). Corrigido: passa por `Engine::append`.
- **deadlock no handler `query`** — GQL escreve (`CREATE`/`DECIDE` → `append`) e
  a auditoria também; sem `spawn_blocking`, N queries-escrita concorrentes
  parqueavam todos os workers do tokio à espera do quórum e o `RaftCore` não
  podia ser escalonado ⇒ deadlock. Corrigido (`spawn_blocking` no `append` E no
  `query`).
- **`install_snapshot` não indexava** — appendava ao log mas não disparava o
  hook ⇒ um nó que apanhava via snapshot tinha os episódios no log mas não nas
  views (queries erradas até ao boot). Corrigido: o hook dispara nos episódios
  recém-instalados; +asserção no teste de snapshot.

## ATUALIZAÇÃO 2026-07-10 — endurecimento pré-merge (revisão adversarial)

Antes de consolidar, uma revisão adversarial multi-agente dos módulos novos
(`durable`/`net`/`planner`) encontrou **5 defeitos reais** que testes verdes +
clippy + gauntlet não apanharam (o `planner` saiu limpo):
- **durável, `fsync` do diretório** — o `rename` do `meta.bin` (voto/committed)
  não era tornado durável com um fsync do diretório-pai; um crash podia reverter
  o voto → **split-brain**. Corrigido (`fsync_dir`, best-effort: total no Linux
  de produção, no-op documentado no Windows). Idem no `sm_meta` da máquina.
- **durável, falha alta em meta corrompido** — `load_meta`/`load_sm_meta` repunham
  o voto/`applied` a vazio em silêncio num decode falhado; agora **recusam
  arrancar** (um voto persistido nunca é descartado sem ruído).
- **rede, teto de frame** — `read_frame` alocava até ~4 GiB a partir do
  comprimento vindo do fio (DoS/abort); agora há `MAX_FRAME = 256 MiB`.
- **rede, resiliência do `accept`** — um erro de `accept()` matava o servidor
  para sempre; agora recua e continua.
- **rede, honestidade** — o header afirmava keep-alive que o cliente (liga por
  pedido) não faz; corrigido.

+2 testes de segurança (`corrupt_meta_refuses_to_start`,
`read_frame_rejects_oversized`). 20 testes com a feature, 25× sem flake.

---

## Cobertura da auditoria

| Ficheiro | Extração | Verificação adversarial |
|---|---|---|
| SPEC-INDEX.md | ⚠️ falhou (limite de sessão fable-5) — banner escrito por leitura manual | — |
| SPEC-009-u64.md | ✅ | ⚠️ falhou (limite sessão); extração mantida |
| SPEC-010.md | ✅ | ⚠️ falhou (limite sessão); extração mantida |
| SPEC-011.md | ✅ | ⚠️ falhou (limite sessão); extração mantida |
| SPEC-019-028.md | ✅ | ✅ **refuted_count = 0** (nenhum finding refutado) |
| SPEC-029-035.md | ✅ | ⚠️ falhou (limite sessão); extração mantida |

Legenda de veredicto: **false** = afirma existência/auditoria e o símbolo/ficheiro
não existe ou é outra coisa · **misleading** = parcialmente verdade mas induz em
erro (existe algo relacionado, não o descrito) · afirmações de *design/intenção
futura* não são listadas (são legítimas como RFC).

---

## SPEC-INDEX.md — o "Manifesto" grandioso

Estado: **RFC/brainstorm**, não índice de algo implementado. Declara-se
`CONGELADO / DECLARATIVO E DETERMINÍSTICO` e `CONGELADO E SELADO`, descreve uma
"Data Computation Platform" com dual-compiler, HQL, Arrow Flight, WASM, cost-based
JIT — **nada disto existe no código**. Contradiz a tese fundadora do próprio
projeto (`SPEC.md`): SPEC.md tem como **não-objetivo** "inventar uma linguagem de
consulta nova" e usa **GQL** (`gql.pest`); o manifesto diz "a inteligência vive no
agente, não no banco" e depois enche o banco de compiladores e feedback adaptativo.
*(A extração automática deste ficheiro falhou por limite de sessão; banner escrito
por leitura manual — as contradições acima já tinham sido verificadas na análise
inicial.)*

---

## SPEC-009-u64.md — "CONGELADA / ALINHADA COM O CORE"

Estado real: os **factos numéricos conferem** (EventId é ULID 128-bit;
GraphIndex projeta EventId→u32 denso em ordem de LSN), mas **os dois artefactos
que a spec existe para especificar não existem**.

| Linha | Afirmação | Veredicto | Evidência |
|---|---|---|---|
| 3 | "Status: CONGELADA / ALINHADA COM O CORE" | misleading | `CanonicalKeyCodec` e `DenseEntityMap` = zero ocorrências em `crates/`. "Alinhada com o core" sugere spec verificada contra código. |
| 27 | "A auditoria do código-fonte... revelou..." | misleading | A conclusão (ULID) confere, mas atribui-a a `vm/codec.rs` — que é o codec de frames `VmInstruction` da H-VM — e coloca nesse ficheiro um `CanonicalKeyCodec` inexistente. |
| 50 | `// heraclitus-core/src/vm/codec.rs` `pub struct CanonicalKeyCodec;` | **false** | `vm/codec.rs` existe mas é o codec binário de `VmInstruction` (M20.1). `CanonicalKeyCodec` não existe em ficheiro nenhum. Bloco apresentado como conteúdo real de um ficheiro nunca escrito. |
| 47 | "O método `encode_f64` realiza o colapso canônico de NaN..." | **false** | Não existe `encode_f64`/`encode_i64`/`SIGN_BIT_MASK`. O único encoder f64→u64 real é `f64_ordered` em `heraclitus-index-attr/src/lib.rs:52` — que **não** trata NaN nem -0.0. |
| 123 | `// heraclitus-index-graph/src/dense_map.rs` | **false** | O ficheiro não existe (a pasta tem lib/adaptive/decision/entity/temporal). `DenseEntityMap`/`FrozenDenseEntityMap` = zero hits. Linha 128 declara `EventId = [u8;16]`, contradizendo o real `EventId(pub ulid::Ulid)`. |
| 30 | "GraphIndex projeta... u32 denso em ordem de LSN" | ✅ true | Confere: `index-graph/src/lib.rs:26-28` + `apply()`. |

---

## SPEC-010.md — design puro (sem selos), mas caracteriza mal o código atual

Estado real: **documento de design** (sem claims de auditoria/CONGELADO/notas).
O problema é dizer que o log atual não tem o que **já tem**, e propor como novo o
que já existe sob outro nome.

| Linha | Afirmação | Veredicto | Evidência |
|---|---|---|---|
| 17 | "...`scan_capped`... **sem metadados estruturais**" | misleading | Falso: o log **já** é segmentado em `.hrkl` com `SegmentHeader`+`SegmentFooter` (record_count, min_lsn, max_lsn, raiz Merkle blake3 — `format.rs:95-100`) + `SegmentMeta`/`SegmentIndex`/`LogCatalog` em memória. |
| 39 | "...tabela indexada em memória... (`SegmentCatalog`)" | misleading | Já existe: `LogCatalog {sealed, active}` + `SegmentIndex` (`log/lib.rs:62-76`). Os símbolos `SegmentCatalog`/`SegmentState`/`SegmentMetadata` do spec não existem; o análogo real é `SegmentMeta` (sem timestamps/compression_type). |
| 232 | "raiz Merkle... salva no seu rodapé" | ✅ true | Já implementado: `SegmentFooter.blake3_root` escrito ao selar (`log/lib.rs:1464`). Mas "Fase 3 (Freeze)" não existe como fase nomeada — o análogo é o *sealing*. |
| 233 | "durante reconstrução... recomputa a assinatura... aborta por divergência" | misleading | O replay real (`views/lib.rs:140-190`) **não** recomputa Merkle nem aborta. Há CRC-32 por registo no decode + verificação Merkle só via `verify_segment` (CLI `check`), não durante replay. |
| 245 | "O operador `WHY` deixa de ser... busca bidirecional simplificada" | misleading | `WHY` existe mas é BFS **unidirecional** de ancestrais (`trace_causes`, `backend.rs:1476`), não bidirecional. A "Provenance Engine" de 1ª classe não existe. |
| 212 | "`heraclitus-analytics` intercepta query complexa... quatro componentes" | misleading | `analytics` é um wrapper SQL DataFusion de ~170 linhas sobre a tabela `events`; não intercepta grafo. Statistics/Cardinality/CostModel/PhysicalPlanner/`GraphOperator` = zero hits. |

Genuinamente confere (estado atual bem descrito): materialização Arrow sem poda
(`analytics/lib.rs:65`), replay single-thread (`views/lib.rs:158`), `GraphIndex`
existe.

---

## SPEC-011.md — "Matriz de Maturidade" com cinco notas 10.0 auto-atribuídas

Estado real: **design puro**. Nenhum componente especificado existe; o único nome
coincidente (`StorageEngine`) é uma **variante de erro**, não uma trait.

| Linha | Afirmação | Veredicto | Evidência |
|---|---|---|---|
| 181 | "Abstração de Armazenamento — **10.0** — a trait `StorageEngine`..." | **false** | Não existe trait `StorageEngine`. Só `HeraclitusError::StorageEngine(String)` em `core/src/error.rs:11`. `append_raw`/`fetch_segment`/`write_manifest` + `DatabaseManifest` = zero hits. |
| 182 | "Consistência de Visão — **10.0** — `TransactionSnapshot`..." | misleading | `TransactionSnapshot` não existe. Real: `pub struct Snapshot(Lsn)` (`txn/lib.rs:16`) — newtype de 1 LSN, sem `watermark_lsn`/`visible_segments`. |
| 183 | "Agnosticismo de Artefatos — **10.0** — `DerivedExecutionArtifact`..." | **false** | `DerivedExecutionArtifact`/`ArtifactManager`/`ArtifactType`/`QueryFingerprint` = zero hits. Índices reais não partilham trait de ciclo de vida. |
| 184 | "Proteção de Hardware — **10.0** — `Memory Manager`+`ResourceScheduler`..." | **false** | `MemoryManager`/`ResourceScheduler`/`SystemResources`/`GraphOperator`/zonas Hot-Warm-Cold = zero hits. O único "cold" é `ColdTier` (tiering p/ object storage), não gestão de RAM. |
| 185 | "Determinismo Lógico — **10.0**" | misleading | Nota a uma garantia sem mecanismo: não há PhysicalPlanner/GraphOperator/múltiplas estratégias entre as quais exigir/testar determinismo. |
| 187 | "...atinge maturidade máxima... chancelado e pronto para a codificação" | misleading | "Chancelado" autodeclarado; nada existe em código. Atenuante: "pronto para a codificação" admite que o código não existe. |

---

## SPEC-019-028.md — verificação adversarial completa: **0 refutados**

Design puro com 3 claims concretos de código, **todos confirmados problemáticos**
(o verificador adversarial tentou refutar e não conseguiu).

| Linha | Afirmação | Veredicto | Evidência |
|---|---|---|---|
| 72 | "consenso de replicação... implementado via Raft no crate `heraclitus-raft`" | misleading | `raft/lib.rs` (153 l.) nega no header: "v0 (RFC-003): single-leader log shipping... we do NOT claim automatic failover". Só `Follower::sync_once` + `LogTransport`. `openraft` nem é dependência. |
| 251 | `EventKind { ... SystemMetric }` em `core/src/event.rs` | **false** | Enum real: `{Observation, Action, Message, RetrievalFeedback, FactDerived, DemotionReceipt, Custom}` — sem `SystemMetric`. Zero telemetria endógena. Shape inventado atribuído a ficheiro real. |
| 263 | "...usa `heraclitus-analytics` e a sintaxe SQL/HQL para investigar a si mesmo" | misleading | `analytics` é SQL DataFusion real, mas "HQL" = zero hits (é GQL). A query exemplo (`WHERE kind='SystemMetric'`, colunas `freeze_duration_ms`) nunca devolveria nada — colunas/eventos inexistentes. |
| 350 | "...perfeitamente amarradas e consolidadas. Deixa de ser um desenho teórico" | misleading | Zero hits para todos os componentes das SPEC-019–028 (também sob nomes alternativos). Continua 100% desenho teórico. |

---

## SPEC-029-035.md — output de chat de LLM colado como spec

Estado real: abre com **bajulação ao interlocutor** ("O seu parecer é definitivo..."),
admite ser pré-código (linha 3), e fecha com decreto auto-emitido
**"CONGELADO, CHANCELADO E APROVADO PARA IMPLEMENTAÇÃO IMEDIATA"**. Nenhum
componente nomeado existe.

| Linha | Afirmação | Veredicto | Evidência |
|---|---|---|---|
| 1 | "O seu parecer é definitivo e eleva o projeto ao nível mais alto..." | misleading (bajulação) | Abertura de resposta de LLM; não há "parecer" no repo. |
| 15 | "`DatabaseManifest`... `StorageFormatVersion` (major/minor/feature_flags)" | **false** | Zero hits. Formato real: magic "HRKL" + `format_version: u16` (FORMAT_VERSION=5), sem tripla nem bitmask. |
| 63 | "`ArtifactRegistry` rastreia a árvore de derivação física" | **false** | `ArtifactRegistry`/`ArtifactDependencyNode` = zero hits. Sem DAG de artefactos. |
| 76 | "`MemoryManager` expurga artefato da RAM..." | **false** | `MemoryManager` = zero hits. Sem evicção em cascata. |
| 119 | "`StatisticsCatalog` consome feedbacks... média móvel exponencial" | **false** | `StatisticsCatalog`/`ExecutionFeedback`/`CostModel` = zero hits. Sem malha adaptativa de custo. |
| 133 | "`ResourceScheduler` obriga core pinning das threads do GraphBLAS" | **false** | `ResourceScheduler`/GraphBLAS = zero hits. NUMA só como comentário em `mmap.rs`. Sem core pinning. |
| 179 | "Todos os plugins... executados dentro de um runtime WASM embarcado" | **false** | wasmtime/extism/wasm/`ExtensionCapabilities`/plugin/sandbox = zero hits. Sem sistema de plugins. |
| 204-206 | "Gate 1/2/3... Blindagem de Identidade / EBR / Sandbox WASM" | **false** | `StableId`/EBR/crossbeam-epoch/sandbox WASM = zero hits. "Formalizado" só neste texto. |
| 208 | "CONGELADO, CHANCELADO E APROVADO PARA IMPLEMENTAÇÃO IMEDIATA" | **false** | Decreto auto-emitido; o código real divergiu por completo destas specs. |

---

## Ação recomendada (Fase 0 do PLANO-SPECS.md)

1. **Rebaixar** toda a pasta `SPEC-new/` de "SPEC congelada" para **RFC/proposta**
   (banners aplicados no topo de cada ficheiro em 2026-07-08/09).
2. **Não citar** estes documentos como estado de implementação.
3. **Extrair** as ~5 ideias boas e compatíveis (segment footers com zone maps/bloom,
   delta-of-delta, format versioning completo, EBR, merge determinístico) como RFCs
   pequenos — ver Fases 2–3 do [PLANO-SPECS.md](../PLANO-SPECS.md).
4. **Rejeitar** HQL (SPEC-023): manter GQL, como o código já decidiu.
