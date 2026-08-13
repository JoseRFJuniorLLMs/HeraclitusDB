# falta_fazer.md — TUDO o que falta fazer (consolidado)

**Gerado:** 2026-07-16 · **Estado de referência:** `main` @ `220c32c`.
Este ficheiro lista SÓ o que está em aberto. O histórico do que já foi feito
(P1–P5, revisão R1–R25, fatias do tier, H-VM pelo consenso) vive em
[falta.md](falta.md) e nos `DECISAO-P*.md`.

**Onde estamos:** tudo o que era acionável sem decisão de dono foi feito e está
verde (workspace + features `replication`/`analytics`/`tier`). O que resta
divide-se em: decisões de dono, features arquiteturais, follow-ups técnicos,
adiados por design e dívida de revisão.

---

## 1. DECISÕES DE DONO — resolvidas 2026-07-16 (ver estado)

**(a) Object store na NUVEM para o cold tier — ✅ GCS PREPARADO (falta creds).**
- Decisão: **GCS**. Feito: `ColdTier` passou a `Arc<dyn ObjectStore>` +
  `ColdTier::open_location(gs://…|s3://…|path)`; features `gcp`/`aws` no crate
  tier (forwardadas como `tier-gcp`/`tier-aws` no server). O Engine resolve o
  backend de `cold_tier_path` (URL ou local). Credenciais vêm do AMBIENTE
  (`GOOGLE_APPLICATION_CREDENTIALS`/`GOOGLE_SERVICE_ACCOUNT`), NUNCA do TOML.
  Compila com `--features gcp`; teste de parsing (local + gating de nuvem).
- **FALTA DO DONO:** criar o bucket GCS + service account, pôr o URL em
  `cold_tier_path` (`gs://<bucket>/<prefixo>`) e a env de credenciais, e
  correr um demote real. SÓ AÍ o guard 409 do `/tier/demote` em cluster pode
  cair (o objeto deixa de ser local ao nó — falta remover o guard quando o
  store partilhado estiver confirmado).

**(b) Wire do `heraclitus-distill` (consolidação §3.9) — ✅ FEITO (task periódica).**
- Decisão: **task periódica**. Feito: refactor `Distiller::distill_episodes`
  (computa Facts SEM appendar, à la tier); `Engine::distill_tick(cfg)` com
  **cursor persistido** (`<views>/distill.cursor`, evita re-emissão) + scan
  JANELADO + Facts via **`Engine::append`** (indexados ao vivo ≡ boot-replay +
  consenso). Task no server (`distill_interval_secs`, env
  `HERACLITUS_DISTILL_INTERVAL`, feature `distill`; nunca sob replicação, v0).
  Teste `distill_tick_consolidates_via_unified_append_with_cursor` (Facts
  consolidam, cursor evita re-emissão, state_hash live ≡ reopen, cursor
  sobrevive ao restart). FactDerived É indexado (é conhecimento, ao contrário
  de `hvm_isa`). LIMITAÇÕES v0 documentadas: clusters que atravessam a
  fronteira de tick/cap ficam partidos; distill em cluster fica para follow-up
  (cursor local ao nó → pula sob replicação).

**(c) GPU no `nearest` — ⏸️ ADIADO ATÉ BENCHMARK (decisão de dono).**
- O motor existe e auto-valida contra CPU, mas o **Gate C** exige ganho MEDIDO
  numa query real do produto no hardware alvo. Sem esse benchmark, ligar é fé,
  não engenharia. Reabrir quando houver medição.

---

## 2. FEATURES ARQUITETURAIS (projeto próprio — NÃO fingir como slice)

**(a) Evicção dos índices quentes / libertar RAM (o "esquecimento" a sério).**
- Hoje o demote é uma CÓPIA: o segmento continua no log local e nos índices
  em RAM. Nenhum índice derivado (graph/vector/text/attr) suporta remoção de
  range — só `memtable::prune_below`.
- Range-deletion no HNSW/BM25/grafo colide com a invariante **I6** (views
  reconstroem do LSN 0) — precisa de desenho: ou views que reconstroem "do
  LSN 0 MENOS segmentos demotados" (com o recibo como prova), ou epoch-based
  rebuild. Inclui também o bound do `ActivationStore` (1 registo/evento).
- **(b) Re-hidratação nos índices quentes após `fetch_cold`** é parte disto
  (hoje o recall devolve os episódios frios ao chamador; não reinsere).

**(c) Generalização formal do caminho §2.6 (`Engine::append_derived`).**
- H-VM e tier-receipt já seguem o padrão caso-a-caso (exclusão `hvm_isa` +
  append via Engine). Uma API formal com regra explícita de "que kinds entram
  em que índices" evitaria que o próximo produtor de evento derivado repita o
  bug (aconteceu 2× — H-VM e tier).

**(d) Auth mútua/TLS no transporte raft (R24) — ⏸️ ADIADO (LAN fechada, decisão de dono).**
- TCP e gRPC do consenso aceitam qualquer par que alcance a porta
  (AppendEntries/Vote/InstallSnapshot sem auth). Documentado como "rede
  privada SEMPRE" no `ReplicationConfig.raft_addr`. Decisão: cluster só em
  rede privada por agora; token-no-handshake ou mTLS ficam para quando houver
  deployment fora de LAN fechada.

---

## 3. FOLLOW-UPS TÉCNICOS em aberto (anotados no código)

- **Cache incremental do ledger H-VM** — `GET /hvm/state` e
  `POST /hvm/checkpoint` fazem replay do log INTEIRO por pedido (admin-gated;
  documentado). Fix real: cache incremental backed pelo checkpoint Bᵋ-tree
  (`<data_dir>/hvm.hbt`) + apply da cauda. (`engine.rs` hvm_state/…)
- **SPEC-016 Flight PARTIAL** — só `DoGet`/`GetSchema` reais; os outros 8
  RPCs (`Handshake`/`ListFlights`/`GetFlightInfo`/`PollFlightInfo`/`DoPut`/
  `DoAction`/`ListActions`/`DoExchange`) devolvem `Unimplemented`
  (`flight_grpc.rs`). Completar só se houver consumidor real.
- **Snapshot do raft é O(log) em RAM por design** — R22 cortou o pico de ~3×
  para ~2× (scan janelado), mas o snapshot continua a ser "todos os episódios
  num Vec". Streaming real de snapshot = mudança de formato do snapshot.
- **Keep-alive/pool de ligações no transporte raft** (TCP e gRPC ligam por
  pedido — otimização anotada nos headers de `net.rs`/`grpc.rs`).
- **Zone maps no footer do segmento** — hoje sidecar `.zmap` (rebuild barato);
  persistir no footer eliminaria o warm read único (anotado em `skip_scan.rs`).
- **XChaCha20 (nonce 24B)** — o nonce aleatório de 12B é ok à escala atual;
  mudar é bump de formato do blob cifrado. Adiado deliberadamente.
- **Merkle dup-leaf (CVE-2012-2459-like)** — mitigado por `record_count` no
  footer/recibos; domain separation por nível exigiria bump de
  FORMAT_VERSION. Adiado deliberadamente (documentado em `merkle_root`).
- **`Engine::recall` com AS OF over-fetcha 4×** — pode devolver <k
  (documentado); fix real = índices versionados por tempo.
- **`GraphIndex::state_hash` não cobre `attr_idx`** — ponto cego do gate de
  equivalência (estrutura+arestas cobertas). Alargar o hash muda o valor —
  coordenar entre nós/versões se se fizer.
- **Env overrides não cobrem `replication`** (config só via TOML) — menor.
- **Remoção física da camada raft v0** — está marcada LEGADO explícito
  (banner em `heraclitus-raft/src/lib.rs`); remover quando os testes de
  convergência pull-based deixarem de ter valor.

---

## 4. ADIADO POR DESIGN (PLANO-SPECS.md §5/Fase 3 — não re-litigar)

- NUMA node-local pleno (hoje só pinning round-robin, e esse é referência).
- Kernels AVX explícitos — só se um benchmark REAL os justificar (os kernels
  Arrow já são SIMD).
- Quórum distribuído para além do TCP/gRPC atual.

---

## 5. DÍVIDA DE REVISÃO (cobertura honesta da revisão R1–R25)

- **Não revistos** (referência por decisão P1–P5, fora do caminho vivo, não
  compilados no default): `hume-ir`, `hume-kernel`, `hume-sketches`,
  `heraclitus-txn`, `heraclitus-wasm`, `analytics::vectorized`/`planner`.
  **Rever OBRIGATORIAMENTE antes de promover qualquer um.**
  - `heraclitus-distill` — ✅ REVISTO E PROMOVIDO (2026-07-16): lido a fundo
    antes do wire; encontrados e corrigidos no wire os 3 riscos que a leitura
    revelou (append direto → `Engine::append`; scan-sem-teto → janelado;
    sem cursor → cursor persistido). Agora no caminho vivo atrás da feature
    `distill`.
- **Só em skim:** `boot.rs` (consola), `bin/service.rs` (SCM Windows), `cli`,
  `query/ast.rs` (semântica validada via plan.rs+testes), internals de
  `compliance/{signer,tsa,rfc3161}`, runtime wgpu do `gpu` (auto-validado
  contra CPU em hardware).
- **Lição das 3 rondas** (gravada na memória): o padrão que reaparece em cada
  módulo novo é o **scan-sem-teto** (`log.scan(0, MAX)` / scan sem cap) —
  apareceu 5× (R9, R10, R20, R22, R25). Verificar em TODO o código novo que
  toque o log.

---

## 6. AUDITORIA DE CÓDIGO RUST (2026-07-16 — ronda focada no código NOVO)

Auditoria multi-agente do **código desta sessão** (`/sql`, `/hvm/*`, `/tier/*`,
gRPC do raft, exclusão `is_hvm`) + áreas só skimmed (activation/retrieval/cli/
raft). Correu na base `8dc0384` (4 commits atrás do HEAD), e os verificadores
adversariais morreram no limite de sessão — por isso **separo o que re-confirmei
à mão contra o HEAD `220c32c` do que fica por verificar**. Não re-lista o que a
R1–R25 já cobriu.

### 6.1 CONFIRMADOS — ✅ TODOS CORRIGIDOS na v1.0.0 (2026-07-16)

Os 4 abaixo foram corrigidos e verificados (msvc) antes do corte da v1.0:
gRPC `max_decoding/encoding_message_size` = 256MiB; REST recusa expor escritas
sem auth fora de loopback; `/verify`+`/tier/demote`+`/tier/fetch` em
`spawn_blocking`; CLI sai com **1** em falha de integridade.


- **[HIGH] gRPC do raft não configura `max_decoding_message_size` (teto 4MB).**
  `heraclitus-raft/src/grpc.rs`: `RaftTransportServer::new(svc)` (~212) e
  `RaftTransportClient::connect` (~119) usam o default de 4MB do tonic, enquanto
  o transporte TCP permite 256MiB (`net.rs` `MAX_FRAME`) e o `heraclitus-client`
  JÁ eleva o limite (`client/lib.rs:27 .max_decoding_message_size(MAX_MSG)`).
  **Cenário:** com `transport = Grpc`, um `InstallSnapshot` (ou lote
  `AppendEntries`) >4MB é rejeitado para SEMPRE ⇒ um seguidor atrasado nunca
  recupera. **Fix:** `.max_decoding_message_size(256<<20)` + `max_encoding` no
  server E no client de `grpc.rs`.
- **[MED/sec] Escritas REST sem autenticação quando `rest_basic_auth = None`
  (o default).** `rest.rs:62-84` monta `POST /hvm/upsert|delete|checkpoint`,
  `/sql`, `/tier/demote` incondicionalmente; o braço `None` do `match basic_auth`
  devolve o router SEM layer de auth. Escritas DURÁVEIS no log append-only sem
  credencial. Mitigante: bind default `127.0.0.1`, mas `rest_addr` é livre
  (`HERACLITUS_REST_ADDR`) sem aviso. **Fix:** recusar as rotas mutating (ou
  recusar bind não-loopback) quando não há auth; separar router read-only vs
  mutating; aviso ruidoso no boot.
- **[MED/perf] Handlers a bloquear o reactor (sem `spawn_blocking`).**
  `rest.rs`: `tier_demote` (~288), `tier_fetch` (~350) e `verify`/`verify/:segment`
  (~384) chamam trabalho pesado e síncrono direto no executor async — ao passo
  que `hvm_state`/`tier_receipts`/`sql`/`flight` já usam `spawn_blocking`.
  `ColdTier::demote` faz `std::fs::read` de até 256MB + blake3 + encode Parquet +
  `log.append` (fsync); `Log::verify` re-lê+re-hasha TODOS os segmentos.
  **Cenário:** um `/verify` ou `/tier/*` num log grande congela um worker do
  tokio por segundos/minutos ⇒ `/healthz` (probes) time-out ⇒ restart. **Fix:**
  `spawn_blocking` como os restantes (classe R11).
- **[MED/sec] A CLI forense sai sempre com código 0.** `cli/src/main.rs:60-79`:
  `verify`/`verify_receipts`/`log_inspect`/`anchor` fazem
  `unwrap_or_else(|e| e.to_string())` — imprimem a falha mas o processo devolve
  0. **Cenário:** `heraclitus verify $DIR && promover-backup` promove um log com
  Merkle corrompido / recibo adulterado. **Fix:** `std::process::exit(1)` em
  qualquer `Err` e quando `verify`/`verify_receipts` reportam falha; erros para
  stderr.

### 6.2 A VERIFICAR / restantes

- **[HIGH] Durabilidade do state-machine sob `GroupCommit` (o DEFAULT) —
  ✅ CONFIRMADO E CORRIGIDO na v1.0.** Confirmado: `FsyncPolicy::default() =
  GroupCommit{5}` e `open_durable` escondia `head < normals` com `saturating_sub`
  ⇒ divergência silenciosa após crash na janela de fsync. Corrigido: falha ALTO
  (`Err`) quando `head < meta.normals` (`consensus.rs`). Follow-up ideal: exigir/
  forçar `Always` sob replicação, ou fsync do episódio antes do `sm_meta`.
- **[HIGH] Unidade de tempo do `ActivationStore` no recall —
  ✅ CONFIRMADO E CORRIGIDO na v1.0.** Confirmado: `apply` faz
  `touch(id, ts_hlc >> 16)` (ms) mas `recall` scoreava com `now = log.head()`
  (LSN) ⇒ todas as idades clampavam a 1 ⇒ decay de recência MORTO. Corrigido:
  `recall` usa `now = <ts_hlc do evento mais recente> >> 16` (mesma unidade,
  determinístico).
- **[MED] `ColdTier::fetch_cold` não valida contagem/root vs recibo —
  ✅ CORRIGIDO (commit `e7ac08d`).** `fetch_cold` corre `scan_and_root` e recusa
  (`HeraclitusError::Corruption`) qualquer objeto cold que não confira com o
  recibo (contagem + blake3_root), em vez de re-indexar um resultado parcial em
  silêncio. Teste `fetch_cold_rejects_corrupted_object`.
- **[MED] O servidor gRPC do raft morre num erro de `accept()` —
  ✅ CORRIGIDO (commit `e7ac08d`).** O incoming stream do `serve_with_incoming`
  passa a saltar erros de `accept()` e continuar a servir (recua-e-continua, como
  o transporte TCP puro do `net.rs`), em vez de terminar o serve e cair o nó do
  cluster até restart.
- **[MED] O WAL do `FileRaftLog` nunca é compactado — ✅ JÁ IMPLEMENTADO (R23).**
  `Inner::rewrite_wal` reescreve o `entries.wal` COMPACTADO (um `Purge` +
  Inserts vivos) atomicamente (tmp + fsync + rename + fsync do diretório),
  chamado no `purge` (pós-snapshot) e no `open` quando o replay consumiu
  Truncate/Purge. O item do audit estava desatualizado. (`durable.rs`)
- **[LOW] `heraclitus-retrieval::rrf_fuse` sem desempate determinístico —
  ✅ CORRIGIDO (commit `e7ac08d`).** Desempate determinístico por `EventId`
  (`.then_with(|| a.id.cmp(&b.id))`) — o corte `RECALL_N` e o top-k deixam de
  variar com a ordem de iteração do `HashMap`.
- **[LOW] Chaves não-UTF-8 colapsam — ✅ CORRIGIDO (2026-07-21).** `hvm_state_json`
  (`GET /hvm/state`) passava as CHAVES do ledger H-VM por `from_utf8_lossy` ⇒ dois
  bytes distintos viravam a mesma string (`U+FFFD`) e uma entrada sobrescrevia a
  outra no mapa JSON (desaparecia). Novo helper `hvm_bytes_str` injetivo: UTF-8
  legível quando possível, senão `hex:<hex>` (aplicado a chave E valor). Testes
  `non_utf8_keys_do_not_collide` + `literal_hex_prefix_is_disambiguated`.
  Ressalva: a "vista do tier" (`/tier/fetch`) usa um ARRAY de episódios, não um
  mapa por chave — o `from_utf8_lossy` no `content` ali é só display, sem colisão
  nem perda; deixado como está (mudar quebraria a saída legível do caso UTF-8).
- **[LOW] O espelho Parquet omite `valid_from`/`valid_to`/`embedding` —
  ✅ CORRIGIDO (2026-07-21).** `segment_to_parquet` (`heraclitus-tier`) ganhou
  três colunas NULÁVEIS: `valid_from`/`valid_to` (UInt64; NULL = aberto, distinto
  de um 0 real) e `embedding_json` (Utf8; JSON do `ProductPoint`, NULL se
  ausente). Teste `parquet_mirror_carries_bitemporal_and_embedding`. Nota: a
  tabela in-memory do `heraclitus-analytics` usa 0=ausente e ainda não espelha
  `embedding`/`parents_json` — convergir os dois schemas fica como follow-up
  menor.

### 6.3 JÁ CORRIGIDO / STALE (o audit correu 4 commits atrás)

- `demotion_receipts` scan-sem-teto → **já paginado** (`scan_capped` janelado, HEAD).
- Pico de RAM do snapshot do raft → já cortado (R22, §3).
- Growth do `ActivationStore` / snapshot O(log) → já rastreados (§2a, §3).

### 6.4 RONDA ADVERSARIAL 2026-07-22 (12 finders + verificação dupla)

Auditoria recursiva com finders por subsistema e verificação adversarial
(refutador + reprodutor por candidato). 21 candidatos ⇒ corrigidos os reais:

**Corrigidos (commits `f5d4a3c`, `da27952`, `adf0867`, + batch atual):**
- **[HIGH] subscribe (gRPC) bloqueava o reactor** — `log.scan` (bloqueante)
  direto no `tokio::spawn` do catch-up de histórico; agora `spawn_blocking`
  por chunk + `saturating_add`. (`f5d4a3c`)
- **[HIGH, DUPLO-CONFIRMADO] WAL raft truncava corrupção a meio do ficheiro**
  — qualquer falha de decode era tratada como cauda torn ⇒ `set_len` descartava
  em silêncio TODAS as entradas raft comprometidas a seguir. Agora: registo
  declarado além do EOF = cauda torn (trunca, como antes); payload completo que
  não decodifica = corrupção ⇒ recusa arrancar (política do meta.bin); alocação
  limitada pelos bytes restantes do ficheiro. (`da27952`)
- **[HIGH] index_applied fora de ordem** — appends concorrentes indexam fora de
  ordem: o guard do AttrIndex DESCARTAVA o evento atrasado para sempre (buraco
  silencioso que nem o replay curava) e os watermarks regrediam (re-replay
  duplicado pós-restart). Attr: inserção ordenada + dedup binary_search;
  watermarks avanço-só (max). (`da27952`)
- **[HIGH] paridade de auth entre superfícies** — o guard loopback-ou-auth só
  existia no REST; gRPC (append/shred/rebuild) e Flight (log inteiro via DoGet,
  sem auth NENHUMA) aceitavam bind não-loopback. Ambos agora recusam. (`adf0867`)
- **[HIGH] /sql permitia DDL** — `CREATE EXTERNAL TABLE ... LOCATION` lia
  ficheiros arbitrários do servidor. `sql_with_options` com DDL/DML/statements
  proibidos. (`adf0867`)
- **[MED] não-determinismo de empates** — BM25, merge_hits (memtable) e top_k
  (activation) desempatavam pela ordem de iteração do HashMap/DashMap; agora
  desempate por LSN/EventId (mesma política do rrf_fuse). (`adf0867`)
- **[MED] mascaramento de NaN** — `dist_hyp`: embedding com NaN ficava a
  distância ZERO de tudo (`NaN.max(1.0)==1.0` ⇒ `acosh(1)=0`) ⇒ agora +INF;
  activation: `d==1.0` dava 0/0 mascarado a 0 ⇒ limite logarítmico correto.
  (`adf0867`)
- **[MED] TOCTOU nas chaves de crypto** — dois threads no primeiro uso geravam
  chaves diferentes e o rename do último ganhava o disco ⇒ dados selados com a
  chave perdedora ilegíveis após restart. Árbitro `create_new` + retry do
  perdedor. (batch atual)
- **[MED] WASM sem teto de memória** — fuel limita CPU mas não RAM; módulo
  válido podia esgotar o host na instanciação. `StoreLimits` 64 MiB. (batch atual)
- **[MED] recall: candidatos só-ativação sem conteúdo** — chegavam com lsn=0 e a
  hidratação falhava em silêncio; agora resolve-se o LSN real via
  `GraphIndex::lsn_of`. (batch atual)
- **[LOW] btree deserialize** — `data[pos]` sem bounds-check (panic) e
  `with_capacity` de u32 cru do disco (alloc gigante); limitado pelos bytes
  restantes + `get()` verificado. (batch atual)
- **[LOW] `bench_recall --n 0`** — resto-por-zero; clamp a 1. (batch atual)

**Refutados (verificação inline contra o código):**
- Memtable evicta por contagem "antes das views indexarem" — FALSO na
  arquitetura atual: as views aplicam SINCRONAMENTE no `index_applied`, tudo o
  que sai do memtable já está indexado. Invariante documentado no local.
- Alocação "ilimitada" no replay do WAL raft — o alvo 64-bit com overcommit não
  aborta; mesmo assim a alocação ficou limitada pelo tamanho do ficheiro (grátis
  com o fix da corrupção).
- `layers.len()-1` no HNSW do query backend — o grow-loop acima garante
  não-vazio. `sync_data`/`sync_all` ignorados no log/durable — são caminhos de
  rollback/best-effort de diretório; o fsync real propaga erro antes do ack.

**Limitações CONHECIDAS e adiadas (design-level, não bugs pontuais):**
- **Transporte raft sem autenticação de pares** (`net.rs`/`grpc.rs`) — qualquer
  host que alcance a porta raft pode falar AppendEntries/Vote. Mitigação atual:
  rede privada/firewall. Follow-up: mTLS ou token partilhado no handshake.
- **RPCs raft sem timeout de connect/read** — um par blackholed segura o RPC
  além do `RPCOption.hard_ttl()`. O openraft tolera (eleição segue), mas
  honrar o ttl liberta recursos mais cedo.
- **Janela residual de checkpoint fora de ordem** — entre dois appends
  concorrentes, um checkpoint pode persistir o estado com o LSN maior aplicado e
  o menor ainda em voo; o restart replaya a partir do wm (agora avanço-só) e o
  dedup idempotente das views absorve a sobreposição — mas uma view SEM dedup
  por id re-contaria. Fecho total exigiria serializar append+index (mata o
  group-commit) ou um sequenciador com buffer; adiado com registo.

---

## 7. REGRAS (referência rápida — não re-litigar)

- **I2** — a inteligência vive no agente, não no banco.
- **I4** — não duplicar o DataFusion (SQL OLAP fica no DataFusion).
- **I6** — views reconstroem do LSN 0 (qualquer evicção tem de a redesenhar).
- **Gate C** — otimização = resultado bit-idêntico + ganho medido real.
- **`replication`/`analytics`/`tier` ficam feature-gated** — nó único é o
  caminho normal.
- Cada mudança: compilar+testar (msvc default), branch → ff-merge a `main` →
  push. Gravar decisão + PORQUÊ + discordância via `claude-mem remember`.
- Eventos derivados novos: passar por `Engine::append` OU exclusão de índice
  em TODOS os pontos (padrão §2.6) — nunca `log.append` direto.
