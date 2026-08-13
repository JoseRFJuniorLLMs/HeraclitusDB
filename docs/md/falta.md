# falta.md — O que falta fazer (handoff para a próxima sessão)

> **⚠️ O QUE FALTA vive agora em [falta_fazer.md](falta_fazer.md)** (consolidado
> 2026-07-16, pós P1–P5 + revisão R1–R25 + fatias do tier). Este ficheiro fica
> como REGISTO HISTÓRICO do que foi feito e porquê.

**Escrito:** 2026-07-16 · **Contexto:** fecho da auditoria de wiring + P1–P5.
Este ficheiro é o ponto de partida da próxima sessão. Lê primeiro a §0.

---

## 0. NOTA DE AMBIENTE — CRÍTICA, ler antes de compilar

A toolchain **default é `stable-x86_64-pc-windows-gnu`** e o **`dlltool.exe` está
em falta** (mingw binutils). Qualquer compilação *fresca* de `getrandom`/
`windows-sys` (i.e. uma combinação de features ainda não em cache) **rebenta** com
`error calling dlltool 'dlltool.exe': program not found`.

**Contorno usado em P1–P5:** compilar/testar com a toolchain **msvc** (instalada):

```
cargo +stable-x86_64-pc-windows-msvc test --manifest-path D:/DEV/HeraclitusDB/Cargo.toml -p <crate> [--features ...] <filtro>
```

**Fix definitivo (é um item desta lista, §2.4):** instalar o `dlltool` (mingw-w64
binutils) **ou** pôr o msvc como default (`rustup default stable-x86_64-pc-windows-msvc`).

---

## 1. Onde estamos (feito, em `main`)

Auditoria de wiring cruzou o grafo de dependências Cargo + grep de callers e
descobriu que **vários "wired ✅" da `STATUS.md` eram falsos** (RFC/referência
disfarçados de implementação). Corrigido + agido:

| P | Ação | Resultado |
|---|---|---|
| P1 | ligou `POST /sql` (DataFusion); rebaixou o motor vetorizado bespoke | `DECISAO-P1-motor-analitico.md` |
| P2 | ligou o transporte **gRPC** do consenso raft (+ toggle `ReplicationConfig.transport`) | commit c9d880c |
| P3 | rebaixou `heraclitus-txn`/`IsolationLevel` (`AS OF` já ligado via GQL) | `DECISAO-P3-isolation-txn.md` |
| P4 | rebaixou plugins/WASM/sandbox; corrigiu também 026/033 | `DECISAO-P4-plugins-wasm.md` |
| P5 | ligou o **ledger H-VM** (REST) → trouxe `heraclitus-btree` ao caminho vivo | `DECISAO-P5-hvm-endpoint.md` |

**Genuinamente ligado (a superfície real):** `heraclitus-log` (segmentos, Merkle,
group-commit, skip-scan/zone-maps, torn-write, `DatabaseManifest`,
`StreamSubscriber`), `heraclitus-views` (replay+checkpoint), `heraclitus-memtable`
(RYOW); GQL completo → grafo (Leiden/CC, temporal `AS OF`, neighbors/traverse/
match_edges, DECIDE/ADAPT, EntityResolver), attr (range+zone maps), texto (BM25),
vetor (HNSW; GPU opt-in); WHY, telemetria (027), `EmaCalibrator` (032),
`ebr::Versioned`; consenso raft (TCP **e gRPC**, feature `replication`); H-VM (REST).

**Contexto do Claude:** `claude-mem recall <termo>` (memória HeraclitusDB, LSN
~57–67), os `DECISAO-P*.md`, `STATUS.md` e `PLANO-SPECS.md`.

---

## 2. O que falta — por prioridade

### 2.1 ALTA — wires reais (valor genuíno, sem equivalente hoje)

**(a) `tier` (cold-storage / esquecimento-com-recibos) — PRIMEIRA FATIA FEITA (2026-07-16).**
`heraclitus-tier` deixou de ser órfão: é agora dep **opcional** do server (feature
`tier`, gated como `analytics` por puxar parquet/arrow/object_store). Ligado:
`Engine::sealed_segment_ids()`/`demote_segment()`/`verify_demotion()` +
`GET /tier/sealed` e `POST /tier/demote {segment}` → materializa o segmento selado
no object store **local** (`cold_tier_path`): `.hrkl` + espelho Parquet +
`DemotionReceipt` com Merkle blake3 apenso ao log. Recusado com 409 sob replicação
(o recibo appenda fora do consenso). Teste
`demote_sealed_segment_produces_verifiable_receipt` (o `verify_receipt` re-computa
o Merkle do objeto cold). Decisão object-store: **local** (o crate já suporta;
nuvem = extensão de config futura).

SEGUNDA FATIA — recall round-trip **FEITO (2026-07-16):** `GET /tier/receipts`
(lista os recibos de demote) + `GET /tier/fetch/:segment` (busca o segmento
demotado do cold tier e devolve os episódios). `Engine::demotion_receipts()` +
`fetch_cold_segment()`. Testado (o fetch devolve `record_count` episódios; verify
re-computa o Merkle).

TERCEIRA FATIA — compaction em background **FEITA (2026-07-16):**
`Engine::tier_compaction_tick(policy)` conta, por segmento demotado (recibo
mais recente da cadeia), os tombstones semânticos (`attrs.tombstone_of`)
ainda presentes no objeto (alvo resolvido a LSN via GraphIndex, menos os já
removidos pela cadeia) e, quando a `CompactionPolicy` dispara, reescreve o
objeto sem eles + appenda o recibo novo pelo caminho unificado §2.6. Task
periódica no server (`tier_compaction_interval_secs`, 0=off, env
`HERACLITUS_TIER_COMPACTION_INTERVAL`; nunca sob replicação). Teste
`tier_compaction_tick_rewrites_when_policy_fires` (reescreve, verifica
Merkle, recall só sobreviventes, 2º tick idempotente).

TAMBÉM (§2.6 aplicado ao tier, 2026-07-16): `demote_segment` e a compaction
usam agora `demote_prepared`/`compact_cold_prepared` do crate tier e o
RECIBO entra pelo **`Engine::append`** (indexação viva ≡ boot-replay +
consenso quando ativo) — o read-back do R21 foi substituído pelo caminho
unificado a sério. O guard 409 do `/tier/demote` fica, mas pela razão nova
e honesta: o OBJETO cold é local ao nó (seguidores teriam recibo sem
objeto); cai quando o object store for partilhado.

FOLLOW-UPS restantes (decisão de dono, NÃO fingir como slice):
- **evicção dos índices quentes / libertar RAM — FEATURE ARQUITETURAL
  grande.** Nenhum índice derivado suporta remoção de range — só
  `memtable::prune_below`. E o `demote` é uma cópia (não apaga o segmento
  local). Range-deletion no HNSW/BM25/grafo colide com a invariante I6
  (views reconstroem do LSN 0). Projeto próprio.
- **re-hidratação nos índices quentes** após `fetch_cold` — parte do item acima.
- **nuvem** (S3/GCS) via config — decisão de provider + credenciais; o
  `object_store` já dá a superfície. Desbloqueia também o demote em cluster.

**(b) Routing do H-VM pelo consenso — ✅ FEITO (2026-07-16, via §2.6).**
`hvm_upsert/delete` passam agora por `Engine::hvm_append` → `Engine::append`
(frame = `Episode Custom("hvm_isa")`, excluído dos índices), logo pelo consenso
quando a replicação está ativa. Guards 409 removidos das rotas `/hvm/*`.
Cluster test `three_server_cluster_replicates_hvm_writes` (commit 8dc0384).
Detalhe e pré-requisito (exclusão de índice) em §2.6.

### 2.2 MÉDIA — correções de honestidade da `STATUS.md` — ✅ FEITO (2026-07-16)

Verificado por grep contra o código e corrigido na `STATUS.md`:
- **SPEC-016 (Flight):** confirmado PARTIAL — feature `analytics` off por default;
  só `DoGet`/`GetSchema` reais; os outros 8 RPCs devolvem `Unimplemented`
  (`flight_grpc.rs:99-146`). Linha corrigida ✅→🟡.
- **SPEC-014 (WHY):** confirmado — caminho vivo é `trace_causes` sobre
  `GraphIndex.parents` (`query/backend.rs:1632`); `ProvenanceEngine` tem 0
  callers externos (referência). Linha corrigida.
- **SPEC-024:** confirmado — `ReplaySink`/`dispatcher` e
  `DerivedExecutionArtifact` têm 0 callers externos (referência). Achado extra:
  `SegmentCatalog` tem impl real no `Log` mas só chamado por teste de integração;
  `StorageEngine` NÃO tem impl no `Log` (só `MemStore` de teste). A frase "os
  contratos de storage estão no caminho vivo" era falsa — corrigida.

### 2.3 BAIXA — decisões pequenas / limpeza
- **`heraclitus-distill`** — DECIDIDO (2026-07-16): **NÃO demote** (ao contrário de
  txn/wasm). É uma capacidade **genuína** (consolidação §3.9: agrupa embeddings
  episódicos na variedade e emite `Fact` `FactDerived` com proveniência no log),
  órfã mas não redundante — deps já no server (core/log/manifold). Mas o wire
  cai no **item arquitetural §2.6** (não é slice); fica lá.
- **Camada raft v0** — ✅ MARCADA COMO LEGADO (2026-07-16): banner explícito
  em `heraclitus-raft/src/lib.rs` (`Follower`/`LogTransport`/`LocalTransport`)
  + a superfície `RaftLogStorage` do log já marcada no R13. Fica como
  referência de convergência pull-based; promover exige reabrir a decisão.
  (Remoção física adiada: os testes de convergência dela ainda têm valor.)

### 2.6 ARQUITETURAL — os "wires" que restam NÃO são slices (achado 2026-07-16)

Investigar H-VM-routing-pelo-consenso e distill revelou um **padrão comum**: os
produtores de **eventos derivados** (H-VM `hvm_isa`, distill `FactDerived`, e o
recibo do tier) appendam **direto ao log**, saltando `Engine::append` — logo
saltam o `index_applied` (indexação viva) **e** o router de consenso. Consequências:

- **Consistência de índice/`state_hash` — PRIMEIRO PASSO FEITO (2026-07-16):**
  `GraphIndex::apply` cria um nó por **cada** episódio (`index-graph/lib.rs:209`),
  por isso os frames H-VM `hvm_isa` **poluíam** os índices — e de forma
  **inconsistente**: o caminho vivo saltava-os (bypass do `index_applied`) mas o
  boot-replay indexava-os (3 nós ao vivo → 5 após reopen), divergindo o
  `state_hash` do grafo. **Corrigido:** `hvm_isa` é agora excluído dos índices em
  TODOS os pontos de despacho — `Engine::index_applied` (vivo), o loop de boot do
  attr, e `ViewRegistry::{apply,catch_up,rebuild}` (`heraclitus-views`). Teste
  `hvm_frames_keep_graph_state_hash_consistent_live_vs_reopen` (state_hash do grafo
  idêntico vivo vs reopen). Isto **desbloqueia** o routing do H-VM.
- **Consenso do H-VM — FEITO (2026-07-16):** `hvm_upsert`/`hvm_delete` routam
  agora por `Engine::append` (via `Engine::hvm_append`, o frame é `Episode
  Custom("hvm_isa")`), logo passam pelo consenso quando a replicação está ativa
  (num não-líder devolvem erro com hint do líder). Guards 409 removidos das rotas
  `/hvm/*`. Cluster test `three_server_cluster_replicates_hvm_writes` (3 nós): as
  escritas H-VM replicam, `hvm_state` idêntico em TODOS os nós, e o `state_hash`
  do grafo é idêntico entre nós (os `hvm_isa` ficam fora dos índices). 5× sem
  flake, ~0.8s. O ledger soberano M20 funciona agora em cluster.
- **tier-receipt — ✅ RESOLVIDO pelo caminho unificado (2026-07-16):** o
  crate tier ganhou `demote_prepared`/`compact_cold_prepared`/
  `receipt_episode` (prepara SEM appendar) e o Engine appenda o recibo por
  `Engine::append` — indexado ao vivo ≡ boot-replay E pelo consenso quando
  ativo. **distill:** o mesmo padrão fica pronto a usar quando o wire do
  distill for feito (Facts via `Engine::append`, indexados como conhecimento).

**O verdadeiro próximo passo de design:** um **caminho unificado de append de
evento derivado** no `Engine` (indexação-viva coerente com o boot-rebuild +
routing de consenso opcional + regra explícita de quais eventos entram em que
índices). Depois disso, H-VM-routing / distill-wire / (parte da) compaction do
tier tornam-se slices. Fazer meia-ligação agora é PIOR que o guard 409 atual
(arrisca divergência de `state_hash` em cluster).

### 2.4 AMBIENTE (dev-experience) — ✅ FEITO (2026-07-16)
- `rustup default stable-x86_64-pc-windows-msvc` aplicado (gnu continuava default
  e o `dlltool` continuava em falta). Builds frescos passam a usar msvc por
  omissão; o `+stable-x86_64-pc-windows-msvc` explícito deixa de ser preciso.

---

## 2.5 REVISÃO DE CÓDIGO RUST (2026-07-16) — ✅ R1–R19 TODOS CORRIGIDOS

Revisão manual de todo o caminho vivo (~20k linhas lidas a fundo; ver
"cobertura" no fim da secção). 4 bugs foram CONFIRMADOS por sonda antes da
correção. **Estado: os 19 itens (R1–R19) foram corrigidos no MESMO dia** —
as sondas perderam o `#[ignore]` e vivem como guardas de regressão ativas em
`crates/heraclitus-query/tests/review_probes.rs` (6 testes, incluindo guardas
novas para R12/R19 e para o pushdown-sob-OR do R1) e
`crates/heraclitus-btree/tests/review_probe.rs`. Workspace + features
`replication`/`analytics` verdes após as correções.

Ressalvas honestas do que ficou DELIBERADAMENTE aquém do fix completo:
- **R7:** o rollback pós-roll ficou correto (baseline re-capturado), mas o
  *phantom commit* residual (registos de um lote falhado que ficaram selados
  com fsync ficam duráveis apesar do erro ao cliente) é ambiguidade inerente a
  qualquer WAL — documentado no código, não "corrigido".
- **R13:** a superfície raft v0 do log foi marcada LEGADO (0 callers; o
  consenso real usa openraft + `append_replicated`) e o default do
  `resolve_lsn_from_consensus_index` passou a PROTETOR (head em vez de 0 —
  bloqueia truncates em vez de permitir apagar committed). A distinção
  ULID-vs-índice por entrada continua impossível sem mudar o formato — aceite
  enquanto legado.
- **R12:** a reabertura preserva a história via `closed_intervals` no `Edge`;
  checkpoints bincode antigos do tgraph ficam ilegíveis → o restore degrada
  para replay (correto por construção, estado derivado).
- **R16:** o lock serializa escritas H-VM entre si; o carimbo `lsn` da
  VmInstruction continua advisory (o LWW real vem da ordem do log).

**RONDA 2 (2026-07-16, revisão do código NOVO pós-R19 + INFO restantes):**
- **(R20) `Engine::demotion_receipts` fazia `log.scan(0, head)` sem teto** —
  materializava o log inteiro num Vec por pedido de `GET /tier/receipts` /
  `fetch_cold_segment` (a mesma classe do R9/R10, reintroduzida pelo wire do
  tier). ✅ Corrigido: scan janelado (`scan_capped` em janelas de 100k).
- **(R21) Recibo de demote não indexado ao vivo** — o `DemotionReceipt` é
  appendado DENTRO do crate tier (log.append direto), saltando
  `index_applied`; o boot-replay indexava o episódio mas o caminho vivo não ⇒
  `state_hash` do grafo divergia vivo vs reopen (o MESMO padrão §2.6 do H-VM,
  já sinalizado para o tier). ✅ Corrigido: read-back do LSN do recibo +
  `index_applied` no `demote_segment`; guarda de regressão no teste de demote
  (state_hash live ≡ reopen).
- **INFO fechados:** claims de perf falsos no header do log corrigidos (doc
  honesta); flag de corrupção ESPÚRIA em segmento selado vazio corrigida
  (footer com `record_count == 0` aceita min/max ausentes); semântica
  generation-vs-LSN do `get_snapshot` documentada no btree; mitigação do
  dup-leaf do `merkle_root` documentada (mudar a regra = bump de formato,
  adiado). Já fechados por outra sessão: permissões dos `.key` (0600/0700).
- **INFO que ficam em aberto POR DECISÃO (não são fixes rápidos):** replay
  por pedido em `GET /hvm/state`/checkpoint (fix real = cache incremental
  backed pelo Bᵋ-tree); GPU não ligado ao `nearest` (feature, decisão de
  dono); nonce 12B (mudança de formato); over-fetch 4× do recall AS OF
  (documentado).

**RONDA 3 (2026-07-16, leitura integral do que antes fora só skim — raft,
compliance, gpu, manifold, activation, retrieval, flight, index-graph
restante, core restante, embedded/client):**
- **(R22) ✅ `build_snapshot` do consenso materializava o log inteiro ×3 em
  RAM** (`consensus.rs`): scan(0,MAX) → Vec de Episodes + Vec de payloads +
  bytes finais, sob o mutex da state machine. Corrigido: scan janelado direto
  para os payloads (pico ~2×, mesmos bytes, mesma atomicidade sob o mutex).
- **(R23) ✅ `entries.wal` do FileRaftLog crescia PARA SEMPRE** (`durable.rs`):
  Insert/Truncate/Purge eram todos appends; nada compactava o ficheiro —
  fuga de disco sem bound num cluster de vida longa. Corrigido: rewrite
  compactado atómico (tmp+fsync+rename+fsync-dir) no `purge` (pós-snapshot,
  vivos são poucos) e no `open` quando o replay descartou lixo real.
- **(R24) ✅/doc — transporte raft (TCP e gRPC) sem autenticação/TLS**:
  qualquer par que alcance a porta injeta AppendEntries/Vote. Documentado
  com aviso de segurança no `ReplicationConfig.raft_addr` (rede privada
  SEMPRE); auth mútua fica como trabalho futuro explícito.
- **(R25) ✅ Flight materializava o log inteiro por pedido** (`flight.rs`):
  `do_get`/`events_as_single_ipc` faziam scan(0,to) completo além dos batches
  Arrow e dos bytes IPC (~3×). Corrigido: scan janelado (50×BATCH_ROWS) —
  os lotes no fio continuam de 1024.
- **Menores ✅:** fsync antes do rename no checkpoint do VectorIndex
  (alinhado com views::ckpt); `GraphIndex::ancestors` de O(n²) para HashSet.
- **Conclusões próprias da ronda 3 (limpos, verificados a fundo):** manifold
  (matemática de Poincaré/Möbius conferida à mão + property tests reais),
  activation (aproximação Petrov com oracle exato e bound <5% testado),
  retrieval (RRF+rerank determinístico), vm/codec (fail-closed, BE canónico),
  dense_map/adaptive/decision/entity, compliance (commitment reprodutível
  com domain separation; worker fora do caminho de escrita; imprint SHA-256
  liga lsn+root), gpu (porta 1:1 do manifold com ranking quantizado p/
  ordem estável entre hardwares + fallback CPU), durable.rs (fsync-antes-
  do-ack real; voto fail-loud), net/grpc raft (frame cap, accept resiliente),
  embedded/client, config/artifact_registry/event.
- **Notas que ficam (não são bugs):** GraphIndex::state_hash não cobre
  attr_idx (ponto cego do gate de equivalência — estrutura/arestas cobertas);
  ActivationStore cresce 1 registo/evento (como as outras views); env
  overrides não cobrem cold_tier_path/replication.

Os itens abaixo ficam como REGISTO HISTÓRICO da revisão (o quê/onde/porquê).

### ALTA — corrigidos ✅ (caminho vivo, resultados errados)

**(R1) GraphMatch ignora condições WHERE não-empurráveis.** ✅ CONFIRMADO.
`MATCH (a)-[r]->(b) WHERE b != "Maria"` devolve TODAS as arestas — no plano
GraphMatch só as igualdades src/dst/etype são empurradas (`eq_filter`) e não
há pós-filtro `matches` como no ScanFilter. Qualquer `!=`, `>`, `<` ou campo
não-id é silenciosamente ignorado ⇒ resultados errados sem erro.
- Ficheiro: `heraclitus-query/src/plan.rs` (~878-914).
- Fix: aplicar pós-filtro sobre as linhas projetadas (ou, mínimo honesto,
  devolver erro "condição não suportada em MATCH de aresta" em vez de ignorar).

**(R2) Bᵋ-tree: valor >~3.9KB rebenta depois de a árvore ganhar profundidade.**
✅ CONFIRMADO: com raiz interna, `upsert` de valor 6KB devolve
`InvalidData("Estouro físico da Página")`. Só o caminho raiz-folha cria
cadeias overflow (>512B); o caminho buffer→`partial_flush_cascade`→folha
insere INLINE sempre, e o buffer do nó interno também serializa o valor
inline na página de 4KB. Um único valor grande não é divisível por split ⇒
erro permanente. **Afeta o ledger H-VM vivo** (`POST /hvm/upsert` aceita
valores arbitrários; `POST /hvm/checkpoint` usa `from_map`).
- Ficheiro: `heraclitus-btree/src/lib.rs` (`partial_flush_cascade` ~1794-1815;
  serialização do buffer ~718-745).
- Fix: criar cadeia overflow também no cascade E no buffer (ou validar tamanho
  no `upsert` com erro claro).

### MÉDIA — corrigidos ✅ (bugs reais com janela mais estreita)

**(R3) ORDER BY por campo compara strings JSON.** ✅ CONFIRMADO:
`ORDER BY n.lsn ASC` devolve [0,1,10,11,2,...]. Afeta lsn, ts_hlc e qualquer
attr numérico. `heraclitus-query/src/plan.rs` (~822-830): `field_of(...)
.to_string()` + `cmp` lexicográfico. Fix: comparar `as_f64` primeiro.

**(R4) Off-by-one no `sync_bundle` do LogBackend.** ✅ CONFIRMADO: um episódio
appendado depois do 1º sync fica INVISÍVEL nas queries de grafo/texto/attr/
vetor (o LSN é saltado para sempre). `heraclitus-query/src/backend.rs`
(938-1026): `bundle.lsn = pinned_head + 1` reclama cobertura de um LSN que
ainda não existe. LogBackend é referência/testes — mas os testes de
equivalência do server comparam contra ele. Fix: `bundle.lsn = pinned_head`
e scan até `pinned_head` (não `+1`).

**(R5) Log: truncate multi-segmento não é atómico.** O `truncate.intent` cobre
só (seg_id, valid_len); crash entre o `set_len` e os `remove_file` dos
segmentos seguintes ⇒ no reopen os segmentos "truncados" RESSUSCITAM
(divergência silenciosa em cluster). `heraclitus-log/src/lib.rs` (1630-1647).
Fix: intent com a lista completa de segmentos a remover.

**(R6) Log: Truncate concorrente com appends envenena o nó inteiro.** Um
`LogCommand::Truncate` que chegue durante o batching de appends responde erro
E põe `poisoned=true` — o nó morre até reopen. Em cluster, truncate do raft
concorrente com escrita mata o nó. `heraclitus-log/src/lib.rs` (557-568).
Fix: drenar o batch e processar o truncate a seguir, em vez de envenenar.

**(R7) Log: rollback pós-roll usa offsets do segmento antigo.** Se
`roll_segment` acontece a meio de um batch e uma escrita posterior falha,
`rollback_active_file` aplica o byte-count do segmento ANTIGO ao ficheiro
NOVO (set_len estende com zeros). Auto-reparado no reopen, mas registos do
batch pré-falha ficam duráveis apesar de o cliente receber erro (phantom
commit). `heraclitus-log/src/lib.rs` (~654-726). Fix: re-capturar o baseline
(segment_id, bytes) após cada roll.

**(R8) Bᵋ-tree: `recycle_id` tombstona páginas do estado DURÁVEL antes do
commit.** A cada push CoW a página da raiz antiga — ainda referenciada pelo
superbloco durável — é sobrescrita imediatamente; crash antes do próximo
`commit()` ⇒ checkpoint ilegível (CRC falha). Mitigante: é estado derivado,
regenerável do log. Mas viola o contrato de shadow paging do próprio header.
`heraclitus-btree/src/lib.rs` (1371-1412). Fix: free list pendente aplicada
só no commit (duas listas: alocadas-neste-epoch vs duráveis).

**(R9) Engine: `lsn_for_timestamp` materializa o log INTEIRO em RAM.** Cada
`AS OF TIMESTAMP` no servidor vivo faz `log.scan(0, u64::MAX)` sem cap (o
LogBackend de referência tem busca binária; o Engine não). `Engine::scan`
idem. Com logs grandes = OOM. `heraclitus-server/src/engine.rs` (646-648,
814-821). Fix: busca binária via `log.read` (copiar do LogBackend) + cap.

**(R10) Views: `rebuild()` materializa o log inteiro num Vec.**
`log.scan(0, u64::MAX)` sem paginação — exatamente o alloc gigante que o
`catch_up` foi corrigido para evitar. E é o fluxo OFICIAL pós bulk-ingest
(`HERACLITUS_LOG_ONLY=1` manda usar `view rebuild`). `heraclitus-views/src/
lib.rs` (200-218). Fix: paginar como o catch_up (scan_capped em janelas).

**(R11) gRPC admin: `rebuild`/`verify` correm no reactor sem spawn_blocking.**
Bloqueiam os workers do tokio por minutos em logs grandes (o mesmo tipo de
deadlock que o P-review corrigiu no `query`). `heraclitus-server/src/grpc.rs`
(190-226). Fix: `spawn_blocking` como no append/query.

**(R12) TemporalGraph: assert→retract→assert deixa a aresta morta para
sempre.** `upsert_edge` faz early-return se o `edge_id` já existe e nunca
reabre `valid_to_lsn`; re-afirmar uma relação terminada é no-op silencioso.
`heraclitus-index-graph/src/temporal.rs` (263-296 + 660-666). Fix: em
`assert` sobre aresta fechada, reabrir (novo intervalo) — decisão de
semântica a registar.

### BAIXA — corrigidos ✅ (endurecimento)

- **(R13)** `resolve_lsn_from_consensus_index` interpreta opaque_meta[8..16]
  (ULID aleatório em appends normais) como raft index — num log misto
  single-node→cluster o `allowed_max_lsn` do truncate pode sair errado
  (`heraclitus-log/src/lib.rs` 826-845).
- **(R14)** Truncar para dentro de segmento selado de versão antiga (v<5)
  reativa-o como ativo mas os novos records são escritos com FORMAT_VERSION
  atual — mistura de regra CRC/layout no mesmo ficheiro (lib.rs 1649-1676).
- **(R15)** `subscribe.rs`: overflow do broadcast antes do 1º evento recebido →
  `on_buffer_overflow(1)`, o LSN 0 nunca é notificado (25-40).
- **(R16)** `hvm_upsert`/`hvm_delete`: `lsn = log.head()` lido fora de lock —
  dois upserts concorrentes carimbam o mesmo lsn na VmInstruction
  (`engine.rs` 402-422).
- **(R17)** Auth REST Basic e gRPC Bearer comparam com `==` (não constant-time)
  — side-channel de timing (`rest.rs` 69-77, `lib.rs` 103-120).
- **(R18)** Bᵋ-tree: evicção do cache itera todos os shards segurando o lock do
  shard alvo — lock-ordering cruzado pode deadlockar sob leituras concorrentes
  (lib.rs 1268-1294). Hoje o uso vivo é single-threaded por instância.
- **(R19)** GQL `matches()`: AND/OR sem precedência (avaliação esq→dir) —
  `A OR B AND C` = `(A OR B) AND C`, diverge de SQL (plan.rs 503-519).
  Documentar ou corrigir.

### INFO — honestidade/limpeza (não são bugs de produção)

- `merkle_root` duplica o último leaf ímpar (padrão CVE-2012-2459); mitigado
  pelo record_count no footer.
- Claims de perf falsos no header do log ("Alocação Zero no Hot-Path" — cada
  append clona o episódio inteiro; `crypto_scratch.clear()` seguido de
  reatribuição).
- `GET /hvm/state` e `/hvm/checkpoint` fazem replay do log inteiro por pedido
  (documentado como "próximo refinamento"; com log grande é DoS autenticado).
  *(Avaliado 2026-07-16: NÃO é fix rápido — o fix real é um cache incremental
  backed pelo Bᵋ-tree checkpoint; entretanto é admin-gated. Fica para follow-up.)*
- GPU (`search_exact_gpu`/`topm_product`): 0 callers fora do próprio crate e
  testes — o caminho GPU NÃO está ligado à query viva (o `nearest` vivo usa o
  HNSW em CPU). *(Avaliado 2026-07-16: ligar RECALL-GPU é uma FEATURE, não um
  endurecimento rápido — decisão de dono; fica nota de referência.)*
- Bᵋ-tree `get_snapshot(key, lsn)`: o "lsn" comparado é na prática a
  GENERATION do superbloco, não um LSN do log — semântica MVCC enganosa.
- crypto: **`.key` 0600 / dir 0700 — FEITO (ronda de endurecimento 2026-07-16):**
  `heraclitus-crypto::KeyStore` restringe agora o ficheiro (no tmp ANTES do rename
  atómico, nunca world-readable) e o diretório no Unix; no Windows herdam a ACL do
  perfil (no-op, sem API std). Teste `key_file_and_dir_are_owner_only` (`#[cfg(unix)]`).
  O nonce de 12B fica (ok à escala atual; XChaCha20 = mudança de formato, adiada).
- Segmento selado vazio (roll com 1º registo gigante) gera flag de corrupção
  espúria no reopen (inofensivo).
- `Engine::recall` com AS OF só over-fetcha 4× — pode devolver <k
  (documentado no código).

### Cobertura da revisão (honestidade, atualizada pós-ronda 3)

- **Lido a fundo (rondas 1-3):** heraclitus-log (todos os módulos), query
  (backend/plan/fusion), server (engine/rest/cluster/lib/grpc/embedded),
  btree, index-graph (todos os módulos), views, memtable, index-attr,
  index-text, index-vector (completo), core (hlc/canonical/vm codec+
  interpreter/event/config/artifact_registry), tier, crypto, raft (consensus/
  durable/net/grpc/lib), compliance (lib/commit/worker; signer/tsa/verify em
  diagonal), gpu (CPU paths + WGSL; runtime wgpu em diagonal), manifold,
  activation, retrieval, analytics (lib/flight), client.
- **Skim apenas:** boot.rs (consola), bin/service.rs (SCM Windows), cli,
  query/ast.rs (mapeamento gramática→AST; a semântica foi validada via
  plan.rs + testes), compliance signer/tsa/rfc3161 internals, gpu wgpu
  runtime (auto-validado contra CPU em hardware).
- **Não revistos (referência por decisão P1-P5, fora do caminho vivo,
  não compilados no default):** hume-ir, hume-kernel, hume-sketches, txn,
  wasm, distill, analytics::vectorized/planner. Rever SE forem promovidos.

---

## 3. Adiado POR DESIGN (não é "falta" — `PLANO-SPECS.md` §5/Fase 3)
- NUMA node-local pleno (hoje só pinning round-robin, e esse é referência).
- Kernels AVX explícitos — só se um benchmark real os justificar (os kernels Arrow
  já são SIMD).
- Quórum distribuído para além do TCP/gRPC in-process atual.

---

## 4. Referência de propósito (NÃO mexer sem reabrir a decisão)

Rebaixados a referência de I&D por decisão explícita (violam I2/I4 ou são
redundantes/sem consumidor). **Não** são "falta" — são "não promover":
`hume-ir` (JIT/SSA), `hume-sketches`, os módulos `hume-kernel` (chunk/partition/
topk/compression/…), o motor vetorizado `analytics::vectorized` (`VecExecutor`/
`SelectivityOptimizer`), `heraclitus-txn`/`IsolationLevel`, `heraclitus-wasm`/
`core::plugin`/`core::sandbox`, `core::capability`, `core::numa`. Ver os
`DECISAO-P1/P3/P4.md` para o porquê e a discordância preservada.

---

## 5. Regras a respeitar (não re-litigar)
- **I2** — a inteligência vive no agente, não no banco (sem catedral de
  compiladores/JIT/plugins no core).
- **I4** — não duplicar o DataFusion (SQL OLAP fica no DataFusion).
- **Gate C** — qualquer otimização tem de dar resultado bit-idêntico ao caminho
  atual + ganho medido numa query real do produto.
- **`replication` fica feature-gated** — nó único é o caminho normal.
- Cada mudança: compilar+testar (msvc), commitar numa branch, ff-merge a `main`,
  push. Gravar decisão + PORQUÊ + discordância na memória (`claude-mem remember`).
