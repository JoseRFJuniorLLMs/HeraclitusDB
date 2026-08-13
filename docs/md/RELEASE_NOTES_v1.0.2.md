# HeraclitusDB v1.0.2 — "fable-5"

**Data:** 2026-07-22

Patch de manutenção sobre a [v1.0.1](RELEASE_NOTES_v1.0.1.md): fecha a **ronda
adversarial de auditoria de 2026-07-22** (12 finders por subsistema +
verificação dupla refutador/reprodutor; §6.4 do `docs/md/falta_fazer.md`).
21 candidatos → **13 bugs reais corrigidos**, 4 refutados com evidência, 4
adiados por design (documentados). **Só correções** — sem mudanças de API nem
de formato em disco; atualizar é seguro e recomendado. Verificado verde (msvc):
suite completa do workspace **403 passed, 0 failed** com
`replication`+`analytics`+`tier`+`distill`.

---

## Correções

### Durabilidade (raft)

- **WAL raft: corrupção a meio do ficheiro deixou de truncar em silêncio.**
  *(DUPLO-CONFIRMADO, high)* Qualquer falha de decode no replay era tratada
  como cauda torn ⇒ `set_len` descartava PERMANENTEMENTE todas as entradas
  raft comprometidas a seguir ao ponto corrupto (e marcadores Truncate/Purge),
  sem erro nenhum. Agora as três classes são distinguidas: registo declarado
  além do EOF = cauda torn genuína (trunca, como antes); payload completo que
  não decodifica = corrupção ⇒ **recusa arrancar** preservando o ficheiro
  (mesma política fail-loud do `meta.bin`); erro de I/O = propagado. A alocação
  do replay ficou limitada pelos bytes restantes do ficheiro (um prefixo de
  comprimento corrompido não pode pedir GiBs). Teste:
  `midfile_corruption_fails_loud_instead_of_truncating`. *(commit `da27952`)*

### Escrita concorrente / índices derivados

- **`index_applied` fora de ordem: AttrIndex descartava eventos.** *(high)*
  Dois appends concorrentes podem indexar fora de ordem (o log atribui o LSN;
  a indexação corre sem guarda de ordem). O guard antigo do índice de
  atributos (`lsn <= watermark → return`) **descartava o evento atrasado para
  sempre** — um buraco silencioso que nem o replay pós-restart curava (o
  watermark persistido já dizia o LSN maior). Agora: inserção ordenada com
  dedup por `binary_search` — idempotente E tolerante a fora-de-ordem, formato
  de checkpoint inalterado. Teste: `out_of_order_apply_indexes_both_events`.
  *(commit `da27952`)*
- **Watermarks avanço-só (registry + text).** Um insert cru regredia o
  watermark quando o LSN menor aplicava por último; um checkpoint nesse estado
  fazia o restart re-replayar eventos já aplicados (duplicação em views
  não-idempotentes, ex.: energia de ativação). Agora `max()` — "tudo ≤ wm foi
  aplicado" volta a ser verdade. *(commit `da27952`)*

### Segurança de superfície

- **Paridade do guard loopback-ou-auth: gRPC e Flight.** *(high)* O guard só
  existia no REST. O gRPC (escritas duráveis + admin `shred`/`rebuild`) servia
  com interceptor no-op sem `auth_token`; o Arrow Flight serve o **log
  inteiro** via `DoGet` e não tem mecanismo de auth nenhum. Ambos agora
  recusam bind não-loopback sem auth. *(commit `adf0867`)*
- **`/sql` read-only IMPOSTO.** *(high)* O endpoint corria numa
  `SessionContext` crua — `CREATE EXTERNAL TABLE ... LOCATION '/…'` lia
  ficheiros arbitrários do servidor através de um endpoint "read-only". Agora
  `sql_with_options` com DDL/DML/statements proibidos. Teste:
  `sql_refuses_ddl_dml_and_statements`. *(commit `adf0867`)*
- **Chaves de crypto: TOCTOU no primeiro uso.** *(medium)* Dois threads em
  corrida geravam chaves DIFERENTES e ambos faziam rename para o mesmo destino
  — o último ganhava o disco, cada um cacheava a sua ⇒ dados selados com a
  chave perdedora ficavam **ilegíveis após restart**. Árbitro `create_new` no
  caminho final: exatamente um criador; perdedores leem a chave do vencedor.
  *(commit `7c3ec13`)*
- **WASM: teto de memória.** *(medium)* Fuel limita CPU mas não RAM — um
  módulo válido podia esgotar a memória do host na instanciação.
  `StoreLimits`: 64 MiB de memória linear, tabelas/instâncias limitadas.
  *(commit `7c3ec13`)*

### Reactor / streaming

- **`subscribe` (gRPC) bloqueava o reactor.** *(high)* O catch-up de histórico
  corria `log.scan` (bloqueante: abre e lê ficheiros de segmento) direto no
  `tokio::spawn` — um subscritor a recuperar de um LSN baixo num log grande
  fazia milhares de leituras de disco nos worker threads do reactor. Agora
  cada chunk corre em `spawn_blocking` (+ `saturating_add` no avanço). A ponte
  história→tail sem lacunas mantém-se. *(commit `f5d4a3c`)*

### Determinismo / NaN

- **Empates determinísticos em BM25, memtable e activation.** *(medium)*
  `search` (BM25), `merge_hits` (memtable) e `top_k` (activation) desempatavam
  pela ordem de iteração do HashMap/DashMap (seed SipHash) — o conjunto top-k
  variava entre execuções. Desempate por LSN/EventId, mesma política do
  `rrf_fuse` da v1.0.1. *(commit `adf0867`)*
- **`dist_hyp`: NaN dava distância ZERO.** *(medium)* `NaN.max(1.0) == 1.0` em
  Rust ⇒ `acosh(1) = 0` — um embedding corrompido ficava a distância zero de
  TUDO (vizinho mais próximo universal). Não-finito agora devolve `+INF`.
  *(commit `adf0867`)*
- **Activation: cauda Petrov com `d == 1.0`.** *(medium)* Dava `0/0 = NaN`,
  mascarado a `0` pelo `max(0.0)` — itens longevos perdiam a cauda inteira em
  silêncio. O limite `d→1` é logarítmico: `ln(l) − ln(h)`. *(commit `adf0867`)*

### Recall / robustez de leitura

- **Recall: candidatos só-ativação sem conteúdo.** *(medium)* Chegavam com
  `lsn=0` (o canal não transporta LSN); a hidratação lia o LSN 0, falhava o
  filtro de id e a linha saía sem conteúdo. O LSN real resolve-se agora via
  `GraphIndex::lsn_of`. *(commit `7c3ec13`)*
- **HNSW: validação de invariantes do checkpoint no load.** *(low)* Um
  checkpoint decodável mas violado (nó com `neighbors` vazio, entry fora de
  alcance, comprimentos incoerentes) panicava toda pesquisa futura
  (`neighbors[..len()-1]` com vec vazio). Agora degrada para rebuild do log
  (invariante I6) — nunca um índice que panica. *(commit `0c8fbf1`)*
- **Bᵋ-tree: bounds no deserialize.** *(low)* `data[pos]` sem bounds-check
  (panic) e `with_capacity` de um u32 cru do disco (pré-alocação gigante);
  ambos limitados pelos bytes restantes da página. *(commit `7c3ec13`)*
- **CLI: `bench_recall --n 0`.** *(low)* Resto-por-zero; clamp a 1.
  *(commit `7c3ec13`)*

---

## Refutados na auditoria (não são bugs — evidência em §6.4)

- Evicção por contagem do memtable "antes das views indexarem" — as views
  aplicam SINCRONAMENTE no `index_applied`; invariante agora documentado no
  local para proteger um futuro refactor async.
- `sync_all`/`sync_data` ignorados no log/durable — caminhos de rollback e
  best-effort de diretório; o fsync real propaga erro antes do ack.
- `layers.len()-1` no HNSW do query backend — o grow-loop acima garante
  não-vazio.

## Limitações conhecidas (adiadas por design, documentadas)

- Transporte raft sem autenticação de pares (decisão: LAN fechada; mTLS/token
  quando houver deployment fora dela).
- RPCs raft sem timeout de connect/read (openraft tolera; honrar o ttl é
  otimização de recursos).
- Janela residual de checkpoint fora-de-ordem (fecho total exigiria serializar
  append+index ou um sequenciador; o custo em throughput não se justifica hoje).

---

**Instalação/upgrade:** substituir o binário; formatos de log, checkpoint e
WAL inalterados. Nós de cluster podem fazer rolling upgrade — mas note que um
nó v1.0.2 com WAL corrompido a meio agora RECUSA arrancar (antes arrancava
"com sucesso" tendo perdido entradas): é o comportamento correto; apagar o
diretório raft do nó e deixá-lo re-replicar dos pares.
