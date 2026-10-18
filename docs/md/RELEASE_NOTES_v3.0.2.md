# HeraclitusDB v3.0.2 — Integridade de grafos, consultas e snapshots

**Data:** 2026-10-16  
**Linha:** 3.x

Esta versão corrige os sete achados G1–G7 da auditoria de 16/10/2026.

## Correções

- **G1:** relações usam uma identidade `e2` com comprimentos dos componentes em bytes. Delimitadores e Unicode deixam de provocar colisões de topologia, hipóteses e retrações.
- **G2:** cada período transacional de uma relação conserva sua própria validade do mundo. `MATCH ... VALID AT ... AS OF ...` e os LSNs de `NEIGHBORS` consultam o mesmo período histórico.
- **G3:** fingerprint temporal v2 inclui validade do mundo atual e arquivada, política, hipóteses, mapeamentos e métricas; strings, coleções e `Option` têm codificação delimitada.
- **G4:** comparações e ordenação GQL preservam inteiros nativos e literais grandes. HLCs adjacentes, limites de `u64`, `ASC`/`DESC` e `LIMIT` deixam de ser confundidos pela conversão para `f64`. Ranges sem representação exata recuam para scan.
- **G5:** igualdades com espaços externos recuam para o scan canônico. O índice continua sendo uma otimização; o resultado mantém a semântica exata do valor gravado.
- **G6:** `_agent` e `_kind` são reservados na ingestão pública e ignorados como atributos do cliente durante replay. Relatórios por titular revalidam o `agent_id` canônico dos postings.
- **G7:** tombstones vetoriais registram o LSN da primeira retirada. HNSW, busca exata e candidatos da memtable usam a mesma regra temporal: em `AS OF LSN b`, a retirada só se aplica quando `tombstone_lsn < b`.

## Atualização e compatibilidade

- O log canônico não muda. Os checkpoints derivados de atributos anteriores a v7, do grafo anteriores a `HTGR0002` e vetoriais sem a versão temporal 2 são recusados e reconstruídos por replay automático. O primeiro arranque pode demorar mais.
- IDs de relações e fingerprints temporais mudam de versão. Consumidores que guardam esses IDs devem voltar a consultá-los a partir da tupla origem/destino/tipo. Não compare fingerprints das duas versões como se usassem o mesmo schema.
- O tipo Rust `Edge.closed_intervals` passa a conter `EdgeInterval`, com transaction time e valid time. O AST adiciona a variante `Int` para literais exatos; consumidores Rust com matches exaustivos precisam tratar a variante.
- A API `tombstone_event` mantém a retirada imediata; ingestão temporal usa `tombstone_event_at`. Buscas históricas estão disponíveis por `search_as_of` e `search_exact_as_of`.

## Validação

Os testes de regressão ficam em `crates/heraclitus-{index-graph,query,server}/tests/regressao_gpt_2026_10_16.rs`, com gates adicionais nos índices de atributos e vetores e no comparador GQL. Cobrem reprodução anterior, delimitadores/Unicode, snapshots fixos após novas escritas, checkpoint/replay/reinício, igualdade indexada versus scan e inteiros adjacentes até `u64::MAX`.

Os resultados executados e os limites de plataforma serão registrados no relatório de validação desta versão. A publicação de código-fonte não substitui a qualificação dos binários produzidos pelo workflow de release.
