# Memória dos índices por evento — 21/10/2026

O soak nightly de 20/10/2026 mediu ~5 KiB de RSS por evento gravado, estável
(ver `SOAK-NIGHTLY-2026-10-20-DIAGNOSTICO.md`). Para pôr um teto à memória é
preciso saber quem a gasta. A medição está em
`crates/heraclitus-server/tests/memoria_por_indice.rs`: cada índice isolado,
sem `Engine` nem servidor, recebe 20 mil episódios iguais aos da carga `mixed`
do soak (incluindo a chave e o hash de idempotência que o `Engine` acrescenta),
e um `GlobalAlloc` contador mede os bytes vivos. Não inclui a fragmentação nem
a sobrecarga do alocador, que o RSS inclui.

```
cargo test -p heraclitus-server --test memoria_por_indice -- --ignored --nocapture
```

## Resultado

| Índice | Antes | Depois desta etapa | O que gasta |
|---|---|---|---|
| memtable (até ao `memtable_cap`) | 1 516 | 1 516 | o episódio inteiro; limitada a 100 mil entradas |
| texto (BM25) | 866 | 866 | termos únicos por evento (número de sequência, marcador hex) e postings |
| vetorial (HNSW) | 461 | 461 | ponto, normas preparadas, vizinhos do nível 0 |
| ativação | 185 | 249 | registo ACT-R; +64 B do índice ordenado do `top_k` (PR #36) |
| atributos | 446 | 236 | o hash de idempotência (64 hex únicos) deixou de ser indexado |
| grafo | 724 | 149 | o `attr_idx` deixou de indexar os atributos internos `__heraclitus_*` |
| grafo temporal, entidades, telemetria | 0 | 0 | — |
| **total** | **4 198** | **3 476** | |

Sem a memtable, que é limitada, a parte que cresce com os dados passou de
2 682 para 1 960 B por evento (−27%).

## Porque é que estas duas mudanças não alteram respostas

- O `attr_idx` do grafo só é lido pelo `filter_eq`, que nenhum caminho de
  produção usa; entra no checkpoint e no `state_hash`. Os atributos internos
  (chave e hash de idempotência, marca de shred) são escritos pelo motor e não
  são filtráveis por clientes. O `restore` descarta-os de checkpoints antigos,
  para o estado restaurado ser igual ao de um rebuild.
- O hash de idempotência é lido do próprio episódio, depois de a chave dar o
  LSN; nunca é procurado por valor. Uma consulta por esse campo passa a varrer
  o log (o índice diz que não o conhece). O índice de atributos sobe para v9,
  para não ficarem postings parciais desse campo.

## Etapas seguintes do teto de memória

1. **Contabilidade e orçamento global**: cada índice reporta os seus bytes
   residentes; o `Engine` soma, publica a métrica por índice e aplica um
   `index_memory_budget_bytes` configurável, com um estado explícito quando é
   ultrapassado.
2. **Memtable por bytes**: além do número de entradas, um teto em bytes.
   Muda o canal da memtable no ranking do `recall` quando o teto corta antes
   do `cap`; precisa de decisão.
3. **Texto em disco**: postings selados em segmentos imutáveis (por geração do
   log), com só o dicionário e a cauda recente em memória.
4. **Vetorial**: pontos em arena plana (sem três `Vec` por nó) e, para o
   despejo, vizinhos do HNSW em disco com cache.
