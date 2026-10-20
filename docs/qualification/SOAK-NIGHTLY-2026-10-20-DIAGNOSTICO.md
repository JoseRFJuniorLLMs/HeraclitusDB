# Soak nightly de 20/10/2026 — diagnóstico

Run: https://github.com/JoseRFJuniorLLMs/HeraclitusDB/actions/runs/39393746314
(perfil `soak-nightly`, 900 s, carga `mixed`, 8 workers, commit da v3.0.3).

**Resultado:** reprovado nos gates de RSS, threads e deriva do p99, com zero
erros de operação e `verify` íntegro no fim. A causa do p99 é custo O(n) em
duas consultas da carga (mais uma terceira que cresce menos), e não um
vazamento. A hipótese saiu da leitura do código e foi **confirmada por medição
por operação** no nightly da branch do PR #34 (secção seguinte).

## Confirmação: nightly da branch, commit `1ce650d`

Run: https://github.com/JoseRFJuniorLLMs/HeraclitusDB/actions/runs/39508445278
(mesmo perfil e semente). Crash-loop do binário aprovado: 40 ciclos, 283 747
appends confirmados, nenhum em falta. Soak reprovado outra vez (p99 13,16×),
agora com a latência separada por operação:

| Operação | p50 / p99 com 9,6 mil eventos | p50 / p99 com 81,8 mil eventos |
|---|---|---|
| `attribute_query` (`agent_id`) | 23 / 67 ms | 557 / 791 ms |
| `vector_retrieval` (`DIST_HYP`) | 28 / 87 ms | 855 / 1 137 ms |
| `text_retrieval` (`recall`) | 13 / 39 ms | 136 / 230 ms |
| `ingest` | 3 / 21 ms | 3 / 149 ms |
| `as_of_analytics` | 21 / 46 ms | 51 / 80 ms |
| `graph_traversal` | 0 / 5 ms | 0 / 5 ms |

- `attribute_query` e `vector_retrieval` crescem em linha reta com o `head`:
  O(n) confirmado.
- `text_retrieval` cresce cerca de 10× e abranda depois dos 50 mil eventos.
- O p50 da ingestão fica plano; o p99 sobe até ~150 ms e estabiliza. A
  explicação provável, não medida, é competição de CPU no runner com as
  consultas que descodificam o log inteiro.
- `memory_per_event`: ~5,1 KB de RSS por evento gravado, e ~5,0 KB na segunda
  metade. A memória é proporcional aos dados, não ao tempo.
- Threads: 17 → 18 uma única vez, aos ~645 s, de novo na segunda metade.

## O que as séries mostram

| Série | Observado | Leitura |
|---|---|---|
| Vazão por janela de 15 s | 12 684 → ~2 200 operações | Os 8 workers ficam presos nas consultas lentas. |
| p50 | ~6–14 ms, sem tendência | A maioria das operações (ingestão, 70%) não degrada. |
| p95 / p99 | 28 → ~250 ms / 48 → ~570 ms | Sobe em linha com o `head` (9 k → 101 k eventos). |
| RSS | 230 MB → 675 MB | Acompanha o `head`; abranda na segunda metade (~1,7 KB/evento entre 600 e 900 s). |
| Threads | 16 → 17, uma vez, aos 570 s | Um único degrau. |
| Handles | 17–24, sem tendência | — |

## Causas identificadas no código

A carga `mixed` (`tools/heraclitus-qualifier/src/load.rs`) é 70% ingestão,
10% atributo, 5% texto, 5% vetor, 5% grafo e 5% AS OF.

1. **Atributo (10%)** — `MATCH (n) WHERE n.agent_id = "x" LIMIT 10`.
   `agent_id` é builtin e fica fora do índice de atributos. O plano usa
   `scan_builtin_eq` (`crates/heraclitus-query/src/plan.rs:1461`), que só
   salta segmentos cujo zone map não contém o valor. Com 4 096 agentes
   espalhados por todos os segmentos nada é saltado. Além disso, o `LIMIT` não
   chega a este caminho: o scan devolve todas as linhas do agente.
2. **Vetor (5%)** — `MATCH (n) RETURN n ORDER BY DIST_HYP([...]) ASC LIMIT 10`.
   Não passa pelo HNSW. O planeador trata-o como top-k exato sobre a janela
   inteira (`plan.rs:1506`), lendo e descodificando todos os eventos do log a
   cada consulta. O caminho com índice é o `Plan::Nearest`.
3. **Texto (5%)** — `recall`. O BM25 usa Block-Max WAND e pode saltar blocos,
   por isso não o dou como O(n). Mas o mesmo recall chama
   `ActivationStore::top_k` (`crates/heraclitus-server/src/engine.rs:3536`),
   que percorre e pontua todos os registos (`crates/heraclitus-activation/src/lib.rs:174`);
   a view de ativação cria um registo por evento ingerido (`lib.rs:329`).

Com pelo menos 20% das operações em O(n), o p95 e o p99 passam a medir o
tamanho da base, e o p50 (ingestão) fica plano. É exatamente a forma das séries.

## Memória

O RSS cresce com os dados que o próprio soak grava: 101 mil eventos em 15
minutos, com índices vetorial, de texto, de grafo, de atributos e de ativação
residentes em memória. É a pendência arquitetural já registada ("teto global,
evicção e spill dos índices"). O orçamento do perfil está em bytes por hora;
numa carga que só acrescenta dados, nenhum desenho com índices em memória
cumpre um orçamento por hora sem limitar o volume. Isto não prova que não haja
vazamento: prova que o gate atual não o consegue distinguir de crescimento
proporcional aos dados.

## Threads

O gate tem uma "regra do degrau": só reprova se a segunda metade da janela
estabilizada também crescer. A janela foi 180–900 s, com ponto médio aos 540 s
(`tools/heraclitus-qualifier/src/soak.rs:281`), e o único degrau caiu aos
570 s, dentro da segunda metade. Numa janela de 12 minutos, um thread a mais
dá 4,24/h contra um orçamento de 4/h. É um thread do runtime, não uma série a
crescer; o gate é que é sensível demais para esta duração.

## O que mudou neste commit

Só diagnóstico; nenhum limite nem veredito foi alterado.

- `latency_by_operation`: p50/p95/p99 por tipo de operação em cada janela,
  alinhados com `latency_windows`, e a razão de deriva do p99 por operação.
- `memory_per_event`: inclinação do RSS contra o `head` (bytes por evento
  gravado), na janela estabilizada e na segunda metade.

O nightly da branch já usou estes campos (secção "Confirmação").

## Decisões que ficam para o responsável

Não alterei nada disto, porque muda o que o gate mede ou o desenho do motor:

1. **Pista vetorial do qualifier**: medir o HNSW (`NEAREST`) em vez do top-k
   exato por scan, ou manter o scan e aceitar que ele é O(n).
2. **`agent_id` sem índice**: índice dedicado para builtins ou `LIMIT`
   empurrado para `scan_builtin_eq`.
3. **`ActivationStore::top_k`**: estrutura ordenada em vez de varrer tudo.
4. **Gate de memória**: complementar bytes/hora com bytes por evento retido,
   ou limitar o volume da carga de soak.
5. **Gate de threads**: exigir mais de um degrau, ou uma janela mais longa no
   perfil nightly.
