# SPEC-0042 — Marco 0: resultado do benchmark HUME vs DataFusion

**Estado:** MEDIDO. Recomendação: **aplicar a §25 (rejeição) — não construir o `HybridExecRouter`.**
**Data:** 2026-08-16 · **Máquina:** Windows 11, 31,5 GB RAM
**Fonte bruta:** `SPEC-0042-marco0-hume_vs_datafusion.txt`
**Benchmark:** `crates/heraclitus-analytics/benches/hume_vs_datafusion.rs`

A §22 Marco 0 pede *"números, não wiring"*, e a §27 autoriza **somente H1** (cadeia
de filtros, sem agregação). É isso que foi medido: 100 células, todas H1.

---

## 1. Mapa de roteamento (§17.3)

`(classe, linhas, seletividade, predicados) → backend vencedor`

| Linhas | Seletividade | Predicados | Vencedor | speedup HUME |
|---|---|---|---|---|
| 10 000 | 50% … 0,1% | 1, 2, 4, 8 | **HUME** | 1,70× – 9,71× |
| 100 000 | 50% … 0,1% | 1, 2, 4, 8 | **DataFusion** | 0,08× – 0,63× |
| 1 000 000 | 50% … 0,1% | 1, 2, 4, 8 | **DataFusion** | 0,14× – 0,75× |

**40 de 100 células cumprem o Gate B — e são todas de 10 000 linhas.**
Zero divergências semânticas em 100 células (Gate C cumprido).

O eixo `largura` (estreita 64 B / média 256 B) foi medido a 10k e 100k e **não
move o veredicto**: na projeção justa de H1 nenhum dos motores lê a coluna
`content`. Por isso 1M correu só na largura estreita — repetir custava ~1,5 h de
geração de dados para reproduzir a mesma tabela.

---

## 2. Porque é que o HUME "ganha" a 10k

O `exec` do DataFusion é praticamente **plano**:

| Linhas | DataFusion p50 |
|---|---|
| 10 000 | ~90 – 230 µs |
| 100 000 | ~143 – 190 µs |
| 1 000 000 | ~578 – 830 µs |

De 10k para 100k — dez vezes mais dados — o tempo **não sobe**. Isso é um piso de
custo fixo por consulta (setup de streams, repartition, arranque do plano
físico), não trabalho proporcional aos dados.

Logo, a 10k linhas o benchmark não está a comparar dois executores: está a
comparar o custo fixo de um motor SQL contra uma chamada de função direta. O
HUME ganha por não ser um motor SQL, não por executar mais depressa. Assim que o
custo fixo amortiza (100k), perde em **todas** as células.

Em valor absoluto, a vitória a 10k vale ~100 µs por consulta. A §9 fixa o limiar
de promoção em 1,20× precisamente como guarda de complexidade: *"um segundo
backend possui custo operacional próprio"*. 100 µs não pagam essa conta.

---

## 3. Duas hipóteses da spec contrariadas pelos dados

### 3.1 `HUME_MIN_ROWS` está invertido

A §7 exige `estimated_input_rows >= HUME_MIN_ROWS` — uma cardinalidade **mínima**
para amortizar o dispatch. Os dados mostram o contrário: o HUME precisa de um
**máximo**. A regra de roteamento de H1 inverte-se, e o Gate D (§16) passaria a
ter de bloquear o HUME acima de ~50k linhas, não abaixo.

### 3.2 Alta seletividade não favorece o HUME

A §7 e a §13 assumem que a materialização tardia compensa em consultas muito
seletivas (`ADAPTIVE_FUSE_THRESHOLD = 0.05`). A 1M linhas com 1 predicado:

| Seletividade | speedup HUME |
|---|---|
| 50% | 0,70× |
| 0,1% | 0,53× |

É **ligeiramente pior** onde devia ser melhor. O crossover que a §22 manda
registar não existe neste eixo.

### 3.3 O eixo dos predicados: onde o HUME sangra

A 1M linhas, 50% de seletividade, ao passar de 1 para 8 predicados:

| Motor | 1 pred | 8 preds |
|---|---|---|
| HUME | 895 µs | **5,42 ms** |
| DataFusion | 625 µs | 758 µs |

O caminho eager do `VecExecutor` materializa as linhas sobreviventes **a cada
filtro** — N filtros, N cópias.

**Ressalva honesta, e não pequena:** o simplificador do DataFusion funde os
predicados redundantes (o benchmark imprime o plano otimizado como prova: 8
predicados colapsam em 2 condições), enquanto o HUME avalia os 8. Parte desta
diferença é esse confounder, não mérito do DataFusion.

**Mas o veredicto não depende disso:** a `preds=1`, onde não há fusão nenhuma, o
DataFusion continua a ganhar 1,4× – 2,4× a 100k e 1M.

---

## 4. Recomendação

Aplicar a **§25 — critérios explícitos de rejeição**, que prevê exatamente este
desfecho: *"HUME não supera DataFusion por margem suficiente em H1"* e *"o
benefício ocorre apenas em microbenchmarks artificiais não representativos da
carga real"*.

- **Não** avançar para o Marco 1 (`HybridExecRouter`).
- **Não** escrever o lowering de H1 (Marco 2).
- O `SelectionVector`, o `MorselSizer`, o `hume-ir` e o JIT continuam válidos
  como I&D e como candidatos aos pipelines multimodais **H4**, onde a vantagem
  arquitetural é outra (evitar materializações sucessivas entre operadores
  heterogéneos) e ainda não foi medida.

Como a própria §25 conclui: *"A arquitetura não exige promover HUME por orgulho
de autoria."*

---

## 5. O que este benchmark corrigiu antes de produzir número

Registado porque cada um destes erros produzia um número confiante e falso:

1. **Media a classe errada.** A primeira versão media `Filter* → GROUP BY → SUM`
   — a classe H2, que a §22 adia para o Marco 6. O `run_aggregate` do HUME aloca
   um `Vec<String>` por linha sobrevivente, portanto o eixo da seletividade
   media o agregador, não o filtro.
2. **Predicados sempre-falsos.** `Log::append` **carimba** o `ts_hlc` por cima do
   valor posto no `Episode`. Os predicados extra `ts_hlc < n+k`, desenhados para
   serem sempre verdadeiros, ficaram sempre falsos: todas as células com 2+
   predicados devolviam **zero linhas**, e os "speedups" de 7× a 30× eram dois
   motores a competir para não devolver nada. O digest dizia `igual` porque
   **ambos** acertavam em vazio. Comparar resultados nunca apanha um predicado
   errado de forma idêntica nos dois lados — daí a guarda de cardinalidade.
3. **Planeamento dentro do cronómetro.** `DataFrame::collect()` faz planeamento
   físico; o HUME recebia o DAG pronto. Corrigido com `create_physical_plan`
   fora do timer, dos dois lados.
4. **Projeção injusta.** O DataFusion arrastava a coluna `content` e calculava
   `octet_length` por linha, enquanto o HUME tinha `content_len` pré-computado
   na materialização. Corrigido: a projeção são as 4 colunas nativas de ambos.

---

## 6. Achado incidental — o append do log é O(n²) por segmento

Fora do âmbito da SPEC-0042, mas medido pela instrumentação de geração de dados:

| Linhas | appends/s |
|---|---|
| 10 000 | 48 738 |
| 100 000 | 1 915 |
| 1 000 000 | **191** |

Dez vezes mais linhas, cem vezes mais tempo. Causa em
`crates/heraclitus-log/src/lib.rs:945`: cada append reconstrói o índice ativo por
cópia integral (`extend_from_slice` de todas as entradas existentes, mais a
nova). `LsnEntry` são 32 B; a 1M entradas são **32 MB copiados por append**.

**Atenuantes:**
- O índice reinicia quando o segmento sela, logo o custo é
  O(registos_por_segmento²), não do log inteiro. Mas o default
  `segment_max_bytes = 256 MB` (~2M registos) é **pior** do que o que foi medido.
- O worker drena comandos em lote: um escritor **síncrono single-thread é o pior
  caso**, e é exatamente o que este benchmark faz. Escritores concorrentes
  amortizam a cópia entre si.

Merece medição dedicada — com escritores concorrentes e vários
`segment_max_bytes` — antes de qualquer carga real de ingestão de logs.
