Fiz a auditoria recursiva do `main` atual do `JoseRFJuniorLLMs/crates`, cruzando os algoritmos entre os crates, e a conclusão é mais interessante do que simplesmente “coloque SIMD em tudo”.

O HeraclitusDB tem **quatro gargalos diferentes que se alimentam mutuamente**:

1. **custo matemático**, principalmente HNSW + manifold + analytics;
2. **representação física**, principalmente `String`, `HashMap`, `BTreeMap`, `Vec` e estruturas orientadas a objetos;
3. **índices residentes**, que hoje são o maior problema de escala;
4. **movimentação de dados**, especialmente CPU↔GPU, disco↔RAM e materializações intermediárias.

A sua própria auditoria de 20 milhões já mostrou o ponto mais brutal: o log ficou perto de **35 B/evento**, enquanto o Engine completo com views chegou a aproximadamente **2,02 KB/evento**, cerca de **57× mais memória por evento**. Portanto, o maior salto não virá de uma `sqrt()` 20% mais rápida. Virá de transformar índices derivados em estruturas compactas, densas, comprimidas e parcialmente disk-backed.

## Resultado da auditoria

Eu dividiria o trabalho em **52 famílias algorítmicas**.

|  # | Área / algoritmo atual | Mudança recomendada                              | CPU | RAM | Compactação | Prioridade |
| -: | ---------------------- | ------------------------------------------------ | :-: | :-: | :---------: | :--------: |
|  1 | Product Manifold       | `PreparedQuery`                                  | ★★★ |  ★  |      –      |   **P0**   |
|  2 | Product Manifold       | `PreparedPoint` com normas pré-calculadas        | ★★★ |  ★  |      –      |   **P0**   |
|  3 | Product Manifold       | ranking por distância², sem `sqrt` final         |  ★★ |  –  |      –      |   **P0**   |
|  4 | dot/L2/norm            | AVX2/FMA, AVX-512, NEON                          | ★★★ |  –  |      –      |   **P0**   |
|  5 | métrica batch          | kernel SoA em lote                               | ★★★ |  ★★ |      –      |   **P0**   |
|  6 | HNSW `visited`         | `HashSet<u32>` → epoch/stamp array               | ★★★ |  ★★ |      –      |   **P0**   |
|  7 | HNSW níveis >0         | `search_layer(ef=1)` → greedy descent            | ★★★ |  ★  |      –      |   **P0**   |
|  8 | HNSW Top-K             | sort/heaps genéricos → seleção especializada     | ★★★ |  ★  |      –      |   **P0**   |
|  9 | HNSW vetores           | AoS `ProductPoint` → SoA contiguous              | ★★★ | ★★★ |      ★      |   **P0**   |
| 10 | HNSW neighbors         | `Vec<Vec<u32>>` → adjacency slab/CSR             | ★★★ | ★★★ |      ★★     |   **P0**   |
| 11 | HNSW insert            | eliminar clones de `ProductPoint`                |  ★★ |  ★★ |      –      |   **P0**   |
| 12 | HNSW recall            | `ef` adaptativo por seletividade                 |  ★★ |  –  |      –      |     P1     |
| 13 | embeddings             | SQ8 para geração de candidatos                   | ★★★ | ★★★ |     ★★★     |     P1     |
| 14 | embeddings grandes     | PQ                                               | ★★★ | ★★★ |     ★★★     |     P1     |
| 15 | embeddings grandes     | OPQ + PQ                                         | ★★★ | ★★★ |     ★★★     |     P1     |
| 16 | GPU vectors            | coleção residente na VRAM                        | ★★★ |  ★  |      –      |   **P0**   |
| 17 | GPU buffers            | pool persistente                                 | ★★★ |  ★★ |      –      |   **P0**   |
| 18 | GPU ranking            | Top-M na própria GPU                             | ★★★ |  ★★ |      –      |   **P0**   |
| 19 | GPU queries            | batching de Q1...Qn                              | ★★★ |  –  |      –      |     P1     |
| 20 | BM25                   | Block-Max WAND/BMW                               | ★★★ |  –  |      –      |   **P0**   |
| 21 | BM25                   | MaxScore                                         | ★★★ |  –  |      –      |     P1     |
| 22 | postings texto         | delta + SIMD-BP128/FOR                           | ★★★ | ★★★ |     ★★★     |   **P0**   |
| 23 | postings texto         | `term String` → TermId/FST/dictionary            |  ★★ | ★★★ |     ★★★     |   **P0**   |
| 24 | BM25 scores            | `HashMap<doc,f32>` → dense accumulator + epoch   | ★★★ |  ★★ |      –      |   **P0**   |
| 25 | BM25 Top-K             | heap/partial selection                           |  ★★ |  ★  |      –      |   **P0**   |
| 26 | BM25                   | pré-calcular IDF e normalização de `doc_len`     |  ★★ |  ★  |      –      |     P1     |
| 27 | AttrIndex              | `"field␟value"` → IDs compostos                  | ★★★ | ★★★ |     ★★★     |   **P0**   |
| 28 | Attr postings          | Elias-Fano / Delta-BP128                         |  ★★ | ★★★ |     ★★★     |   **P0**   |
| 29 | Attr postings densos   | Roaring containers                               | ★★★ | ★★★ |     ★★★     |   **P0**   |
| 30 | range index            | BTreeMap → disk-backed B+tree/PMA conforme carga |  ★★ | ★★★ |      ★★     |   **P0**   |
| 31 | SelectionVector        | cachear cardinalidade                            |  ★★ |  –  |      –      |     P1     |
| 32 | SelectionVector        | galloping intersection                           | ★★★ |  ★  |      –      |     P1     |
| 33 | SelectionVector        | bitmap×index sem converter representação         | ★★★ |  ★★ |      –      |     P1     |
| 34 | SelectionVector        | containers tipo Roaring por chunk                | ★★★ | ★★★ |     ★★★     |     P1     |
| 35 | graph                  | `String` IDs → dense `u32`                       | ★★★ | ★★★ |     ★★★     |   **P0**   |
| 36 | graph adjacency        | BTreeMap → CSR/CSC + delta overlay               | ★★★ | ★★★ |     ★★★     |   **P0**   |
| 37 | BFS                    | frontier bitset/direction-optimizing BFS         | ★★★ |  ★★ |      –      |     P1     |
| 38 | path search            | bidirectional BFS                                | ★★★ |  ★  |      –      |     P1     |
| 39 | belief                 | cache do log-odds head                           | ★★★ |  ★  |      –      |   **P0**   |
| 40 | belief temporal        | prefix sums + binary search LSN                  | ★★★ |  ★  |      –      |   **P0**   |
| 41 | Leiden                 | grafo CSR persistente + incremental rebuild      | ★★★ | ★★★ |      –      |     P1     |
| 42 | Distill                | centroid incremental                             | ★★★ | ★★★ |      –      |   **P0**   |
| 43 | Distill                | ANN sobre centroides                             | ★★★ |  ★  |      –      |     P1     |
| 44 | Activation             | ring buffer em vez de `remove(0)`                |  ★★ |  ★  |      –      |     P1     |
| 45 | Activation             | `d=0.5` → `1/sqrt(age)`                          | ★★★ |  –  |      –      |     P1     |
| 46 | Activation             | Top-K parcial                                    | ★★★ |  ★  |      –      |   **P0**   |
| 47 | HLL                    | LUT `2^-r`                                       | ★★★ |  –  |      –      |     P1     |
| 48 | HLL                    | registradores 6-bit/sparse HLL++                 |  ★★ | ★★★ |     ★★★     |     P1     |
| 49 | Count-Min              | largura potência de 2 + máscara                  |  ★★ |  –  |      –      |     P1     |
| 50 | Count-Min              | Conservative Update/contadores compactos         |  ★★ | ★★★ |     ★★★     |     P1     |
| 51 | Adaptive F1            | O(n²) → sweep O(n log n)                         | ★★★ |  ★  |      –      |   **P0**   |
| 52 | Query planner          | CBO real cruzando todos esses índices            | ★★★ | ★★★ |     ★★★     |   **P0**   |

Esses itens não são hipotéticos jogados ao acaso. Por exemplo, o HNSW atual ainda trabalha com estruturas e caminhos que justificam diretamente `PreparedQuery`, visited denso, greedy descent e armazenamento vetorial contíguo.  A geometria do produto repete normas, raízes e funções transcendentais suficientes para tornar essa preparação especialmente valiosa.

---

# 1. O maior alvo matemático: HNSW + Product Manifold

Aqui está, para mim, o **hotspot algorítmico nº 1 de consulta**.

Hoje uma distância pode envolver:

```text
Poincaré
 ├─ norm(q)
 ├─ norm(x)
 ├─ clamp
 ├─ diff²
 ├─ divisão
 └─ acosh

Sphere
 ├─ norm(q)
 ├─ norm(x)
 ├─ dot
 └─ acos

Euclidean
 ├─ diff²
 └─ sqrt

Product
 └─ sqrt(wH*dH² + wS*dS² + wE*dE²)
```

Agora multiplique isso por centenas ou milhares de candidatos visitados pelo HNSW. A CPU começa a considerar a aposentadoria.

A transformação correta seria:

```text
QUERY
   │
   ▼
PreparedQuery
 norm_h
 scale_h
 norm_s
 inv_norm_s
 constants curvature
   │
   ▼
HNSW
   │
   ├── SQ8/PQ approximate metric
   │
   └── SIMD prepared metric
           │
           ▼
       Top-M
           │
           ▼
   EXACT f64 RESCORE
```

O mais importante: **não substituir a matemática canônica**.

O `ProductMetric::dist()` continua sendo oracle. As versões SQ8/PQ/f32/SIMD servem para eliminar candidatos.

Isso preserva uma propriedade excelente do Heraclitus: velocidade não precisa contaminar a reprodutibilidade.

A sua `SPEC-0043` já percebeu exatamente essa arquitetura: `PreparedQuery`, `PreparedPoint`, distância², SIMD, visited epoch, greedy `ef=1`, SoA, SQ8, PQ e rescore exato já estão especificados.

### Mas eu acrescentaria uma coisa à SPEC-0043

**Adjacency HNSW compacta.**

Não deixaria:

```rust
Vec<Vec<u32>>
```

como representação final para milhões de nós.

Faria algo semelhante a:

```text
level_offsets[]
node_offsets[]
neighbors[]
```

com IDs delta-coded dentro de cada adjacency quando isso for vantajoso.

É menos pointer chasing, menos heap allocations e muito melhor para prefetch.

---

# 2. O maior alvo de RAM: índice de texto

Aqui está provavelmente o **alvo nº 1 de memória depois dos embeddings**.

O índice atual mantém conceitualmente:

```rust
HashMap<String, Vec<(u32, u32)>>
```

mais:

```text
doc_len
ids
lsns
by_event
```

e na busca cria um:

```rust
HashMap<u32, f32>
```

para scores e depois ordena os hits.

Para um banco com milhões de documentos, eu mudaria completamente o layout:

```text
TERM DICTIONARY
"contrato" → 381
"fraude"   → 982
"servidor" → 1441

            │
            ▼

POSTING BLOCK
base_doc = 28,000,000

delta docs:
1, 2, 4, 3, 1, 8...
     │
     ▼
SIMD-BP128 / PForDelta

tf:
u8 / packed

block_max_score:
f32
```

E a busca:

```text
BM25 atual
todos postings
      ↓
todos scores
      ↓
sort
      ↓
top K
```

vira:

```text
Block-Max WAND
      ↓
skip blocos incapazes
de superar threshold
      ↓
Top-K heap
```

Isso pode reduzir **ordens de magnitude o número de documentos efetivamente pontuados** em queries seletivas.

Isso é mais importante que SIMD no BM25.

---

# 3. AttrIndex precisa deixar de ser uma fábrica de Strings

O `AttrIndex` já começou a fazer uma coisa boa: mede se uma posting list fica menor com o codec do `hume-kernel` e persiste a representação vencedora.

Mas o problema começa antes da compressão.

Hoje a chave lógica equivalente a:

```text
"cpf␟12345678900"
```

é uma `String`.

Para milhões de atributos, isso é caro demais.

Eu faria:

```text
FieldDictionary

cpf  → 17
cnpj → 18
tipo → 19
```

e:

```text
ValueDictionary

"12345678900" → 83
"contrato"    → 84
```

A chave vira:

```rust
struct AttrKey {
    field: u32,
    value: u32,
}
```

Ou mesmo:

```text
u64 = field_id << 32 | value_id
```

De repente:

```text
Hash String
malloc
UTF-8 bytes
capacity
pointer
```

desaparecem do hot path.

### Postings

LSNs são crescentes.

Esse é praticamente um convite formal para:

* Delta-BP128;
* Elias-Fano;
* Rice coding em distribuições adequadas;
* Roaring para conjuntos densos;
* plain `u32` quando a janela permitir relative LSN.

E o algoritmo deve **escolher por bloco**.

Não existe um codec campeão universal. A humanidade já tentou esse tipo de otimismo antes.

---

# 4. O grafo pode ficar radicalmente menor

O `DenseEntityMap` já existe e já projeta IDs para `u32`, inclusive mencionando explicitamente a vantagem para CSR e cache.

Mas partes importantes do grafo temporal continuam estruturalmente baseadas em:

```text
String
BTreeMap<String,...>
BTreeSet<String>
Vec<String>
```

e belief recalculado sobre as versões.

O estado analítico deveria ser:

```text
API / LOG
EntityId/String
      │
      ▼
DenseEntityMap
      │
      ▼
u32
      │
 ┌────┴──────────────┐
 ▼                   ▼
CSR OUT             CSC IN

offsets[]           offsets[]
neighbors[]         neighbors[]
weights[]           weights[]
edge_ids[]          edge_ids[]
```

### Consequências

Você ganha simultaneamente:

**RAM**

* sem String repetida na adjacência;
* sem node object por ligação;
* arrays densos.

**CPU**

* acesso sequencial;
* hardware prefetch;
* SIMD;
* melhor paralelismo.

**compactação**

* IDs `u32`;
* deltas;
* bitpacking.

**GPU**

* CSR é uma representação natural para kernels de grafo.

---

# 5. Belief temporal está fazendo trabalho repetido

Hoje a agregação de crença filtra versões por LSN, pode construir um vetor temporário, ordenar e calcular:

```text
logit(p1)
logit(p2)
...
sum
sigmoid(sum)
```

apesar de as versões já serem mantidas em ordem determinística.

Transformaria em:

```text
version LSN   log_odds   cumulative
100           +1.38      +1.38
140           -0.62      +0.76
200           +2.20      +2.96
...
```

Então:

```text
belief HEAD
=
sigmoid(head_cumulative)
```

O(1).

E:

```text
belief AS OF LSN 173
```

vira:

```text
binary search
+
sigmoid(prefix[i])
```

O(log n).

Hoje é mais próximo de O(n), com transcendentais repetidas.

---

# 6. BFS e temporal graph também precisam de representação densa

O `TemporalGraph::traverse` usa BFS determinístico, mas trabalha com sets/strings e cria vetores de vizinhos.

Para grafos grandes:

```text
frontier = bitset
visited  = bitset

next =
 OR adjacency(frontier)
 AND NOT visited
```

Para graus altos pode usar **direction-optimizing BFS**, alternando:

```text
top-down
```

e:

```text
bottom-up
```

conforme o tamanho da fronteira.

Para encontrar caminho entre A e B:

```text
bidirectional BFS
```

pode cortar brutalmente o espaço explorado.

---

# 7. O Sentinel repete o mesmo problema

A auditoria recursiva revelou que não é só o `heraclitus-index-graph`.

O grafo temporal do Sentinel também mantém arestas em `BTreeMap<String,...>`, e `neighbors_as_of()` filtra o universo de arestas. O `find_path()` ainda carrega cópias dos vetores de entidades e arestas junto de cada elemento da fila BFS.

Eu unificaria a infraestrutura:

```text
DenseEntityId
TemporalEdgeStore
CSR snapshot
Delta adjacency
TemporalIntervalIndex
```

usada por:

```text
heraclitus-index-graph
heraclitus-sentinel
provenance
WHY
traverse
correlation
```

Não faz sentido o Heraclitus pagar quatro vezes pelo mesmo problema de teoria dos grafos.

---

# 8. Distill tem um problema algorítmico claro

O `Distiller` atual encontra o cluster e, quando adiciona um membro, reconstrói os pontos do cluster e recalcula o centroide.

Isso faz o custo tender a:

$$
O(m^2D)
$$

para um cluster crescente de tamanho \(m\).

Você quer:

```rust
struct CentroidState {
    accumulator: ...,
    weight: f64,
    count: u64,
}
```

Atualização:

$$
C_{n+1}=f(C_n,x_{n+1})
$$

em aproximadamente:

$$
O(D)
$$

por elemento.

E quando o número de clusters crescer:

```text
episode
   ↓
ANN dos centroides
   ↓
5-20 clusters candidatos
   ↓
distância manifold EXATA
   ↓
threshold
```

Não:

```text
comparar contra TODOS os centroides
```

---

# 9. Activation tem três otimizações fáceis

A implementação já é matematicamente elegante: ACT-R aproximado em O(1) de estado por item.

Mas há desperdícios.

### Ring buffer

Em vez de:

```rust
recent.remove(0);
recent.push(t);
```

usar:

```text
[ t0 t1 t2 ... t7 ]
        ^
       head
```

O(1), sem deslocar o array.

### `d = 0.5`

Quando decay é 0,5:

$$
age^{-0.5}=\frac1{\sqrt{age}}
$$

Não precisa de `powf`.

### Top-K

Hoje:

```text
score N
sort N
take K
```

Deveria ser:

```text
score N
Top-K
```

$$
O(N\log K)
$$

em vez de:

$$
O(N\log N)
$$

---

# 10. HLL e Count-Min ainda são implementações de referência

O HLL atual faz `2^-register` durante `estimate()` e depois outra passagem para zeros.

Use uma LUT:

```text
pow2_neg[0]
pow2_neg[1]
...
pow2_neg[64]
```

e em uma passagem:

```text
sum += LUT[r]
zeros += r == 0
```

Pode ainda substituir:

```text
u8/register
```

por aproximadamente:

```text
6 bits/register
```

e usar modo sparse em cardinalidades muito pequenas.

Isso aproxima a estrutura de HLL++.

### Count-Min

Se:

```text
width = 4096
```

então:

```rust
hash % 4096
```

é desnecessário.

Use:

```rust
hash & 4095
```

Além disso eu estudaria:

```text
Conservative Update
```

para reduzir overestimation e permitir tabelas menores para a mesma utilidade.

---

# 11. Há um O(n²) escondido no adaptive learner

O `learn_threshold()` ordena os thresholds candidatos e depois, para cada threshold, chama uma avaliação que volta a percorrer as amostras.

Pior caso:

$$
O(n^2)
$$

Não precisa disso.

Ordene os exemplos uma vez:

```text
score ↓

0.99 true
0.94 false
0.91 true
...
```

e faça sweep atualizando:

```text
TP
FP
FN
precision
recall
F1
```

Resultado:

$$
O(n \log n)
$$

pelo sort e:

$$
O(n)
$$

pela otimização do threshold.

Mesma resposta. Muito mais escalável.

---

# 12. SelectionVector está boa, mas ainda copia demais

A ideia de alternar:

```text
Bitmap
Index16
Index32
```

por densidade é boa.

Eu manteria o conceito, mas mudaria a implementação.

Hoje operações podem acabar fazendo:

```text
Index
 ↓
Vec<u32>
 ↓
Bitmap
 ↓
operação
 ↓
contar
 ↓
reconverter
```

Você quer especializações:

```text
Index16 ∩ Index16 → merge
Index32 ∩ Index32 → merge
tiny ∩ huge       → galloping
Bitmap ∩ Bitmap   → SIMD AND
Bitmap ∩ Index    → probe dos índices
Index ∪ Index     → merge
```

E guardar:

```rust
selected_count
```

dentro da estrutura.

Assim `selected()` deixa de escanear o bitmap.

O threshold fixo `25%` também não deveria ser religião. Pode ser calibrado por hardware/morsel.

---

# 13. Memtable está fazendo força bruta desnecessária

O tail é pequeno, mas hoje:

### KNN

```text
todos embeddings
distance
Vec<hit>
sort
```

### texto

```text
cada query
  ↓
lowercase de cada episódio
  ↓
String::matches para cada termo
```

### get(id)

scan reverso do `VecDeque`.

Tudo isso aparece no código atual.

Eu colocaria dentro da memtable:

```text
EventId → slot
term → tiny posting list
flat vector SoA
adjacency
```

Não precisa HNSW para 5.000 itens. Flat SIMD + Top-K provavelmente vence.

---

# 14. Block Directory pode ficar bem menor

No HRKL v6 cada entrada do diretório ocupa **56 bytes**, contendo:

```text
offset
stored_len
uncompressed_len
record_count
flags
first_lsn
last_lsn
min_hlc
max_hlc
```

Só que vários campos são monotônicos ou fortemente correlacionados.

Exemplo:

```text
offset:
500
62000
124000
185900
```

guarde:

```text
base = 500
delta = 61500, 62000, 61900...
```

FOR + bitpack.

Mesma coisa para:

```text
first_lsn
last_lsn
min_hlc
max_hlc
```

Uma versão `BlockDirectoryV2` pode cair significativamente abaixo de 56 B/bloco.

### Outra melhoria simples

`blocks_for_lsn_range()` hoje pode percorrer entries.

Como elas estão ordenadas:

```text
partition_point(lo)
partition_point(hi)
```

e devolva um intervalo.

Passa de:

$$
O(B)
$$

para:

$$
O(\log B + K)
$$

---

# 15. HRKI Bloom tem uma alocação bastante desnecessária

No Bloom do `.hrki`, a inserção calcula os índices e faz algo equivalente a:

```rust
self.indices(item).collect::<Vec<_>>()
```

antes de marcar bits.

Isso significa uma alocação para inserir um item no Bloom.

Tire-a.

Além disso, para sidecars imutáveis eu benchmarkaria:

```text
Bloom
vs
Xor8
vs
Binary Fuse Filter
```

Binary Fuse/Xor Filters podem oferecer:

* menos bits/item;
* lookup muito rápido;
* excelente locality.

Para identificadores sensíveis, porém, a política de keyed hashing atual deve continuar. Não se troca privacidade por um benchmark bonitinho.

---

# 16. Compressão deve ser em camadas, não só Zstd/LZ4

O v6 já usa LZ4/Zstd por bloco e faz RAW fallback quando a compressão não compensa.

Isso está certo.

Mas eu adicionaria uma camada **pré-codec estrutural**:

```text
Canonical records
      ↓
TRANSFORMS REVERSÍVEIS

LSN    → delta
HLC    → delta
offset → FOR
enum   → bitpack
bool   → bitmap
IDs    → dictionary
f64    → XOR quando aplicável

      ↓
LZ4/Zstd
```

Zstd é muito bom, mas fazê-lo receber números já estruturados deixa o trabalho ridiculamente mais fácil.

### Para colunas ordenadas

O `hume-kernel` já possui:

* RLE;
* Delta;
* FOR;
* Bitpack;
* codec adaptativo.

Eu acrescentaria:

```text
SIMD-BP128
PForDelta
StreamVByte
Group Varint
Elias-Fano
Rice
```

dependendo do tipo da coluna.

---

# 17. O ULEB128 canônico eu não substituiria

O HRKL v6 exige uma representação canônica única do varint.

Então não faria a gracinha de trocar:

```text
ULEB128
```

por:

```text
StreamVByte
```

dentro de algo cuja identidade física/canônica depende desses bytes.

Pode acelerar o decoder:

```text
fast path 1-byte
fast path 2-byte
unrolled decode
batch decode
```

Mas codec diferente só:

* em estruturas derivadas;
* ou em nova versão de formato.

---

# 18. Packer v6 está materializando e copiando mais do que precisa

No `pack_segment`, a origem é escaneada, os records são mantidos na estrutura de scan e o payload é clonado ao passar para o writer. Depois ocorre uma releitura independente da geração packed para validar a raiz.

A releitura independente tem valor de integridade. Eu manteria.

Mas mudaria o pipeline:

```text
RAW reader
    │
    ▼
bounded queue
    │
    ├───────────┐
    ▼           ▼
transform    hashing
    │
    ▼
block compressors
    │
    ▼
ordered writer
```

Assim:

* não materializa o RAW inteiro;
* não clona payload por registro;
* limita RAM;
* paraleliza compressão por bloco;
* preserva a ordem na publicação.

---

# 19. Merkle está ótimo. A prova de inclusão não.

O acumulador Merkle principal já é muito bom:

$$
O(\log N)
$$

em RAM, com apenas 64 níveis.

Eu **não mexeria nele**.

O problema está no construtor de prova de inclusão, que aceita todos os hashes e constrói os níveis em memória.

O próprio código observa que:

```text
20 milhões × 32 B = 640 MB
```

Só para hashes.

Troque por:

```text
two-pass streaming proof
```

ou melhor:

```text
block subtree roots
       +
local block proof
       +
segment-level proof
```

A prova passa a usar memória aproximadamente:

$$
O(\log N)
$$

em vez de O(N).

Para pedidos múltiplos:

```text
Merkle multiproof
```

elimina siblings duplicados.

---

# 20. Bε-tree deve virar o destino dos índices frios

O `heraclitus-btree` já possui Bε-tree/Fractal Tree, prefix compression, Bloom por página, CoW e cache.

Eu o usaria como **backend de spill dos índices derivados**.

Arquitetura:

```text
HOT
small mutable delta
RAM

      ↓ flush

WARM
compressed immutable runs/pages

      ↓

COLD
Bε-tree / packed postings
disk
```

Assim TextIndex/AttrIndex/Graph não precisam manter o universo inteiro em heap Rust.

### B-tree em si

Também há espaço para:

```text
pread/pwrite
```

em vez de:

```text
Mutex<File> + seek
```

e filtros mais econômicos em páginas imutáveis.

Para Bloom interno, BLAKE3 é criptograficamente lindo e computacionalmente um tanto aristocrático para uma pergunta “esta chave talvez esteja nesta página?”. Benchmarkaria um hash não criptográfico versionado para o Bloom, mantendo BLAKE3 onde integridade exige.

---

# 21. CBO é multiplicador de todas as otimizações

O planner ainda é descrito como **rule-based v0**, embora já recolha informação para um cost-based planner futuro.

Isso é importante.

Porque depois de criar:

```text
BM25-WAND
HNSW
AttrIndex
CSR
zone maps
Bloom
HLL
Count-Min
```

alguém precisa decidir qual vem primeiro.

Exemplo:

```text
WHERE órgão = ANA
AND text ~= "fraude"
AND nearest(vector)
```

Se:

```text
órgão=ANA → 0.05% dos dados
```

o plano deve ser:

```text
AttrIndex
   ↓ 500 IDs
vector exact/ANN filtered
   ↓
BM25
```

Se:

```text
órgão=Brasil → 90%
```

pode ser:

```text
ANN
 ↓
Top-1000
 ↓
attribute filter
```

Mesma query lógica. Plano físico completamente diferente.

---

# 22. Fusão graph + vector + text pode ter early termination

O Heraclitus tem duas estratégias de fusão:

* weighted fusion em `heraclitus-query`;
* RRF/two-stage em `heraclitus-retrieval`.

Eu aproximaria as duas arquiteturas.

Mais interessante: Block-Max WAND, ANN e Top-K podem compartilhar um **threshold global de competitividade**.

Imagine:

$$
S=\alpha G+\beta V+\gamma T
$$

Para um candidato, se o limite superior ainda possível for:

$$
S_{max} < S_{K}
$$

ele não pode entrar no Top-K.

Então você pode parar de:

* percorrer postings;
* expandir HNSW;
* visitar grafo.

Isso é **branch-and-bound cross-modal**.

É uma das melhorias mais sofisticadas que eu acrescentaria ao Heraclitus.

---

# 23. A interação recursiva que mais importa

O verdadeiro pipeline ideal seria:

```text
                   QUERY
                     │
                     ▼
             Cost Based Optimizer
                     │
          ┌──────────┼───────────┐
          │          │           │
          ▼          ▼           ▼
      AttrIndex    BM25       Graph CSR
     compressed   BMW/WAND    temporal
          │          │           │
          └──────┬───┴──────┬────┘
                 │          │
                 ▼          ▼
            SelectionVector
            Bitmap/Index16
                 │
                 ▼
        filtered HNSW recall
       SQ8/PQ/SIMD/GPU resident
                 │
                 ▼
              Top-M
                 │
                 ▼
        exact manifold rescore
                 │
                 ▼
         graph/text/vector
          bounded fusion
                 │
                 ▼
              TOP-K
```

Essa interação é superior a otimizar isoladamente cada módulo.

---

# 24. Compactação física que eu perseguiria

Hoje eu miraria uma hierarquia parecida com esta:

```text
                   HOT                    COLD

EventId        128-bit       →      dense u32
EntityId       String        →      dictionary u32
Term           String        →      TermId u32
Attribute      String pair   →      packed u64
Graph          trees/vectors →      CSR/CSC
Posting docs   u32 pairs     →      delta SIMD-BP128
Posting LSN    u64           →      Elias-Fano/Delta
Dense sets     Vec<u64>      →      Roaring
Embedding      f32           →      SQ8/PQ recall + f32 canonical
HLL            u8            →      6-bit/sparse
Selection      generic       →      bitmap/16/32 adaptive
Block dir      56 B/block    →      delta/FOR packed v2
HRKL blocks    raw structs   →      transforms + Zstd/LZ4
```

Essa é a rota real para chegar a uma diferença de **múltiplos × na RAM**, não alguns porcentos.

---

# 25. O que já está coberto pela SPEC-0043

A boa notícia é que não precisamos escrever cinquenta páginas para descobrir que já existem cinquenta páginas. A `SPEC-0043` já cobre boa parte do lado matemático:

* prepared metric;
* SIMD;
* HNSW visited;
* greedy search;
* partial Top-K;
* SoA;
* SQ8/PQ;
* GPU resident;
* GPU Top-M;
* Activation;
* HUME SIMD/JIT;
* sketches;
* belief cache;
* CSR;
* distill incremental;
* compression SIMD;
* autotuning.

**O que esta nova auditoria acrescenta de relevante à SPEC-0043:**

| Novo bloco                               | Por que merece entrar                        |
| ---------------------------------------- | -------------------------------------------- |
| **TextIndex Block-Max WAND**             | enorme redução de trabalho BM25              |
| **Postings SIMD-BP128/Elias-Fano**       | RAM + cache + disco                          |
| **Dictionary/FST de termos**             | elimina Strings do índice                    |
| **AttrIndex internado/denso**            | ataca diretamente RAM                        |
| **Roaring/Elias-Fano adaptativo**        | postings diferentes exigem codecs diferentes |
| **disk-backed derived indexes**          | resolve o teto real de ~2 KB/evento          |
| **Bε-tree como spill backend**           | infraestrutura já existe                     |
| **BlockDirectoryV2 compactado**          | reduz metadados HRKL                         |
| **HRKI Xor/Binary Fuse candidate**       | sidecar mais compacto                        |
| **Streaming Merkle proof**               | 640 MB → O(logN)                             |
| **Streaming/parallel packer**            | menos RAM e cópias                           |
| **Memtable micro-indexes**               | remove scans repetidos                       |
| **Adaptive F1 sweep**                    | O(n²) → O(n logn)                            |
| **CBO cross-index**                      | multiplica todos os outros ganhos            |
| **Cross-modal upper bounds**             | early termination graph/vector/text          |
| **Temporal interval indexing**           | AS OF sem scans amplos                       |
| **Sentinel usando dense temporal graph** | evita segundo grafo caro                     |
| **Raft batching/storage optimization**   | sem mexer no consenso                        |

---

# 26. E o Raft?

O `FileRaftLog` está corretamente preocupado primeiro com durabilidade: WAL, `fsync` antes do ACK, recovery, truncation e compactação.

Aqui eu faria otimização física, não matemática:

```text
AppendEntries batch
        ↓
single serialization buffer
        ↓
single write
        ↓
single fsync/group commit
```

e possivelmente:

```text
BTreeMap<u64, Entry>
```

→ representação segmentada/densa para ranges recentes.

Mas **não alteraria a matemática do Raft**.

---

# 27. Criptografia e compliance: quase nada de “otimização criativa”

O compliance usa SHA-256/384/512, RSA/PSS/ECDSA e bibliotecas especializadas.

Eu faria apenas:

```text
batch verification
certificate-chain cache
parsed-key cache
digest streaming
parallel independent validations
```

Não implementaria SHA, RSA ou ECDSA “mais rápidos do Heraclitus”.

Existem lugares em engenharia onde criatividade é virtude. Implementar sua própria criptografia não costuma ser um deles.

---

# 28. Ordem que eu implementaria

Se o objetivo for **máximo ganho agregado**, minha sequência mudou um pouco em relação à SPEC-0043:

```text
FASE 1 — MATEMÁTICA BARATA
PreparedQuery
PreparedPoint
dist²
VisitedEpoch
Greedy HNSW
generic TopK
Activation TopK
Adaptive F1 sweep

        ↓

FASE 2 — MATAR O TETO DE RAM
Dense IDs globais
Text TermDictionary
compressed postings
Attr dictionary
Roaring/Elias-Fano
CSR graph
disk-backed derived indexes
Bε-tree spill

        ↓

FASE 3 — CPU/VECTOR
SIMD dot/norm/L2
SoA VectorStore
SelectionVector specialized
BM25 Block-Max WAND
belief prefix cache

        ↓

FASE 4 — COMPACTAÇÃO
SIMD-BP128
FOR/PForDelta
BlockDirectoryV2
structural transforms HRKL
Zstd dictionaries
packed checkpoints

        ↓

FASE 5 — GPU
resident store
buffer pool
batched query
GPU Top-M
SQ8
PQ/OPQ

        ↓

FASE 6 — EXECUÇÃO GLOBAL
CBO
cross-index selectivity
branch-and-bound hybrid retrieval
adaptive ANN ef
adaptive codecs/layout
autotuning
```

## Prioridade absoluta

Se eu tivesse que reduzir tudo a **10 alterações que mais mudariam o HeraclitusDB**, seriam:

**1. Derived indexes disk-backed + comprimidos.** Resolve o teto de ~2 KB/evento.
**2. BM25 Block-Max WAND + postings comprimidas.**
**3. Dense IDs + CSR/CSC para todo grafo.**
**4. HNSW SoA + PreparedMetric + VisitedEpoch.**
**5. SQ8/PQ para recall, com exact rescore.**
**6. AttrIndex com dictionary IDs + compressed postings.**
**7. CBO real cruzando attr/text/vector/grafo.**
**8. SIMD-BP128/Elias-Fano/Roaring adaptativos.**
**9. GPU resident vectors + GPU Top-M.**
**10. Streaming packer + compact BlockDirectory/HRKI.**

E existe evidência de que o lado de I/O também não pode ser ignorado: a auditoria de 20M já mediu **27,3×** para CRC32C por hardware, **14,3×** para o caminho otimizado de boot/verify, **10,3×** para leitura pontual com handle reutilizado e **3,25×** no scan com buffering. Portanto o Heraclitus não está numa fase em que falta “uma grande otimização”. Há ganhos grandes em **todas as camadas**, o que é uma situação muito melhor e muito mais trabalhosa.

### Veredito

A arquitetura matemática do HeraclitusDB já é sofisticada. O que ainda o impede de escalar confortavelmente para dezenas ou centenas de milhões de eventos não é falta de algoritmos avançados. É que **a representação física ainda não alcançou a sofisticação da arquitetura lógica**.

O salto SOTA seria transformar o Heraclitus em:

> **log canônico imutável + índices derivados densos/comprimidos/disk-backed + HNSW quantizado com rescore exato + grafo CSR temporal + BM25 WAND + CBO multimodal + execução SIMD/GPU.**

Essa combinação atacaria simultaneamente **RAM, cache misses, I/O, CPU, VRAM/PCIe, tamanho de checkpoint, tempo de boot e latência de query**, sem sacrificar o principal diferencial arquitetural do banco: replay e auditabilidade determinísticos.

```python
import os

zip_dir = "crates-b95ea7a19a71aca6e0ebae3a43b929d8d0587d53"
if os.path.exists(zip_dir):
    crates = [d for d in os.listdir(zip_dir) if os.path.isdir(os.path.join(zip_dir, d)) and (d.startswith("heraclitus") or d.startswith("hume"))]
    print(f"Total crates found: {len(crates)}")
    print(sorted(crates))


```

```python
import os
print(os.listdir('.'))


```

```text
['joserfjuniorllms']


```

```python
import os
for root, dirs, files in os.walk('.'):
    if 'Cargo.toml' in files:
        print(root)


```

```python
import os
for root, dirs, files in os.walk('.', topdown=True):
    print(root, dirs[:5], files[:5])
    if len(root.split(os.sep)) > 3:
        dirs.clear()


```

```text
. ['joserfjuniorllms'] []
./joserfjuniorllms [] ['crates']


```

```python
import os
print(os.path.isfile('./joserfjuniorllms/crates'))
print(os.path.getsize('./joserfjuniorllms/crates'))


```

```text
True
2032020


```

```python
import zipfile, tarfile

path = './joserfjuniorllms/crates'
if zipfile.is_zipfile(path):
    with zipfile.ZipFile(path) as z:
        print("Zip file contents sample:")
        print(z.namelist()[:20])
else:
    try:
        with tarfile.open(path) as t:
            print("Tar file contents sample:")
            print(t.getnames()[:20])
    except Exception as e:
        print("Error:", e)


```

```text
Zip file contents sample:
['crates-b95ea7a19a71aca6e0ebae3a43b929d8d0587d53/', 'crates-b95ea7a19a71aca6e0ebae3a43b929d8d0587d53/README.md', 'crates-b95ea7a19a71aca6e0ebae3a43b929d8d0587d53/SPEC-NEW/', 'crates-b95ea7a19a71aca6e0ebae3a43b929d8d0587d53/SPEC-NEW/AUDITORIA-PRODUCAO-FORGE-2026-08-14.md', 'crates-b95ea7a19a71aca6e0ebae3a43b929d8d0587d53/SPEC-NEW/BUGS.md', 'crates-b95ea7a19a71aca6e0ebae3a43b929d8d0587d53/SPEC-NEW/DECISAO-P1-motor-analitico.md', 'crates-b95ea7a19a71aca6e0ebae3a43b929d8d0587d53/SPEC-NEW/DECISAO-P3-isolation-txn.md', 'crates-b95ea7a19a71aca6e0ebae3a43b929d8d0587d53/SPEC-NEW/DECISAO-P4-plugins-wasm.md', 'crates-b95ea7a19a71aca6e0ebae3a43b929d8d0587d53/SPEC-NEW/DECISAO-P5-hvm-endpoint.md', 'crates-b95ea7a19a71aca6e0ebae3a43b929d8d0587d53/SPEC-NEW/PLANO-HOMOLOGACAO-FORGE.md', 'crates-b95ea7a19a71aca6e0ebae3a43b929d8d0587d53/SPEC-NEW/PLANO-SPECS.md', 'crates-b95ea7a19a71aca6e0ebae3a43b929d8d0587d53/SPEC-NEW/RELEASE_NOTES_v1.0.0.md', 'crates-b95ea7a19a71aca6e0ebae3a43b929d8d0587d53/SPEC-NEW/RELEASE_NOTES_v1.0.1.md', 'crates-b95ea7a19a71aca6e0ebae3a43b929d8d0587d53/SPEC-NEW/RELEASE_NOTES_v1.0.2.md', 'crates-b95ea7a19a71aca6e0ebae3a43b929d8d0587d53/SPEC-NEW/RELEASE_NOTES_v1.0.3.md', 'crates-b95ea7a19a71aca6e0ebae3a43b929d8d0587d53/SPEC-NEW/RELEASE_NOTES_v1.0.4.md', 'crates-b95ea7a19a71aca6e0ebae3a43b929d8d0587d53/SPEC-NEW/RELEASE_NOTES_v1.0.5.md', 'crates-b95ea7a19a71aca6e0ebae3a43b929d8d0587d53/SPEC-NEW/SPEC-000.md', 'crates-b95ea7a19a71aca6e0ebae3a43b929d8d0587d53/SPEC-NEW/SPEC-0036.md', 'crates-b95ea7a19a71aca6e0ebae3a43b929d8d0587d53/SPEC-NEW/SPEC-0037.md']


```

```python
import zipfile

path = './joserfjuniorllms/crates'
with zipfile.ZipFile(path) as z:
    cargo_files = [f for f in z.namelist() if f.endswith('Cargo.toml')]
    print("Found Cargo.toml files:", len(cargo_files))
    for f in sorted(cargo_files):
        print(" -", f)


```

```text
Found Cargo.toml files: 30
 - crates-b95ea7a19a71aca6e0ebae3a43b929d8d0587d53/heraclitus-activation/Cargo.toml
 - crates-b95ea7a19a71aca6e0ebae3a43b929d8d0587d53/heraclitus-analytics/Cargo.toml
 - crates-b95ea7a19a71aca6e0ebae3a43b929d8d0587d53/heraclitus-btree/Cargo.toml
 - crates-b95ea7a19a71aca6e0ebae3a43b929d8d0587d53/heraclitus-cli/Cargo.toml
 - crates-b95ea7a19a71aca6e0ebae3a43b929d8d0587d53/heraclitus-client/Cargo.toml
 - crates-b95ea7a19a71aca6e0ebae3a43b929d8d0587d53/heraclitus-compliance/Cargo.toml
 - crates-b95ea7a19a71aca6e0ebae3a43b929d8d0587d53/heraclitus-core/Cargo.toml
 - crates-b95ea7a19a71aca6e0ebae3a43b929d8d0587d53/heraclitus-crypto/Cargo.toml
 - crates-b95ea7a19a71aca6e0ebae3a43b929d8d0587d53/heraclitus-distill/Cargo.toml
 - crates-b95ea7a19a71aca6e0ebae3a43b929d8d0587d53/heraclitus-gpu/Cargo.toml
 - crates-b95ea7a19a71aca6e0ebae3a43b929d8d0587d53/heraclitus-index-attr/Cargo.toml
 - crates-b95ea7a19a71aca6e0ebae3a43b929d8d0587d53/heraclitus-index-graph/Cargo.toml
 - crates-b95ea7a19a71aca6e0ebae3a43b929d8d0587d53/heraclitus-index-text/Cargo.toml
 - crates-b95ea7a19a71aca6e0ebae3a43b929d8d0587d53/heraclitus-index-vector/Cargo.toml
 - crates-b95ea7a19a71aca6e0ebae3a43b929d8d0587d53/heraclitus-log/Cargo.toml
 - crates-b95ea7a19a71aca6e0ebae3a43b929d8d0587d53/heraclitus-manifold/Cargo.toml
 - crates-b95ea7a19a71aca6e0ebae3a43b929d8d0587d53/heraclitus-memtable/Cargo.toml
 - crates-b95ea7a19a71aca6e0ebae3a43b929d8d0587d53/heraclitus-proto/Cargo.toml
 - crates-b95ea7a19a71aca6e0ebae3a43b929d8d0587d53/heraclitus-query/Cargo.toml
 - crates-b95ea7a19a71aca6e0ebae3a43b929d8d0587d53/heraclitus-raft/Cargo.toml
 - crates-b95ea7a19a71aca6e0ebae3a43b929d8d0587d53/heraclitus-retrieval/Cargo.toml
 - crates-b95ea7a19a71aca6e0ebae3a43b929d8d0587d53/heraclitus-sentinel/Cargo.toml
 - crates-b95ea7a19a71aca6e0ebae3a43b929d8d0587d53/heraclitus-server/Cargo.toml
 - crates-b95ea7a19a71aca6e0ebae3a43b929d8d0587d53/heraclitus-tier/Cargo.toml
 - crates-b95ea7a19a71aca6e0ebae3a43b929d8d0587d53/heraclitus-txn/Cargo.toml
 - crates-b95ea7a19a71aca6e0ebae3a43b929d8d0587d53/heraclitus-views/Cargo.toml
 - crates-b95ea7a19a71aca6e0ebae3a43b929d8d0587d53/heraclitus-wasm/Cargo.toml
 - crates-b95ea7a19a71aca6e0ebae3a43b929d8d0587d53/hume-ir/Cargo.toml
 - crates-b95ea7a19a71aca6e0ebae3a43b929d8d0587d53/hume-kernel/Cargo.toml
 - crates-b95ea7a19a71aca6e0ebae3a43b929d8d0587d53/hume-sketches/Cargo.toml


```

A análise cobriu rigorosamente os 30 *crates* que compõem o ecossistema `JoseRFJuniorLLMs/crates`, identificando as dependências de dados, alocações de memória e gargalos matemáticos em cada módulo do projeto:

* **Armazenamento e Log (`heraclitus-log`, `heraclitus-btree`, `heraclitus-memtable`, `heraclitus-tier`)**
* **`heraclitus-log`:** Estrutura do formato HRKL v6, alocação de 56 B no `BlockDirectory`, serialização ULEB128 no *hot path*, *pipeline* de *packer* com clonagem desnecessária e geração de provas Merkle O(N) em memória.
* **`heraclitus-btree`:** Mecânica de pites e *spill* de índices derivados em disco via Bε-tree / *Fractal Tree*, além de travamento por `Mutex<File>` e hashes criptográficos no Bloom interno.
* **`heraclitus-memtable`:** Busca linear (*scans* reversos em `VecDeque`) e filtros de string simples sem mini-índices estruturados em memória.
* **`heraclitus-tier`:** Ciclo de vida da movimentação de dados entre *hot*, *cold*, *object storage* e exportação Parquet/Delta/Iceberg.


* **Matemática Vetorial e Aceleração (`heraclitus-manifold`, `heraclitus-index-vector`, `heraclitus-gpu`)**
* **`heraclitus-manifold`:** Funções transcendentais (`acosh`, `acos`) na travessia de manifolds de produto (Poincaré + Esfera + Euclidiana) e recalculo de normas.
* **`heraclitus-index-vector`:** Estrutura de travessia do HNSW, alocação de `HashSet<u32>` para `visited`, ponteiros via `Vec<Vec<u32>>` para adjacências, arranjo AoS versus SoA e integração com SQ8/PQ.
* **`heraclitus-gpu`:** Transferência de vetores entre CPU e VRAM via PCIe e *buffer pool* persistente para eliminação de latência.


* **Índices de Texto, Atributo e Esboços Probabilísticos (`heraclitus-index-text`, `heraclitus-index-attr`, `hume-sketches`)**
* **`heraclitus-index-text`:** Layout do índice invertido, avaliação exaustiva de BM25 sem pivô de parada (ausência de Block-Max WAND / MaxScore) e alocação dinâmica de `HashMap<doc, f32>` por consulta.
* **`heraclitus-index-attr`:** Atribuição de chaves em formato `String` concatenado (`"field␟value"`), falta de dicionário de termos unificado e seleção de codecs de compressão (SIMD-BP128, Elias-Fano, Roaring).
* **`hume-sketches`:** Tabelas de busca para potências de 2 no HyperLogLog (HLL) e máscaras de bits por deslocamento nas tabelas do Count-Min Sketch.


* **Grafos Temporais e Análise Comportamental (`heraclitus-index-graph`, `heraclitus-sentinel`, `heraclitus-distill`, `heraclitus-activation`)**
* **`heraclitus-index-graph`:** Mapeamento do `DenseEntityMap`, dependência de `BTreeMap<String, ...>` para adjacência temporal, ausência de matrizes esparsas compactas (CSR/CSC) e recálculo de *belief* via log-odds sem somas de prefixo.
* **`heraclitus-sentinel`:** Duplicação do grafo temporal com IDs em `String` e cópia de coleções durante travessias BFS no mecanismo de detecção de ameaças.
* **`heraclitus-distill`:** Custo $O(m^2 D)$ na reconstrução de agrupamentos em clusters para recalculo de centroides.
* **`heraclitus-activation`:** Modelo ACT-R operando com `remove(0)` em vetores em vez de *ring buffers* e custo de exponenciação `powf` no *decay*.


* **Planejamento e Execução Analítica (`heraclitus-query`, `heraclitus-analytics`, `hume-kernel`, `hume-ir`)**
* **`heraclitus-query`:** Integração e fusão de múltiplos modais (vetor, texto, grafo, atributos) com regras puramente estáticas (Planner v0) e ausência de limites superiores (*branch-and-bound*) cruzados.
* **`heraclitus-analytics` & `hume-kernel`:** Execução por *morsels*, vetorização SIMD de colunas e uso das abstrações de vetor do `SelectionVector`.
* **`hume-ir`:** Compilação JIT de IR para expressão de consulta e otimização de laços.


* **Consenso, Protocolo e Infraestrutura (`heraclitus-raft`, `heraclitus-proto`, `heraclitus-server`, `heraclitus-client`, `heraclitus-cli`)**
* **`heraclitus-raft`:** Agrupamento (*batching*) de gravações no WAL e execução de `fsync` no log persistente.
* **`heraclitus-proto` & `heraclitus-server`:** Camada de transporte gRPC/Flight, serialização e buffers do servidor embarcado.
* **`heraclitus-client` & `heraclitus-cli`:** Ponto de entrada de comandos e abstração do driver de conexão.


* **Segurança, Conformidade e Extensibilidade (`heraclitus-compliance`, `heraclitus-crypto`, `heraclitus-txn`, `heraclitus-views`, `heraclitus-wasm`)**
* **`heraclitus-compliance` & `heraclitus-crypto`:** Uso do BLAKE3/SHA-2, assinaturas RFC 3161/PKI, verificação em lote (*batch verification*) de certificados e eliminação de alocações na construção de árvores/provas.
* **`heraclitus-txn`:** Controle de concorrência e isolamento.
* **`heraclitus-views`:** Lógica de *skip-replay* para reinicialização rápida (*boot*) de visões materializadas.
* **`heraclitus-wasm`:** Execução isolada de *plugins* no *runtime* WASM.

SPEC-OTIMIZACAO — HeraclitusDB Recursive Performance & Compaction Program

Status: Draft Normativo / Implementável
Classe: Performance / Storage / Indexing / Mathematical Execution / Compression / Query Planning
Escopo: HeraclitusDB + HUME + Sentinel
Prioridade: P0–P3
Público-alvo: Agentes de IA de engenharia, maintainers e revisores humanos
Princípio central: Optimize algorithm → layout → memory movement → instructions

1. Objetivo

Esta SPEC define um programa recursivo, exaustivo e mensurável para otimizar o HeraclitusDB em quatro dimensões simultâneas:

velocidade de ingestão e leitura;

redução de consumo de memória RAM/VRAM;

maior compactação em disco e checkpoints;

menor latência de consulta, boot, recovery e auditoria.

A implementação DEVE atacar primeiro custos assintóticos e estruturas físicas, e somente depois micro-otimizações de instrução.

A IA implementadora NÃO DEVE:

substituir algoritmos corretos apenas porque outro parece “mais moderno”;

alterar a semântica canônica do log;

alterar a ordem determinística de replay;

introduzir dependência obrigatória de Rust nightly;

introduzir unsafe sem benchmark, invariantes documentados e testes;

alterar formato persistente sem versionamento explícito;

degradar Recall/NDCG/MRR sem gate aprovado;

trocar durabilidade por throughput silenciosamente;

remover validações de integridade para melhorar benchmark;

considerar “compila” como critério de conclusão.

2. Meta arquitetural

O estado final esperado é:

                         CANONICAL LOG
                     immutable / replayable
                              │
                              ▼
                    compact physical blocks
                    delta/FOR/bitpack/Zstd
                              │
             ┌────────────────┼────────────────┐
             │                │                │
             ▼                ▼                ▼
       DERIVED TEXT      DERIVED GRAPH    DERIVED ATTR
       dictionary        dense IDs         dictionary
       WAND/BMW          CSR/CSC           compressed postings
       compressed        disk-backed       disk-backed
       postings
             │                │                │
             └────────────┬───┴───────────────┘
                          ▼
                    SELECTION VECTOR
                  bitmap/index16/index32
                          │
                          ▼
                    VECTOR RECALL
                  HNSW + SQ8/PQ/SIMD
                  optional GPU resident
                          │
                          ▼
                    EXACT RESCORE
                     canonical f64
                          │
                          ▼
                   HYBRID TOP-K
            graph + vector + text + activation
                          │
                          ▼
                    CBO / EXPLAIN

3. Invariantes globais

3.1 Determinismo

A mesma sequência de eventos DEVE produzir:

same canonical bytes
same logical_root
same state_hash
same derived logical result
same deterministic tie-breaking

independentemente de:

scalar
AVX2
AVX-512
NEON
GPU
thread count
scheduler order

quando a operação for declarada exata.

Caminhos aproximados podem produzir conjuntos intermediários diferentes SOMENTE quando:

a operação estiver formalmente marcada como aproximada;

o resultado final respeitar o gate de recall;

nenhum estado persistente depender dessa aproximação.

3.2 Log canônico é soberano

Índices, caches, sidecars, CSR, HNSW, postings, zone maps, sketches, checkpoints e artefatos GPU são derivados.

Portanto:

derived corruption → rebuild
canonical corruption → fail high

Nunca transformar falha de índice derivado em corrupção do log canônico.

3.3 Stable Rust

Produção DEVE compilar em Rust Stable.

SIMD:

scalar fallback
    ↓
core::arch AVX2/FMA
    ↓
core::arch AVX-512
    ↓
ARM64 NEON

std::simd pode existir apenas sob feature experimental desativada por default.

3.4 Semântica matemática

heraclitus-manifold::ProductMetric::dist() permanece o oracle canônico.

Aproximações são permitidas apenas para:

candidate generation
pruning
estimation
GPU recall
SQ8/PQ
fast screening

Quando o contrato exigir exatidão:

approximate recall
      ↓
candidate set
      ↓
exact f64 rescore
      ↓
final deterministic ranking

4. Método obrigatório da IA implementadora

Cada otimização DEVE seguir o ciclo:

INSPECT
  ↓
BASELINE
  ↓
PROFILE
  ↓
IMPLEMENT
  ↓
CORRECTNESS GATE
  ↓
BENCHMARK A/B
  ↓
MEMORY GATE
  ↓
END-TO-END GATE
  ↓
KEEP / REVERT

Nenhuma etapa pode ser pulada.

5. Auditoria recursiva obrigatória

A IA DEVE analisar:

caller
  ↓
callee
  ↓
allocation
  ↓
data layout
  ↓
cache behavior
  ↓
serialization
  ↓
index interaction
  ↓
query planner
  ↓
storage
  ↓
recovery

A otimização de um módulo só é aceita se não provocar regressão significativa em outro.

Exemplo:

postings menores
    ↓
mais CPU de decode
    ↓
WAND visita menos postings
    ↓
efeito global positivo

A decisão é pelo pipeline total, não pelo microbenchmark isolado.

6. Métricas obrigatórias

CPU

ns/op
cycles/op
instructions/op
branch misses
cache misses
IPC
GB/s
distance evaluations/query
decoded postings/query

Memória

RSS
heap bytes
bytes/event
bytes/vector
bytes/edge
bytes/posting
allocations/query
allocations/append
peak temporary memory

Storage

bytes/event
bytes/posting
bytes/block
bytes/checkpoint
compression ratio
write amplification
read amplification

Latência

p50
p95
p99
max

Retrieval

Recall@10
Recall@50
Recall@100
MRR
NDCG@10
QPS

Operacional

boot time
verify time
recovery time
rebuild time
checkpoint time
restore time

7. Workloads de referência

Executar no mínimo:

100k
1M
10M
20M
50M

quando o ambiente permitir.

Para índices vetoriais:

5k
50k
500k
5M

Dimensões mínimas:

48
128
384
768
1536

Dados:

sintéticos controlados;

corpus textual;

dados governamentais representativos;

workload temporal;

workload de fraude/grafo;

escrita concorrente;

leitura sob escrita.

8. P0 — Prepared Product-Manifold Metric

Criar:

pub struct PreparedQuery {
    pub point: ProductPoint,
    pub hyp_norm: f64,
    pub hyp_scale: f64,
    pub sph_norm: f64,
    pub sph_inv_norm: f64,
    pub sqrt_c1: f64,
    pub inv_sqrt_c1: f64,
    pub sqrt_k2: f64,
    pub inv_sqrt_k2: f64,
    pub weights: [f64; 3],
}

E:

pub struct PreparedPoint {
    pub hyp_norm: f32,
    pub hyp_scale: f32,
    pub sph_norm: f32,
    pub sph_inv_norm: f32,
}

Objetivo:

remover normas repetidas;

remover constantes de curvatura repetidas;

reduzir sqrt e divisões redundantes.

Gate:

ranking exact == baseline
speedup >= 1.20x em HNSW real

9. P0 — Ranking por distância quadrática

Quando a API não precisa devolver a distância final:

sqrt(S)

NÃO deve ser calculado apenas para ordenar.

Usar:

S = wH*dH² + wS*dS² + wE*dE²

O sqrt() é monotônico em S >= 0.

Gate:

ordem idêntica
zero mudança de resultado

10. P0 — SIMD mathematical kernels

Criar:

hume-kernel/src/math/
├── mod.rs
├── scalar.rs
├── x86/
│   ├── avx2.rs
│   └── avx512.rs
└── arm/
    └── neon.rs

Primitivas:

dot_f32
dot_f64
sq_l2_f32
sq_l2_f64
norm2_f32
norm2_f64
sum_f32
sum_f64
max_u8
bitwise_and
bitwise_or

Dispatch ocorre uma vez.

Hot loop NÃO testa capabilities a cada vetor.

11. P0 — HNSW visited epoch table

Substituir estruturas hash para IDs internos densos.

pub struct VisitedTable {
    epoch: u32,
    stamps: Vec<u32>,
}

Nova query:

epoch += 1

Visit:

stamps[id] == epoch

Tratar overflow:

epoch == MAX
→ clear stamps
→ epoch = 1

Gate:

zero diferença de recall
zero hash allocations/query

12. P0 — HNSW greedy descent

Níveis superiores devem possuir caminho especializado para ef = 1.

entry
 ↓
scan neighbors
 ↓
move if better
 ↓
repeat

Sem:

HashSet
BinaryHeap
full search_layer

13. P0 — HNSW compact adjacency

Migrar progressivamente de:

Vec<Vec<u32>>

para layout contíguo.

Alvo:

pub struct HnswAdjacency {
    level_offsets: Vec<u64>,
    node_offsets: Vec<u32>,
    neighbors: Vec<u32>,
}

Opcional:

delta-coded neighbor ids

quando reduzir bytes sem aumentar p99.

14. P0 — VectorStore SoA

Representação física:

pub struct VectorStore {
    hyp: AlignedBuffer,
    sph: AlignedBuffer,
    euc: AlignedBuffer,
    hyp_norm: Vec<f32>,
    hyp_scale: Vec<f32>,
    sph_inv_norm: Vec<f32>,
    len: usize,
    dims: Signature,
}

Sem Vec por vetor.

Objetivos:

reduzir pointer chasing;

aumentar densidade por cache line;

alimentar SIMD e GPU sem repack.

15. P1 — SQ8

SQ8 só para recall.

canonical f32 vector
       +
SQ8 derived vector

Query:

SQ8 recall
   ↓
Top-M
   ↓
exact f64 rescore

Gate default:

Recall@10 >= 0.99

Não persistir SQ8 como única representação de um embedding canônico.

16. P1 — Product Quantization

Adicionar:

PQ
OPQ + PQ

para coleções grandes.

Medir:

bytes/vector
candidate QPS
Recall@10
Recall@100
rescore count

Nunca tornar default sem benchmark real.

17. P0 — GPU resident vector store

Não reconstruir/uploadar toda a coleção por query.

Criar:

pub struct GpuVectorStore {
    vectors: wgpu::Buffer,
    metadata: wgpu::Buffer,
    capacity: usize,
    len: usize,
    generation: u64,
}

Atualização em:

insert
bulk build
restore
rebuild

Query envia:

query vector
params

18. P0 — GPU buffer pool

Reciclar:

query buffers
distance buffers
candidate buffers
readback buffers
uniform buffers

Nenhum create_buffer desnecessário por consulta.

19. P0 — GPU Top-M

A GPU não deve devolver N distâncias quando o chamador quer M candidatos.

Pipeline:

distance
   ↓
workgroup Top-M
   ↓
hierarchical merge
   ↓
global Top-M
   ↓
readback M

20. P1 — GPU query batching

Suportar:

batch 8
batch 32
batch 128

O scheduler pode acumular uma microfila com limite de latência configurável.

21. P0 — Text dictionary

Substituir chaves String repetidas por TermId.

String
  ↓
TermDictionary
  ↓
u32

Possíveis implementações:

FST
front-coded sorted dictionary
minimal trie
hash → stable term id

A escolha deve respeitar determinismo.

22. P0 — BM25 compressed postings

Postings devem ser blocadas.

block
├── base_doc
├── doc_deltas
├── tf
├── block_max_score
└── optional skip metadata

Codecs candidatos:

SIMD-BP128
PForDelta
StreamVByte
delta-varint

Selecionar por benchmark.

23. P0 — Block-Max WAND

Implementar BMW/WAND no caminho de busca textual.

Objetivo:

não pontuar documentos incapazes de superar current_top_k_threshold

Gate:

resultado Top-K exato == baseline BM25

BMW é otimização exata de ranking, não aproximação.

24. P1 — MaxScore

Implementação opcional como alternativa a BMW.

O planner escolhe conforme:

query term count
posting lengths
upper bounds
current k

25. P0 — Dense score accumulator para BM25

Evitar HashMap<DocId, f32> quando DocIds forem densos.

Criar:

pub struct DenseAccumulator {
    epoch: u32,
    stamp: Vec<u32>,
    score: Vec<f32>,
    touched: Vec<u32>,
}

Reset lógico por epoch.

26. P0 — Text Top-K parcial

Nenhum sort(all) para K << N.

Usar:

heap O(N log K)

ou:

select_nth_unstable
+
sort K

27. P1 — BM25 prepared statistics

Pré-calcular quando possível:

idf(term)
doc_len normalization
avgdl-derived constants

Atualizar incrementalmente quando o índice muda.

28. P0 — AttrIndex dictionary encoding

Substituir:

"field<SEP>value"

por:

struct AttrKey {
    field: u32,
    value: u32,
}

ou packed u64.

Manter dictionary reversível para EXPLAIN/materialização.

29. P0 — Adaptive compressed attr postings

Postings de LSN são monotônicas.

Testar por bloco/lista:

plain
delta-varint
SIMD-BP128
Elias-Fano
Roaring

O codec deve ser escolhido por tamanho + decode throughput.

30. P0 — Elias-Fano

Usar para listas monotônicas grandes e esparsas quando vantajoso.

Gate:

space reduction
AND
p99 lookup/range não piora acima do limite configurado

31. P0 — Roaring

Usar para conjuntos densos/interseções frequentes.

Não converter tudo para Roaring por dogma.

Seleção:

sparse ordered list
vs
roaring
vs
bitmap

deve depender de cardinalidade e universo.

32. P0 — Disk-backed derived indexes

Este é um objetivo estrutural obrigatório.

Índices derivados NÃO devem exigir que todo o estado histórico esteja residente.

Arquitetura:

HOT DELTA
RAM mutable
    ↓
flush
WARM IMMUTABLE RUNS
compressed / mmap or buffered
    ↓
COLD
Bε-tree / packed files

Aplicar progressivamente a:

TextIndex
AttrIndex
GraphIndex
Activation historical state

33. P0 — Bε-tree as spill backend

Reutilizar heraclitus-btree.

Não criar um segundo motor de páginas sem necessidade.

Investigar:

prefix-compressed keys
page-local filters
batched message flush
pread/pwrite
cache sharding

34. P1 — SelectionVector cardinality cache

Adicionar selected_count.

Evitar popcount repetido quando conjunto não mudou.

35. P1 — SelectionVector specialized operations

Implementar:

Index16 ∩ Index16
Index32 ∩ Index32
Index16 ∩ Index32
Bitmap ∩ Bitmap
Bitmap ∩ Index16
Bitmap ∩ Index32

Sem converter ambas as estruturas cegamente.

36. P1 — Galloping intersection

Quando:

small << large

usar galloping/exponential search.

Benchmark contra merge linear.

37. P1 — Adaptive representation threshold

O threshold Bitmap/Index não deve ser fixado universalmente em 25%.

Criar perfil por:

morsel size
CPU
cache
operation mix

Persistir apenas configuração, nunca resultado dependente do hardware.

38. P0 — Dense graph IDs

Toda camada analítica interna deve migrar para:

EntityId/String
      ↓
DenseEntityMap
      ↓
u32

Strings permanecem nas APIs externas.

39. P0 — CSR/CSC graph

Representação de leitura:

pub struct CsrGraph {
    offsets: Vec<u32>,
    neighbors: Vec<u32>,
    edge_ids: Vec<u32>,
    weights: Vec<f32>,
}

Manter delta overlay para eventos recentes.

Rebuild/merge de CSR deve ser derivado e determinístico.

40. P1 — Direction-optimizing BFS

Suportar:

top-down BFS
bottom-up BFS

e alternar conforme frontier.

Visited:

bitset

Frontier:

bitmap ou dense u32 list

41. P1 — Bidirectional BFS

Usar para find_path(A,B) quando adequado.

Gate:

mesmo shortest path
mesma regra determinística de desempate

42. P0 — Belief head cache

Manter:

cached_log_odds

por aresta.

belief(head):

sigmoid(cached_log_odds)

O(1).

43. P0 — Temporal belief prefix

Armazenar:

(lsn, cumulative_log_odds)

Busca:

binary_search(as_of)

Resultado:

sigmoid(prefix[i])

Evitar scan/re-sort de versões.

44. P1 — Temporal interval indexing

Para arestas/fatos com:

valid_from
valid_to

avaliar:

interval tree
segment tree
sorted endpoint index

Não aplicar por padrão sem benchmark.

Objetivo:

AS OF / VALID AT

sem scan amplo.

45. P1 — Leiden over dense graph

Executar Leiden sobre representação densa CSR.

Evitar reconstruir mapa String→usize a cada análise.

Cache/rebuild por geração de grafo.

46. P0 — Sentinel shared dense graph infrastructure

O Sentinel deve reutilizar:

DenseEntityMap
TemporalEdgeStore
CSR
TemporalIntervalIndex

quando os contratos forem compatíveis.

Evitar um segundo ecossistema de grafo String/BTreeMap para o mesmo padrão de problema.

47. P0 — Incremental distillation centroid

Não reconstruir o cluster inteiro após cada inserção.

Criar estado incremental compatível com a geometria escolhida.

Se a geometria exigir centroides específicos, o algoritmo incremental DEVE ser matematicamente validado contra hyp_centroid.

Gate:

distance/centroid error dentro do contrato

48. P1 — ANN over cluster centroids

Quando o nº de clusters superar threshold:

episode
  ↓
centroid ANN
  ↓
candidate centroids
  ↓
exact metric
  ↓
threshold test

Sem alterar membership final.

49. P1 — Activation ring

Substituir deslocamento de ArrayVec por ring fixo.

pub struct RecentRing {
    values: [u64; RECENT_K],
    head: u8,
    len: u8,
}

50. P1 — Activation specialization

Para d = 0.5:

age^-0.5
=
1/sqrt(age)

Adicionar outros fast paths SOMENTE quando matematicamente equivalentes.

51. P0 — Activation Top-K

Substituir full sort por Top-K parcial.

52. P1 — HyperLogLog LUT

Criar LUT de:

2^-r

Eliminar powi por registro.

Fundir:

sum
zero_count

na mesma passagem.

53. P1 — HLL compact registers

Avaliar:

6-bit registers
sparse mode
dense mode

Estilo HLL++.

Formato derivado pode ser versionado independentemente do log canônico.

54. P1 — HLL SIMD merge

Implementar max vetorizado:

AVX2
AVX-512
NEON

para grandes merges.

55. P1 — Count-Min power-of-two width

Quando w for potência de 2:

hash & (w - 1)

em vez de:

hash % w

56. P1 — Count-Min Conservative Update

Avaliar Conservative Update para:

reduzir overestimation;

reduzir largura necessária;

economizar RAM.

Benchmark obrigatório.

57. P1 — Sketch hash benchmark

Comparar:

FNV-1a
xxHash3
WyHash
existing deterministic hash

Requisitos:

fixed version
fixed seed
stable output

Não mudar hash persistido sem versionamento.

58. P0 — Adaptive threshold learner O(n log n)

Substituir avaliação repetida de thresholds por:

sort scores
   ↓
single sweep
   ↓
update TP/FP/FN
   ↓
best F1

Complexidade:

O(n log n)

em vez de O(n²).

Preservar regra de tie-break.

59. P1 — HUME vectorized IR

Adicionar lowering físico SIMD.

Operações candidatas:

Fma
Dot
SqDistance
ReduceSum
MaskedLoad
MaskedStore

A IR lógica não depende da ISA.

60. P1 — Predicate fusion

Transformar:

mask A
materialize
mask B
materialize
AND

em:

load
cmp
cmp
AND registers
emit SelectionVector

61. P1 — JIT direct SelectionVector output

Evitar:

Vec<u8> mask
   ↓
second scan
   ↓
Vec<u32>

Permitir emissão direta:

Bitmap
Index16
Index32

62. P1 — Dictionary GROUP BY

Strings não devem ser chaves físicas no hot loop.

String
 ↓
DictionaryId(u32)

GROUP BY opera sobre IDs.

Texto é materializado no fim.

63. P1 — Radix aggregation

Para alta cardinalidade:

hash
 ↓
radix partition
 ↓
cache-sized partitions
 ↓
local aggregation
 ↓
merge

Autotune radix_bits.

64. P1 — Persistent worker pool

Não criar/destruir threads por operador.

Usar worker pool do runtime.

Morsels entram em fila.

65. P0 — Memtable EventId index

Adicionar:

EventId → slot

para get(id) O(1).

Remover scan reverso do deque.

66. P0 — Memtable tiny text index

Manter postings leves da cauda.

Não executar:

lowercase + matches

sobre todos os episódios a cada query.

67. P0 — Memtable flat SIMD KNN

Para tail pequena:

flat SoA
+
SIMD
+
Top-K

provavelmente vence HNSW.

Medir crossover.

68. P0 — BlockDirectory range binary search

blocks_for_lsn_range deve usar dois partition_point.

Complexidade alvo:

O(log B + K)

69. P1 — BlockDirectoryV2 compact

Avaliar formato derivado/versionado com:

offset deltas
first_lsn deltas
last_lsn deltas
HLC deltas
FOR
bitpack

Não quebrar leitura v1.

70. P0 — HRKI Bloom no-allocation insert

Eliminar qualquer collect::<Vec<_>>() para índices do Bloom.

Iterar diretamente.

71. P1 — Xor/Binary Fuse filters

Benchmark:

Bloom
Xor8
Binary Fuse

para sidecars imutáveis.

Requisitos:

zero false negatives;

FPR declarada;

política de privacidade preservada;

keyed digest quando necessário.

72. P1 — Structural compression before Zstd/LZ4

Pré-transformações reversíveis por bloco:

LSN delta
HLC delta
enum bitpack
bool bitmap
offset FOR
dictionary IDs

Depois:

LZ4/Zstd

Objetivo:

menos bytes
+
menos I/O

73. P1 — SIMD compression kernels

Adicionar kernels para:

delta encode/decode
prefix sum
bit unpack
FOR decode

Medir em GB/s e cycles/value.

74. P0 — Preserve canonical ULEB128

ULEB128 canônico do formato v6 NÃO pode ser substituído silenciosamente.

Permitido:

fast 1-byte path
fast 2-byte path
unrolled decode
batch decode

Mudança de codec exige nova versão de formato.

75. P0 — Streaming packer

O packer deve processar em streaming e memória limitada.

Alvo:

reader
 ↓
bounded queue
 ↓
transform/hash
 ↓
parallel block compression
 ↓
ordered writer

Não materializar um segmento inteiro se não for necessário.

76. P0 — Remove payload clones in packer

Evitar clone de payload por registro.

Usar ownership transfer ou slices/buffers reutilizáveis.

77. P1 — Parallel block compression

Blocos independentes podem comprimir em paralelo.

A escrita final deve preservar a ordem física/canônica definida.

78. P0 — Merkle accumulator preserve

O MerkleAccumulatorV1 streaming DEVE ser preservado salvo prova clara de melhoria.

Ele já possui memória O(log N).

Não “otimizar” para uma árvore que guarda folhas.

79. P0 — Streaming inclusion proof

Substituir construção O(N) em RAM por:

two-pass streaming proof

ou:

block-local proof
+
segment proof

Meta:

O(log N) auxiliary memory

80. P1 — Merkle multiproof

Para várias folhas:

deduplicate shared siblings

Reduz bytes e CPU de auditoria.

81. P0 — Hardware CRC32C

Usar:

SSE4.2 CRC32C
ARM CRC instructions
scalar fallback

Preservar vetor golden.

82. P0 — Read path file-handle reuse

Evitar:

open
seek
read header
seek
...

por leitura pontual.

Usar:

cached handles
pread / FileExt
known segment metadata

83. P0 — Buffered sequential scans

Sequential scan deve usar buffer adequado.

Não assumir mmap como superior.

Benchmark:

BufReader
mmap
direct file

84. P0 — Batched write path

Montar vários registros em buffer reutilizável e reduzir syscalls.

Gate de crash:

kill -9
power-loss simulation
partial write
recovery

85. P0 — AppendBatch protocol

Adicionar API de lote no protocolo.

Não manter “batch” do cliente como loop serial de chamadas unitárias.

Medir:

1
16
64
256
512 inflight
native batch

86. P0 — Raft batching without semantic change

Não alterar matemática do Raft.

Otimizar:

serialization batch
write batch
fsync batch
AppendEntries payload grouping

Ack continua condicionado à durabilidade exigida.

87. P1 — Raft log dense/segmented storage

Avaliar substituir BTreeMap in-memory por estrutura mais adequada a índices quase densos.

Exemplo:

segments
base_index
Vec<Entry>

Truncate/Purge devem continuar eficientes.

88. P1 — Crypto/compliance caches

Permitido:

parsed certificate cache
public key cache
validated chain cache
batch digest
parallel independent verification

Não reimplementar primitivas criptográficas próprias.

89. P0 — Cost Based Optimizer

Implementar CBO real.

Estatísticas:

NDV
frequency
posting length
selectivity
segment stats
vector candidate cost
graph degree

Fontes:

HLL
Count-Min
index counters
zone maps
histograms

90. P0 — Cross-index planning

O planner deve escolher entre:

Attr → Vector → Text
Text → Attr → Vector
Vector → Attr → Graph
Graph → Attr → Text

conforme custo estimado.

91. P0 — Join / filter ordering

Filtros mais seletivos não são automaticamente os mais baratos.

Custo deve considerar:

selectivity
operator CPU
materialization cost
decode cost
cache locality

92. P0 — Cross-modal upper bounds

Implementar branch-and-bound para fusão:

S = αG + βV + γT + δA

Se:

max_possible(candidate) < current_top_k_threshold

o candidato pode ser abandonado.

Aplicável a:

BM25 WAND
HNSW traversal
graph expansion
activation

Sem alterar resultado quando bounds forem exatos/conservadores.

93. P1 — Learned fusion improvement

A fusão pode usar pesos aprendidos, mas o treinamento deve ser offline/determinístico.

Avaliar:

MRR-based weights
logistic regression
coordinate descent
pairwise ranking

Somente se houver dataset e ganho mensurável.

94. P0 — Avoid full sorting globally

Auditar todo workspace por padrões:

sort(...)
truncate(k)
sort_by(...)
take(k)
collect::<Vec<_>>()

Quando objetivo for Top-K, avaliar:

heap
partial selection
streaming threshold
WAND

95. P0 — Allocation audit

Auditar hot paths por:

String::new
to_string
format!
clone
Vec::new
collect::<Vec>
HashMap temporary
BTreeMap temporary

Cada alocação dentro de loops por evento/query deve ser justificada.

Meta:

append hot path → zero/minimal transient allocation
distance hot loop → zero allocation
postings decode → reusable scratch

96. P1 — String interning global

Quando semanticamente adequado, unificar:

agent
field
term
edge type
security entity kind

em dictionaries versionados.

Não internar conteúdo livre arbitrário.

97. P1 — Small-vector optimization

Para coleções tipicamente pequenas:

parents
small provenance
tiny adjacency

avaliar inline storage/SmallVec.

Somente se reduzir heap no workload real.

98. P1 — Cache-aware morsel sizing

Morsels devem considerar largura real de linha, não apenas constantes fixas.

Autotune:

L1
L2
L3
row width
operator type

99. P1 — NUMA awareness

Somente para servidores multi-socket.

Suportar:

pin workers
partition data
local allocations

Feature opcional.

100. P2 — Prefetch

Adicionar software prefetch apenas após provar cache-miss dominante.

Nunca inserir prefetch “porque parece rápido”.

101. P2 — Fast transcendentals

Criar camada opcional:

fast_exp
fast_ln
fast_acos
fast_acosh
fast_tanh

Somente recall aproximado/estimativa.

Cada função declara:

max_abs_error
max_rel_error
domain

102. P2 — Learned index experiments

Para estruturas monotônicas muito grandes, permitir experimento com learned index apenas como acelerador derivado.

Fallback obrigatório:

binary search / B-tree

Nenhum learned model define correção.

103. Gates de corretude

Toda alteração deve rodar:

cargo test --workspace

mais gates específicos.

Storage

append
restart
verify
pack
repack
GC
crash injection
corruption injection

Query

baseline == optimized

para caminhos exatos.

Graph

same edges
same traversal result
same tie-break
same AS OF semantics

Retrieval

exact:
same Top-K

approx:
Recall gate

104. Gate de replay

Para dataset fixo:

build A
restart
replay
build B

Verificar:

state_hash(A) == state_hash(B)
logical_root(A) == logical_root(B)
derived result set equivalent

105. Gate de hardware

Executar quando disponível:

scalar
AVX2
AVX512
NEON
GPU

Estado persistente não pode divergir.

106. Gate de memória

Nenhuma otimização de CPU é automaticamente aceita se aumentar memória.

Reportar:

RSS before
RSS after
peak before
peak after
bytes/event
bytes/index-entry

Para mudanças de layout P0:

RAM reduction target >= 20%

salvo justificativa.

107. Gate de compactação

Para novas representações:

bytes_before
bytes_after
ratio
decode throughput
encode throughput

Não aceitar codec que economiza pouco espaço e destrói leitura.

108. Gate de latência

Não usar apenas média.

Medir:

p50
p95
p99
max

Especialmente:

point lookup
Top-K
append
boot
restore

109. Gate de regressão end-to-end

Criar cenários:

ingest → query → checkpoint → restart → query
ingest → pack → query
ingest → graph → hybrid retrieval
ingest → crash → recover

Uma micro-otimização só entra se o sistema total não piorar de forma relevante.

110. Critério de aceitação de performance

Padrão recomendado:

microbenchmark:
>= 1.10x

hot-path P0:
>= 1.20x

structural:
>= 20% RAM reduction
OR
>= 20% disk reduction
OR
>= 1.5x throughput

Exceções precisam de justificativa.

111. Critério de rejeição

Reverter se:

correctness gate falhar
state hash divergir
logical root divergir
Recall@10 abaixo do gate
p99 piorar > 10% sem ganho estrutural relevante
RAM subir > 10% sem benefício justificável
complexidade de manutenção crescer sem ganho mensurável

112. Sequência obrigatória de execução

A IA deve executar nesta ordem.

Fase A — Baseline

A01 benchmark harness
A02 allocations
A03 RSS
A04 CPU profile
A05 disk size
A06 query latency
A07 recall

Fase B — Quick wins exatos

B01 PreparedQuery
B02 PreparedPoint
B03 dist²
B04 VisitedEpoch
B05 greedy HNSW
B06 Top-K shared
B07 Adaptive F1 sweep
B08 Activation ring/top-k
B09 HRKI no-allocation insert
B10 BlockDirectory binary range

Fase C — Layout / RAM

C01 VectorStore SoA
C02 TermDictionary
C03 AttrDictionary
C04 Dense graph IDs
C05 CSR/CSC
C06 compressed postings
C07 disk-backed views
C08 Bε-tree spill

Fase D — Query algorithms

D01 BMW/WAND
D02 dense BM25 accumulator
D03 SelectionVector specialization
D04 belief cache
D05 temporal prefix
D06 CBO
D07 cross-index planning
D08 cross-modal bounds

Fase E — Storage

E01 CRC hardware
E02 buffered scans
E03 file handle cache/pread
E04 write batching
E05 streaming packer
E06 parallel block compression
E07 BlockDirectoryV2 experiment
E08 structural compression
E09 streaming Merkle proof

Fase F — Quantization

F01 SQ8
F02 PQ
F03 OPQ
F04 Recall gates

Fase G — GPU

G01 resident store
G02 buffer pool
G03 batched queries
G04 GPU Top-M
G05 crossover calibration

Fase H — HUME

H01 SIMD kernels
H02 fused predicates
H03 vector IR
H04 direct SelectionVector output
H05 dictionary GROUP BY
H06 radix aggregation
H07 persistent worker pool

Fase I — Advanced

I01 temporal interval indexes
I02 direction-optimized BFS
I03 bidirectional BFS
I04 Leiden dense
I05 HLL++
I06 Conservative Count-Min
I07 fast transcendentals
I08 NUMA

113. Dependências críticas

Dense IDs
 ├─→ CSR
 ├─→ dense accumulators
 └─→ compact postings

VectorStore SoA
 ├─→ SIMD
 ├─→ SQ8/PQ
 └─→ GPU resident

Compressed postings
 ├─→ BMW/WAND
 └─→ disk-backed TextIndex

Statistics
 ├─→ CBO
 └─→ adaptive operator choice

SelectionVector
 ├─→ filtered ANN
 ├─→ graph filters
 └─→ predicate fusion

A IA NÃO deve implementar dependentes antes da base necessária, salvo branch experimental isolada.

114. Arquivos que exigem atenção especial

A IA deve localizar as versões atuais dos seguintes módulos:

heraclitus-manifold
heraclitus-index-vector
heraclitus-index-text
heraclitus-index-attr
heraclitus-index-graph
heraclitus-activation
heraclitus-retrieval
heraclitus-distill
heraclitus-memtable
heraclitus-gpu
heraclitus-log/v6
heraclitus-btree
heraclitus-raft
heraclitus-sentinel
hume-kernel
hume-ir
hume-sketches
heraclitus-analytics
heraclitus-query

Não assumir que paths antigos continuam válidos. A IA deve inspecionar a árvore antes de editar.

115. Formato obrigatório dos relatórios da IA

Após cada marco:

## OPT-XXX

### Baseline
...

### Gargalo
...

### Hipótese
...

### Alteração
...

### Corretude
...

### Benchmark
...

### Memória
...

### Regressões
...

### Decisão
KEEP / REVERT / EXPERIMENTAL

116. Commits

Cada otimização deve ser isolada quando possível.

Formato recomendado:

perf(vector): replace visited HashSet with epoch table
perf(text): add block-max WAND
perf(graph): add dense CSR snapshot
perf(storage): stream v6 packer

Não agrupar dez mudanças algorítmicas independentes em um único commit.

117. Política de feature flags

Mudanças de alto risco devem entrar inicialmente por feature/config:

hnsw_dense_adjacency
bmw
pq
gpu_topm
disk_backed_views
block_directory_v2
fast_math

Após estabilização, o melhor caminho pode virar default.

118. Observabilidade

Adicionar métricas:

distance_evaluations
hnsw_visited
wand_skipped_blocks
postings_decoded
selection_rep
selection_density
graph_edges_scanned
gpu_h2d_bytes
gpu_d2h_bytes
compression_ratio
view_resident_bytes
spill_reads
spill_writes

Sem observabilidade, o CBO e o autotuning ficam cegos.

119. Autotuning

Autotuning pode escolher:

Top-K strategy
SelectionVector threshold
GPU crossover
morsel size
radix bits
compression block size
ANN ef
PQ candidate multiplier

O perfil deve ser:

hardware-specific
non-canonical
rebuildable

Nunca entra em hashes canônicos.

120. Targets finais sugeridos

Não são promessas comerciais. São metas de engenharia.

Log

RAM:
<= 20 B/evento para índice de localização, se layout permitir

scan:
>= 1M eventos/s em NVMe moderno quando CPU não for gargalo

boot:
sublinear em dados já indexados/manifestados quando possível

Views

Reduzir de ordem de grandeza de:

~2 KB/evento

para alvo inicial:

< 500 B/evento

com progressão futura para:

< 250 B/evento

dependendo de corpus e embeddings.

Text

postings:
2–6 bits/doc delta em casos favoráveis

Top-K:
BMW deve evitar pontuar a maioria dos docs em queries seletivas

Vector

Recall@10 >= 0.99
candidate memory reduction >= 4x com SQ8
PQ optional for >1M vectors

Graph

CSR adjacency:
single-digit bytes/edge quando metadados externos permitirem

121. Definição de DONE

Esta SPEC NÃO está concluída quando todos os itens possuem código.

Ela está concluída quando:

os P0 estão implementados ou formalmente rejeitados por benchmark;

os principais índices podem operar sem residir integralmente em RAM;

o CBO usa estatísticas reais;

os caminhos exatos passam gates de replay;

os caminhos aproximados passam Recall Gates;

storage/recovery passam crash tests;

há benchmarks reproduzíveis antes/depois;

RSS por evento caiu significativamente;

p99 não sofreu regressões injustificadas;

o resultado é documentado no repositório.

122. Regra final para a IA

A IA implementadora deve agir como engenheiro de banco de dados, não como gerador de patches.

A ordem de raciocínio é obrigatória:

1. Qual é o custo assintótico?
2. Qual é o volume de dados movido?
3. Qual é o layout físico?
4. Quantas alocações existem?
5. Quantos cache misses?
6. Há trabalho que pode ser eliminado?
7. Há pruning?
8. Há Top-K sem full sort?
9. Há estrutura densa disponível?
10. Só então: SIMD/GPU.

O objetivo não é obter a maior quantidade de “otimizações”.

O objetivo é produzir um HeraclitusDB:

mais rápido
mais compacto
mais previsível
mais escalável
mais eficiente

sem sacrificar:

determinismo
auditabilidade
replay
integridade
durabilidade
corretude matemática

Nenhum benchmark justifica quebrar o contrato do banco.