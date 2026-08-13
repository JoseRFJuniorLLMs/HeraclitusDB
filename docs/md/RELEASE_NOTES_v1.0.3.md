# HeraclitusDB v1.0.3 — "fable-5"

**Data:** 2026-07-28

Patch **CRÍTICO** sobre a [v1.0.2](RELEASE_NOTES_v1.0.2.md). Fecha quatro
defeitos na **camada de verdade** (o log append-only) encontrados na auditoria
de 2026-07-28 — incluindo **perda silenciosa de registos já confirmados ao
cliente** e **leituras a devolver o episódio errado em builds de release**.

> ### ⚠️ Atualização FORTEMENTE recomendada
> Três destes bugs são silenciosos em produção: não há panic, não há erro no
> log — há dados errados, dados em falta e, no pior caso, um servidor que
> pendura no arranque. Quem escreve com **appends concorrentes** (o caso normal
> de um servidor) está exposto assim que um segmento **rola**.

**Sem mudanças de API nem de formato em disco.** Verificado verde (msvc):
suite completa do workspace **408 passed, 0 failed, 0 ignored** com
`replication`+`analytics`+`tier`+`distill`.

---

## Correções

### Log — o roll de segmento perdia registos já aceites *(CRÍTICO)*

O worker escreve o lote (FASE 2) e só publica o índice no catálogo (FASE 4).
Quando um registo não cabia, `roll_segment` era chamado **a meio da FASE 2** — e
sela o segmento com `catalog.active.index`, isto é, o índice de **antes** do
lote. Duas consequências, ambas silenciosas:

1. o segmento selado ficava com um índice **incompleto**: registos já escritos
   nesse lote desapareciam de `scan`/`read` **apesar de o cliente ter recebido
   ACK**;
2. pior — a FASE 4 colava depois essas entradas ao segmento **novo**, com os
   **offsets do ficheiro antigo**: seeks para o sítio errado, origem dos LSNs
   trocados e do erro `anomalia de payload`.

A perda correlacionava com o **nº de rolls**, não com o tamanho do segmento.
Medido com 8 threads × 100 appends:

| segmento | rolls | scan antes | scan depois | ausentes antes → depois |
|---|---|---|---|---|
| 4 KB | 42 | 171/800 | **800/800** | 125 → **0** |
| 64 KB | 2 | 618/800 | **800/800** | 2 → **0** |
| 1 MB / 64 MB | 0 | 800/800 | 800/800 | 0 → 0 |

Correção: publicar no catálogo as entradas do lote que pertencem ao segmento
prestes a ser selado **antes** de rolar (marcador `pending_index_start`), para
`roll_segment` selar com o índice completo e o segmento novo começar limpo. A
FASE 4 indexa só a cauda; o `committed_lsn` continua a sair do lote inteiro.
*(commit `8cd1af0`)*

### Log — `read(lsn)` devolvia o episódio ERRADO *(CRÍTICO)*

Ambos os caminhos de leitura (container ativo e selado) localizavam a entrada
por **aritmética** (`offset = lsn - base_lsn`), assumindo um índice **denso**.
Essa invariante não se verifica com rolls concorrentes (repro: `entry.lsn=16` na
posição do LSN 19). O único guarda era um **`debug_assert_eq!`**, que o
compilador **remove em release**: em debug havia panic no caminho de leitura, em
**produção devolvia outro registo, em silêncio**. Agora confirma-se
`entry.lsn == lsn` e, se não bater, localiza-se por busca binária (as entradas
são gravadas por ordem de LSN). *(commit `74cad6c`)*

### Log — `scan` entrava em loop infinito *(CRÍTICO)*

`scan_capped` podia girar para sempre a 100 % de CPU. O loop interno tem quatro
`break` que **não movem o cursor** (footer, EOF, `read_exact` falhado,
`scan_lsn > max_lsn`) e devolvem ao loop externo, que reescolhia o **mesmo**
container e refazia o mesmo seek/leitura. Havia ainda o salto
`scan_lsn = max_lsn + 1`, que não avança se houver lacuna entre segmentos.

Impacto: alcançável a partir do **replay de boot** (`ViewRegistry::catch_up`) e
do **`subscribe`** — um servidor podia **pendurar no arranque**. Corrigido com
progresso estrito garantido por iteração externa: a terminação deixa de depender
de metadados consistentes. *(commit `74cad6c`)*

### Views — watermark avanço-só em `graph`, `vector` e `activation`

`Engine::index_applied` **não é atómico** (memtable, views e attr são trancados
em statements separadas), por isso dois appends concorrentes podem aplicar o LSN
6 antes do 5. A v1.0.2 corrigiu o mapa do `ViewRegistry` e o `TextIndex`/
`AttrIndex`, mas os campos `watermark` **próprios** destas três views ainda
faziam insert cru (`= lsn`), regredindo. Esse campo é serializado no snapshot,
logo passava a mentir sobre o que a view cobre; em `activation` é pior, porque
a view **não é idempotente** (`touch` conta cada acesso) e um re-replay contaria
a dobrar. Passam todos a `.max(lsn)`. *(commit `8b23c1c`)*

### Cliente — timeouts de ligação e por chamada

O SDK construía o canal gRPC sem timeout: um servidor inacessível ou pendurado
deixava a chamada **à espera para sempre**. *(commit `df9417e`)*

---

## Testes novos

- `roll_must_not_lose_records` — nenhum registo aceite desaparece, por muitos
  rolls que haja (era o repro do bug, antes `#[ignore]`, agora **verde**).
- `scan_terminates_and_read_never_returns_wrong_lsn` — o `scan` termina sempre e
  o `read` nunca devolve um LSN por outro.
- `no_roll_no_loss` — prova que a perda vinha do **roll**, não da concorrência.
- `out_of_order_apply_does_not_regress_watermark` (activation).

## Refutados na auditoria (verificados no código — não são bugs)

Deadlock por inversão de locks em `index_applied` (os locks são sequenciais,
nunca aninhados) · atomicidade do checkpoint (o lock cobre views+watermarks) ·
`ORDER BY` do motor de query (`total_cmp` + sort estável) · `state_hash` do
grafo (itera `dense.events()` e ordena as out-edges) · `catch_up` (o insert do
watermark é guardado por `*lsn > wm`) · replay do attr no boot (o dedup por
`binary_search` absorve o re-apply).

---

**Instalação/upgrade:** substituir o binário. Formatos de log, checkpoint e WAL
**inalterados** — rolling upgrade seguro, sem migração.

> **Nota para quem corre a v1.0.2 ou anterior:** um log escrito por uma versão
> afetada pode já ter segmentos cujo índice está incompleto. Esta versão deixa
> de *criar* o problema e o leitor deixa de pendurar/mentir, mas registos
> perdidos em rolls antigos continuam invisíveis ao índice — se a integridade
> histórica for crítica, corra `heraclitus verify` e considere um
> `view rebuild` a partir do log.
