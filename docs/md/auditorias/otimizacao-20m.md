# Carga de 20 000 000 de registos — relatório e plano de otimização

**Data:** 2026-08-19
**Carga:** `crates/heraclitus-log/benches/carga_real_20m.rs`
**Sondas:** `otim_crc.rs`, `otim_leitura.rs`, `otim_boot.rs` (mesmo crate)
**Resultados brutos:** `carga-real-20m-resultados.txt`
**Antecedentes:** `append-lento-com-o-crescimento.md` (200k → 1M), `carga-real-10m-resultados.txt`

> Nada aqui é argumentado só por leitura de código. Cada otimização proposta
> tem uma sonda que mede o código atual e a alternativa **lado a lado, nos
> mesmos dados reais**, e as duas sondas que mudam semântica verificam a
> igualdade do resultado **antes** de reportar velocidade.

---

## 1. O que foi carregado

20 000 000 de eventos com forma de linha de log de servidor — 8 serviços,
5 níveis, 6 rotas, mensagem de 120–400 B e 3 atributos por registo num
`BTreeMap` serializado por bincode. É o mesmo gerador das corridas de 1M e 10M
já arquivadas, de propósito: trocar os dados tornaria as três corridas
incomparáveis, e a comparação é metade do valor.

| | |
|---|---|
| Registos | 20 000 000 (+392 171 da fase de leitura sob escrita) |
| Log em disco | **9 755,7 MB** em **1 164** segmentos de 8 MiB |
| Média por registo | **488 B** |
| Configuração | `segment_max_bytes = 8 MiB`, `fsync = GroupCommit{1000 ms}` |

### Ambiente — leia isto antes de citar qualquer número absoluto

A máquina **não estava ociosa**: três processos do Claude Code, Antigravity IDE
e LM Studio em simultâneo, num Windows 11 com 8 CPUs lógicos, 31,5 GB de RAM e
um único NVMe SK hynix PC801 partilhado entre `C:` e `D:`. Uma das janelas (a
32.ª, 3 141 app/s) apanhou uma varredura de 4,1 GB feita em paralelo.

Consequência honesta: **os valores absolutos são um piso, não o desempenho da
máquina.** O que é robusto — e é onde as conclusões assentam — é a **forma da
curva** e as **razões entre variantes medidas nas mesmas condições**.

---

## 2. Resultados da carga

### 2.1 Escrita — a curva ficou plana, e é isso que importa

```
débito por janela de 500 000 (40 janelas):
7879  9614 14868 13198 14087 12677 14695 14142 21426 21951
14869 12980 13634 15319 14745 12456 12574  9305  7436 10078
11828  9833 10701 10473 11634  8794 22995 23721 26808 24870
24073  3141 23171  5582 22855 25443 24011 24186 20548 19954
```

**12 533 append/s** no total, 1 595,8 s (26,6 min). Primeira janela 7 879 →
última 19 954: a escrita **acelerou 2,5×** ao longo dos 20 milhões.

Confirmação definitiva da auditoria anterior. Com o default antigo de 256 MiB a
mesma carga degradava monotonamente (a 10M: 695 → 270 app/s, 7,9 horas em vez
de 27 minutos). Com 8 MiB, o quadrático da publicação do índice nunca chega a
doer, porque a selagem reinicia o `n` a cada ~17 000 registos. **O default de
produção está correto e agora está validado no dobro do volume.**

### 2.2 Concorrência — 3,1× com 8 escritores

A fase 5 (4 leitores + 4 escritores durante 10 s sobre o log de 20M já
construído) mediu **39 217 escritas/s** contra as 12 533 do escritor único.

> **Nota de método.** A fase 8 do bench faria 20M de escritas com 8 escritores
> num diretório novo. Não foi executada: custava mais ~10 GB e ~25 min para
> medir o que a fase 5 já mediu no mesmo volume. Está registada como **não
> executada** nos resultados brutos — não como se tivesse corrido.

A auditoria de 200k previu 6,5× para esta mitigação. Mediu-se 3,1× a 20M: a
previsão era otimista, porque a esta escala o worker satura noutro sítio (§3.4).

### 2.3 Leitura

| Métrica | Valor |
|---|---|
| `read(lsn)` aleatório — p50 | **115,50 µs** |
| p95 / p99 / max | 247,20 µs / 409,40 µs / 12,54 ms |
| débito, um leitor | 8 081 leituras/s |
| `scan` de 10 000 | 52,79 ms = 189 443 registos/s |
| `scan` de 100 000 | 622,25 ms = 160 708 registos/s |
| `scan_capped` do log INTEIRO (20M) | **96,81 s** = 206 596 registos/s |

**A leitura pontual regrediu face a 10M** (115,50 µs contra 19,90 µs). A causa
não é o índice — continua O(1) — é o cache de páginas: 9,8 GB de log não cabem
no que o SO tinha livre. Cada leitura passou a ser I/O real. É exatamente o
regime em que o desperdício do §3.3 mais custa.

### 2.4 Leitura sob escrita — a troca continua a compensar

| | p50 | p95 | p99 | max |
|---|---|---|---|---|
| leitura **sem** escrita | 115,50 µs | 247,20 µs | 409,40 µs | 12,54 ms |
| leitura **sob** escrita | **37,20 µs** | 193,10 µs | 310,20 µs | 46,78 ms |

A leitura ficou 3× mais *rápida* com escrita concorrente. Não é magia: a fase 3
varreu o log inteiro imediatamente antes e deixou o cache quente.

O que o teste prova é o que foi desenhado para provar: **62 121 leituras/s em
simultâneo com 39 217 escritas/s, sem os leitores bloquearem**. O índice é
copiado na escrita precisamente para isto, e o custo está a comprar o que
prometia.

### 2.5 Os dois números operacionais que ninguém tinha

| | 10M (medido antes) | **20M (agora)** |
|---|---|---|
| `Log::open` (arranque a frio) | 24,53 s | **50,23 s** |
| `verify()` (auditoria forense) | não medido | **51,93 s** |

**50,23 s é indisponibilidade real num restart do serviço**, e escala
linearmente: 40M seriam ~100 s, 100M ~4 minutos.

O `verify()` percorreu 20 392 171 registos e 1 187 segmentos, confirmando
1 186 raízes Merkle (o 1187.º é o ativo, sem rodapé), em 51,93 s =
**392 718 registos/s**. Auditoria forense completa de 10 GB em menos de um
minuto é um número defensável perante um regulador.

**A §3.2 mostra que ~93 % desse tempo é trabalho desperdiçado.**

### 2.6 RAM — 692 MB para 20M

Pico de working set: **692 MB**, ~35 B por registo. Bate com a aritmética:
`LsnEntry` são 32 B e **o índice de todos os segmentos fica residente em
memória para sempre** (`LogCatalog.sealed`). Isto é o log **sozinho**, sem
nenhuma view derivada (§3.11).

### 2.7 O achado que a auditoria anterior deixou por medir

`resolve_lsn_from_consensus_index` — marcado na secção 7 da auditoria de 200k
como "O(n) por inspeção, não medido":

```
200 chamadas: p50 30,15 ms · p95 40,64 ms · max 82,70 ms
```

**30 milissegundos de mediana.** Está medido (§3.9).

---

## 3. O que otimizar, por ficheiro

### Resumo dos ganhos MEDIDOS

| # | Ficheiro | Otimização | Ganho medido |
|---|---|---|---|
| 1 | `heraclitus-log/src/cpm.rs:284` | CRC-32C por SSE4.2 | **27,3×** no CRC |
| 2 | `heraclitus-log/src/lib.rs:2218` | boot/verify sem desperdício + paralelo | **14,3×** |
| 3 | `heraclitus-log/src/lib.rs:1165` | `read_at` sem re-seek, com cache de fd | **10,3×** |
| 4 | `heraclitus-log/src/lib.rs:1236` | `BufReader` no `scan_capped` | **3,25×** |
| 5 | `heraclitus-server/src/engine.rs:1303` | não reler o disco para o `event_id` | (não medido) |
| 6 | `proto/heraclitus.proto:7` | appends concorrentes / `AppendBatch` | **20,5×** (§3.6) |

### 3.1 `cpm.rs:284` — CRC-32C byte-a-byte · **27,3×**

Desde `FORMAT_VERSION = 5`, **todo registo escrito e todo registo lido** passa
por uma tabela byte-a-byte:

```rust
for &b in data { crc = CRC32C_TABLE[((crc ^ b as u32) & 0xFF) as usize] ^ (crc >> 8); }
```

Está no caminho crítico do worker de escrita (`format::encode_record`,
`lib.rs:786`) e em cada `decode_record` — leitura, scan e `verify()`. O x86-64
tem a instrução `crc32` (SSE4.2) desde 2008, para **exatamente este polinómio**
(Castagnoli `0x1EDC6F41`), 8 bytes por instrução.

```
corretude: identicas em 11 tamanhos + vetor 0xE3069283 ✓

  bloco de 487 B (registo medio real)
    tabela byte-a-byte (atual) :   349 MB/s
    SSE4.2 `crc32` (disponivel):  9544 MB/s   (27,3x)

  Traducao para 20M registos, UMA passagem:
    tabela :  25,4 s de CPU só em CRC
    SSE4.2 :   0,9 s                  (poupança 24,5 s por passagem)
```

São **três passagens** no ciclo de vida normal: escrita, scan completo,
`verify()`. **Risco:** baixo — a sonda confirma igualdade bit-a-bit antes de
medir, e um acelerador que mudasse um bit invalidaria todo o log já selado.
**Esforço:** 1 dia.

### 3.2 `lib.rs:2218` — o arranque a frio faz três coisas inúteis por registo · **14,3×**

`scan_segment_file` é o corpo do `Log::open` **e** do `verify()`. Por cada um
dos 20 milhões de registos, hoje:

```rust
let mut remainder_buf = vec![0u8; remainder_len];          // 1. alocação
let mut record_buf = vec![0u8; RECORD_HEADER_LEN + len];   // 2. segunda alocação + 2 cópias
let (sp, _): (StoragePayload, usize) =
    bincode::serde::decode_from_slice(payload, BINCODE_CFG)?;  // 3. Episode INTEIRO...
sp.opaque_meta                                              //    ...para ler 16 bytes
hashes.push(format::record_leaf(version, &record_buf[..consumed])); // 4. blake3 descartado
```

O ponto 3 desserializa o `content`, o `BTreeMap` de attrs, o `embedding` e os
`parents` — todos alocados — para extrair `opaque_meta`, que é o **primeiro**
campo. O ponto 4 calcula um blake3 cujo resultado é **deitado fora** nos
segmentos selados: aí a raiz vem do rodapé. E o laço percorre os 1 164
ficheiros **em série** (`lib.rs:405`), sendo eles independentes, com 8 núcleos
disponíveis.

```
corretude: opaque_meta == payload[..16] em 500 registos reais ✓

  1. como esta (bincode completo + blake3)   190,81s ·  106 872 reg/s
  2. sem desserializar o Episode              96,54s ·  211 230 reg/s  (1,98x)
  3. + sem blake3 (raiz ja esta no rodape)    66,37s ·  307 261 reg/s  (2,88x)
  4. + em paralelo (8 threads)                13,36s · 1 526 451 reg/s (14,28x)
  5. so paralelizar, sem mais nada            55,03s ·  370 564 reg/s  (3,47x)
```

*(a linha 1 é mais lenta que os 50,23 s do `Log::open` real porque a sonda
correu com a máquina a fazer a carga governamental em simultâneo; o que se lê
aqui são as razões, não os absolutos.)*

Traduzindo para os números da §2.5: **arranque a frio de 50,23 s → ~3,5 s**, e
**`verify()` de 51,93 s → ~3,6 s**.

Nota importante: a linha 5 mostra que **só paralelizar dá 3,47×** — é a metade
do trabalho com o risco mais baixo, porque não muda o que é validado.

**Risco:** (1)(2)(4) baixo; (3) médio — muda o que o boot valida, é uma decisão
de política de durabilidade e deve ser explícita. **Esforço:** 2–3 dias.

### 3.3 `lib.rs:1165` — `read_at` reabre e relê a cada leitura · **10,3×**

Por **cada** leitura pontual:

```rust
let mut f = File::open(&path)?;   // abre o ficheiro
f.seek(SeekFrom::Start(off))?;    // salta para o registo
f.read_exact(&mut rh)?;           // cabeçalho do registo
f.read_exact(&mut buf[..])?;      // corpo
f.seek(SeekFrom::Start(0))?;      // VOLTA AO INÍCIO
f.read_exact(&mut hdr)?;          // relê 22 B só para saber a versão
```

A versão do segmento **já está no catálogo em memória**
(`SegmentMeta.version`, `lib.rs:100`); o `read_at` só não a usa porque recebe
`(seg, off)` em vez do container.

```
  1. como esta (open + seek + re-le cabecalho) : p50 26,30µs ·  22 959 leituras/s
  2. sem reler o cabecalho do segmento         : p50 20,60µs ·  32 250 leituras/s  (1,40x)
  3. + handle reutilizado (cache de fd)        : p50  3,50µs · 236 244 leituras/s  (10,29x)
```

**Risco:** baixo. **Esforço:** 1 dia.

### 3.4 `lib.rs:1236` e `:860` — sem buffer, nos dois sentidos · **3,25×**

**Leitura.** `scan_capped` lê de um `File` cru, com **dois `read_exact` por
registo**. O scan completo do log fez 20M × 2 = **40 milhões de syscalls** em
96,81 s. Não há `BufReader` nenhum.

```
  4. como esta (File cru, 2 read_exact/registo) : 235 941 reg/s · 109 MB/s
  5. com BufReader de 1 MiB                     : 767 419 reg/s · 356 MB/s  (3,25x)
  6. por mmap (zero-copy, hoje desligado)       : 624 805 reg/s · 290 MB/s  (2,65x)
```

**O `BufReader` bate o mmap.** Isto resolve uma questão em aberto: o `mmap.rs`
foi medido em 2026-08-15 contra um leitor **com `BufReader`** e perdeu — mas o
caminho vivo nunca teve buffer. A conclusão certa não era "mmap é mau", era
"falta um `BufReader` no `scan_capped`". Pondo-o, o mmap continua a não valer a
pena, e por uma razão agora medida em vez de assumida.

**Escrita.** Simetricamente, `active.file.write_all(&record)` (`lib.rs:860`)
escreve num `File` cru — **um `write()` por registo**, 20 milhões deles — e
`format::encode_record` (`format.rs:144`) **aloca um `Vec` novo por registo**,
apesar de o `scratch_buffer` ao lado já ser reutilizado. Montar o lote (até 128
registos) num buffer reutilizado e emitir **um** `write_all` por lote ataca
diretamente o teto que a §2.2 revelou.

**Risco:** baixo — o rollback por lote já opera sobre `bytes_written`.
**Esforço:** 2 dias.

### 3.5 `engine.rs:1303` — relê do disco para devolver o que já tem

No append por gRPC **sem** chave de idempotência (o caso normal):

```rust
if key.is_empty() {
    let lsn = self.append(episode)?;
    let id = self.log.read(lsn)?          // <- lê o registo TODO do disco
        .ok_or(...)?.1.id.to_string();    //    para tirar o `id`
    return Ok((lsn, false, id));
}
```

`append_internal` nunca altera o `id` — é gerado por `Episode::new` antes de
chegar aqui. Basta `let id = episode.id.to_string();` antes do move. Como está,
**cada append por gRPC paga uma leitura pontual completa** — incluindo o
re-seek do §3.3 — para devolver um valor que o chamador tinha na mão.

**Risco:** nenhum. **Esforço:** 1 hora. Melhor relação retorno/esforço da lista.

### 3.6 `proto/heraclitus.proto:7` — não existe append em lote · **20,5× medido**

```proto
rpc Append (AppendRequest) returns (AppendResponse);
```

Unário, **um evento por chamada**. O `heraclitus-ingestor` tinha uma flag
`--batch 500`, mas o `enviar_lote` fazia um `for` com `await` a cada evento: o
"lote" era só o tamanho do buffer.

Isto foi medido em produção durante a carga governamental de 2026-08-19
(8,87M linhas de `D:\dados-governo` para o serviço vivo):

| Appends em voo | Débito | ETA para 8,87M |
|---|---|---|
| 1 (serial, como estava) | **86 eventos/s** | 28 horas |
| 16 | 274 eventos/s (3,2×) | 9 h |
| 64 | 748 eventos/s (8,7×) | 3,3 h |
| 256 | **1 760 eventos/s (20,5×)** | 1,4 h |

O escalonamento quase linear diz onde está o gargalo: **latência, não
saturação**. Confirmado por medição direta no servidor durante a carga — CPU
próximo de zero, fila de disco 0,0, 2 MB/s de escrita. Cada append espera a sua
própria janela de fsync, por isso um emissor serial fica preso perto de
`1000/intervalo_ms` **independentemente do hardware**.

Correção aplicada (lado do cliente, sem tocar no servidor):
`heraclitus-client::Client` passou a ser `Clone` (o `Channel` do tonic já
multiplexa HTTP/2, logo clonar não abre outra ligação TCP), e o `enviar_lote`
reparte o lote por `HERACLITUS_INGEST_INFLIGHT` tarefas concorrentes.

Correção estrutural que falta: `rpc AppendBatch (AppendBatchRequest) returns
(AppendBatchResponse)` com `repeated AppendRequest` e **um** `spawn_blocking`
por lote em vez de um por evento (`grpc.rs:90`). **Risco:** baixo (aditivo).
**Esforço:** 3 dias.

### 3.7 Alocação de `String` por evento — padrão sistémico

| Ficheiro | Linha | O quê |
|---|---|---|
| `heraclitus-views/src/lib.rs` | 141 | `watermarks.entry(v.name().to_string())` — **uma `String` por view por evento** (6 views) |
| `heraclitus-index-graph/src/lib.rs` | 220 | `attr_idx.entry(format!("{k}={v}"))` — uma por atributo por evento |
| `heraclitus-index-attr/src/lib.rs` | 219 | `ikey(field, value)` — idem |
| `heraclitus-server/src/engine.rs` | 408 | `memtable.apply(lsn, episode.clone())` — **clone completo do `Episode`** |

A 20M eventos com 3 atributos, só as três primeiras dão ~180 milhões de
alocações que existem durante uma consulta a um `HashMap`.

**O que fazer:** watermarks num `Vec<Lsn>` paralelo ao `Vec<Box<dyn View>>`
(o índice da view é estável); chave composta sem materialização nos índices de
atributos; memtable a receber `Arc<Episode>`.

**Bónus:** o alocador default no Windows é o `HeapAlloc` do sistema. Num
caminho tão alocador-intensivo, `mimalloc` é uma linha
(`#[global_allocator]`). Medir antes de prometer. **Esforço:** 2 dias.

### 3.8 Sem compressão — 9,8 GB para dados que comprimem 5–10×

O `format.rs` não comprime. O `cpm.rs` **define** `FLAG_COMPRESSED` e
`FLAG_PAYLOAD_CODEC` (`cpm.rs:57`, `:61`), mas o caminho vivo não os usa, e o
cold tier também não.

488 B por linha de log — o caso canónico de dados compressíveis (zstd-3 dá
tipicamente 5–10×). Não é só disco: é **menos I/O em cada scan, cada boot e
cada `verify()`**, e a §2.3 mostrou que a esta escala já se está limitado por
I/O. **Risco:** médio (toca no formato). **Esforço:** 1 semana.

### 3.9 `lib.rs:1050` — `resolve_lsn_from_consensus_index` é O(n) sobre o log todo

Medido: **p50 30,15 ms, max 82,70 ms** (§2.7). Quando o índice ativo não tem
correspondência, varre linearmente o índice de **todos os 1 164 segmentos
selados** — 20 milhões de entradas. Num log que não seja de raft,
`opaque_meta[8..16]` são bytes de ULID (aleatórios), pelo que o pior caso é o
caso normal.

O próprio código documenta o trait como legado ("0 callers fora do crate"), mas
está exposto na API pública e é o caminho que protege truncates de consenso.

**O que fazer:** índice lateral `raft_index → lsn`, ou remover a superfície
legada (o consenso real usa `append_replicated` + `FileRaftLog`).
**Esforço:** 1–2 dias.

### 3.10 `lib.rs:1937` — `roll_segment` clona e reordena a cada selagem

```rust
let mut new_sealed = (*current_catalog.sealed).clone();   // O(segmentos)
new_sealed.push(...);
new_sealed.sort_by_key(|c| c.meta.base_lsn);              // O(s log s), JÁ ordenado
```

O `sort_by_key` é **puramente redundante** — os segmentos são criados por ordem
monotónica de `base_lsn` e o `push` mantém-na. Tirá-lo é grátis. O `clone()` é
O(s) por selagem → O(s²) no total; a 1 164 segmentos não dói, a 12 000 volta a
contar. **Esforço:** 1 hora.

### 3.11 Estrutural — os índices derivados são 100 % residentes em RAM · **~2 KB/evento, MEDIDO**

O log sozinho custou 692 MB a 20M (§2.6) — ~35 B por registo. Com as **views
ligadas** o custo é outra ordem de grandeza, e agora está medido: durante a
carga governamental de 2026-08-19, com as 6 views + índice de atributos ativos:

```
1 349 193 eventos  ->  servidor a 2 728 MB de RSS  =  ~2,02 KB por evento
```

**~57× mais caro por evento do que o log sozinho.** Extrapolando linearmente
(as estruturas são todas lineares no nº de eventos): 8,87M eventos exigem
**~18 GB**, e 20M exigiriam **~40 GB** — mais RAM do que a máquina tem.

Por leitura de código, onde é que isso vai:

- `heraclitus-index-text`: `postings: HashMap<String, Vec<(u32,u32)>>`, mais
  `ids`, `lsns`, `doc_len` e `by_event` **por evento** — >700 MB a 20M só nas
  estruturas por evento, antes das postings dos termos;
- `heraclitus-index-attr`: um `Vec<Lsn>` por par (campo, valor) — ~640 MB;
- `heraclitus-index-graph`: `attr_idx` com uma `String` `"k=v"` por par.

Nada tem teto nem spill para disco. É por isso que existe
`HERACLITUS_LOG_ONLY`, que desliga as views (`engine.rs:1415`) — e é por isso
que o modo existe: sem ele, uma carga massiva não cabe em memória.

**É o verdadeiro limite de escala do produto.** Os §3.1–§3.10 são otimizações;
este é um teto. Com ~2 KB/evento, a RAM da máquina fixa quantos eventos o
`Engine` completo consegue servir — na desta auditoria (31,5 GB, partilhados),
algures entre 7 e 10 milhões.

O épico: índices com spill para disco (o `heraclitus-btree` já existe no
workspace) e postings comprimidas (`roaring` **já é dependência**). Enquanto
isso não existir, a receita operacional para cargas grandes é a que o código já
prevê — ingerir com `HERACLITUS_LOG_ONLY=1` e reconstruir as views depois, a
partir do log, que é a fonte da verdade.

---

## 4. O que NÃO mexer

- **`segment_max_bytes`.** Está em 8 MiB e a §2.1 validou-o no dobro do volume
  anterior. Não descer sem medir: abaixo de ~50k registos por segmento o custo
  fixo da selagem domina.
- **Ligar o `mmap` ao scan sequencial.** Agora medido em condições justas
  (§3.4): `BufReader` 3,25× contra mmap 2,65×. A decisão de o deixar desligado
  estava certa — mas pela razão errada, e agora está pela razão certa.
- **A cópia do índice na escrita.** É o que compra 62 121 leituras/s
  concorrentes com escrita (§2.4). A correção certa é o índice em blocos
  (`Arc<Vec<Arc<[LsnEntry; K]>>>`, secção 6.3 da auditoria anterior), que
  reduz a constante sem sacrificar a leitura sem lock.

---

## 5. Plano sugerido

**Semana 1 — o barato e o certo.**
§3.5 (`event_id` sem releitura, 1 h), §3.10 (`sort` redundante, 1 h),
§3.1 (CRC por hardware, **27,3×**), §3.3 (`read_at`, **10,3×**).
Nada toca no formato do disco.

**Semana 2 — o boot e o verify (§3.2).**
Buffer reutilizado, prefixo em vez de desserialização, blake3 só onde é preciso,
paralelizar por segmento. **14,3×** — os 50,23 s de indisponibilidade passam a
~3,5 s. Se só houver tempo para uma coisa, paralelizar sozinho já dá 3,47×.

**Semana 3 — o débito de escrita.**
§3.4 (um `write` por lote + `BufReader`), §3.6 (`AppendBatch`), §3.7 (as
`String` por evento).

**Depois — decisões de produto.** §3.8 (compressão) e §3.11 (índices com
spill). Ambos exigem medição própria antes de qualquer promessa.

---

## 6. O que fica por fazer

1. Medir o `Engine` completo (views ligadas) a 1M, para dimensionar §3.11.
2. Repetir a carga numa máquina ociosa, para converter o piso da §2 em
   desempenho real.
3. Decidir a política do §3.2(3): o boot deve continuar a recalcular o blake3
   de segmentos já selados, ou confiar no rodapé e deixar isso para o
   `verify()`? É uma escolha de durabilidade, não de desempenho.
