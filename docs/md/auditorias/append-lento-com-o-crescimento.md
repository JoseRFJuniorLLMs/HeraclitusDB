# Auditoria: o append do log fica mais lento quanto mais coisas já lá tens

**Data:** 2026-08-16
**Veredicto:** **armadilha de afinação, não teto arquitetural.** O default de
produção (`segment_max_bytes = 256 MiB`) é o valor errado para carga de escrita.
**Não é preciso mexer em código para o resolver** — mas é preciso mexer na
configuração. Ganho medido: **12,5× a 40,7×** a 200 mil registos e **32,0×** a
1 milhão com carga realista (ver a ADENDA no fim, que também delimita o ponto de
cruzamento abaixo do qual a recomendação **piora**).
**Benchmarks:** `crates/heraclitus-log/benches/append_scaling.rs` (o mecanismo) e
`benches/carga_real_1m.rs` (validação a 1M, escrita + leitura)
**Origem:** apareceu de lado, ao instrumentar a geração de dados do benchmark da
SPEC-0042. Não era o que se procurava.

---

## 1. O sintoma

Ao gerar dados para outro benchmark, a escrita degradava-se de forma absurda:

| Registos já no log | appends/s |
|---|---|
| 10 000 | 48 738 |
| 100 000 | 1 915 |
| 1 000 000 | **191** |

Dez vezes mais registos, cem vezes mais tempo. Isso é **O(n²)**.

---

## 2. A causa, e porque é que ela existe

A FASE 4 do worker (`crates/heraclitus-log/src/lib.rs:938`) publica o índice do
segmento ativo por **copy-on-write**:

```rust
let mut updated_entries = Vec::with_capacity(
    old_active_container.index.entries.len() + tail.len(),
);
updated_entries.extend_from_slice(&old_active_container.index.entries); // copia TUDO
for update in tail { updated_entries.push(LsnEntry { .. }) }            // + o lote
```

`LsnEntry` são 32 B. Com 1M entradas, são **32 MB copiados por lote**.

**Isto não é descuido — é uma troca deliberada.** O catálogo é lido por `ArcSwap`
**sem lock nenhum**, e o `read(lsn)` (`lib.rs:1102`) faz acesso **posicional
O(1)** direto ao vetor, com busca binária só como recurso. Um vetor contíguo e
imutável é o que torna a leitura rápida e sem contenção. **O preço dessa leitura
é pago na escrita.**

A conta exata é `O(entradas_no_segmento)` **por lote**, não por append. Com lotes
de tamanho `B`, cada append custa `O(n/B)` e o segmento inteiro custa `O(n²/B)`.

### As duas variáveis que controlam o estrago

1. **`segment_max_bytes`** — quando o segmento sela, o índice ativo reinicia
   (`lib.rs:1964`, `entries: Arc::new(Vec::new())`). **O `n` do quadrático é
   *registos por segmento*, não do log todo.** Segmento maior = quadrático a
   correr durante mais tempo.
2. **Concorrência de escrita** — o worker junta até **128** comandos por lote
   (`lib.rs:651`). Um escritor síncrono (append → esperar ACK → repetir) produz
   lotes de 1 e paga o pior caso sozinho; escritores concorrentes dividem a
   cópia entre si.

Confirmado que **mais nada no append é O(n)**: `record_hashes.push` é O(1)
amortizado e o `merkle_root` só corre na selagem.

---

## 3. Evidência: a curva

200 000 registos de 64 B, um escritor síncrono, débito por janela de 25 000.
Se o custo por append fosse constante, a linha seria plana.

| Janela | 25k | 50k | 75k | 100k | 125k | 150k | 175k | 200k | Degradação |
|---|---|---|---|---|---|---|---|---|---|
| **1 GiB** (nunca sela) | 8 968 | 1 790 | 1 228 | 964 | 769 | 631 | 568 | **506** | **17,7×** |
| **4 MiB** (~7 selagens) | 12 067 | 11 764 | 10 703 | 10 490 | 10 635 | 11 101 | 10 139 | **10 752** | 1,1× |
| **256 KiB** (~100 selagens) | 14 800 | 15 091 | 15 344 | 14 826 | 15 133 | 14 360 | 16 307 | **16 757** | 0,9× |

A linha do segmento grande cai **17,7× em apenas 200 mil registos**. As outras
duas são planas. Isto é a assinatura exata do mecanismo: selar reinicia o índice
e o custo volta ao início.

---

## 4. Evidência: as duas mitigações

| Configuração | appends/s | Ganho |
|---|---|---|
| 1 escritor · segmento 1 GiB | 875 | — *(pior caso)* |
| 1 escritor · segmento 4 MiB | 10 923 | 12,5× |
| 1 escritor · segmento 256 KiB | **15 292** | 17,5× |
| 8 escritores · segmento 1 GiB | 5 661 | 6,5× |
| 8 escritores · segmento 4 MiB | **35 563** | **40,7×** |

As duas mitigações são **independentes e compõem-se**: o tamanho do segmento
corta o `n` do quadrático; a concorrência divide a cópia por até 128 escritas.

---

## 5. A contraprova (e o seu limite)

Encolher o segmento podia limitar-se a **mudar o quadrático de sítio**:
`roll_segment` (`lib.rs:1936`) faz `(*catalog.sealed).clone()` — clona o vetor de
segmentos **selados** a cada selagem, o que é `O(segmentos)` por seal e
`O(segmentos²)` no total.

Por isso a terceira curva usa segmentos de 256 KiB (~100 selagens em vez de ~7).
**Resultado: fica plana (0,9×) e é a mais rápida de todas.** Não existe segundo
quadrático a esta escala.

**Limite honesto desta contraprova:** testou ~100 segmentos. O mecanismo existe e
a escalas muito maiores voltaria a contar. A diferença de peso é grande — o termo
das entradas copia estruturas de 32 B, o dos segmentos clona ponteiros `Arc` de
8 B — mas **isto não foi medido acima de 100 segmentos**. Quem for para volumes
grandes deve validar no volume-alvo, não confiar nesta extrapolação.

---

## 6. Recomendação

### 6.1 Configuração (resolve sem tocar em código)

**Baixar `segment_max_bytes` de 256 MiB para a gama 4–16 MiB.**

- É configurável em `HeraclitusConfig` (TOML ou override `HERACLITUS_*`).
- 4 MiB dá curva plana e 12,5× de ganho, medido.
- 256 KiB é ainda mais rápido, mas multiplica o número de ficheiros — pior para
  backup, handles e operação. 4–16 MiB é o compromisso defensável.
- **Não** descer abaixo de ~1 MiB sem medir: cada selagem custa fsync, criação de
  ficheiro e sync do diretório-pai, custos fixos que este benchmark não isola.

### 6.2 Escrita concorrente (onde for aplicável)

Quem ingere em volume deve usar **vários escritores em paralelo**, para o worker
poder juntar lotes até 128. Vale 6,5× sozinho.

Nota sobre o caso concreto deste repo: o hook `claude-mirror` escreve um turno de
cada vez e espera o ACK — é o pior caso por construção. **Não importa ali**
(volume baixíssimo), mas importa muito na ingestão de logs do Forge.

### 6.3 Correção de código, se a configuração não chegar

Se o volume-alvo tornar a configuração insuficiente, a correção mínima é
**índice em blocos**: em vez de um `Arc<Vec<LsnEntry>>`, um
`Arc<Vec<Arc<[LsnEntry; K]>>>`. Publicar passa a copiar só o vetor de ponteiros
de bloco mais o último bloco parcial, em vez de todas as entradas.

**Preserva as duas propriedades que justificam o desenho atual:**
- leitura continua sem lock (`ArcSwap` sobre a estrutura imutável);
- lookup continua **O(1)** — `bloco = idx / K`, `slot = idx % K`.

Com `K = 4096`, a cópia por lote passa de `n` entradas para `n/4096` ponteiros
mais ≤4096 entradas — cerca de **500× menos** a 2M entradas. Não elimina o
quadrático, reduz-lhe a constante por três ordens de grandeza.

---

## 7. Achados secundários

- **`resolve_lsn_from_consensus_index` (`lib.rs:1053`)** faz varredura **linear**
  do índice ativo (`.iter().rev().find(..)`). É O(n) no caminho de leitura de
  consenso, e sofre exatamente do mesmo crescimento. Não foi medido nesta
  auditoria.
- **O benchmark que já existia não podia apanhar isto.** `benches/append.rs`
  percorre o mesmo código, mas reporta a **média** do criterion — e uma
  degradação progressiva desaparece numa média. Foi por isso que a auditoria
  mede **débito por janela**: é a curva que prova, e é a média que a esconde.
  Lição transferível: para regressões que dependem de estado acumulado, a média
  é a estatística errada.

---

## 8. O que fica por fazer

1. Escolher e aplicar o `segment_max_bytes` de produção (decisão de operação).
2. Validar a curva no **volume real alvo** — esta auditoria mediu 200 mil
   registos e ~100 segmentos.
3. Decidir se `resolve_lsn_from_consensus_index` merece medição própria.

---

# ADENDA — validação a 1 000 000 de registos, com carga realista

**Data:** 2026-08-16
**Benchmark:** `crates/heraclitus-log/benches/carga_real_1m.rs`
**Resultados brutos:** `carga-real-1m-resultados.txt`

A auditoria acima mediu 200 mil registos com payload artificial e recomendou
4–16 MiB **por extrapolação**. A secção 8 deixou isso explícito como trabalho
por fazer. Está feito: 1 milhão de registos, eventos com forma de log de
servidor (8 serviços, 5 níveis, 6 rotas, mensagem de 120–400 B, 3 atributos
por registo em `BTreeMap` serializado por bincode). Média real: **487 B/registo,
486,5 MB em 59 ficheiros**.

## A recomendação confirma-se — e por uma margem maior

| Configuração | appends/s | Curva ao longo de 1M |
|---|---|---|
| segmento **8 MiB** (recomendado) | **12 798** | **plana** (0,8× — acaba mais rápida) |
| segmento **256 MiB** (default) | **399** | degrada **7,4×** |

**Ganho de 32,0× no volume alvo.** 1M registos levam **78 segundos** com 8 MiB e
**42 minutos** com o default.

## A prova causal está visível na curva

Débito da configuração default, por janela de 100 000:

```
1908  675  408  304  226 │ 384  944 │ 489  305  258
                          └── o segmento sela aqui ──┘
```

A 487 B/registo, um segmento de 256 MiB enche-se a ~551 000 registos. O débito
cai monotonamente até à janela dos 400–500k (226 app/s), **sobe para 944** nas
janelas seguintes, e recomeça a cair. Isso é o índice ativo a ser reiniciado
pela selagem, exatamente como a secção 2 previa.

Não é inferência a partir da forma da curva: é o mecanismo a ser observado a
acontecer, no sítio onde a aritmética diz que tem de acontecer.

## Existe um ponto de cruzamento, e agora está delimitado

A mesma bateria com **20 000** registos dá o resultado **inverso**:

| Volume | 8 MiB | 256 MiB | Vencedor |
|---|---|---|---|
| 20 000 registos | 10 109 app/s | 18 393 app/s | **default**, 1,8× |
| 1 000 000 registos | 12 798 app/s | 399 app/s | **8 MiB**, 32× |

Segmentos pequenos **não são grátis**: cada selagem custa fsync, criação de
ficheiro e sync do diretório-pai — um custo fixo pago desde o primeiro registo,
enquanto o quadrático só começa a doer por volta dos 50k. Abaixo do cruzamento,
encolher o segmento **piora**.

A recomendação de 4–16 MiB continua correta para o caso de uso alvo (ingestão
contínua de logs, que passa o cruzamento em minutos), mas a razão tem de ser
dita: não é que segmentos menores sejam sempre melhores; é que este volume está
muito acima do ponto onde passam a ser.

## Leitura: o desenho aguenta-se

| Métrica | Valor |
|---|---|
| `read(lsn)` aleatório, p50 | 68,5 µs |
| p95 / p99 / max | 114,7 µs / 270,5 µs / 14,0 ms |
| débito, um leitor | 12 477 leituras/s |
| `scan` de 100k registos | 1,12 s = 89 639 registos/s |
| `scan_capped` do log inteiro (1M) | 12,22 s = 81 818 registos/s |

### Leitura sob escrita — o teste que valida a troca

O índice é copiado na escrita precisamente para os leitores nunca bloquearem.
Com **4 leitores + 4 escritores** durante 10 s sobre o log de 1M:

| | p50 | p95 | p99 | max |
|---|---|---|---|---|
| leitura **sem** escrita | 68,5 µs | 114,7 µs | 270,5 µs | 14,0 ms |
| leitura **sob** escrita | **73,2 µs** | 156,2 µs | 451,7 µs | 121,4 ms |

**Degradação de p50: 1,07×.** A troca compensa: 414 643 leituras (41 464/s)
concorrentes com escrita, e a latência mediana sobe 7%. **O custo pago na
escrita está a comprar o que prometia.**

Duas ressalvas honestas:
- a **cauda** piora bastante (p99 de 270 µs para 452 µs; máximo de 14 ms para
  121 ms). Quem tiver SLO de cauda tem de medir isto na sua carga;
- a **escrita** é que sofre: 6 170 escritas/s neste teste misto, contra 12 798
  em escrita pura. Sob carga de leitura pesada, o débito de escrita cai ~2×.
  Os leitores ganham a contenção de I/O.

A 20 000 registos a degradação de leitura era 2,87×, não 1,07×. Não se
extrapole a partir de logs pequenos: o efeito **desaparece** à escala real.

## Arranque a frio

```
Log::open sobre 1 061 696 registos: 5,36 s
primeira leitura depois de reabrir:  202,8 µs
```

**5,36 s é o tempo de indisponibilidade num restart do serviço**, e escala com
o nº de registos. Não estava medido em lado nenhum. Merece entrar no plano de
operação antes de alguém reiniciar em produção.

## O que muda na secção 8 (trabalho por fazer)

- ~~Validar a curva no volume real alvo~~ — **feito**: 32× a favor da
  recomendação a 1M, com a causa observada diretamente.
- Continua por fazer: escolher e aplicar o `segment_max_bytes` de produção;
  medir `resolve_lsn_from_consensus_index`.
- **Novo:** a cauda de leitura sob escrita (p99, max) e a queda de ~2× no débito
  de escrita sob carga de leitura merecem medição na carga real, não sintética.
