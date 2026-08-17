# Auditoria: o append do log fica mais lento quanto mais coisas já lá tens

**Data:** 2026-08-16
**Veredicto:** **armadilha de afinação, não teto arquitetural.** O default de
produção (`segment_max_bytes = 256 MiB`) é o valor errado para carga de escrita.
**Não é preciso mexer em código para o resolver** — mas é preciso mexer na
configuração, e o ganho medido é de **12,5× a 40,7×**.
**Benchmark:** `crates/heraclitus-log/benches/append_scaling.rs`
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
