# `compression.rs` — ligado ao caminho de storage (2026-08-15)

> **Estado anterior deste documento:** os codecs existiam, funcionavam e tinham
> testes, mas eram *"primitivas de referência — não estão ligadas ao caminho de
> storage vivo"*. O diagnóstico estava certo: **o motor estava na bancada e
> faltava ligá-lo às rodas.** Este documento regista como foi ligado e o que se
> aprendeu ao fazê-lo.

## O que faltava

Os codecs (`rle`, `delta`, `frame_of_reference`, `bitpack`) são primitivas: quem
chama tem de saber qual usar, com que largura de bits, e guardar essa escolha
algures para conseguir ler de volta. Faltava a peça do meio.

Novo módulo **`compression::column`**:

```text
coluna de u64  ->  analisa  ->  escolhe  ->  [tag|meta|payload]  ->  disco
                              RLE / Δ+bitpack / FOR+bitpack / cru
```

`column::encode` mede os candidatos e devolve o menor, num blob autodescritivo.
`column::decode` reverte sem contexto nenhum.

## Onde foi ligado

No **índice de atributos** (`heraclitus-index-attr`), cujos postings são LSNs em
ordem crescente estrita — o caso exato em que delta+bitpack ganha.

O checkpoint passou a `attr_index.bin` v2: magic `HATR` + versão + bincode. Os
ficheiros v1 (bincode cru) **continuam a ser lidos** — sem isso, o primeiro
arranque depois da mudança deitaria fora um checkpoint válido e reconstruiria o
índice por replay: correto, mas caro e silencioso.

## O ganho, medido

| Perfil do índice | v1 | v2 | |
| --- | ---: | ---: | ---: |
| Postings longos (10 valores × 50k eventos) | 149.634 | 25.364 | **−83,0%** |
| Misto (1 valor comum + 20k quase únicos) | 587.395 | 530.427 | −9,7% |
| Quase únicos (50k valores distintos) | 888.396 | 888.404 | −0,0% |
| **Real, nesta máquina** (180 eventos, 507 colunas) | 23.049 | 22.983 | −0,3% |

A leitura honesta: **à escala atual isto não faz diferença nenhuma.** O maior
posting real tem 137 LSNs. O ganho aparece quando os postings crescem — e é aí
que 83% deixa de ser um número de laboratório.

## Três coisas que só se souberam medindo

O caminho até aos números acima passou por três versões erradas. Cada uma parecia
óbvia antes de ser medida.

**1. Comprimir tudo fez o ficheiro CRESCER** — 587 KB → 1,09 MB. O bincode já
codifica inteiros em varint: uma lista de um LSN pequeno custa-lhe 1–2 bytes,
enquanto o cabeçalho autodescritivo do codec custa 9 antes de qualquer dado. Num
índice de atributos, a maioria dos postings é curta.

> A garantia de não-expansão do `column::encode` é **contra um array de `u64`
> crus**. Quando o baseline é o bincode, essa garantia não se aplica — e é fácil
> não ver isso.

**2. Escolher por coluna com um `enum` ainda expandiu 5,6%** no caso de valores
quase únicos: o discriminante custa **um byte por coluna**, e com 50.000 colunas
minúsculas isso sozinho domina. A solução foram dois mapas — `exact_plain` e
`exact_packed` — onde uma chave vive num ou no outro, sem tag nenhuma.

> Num ficheiro dominado por metadados, a autodescrição paga-se em bytes.

**3. O primeiro teste de ganho estava a medir a coisa errada.** Assertava 4× de
redução num índice cujo peso era 20.000 *chaves de texto*, não postings. Passou a
haver dois testes: um que exige ganho grande onde a compressão se aplica, e outro
que exige que nunca piore onde não se aplica.

## Dois bugs que os testes novos apanharam

Estavam no código que este documento dava como *"funciona e possui testes"*:

- **`delta::encode` transbordava** com `u64` grandes (hashes, ids aleatórios,
  `u64::MAX`): `v as i64` fica negativo e a subtração estoura — pânico em debug
  e, pior, resultado silenciosamente errado em release. Passou a aritmética
  envolvente, que é total e continua exatamente invertível.
- **`bitpack::unpack` entrava em pânico** com um `count`/`bits` maiores do que as
  palavras disponíveis. Como esses valores vêm do disco, a validação passou a
  acontecer na fronteira, no `column::decode`, antes de qualquer alocação.

## O que continua por ligar

O `column` está ligado ao índice de atributos. **Não** está ligado a:

- `heraclitus-index-text` — os postings `(doc, tf)` são o mesmo tipo de coluna e
  o `text.ckpt` é o maior dos checkpoints depois do vetorial;
- `heraclitus-tier` — o tier frio escreve Parquet, que já traz compressão própria;
  ligar aqui seria redundante e provavelmente pior;
- o log (`.hrkl`) — é o registo imutável e comprimi-lo mexeria com o caminho de
  verificação Merkle. Decisão de dono, não de implementação.

O próximo passo natural é o índice de texto, pelo mesmo caminho e com o mesmo
cuidado: medir antes de assumir.
