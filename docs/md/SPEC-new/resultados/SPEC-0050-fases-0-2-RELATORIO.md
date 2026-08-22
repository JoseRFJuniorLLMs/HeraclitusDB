# SPEC-0050 (HRKL v6) — Fases 0 a 2 implementadas

**Data:** 2026-08-21
**Âmbito:** `crates/heraclitus-log/src/v6/` + testes
**Estado:** Fases 0, 1 e 2 do roadmap de §197–§199 fechadas e verdes.

---

## 1. Auditoria das SPECs (contra o `SPEC-RESUMO.md`)

### 1.1 O que existe em disco

`docs/md/SPEC-new/` contém:

| Ficheiro | Nota |
| --- | --- |
| `SPEC-000.md` | Fundações |
| `SPEC-0036.md` … `SPEC-0041.md` | 6 ficheiros |
| `SPEC-0042.md` … `SPEC-0049.md` | 8 ficheiros |
| `SPEC-HRKL-0050.md` | **é a SPEC-0050** — o nome no disco não é `SPEC-0050.md` |
| `SPECs 0051.md` | **não consta do resumo** |
| `SPEC-HUME.md`, `STATUS.md` | apoio |
| `resultados/SPEC-0042-marco0-*` | veredicto do benchmark |

### 1.2 Três divergências face ao resumo

1. **`SPEC-0050.md` não existe com esse nome.** O ficheiro chama-se
   `SPEC-HRKL-0050.md`. Foi esse o implementado.
2. **`SPEC-0001` a `SPEC-0035` não têm ficheiro nesta pasta.** O resumo dá-as
   como "Concluídas / Mapeadas"; o registo dessas está em `PLANO-SPECS.md` e
   `STATUS.md`, não em `SPEC-new/`. Não há aqui nada a implementar, mas o resumo
   promete ficheiros que não estão nesta pasta.
3. **`SPECs 0051.md` existe e o resumo não a menciona.** É o roadmap
   pós-0050 ("Sovereign Security Intelligence Platform"), com fases P0/P1.
   Vale a pena acrescentá-la ao resumo com estado *Proposta*.

### 1.3 Estado real

| SPEC | Estado |
| --- | --- |
| 0001–0041 | Concluídas / mapeadas |
| 0042 | Concluída (veredicto em `resultados/`) |
| 0043 | Concluída / mapeada |
| 0044 | Proposta — por implementar |
| 0045 | Proposta — por implementar |
| 0046 | Proposta — por implementar |
| 0047 | Proposta — por implementar |
| 0048 | Proposta — por implementar |
| 0049 | Proposta — suíte de qualificação por executar |
| **0050** | **Fases 0–2 implementadas** (este relatório); Fases 3–8 em aberto |
| 0051 | Proposta (fora do resumo) |

---

## 2. O que ficou implementado

Módulo novo `crates/heraclitus-log/src/v6/`, 15 ficheiros, ~6 200 linhas.

### Fase 0 — Contratos (§197)

| Ficheiro | Conteúdo |
| --- | --- |
| `varint.rs` | ULEB128 **canónico**: rejeita forma longa, overflow, >10 bytes e EOF parcial (§138–§139) |
| `canonical.rs` | `CanonicalRecordV1`, `CanonicalRecordCodecV1`, `CanonicalRecordHasherV1` (§8–§15) |
| `merkle.rs` | `MerkleAccumulatorV1` streaming O(log N) + provas de inclusão (§16–§18, §122) |
| `error.rs` | Tectos de alocação e fatiamento verificado (§137, §140–§141) |

Decisões que valem a pena registar:

- **Um só codec, dois destinos.** O `CanonicalSink` faz com que o encoder de
  buffer (golden vectors, provas) e o hasher incremental (hot-path) partilhem a
  mesma gramática. §27 proíbe duas implementações da serialização lógica; aqui
  não há como divergirem sem o compilador ir junto.
- **`opaque_meta` entra na identidade** (§8), ao contrário do rascunho anterior.
- **Tags de `EventKind` explícitos e permanentes** (0x01–0x08, §11): a identidade
  deixa de depender do discriminante posicional do Serde, que se desloca sempre
  que alguém insere uma variante a meio do `enum`.
- **A raiz de Merkle não conhece blocos** (§16). Se conhecesse, repackar com
  blocos de 1 MiB em vez de 256 KiB mudaria a raiz — e a equivalência lógica
  entre gerações, que é o que autoriza o GC do RAW, deixaria de poder ser
  afirmada. Folhas ímpares **promovem** (não duplicam), e a raiz final sela o
  `leaf_count`, o que fecha a ambiguidade estilo CVE-2012-2459.

### Fase 1 — HRKL v6 RAW (§198)

| Ficheiro | Conteúdo |
| --- | --- |
| `header.rs` | `FileHeaderV6`, **64 bytes exactos**, codec manual, CRC-32C |
| `footer.rs` | `FooterV6`, **128 bytes exactos**, CRC cobre também os `reserved` |
| `raw.rs` | Registo RAW (24 B de overhead), writer, scan, reparo de cauda rasgada |

- O hot-path mantém-se deliberadamente simples (§25): sem varints, sem
  compressão, sem dicionários. A poupança agressiva acontece depois do seal.
- O estado *sealed* não vive no header (§24) — é a existência de um footer
  válido que o define, o que evita reescrever bytes já sincronizados.
- `repair_active_tail` **recusa-se** a truncar um segmento selado (§123).

### Fase 2 — HRKL v6 PACKED (§199)

| Ficheiro | Conteúdo |
| --- | --- |
| `compress.rs` | Codecs 0/1/2, perfis fast/balanced/archive, RAW fallback a 0.92 (§32–§34) |
| `block.rs` | `BlockHeaderV1` (64 B), delta de HLC, LSN contíguo, restart points (§28–§40) |
| `block_directory.rs` | `BlockDirectoryEntryV1` (56 B), busca binária, zone maps (§49–§51) |
| `packed.rs` | Writer, `BlockSource`, reader com point lookup e `ScanCounters` (§76–§77, §116) |
| `packer.rs` | Transacção de §88 (16 passos) + repack de §188 |
| `receipts.rs` | `AttestationEnvelopeV1`, `PackReceipt`, `PhysicalGeneration` (§19, §71–§72, §86–§87) |
| `verify.rs` | Níveis FAST/PHYSICAL/LOGICAL/FORENSIC, `prove --lsn`, `inspect` (§119–§124, §161) |

Pontos onde a implementação toma posição:

- **Num restart point os valores vão absolutos, não em delta.** Foi um bug real
  apanhado pelos testes: com delta zero, o varrimento sequencial perdia o HLC ao
  atravessar a fronteira. Custa ~4 bytes por 64 registos e torna o bloco
  navegável tanto de frente como por salto.
- **`base_hlc` é o mínimo do bloco, não o HLC do primeiro registo.** Num bloco
  `HLC_ABSOLUTE` (§6) um registo pode recuar no tempo; usar o primeiro como
  limite inferior do zone map produziria um falso negativo de pruning —
  exactamente o que o invariante 8 proíbe.
- **O packer não reinterpreta payloads** (§42, §47). Recebe um `CanonicalHasher`
  de fora e trata os bytes como opacos: nunca decifra, nunca depende de
  `bincode` nem de qualquer geração de `StoragePayload`.
- **Publicar exige releitura.** O passo 9 de §88 não confia no que o writer
  tinha em memória: reabre o ficheiro temporário, recalcula a raiz a partir do
  disco e só então faz `rename`. Um `hasher` divergente aborta sem publicar.

---

## 3. Verificação

```text
cargo test  -p heraclitus-log        123 testes verdes
  unit (src/v6/**)                   101
  tests/hrkl_v6_golden.rs              9
  tests/hrkl_v6_props.rs              13
cargo clippy --all-targets           0 avisos
```

### Golden vectors (§165)

Congelados: bytes do `CanonicalRecordCodecV1` (3 vectores), `FileHeaderV6`,
`FooterV6`, registo RAW com CRC, entrada do directório e o **corpo
descomprimido** de um bloco.

**Não** congelados: os bytes comprimidos. §167 é explícito — a identidade lógica
não depende de o Zstd produzir os mesmos bytes entre versões, e um golden vector
sobre a saída do compressor transformaria uma actualização de biblioteca num
falso alarme de corrupção.

### Property tests (§164), corpus de §152

Sete perfis de dados (repetitivo, realista, incompressível, embeddings, alta
cardinalidade, payloads grandes, cifrado). `HRKL_V6_CORPUS=20000000` corre o
item 8 de §152; o default são 30 000 registos.

| Propriedade | Estado |
| --- | --- |
| `RAW decode == PACKED decode` | ✅ |
| `RAW logical_root == PACKED logical_root` | ✅ |
| `pack(pack(x))` logicamente equivalente a `pack(x)` | ✅ |
| `unpack(pack(x)) == logical x` | ✅ |
| Codec/block size diferentes, mesma raiz lógica | ✅ |
| Pruning nunca produz falso negativo | ✅ |
| Input malformado nunca entra em pânico | ✅ |
| HRKI pruning / HRKI corrupto | — Fase 4 |
| Legacy decode preserva eventos | — migração v1–v5 |

### Gates de §153–§159

| Gate | Alvo | Medido |
| --- | --- | --- |
| §156 metadados por registo | ≥ 60% abaixo dos 24 B do RAW | **3,66 B/registo** (85% abaixo) |
| §157 point lookup | ≤ 1 bloco descomprimido | **1 bloco**, provado pelos `ScanCounters` |
| §155 dados incompressíveis | expansão ≤ 2% | **≤ 1,8%** |
| §158 range selectivo | menos blocos **e** menos bytes lidos | **< 25% dos bytes** do scan completo |
| §159 boot | sem varrimento integral | `open()` lê header + footer + directório |
| §153 hot write | regressão ≤ 3% vs v5 | **por medir** — precisa do bench `carga_real_20m` contra v5 |
| §154 compressão | ≤ 50% no corpus operacional | **por medir com Zstd real** (ver §5) |

---

## 4. Alterações fora do módulo

Três diffs mínimos:

```diff
Cargo.toml (workspace)
+ zstd = "0.13"
+ lz4_flex = { version = "0.11", default-features = false, features = ["std"] }

crates/heraclitus-log/Cargo.toml
+ zstd = { workspace = true }
+ lz4_flex = { workspace = true }
+ ulid = { workspace = true }        # dev-dependency, para os golden vectors

crates/heraclitus-log/src/lib.rs
+ pub mod v6;
```

Nada de existente foi tocado. O caminho v5 continua intacto — o v6 é aditivo até
que a Fase 3 ligue o writer.

**Antes do primeiro commit:** `cargo build -p heraclitus-log` para actualizar o
`Cargo.lock` (o CI usa `--locked`).

---

## 5. Uma ressalva honesta sobre a compressão

O módulo foi desenvolvido e verificado num ambiente sem acesso ao registo de
crates, portanto `zstd` e `lz4_flex` foram exercitados através de *stubs* com as
assinaturas públicas reais (`zstd::bulk::{compress, decompress}`,
`lz4_flex::block::{compress, decompress}`). Toda a lógica de blocos, deltas,
directório, raízes e transacção foi validada; o que **não** foi executado contra
as bibliotecas verdadeiras foram essas quatro chamadas, isoladas em
`compress.rs`.

Consequências práticas:

- Se alguma assinatura divergir, a correcção são duas linhas num ficheiro.
- Os rácios de §154 medidos aqui vêm do stub e **não** são representativos.
  Correr `cargo test -p heraclitus-log --test hrkl_v6_props compressao -- --nocapture`
  com o Zstd real dá os números verdadeiros por perfil de corpus.

---

## 6. O que falta na SPEC-0050

| Fase | Âmbito | Dependências já prontas |
| --- | --- | --- |
| 3 — Manifest Generations (§200) | evoluir `DatabaseManifest` para `.hrkm`, máquina de estados, commit crash-safe, política de GC | `PhysicalGeneration`, `GenerationState`, `physical_digest`, `PackReceipt` |
| 4 — HRKI (§201) | absorver o `.zmap`, zone maps, Bloom, bitmap de `EventKind`, política de confidencialidade | `BlockDirectory` já dá o pruning por LSN/HLC |
| 5 — Object Storage (§202) | chaves imutáveis, range reads, `DemotionReceipt v2` | `BlockSource` é a fronteira; falta o `impl` para `object_store` |
| 6 — Lakehouse (§203) | exportador Parquet, proveniência, watermark, Iceberg, Delta, Arrow | `for_each_record` é o ponto de entrada |
| 7 — `PackedEpisodeV1` (§204) | codec físico estruturado, dicionários adaptativos | `PayloadEncoding` fica atrás do mesmo `logical_root` |
| 8 — Indexação avançada (§205) | Xor/BinaryFuse, HLL, histogramas | — |

Fora do roadmap mas necessário para fechar §210: os comandos de CLI
(`inspect`, `verify`, `prove`, `pack`, `rebuild-index`, `export`,
`storage doctor`). A lógica já existe em `verify.rs`; falta o *wiring* em
`heraclitus-cli`.

---

## 7. Sugestão de ordem para o próximo passo

1. `cargo build` + correr a suíte com o Zstd real, e registar os rácios de §154.
2. **Fase 3** antes da Fase 4: sem manifesto com gerações, o packer produz
   ficheiros que ninguém sabe que existem, e o GC de §90–§93 não tem sobre o que
   decidir. É a fase que transforma isto de biblioteca em comportamento do motor.
3. Só depois ligar o writer do log ao `RawSegmentWriter` v6 (§130: selar a cauda
   legada e começar um segmento v6 novo, nunca continuar a acrescentar v6 a um
   ficheiro legado).
