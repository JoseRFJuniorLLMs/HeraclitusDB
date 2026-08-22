# SPEC-0050 - HRKL v6: Canonical Storage, Packed Segments, Sidecar Indexes & Lakehouse Architecture

**Status:** Proposed / Implementation Contract
**Prioridade:** P0
**Classe:** Core Storage / Persistence / Compression / Query Pruning / Lakehouse
**Formato alvo:** HRKL v6
**Toolchain:** Rust Stable
**Compatibilidade de leitura:** HRKL v1-v6
**Formato padrão de escrita após ativação:** HRKL v6

**Crates primários:**

* `heraclitus-log`
* `heraclitus-core`
* `heraclitus-tier`

**Integrações obrigatórias:**

* `heraclitus-query`
* `heraclitus-analytics`
* `heraclitus-compliance`
* `heraclitus-forensic`
* `heraclitus-cli`
* `hume-kernel`
* DataFusion

---

# 0. Decisão Arquitetural

O HRKL v6 formaliza uma nova separação entre:

1. **verdade lógica canônica**;
2. **codificação física dos segmentos**;
3. **estruturas derivadas de busca**;
4. **projeções analíticas interoperáveis**.

A regra fundamental é:

> **Nenhum registro lógico canônico pode desaparecer do histórico do HeraclitusDB. A representação física desse histórico pode ser reorganizada, comprimida ou substituída por outra representação comprovadamente equivalente.**

Portanto:

```text
Canonical History
        │
        ├── HRKL RAW
        │
        ├── HRKL PACKED
        │
        └── HRKL ARCHIVED
                 │
                 │ mesmas CanonicalRecords
                 │ mesma logical_root
                 ▼
             mesma verdade
```

Essa regra substitui uma interpretação excessivamente rígida de:

> "os bytes físicos originais nunca podem ser removidos".

O que jamais pode ser removido é a **última representação canônica verificável de um segmento**.

Uma geração RAW antiga poderá ser coletada por GC depois que uma geração PACKED equivalente tiver sido:

* completamente escrita;
* sincronizada;
* validada;
* vinculada à mesma `logical_root`;
* registrada no manifesto;
* protegida contra leitores concorrentes;
* liberada por política de retenção;
* liberada por `LegalHold`.

Para segmentos HRKL v1-v5 cuja prova criptográfica histórica depende dos bytes físicos antigos, aplicam-se regras de migração específicas definidas nesta SPEC.

---

# 1. Objetivos

O HRKL v6 deverá atingir simultaneamente os seguintes objetivos.

## 1.1 Escrita

Preservar o caminho de escrita do HeraclitusDB como:

```text
serialize
   ↓
append
   ↓
CRC32C
   ↓
write
   ↓
fsync/group commit
   ↓
commit LSN
```

A compressão pesada jamais entra no hot-path de `append()`.

---

## 1.2 Armazenamento

Reduzir significativamente:

* overhead de metadados por registro;
* repetição de LSN;
* repetição de HLC;
* strings recorrentes;
* redundância estrutural;
* custo de armazenamento cold;
* bytes transferidos de object storage.

---

## 1.3 Leitura

Permitir:

* leitura sequencial rápida;
* leitura pontual por LSN;
* `AS OF LSN`;
* `AS OF TIMESTAMP`;
* range scans;
* block pruning;
* segment pruning;
* consultas sobre object storage usando range reads;
* recuperação sem descompactação do segmento completo.

---

## 1.4 Integridade

Separar formalmente:

```text
integridade física
        │
        └── CRC32C

identidade física
        │
        └── physical_digest

identidade lógica
        │
        └── CanonicalRecord hash

proveniência
        │
        └── segment logical Merkle root
```

---

## 1.5 Interoperabilidade

Permitir projeção determinística para:

* Apache Parquet;
* Apache Arrow;
* Arrow IPC;
* Arrow Flight;
* Apache Iceberg;
* Delta Lake;
* DataFusion;
* DuckDB;
* Spark;
* Trino;
* Databricks.

Sem transformar Parquet, Iceberg ou Delta na fonte de verdade do banco.

---

# 2. Não objetivos

A SPEC-0050 NÃO pretende:

* substituir o log por Parquet;
* escrever Iceberg diretamente no hot-path;
* tornar `.hrki` necessário para recuperar dados;
* transformar `.hrkm` em implementação proprietária do protocolo Iceberg;
* descompactar um segmento inteiro para uma leitura pontual;
* alterar retroativamente segmentos v1-v5;
* permitir compaction destrutiva do histórico canônico;
* permitir que otimizações físicas alterem a identidade lógica dos registros;
* tornar HNSW, BM25, grafos ou Parquet autoritativos.

---

# 3. Estado Atual HRKL v5

O HRKL v5 possui conceitualmente:

```text
[Segment Header]

magic          : "HRKL"
format_version : u16
segment_id     : u64
created_hlc    : u64


[Record]

len            : u32
crc32c         : u32
lsn            : u64
hlc            : u64
payload        : StoragePayload


[Footer]

magic          : "HFTR"
record_count   : u64
min_lsn        : u64
max_lsn        : u64
blake3_root    : [u8; 32]
```

O `RecordHeader` atual possui:

```text
4 + 4 + 8 + 8 = 24 bytes
```

por registro.

O payload v4+ contém:

* `opaque_meta`;
* `EventId`;
* `agent_id`;
* `session_id`;
* `ts_hlc`;
* `EventKind`;
* `content`;
* `embedding`;
* `attrs`;
* `parents`;
* `valid_from`;
* `valid_to`.

---

# 4. Problemas Identificados

## 4.1 Metadados repetidos

Cada registro paga novamente:

```text
len    4 bytes
crc    4 bytes
lsn    8 bytes
hlc    8 bytes
-------------
      24 bytes
```

Para um registro médio relativamente pequeno, isso é significativo.

---

## 4.2 LSN altamente compressível

Dentro de um segmento normal:

```text
9000001
9000002
9000003
9000004
...
```

O LSN é essencialmente:

```text
first_lsn + ordinal
```

na maioria dos casos.

Armazenar um `u64` completo por registro é desnecessário quando a sequência é contígua.

---

# 5. Novo Invariante de Contiguidade de LSN

Segmentos canônicos v6 DEVERÃO preferencialmente satisfazer:

```text
max_lsn - min_lsn + 1 == record_count
```

Nesse modo:

```text
lsn(record_n) = first_lsn + n
```

e nenhum LSN precisa ser persistido dentro do registro PACKED.

Será mantido um modo alternativo:

```text
SPARSE_LSN
```

para futuros casos em que a contiguidade não possa ser garantida.

Nesse modo, o registro utilizará `lsn_delta` em varint.

Portanto:

```text
CONTIGUOUS_LSN:
    bytes de LSN/record = 0

SPARSE_LSN:
    bytes de LSN/record = varint(delta)
```

---

# 6. HLC Monotônico e Delta Encoding

O HRKL já depende da monotonicidade temporal por LSN para funcionalidades temporais.

No v6:

```text
HLC0
HLC1
HLC2
...
```

será representado como:

```text
base_hlc
delta_1
delta_2
delta_3
...
```

utilizando unsigned varint.

O encoder DEVE rejeitar uma codificação `HLC_DELTA_MONOTONIC` caso encontre:

```text
HLC[n] < HLC[n-1]
```

Nesse caso poderá utilizar um encoding alternativo explicitamente sinalizado.

---

# 7. Três Identidades Diferentes

Essa distinção é obrigatória.

## 7.1 Logical Record Hash

Identidade do evento lógico.

Independente de:

* RAW;
* PACKED;
* Zstd;
* LZ4;
* block size;
* posição física;
* dictionary encoding;
* object storage.

---

## 7.2 Segment Logical Root

Raiz criptográfica dos `CanonicalRecord`s ordenados por LSN.

Deve ser idêntica em:

```text
segment RAW
segment PACKED
segment local
segment S3
segment GCS
segment reconstruído
```

desde que todos representem exatamente os mesmos registros lógicos.

---

## 7.3 Physical Digest

Hash dos bytes físicos do objeto específico.

Exemplo:

```text
RAW physical_digest     != PACKED physical_digest

RAW logical_root        == PACKED logical_root
```

Isso é intencional.

---

# 8. CanonicalRecord v1

O rascunho anterior omitiria `opaque_meta`.

Isso NÃO é permitido.

Se `opaque_meta` afeta recuperação, indexação ou semântica interna, modificá-lo deve alterar a identidade lógica.

Contrato:

```rust
pub struct CanonicalRecordV1 {
    pub lsn: Lsn,
    pub record_hlc: u64,
    pub opaque_meta: [u8; 16],
    pub episode: Episode,
}
```

---

# 9. CanonicalRecordCodec v1

A identidade lógica NÃO pode depender diretamente de:

* `bincode`;
* `serde`;
* layout Rust;
* `repr(C)`;
* ordem incidental de enum;
* padding;
* arquitetura da CPU.

Será criado:

```text
CanonicalRecordCodecV1
```

com encoding formal e estável.

---

# 10. Princípios do Codec Canônico

Todo campo deverá possuir:

* ordem fixa;
* endianness definida;
* encoding definido;
* representação determinística;
* ausência de padding;
* ausência de dependência de ABI.

Inteiros fixos:

```text
Little Endian
```

Comprimentos:

```text
ULEB128 / unsigned varint canônico
```

Strings:

```text
length(varint)
UTF-8 bytes
```

Coleções:

```text
count(varint)
items...
```

---

# 11. EventKind Canônico

A identidade lógica não poderá depender do discriminante automático do Serde.

Deverão ser definidos tags explícitos e permanentes.

Exemplo:

```text
0x01 Observation
0x02 Action
0x03 Message
0x04 RetrievalFeedback
0x05 FactDerived
0x06 DemotionReceipt
0x07 Custom
0x08 SystemMetric
```

`Custom`:

```text
tag
string_len
string_bytes
```

Um tag publicado jamais poderá mudar de significado.

Novos kinds recebem novos valores.

---

# 12. Attributes Canônicos

`attrs` devem ser codificados em ordem lexicográfica.

Como o tipo atual é `BTreeMap`, essa propriedade já é natural, porém ela será formalizada no codec.

```text
attribute_count
key_0
value_0
key_1
value_1
...
```

---

# 13. Parent IDs

`parents` serão codificados na ordem persistida.

Caso no futuro a ordem seja declarada semanticamente irrelevante, isso exigirá uma nova versão do codec canônico.

O v1 NÃO reordena parents.

---

# 14. Floats em ProductPoint

Cada `f32` será convertido para representação IEEE-754 estável.

Regras:

```text
-0.0  -> +0.0

NaN payloads ->
canonical quiet NaN

demais valores ->
bits IEEE-754 originais
```

Dimensões são codificadas explicitamente:

```text
hyp_count
hyp[]

sph_count
sph[]

euc_count
euc[]
```

Nenhuma estrutura Rust é despejada diretamente em disco.

---

# 15. Hash Canônico

A leaf lógica deve usar domain separation.

Conceitualmente:

```text
leaf =
BLAKE3(
    "HRKL6:CANONICAL_RECORD:V1" ||
    CanonicalRecordCodecV1(record)
)
```

O prefixo impede reutilização acidental do mesmo hash em outros domínios.

---

# 16. Merkle Root Canônica

A raiz do segmento NÃO poderá depender da divisão física em blocos.

Isto é fundamental.

Errado:

```text
root(
   root(block0),
   root(block1),
   root(block2)
)
```

caso alterar o tamanho dos blocos possa alterar a árvore final.

Correto:

```text
leaf(record0)
leaf(record1)
leaf(record2)
...
        │
        ▼
Canonical Merkle Accumulator
        │
        ▼
segment_logical_root
```

A divisão em blocos é exclusivamente física.

---

# 17. MerkleAccumulatorV1

Será definida uma implementação streaming determinística.

Propriedades:

* ordem por LSN;
* memória O(log N);
* sem necessidade de manter todas as leaves em RAM;
* domain separation entre leaf e internal node;
* algoritmo formalmente versionado.

Exemplo conceitual:

```text
Leaf:

BLAKE3(
  "HRKL6:MERKLE:LEAF" ||
  canonical_record_hash
)

Node:

BLAKE3(
  "HRKL6:MERKLE:NODE" ||
  left ||
  right
)
```

A regra de tratamento de número ímpar de folhas deverá ser definida uma única vez e testada com golden vectors.

---

# 18. Auxiliary Block Roots

Cada bloco poderá armazenar uma raiz auxiliar para:

* verificação localizada;
* forensic proof;
* reparo;
* cache.

Porém:

> **block roots não definem a identidade do segmento.**

A autoridade permanece:

```text
segment_logical_root
```

---

# 19. Attestation Envelope

Para RFC3161, ICP-Brasil ou outro mecanismo de timestamping, não deverá ser assinado apenas um hash solto.

Será criado um envelope lógico:

```text
AttestationEnvelopeV1 {
    storage_namespace_id,
    segment_id,
    canonical_codec_version,
    first_lsn,
    last_lsn,
    record_count,
    logical_root,
}
```

O timestamp/imprint será calculado sobre a representação canônica desse envelope.

Assim um root não poderá ser transplantado silenciosamente para outro segmento ou banco.

---

# 20. Namespace Persistente do Banco

Cada banco deverá possuir:

```text
storage_namespace_id: [u8; 16]
```

imutável durante sua existência lógica.

Ele identifica o namespace criptográfico do storage.

Segmentos importados explicitamente de outro banco devem passar por operação de import/migration, não simplesmente ser copiados para o diretório e aceitos como nativos.

---

# 21. Ciclo de Vida de Segmento v6

Novo estado lógico:

```text
ACTIVE_RAW
     │
     ▼
SEALED_RAW
     │
     ▼
PACKING
     │
     ▼
SEALED_PACKED
     │
     ▼
ARCHIVED
```

Possíveis estados excepcionais:

```text
PACK_FAILED
CORRUPT
QUARANTINED
LEGAL_HOLD
SUPERSEDED
```

---

# 22. O Seal NÃO Deve Esperar a Compressão

O writer deverá:

1. finalizar o segmento RAW;
2. escrever seu footer;
3. sincronizar;
4. abrir imediatamente o próximo segmento ACTIVE;
5. publicar a rotação;
6. delegar packing do segmento anterior ao background worker.

Portanto:

```text
append thread
     │
     ├── seal RAW
     │
     ├── rotate
     │
     └── continua escrevendo

packer thread
     │
     └── RAW -> PACKED
```

A compressão não bloqueia novos appends.

---

# 23. Layout HRKL v6 - FileHeader

Nenhum tipo persistido usará `#[repr(C)]` como especificação de disco.

Será feito codec manual.

O `FileHeaderV6` terá exatamente **64 bytes**.

```text
Offset Size  Campo

0      4     magic = "HRKL"
4      2     format_version = 6
6      2     header_len = 64

8      1     physical_layout
9      1     canonical_codec
10     2     flags

12     8     segment_id
20     8     created_hlc
28     8     first_lsn

36     8     writer_epoch

44     16    storage_namespace_id

60     4     header_crc32c
```

---

# 24. PhysicalLayout

```rust
pub enum PhysicalLayout {
    Raw = 0,
    Packed = 1,
}
```

O estado "sealed" NÃO será representado mutando o header.

A existência de um footer válido determina que o arquivo está selado.

---

# 25. RAW Record v6

O hot-path continuará deliberadamente simples.

```text
payload_len     u32
record_crc32c   u32
lsn             u64
hlc             u64
payload         bytes
```

Overhead:

```text
24 bytes/record
```

Isso é intencional.

O v6 não tentará economizar alguns bytes no hot-path ao custo de:

* branches adicionais;
* varint encoding;
* compressão;
* dictionary maintenance;
* pior recovery.

A economia agressiva ocorre após o seal.

---

# 26. CRC do RAW Record

O CRC32C deverá proteger:

```text
payload_len
lsn
hlc
payload
```

ignorando o próprio campo `crc`.

A implementação atual acelerada por hardware deverá ser reutilizada.

---

# 27. RAW Logical Hash

Durante append, o writer deve alimentar um:

```text
CanonicalRecordHasherV1
```

sem necessidade de alocar um buffer canônico completo.

A API deverá suportar hashing incremental:

```rust
hasher.write_u64(...);
hasher.write_string(...);
hasher.write_bytes(...);
```

O codec e o hasher DEVEM compartilhar as mesmas primitivas canônicas.

É proibido manter duas implementações independentes da serialização lógica.

---

# 28. Layout HRKL PACKED

Estrutura:

```text
┌──────────────────────────┐
│ FileHeaderV6             │
├──────────────────────────┤
│ Optional Dictionary      │
├──────────────────────────┤
│ Block 0                  │
├──────────────────────────┤
│ Block 1                  │
├──────────────────────────┤
│ ...                      │
├──────────────────────────┤
│ Block N                  │
├──────────────────────────┤
│ Block Directory          │
├──────────────────────────┤
│ FooterV6                 │
└──────────────────────────┘
```

O `.hrkl` PACKED deve continuar legível sem `.hrki`.

---

# 29. Block Target

Default:

```text
256 KiB uncompressed
```

Configuração permitida:

```text
minimum: 64 KiB
default: 256 KiB
maximum: 1 MiB
```

O limite deve ser tunável.

---

# 30. Motivo do Block Compression

Nunca:

```text
compress(segment_256MB)
```

Preferir:

```text
segment
├── 256KiB block
├── 256KiB block
├── 256KiB block
├── ...
```

Isso permite:

* range reads;
* paralelismo;
* block cache;
* block pruning;
* bounded decompression;
* menor amplificação de leitura;
* object-store range GET.

---

# 31. BlockHeaderV1

O header de bloco terá **64 bytes exatos**, manualmente codificados.

```text
Offset Size Campo

0      4    magic = "HBLK"
4      2    header_len = 64
6      1    compression_codec
7      1    flags

8      4    uncompressed_len
12     4    compressed_len
16     4    record_count

20     2    restart_interval
22     2    restart_count

24     8    first_lsn
32     8    last_lsn

40     8    base_hlc
48     8    max_hlc

56     4    block_crc32c
60     4    dictionary_id
```

Nada de padding implícito.

---

# 32. CompressionCodec

```text
0 = RAW
1 = ZSTD
2 = LZ4_RAW
```

IDs publicados nunca serão reutilizados.

---

# 33. Perfis de Packing

## FAST

```text
codec = LZ4_RAW ou Zstd level 1
```

Objetivo:

* mínimo CPU;
* warm tier;
* leitura de baixa latência.

---

## BALANCED

Default:

```text
codec = Zstd level 3
```

Objetivo:

* boa densidade;
* boa velocidade de decode;
* custo de packing aceitável.

---

## ARCHIVE

Exemplo:

```text
codec = Zstd level 6
```

Executado apenas fora do hot-path.

---

# 34. Raw Fallback Adaptativo

Nem todo dado comprime.

Se:

```text
compressed_size >= raw_size * threshold
```

o bloco deverá ser armazenado como:

```text
CompressionCodec::RAW
```

Default sugerido:

```text
threshold = 0.92
```

Ou seja, exigir pelo menos aproximadamente 8% de economia antes de aceitar a versão comprimida.

Isso impede que dados incompressíveis fiquem maiores.

---

# 35. Registro PACKED

Dentro do bloco descompactado:

```text
record_meta
hlc_delta
[lsn_delta]
payload
```

---

# 36. Tagged Record Meta

Em vez de:

```text
len varint
flags u8
```

será utilizado:

```text
record_meta = (payload_len << FLAG_BITS) | flags
```

Exemplo com 3 bits de flags:

```text
bits 0..2 = flags
bits 3..  = payload_len
```

Assim `len + flags` normalmente ocupa um único varint.

---

# 37. LSN no Packed

Se:

```text
CONTIGUOUS_LSN
```

não haverá bytes de LSN por registro.

Cálculo:

```text
record_lsn = block.first_lsn + record_ordinal
```

Se:

```text
SPARSE_LSN
```

será persistido:

```text
lsn_delta: varint
```

---

# 38. HLC no Packed

Primeiro registro:

```text
block.base_hlc
```

Registros seguintes:

```text
hlc_delta = current_hlc - previous_hlc
```

armazenado como varint.

---

# 39. Restart Points

Delta encoding não pode tornar uma leitura pontual dependente de escanear milhares de registros anteriores.

Cada bloco terá restart points.

Default:

```text
restart_interval = 64 records
```

Cada restart deverá guardar ao menos:

```text
record_ordinal
byte_offset
absolute_hlc
```

Assim:

```text
LSN
 ↓
ordinal
 ↓
restart anterior
 ↓
scan <= 63 registros
```

---

# 40. Large Records

Um registro maior que o `block_target` NÃO será dividido entre blocos por padrão.

Será criado:

```text
LARGE_RECORD_BLOCK
```

contendo um único registro.

Isso simplifica:

* recuperação;
* random access;
* integridade;
* compressão;
* provas.

O hard limit continuará explicitamente configurado e validado.

---

# 41. Payload Encoding

O PACKED suportará inicialmente duas representações.

```text
PayloadEncoding::LegacyStoragePayload
PayloadEncoding::PackedEpisodeV1
```

---

# 42. Fase Inicial Segura

Na primeira implementação, o packer poderá manter o payload existente intacto:

```text
bincode StoragePayload bytes
```

e apenas aplicar:

* block framing;
* remoção de LSN redundante;
* HLC delta;
* block compression;
* block directory.

Isso reduz drasticamente o risco da primeira entrega.

---

# 43. PackedEpisodeV1

A fase seguinte poderá introduzir uma representação física estruturada específica para PACKED.

Isso NÃO altera a identidade lógica porque:

```text
CanonicalRecordCodecV1
```

permanece independente da representação.

---

# 44. Dictionary Encoding

Dictionary encoding será **adaptativo**, não obrigatório.

Candidatos:

* attribute keys;
* `agent_id`;
* `session_id`;
* `EventKind::Custom`;
* valores textuais altamente repetidos.

---

# 45. O Dicionário Não Deve Piorar o Arquivo

Antes de materializar dictionary encoding, o packer estimará:

```text
bytes_without_dictionary

vs.

dictionary_bytes +
encoded_references
```

Só ativará caso exista ganho mínimo configurado.

Sugestão:

```text
minimum_dictionary_saving = 5%
```

---

# 46. Dicionário Local vs Segment-Level

Primeira implementação:

```text
block-local dictionary
```

Vantagens:

* bloco autossuficiente;
* range read simples;
* menos dependências.

Futuro opcional:

```text
segment dictionary
```

apenas se benchmarks demonstrarem ganho material.

---

# 47. Criptografia e Dictionary Encoding

O packer trabalha sobre a representação persistida.

Ele NÃO deve:

* descriptografar campos;
* extrair segredos para sidecars;
* criar dicionários com plaintext sensível que não existia publicamente no storage.

A ordem é:

```text
logical event
     ↓
field encryption
     ↓
persisted logical representation
     ↓
packing
```

e nunca:

```text
packing
     ↓
decrypt
```

---

# 48. Block CRC32C

O CRC deverá validar simultaneamente:

* header físico do bloco;
* compressed payload.

Conceitualmente:

```text
CRC32C(
    BlockHeader with crc=0 ||
    stored_block_bytes
)
```

Assim corrupção em:

* codec;
* lengths;
* ranges;
* payload comprimido;

é detectada.

---

# 49. Block Directory

O PACKED terá um índice físico mínimo obrigatório dentro do próprio `.hrkl`.

Isso NÃO pertence ao `.hrki`, porque o segmento precisa continuar navegável sem qualquer sidecar.

Cada entrada conterá:

```text
block_offset
stored_length
uncompressed_length
record_count
flags
first_lsn
last_lsn
min_hlc
max_hlc
```

---

# 50. BlockDirectoryEntryV1

Encoding explícito:

```text
offset              u64
stored_len          u32
uncompressed_len    u32
record_count        u32
flags               u32
first_lsn           u64
last_lsn            u64
min_hlc             u64
max_hlc             u64
```

Total:

```text
56 bytes
```

---

# 51. Por Que Duplicar Alguns Campos?

Apesar de os mesmos campos existirem no `BlockHeader`, o diretório permite descobrir:

* offsets;
* tamanhos;
* LSN;
* HLC;

sem abrir cada bloco.

É um índice de navegação física.

---

# 52. FooterV6

Footer fixo de 128 bytes.

```text
magic                   [u8;4] = "HFTR"
footer_version          u16
footer_len              u16

record_count            u64

min_lsn                 u64
max_lsn                 u64

min_hlc                 u64
max_hlc                 u64

block_count             u32
flags                   u32

block_directory_offset  u64
block_directory_len     u64

logical_root            [u8;32]

footer_crc32c           u32

reserved                [...]
```

Campos `reserved` devem ser zerados no writer e ignorados por readers compatíveis.

---

# 53. Physical Digest

O `physical_digest` não deverá ser autorreferencial dentro do próprio objeto.

Ele será armazenado:

* em `SegmentGeneration`;
* no manifesto;
* no receipt de demotion/packing.

```text
physical_digest =
BLAKE3(entire physical file)
```

---

# 54. `.hrki` - HRKL Index Sidecar

Novo sidecar:

```text
00000000000000000421.hrkl
00000000000000000421.hrki
```

O `.hrki` é:

* opcional;
* derivado;
* reconstruível;
* descartável;
* versionado;
* vinculado ao `logical_root`.

---

# 55. Migração do `.zmap`

O `.zmap` existente NÃO continuará como uma segunda família permanente de índices.

O `.hrki` absorverá sua função.

Migração:

```text
existing .zmap
      │
      ├── importável
      │
      └── ou reconstruído do .hrkl
              ↓
             .hrki
```

Após validação, `.zmap` pode ser removido.

---

# 56. HRKI Header

Deverá conter no mínimo:

```text
magic = "HRKI"

version

segment_id

canonical_codec_version

segment_logical_root

index_policy_hash

section_count
```

Um `.hrki` cujo `logical_root` não corresponda ao segmento deve ser ignorado.

Nunca tratado como corrupção do `.hrkl`.

---

# 57. Sections do `.hrki`

Arquitetura extensível:

```text
HRKI
├── Section Directory
├── Segment Statistics
├── Block Zone Maps
├── Equality Filters
├── EventKind Bitmap
├── Attribute Metadata
├── Optional Cardinality Sketches
└── Checksums
```

Cada section terá:

```text
section_type
section_version
offset
length
crc32c
```

---

# 58. Zone Maps

Baseline:

```text
LSN
HLC
valid_from
valid_to
```

Campos adicionais apenas se configurados como seguros.

---

# 59. Zone Maps por Bloco

Exemplo:

```text
Block 33

LSN:
  900000 .. 900511

HLC:
  1760000100 .. 1760000450

valid_time:
  ...
```

Consulta:

```sql
WHERE hlc > 1765000000
```

pode eliminar o bloco antes de:

* range read;
* decompress;
* decode.

---

# 60. Filtros de Igualdade

Bons candidatos:

```text
event_id
entity_id
session_id
tenant_id
content_hash
```

Não utilizar Bloom/Xor para campos cuja consulta predominante seja range.

---

# 61. Filtro Baseline

A implementação obrigatória inicial será um Bloom Filter imutável.

Versões futuras poderão suportar:

```text
Xor8
BinaryFuse
```

sem mudar o `.hrkl`.

---

# 62. FPR Configurável

Default recomendado:

```text
false positive rate <= 1%
```

Campos particularmente seletivos poderão usar:

```text
0.1%
```

A ausência de falso negativo é inegociável.

---

# 63. EventKind Bitmap

`EventKind` possui cardinalidade pequena.

Utilizar um bitmap é melhor que Bloom filter.

Exemplo:

```text
bit 0 Observation
bit 1 Action
bit 2 Message
...
```

Custom kinds poderão usar filtro/dicionário separado.

---

# 64. Segurança do `.hrki`

Sidecars são uma potencial fonte de vazamento.

Zone maps de strings podem expor:

* IDs;
* nomes;
* sessões;
* tenants;
* atributos privados.

Portanto:

> **o HRKI não persiste automaticamente min/max de strings arbitrárias.**

---

# 65. Index Metadata Policy

Configuração:

```text
PUBLIC_TECHNICAL
HASHED_EQUALITY
ENCRYPTED_SIDECAR
DO_NOT_INDEX
```

---

# 66. Keyed Equality Filters

Para identificadores sensíveis poderá ser utilizado:

```text
keyed_blake3(index_key, canonical_value)
```

antes de inserir no filtro.

Assim o sidecar não precisa guardar o identificador em plaintext.

---

# 67. Arbitrary attrs

Por padrão:

```text
attrs.* -> DO_NOT_INDEX
```

Somente campos declarados explicitamente ou promovidos por política poderão ganhar estatísticas persistentes.

---

# 68. `.hrkm` - Manifesto Interno

`.hrkm` NÃO significa "arquivo Iceberg".

Ele é o manifesto interno do Heraclitus.

Sua função:

* catálogo de segmentos;
* generations;
* localização física;
* logical roots;
* derived artifacts;
* estados;
* watermarks;
* retenção.

---

# 69. Reutilização do DatabaseManifest

Não deverá surgir um segundo catálogo concorrente ao `DatabaseManifest`.

A SPEC-0050 deverá evoluir:

```text
heraclitus_core::DatabaseManifest
```

para que `.hrkm` seja sua representação persistente.

---

# 70. SegmentDescriptorV2

Conceitualmente:

```rust
pub struct SegmentDescriptorV2 {
    pub segment_id: SegmentId,

    pub first_lsn: Lsn,
    pub last_lsn: Lsn,
    pub record_count: u64,

    pub canonical_codec: u16,
    pub logical_root: [u8; 32],

    pub active_generation: u32,

    pub generations: Vec<PhysicalGeneration>,

    pub hrki: Option<DerivedArtifactRef>,
    pub parquet: Option<DerivedArtifactRef>,

    pub retention: RetentionPolicy,
}
```

---

# 71. PhysicalGeneration

```rust
pub struct PhysicalGeneration {
    pub generation: u32,

    pub layout: PhysicalLayout,

    pub compression: CompressionCodec,

    pub location: String,

    pub physical_size: u64,

    pub physical_digest: [u8; 32],

    pub state: GenerationState,
}
```

---

# 72. GenerationState

```text
WRITING
VERIFIED
ACTIVE
SUPERSEDED
ARCHIVED
QUARANTINED
```

---

# 73. Uma Verdade, Várias Gerações

Exemplo:

```text
Segment 88
logical_root = ABC...

generation 0:
    RAW
    256 MB
    digest = XXX
    SUPERSEDED

generation 1:
    PACKED ZSTD
    79 MB
    digest = YYY
    ACTIVE

generation 2:
    ARCHIVE ZSTD
    71 MB
    digest = ZZZ
    ARCHIVED
```

Todos:

```text
logical_root == ABC
```

---

# 74. Manifest Snapshots

Macro-alterações devem produzir uma nova geração de manifesto.

```text
manifest-0000000001.hrkm
manifest-0000000002.hrkm
manifest-0000000003.hrkm
CURRENT
```

O arquivo `CURRENT` aponta para a geração válida.

---

# 75. Commit do Manifesto

Filesystem:

```text
write manifest.tmp
fsync(manifest.tmp)
rename(manifest.tmp, final)
fsync(directory)

write CURRENT.tmp
fsync(CURRENT.tmp)
rename(CURRENT.tmp, CURRENT)
fsync(directory)
```

O manifesto antigo permanece válido durante toda a operação.

---

# 76. Multi-Level Pruning

Pipeline:

```text
Query
  │
  ▼
Manifest pruning
  │
  ▼
Segment stats/filter
  │
  ▼
Block pruning
  │
  ▼
Block directory
  │
  ▼
Range read
  │
  ▼
CRC32C
  │
  ▼
Decompress
  │
  ▼
Restart point
  │
  ▼
Record decode
  │
  ▼
Predicate execution
```

---

# 77. Point Lookup por LSN

```text
LSN = 98,712,556
        │
        ▼
HRKM binary search
        │
        ▼
segment 193
        │
        ▼
BlockDirectory binary search
        │
        ▼
block 71
        │
        ▼
range read block
        │
        ▼
decompress 256 KiB
        │
        ▼
ordinal = LSN - first_lsn
        │
        ▼
restart point
        │
        ▼
record
```

Nenhum outro bloco precisa ser lido.

---

# 78. `AS OF LSN`

O planner elimina imediatamente:

```text
segment.first_lsn > target_lsn
```

O último segmento necessário pode ser truncado logicamente no target.

---

# 79. `AS OF TIMESTAMP`

Utiliza:

* manifest HLC ranges;
* block HLC ranges;
* monotonic HLC;
* binary search quando aplicável.

---

# 80. Block Cache

Novo cache opcional:

```text
DecompressedBlockCache
```

Key:

```text
(
  segment_id,
  logical_root,
  physical_generation,
  block_index
)
```

Nunca apenas:

```text
segment_id + block
```

porque generations físicas podem mudar.

---

# 81. Cache Eviction

Deverá integrar-se aos mesmos contratos de orçamento e lifecycle de artifacts.

Eviction:

* LRU/TinyLFU inicialmente;
* bounded memory;
* nunca causa perda;
* nunca impede leitura fallback.

---

# 82. Object Storage

PACKED HRKL é especialmente adequado a object storage.

Exemplo:

```text
canonical/
  <namespace>/
    segment-0000000088/
      <logical-root>/
        generation-1.hrkl
```

---

# 83. Object Keys Imutáveis

Uma geração publicada não deve ser sobrescrita.

Nova representação:

```text
nova generation
```

e não:

```text
PUT sobre o mesmo objeto
```

---

# 84. ETag Não É Hash Canônico

Nunca assumir:

```text
ETag == content hash
```

A autoridade será:

```text
physical_digest
logical_root
```

calculados pelo Heraclitus.

---

# 85. Cold Range Reads

Recall do cold tier deve evoluir de:

```text
baixar segmento inteiro
```

para:

```text
read footer/directory
        ↓
identify blocks
        ↓
object_store range GET
        ↓
download only matching blocks
```

quando o backend oferecer range reads.

---

# 86. DemotionReceipt v2

Novo receipt deverá incluir:

```text
segment_id

generation

first_lsn
last_lsn
record_count

canonical_codec_version

logical_root

physical_digest

physical_size

physical_layout

compression_codec

object_path

hrki_path?

parquet_path?

source_generation?

created_hlc
```

---

# 87. PackReceipt

Transformar:

```text
RAW -> PACKED
```

é um evento auditável.

```text
PackReceipt {
    segment_id,

    source_generation,
    source_physical_digest,

    target_generation,
    target_physical_digest,

    logical_root,

    codec,
    block_size,

    packer_version,
}
```

---

# 88. Transação de Packing

Sequência:

```text
1. pin RAW source
2. create packed temp
3. stream source records
4. canonical verification
5. write blocks
6. write block directory
7. write footer
8. fsync packed temp
9. verify packed logical_root
10. publish immutable final object
11. fsync parent / confirm object
12. append PackReceipt
13. commit new HRKM
14. mark RAW generation SUPERSEDED
15. release pin
16. GC only later
```

---

# 89. Falha Durante Packing

Se o processo morrer em qualquer ponto antes do manifesto:

```text
RAW permanece autoridade
```

Arquivos:

```text
*.tmp
```

são órfãos e poderão ser removidos no próximo recovery.

---

# 90. Garbage Collection

GC físico pode remover:

* `.hrki` antigos;
* Parquet antigo;
* manifests superseded após retenção;
* physical generations superseded;
* temporários;
* caches.

---

# 91. Invariante de GC Canônico

GC jamais pode remover:

> a última geração física VERIFIED capaz de reconstruir todas as CanonicalRecords daquele segmento.

---

# 92. Readers Pinned

Antes de remover uma generation superseded:

```text
reader_pin_count == 0
```

ou mecanismo equivalente de epoch/reference tracking.

---

# 93. Grace Period

Toda geração superseded deve permanecer por um período configurável.

Exemplo:

```text
generation_gc_grace = 24h
```

O valor padrão definitivo será determinado operacionalmente.

---

# 94. Legal Hold

`LegalHold` bloqueia:

* canonical generation GC;
* migration destructive;
* crypto shredding;
* archive purge.

---

# 95. Logical Delete

Delete semântico:

```text
Tombstone Event
```

Não:

```text
remover registro antigo do HRKL
```

---

# 96. Correção de `compact_cold`

Compaction canônica nunca remove registros históricos.

Portanto operações atuais ou futuras equivalentes a:

```text
compact_cold(... is_deleted ...)
```

que produzam um `.hrkl` omitindo records NÃO poderão ser tratadas como nova representação canônica equivalente.

Elas devem ser reclassificadas como:

```text
projection compaction
```

ou:

```text
analytics compaction
```

---

# 97. Regra Formal

Se:

```text
input CanonicalRecords != output CanonicalRecords
```

então:

```text
input.logical_root != output.logical_root
```

e o output NÃO substitui o segmento canônico original.

---

# 98. Crypto-Shredding

Quando aplicável:

```text
canonical event remains
encrypted field remains
decryption key destroyed
```

A estrutura histórica continua provando:

* que um evento existiu;
* seu posicionamento temporal;
* sua identidade criptográfica;

sem necessariamente preservar a capacidade de recuperar o dado pessoal em plaintext.

A implementação concreta permanece sob responsabilidade do módulo de compliance.

---

# 99. Lakehouse Architecture

Arquitetura:

```text
                    HRKL CANONICAL
                         │
              ┌──────────┴───────────┐
              │                      │
              ▼                      ▼
          HRKI                    Parquet
        pruning                 projection
              │                      │
              ▼              ┌───────┴────────┐
      Heraclitus Planner      ▼                ▼
                           Iceberg           Delta
                              │                │
                              └───────┬────────┘
                                      ▼
                           Spark / Trino / DuckDB
```

---

# 100. Parquet Não é Canônico

Parquet poderá ser:

* apagado;
* recomposto;
* reclusterizado;
* compactado;
* reordenado;
* Z-ordered.

Isso não altera a verdade.

---

# 101. Schema Parquet Recomendado

Baseline:

```text
namespace_id
segment_id
segment_logical_root

lsn
transaction_hlc

event_id

agent_id
session_id

event_kind

content

valid_from
valid_to

attrs

parents

embedding_hyp
embedding_sph
embedding_euc
```

Campos criptografados permanecem criptografados salvo export explícito autorizado.

---

# 102. Proveniência no Parquet

Cada row deverá preservar:

```text
lsn
segment_id
logical_root
```

ou metadados equivalentes suficientes para vincular a projeção à origem.

---

# 103. Parquet File Metadata

O exporter deverá incluir metadados como:

```text
heraclitus.namespace
heraclitus.segment_id
heraclitus.first_lsn
heraclitus.last_lsn
heraclitus.logical_root
heraclitus.canonical_codec
heraclitus.export_version
```

---

# 104. Incremental Export

Exporter trabalha por watermark:

```text
last_exported_lsn
```

Novo ciclo:

```text
(last_exported_lsn, committed_lsn]
```

---

# 105. Export Idempotente

Nome de objeto derivado de:

```text
namespace
LSN range
logical root
export format version
```

Assim retry não deve produzir duplicação lógica.

---

# 106. Iceberg Real

`catalog.hrkm` NÃO torna o Heraclitus uma tabela Iceberg.

Integração Iceberg real deverá gerar:

* Parquet data files;
* Iceberg table metadata;
* manifest lists;
* manifests;
* snapshots;
* schemas;
* partition specs.

---

# 107. Iceberg Snapshot Mapping

Snapshots Iceberg representam:

```text
estado da projeção analítica
```

Não necessariamente:

```text
um LSN individual do Heraclitus
```

Deverá ser persistido:

```text
heraclitus.exported_through_lsn
```

em snapshot metadata quando suportado.

---

# 108. Partitioning Iceberg

Evitar:

```text
partition by event_id
partition by session_id
partition by user_id
```

por alta cardinalidade.

Preferir transforms temporais ou campos operacionais de baixa cardinalidade, conforme workload.

Exemplo:

```text
day(transaction_time)
tenant bucket
event class
```

A decisão final pertence ao exporter/planner e não ao HRKL.

---

# 109. Delta Lake

A projeção Delta seguirá o mesmo princípio:

```text
HRKL
  ↓
Parquet
  ↓
Delta transaction metadata
```

O HRKL continua autoritativo.

---

# 110. Data Skipping

A escolha de estatísticas no `.hrki` seguirá a mesma filosofia de engines analíticos:

* min/max para ranges;
* filtros probabilísticos para equality;
* bitmaps para baixíssima cardinalidade;
* não indexar tudo indiscriminadamente.

---

# 111. Arrow

O Heraclitus deverá expor:

```text
CanonicalRecord
      ↓
Arrow RecordBatch
```

por um adaptador vetorizado.

---

# 112. Zero Copy

Nenhuma API será documentada como "zero-copy" sem que o caminho real seja zero-copy.

Se ocorrer:

```text
HRKL packed
  ↓
decompress
  ↓
decode
  ↓
allocate Arrow arrays
```

não é zero-copy.

Pode continuar extremamente rápido, apenas não será vendido à física como algo que a física não fez.

---

# 113. Arrow IPC

Suportar:

```text
heraclitus export --format arrow
```

para arquivo/random access.

---

# 114. Arrow Flight

Flight deverá operar em `RecordBatch`.

Fluxo:

```text
query planner
    ↓
block pruning
    ↓
decode/vectorize
    ↓
RecordBatch
    ↓
Flight
```

---

# 115. DataFusion e HUME

O planner deverá usar a mesma fronteira de leitura.

```text
HRKM/HRKI
    ↓
candidate blocks
    ↓
RecordBatch/DataChunk
    ↓
planner
    │
    ├── HUME eligible fast path
    │
    └── DataFusion fallback
```

Storage não deve duplicar paths para cada motor.

---

# 116. FileScanProvider

Criar abstração:

```rust
trait HrklScanProvider {
    fn plan_scan(&self, predicate: &Predicate)
        -> Result<ScanPlan>;

    fn read_blocks(&self, plan: &ScanPlan)
        -> Result<BlockStream>;
}
```

Ela deverá esconder:

* local FS;
* mmap;
* positional read;
* S3;
* GCS;
* compression.

---

# 117. Predicates Pushdown

Baseline:

```text
LSN range
HLC range
valid-time range
event kind
session equality
tenant equality
entity equality
```

Arbitrary attrs entram apenas quando index policy permitir.

---

# 118. CLI

Adicionar:

```bash
heraclitus inspect segment.hrkl
```

---

# 119. `inspect`

Exemplo:

```text
HRKL Segment

Format               v6
Physical Layout      PACKED
Canonical Codec      v1

Segment ID           812
Generation           2

Records              521,991
LSN                   87122991..87644981

Blocks               1,037

Compression          ZSTD
Compressed           91.4 MiB
Logical/Raw          247.2 MiB
Ratio                 0.37

Logical Root         ...
Physical Digest      ...

HRKI                  valid
Parquet Projection    available

Logical Integrity     VERIFIED
Physical Integrity    VERIFIED
```

---

# 120. Outros Comandos

```bash
heraclitus verify segment.hrkl

heraclitus verify segment.hrkl --logical

heraclitus verify segment.hrkl --physical

heraclitus prove --lsn 1234567

heraclitus pack segment.hrkl

heraclitus rebuild-index segment.hrkl

heraclitus export segment.hrkl --format parquet

heraclitus export segment.hrkl --format arrow

heraclitus export segment.hrkl --format jsonl

heraclitus export table --format iceberg

heraclitus export table --format delta

heraclitus manifest show

heraclitus storage doctor
```

---

# 121. JSONL

Formato amigável para humanos e integração simples:

```bash
heraclitus export segment.hrkl --format jsonl
```

Ele é exportação.

Nunca storage canônico.

---

# 122. Forensic Proof

```bash
heraclitus prove --lsn X
```

deve produzir:

```text
CanonicalRecord
record_hash
Merkle inclusion proof
segment logical_root
AttestationEnvelope
timestamp receipt, se disponível
```

---

# 123. Recovery do Active RAW

Permanece conservador.

Apenas o segmento ativo pode sofrer reparo automático de torn tail.

Corrupção interna em segmento anteriormente selado:

```text
FAIL HIGH
```

Não:

```text
truncate e fingir que nada aconteceu
```

---

# 124. Recovery PACKED

Um PACKED válido exige:

1. FileHeader válido;
2. Footer válido;
3. BlockDirectory válido;
4. ranges coerentes;
5. CRCs dos blocos acessados válidos.

Verificação completa opcional/requisitada:

6. todos os blocks válidos;
7. todas as CanonicalRecords válidas;
8. `logical_root` recalculada igual.

---

# 125. Sidecar Corrupto

Se `.hrki` estiver corrupto:

```text
ignore
rebuild
continue
```

Nunca:

```text
database corruption
```

---

# 126. Parquet Corrupto

Mesmo princípio:

```text
delete/rebuild projection
```

O HRKL continua autoridade.

---

# 127. Packed Corrupto com RAW Disponível

Se generation PACKED falhar e RAW equivalente existir:

```text
quarantine PACKED
reactivate/rebuild from RAW
```

Toda transição gera evento/telemetria apropriada.

---

# 128. Packed Corrupto sem Outra Cópia

Falha canônica.

Tentar:

* réplica;
* object storage;
* backup;
* archive generation.

Nunca reconstruir silenciosamente dados ausentes.

---

# 129. Migração HRKL v1-v5

Readers continuarão versionados.

Novo writer:

```text
write v6 only
```

---

# 130. Legacy Active Tail

Ao abrir um tail v1-v5 não selado:

```text
recover according to legacy rules
seal legacy tail
start fresh v6 segment
```

Não continuar appendando registros v6 em arquivo legado.

---

# 131. v5 e a Nova Logical Root

v5 possui identidade histórica baseada na regra antiga.

Não é correto simplesmente declarar:

```text
v5 physical root == v6 logical root
```

porque são conceitos diferentes.

---

# 132. LegacyMigrationReceipt

Ao criar representação v6 de segmento legado:

```text
LegacyMigrationReceipt {
    legacy_format,

    legacy_segment_id,
    legacy_root,

    canonical_codec_v6,

    v6_logical_root,

    target_generation,
    target_physical_digest,
}
```

Isso cria uma ponte auditável.

---

# 133. Retenção de Segmentos Legacy

Default:

```text
preserve legacy original = true
```

Especialmente quando houver:

* RFC3161;
* assinatura;
* legal hold;
* processo pericial;
* evidência externa referenciando o hash antigo.

---

# 134. Packing de Segmentos v6

Para um segmento criado já sob CanonicalRecordCodec v1:

```text
RAW logical_root == PACKED logical_root
```

obrigatoriamente.

---

# 135. Compatibilidade do Decoder

Matrix:


| Versão   | Read | Append |       Pack |
| --------- | ---: | -----: | ---------: |
| v1        |  sim |   não |  migration |
| v2        |  sim |   não |  migration |
| v3        |  sim |   não |  migration |
| v4        |  sim |   não |  migration |
| v5        |  sim |   não |  migration |
| v6 RAW    |  sim |    sim |        sim |
| v6 PACKED |  sim |   não | já packed |

---

# 136. Nenhum `repr(C)` Como Disk Format

Regra absoluta.

Permitido:

```rust
struct BlockHeader { ... }
```

como modelo lógico.

Proibido:

```rust
unsafe {
    write_all(as_bytes(&header))
}
```

O encoder deve escrever campos explicitamente.

---

# 137. Parsing Seguro

Todo length deverá ser verificado contra:

* remaining bytes;
* hard maximum;
* overflow;
* integer conversion;
* configured limits.

---

# 138. Malformed Varint

Reader deve rejeitar:

* varint longo demais;
* overflow;
* encoding não canônico;
* EOF parcial.

---

# 139. Canonical Varint

A mesma quantidade não poderá possuir múltiplas representações válidas.

Exemplo:

```text
1
```

não pode ser aceito em uma representação artificialmente maior.

Isso impede múltiplos byte streams para o mesmo valor lógico.

---

# 140. Compression Bomb Protection

Antes de alocar:

```text
uncompressed_len <= configured_max_block
```

Além disso:

```text
compressed_len <= file_remaining
```

Blocos maliciosos não podem forçar alocação arbitrária.

---

# 141. Memory Budget

Decompression usa buffer pool limitado.

Nunca:

```text
Vec::with_capacity(untrusted_length)
```

sem validação.

---

# 142. Compression Threads

Packer deverá possuir orçamento independente:

```text
pack_threads

max_pack_memory

max_pack_io_bytes_per_sec

max_cpu_percentage
```

ou política equivalente.

O objetivo é não competir descontroladamente com queries.

---

# 143. Backpressure

Se o packer ficar atrasado:

```text
sealed RAW queue grows
```

O writer não para imediatamente.

Ao ultrapassar limites operacionais, aplicar:

* telemetry;
* warning;
* optional throttling;
* disk pressure policy.

Nunca descartar log.

---

# 144. Packing Queue

Persistir ou reconstruir a fila a partir do manifesto.

Não depender exclusivamente de memória.

Após restart:

```text
find SEALED_RAW without PACKED
       ↓
resume queue
```

---

# 145. Sidecar Build Queue

Mesmo princípio:

```text
PACKED without HRKI
      ↓
rebuild async
```

---

# 146. Lakehouse Queue

```text
segment canonical
but parquet missing
      ↓
export async
```

Nenhuma dessas filas afeta correção do storage.

---

# 147. Prioridades de Background Work

Sugestão:

```text
1. canonical durability
2. recovery/replication
3. packing
4. HRKI
5. Parquet projection
6. statistics/sketch refinement
```

---

# 148. Configuração

Exemplo:

```toml
[storage.hrkl_v6]
enabled = true

block_target_bytes = 262144
restart_interval = 64

compression_profile = "balanced"
raw_fallback_ratio = 0.92

pack_threads = 2

preserve_superseded_raw = false
generation_gc_grace_seconds = 86400


[storage.hrki]
enabled = true

bloom_fpr = 0.01
index_event_kind = true
index_session_id = true

arbitrary_attrs = "opt_in"


[storage.lakehouse]
parquet_enabled = true

iceberg_enabled = false
delta_enabled = false
```

Valores finais deverão ser centralizados no config crate e não duplicados por crate.

---

# 149. Profiles

Permitir profile de alto nível.

## throughput

```text
Zstd1/LZ4
larger packing concurrency
```

## balanced

```text
Zstd3
256 KiB blocks
```

## archive

```text
higher Zstd
lower priority
```

O usuário pode sobrescrever valores individualmente.

---

# 150. Métricas

Expor:

```text
hrkl_append_bytes_total

hrkl_raw_bytes

hrkl_packed_bytes

hrkl_compression_ratio

hrkl_pack_queue_depth

hrkl_pack_seconds

hrkl_pack_throughput_bytes_sec

hrkl_blocks_total

hrkl_blocks_read

hrkl_blocks_pruned

hrkl_bytes_pruned

hrkl_decompressed_bytes

hrki_hits

hrki_misses

hrki_rebuilds

cold_range_reads

cold_bytes_downloaded

parquet_export_lag_lsn

canonical_verify_failures

physical_crc_failures
```

---

# 151. Explain Query

`EXPLAIN` deve mostrar pruning.

Exemplo:

```text
Segments total:       1,840
Manifest pruned:      1,730
HRKI pruned:             87
Segments read:           23

Blocks candidate:     8,331
Blocks pruned:        8,104
Blocks decompressed:    227

Bytes logical:        2.1 GiB
Bytes physical read:  19.2 MiB
```

Isso transforma a otimização em algo observável.

---

# 152. Benchmarks Obrigatórios

Corpus mínimo:

1. eventos pequenos altamente repetitivos;
2. eventos médios reais;
3. conteúdo incompressível;
4. embeddings;
5. atributos de alta cardinalidade;
6. payloads grandes;
7. mistura de eventos criptografados;
8. 20M+ records.

---

# 153. Hot Write Gate

Comparar v5 vs v6 RAW.

Hard regression gate inicial:

```text
median throughput regression <= 3%
```

Target:

```text
<= 1%
```

P99 de append também deverá ser medido.

---

# 154. Compression Gate

Não usar promessa universal como:

```text
sempre comprime 65%
```

Compressão depende dos dados.

Usar corpus de referência.

Target no corpus operacional:

```text
packed_size <= 50% do RAW
```

ou valor calibrado após benchmark.

---

# 155. Incompressible Gate

Em dados incompressíveis:

```text
PACKED expansion <= 2%
```

por causa do RAW fallback.

---

# 156. Metadata Gate

Para registros pequenos sem considerar payload compression:

```text
packed physical metadata per record
```

deve cair substancialmente em relação aos 24 bytes RAW.

Target:

```text
>= 60% reduction
```

em workload contíguo/monotônico.

---

# 157. Point Read Gate

Consultar um LSN PACKED não pode descompactar:

```text
segment inteiro
```

Hard invariant:

```text
<= 1 block decompressed
```

exceto em casos explicitamente documentados.

---

# 158. Range Query Gate

Predicado seletivo deverá demonstrar redução real de:

```text
blocks read
bytes read
```

e não apenas redução de CPU após os bytes já terem sido carregados.

---

# 159. Boot Gate

Com HRKM válido:

```text
startup must not require full scan
of every sealed canonical segment
```

Verificações profundas passam a ser:

```text
background
explicit verify
sampled scrub
```

e não parte obrigatória de todo boot.

---

# 160. Scrubber

Criar background scrub opcional.

```text
scrub physical CRC
scrub physical digest
scrub logical root
```

com cadence configurável.

---

# 161. Integrity Levels

```text
FAST
    header/footer/catalog

PHYSICAL
    + all block CRC

LOGICAL
    + canonical decode
    + logical Merkle root

FORENSIC
    + receipts
    + timestamps
    + replicas/object copies
```

---

# 162. Crash Injection

Testar falha após cada etapa crítica:

* append;
* fsync;
* seal;
* temp packed;
* directory;
* footer;
* packed fsync;
* publish;
* PackReceipt;
* manifest commit;
* GC.

Nenhuma sequência de crash pode causar:

```text
loss of committed CanonicalRecord
```

---

# 163. Fuzzing

Targets:

```text
FileHeader decoder

RAW record decoder

BlockHeader decoder

varint decoder

Packed record decoder

BlockDirectory decoder

Footer decoder

HRKI decoder

HRKM decoder
```

Malformed input jamais deve:

* panic;
* integer overflow;
* uncontrolled allocation;
* UB.

---

# 164. Property Tests

Obrigatórios:

```text
RAW decode == PACKED decode

RAW logical_root == PACKED logical_root

pack(pack(x)) logical-equivalent to pack(x)

unpack(pack(x)) == logical x

HRKI pruning never false-negative

manifest pruning never false-negative

legacy decode preserves events

corrupt HRKI never corrupts HRKL

different physical codec same logical root
```

---

# 165. Golden Vectors

Versionar arquivos pequenos em:

```text
tests/golden/hrkl-v6/
```

incluindo:

```text
raw-empty
raw-one-record
packed-one-block
packed-multi-block
packed-large-record
packed-dictionary
packed-sparse-lsn
corrupt-crc
corrupt-footer
```

Os bytes serão parte do contrato de compatibilidade.

---

# 166. Determinism Test

Executar pack em:

* x86-64;
* ARM64;
* Linux;
* Windows/macOS quando suportados;

e verificar:

```text
logical_root identical
decoded records identical
```

O `physical_digest` poderá diferir apenas se o compressor não garantir bitstream determinístico e tal comportamento estiver explicitamente permitido.

Idealmente versões/políticas de compressor usadas em archival determinístico devem ser registradas.

---

# 167. Compressão e Reprodutibilidade

A identidade lógica NÃO depende de a biblioteca Zstd produzir os mesmos bytes entre versões.

Isso é proposital.

O manifesto registra:

```text
logical_root
physical_digest
compression codec
packer version
```

---

# 168. Integration com ArtifactRegistry

Adicionar tipos derivados adequados:

```text
HrkiSegmentIndex
DecompressedBlock
ParquetProjection
```

ou nomenclatura equivalente.

O lifecycle de artefatos já existente deve ser reaproveitado.

---

# 169. Dependências de Artifact

Exemplo:

```text
Canonical Segment
    │
    ├── HRKI
    │
    ├── Parquet
    │
    └── Block Cache
          │
          └── Query-specific artifacts
```

Eviction de derived artifacts nunca evicta o canonical segment.

---

# 170. Pruning Conservador

Regra:

```text
pruner false -> definitely cannot match
pruner true  -> maybe match
```

Nunca inverter essa semântica.

---

# 171. Statistics Evolution

`.hrki` poderá ganhar no futuro:

* HyperLogLog;
* quantiles;
* TDigest;
* histograms;
* sketches;
* learned selectivity models.

Sem alterar HRKL.

---

# 172. Não Colocar Tudo no Footer

O footer canônico deve continuar pequeno.

Não colocar nele:

* Bloom gigantes;
* HLL;
* histogramas;
* dicionários analíticos;
* caches;
* HNSW;
* planner hints.

Esses pertencem ao `.hrki` ou a outros artifacts.

---

# 173. Internal Manifest vs Iceberg

Resumo:

```text
HRKM:
Heraclitus internal storage catalog

Iceberg:
external lakehouse table metadata
```

Podem compartilhar ideias.

Não compartilham formato.

---

# 174. Parquet Page-Level Optimizations

Ao exportar Parquet, o exporter deverá habilitar recursos suportados pelo stack utilizado que beneficiem:

* predicate pushdown;
* row-group skipping;
* page skipping;
* dictionary encoding;
* Bloom filtering quando apropriado.

Essas otimizações permanecem exclusivas da projeção Parquet.

---

# 175. Compactação Parquet

Permitida:

```text
small parquet files
      ↓
rewrite
      ↓
larger parquet files
```

desde que o watermark e proveniência continuem corretos.

Não afeta HRKL.

---

# 176. Lakehouse GC

Parquet superseded pode ser coletado segundo regras do lakehouse.

Isso não significa remover o `.hrkl`.

---

# 177. SQL AS OF

Heraclitus:

```sql
AS OF LSN
AS OF TIMESTAMP
```

continua baseado no histórico canônico.

Não deve depender dos snapshots externos do Iceberg/Delta.

---

# 178. Export Friendly

O usuário deve conseguir tratar o Heraclitus como uma fonte normal de dados sem conhecer o formato binário.

Superfícies oficiais:

```text
SQL
Arrow Flight
Parquet
Iceberg
Delta
JSONL
REST/gRPC
```

---

# 179. `.hrkl` Não É Interface Humana

Não sacrificar:

* densidade;
* integridade;
* velocidade;
* recovery;

para tornar o arquivo legível no editor de texto.

A CLI torna o formato amigável.

---

# 180. Observabilidade do Storage

Dashboard poderá mostrar:

```text
RAW size
PACKED size
compression ratio
canonical bytes
derived bytes
cold bytes
index bytes

packing backlog
lakehouse lag
verification status
legal hold
```

---

# 181. Storage Amplification

Definir:

```text
storage_amplification =
all_physical_bytes /
canonical_logical_bytes
```

Separar:

```text
canonical amplification

derived amplification

temporary packing amplification
```

---

# 182. Packing Temporary Space

Packing exige temporariamente:

```text
RAW + PACKED
```

Portanto antes de iniciar packing local:

```text
available_disk >= safety_threshold
```

Se não houver espaço:

* adiar packing;
* packing direto para object storage;
* alertar operador.

Nunca apagar RAW primeiro esperando que o pack dê certo depois.

---

# 183. Direct-to-Object Packing

Futuro/opt-in:

```text
sealed RAW local
       ↓
stream pack
       ↓
object storage PACKED
       ↓
verify
       ↓
receipt
       ↓
manifest
       ↓
local RAW eligible for GC
```

Isso reduz necessidade de armazenamento local duplicado.

---

# 184. Replica Safety

Em cluster:

GC local de canonical generation só será permitido após satisfazer política de durabilidade.

Exemplo:

```text
at least N verified canonical copies
```

ou canonical object store durable.

A política pertence à camada de replication/storage durability.

---

# 185. Segment Size

O segment size e block size são conceitos diferentes.

Exemplo:

```text
segment = 256 MiB
block   = 256 KiB
```

aproximadamente:

```text
1024 blocks/segment
```

antes de considerar records grandes e variações.

---

# 186. Segment Size Futuro

A SPEC não fixa 256 MiB eternamente.

Segment size pode evoluir independentemente de block size.

Manifest e format não devem codificar assumptions como:

```text
segment always 256MB
```

---

# 187. Query Adaptive Block Size

Não implementar inicialmente.

Block size definido no momento de packing permanece propriedade da generation.

Uma futura generation poderá usar outro tamanho mantendo:

```text
logical_root
```

idêntica.

---

# 188. Repacking

Permitido:

```text
PACKED generation 1
Zstd3 256KiB blocks
        ↓
PACKED generation 2
Zstd6 1MiB blocks
```

desde que:

```text
logical_root1 == logical_root2
```

---

# 189. Repacking Use Cases

* archive;
* mudança de compressor;
* mudança de block size;
* object-store optimization;
* storage cost reduction.

---

# 190. Repacking NÃO É Logical Compaction

Não pode:

* remover tombstones;
* remover episodes;
* reordenar LSN;
* alterar payload lógico;
* colapsar duplicatas.

---

# 191. Hot/Cold Separação Final

```text
HOT
┌─────────────────────┐
│ Active RAW HRKL     │
│ Append              │
│ fsync               │
│ minimal CPU         │
└─────────┬───────────┘
          │ seal
          ▼

WARM
┌─────────────────────┐
│ Packed HRKL         │
│ Zstd/LZ4            │
│ Block Directory     │
│ HRKI                │
└─────────┬───────────┘
          │ demote
          ▼

COLD
┌─────────────────────┐
│ Packed HRKL         │
│ Object Storage      │
│ immutable           │
│ range-readable      │
└─────────┬───────────┘
          │
          ├───────────────┐
          ▼               ▼
      Parquet          Archive
         │
     Iceberg/Delta
```

---

# 192. Módulos Sugeridos

```text
heraclitus-log/src/v6/
    mod.rs
    header.rs
    footer.rs
    canonical.rs
    merkle.rs
    raw.rs
    packed.rs
    block.rs
    block_directory.rs
    varint.rs
    dictionary.rs
    packer.rs
    verify.rs
```

---

# 193. Sidecar

```text
heraclitus-log/src/index/
    hrki.rs
    zone_map.rs
    bloom.rs
    bitmap.rs
```

Migrar gradualmente o código atual de `.zmap`.

---

# 194. Manifest

```text
heraclitus-core/
    runtime.rs
    manifest.rs
```

ou reorganização equivalente sem duplicar `DatabaseManifest`.

---

# 195. Tier

```text
heraclitus-tier/
    object_store.rs
    demotion.rs
    generation.rs
    receipts.rs
    lakehouse/
        parquet.rs
        iceberg.rs
        delta.rs
```

---

# 196. CLI

```text
heraclitus-cli/
    inspect.rs
    verify.rs
    pack.rs
    prove.rs
    export.rs
    doctor.rs
```

---

# 197. Roadmap de Implementação

## Fase 0 - Contratos

* definir `CanonicalRecordV1`;
* definir `CanonicalRecordCodecV1`;
* definir logical hash;
* definir MerkleAccumulatorV1;
* golden vectors;
* property tests.

Nada de compressão antes disso.

---

# 198. Fase 1 - v6 RAW

* FileHeaderV6;
* FooterV6;
* RAW record compatível com hot-path atual;
* logical root nova;
* reader v6 RAW;
* writer v6 RAW;
* compatibility v1-v5.

---

# 199. Fase 2 - PACKED Baseline

* BlockHeader;
* block framing;
* Zstd;
* RAW fallback;
* block directory;
* HLC delta;
* contiguous LSN elimination;
* restart points;
* PACKED reader;
* packer assíncrono.

Payload permanece inicialmente compatível com StoragePayload existente.

---

# 200. Fase 3 - Manifest Generations

* evoluir `DatabaseManifest`;
* physical generations;
* logical root;
* physical digest;
* state machine;
* crash-safe commit;
* GC policy.

---

# 201. Fase 4 - HRKI

* absorver `.zmap`;
* segment stats;
* block zone maps;
* Bloom;
* EventKind bitmap;
* confidentiality policy;
* pruning integration.

---

# 202. Fase 5 - Object Storage

* immutable generation keys;
* range reads;
* receipts v2;
* verification;
* cold block fetching.

---

# 203. Fase 6 - Lakehouse

* Parquet v2 exporter;
* provenance metadata;
* incremental watermark;
* Iceberg exporter;
* Delta exporter;
* Arrow IPC/Flight.

---

# 204. Fase 7 - PackedEpisodeV1

Somente após benchmarks demonstrarem benefício além de Zstd.

* structured physical codec;
* adaptive dictionaries;
* dictionary stats;
* no logical-format change.

---

# 205. Fase 8 - Advanced Indexing

Opcional:

* Xor/BinaryFuse;
* HLL;
* histograms;
* workload-adaptive HRKI;
* learned pruning.

---

# 206. Definition of Done - Correção

* [ ]  v1-v5 permanecem legíveis.
* [ ]  writer novo gera v6.
* [ ]  RAW v6 recupera torn tail.
* [ ]  PACKED v6 é totalmente legível sem HRKI.
* [ ]  RAW e PACKED equivalentes possuem mesma logical root.
* [ ]  physical digest muda quando bytes físicos mudam.
* [ ]  CanonicalRecord inclui `opaque_meta`.
* [ ]  EventKind não depende de discriminante Serde.
* [ ]  canonical codec possui golden vectors.
* [ ]  nenhuma estrutura on-disk depende de `repr(C)`.
* [ ]  malformed input não causa panic ou alocação descontrolada.
* [ ]  GC nunca remove última canonical generation.
* [ ]  LegalHold impede GC relevante.
* [ ]  canonical compaction jamais remove records.

---

# 207. Definition of Done - Performance

* [ ]  v6 RAW degrada throughput mediano <=3% vs baseline v5.
* [ ]  objetivo preferencial <=1%.
* [ ]  packed não descompacta segmento completo para point lookup.
* [ ]  point lookup lê no máximo um bloco canônico em caso normal.
* [ ]  dados incompressíveis crescem <=2%.
* [ ]  corpus real demonstra redução substancial de storage.
* [ ]  metadata por record PACKED reduz >=60% em corpus contíguo.
* [ ]  pruning reduz bytes físicos lidos em consultas seletivas.
* [ ]  boot com HRKM não exige scan integral de sealed segments.

---

# 208. Definition of Done - Resiliência

* [ ]  crash injection cobre todas as etapas de packing.
* [ ]  crash nunca perde committed CanonicalRecord.
* [ ]  `.tmp` órfão é recuperável/removível.
* [ ]  HRKI corrupto é ignorado/reconstruído.
* [ ]  Parquet corrupto é regenerável.
* [ ]  PACKED corrupto pode ser reconstruído se RAW equivalente existir.
* [ ]  corrupção canônica sem réplica falha explicitamente.
* [ ]  legacy roots nunca são silenciosamente reinterpretadas como roots v6.

---

# 209. Definition of Done - Lakehouse

* [ ]  export Parquet preserva LSN.
* [ ]  export preserva segment provenance.
* [ ]  export é idempotente.
* [ ]  watermark é persistido.
* [ ]  Iceberg exporter gera metadata Iceberg real.
* [ ]  HRKM não é apresentado como Iceberg.
* [ ]  Delta utiliza Parquet derivado.
* [ ]  nenhuma projeção lakehouse participa da durabilidade do append.

---

# 210. Definition of Done - Operação

* [ ]  `heraclitus inspect` implementado.
* [ ]  `heraclitus verify` implementado.
* [ ]  `heraclitus prove --lsn` implementado.
* [ ]  `heraclitus rebuild-index` implementado.
* [ ]  metrics de packing/pruning/export disponíveis.
* [ ]  `EXPLAIN` mostra blocks/segments/bytes pruned.
* [ ]  `storage doctor` detecta generations órfãs, sidecars inválidos e divergências de manifesto.

---

# 211. Invariantes Finais

## Invariante 1

```text
The canonical logical history is immutable.
```

---

## Invariante 2

```text
Physical representation is replaceable
only by verified logical equivalence.
```

---

## Invariante 3

```text
RAW logical_root == PACKED logical_root
for the same v6 CanonicalRecords.
```

---

## Invariante 4

```text
HRKI is never required for correctness.
```

---

## Invariante 5

```text
Parquet is never authoritative.
```

---

## Invariante 6

```text
Iceberg/Delta metadata never participates
in Heraclitus commit durability.
```

---

## Invariante 7

```text
No canonical record is removed by packing.
```

---

## Invariante 8

```text
No sidecar may create a false-negative prune.
```

---

## Invariante 9

```text
No optimization may silently leak protected
plaintext into derived metadata.
```

---

## Invariante 10

```text
The hot append path never waits for Zstd,
Iceberg, Parquet, HRKI or background packing.
```

---

# 212. Arquitetura Final

```text
                              APPEND
                                │
                                ▼
                ┌────────────────────────────┐
                │      HRKL v6 RAW           │
                │                            │
                │ append-only                │
                │ CRC32C                     │
                │ canonical record hash      │
                │ fsync/group commit         │
                └─────────────┬──────────────┘
                              │ seal + rotate
                              ▼
                ┌────────────────────────────┐
                │       SEALED RAW           │
                │                            │
                │ logical_root               │
                │ canonical generation       │
                └─────────────┬──────────────┘
                              │ async packing
                              ▼
                ┌────────────────────────────┐
                │     HRKL v6 PACKED         │
                │                            │
                │ 256 KiB blocks             │
                │ Zstd/LZ4/RAW               │
                │ HLC delta                  │
                │ implicit LSN               │
                │ restart points             │
                │ BlockDirectory             │
                └───────┬──────────┬─────────┘
                        │          │
                 derived│          │canonical
                        ▼          ▼
               ┌────────────┐  ┌────────────────┐
               │    HRKI    │  │ Object Storage │
               │            │  │ Packed HRKL    │
               │ zone maps  │  │ WORM optional  │
               │ Bloom      │  │ range reads    │
               │ bitmaps    │  └───────┬────────┘
               └─────┬──────┘          │
                     │                 │
                     └────────┬────────┘
                              ▼
                     ┌─────────────────┐
                     │ HRKM Manifest   │
                     │                 │
                     │ generations     │
                     │ roots           │
                     │ locations       │
                     │ watermarks      │
                     └────────┬────────┘
                              │
                ┌─────────────┼────────────────┐
                │             │                │
                ▼             ▼                ▼
              HUME        DataFusion         Parquet
                                                  │
                                   ┌──────────────┴─────────────┐
                                   ▼                            ▼
                                Iceberg                       Delta
                                   │                            │
                                   └──────────────┬─────────────┘
                                                  ▼
                                      Spark / Trino / DuckDB
```

---

# 213. Resultado Esperado

Com a SPEC-0050 concluída, o `.hrkl` deixa de ser apenas um append-only log eficiente e passa a ser um **formato canônico temporal de armazenamento com múltiplas representações físicas verificáveis**.

O Heraclitus poderá:

* escrever em um formato RAW extremamente simples;
* selar sem bloquear a próxima geração de escrita;
* recomprimir segmentos de forma assíncrona;
* reduzir substancialmente storage;
* realizar point lookup sem ler o segmento inteiro;
* eliminar segmentos e blocos antes do I/O;
* consultar diretamente object storage;
* reconstruir todos os índices derivados;
* gerar Parquet/Iceberg/Delta sem dual-write transacional;
* provar a equivalência entre gerações físicas;
* preservar AS OF LSN, bitemporalidade e proveniência;
* manter a cadeia criptográfica independente do compressor;
* evoluir o formato físico novamente no futuro sem alterar a verdade lógica.

A consequência arquitetural mais importante é:

> **o HeraclitusDB deixa de vincular a identidade da informação aos bytes específicos usados para armazená-la, sem abrir mão da prova dos bytes que efetivamente foram armazenados.**

Isso permite simultaneamente:

```text
imutabilidade lógica
+
compressão física
+
repacking
+
object storage
+
forensics
+
lakehouse
+
evolução de formato
```

sem colocar nenhuma dessas propriedades no hot-path das demais.

Essa é a fronteira que o HRKL v6 deve estabelecer.
