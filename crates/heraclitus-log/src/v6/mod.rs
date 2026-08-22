//! # HRKL v6 — armazenamento canónico, segmentos empacotados e ciclo de vida
//!
//! Implementação da **SPEC-0050**, Fases 0 a 3 do roadmap de §197–§200.
//!
//! ## A decisão que organiza tudo
//!
//! O v6 separa formalmente quatro coisas que o v5 confundia:
//!
//! ```text
//! verdade lógica canónica        CanonicalRecordV1 + logical_root
//! codificação física             RAW | PACKED (Zstd/LZ4/RAW por bloco)
//! catálogo                       .hrkm — gerações, estados, retenção
//! estruturas derivadas           .hrki  (Fase 4)
//! projecções analíticas          Parquet/Iceberg/Delta (Fase 6)
//! ```
//!
//! E substitui a leitura rígida de *"os bytes físicos originais nunca podem ser
//! removidos"* por uma regra operável:
//!
//! > Nenhum registo lógico canónico pode desaparecer do histórico. A
//! > representação física desse histórico pode ser reorganizada, comprimida ou
//! > substituída por outra **comprovadamente equivalente**.
//!
//! "Comprovadamente" é literal: a substituição de uma geração RAW por uma
//! PACKED só é autorizada quando a `logical_root` recalculada a partir do
//! ficheiro publicado é igual à do original ([`packer::pack_segment`], passo 9
//! de §88).
//!
//! ## Três identidades, deliberadamente distintas (§7)
//!
//! | identidade | o quê | onde |
//! |---|---|---|
//! | lógica do registo | [`canonical::canonical_record_hash`] | folha de Merkle |
//! | lógica do segmento | [`merkle::MerkleAccumulatorV1`] | `footer.logical_root` |
//! | física do objecto | [`receipts::physical_digest`] | manifesto/recibo |
//!
//! `RAW physical_digest != PACKED physical_digest` **e**
//! `RAW logical_root == PACKED logical_root`. As duas coisas ao mesmo tempo são
//! o ponto.
//!
//! ## Mapa dos módulos
//!
//! | módulo | SPEC | papel |
//! |---|---|---|
//! | [`varint`] | §138–§139 | ULEB128 canónico, sem formas duplicadas |
//! | [`canonical`] | §8–§15 | `CanonicalRecordCodecV1` e o hash lógico |
//! | [`merkle`] | §16–§18, §122 | acumulador streaming e provas de inclusão |
//! | [`header`] | §23–§24 | `FileHeaderV6` (64 B) |
//! | [`footer`] | §52 | `FooterV6` (128 B) |
//! | [`raw`] | §25–§27, §123 | hot-path de append e recuperação de cauda |
//! | [`block`] | §28–§40 | `BlockHeaderV1` (64 B), restart points, deltas |
//! | [`block_directory`] | §49–§51 | índice físico dentro do `.hrkl` |
//! | [`compress`] | §32–§34 | codecs, perfis e RAW fallback |
//! | [`packed`] | §76–§77, §116 | escrita/leitura PACKED e fronteira de scan |
//! | [`packer`] | §88–§89, §188 | transacção RAW→PACKED e repack |
//! | [`manifest`] | §68–§75 | `.hrkm`, snapshots, `CURRENT`, estados |
//! | [`gc`] | §90–§97, §182 | política de coleta, pins, LegalHold |
//! | [`receipts`] | §19, §86–§87 | envelopes e recibos |
//! | [`verify`] | §119–§124, §161 | níveis de integridade, `prove`, `inspect` |
//!
//! ## O que ainda não está aqui
//!
//! Fases 4 a 8 da SPEC: o sidecar `.hrki`, object storage com range reads, os
//! exportadores do lakehouse, `PackedEpisodeV1` e a indexação avançada. Os
//! contratos de que essas fases dependem já existem e estão povoados pelo
//! manifesto: [`heraclitus_core::runtime::DerivedArtifactRef`] para os
//! sidecars e a projecção Parquet, `location` em
//! [`heraclitus_core::runtime::PhysicalGeneration`] para object storage, e as
//! filas de §144–§146 em [`heraclitus_core::DatabaseManifest`].
//!
//! ## Invariantes que este código faz cumprir mecanicamente
//!
//! 1. A raiz lógica não depende da divisão física em blocos ([`merkle`]).
//! 2. `RAW logical_root == PACKED logical_root`, verificado antes de publicar.
//! 3. Nenhum registo é removido pelo packing (a raiz mudaria).
//! 4. Nenhuma estrutura em disco depende de `repr(C)` — todos os codecs são
//!    manuais e little-endian.
//! 5. Input malformado não causa panic, overflow nem alocação descontrolada
//!    ([`error::checked_len`], [`varint::read_varint`]).
//! 6. O hot-path de append nunca espera por Zstd, HRKI, Parquet ou packing.
//! 7. O GC nunca remove a última geração capaz de reconstruir um segmento
//!    ([`gc::assert_gc_invariant`], escrito independentemente da decisão).
//! 8. Uma geração publicada — de segmento ou de manifesto — nunca é
//!    sobrescrita; muda-se de geração, não de bytes.

pub mod block;
pub mod block_directory;
pub mod canonical;
pub mod compress;
pub mod engine;
pub mod error;
pub mod footer;
pub mod gc;
pub mod header;
pub mod manifest;
pub mod merkle;
pub mod packed;
pub mod packer;
pub mod raw;
pub mod receipts;
pub mod varint;
pub mod verify;

pub use canonical::{
    canonical_record_bytes, canonical_record_hash, CanonicalRecordHasherV1, CanonicalRecordV1,
    CANONICAL_CODEC_V1,
};
pub use compress::{CompressionCodec, PackingProfile};
pub use error::V6Result;
pub use engine::V6Log;
pub use footer::FooterV6;
pub use gc::{
    apply_gc, assert_gc_invariant, classify_compaction, plan_gc, GcBlockReason, GcOptions, GcPlan,
    PinRegistry,
};
pub use header::{FileHeaderV6, PhysicalLayout, FORMAT_VERSION_V6};
pub use heraclitus_core::runtime::{DatabaseManifest, GenerationState, PhysicalGeneration};
pub use manifest::{
    boot_report, decode_manifest, encode_manifest, record_pack, register_sealed_raw, BootReport,
    LoadedManifest, ManifestStore,
};
pub use merkle::{InclusionProof, MerkleAccumulatorV1};
pub use packed::{open_packed, PackOptions, PackStats, PackedSegmentReader, ScanCounters};
pub use packer::{pack_and_commit, pack_segment, repack_segment, sweep_orphan_temps, PackOutcome};
pub use raw::{RawSegmentWriter, SegmentInit};
pub use receipts::{AttestationEnvelopeV1, PackReceipt};
pub use verify::{inspect, prove_lsn, verify_segment, IntegrityLevel, VerifyReport};

/// CRC-32C partilhado com o resto do crate — a mesma via acelerada por
/// hardware que o v5 usa (CPM-200 §2). Uma única implementação, para que um
/// segmento não possa validar por um caminho e falhar por outro.
#[inline]
pub(crate) fn crc32c_of(data: &[u8]) -> u32 {
    crate::cpm::crc32c(data)
}

/// Ergue um [`CanonicalRecordV1`] a partir de um `Episode` já descodificado e
/// devolve o seu hash lógico.
///
/// É a ponte entre o crate do log (que sabe descodificar `StoragePayload`) e o
/// v6 (que não sabe, nem deve saber).
pub fn hash_episode_record(
    lsn: heraclitus_core::Lsn,
    record_hlc: u64,
    opaque_meta: [u8; 16],
    episode: &heraclitus_core::Episode,
) -> [u8; 32] {
    canonical_record_hash(&CanonicalRecordV1 {
        lsn,
        record_hlc,
        opaque_meta,
        episode,
    })
}
