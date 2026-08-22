//! SPEC-0050 §19, §86–§87, §132 — envelopes e recibos.
//!
//! Todos codificados pelo mesmo [`CanonicalSink`] dos registos: um recibo que
//! dependesse de `serde` teria a mesma fragilidade que a SPEC proíbe para a
//! identidade lógica — recompilar mudaria os bytes assinados.

use heraclitus_core::{Lsn, SegmentId};

use super::canonical::{CanonicalSink, CANONICAL_CODEC_V1};
use super::compress::CompressionCodec;
use super::header::StorageNamespaceId;

pub const DOMAIN_ATTESTATION: &[u8] = b"HRKL6:ATTESTATION_ENVELOPE:V1";
pub const DOMAIN_PACK_RECEIPT: &[u8] = b"HRKL6:PACK_RECEIPT:V1";

/// SPEC-0050 §19 — o que é carimbado por RFC 3161 / ICP-Brasil.
///
/// Não se assina um hash solto. Sem o `storage_namespace_id`, o `segment_id` e
/// o intervalo de LSN dentro do envelope, uma `logical_root` podia ser
/// transplantada em silêncio para outro segmento ou outro banco e continuar a
/// fechar contra o mesmo carimbo do tempo.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AttestationEnvelopeV1 {
    pub storage_namespace_id: StorageNamespaceId,
    pub segment_id: SegmentId,
    pub canonical_codec_version: u16,
    pub first_lsn: Lsn,
    pub last_lsn: Lsn,
    pub record_count: u64,
    pub logical_root: [u8; 32],
}

impl AttestationEnvelopeV1 {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(96);
        out.put_bytes(&self.storage_namespace_id);
        out.put_u64_le(self.segment_id);
        out.put_bytes(&self.canonical_codec_version.to_le_bytes());
        out.put_u64_le(self.first_lsn);
        out.put_u64_le(self.last_lsn);
        out.put_u64_le(self.record_count);
        out.put_bytes(&self.logical_root);
        out
    }

    /// O *imprint* a submeter à autoridade de carimbo do tempo.
    pub fn imprint(&self) -> [u8; 32] {
        let mut h = blake3::Hasher::new();
        h.update(DOMAIN_ATTESTATION);
        h.update(&self.encode());
        *h.finalize().as_bytes()
    }
}

/// SPEC-0050 §87 — transformar RAW em PACKED é um evento auditável.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackReceipt {
    pub segment_id: SegmentId,
    pub storage_namespace_id: StorageNamespaceId,
    pub source_generation: u32,
    pub source_physical_digest: [u8; 32],
    pub target_generation: u32,
    pub target_physical_digest: [u8; 32],
    /// A prova de que a substituição é legítima: tem de ser a mesma dos dois
    /// lados (§134 e invariante 3).
    pub logical_root: [u8; 32],
    pub canonical_codec: u8,
    pub codec: CompressionCodec,
    pub block_size: u32,
    pub first_lsn: Lsn,
    pub last_lsn: Lsn,
    pub record_count: u64,
    pub source_physical_size: u64,
    pub target_physical_size: u64,
    pub packer_version: u32,
    pub created_hlc: u64,
}

/// Versão do packer que entra no recibo. Sobe quando o encoding físico muda,
/// mesmo que a identidade lógica não mude — é o que permite reproduzir um
/// `physical_digest` mais tarde (§167).
pub const PACKER_VERSION: u32 = 1;

impl PackReceipt {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(200);
        out.put_u64_le(self.segment_id);
        out.put_bytes(&self.storage_namespace_id);
        out.put_u32_le(self.source_generation);
        out.put_bytes(&self.source_physical_digest);
        out.put_u32_le(self.target_generation);
        out.put_bytes(&self.target_physical_digest);
        out.put_bytes(&self.logical_root);
        out.put_u8(self.canonical_codec);
        out.put_u8(self.codec as u8);
        out.put_u32_le(self.block_size);
        out.put_u64_le(self.first_lsn);
        out.put_u64_le(self.last_lsn);
        out.put_u64_le(self.record_count);
        out.put_u64_le(self.source_physical_size);
        out.put_u64_le(self.target_physical_size);
        out.put_u32_le(self.packer_version);
        out.put_u64_le(self.created_hlc);
        out
    }

    pub fn digest(&self) -> [u8; 32] {
        let mut h = blake3::Hasher::new();
        h.update(DOMAIN_PACK_RECEIPT);
        h.update(&self.encode());
        *h.finalize().as_bytes()
    }

    /// Rácio físico alcançado — a métrica que a operação lê (§180).
    pub fn compression_ratio(&self) -> f64 {
        if self.source_physical_size == 0 {
            return 1.0;
        }
        self.target_physical_size as f64 / self.source_physical_size as f64
    }

    pub fn attestation(&self) -> AttestationEnvelopeV1 {
        AttestationEnvelopeV1 {
            storage_namespace_id: self.storage_namespace_id,
            segment_id: self.segment_id,
            canonical_codec_version: self.canonical_codec as u16,
            first_lsn: self.first_lsn,
            last_lsn: self.last_lsn,
            record_count: self.record_count,
            logical_root: self.logical_root,
        }
    }
}

/// SPEC-0050 §132 — a ponte auditável entre um segmento v1–v5 e a sua
/// representação v6.
///
/// §131: é **incorrecto** declarar `v5 physical root == v6 logical root`. São
/// conceitos diferentes (a raiz v5 é sobre bytes físicos, a v6 sobre registos
/// canónicos). O recibo regista os dois lado a lado em vez de os confundir.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LegacyMigrationReceipt {
    pub legacy_format: u16,
    pub legacy_segment_id: SegmentId,
    pub legacy_root: [u8; 32],
    pub canonical_codec_v6: u8,
    pub v6_logical_root: [u8; 32],
    pub target_generation: u32,
    pub target_physical_digest: [u8; 32],
    pub record_count: u64,
}

impl LegacyMigrationReceipt {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(160);
        out.put_bytes(&self.legacy_format.to_le_bytes());
        out.put_u64_le(self.legacy_segment_id);
        out.put_bytes(&self.legacy_root);
        out.put_u8(self.canonical_codec_v6);
        out.put_bytes(&self.v6_logical_root);
        out.put_u32_le(self.target_generation);
        out.put_bytes(&self.target_physical_digest);
        out.put_u64_le(self.record_count);
        out
    }
}

// SPEC-0050 §71–§72 — `GenerationState` e `PhysicalGeneration` **não** são
// definidos aqui. §69 proíbe um segundo catálogo, e um segundo tipo para
// descrever gerações seria a mesma doença noutra camada: o manifesto teria de
// converter entre duas noções de "o que é uma geração", e a conversão é onde a
// verdade se perde. A definição vive em `heraclitus_core::runtime`, junto do
// `DatabaseManifest` que as guarda; aqui só se reexporta para quem trabalha
// contra o v6 não ter de saber disso.
pub use heraclitus_core::runtime::{GenerationState, PhysicalGeneration};

/// SPEC-0050 §53 — `BLAKE3` sobre o ficheiro físico inteiro.
///
/// Não é auto-referencial: vive no `SegmentGeneration`, no manifesto e no
/// recibo, nunca dentro do próprio objecto.
pub fn physical_digest(bytes: &[u8]) -> [u8; 32] {
    *blake3::hash(bytes).as_bytes()
}

/// `physical_digest` de um ficheiro, em streaming.
pub fn physical_digest_of_file(path: &std::path::Path) -> super::error::V6Result<[u8; 32]> {
    use std::io::Read;
    let mut f = std::fs::File::open(path)?;
    let mut h = blake3::Hasher::new();
    let mut buf = vec![0u8; 1 << 20];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(*h.finalize().as_bytes())
}

/// Constrói o envelope de atestação de um segmento selado.
pub fn attestation_for(
    storage_namespace_id: StorageNamespaceId,
    segment_id: SegmentId,
    footer: &super::footer::FooterV6,
) -> AttestationEnvelopeV1 {
    AttestationEnvelopeV1 {
        storage_namespace_id,
        segment_id,
        canonical_codec_version: CANONICAL_CODEC_V1 as u16,
        first_lsn: footer.min_lsn,
        last_lsn: footer.max_lsn,
        record_count: footer.record_count,
        logical_root: footer.logical_root,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env() -> AttestationEnvelopeV1 {
        AttestationEnvelopeV1 {
            storage_namespace_id: [1u8; 16],
            segment_id: 88,
            canonical_codec_version: 1,
            first_lsn: 100,
            last_lsn: 199,
            record_count: 100,
            logical_root: [0xAB; 32],
        }
    }

    #[test]
    fn envelope_tem_tamanho_fixo_e_e_deterministico() {
        let e = env();
        assert_eq!(e.encode().len(), 16 + 8 + 2 + 8 + 8 + 8 + 32);
        assert_eq!(e.imprint(), env().imprint());
    }

    #[test]
    fn raiz_nao_pode_ser_transplantada() {
        // Mesma logical_root, segmento diferente => imprint diferente.
        let a = env();
        let mut b = env();
        b.segment_id = 89;
        assert_ne!(a.imprint(), b.imprint());

        // Mesma logical_root, banco diferente => imprint diferente.
        let mut c = env();
        c.storage_namespace_id = [2u8; 16];
        assert_ne!(a.imprint(), c.imprint());
    }

    #[test]
    fn recibo_de_packing_amarra_as_duas_geracoes() {
        let r = PackReceipt {
            segment_id: 88,
            storage_namespace_id: [1u8; 16],
            source_generation: 0,
            source_physical_digest: [0x11; 32],
            target_generation: 1,
            target_physical_digest: [0x22; 32],
            logical_root: [0xAB; 32],
            canonical_codec: CANONICAL_CODEC_V1,
            codec: CompressionCodec::Zstd,
            block_size: 262_144,
            first_lsn: 100,
            last_lsn: 199,
            record_count: 100,
            source_physical_size: 1000,
            target_physical_size: 370,
            packer_version: PACKER_VERSION,
            created_hlc: 5,
        };
        assert_eq!(r.digest(), r.clone().digest());
        assert!((r.compression_ratio() - 0.37).abs() < 1e-9);
        assert_eq!(r.attestation().logical_root, r.logical_root);

        let mut outro = r.clone();
        outro.target_physical_digest = [0x33; 32];
        assert_ne!(r.digest(), outro.digest());
    }

    #[test]
    fn estados_que_sao_autoridade_canonica() {
        assert!(GenerationState::Verified.is_canonical_authority());
        assert!(GenerationState::Active.is_canonical_authority());
        assert!(GenerationState::Archived.is_canonical_authority());
        // Superseded CONTA: os bytes continuam verificados e legíveis, e é
        // isso que permite a §127 reactivar a RAW quando a PACKED falha.
        assert!(GenerationState::Superseded.is_canonical_authority());
        assert!(!GenerationState::Quarantined.is_canonical_authority());
        assert!(!GenerationState::Writing.is_canonical_authority());
    }

    #[test]
    fn digest_fisico_muda_com_os_bytes() {
        assert_ne!(physical_digest(b"abc"), physical_digest(b"abd"));
    }
}
