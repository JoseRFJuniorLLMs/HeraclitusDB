//! SPEC-0050 §19, §86–§87, §132 — envelopes e recibos.
//!
//! Todos codificados pelo mesmo [`CanonicalSink`] dos registos: um recibo que
//! dependesse de `serde` teria a mesma fragilidade que a SPEC proíbe para a
//! identidade lógica — recompilar mudaria os bytes assinados.

use std::io::Write;
use std::path::{Path, PathBuf};

use heraclitus_core::{Lsn, SegmentId};

use super::canonical::{CanonicalSink, CANONICAL_CODEC_V1};
use super::compress::CompressionCodec;
use super::header::StorageNamespaceId;

pub const DOMAIN_ATTESTATION: &[u8] = b"HRKL6:ATTESTATION_ENVELOPE:V1";
pub const DOMAIN_PACK_RECEIPT: &[u8] = b"HRKL6:PACK_RECEIPT:V1";
pub const DOMAIN_MIGRATION_RECEIPT: &[u8] = b"HRKL6:LEGACY_MIGRATION_RECEIPT:V1";
pub const PACK_RECEIPT_MAGIC: [u8; 4] = *b"HRPR";
pub const MIGRATION_RECEIPT_MAGIC: [u8; 4] = *b"HRMR";
pub const MIGRATION_RECEIPT_FILE_VERSION: u16 = 1;
/// 2 + 8 + 32 + 1 + 32 + 4 + 32 + 8
pub const MIGRATION_RECEIPT_BODY_LEN: usize = 119;
pub const PACK_RECEIPT_FILE_VERSION: u16 = 1;
pub const PACK_RECEIPT_BODY_LEN: usize = 186;

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

    /// Descodifica os bytes canónicos fixos do recibo. O comprimento exato
    /// evita aceitar prefixos, sufixos ou layouts futuros como se fossem v1.
    pub fn decode(bytes: &[u8]) -> super::error::V6Result<Self> {
        use super::error::corrupt;
        const CTX: &str = "hrkl v6 pack receipt";
        if bytes.len() != PACK_RECEIPT_BODY_LEN {
            return Err(corrupt(
                CTX,
                format!(
                    "receipt body has {} bytes, expected {PACK_RECEIPT_BODY_LEN}",
                    bytes.len()
                ),
            ));
        }
        let mut at = 0usize;
        fn take<const N: usize>(bytes: &[u8], at: &mut usize) -> [u8; N] {
            let out = bytes[*at..*at + N].try_into().unwrap();
            *at += N;
            out
        }
        let segment_id = u64::from_le_bytes(take(bytes, &mut at));
        let storage_namespace_id = take(bytes, &mut at);
        let source_generation = u32::from_le_bytes(take(bytes, &mut at));
        let source_physical_digest = take(bytes, &mut at);
        let target_generation = u32::from_le_bytes(take(bytes, &mut at));
        let target_physical_digest = take(bytes, &mut at);
        let logical_root = take(bytes, &mut at);
        let canonical_codec = take::<1>(bytes, &mut at)[0];
        let codec = CompressionCodec::from_u8(take::<1>(bytes, &mut at)[0])?;
        let block_size = u32::from_le_bytes(take(bytes, &mut at));
        let first_lsn = u64::from_le_bytes(take(bytes, &mut at));
        let last_lsn = u64::from_le_bytes(take(bytes, &mut at));
        let record_count = u64::from_le_bytes(take(bytes, &mut at));
        let source_physical_size = u64::from_le_bytes(take(bytes, &mut at));
        let target_physical_size = u64::from_le_bytes(take(bytes, &mut at));
        let packer_version = u32::from_le_bytes(take(bytes, &mut at));
        let created_hlc = u64::from_le_bytes(take(bytes, &mut at));
        debug_assert_eq!(at, PACK_RECEIPT_BODY_LEN);
        Ok(Self {
            segment_id,
            storage_namespace_id,
            source_generation,
            source_physical_digest,
            target_generation,
            target_physical_digest,
            logical_root,
            canonical_codec,
            codec,
            block_size,
            first_lsn,
            last_lsn,
            record_count,
            source_physical_size,
            target_physical_size,
            packer_version,
            created_hlc,
        })
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

/// Persiste um `PackReceipt` como objeto imutável e sincronizado antes do
/// commit do HRKM. Um crash pode deixar recibo/PACKED órfãos, mas nunca faz o
/// manifesto afirmar uma transição sem a evidência auditável correspondente.
pub fn persist_pack_receipt(dir: &Path, receipt: &PackReceipt) -> super::error::V6Result<PathBuf> {
    std::fs::create_dir_all(dir)?;
    let path = dir.join(format!(
        "pack-{:020}-g{:04}-g{:04}.hrpr",
        receipt.segment_id, receipt.source_generation, receipt.target_generation
    ));
    let encoded = encode_pack_receipt_file(receipt);
    if path.exists() {
        let existing = std::fs::read(&path)?;
        let decoded = decode_pack_receipt_file(&existing)?;
        if decoded != *receipt {
            return Err(super::error::corrupt(
                "hrkl v6 pack receipt store",
                "immutable receipt path already contains different evidence",
            ));
        }
        return Ok(path);
    }

    let tmp = path.with_extension("hrpr.tmp");
    let _ = std::fs::remove_file(&tmp);
    let mut file = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&tmp)?;
    file.write_all(&encoded)?;
    file.sync_all()?;
    drop(file);
    std::fs::rename(&tmp, &path)?;
    sync_parent_dir(dir)?;
    Ok(path)
}

/// SPEC-0050 §132 — persiste a ponte auditável entre um segmento legado e a
/// sua representação v6.
///
/// Um recibo que só existisse em memória não é uma ponte auditável: o auditor
/// aparece meses depois, com o ficheiro legado numa mão e o v6 na outra, e
/// precisa de um terceiro artefacto que diga *qual* deu origem a *qual* e sob
/// que codec. É esse artefacto.
///
/// Reescrever com bytes diferentes é **erro**, não um `PUT`: um recibo é uma
/// afirmação assinada sobre um facto passado. Reescrever com os mesmos bytes é
/// idempotente, porque um retry não pode virar falha operacional.
pub fn persist_migration_receipt(
    dir: &Path,
    receipt: &LegacyMigrationReceipt,
) -> super::error::V6Result<PathBuf> {
    use super::error::corrupt;
    std::fs::create_dir_all(dir)?;
    let path = dir.join(format!(
        "migrate-{:020}-g{:04}.hrmr",
        receipt.legacy_segment_id, receipt.target_generation
    ));
    let encoded = encode_migration_receipt_file(receipt);
    if path.exists() {
        let existing = std::fs::read(&path)?;
        let decoded = decode_migration_receipt_file(&existing)?;
        if decoded != *receipt {
            return Err(corrupt(
                "hrkl v6 migration receipt",
                format!(
                    "já existe um recibo diferente para o segmento {} geração {}",
                    receipt.legacy_segment_id, receipt.target_generation
                ),
            ));
        }
        return Ok(path);
    }
    let tmp = path.with_extension("hrmr.tmp");
    let mut file = std::fs::File::create(&tmp)?;
    file.write_all(&encoded)?;
    file.sync_all()?;
    drop(file);
    std::fs::rename(&tmp, &path)?;
    Ok(path)
}

pub fn read_migration_receipt(path: &Path) -> super::error::V6Result<LegacyMigrationReceipt> {
    decode_migration_receipt_file(&std::fs::read(path)?)
}

fn encode_migration_receipt_file(receipt: &LegacyMigrationReceipt) -> Vec<u8> {
    let body = receipt.encode();
    debug_assert_eq!(body.len(), MIGRATION_RECEIPT_BODY_LEN);
    let mut out = Vec::with_capacity(8 + body.len() + 36);
    out.extend_from_slice(&MIGRATION_RECEIPT_MAGIC);
    out.extend_from_slice(&MIGRATION_RECEIPT_FILE_VERSION.to_le_bytes());
    out.extend_from_slice(&(MIGRATION_RECEIPT_BODY_LEN as u16).to_le_bytes());
    out.extend_from_slice(&body);
    out.extend_from_slice(&receipt.digest());
    out.extend_from_slice(&0u32.to_le_bytes());
    let crc = super::crc32c_of(&out);
    let crc_at = out.len() - 4;
    out[crc_at..].copy_from_slice(&crc.to_le_bytes());
    out
}

fn decode_migration_receipt_file(bytes: &[u8]) -> super::error::V6Result<LegacyMigrationReceipt> {
    use super::error::corrupt;
    const CTX: &str = "hrkl v6 migration receipt file";
    const PREFIX: usize = 8;
    const SUFFIX: usize = 36;
    if bytes.len() != PREFIX + MIGRATION_RECEIPT_BODY_LEN + SUFFIX {
        return Err(corrupt(CTX, "comprimento inesperado"));
    }
    if bytes[..4] != MIGRATION_RECEIPT_MAGIC {
        return Err(corrupt(CTX, "magia errada"));
    }
    if u16::from_le_bytes(bytes[4..6].try_into().unwrap()) != MIGRATION_RECEIPT_FILE_VERSION {
        return Err(corrupt(CTX, "versão de recibo não suportada"));
    }
    if u16::from_le_bytes(bytes[6..8].try_into().unwrap()) as usize != MIGRATION_RECEIPT_BODY_LEN {
        return Err(corrupt(CTX, "comprimento de corpo inesperado"));
    }
    let stored_crc = u32::from_le_bytes(bytes[bytes.len() - 4..].try_into().unwrap());
    let mut checked = bytes.to_vec();
    checked[bytes.len() - 4..].fill(0);
    if stored_crc != super::crc32c_of(&checked) {
        return Err(corrupt(CTX, "crc32c não bate"));
    }
    let body = &bytes[PREFIX..PREFIX + MIGRATION_RECEIPT_BODY_LEN];
    let receipt = LegacyMigrationReceipt::decode(body)?;
    let declared: [u8; 32] = bytes
        [PREFIX + MIGRATION_RECEIPT_BODY_LEN..PREFIX + MIGRATION_RECEIPT_BODY_LEN + 32]
        .try_into()
        .unwrap();
    if receipt.digest() != declared {
        return Err(corrupt(CTX, "digest do recibo não bate"));
    }
    Ok(receipt)
}

pub fn read_pack_receipt(path: &Path) -> super::error::V6Result<PackReceipt> {
    decode_pack_receipt_file(&std::fs::read(path)?)
}

fn encode_pack_receipt_file(receipt: &PackReceipt) -> Vec<u8> {
    let body = receipt.encode();
    debug_assert_eq!(body.len(), PACK_RECEIPT_BODY_LEN);
    let mut out = Vec::with_capacity(4 + 2 + 2 + body.len() + 32 + 4);
    out.extend_from_slice(&PACK_RECEIPT_MAGIC);
    out.extend_from_slice(&PACK_RECEIPT_FILE_VERSION.to_le_bytes());
    out.extend_from_slice(&(PACK_RECEIPT_BODY_LEN as u16).to_le_bytes());
    out.extend_from_slice(&body);
    out.extend_from_slice(&receipt.digest());
    out.extend_from_slice(&0u32.to_le_bytes());
    let crc = super::crc32c_of(&out);
    let crc_at = out.len() - 4;
    out[crc_at..].copy_from_slice(&crc.to_le_bytes());
    out
}

fn decode_pack_receipt_file(bytes: &[u8]) -> super::error::V6Result<PackReceipt> {
    use super::error::corrupt;
    const CTX: &str = "hrkl v6 pack receipt file";
    const PREFIX: usize = 8;
    const SUFFIX: usize = 36;
    if bytes.len() != PREFIX + PACK_RECEIPT_BODY_LEN + SUFFIX {
        return Err(corrupt(CTX, "unexpected receipt file length"));
    }
    if bytes[..4] != PACK_RECEIPT_MAGIC {
        return Err(corrupt(CTX, "bad magic"));
    }
    if u16::from_le_bytes(bytes[4..6].try_into().unwrap()) != PACK_RECEIPT_FILE_VERSION {
        return Err(corrupt(CTX, "unsupported receipt version"));
    }
    if u16::from_le_bytes(bytes[6..8].try_into().unwrap()) as usize != PACK_RECEIPT_BODY_LEN {
        return Err(corrupt(CTX, "unexpected receipt body length"));
    }
    let stored_crc = u32::from_le_bytes(bytes[bytes.len() - 4..].try_into().unwrap());
    let mut checked = bytes.to_vec();
    checked[bytes.len() - 4..].fill(0);
    if stored_crc != super::crc32c_of(&checked) {
        return Err(corrupt(CTX, "crc32c mismatch"));
    }
    let body = &bytes[PREFIX..PREFIX + PACK_RECEIPT_BODY_LEN];
    let receipt = PackReceipt::decode(body)?;
    let declared: [u8; 32] = bytes
        [PREFIX + PACK_RECEIPT_BODY_LEN..PREFIX + PACK_RECEIPT_BODY_LEN + 32]
        .try_into()
        .unwrap();
    if receipt.digest() != declared {
        return Err(corrupt(CTX, "receipt digest mismatch"));
    }
    Ok(receipt)
}

fn sync_parent_dir(dir: &Path) -> super::error::V6Result<()> {
    #[cfg(unix)]
    std::fs::File::open(dir)?.sync_all()?;
    #[cfg(not(unix))]
    let _ = dir;
    Ok(())
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
    /// Identidade do recibo, com separador de domínio próprio.
    ///
    /// Sem o separador, os bytes de um recibo de migração e os de um recibo de
    /// packing poderiam colidir no mesmo digest — e são afirmações
    /// completamente diferentes sobre um segmento.
    pub fn digest(&self) -> [u8; 32] {
        let mut h = blake3::Hasher::new();
        h.update(DOMAIN_MIGRATION_RECEIPT);
        h.update(&self.encode());
        *h.finalize().as_bytes()
    }

    /// Descodifica os bytes canónicos fixos. O comprimento exacto evita aceitar
    /// prefixos, sufixos ou layouts futuros como se fossem v1.
    pub fn decode(bytes: &[u8]) -> super::error::V6Result<Self> {
        use super::error::corrupt;
        const CTX: &str = "hrkl v6 migration receipt";
        if bytes.len() != MIGRATION_RECEIPT_BODY_LEN {
            return Err(corrupt(
                CTX,
                format!(
                    "corpo com {} bytes, esperava {MIGRATION_RECEIPT_BODY_LEN}",
                    bytes.len()
                ),
            ));
        }
        let mut p = 0usize;
        let mut take = |n: usize| {
            let out = &bytes[p..p + n];
            p += n;
            out
        };
        let legacy_format = u16::from_le_bytes(take(2).try_into().unwrap());
        let legacy_segment_id = u64::from_le_bytes(take(8).try_into().unwrap());
        let legacy_root: [u8; 32] = take(32).try_into().unwrap();
        let canonical_codec_v6 = take(1)[0];
        let v6_logical_root: [u8; 32] = take(32).try_into().unwrap();
        let target_generation = u32::from_le_bytes(take(4).try_into().unwrap());
        let target_physical_digest: [u8; 32] = take(32).try_into().unwrap();
        let record_count = u64::from_le_bytes(take(8).try_into().unwrap());
        Ok(Self {
            legacy_format,
            legacy_segment_id,
            legacy_root,
            canonical_codec_v6,
            v6_logical_root,
            target_generation,
            target_physical_digest,
            record_count,
        })
    }

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

    fn receipt() -> PackReceipt {
        PackReceipt {
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
        let r = receipt();
        assert_eq!(r.digest(), r.clone().digest());
        assert!((r.compression_ratio() - 0.37).abs() < 1e-9);
        assert_eq!(r.attestation().logical_root, r.logical_root);

        let mut outro = r.clone();
        outro.target_physical_digest = [0x33; 32];
        assert_ne!(r.digest(), outro.digest());
    }

    #[test]
    fn recibo_persistido_e_imutavel_idempotente() {
        let dir = std::env::temp_dir().join(format!("hrkl-v6-receipts-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let r = receipt();
        let path = persist_pack_receipt(&dir, &r).unwrap();
        assert_eq!(read_pack_receipt(&path).unwrap(), r);
        assert_eq!(persist_pack_receipt(&dir, &r).unwrap(), path);

        let mut conflicting = r.clone();
        conflicting.target_physical_digest[0] ^= 1;
        assert!(persist_pack_receipt(&dir, &conflicting).is_err());

        let mut corrupt = std::fs::read(&path).unwrap();
        corrupt[20] ^= 1;
        std::fs::write(&path, corrupt).unwrap();
        assert!(read_pack_receipt(&path).is_err());
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
