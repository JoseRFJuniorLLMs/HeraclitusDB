//! SPEC-0050 §68–§75 — o manifesto interno `.hrkm`.
//!
//! # O que o `.hrkm` é e o que não é
//!
//! §68/§173: `.hrkm` **não** significa "ficheiro Iceberg". É o catálogo interno
//! do Heraclitus — segmentos, gerações, localização física, raízes lógicas,
//! artefactos derivados, estados, watermarks e retenção. Iceberg é metadata de
//! tabela externa; podem partilhar ideias, não partilham formato.
//!
//! §69: não há aqui um segundo catálogo. O tipo é
//! [`heraclitus_core::DatabaseManifest`]; este módulo é apenas a sua
//! representação persistente e o protocolo de commit.
//!
//! # Layout
//!
//! ```text
//! HrkmHeaderV1   64 bytes
//! body           segment_count descritores canónicos (varint)
//! HrkmFooterV1   96 bytes
//! ```
//!
//! O CRC-32C do footer cobre o **ficheiro inteiro** com o próprio campo a zero,
//! e o `body_blake3` identifica o corpo independentemente do enquadramento. Um
//! manifesto meio escrito falha nos dois.
//!
//! # Porque snapshots numerados e um `CURRENT`
//!
//! §74/§75. A alternativa — reescrever `manifest.hrkm` no sítio — tem uma
//! janela em que o ficheiro não é nem o antigo nem o novo. Com snapshots
//! imutáveis mais um ponteiro trocado por `rename`, **o manifesto antigo
//! permanece válido durante toda a operação**: se o processo morrer a meio,
//! `CURRENT` ainda aponta para uma geração completa.

use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};

use heraclitus_core::runtime::{
    CompressionCodec, DatabaseManifest, DerivedArtifactRef, GenerationState, PhysicalGeneration,
    PhysicalLayout, RetentionPolicy, SegmentDescriptorV2,
};
use heraclitus_core::{Lsn, SegmentId};

use super::canonical::CanonicalSink;
use super::error::{corrupt, slice_at, V6Result};
use super::footer::FooterV6;
use super::receipts::PackReceipt;
use super::varint::{read_varint, read_varint_usize};

pub const HRKM_MAGIC: [u8; 4] = *b"HRKM";
pub const HRKM_FOOTER_MAGIC: [u8; 4] = *b"HKMF";
pub const HRKM_FORMAT_VERSION: u16 = 1;
pub const HRKM_HEADER_LEN: usize = 64;
pub const HRKM_FOOTER_LEN: usize = 96;
const FOOTER_CRC_OFFSET: usize = 92;

/// Tecto do número de segmentos num manifesto. 2^24 segmentos de 256 MiB são
/// 4 PiB — muito acima do plausível, e finito, que é o que §137 exige.
pub const HARD_MAX_SEGMENTS: u32 = 1 << 24;
/// Tecto do corpo, para que um `body_len` vindo do disco não vire alocação.
pub const HARD_MAX_BODY_BYTES: usize = 512 * 1024 * 1024;
/// Tecto do comprimento de uma `location` (caminho ou chave de objecto).
pub const HARD_MAX_LOCATION_BYTES: usize = 8 * 1024;

/// Nome do ficheiro que aponta para a geração válida (§74).
pub const CURRENT_FILE: &str = "CURRENT";

// ---------------------------------------------------------------------------
// Codec
// ---------------------------------------------------------------------------

fn encode_generation(out: &mut Vec<u8>, g: &PhysicalGeneration) {
    out.put_varint(g.generation as u64);
    out.put_u8(g.layout as u8);
    out.put_u8(g.compression as u8);
    out.put_u8(g.state as u8);
    out.put_varint(g.physical_size);
    out.put_bytes(&g.physical_digest);
    out.put_str(&g.location);
    out.put_varint(g.created_hlc);
    out.put_varint(g.verified_hlc);
    out.put_varint(g.superseded_hlc);
    out.put_varint(g.verified_copies as u64);
}

fn decode_generation(buf: &[u8], pos: &mut usize) -> V6Result<PhysicalGeneration> {
    const CTX: &str = "hrkm generation";
    let generation = read_u32(buf, pos, CTX)?;
    let layout = PhysicalLayout::from_u8(read_u8(buf, pos, CTX)?)?;
    let compression = CompressionCodec::from_u8(read_u8(buf, pos, CTX)?)?;
    let state = GenerationState::from_u8(read_u8(buf, pos, CTX)?)?;
    let physical_size = read_v(buf, pos, CTX)?;
    let physical_digest = read_32(buf, pos, CTX)?;
    let location = read_string(buf, pos, CTX)?;
    let created_hlc = read_v(buf, pos, CTX)?;
    let verified_hlc = read_v(buf, pos, CTX)?;
    let superseded_hlc = read_v(buf, pos, CTX)?;
    let verified_copies = read_u32(buf, pos, CTX)?;
    Ok(PhysicalGeneration {
        generation,
        layout,
        compression,
        location,
        physical_size,
        physical_digest,
        state,
        created_hlc,
        verified_hlc,
        superseded_hlc,
        verified_copies,
    })
}

fn encode_artifact(out: &mut Vec<u8>, a: &Option<DerivedArtifactRef>) {
    match a {
        None => out.put_u8(0),
        Some(a) => {
            out.put_u8(1);
            out.put_str(&a.location);
            out.put_varint(a.size);
            out.put_bytes(&a.digest);
            out.put_bytes(&a.logical_root);
            out.put_varint(a.created_hlc);
        }
    }
}

fn decode_artifact(buf: &[u8], pos: &mut usize) -> V6Result<Option<DerivedArtifactRef>> {
    const CTX: &str = "hrkm derived artifact";
    match read_u8(buf, pos, CTX)? {
        0 => Ok(None),
        1 => Ok(Some(DerivedArtifactRef {
            location: read_string(buf, pos, CTX)?,
            size: read_v(buf, pos, CTX)?,
            digest: read_32(buf, pos, CTX)?,
            logical_root: read_32(buf, pos, CTX)?,
            created_hlc: read_v(buf, pos, CTX)?,
        })),
        other => Err(corrupt(CTX, format!("invalid presence byte {other}"))),
    }
}

fn encode_segment(out: &mut Vec<u8>, s: &SegmentDescriptorV2) {
    out.put_varint(s.segment_id);
    out.put_varint(s.first_lsn);
    out.put_varint(s.last_lsn);
    out.put_varint(s.record_count);
    out.put_bytes(&s.canonical_codec.to_le_bytes());
    out.put_bytes(&s.logical_root);
    out.put_varint(s.min_hlc);
    out.put_varint(s.max_hlc);
    out.put_varint(s.active_generation as u64);
    out.put_varint(s.generations.len() as u64);
    for g in &s.generations {
        encode_generation(out, g);
    }
    encode_artifact(out, &s.hrki);
    encode_artifact(out, &s.parquet);
    out.put_u8(u8::from(s.retention.legal_hold));
    out.put_varint(s.retention.gc_grace_seconds);
    out.put_varint(s.retention.min_verified_copies as u64);
    out.put_u8(u8::from(s.retention.preserve_legacy_original));
}

fn decode_segment(buf: &[u8], pos: &mut usize) -> V6Result<SegmentDescriptorV2> {
    const CTX: &str = "hrkm segment descriptor";
    let segment_id = read_v(buf, pos, CTX)?;
    let first_lsn = read_v(buf, pos, CTX)?;
    let last_lsn = read_v(buf, pos, CTX)?;
    let record_count = read_v(buf, pos, CTX)?;
    let canonical_codec = u16::from_le_bytes(slice_at(buf, *pos, 2, CTX)?.try_into().unwrap());
    *pos += 2;
    let logical_root = read_32(buf, pos, CTX)?;
    let min_hlc = read_v(buf, pos, CTX)?;
    let max_hlc = read_v(buf, pos, CTX)?;
    let active_generation = read_u32(buf, pos, CTX)?;
    let gen_count = read_varint_usize(&buf[*pos..], CTX).map(|(v, n)| {
        *pos += n;
        v
    })?;
    // O número de gerações é um length vindo do disco: verificar contra os
    // bytes que restam ANTES de reservar (§137/§141). Uma geração ocupa no
    // mínimo 8 bytes codificados.
    if gen_count > (buf.len() - *pos) / 8 + 1 {
        return Err(corrupt(CTX, "generation count exceeds remaining bytes"));
    }
    let mut generations = Vec::with_capacity(gen_count.min(64));
    for _ in 0..gen_count {
        generations.push(decode_generation(buf, pos)?);
    }
    let hrki = decode_artifact(buf, pos)?;
    let parquet = decode_artifact(buf, pos)?;
    let retention = RetentionPolicy {
        legal_hold: read_bool(buf, pos, CTX)?,
        gc_grace_seconds: read_v(buf, pos, CTX)?,
        min_verified_copies: read_u32(buf, pos, CTX)?,
        preserve_legacy_original: read_bool(buf, pos, CTX)?,
    };

    let desc = SegmentDescriptorV2 {
        segment_id,
        first_lsn,
        last_lsn,
        record_count,
        canonical_codec,
        logical_root,
        min_hlc,
        max_hlc,
        active_generation,
        generations,
        hrki,
        parquet,
        retention,
    };
    check_segment_coherence(&desc)?;
    Ok(desc)
}

/// Coerência interna de um descritor. Um manifesto que passa o CRC pode ainda
/// assim declarar impossibilidades — e um catálogo incoerente leva o planner a
/// pedir LSNs que não existem.
fn check_segment_coherence(s: &SegmentDescriptorV2) -> V6Result<()> {
    const CTX: &str = "hrkm segment descriptor";
    if s.record_count > 0 {
        if s.first_lsn > s.last_lsn {
            return Err(corrupt(
                CTX,
                format!("segment {} has first_lsn > last_lsn", s.segment_id),
            ));
        }
        if s.min_hlc > s.max_hlc {
            return Err(corrupt(
                CTX,
                format!("segment {} has min_hlc > max_hlc", s.segment_id),
            ));
        }
        let span = s.last_lsn - s.first_lsn;
        if span.saturating_add(1) < s.record_count {
            return Err(corrupt(
                CTX,
                format!(
                    "segment {} declares more records than its LSN span",
                    s.segment_id
                ),
            ));
        }
    }
    let mut seen: Vec<u32> = s.generations.iter().map(|g| g.generation).collect();
    seen.sort_unstable();
    let antes = seen.len();
    seen.dedup();
    if seen.len() != antes {
        return Err(corrupt(
            CTX,
            format!("segment {} has duplicate generation numbers", s.segment_id),
        ));
    }
    if !s.generations.is_empty() && s.active().is_none() {
        return Err(corrupt(
            CTX,
            format!(
                "segment {} points at generation {} which does not exist",
                s.segment_id, s.active_generation
            ),
        ));
    }
    Ok(())
}

// Leitores primitivos, todos com verificação de limites.

fn read_u8(buf: &[u8], pos: &mut usize, ctx: &'static str) -> V6Result<u8> {
    let b = *slice_at(buf, *pos, 1, ctx)?.first().unwrap();
    *pos += 1;
    Ok(b)
}

fn read_bool(buf: &[u8], pos: &mut usize, ctx: &'static str) -> V6Result<bool> {
    match read_u8(buf, pos, ctx)? {
        0 => Ok(false),
        1 => Ok(true),
        other => Err(corrupt(ctx, format!("invalid boolean byte {other}"))),
    }
}

fn read_v(buf: &[u8], pos: &mut usize, ctx: &'static str) -> V6Result<u64> {
    let (v, n) = read_varint(&buf[(*pos).min(buf.len())..], ctx)?;
    *pos += n;
    Ok(v)
}

fn read_u32(buf: &[u8], pos: &mut usize, ctx: &'static str) -> V6Result<u32> {
    let v = read_v(buf, pos, ctx)?;
    u32::try_from(v).map_err(|_| corrupt(ctx, "value exceeds u32"))
}

fn read_32(buf: &[u8], pos: &mut usize, ctx: &'static str) -> V6Result<[u8; 32]> {
    let s: [u8; 32] = slice_at(buf, *pos, 32, ctx)?.try_into().unwrap();
    *pos += 32;
    Ok(s)
}

fn read_string(buf: &[u8], pos: &mut usize, ctx: &'static str) -> V6Result<String> {
    let (len, n) = read_varint_usize(&buf[(*pos).min(buf.len())..], ctx)?;
    *pos += n;
    if len > HARD_MAX_LOCATION_BYTES {
        return Err(corrupt(
            ctx,
            format!("string of {len} bytes exceeds the hard maximum"),
        ));
    }
    let raw = slice_at(buf, *pos, len, ctx)?;
    *pos += len;
    String::from_utf8(raw.to_vec()).map_err(|_| corrupt(ctx, "location is not valid UTF-8"))
}

/// Serializa um `DatabaseManifest` no formato `.hrkm`.
pub fn encode_manifest(m: &DatabaseManifest) -> V6Result<Vec<u8>> {
    const CTX: &str = "hrkm encode";
    if m.segments_v2.len() as u64 > HARD_MAX_SEGMENTS as u64 {
        return Err(corrupt(CTX, "too many segments for one manifest"));
    }
    let mut body = Vec::with_capacity(256 * m.segments_v2.len() + 64);
    for s in &m.segments_v2 {
        encode_segment(&mut body, s);
    }
    if body.len() > HARD_MAX_BODY_BYTES {
        return Err(corrupt(CTX, "manifest body exceeds the hard maximum"));
    }

    let mut out = Vec::with_capacity(HRKM_HEADER_LEN + body.len() + HRKM_FOOTER_LEN);
    let mut h = [0u8; HRKM_HEADER_LEN];
    h[0..4].copy_from_slice(&HRKM_MAGIC);
    h[4..6].copy_from_slice(&HRKM_FORMAT_VERSION.to_le_bytes());
    h[6..8].copy_from_slice(&(HRKM_HEADER_LEN as u16).to_le_bytes());
    h[8..16].copy_from_slice(&m.manifest_generation.to_le_bytes());
    h[16..32].copy_from_slice(&m.storage_namespace_id);
    h[32..40].copy_from_slice(&m.cumulative_watermark.to_le_bytes());
    h[40..48].copy_from_slice(&m.exported_through_lsn.to_le_bytes());
    h[48..52].copy_from_slice(&(m.segments_v2.len() as u32).to_le_bytes());
    h[52..56].copy_from_slice(&0u32.to_le_bytes());
    let hcrc = super::crc32c_of(&h[..60]);
    h[60..64].copy_from_slice(&hcrc.to_le_bytes());
    out.extend_from_slice(&h);
    out.extend_from_slice(&body);

    let mut f = [0u8; HRKM_FOOTER_LEN];
    f[0..4].copy_from_slice(&HRKM_FOOTER_MAGIC);
    f[4..6].copy_from_slice(&1u16.to_le_bytes());
    f[6..8].copy_from_slice(&(HRKM_FOOTER_LEN as u16).to_le_bytes());
    f[8..16].copy_from_slice(&(body.len() as u64).to_le_bytes());
    f[16..48].copy_from_slice(blake3::hash(&body).as_bytes());
    f[48..80].copy_from_slice(&m.statistics_root_hash);
    out.extend_from_slice(&f);

    // CRC sobre o ficheiro inteiro com o próprio campo a zero.
    let crc = super::crc32c_of(&out);
    let at = out.len() - HRKM_FOOTER_LEN + FOOTER_CRC_OFFSET;
    out[at..at + 4].copy_from_slice(&crc.to_le_bytes());
    Ok(out)
}

/// Descodifica um `.hrkm`.
pub fn decode_manifest(buf: &[u8]) -> V6Result<DatabaseManifest> {
    const CTX: &str = "hrkm";
    if buf.len() < HRKM_HEADER_LEN + HRKM_FOOTER_LEN {
        return Err(corrupt(CTX, "file too small to hold a header and a footer"));
    }
    if buf[0..4] != HRKM_MAGIC {
        return Err(corrupt(CTX, "bad magic"));
    }
    let version = u16::from_le_bytes(buf[4..6].try_into().unwrap());
    if version != HRKM_FORMAT_VERSION {
        return Err(corrupt(CTX, format!("unsupported hrkm version {version}")));
    }
    if u16::from_le_bytes(buf[6..8].try_into().unwrap()) as usize != HRKM_HEADER_LEN {
        return Err(corrupt(CTX, "unexpected header_len"));
    }
    let hcrc = u32::from_le_bytes(buf[60..64].try_into().unwrap());
    if hcrc != super::crc32c_of(&buf[..60]) {
        return Err(corrupt(CTX, "header crc32c mismatch"));
    }

    let footer_at = buf.len() - HRKM_FOOTER_LEN;
    let f = &buf[footer_at..];
    if f[0..4] != HRKM_FOOTER_MAGIC {
        return Err(corrupt(CTX, "bad footer magic"));
    }
    if u16::from_le_bytes(f[6..8].try_into().unwrap()) as usize != HRKM_FOOTER_LEN {
        return Err(corrupt(CTX, "unexpected footer_len"));
    }
    let stored_crc = u32::from_le_bytes(
        f[FOOTER_CRC_OFFSET..FOOTER_CRC_OFFSET + 4]
            .try_into()
            .unwrap(),
    );
    let mut zeroed = buf.to_vec();
    let at = footer_at + FOOTER_CRC_OFFSET;
    zeroed[at..at + 4].fill(0);
    if stored_crc != super::crc32c_of(&zeroed) {
        return Err(corrupt(CTX, "file crc32c mismatch"));
    }

    let body_len = u64::from_le_bytes(f[8..16].try_into().unwrap());
    let body_len = usize::try_from(body_len).map_err(|_| corrupt(CTX, "body_len exceeds usize"))?;
    if body_len != footer_at - HRKM_HEADER_LEN {
        return Err(corrupt(CTX, "body_len does not match the framed body"));
    }
    let body = &buf[HRKM_HEADER_LEN..footer_at];
    let declared_body_digest: [u8; 32] = f[16..48].try_into().unwrap();
    if *blake3::hash(body).as_bytes() != declared_body_digest {
        return Err(corrupt(CTX, "body digest mismatch"));
    }

    let segment_count = u32::from_le_bytes(buf[48..52].try_into().unwrap());
    if segment_count > HARD_MAX_SEGMENTS {
        return Err(corrupt(CTX, "segment_count above hard maximum"));
    }
    let mut segments_v2 = Vec::with_capacity((segment_count as usize).min(4096));
    let mut pos = 0usize;
    for _ in 0..segment_count {
        segments_v2.push(decode_segment(body, &mut pos)?);
    }
    if pos != body.len() {
        return Err(corrupt(CTX, "trailing bytes after the declared segments"));
    }
    // A ordem por `first_lsn` é o que torna a busca binária de §77 correcta.
    for w in segments_v2.windows(2) {
        if w[0].first_lsn > w[1].first_lsn {
            return Err(corrupt(CTX, "segments are not ordered by first_lsn"));
        }
    }

    Ok(DatabaseManifest {
        manifest_version: version as u32,
        format_identifier: HRKM_MAGIC,
        segments: Vec::new(),
        cumulative_watermark: u64::from_le_bytes(buf[32..40].try_into().unwrap()),
        statistics_root_hash: f[48..80].try_into().unwrap(),
        storage_namespace_id: buf[16..32].try_into().unwrap(),
        manifest_generation: u64::from_le_bytes(buf[8..16].try_into().unwrap()),
        segments_v2,
        exported_through_lsn: u64::from_le_bytes(buf[40..48].try_into().unwrap()),
    })
}

/// `BLAKE3` do ficheiro inteiro — a identidade de uma geração de manifesto.
pub fn manifest_digest(bytes: &[u8]) -> [u8; 32] {
    *blake3::hash(bytes).as_bytes()
}

// ---------------------------------------------------------------------------
// Store
// ---------------------------------------------------------------------------

/// Um manifesto carregado do disco.
#[derive(Debug, Clone)]
pub struct LoadedManifest {
    pub manifest: DatabaseManifest,
    pub generation: u64,
    pub digest: [u8; 32],
    pub path: PathBuf,
    /// `true` se o `CURRENT` estava ausente ou inutilizável e a geração foi
    /// encontrada por varrimento do directório. Não é erro — é o caminho de
    /// recuperação de §75 — mas tem de ser visível ao operador.
    pub recovered_by_scan: bool,
}

/// O directório de manifestos, com o protocolo de commit de §75.
pub struct ManifestStore {
    dir: PathBuf,
}

impl ManifestStore {
    pub fn open(dir: impl AsRef<Path>) -> V6Result<Self> {
        let dir = dir.as_ref().to_path_buf();
        std::fs::create_dir_all(&dir)?;
        Ok(Self { dir })
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    pub fn path_for(&self, generation: u64) -> PathBuf {
        self.dir.join(format!("manifest-{generation:010}.hrkm"))
    }

    pub fn current_path(&self) -> PathBuf {
        self.dir.join(CURRENT_FILE)
    }

    /// Gerações presentes no directório, por ordem crescente.
    pub fn generations(&self) -> V6Result<Vec<u64>> {
        let mut out = Vec::new();
        for entry in std::fs::read_dir(&self.dir)? {
            let path = entry?.path();
            if let Some(g) = generation_of(&path) {
                out.push(g);
            }
        }
        out.sort_unstable();
        Ok(out)
    }

    /// Carrega o manifesto válido.
    ///
    /// Caminho normal: lê `CURRENT`, abre a geração que ele nomeia e confirma o
    /// digest. Caminho de recuperação: se `CURRENT` faltar ou apontar para algo
    /// inutilizável, varre o directório e usa a geração mais alta que
    /// descodifique — nunca inventa um manifesto vazio por cima de dados.
    pub fn load(&self) -> V6Result<Option<LoadedManifest>> {
        if let Some(loaded) = self.load_from_current()? {
            return Ok(Some(loaded));
        }
        let mut gens = self.generations()?;
        gens.reverse();
        for g in gens {
            let path = self.path_for(g);
            if let Ok(bytes) = std::fs::read(&path) {
                if let Ok(manifest) = decode_manifest(&bytes) {
                    return Ok(Some(LoadedManifest {
                        generation: manifest.manifest_generation,
                        digest: manifest_digest(&bytes),
                        manifest,
                        path,
                        recovered_by_scan: true,
                    }));
                }
            }
        }
        Ok(None)
    }

    fn load_from_current(&self) -> V6Result<Option<LoadedManifest>> {
        let raw = match std::fs::read_to_string(self.current_path()) {
            Ok(s) => s,
            Err(_) => return Ok(None),
        };
        let mut lines = raw.lines();
        let Some(name) = lines.next().map(str::trim) else {
            return Ok(None);
        };
        if name.is_empty() || name.contains('/') || name.contains('\\') {
            return Ok(None);
        }
        let path = self.dir.join(name);
        let Ok(bytes) = std::fs::read(&path) else {
            return Ok(None);
        };
        let digest = manifest_digest(&bytes);
        if let Some(expected) = lines.next().map(str::trim) {
            if !expected.is_empty() && expected != hex32(&digest) {
                // `CURRENT` aponta para bytes que não são os que foram
                // committed. Cair para o varrimento é mais seguro do que
                // aceitar — pode ser um ficheiro truncado que ainda passa CRC
                // por acaso, ou um restauro parcial de backup.
                return Ok(None);
            }
        }
        let Ok(manifest) = decode_manifest(&bytes) else {
            return Ok(None);
        };
        Ok(Some(LoadedManifest {
            generation: manifest.manifest_generation,
            digest,
            manifest,
            path,
            recovered_by_scan: false,
        }))
    }

    /// A próxima geração livre: uma acima da mais alta em disco.
    pub fn next_generation(&self) -> V6Result<u64> {
        Ok(self
            .generations()?
            .last()
            .copied()
            .map(|g| g + 1)
            .unwrap_or(1))
    }

    /// Escreve uma nova geração de manifesto e trocá o `CURRENT` (§75).
    ///
    /// A sequência é a da SPEC e a ordem **é** a garantia:
    ///
    /// ```text
    /// write manifest.tmp -> fsync -> rename -> fsync(dir)
    /// write CURRENT.tmp  -> fsync -> rename -> fsync(dir)
    /// ```
    ///
    /// Morrer em qualquer ponto deixa `CURRENT` a apontar para a geração
    /// anterior, que continua completa.
    pub fn commit(&self, manifest: &mut DatabaseManifest) -> V6Result<LoadedManifest> {
        const CTX: &str = "hrkm commit";
        let generation = self.next_generation()?;
        manifest.manifest_generation = generation;
        manifest.format_identifier = HRKM_MAGIC;
        let final_path = self.path_for(generation);
        if final_path.exists() {
            return Err(corrupt(
                CTX,
                "manifest generation already exists; generations are immutable",
            ));
        }
        let bytes = encode_manifest(manifest)?;
        let digest = manifest_digest(&bytes);

        let tmp = with_suffix(&final_path, ".tmp");
        write_and_sync(&tmp, &bytes)?;
        std::fs::rename(&tmp, &final_path)?;
        sync_dir(&self.dir)?;

        let current = self.current_path();
        let current_tmp = with_suffix(&current, ".tmp");
        let payload = format!("{}\n{}\n", file_name_of(&final_path), hex32(&digest));
        write_and_sync(&current_tmp, payload.as_bytes())?;
        std::fs::rename(&current_tmp, &current)?;
        sync_dir(&self.dir)?;

        Ok(LoadedManifest {
            manifest: manifest.clone(),
            generation,
            digest,
            path: final_path,
            recovered_by_scan: false,
        })
    }

    /// §89 — remove `.tmp` órfãos de um commit interrompido. Sempre seguro: um
    /// `.tmp` nunca é referenciado por `CURRENT`.
    pub fn sweep_orphan_temps(&self) -> V6Result<Vec<PathBuf>> {
        let mut removed = Vec::new();
        for entry in std::fs::read_dir(&self.dir)? {
            let path = entry?.path();
            if path.extension().and_then(|e| e.to_str()) == Some("tmp") {
                std::fs::remove_file(&path)?;
                removed.push(path);
            }
        }
        Ok(removed)
    }

    /// §90 — manifestos superseded podem ser coletados depois da retenção.
    /// `keep` é quantas gerações (incluindo a corrente) permanecem.
    ///
    /// Nunca remove a geração para que `CURRENT` aponta, mesmo que `keep` seja
    /// pequeno: o ponteiro tem de continuar a resolver.
    pub fn prune_old_manifests(&self, keep: usize) -> V6Result<Vec<PathBuf>> {
        let corrente = self.load_from_current()?.map(|l| l.generation);
        let gens = self.generations()?;
        let manter_a_partir = gens.len().saturating_sub(keep.max(1));
        let mut removed = Vec::new();
        for (i, g) in gens.iter().enumerate() {
            if i >= manter_a_partir || Some(*g) == corrente {
                continue;
            }
            let path = self.path_for(*g);
            std::fs::remove_file(&path)?;
            removed.push(path);
        }
        Ok(removed)
    }
}

fn generation_of(path: &Path) -> Option<u64> {
    let name = path.file_name()?.to_str()?;
    let rest = name.strip_prefix("manifest-")?.strip_suffix(".hrkm")?;
    rest.parse::<u64>().ok()
}

fn file_name_of(path: &Path) -> String {
    path.file_name()
        .and_then(|s| s.to_str())
        .unwrap_or_default()
        .to_string()
}

fn with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut s = path.as_os_str().to_os_string();
    s.push(suffix);
    PathBuf::from(s)
}

fn write_and_sync(path: &Path, bytes: &[u8]) -> V6Result<()> {
    let mut f = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(path)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    Ok(())
}

fn sync_dir(dir: &Path) -> V6Result<()> {
    // No Windows não é possível abrir um directório como ficheiro; o `rename`
    // do NTFS é atómico e o `sync_all` do ficheiro já cobriu os dados.
    #[cfg(unix)]
    File::open(dir)?.sync_all()?;
    #[cfg(not(unix))]
    let _ = dir;
    Ok(())
}

fn hex32(b: &[u8; 32]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(64);
    for x in b {
        let _ = write!(s, "{x:02x}");
    }
    s
}

// ---------------------------------------------------------------------------
// Máquina de estados (SPEC-0050 §72–§73, §88 passo 13)
// ---------------------------------------------------------------------------

/// Regista um segmento RAW acabado de selar.
///
/// Este é o momento em que o segmento entra no catálogo com identidade lógica.
/// A geração 0 nasce `Verified` porque o writer acabou de a produzir e o footer
/// já foi sincronizado — não é uma promessa, é o estado real.
#[allow(clippy::too_many_arguments)]
pub fn register_sealed_raw(
    m: &mut DatabaseManifest,
    segment_id: SegmentId,
    footer: &FooterV6,
    canonical_codec: u16,
    location: &str,
    physical_size: u64,
    physical_digest: [u8; 32],
    now_hlc: u64,
) -> V6Result<()> {
    const CTX: &str = "hrkm register";
    if let Some(existing) = m.segment(segment_id) {
        if existing.logical_root != footer.logical_root {
            return Err(corrupt(
                CTX,
                format!("segment {segment_id} is already catalogued with a different logical_root"),
            ));
        }
    }
    let gen = PhysicalGeneration {
        generation: 0,
        layout: PhysicalLayout::Raw,
        compression: CompressionCodec::Raw,
        location: location.to_string(),
        physical_size,
        physical_digest,
        state: GenerationState::Active,
        created_hlc: now_hlc,
        verified_hlc: now_hlc,
        superseded_hlc: 0,
        verified_copies: 1,
    };
    let desc = SegmentDescriptorV2 {
        segment_id,
        first_lsn: footer.min_lsn,
        last_lsn: footer.max_lsn,
        record_count: footer.record_count,
        canonical_codec,
        logical_root: footer.logical_root,
        min_hlc: footer.min_hlc,
        max_hlc: footer.max_hlc,
        active_generation: 0,
        generations: vec![gen],
        hrki: None,
        parquet: None,
        retention: RetentionPolicy::default(),
    };
    check_segment_coherence(&desc)?;
    m.upsert_segment(desc);
    m.cumulative_watermark = m.cumulative_watermark.max(footer.max_lsn);
    Ok(())
}

/// SPEC-0050 §88 passo 13/14 — regista o packing no manifesto.
///
/// A nova geração entra `Active` e a origem passa a `Superseded` com o carimbo
/// que arranca o grace period de §93. Nada é apagado: o passo 16 é
/// explicitamente "GC only later".
pub fn record_pack(
    m: &mut DatabaseManifest,
    receipt: &PackReceipt,
    target_location: &str,
    now_hlc: u64,
) -> V6Result<()> {
    const CTX: &str = "hrkm record_pack";
    let Some(desc) = m.segment_mut(receipt.segment_id) else {
        return Err(corrupt(
            CTX,
            format!("segment {} is not catalogued", receipt.segment_id),
        ));
    };
    // §97: se a raiz não bate, o output NÃO substitui o segmento canónico.
    if desc.logical_root != receipt.logical_root {
        return Err(corrupt(
            CTX,
            "pack receipt logical_root differs from the catalogued segment; refusing to record",
        ));
    }
    if desc.generation(receipt.target_generation).is_some() {
        return Err(corrupt(
            CTX,
            "target generation already recorded; generations are immutable",
        ));
    }
    desc.generations.push(PhysicalGeneration {
        generation: receipt.target_generation,
        layout: PhysicalLayout::Packed,
        compression: receipt.codec,
        location: target_location.to_string(),
        physical_size: receipt.target_physical_size,
        physical_digest: receipt.target_physical_digest,
        state: GenerationState::Active,
        created_hlc: now_hlc,
        verified_hlc: now_hlc,
        superseded_hlc: 0,
        verified_copies: 1,
    });
    desc.active_generation = receipt.target_generation;
    if let Some(src) = desc.generation_mut(receipt.source_generation) {
        if src.state != GenerationState::Quarantined {
            src.state = GenerationState::Superseded;
            src.superseded_hlc = now_hlc;
        }
    }
    check_segment_coherence(desc)
}

/// SPEC-0050 §127 — uma geração PACKED que falha a verificação é posta em
/// quarentena, **não** apagada, e o segmento volta a apontar para uma geração
/// autoritativa se existir.
pub fn quarantine_generation(
    m: &mut DatabaseManifest,
    segment_id: SegmentId,
    generation: u32,
    now_hlc: u64,
) -> V6Result<u32> {
    const CTX: &str = "hrkm quarantine";
    let Some(desc) = m.segment_mut(segment_id) else {
        return Err(corrupt(
            CTX,
            format!("segment {segment_id} is not catalogued"),
        ));
    };
    let Some(g) = desc.generation_mut(generation) else {
        return Err(corrupt(
            CTX,
            format!("generation {generation} does not exist"),
        ));
    };
    g.state = GenerationState::Quarantined;
    g.superseded_hlc = now_hlc;

    // Reactivar a melhor autoridade que reste: preferir PACKED por ser mais
    // barata de ler, mas aceitar RAW — §127 diz "reactivate/rebuild from RAW".
    let escolha = desc
        .generations
        .iter()
        .filter(|g| g.is_canonical_authority())
        .max_by_key(|g| (u8::from(g.layout == PhysicalLayout::Packed), g.generation))
        .map(|g| g.generation);
    match escolha {
        Some(g) => {
            desc.active_generation = g;
            if let Some(gg) = desc.generation_mut(g) {
                if gg.state == GenerationState::Superseded {
                    gg.state = GenerationState::Active;
                    gg.superseded_hlc = 0;
                }
            }
            Ok(g)
        }
        // §128: falha canónica. Nunca reconstruir silenciosamente.
        None => Err(corrupt(
            CTX,
            format!("segment {segment_id} has no remaining canonical authority after quarantine"),
        )),
    }
}

/// §145 — liga um `.hrki` reconstruído ao segmento.
pub fn attach_sidecar(
    m: &mut DatabaseManifest,
    segment_id: SegmentId,
    artifact: DerivedArtifactRef,
) -> V6Result<()> {
    const CTX: &str = "hrkm attach_sidecar";
    let Some(desc) = m.segment_mut(segment_id) else {
        return Err(corrupt(
            CTX,
            format!("segment {segment_id} is not catalogued"),
        ));
    };
    // §56: um sidecar cuja raiz não corresponde é ignorado, não aceite.
    if artifact.logical_root != desc.logical_root {
        return Err(corrupt(
            CTX,
            "sidecar logical_root does not match the segment",
        ));
    }
    desc.hrki = Some(artifact);
    Ok(())
}

/// §146/§104 — liga uma projecção Parquet e avança o watermark de exportação.
pub fn attach_parquet(
    m: &mut DatabaseManifest,
    segment_id: SegmentId,
    artifact: DerivedArtifactRef,
) -> V6Result<()> {
    const CTX: &str = "hrkm attach_parquet";
    let (root, last_lsn) = {
        let Some(desc) = m.segment(segment_id) else {
            return Err(corrupt(
                CTX,
                format!("segment {segment_id} is not catalogued"),
            ));
        };
        (desc.logical_root, desc.last_lsn)
    };
    if artifact.logical_root != root {
        return Err(corrupt(
            CTX,
            "parquet logical_root does not match the segment",
        ));
    }
    m.segment_mut(segment_id).unwrap().parquet = Some(artifact);
    // O watermark só avança quando TODOS os segmentos até esse ponto estão
    // exportados; avançar por segmento isolado daria um watermark que mente.
    m.exported_through_lsn = contiguous_exported_lsn(m).max(m.exported_through_lsn.min(last_lsn));
    Ok(())
}

/// O maior LSN tal que todos os segmentos até ele têm projecção Parquet válida.
fn contiguous_exported_lsn(m: &DatabaseManifest) -> Lsn {
    let mut watermark = 0;
    for s in &m.segments_v2 {
        let ok = s
            .parquet
            .as_ref()
            .map(|p| p.logical_root == s.logical_root)
            .unwrap_or(false);
        if !ok {
            break;
        }
        watermark = s.last_lsn;
    }
    watermark
}

/// §94 — liga/desliga o legal hold de um segmento.
pub fn set_legal_hold(m: &mut DatabaseManifest, segment_id: SegmentId, hold: bool) -> V6Result<()> {
    let Some(desc) = m.segment_mut(segment_id) else {
        return Err(corrupt(
            "hrkm legal_hold",
            format!("segment {segment_id} is not catalogued"),
        ));
    };
    desc.retention.legal_hold = hold;
    Ok(())
}

/// §184 — actualiza o número de cópias canónicas verificadas conhecidas.
pub fn set_verified_copies(
    m: &mut DatabaseManifest,
    segment_id: SegmentId,
    generation: u32,
    copies: u32,
) -> V6Result<()> {
    const CTX: &str = "hrkm verified_copies";
    let Some(desc) = m.segment_mut(segment_id) else {
        return Err(corrupt(
            CTX,
            format!("segment {segment_id} is not catalogued"),
        ));
    };
    let Some(g) = desc.generation_mut(generation) else {
        return Err(corrupt(
            CTX,
            format!("generation {generation} does not exist"),
        ));
    };
    g.verified_copies = copies;
    Ok(())
}

/// Relatório de arranque (§159): o que o boot soube **sem** abrir um segmento.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootReport {
    pub manifest_generation: u64,
    pub segments: usize,
    pub records: u64,
    pub committed_lsn: Lsn,
    pub canonical_bytes: u64,
    pub derived_bytes: u64,
    pub packing_queue: Vec<SegmentId>,
    pub sidecar_queue: Vec<SegmentId>,
    pub lakehouse_queue: Vec<SegmentId>,
    pub recovered_by_scan: bool,
    /// Segmentos sem qualquer geração autoritativa — falha canónica de §128,
    /// que tem de aparecer alta e não ser silenciosamente ignorada.
    pub segments_without_authority: Vec<SegmentId>,
}

/// Constrói o relatório de arranque a partir do manifesto, sem I/O de segmentos.
pub fn boot_report(loaded: &LoadedManifest) -> BootReport {
    let m = &loaded.manifest;
    let (canonical_bytes, derived_bytes) = m.storage_bytes();
    BootReport {
        manifest_generation: loaded.generation,
        segments: m.segments_v2.len(),
        records: m.total_records(),
        committed_lsn: m.cumulative_watermark,
        canonical_bytes,
        derived_bytes,
        packing_queue: m.packing_queue(),
        sidecar_queue: m.sidecar_queue(),
        lakehouse_queue: m.lakehouse_queue(),
        recovered_by_scan: loaded.recovered_by_scan,
        segments_without_authority: m
            .segments_v2
            .iter()
            .filter(|s| s.canonical_authorities().next().is_none())
            .map(|s| s.segment_id)
            .collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use heraclitus_core::runtime::CompressionCodec;

    fn gen(n: u32, layout: PhysicalLayout, state: GenerationState) -> PhysicalGeneration {
        PhysicalGeneration {
            generation: n,
            layout,
            compression: if layout == PhysicalLayout::Packed {
                CompressionCodec::Zstd
            } else {
                CompressionCodec::Raw
            },
            location: format!("canonical/seg-88/generation-{n}.hrkl"),
            physical_size: 1000 + n as u64,
            physical_digest: [n as u8; 32],
            state,
            created_hlc: 100 << 16,
            verified_hlc: 100 << 16,
            superseded_hlc: 0,
            verified_copies: 1,
        }
    }

    fn seg(id: SegmentId, first: Lsn, count: u64) -> SegmentDescriptorV2 {
        SegmentDescriptorV2 {
            segment_id: id,
            first_lsn: first,
            last_lsn: first + count - 1,
            record_count: count,
            canonical_codec: 1,
            logical_root: [id as u8; 32],
            min_hlc: 1_000 + first,
            max_hlc: 1_000 + first + count,
            active_generation: 0,
            generations: vec![gen(0, PhysicalLayout::Raw, GenerationState::Active)],
            hrki: None,
            parquet: None,
            retention: RetentionPolicy::default(),
        }
    }

    fn manifesto() -> DatabaseManifest {
        let mut m = DatabaseManifest {
            storage_namespace_id: [0xC0; 16],
            cumulative_watermark: 3_000,
            exported_through_lsn: 1_000,
            statistics_root_hash: [7u8; 32],
            ..Default::default()
        };
        for i in 0..4u64 {
            m.upsert_segment(seg(i, 1 + i * 1_000, 1_000));
        }
        m
    }

    #[test]
    fn roundtrip_do_hrkm() {
        let mut m = manifesto();
        m.manifest_generation = 42;
        m.segments_v2[1]
            .generations
            .push(gen(1, PhysicalLayout::Packed, GenerationState::Active));
        m.segments_v2[1].active_generation = 1;
        m.segments_v2[1].generations[0].state = GenerationState::Superseded;
        m.segments_v2[1].generations[0].superseded_hlc = 200 << 16;
        m.segments_v2[2].hrki = Some(DerivedArtifactRef {
            location: "sidecar/2.hrki".into(),
            size: 4096,
            digest: [1; 32],
            logical_root: m.segments_v2[2].logical_root,
            created_hlc: 300 << 16,
        });
        m.segments_v2[3].retention.legal_hold = true;

        let bytes = encode_manifest(&m).unwrap();
        let back = decode_manifest(&bytes).unwrap();
        assert_eq!(back.segments_v2, m.segments_v2);
        assert_eq!(back.storage_namespace_id, m.storage_namespace_id);
        assert_eq!(back.manifest_generation, 42);
        assert_eq!(back.cumulative_watermark, 3_000);
        assert_eq!(back.exported_through_lsn, 1_000);
        assert_eq!(back.statistics_root_hash, [7u8; 32]);
    }

    #[test]
    fn manifesto_vazio() {
        let m = DatabaseManifest::default();
        let bytes = encode_manifest(&m).unwrap();
        assert_eq!(bytes.len(), HRKM_HEADER_LEN + HRKM_FOOTER_LEN);
        let back = decode_manifest(&bytes).unwrap();
        assert!(back.segments_v2.is_empty());
    }

    #[test]
    fn cada_byte_flipado_e_apanhado() {
        let bytes = encode_manifest(&manifesto()).unwrap();
        // Amostragem determinística: um em cada 7 bytes, mais as fronteiras.
        let mut alvos: Vec<usize> = (0..bytes.len()).step_by(7).collect();
        alvos.extend([
            0,
            4,
            60,
            HRKM_HEADER_LEN,
            bytes.len() - HRKM_FOOTER_LEN,
            bytes.len() - 1,
        ]);
        for i in alvos {
            if (bytes.len() - HRKM_FOOTER_LEN + FOOTER_CRC_OFFSET
                ..bytes.len() - HRKM_FOOTER_LEN + FOOTER_CRC_OFFSET + 4)
                .contains(&i)
            {
                continue; // o próprio campo crc
            }
            let mut c = bytes.clone();
            c[i] ^= 0xff;
            assert!(decode_manifest(&c).is_err(), "flip no byte {i} passou");
        }
    }

    #[test]
    fn ficheiros_truncados_nao_entram_em_panico() {
        let bytes = encode_manifest(&manifesto()).unwrap();
        for n in 0..bytes.len() {
            let _ = decode_manifest(&bytes[..n]);
        }
    }

    #[test]
    fn descritor_incoerente_e_recusado() {
        let mut m = manifesto();
        m.segments_v2[0].record_count = 10_000; // maior que o span de LSN
        let bytes = encode_manifest(&m).unwrap();
        assert!(decode_manifest(&bytes).is_err());

        let mut m = manifesto();
        m.segments_v2[0].active_generation = 9; // não existe
        let bytes = encode_manifest(&m).unwrap();
        assert!(decode_manifest(&bytes).is_err());

        let mut m = manifesto();
        m.segments_v2[0]
            .generations
            .push(gen(0, PhysicalLayout::Packed, GenerationState::Active));
        let bytes = encode_manifest(&m).unwrap();
        assert!(decode_manifest(&bytes).is_err(), "gerações duplicadas");
    }

    #[test]
    fn segmentos_desordenados_sao_recusados() {
        let mut m = manifesto();
        m.segments_v2.swap(0, 3);
        let bytes = encode_manifest(&m).unwrap();
        assert!(decode_manifest(&bytes).is_err());
    }

    #[test]
    fn busca_binaria_e_pruning() {
        let m = manifesto();
        assert_eq!(m.find_segment_for_lsn(1).unwrap().segment_id, 0);
        assert_eq!(m.find_segment_for_lsn(1_500).unwrap().segment_id, 1);
        assert_eq!(m.find_segment_for_lsn(3_999).unwrap().segment_id, 3);
        assert!(m.find_segment_for_lsn(0).is_none());
        assert!(m.find_segment_for_lsn(9_999).is_none());

        // §78 — AS OF LSN corta os segmentos que começam depois do alvo.
        assert_eq!(m.visible_segments_v2(1_500).count(), 2);
        assert_eq!(m.visible_segments_v2(0).count(), 0);
        assert_eq!(m.visible_segments_v2(u64::MAX).count(), 4);

        // §79 — pruning por HLC, conservador.
        let s0 = &m.segments_v2[0];
        assert!(m.segments_for_hlc_range(s0.min_hlc, s0.max_hlc).count() >= 1);
        assert_eq!(m.segments_for_hlc_range(0, 500).count(), 0);
    }

    #[test]
    fn filas_de_background_saem_do_manifesto() {
        let mut m = manifesto();
        // Todos RAW sem PACKED => todos na fila de packing (§144).
        assert_eq!(m.packing_queue(), vec![0, 1, 2, 3]);
        assert!(
            m.sidecar_queue().is_empty(),
            "sem PACKED não há sidecar a construir"
        );

        // Depois de packar o 1, ele sai da fila de packing e entra na de sidecar.
        m.segments_v2[1]
            .generations
            .push(gen(1, PhysicalLayout::Packed, GenerationState::Active));
        m.segments_v2[1].active_generation = 1;
        m.segments_v2[1].generations[0].state = GenerationState::Superseded;
        assert_eq!(m.packing_queue(), vec![0, 2, 3]);
        assert_eq!(m.sidecar_queue(), vec![1]);

        // Um `.hrki` com a raiz certa tira-o da fila; com a raiz errada, volta.
        let root = m.segments_v2[1].logical_root;
        m.segments_v2[1].hrki = Some(DerivedArtifactRef {
            location: "x.hrki".into(),
            size: 1,
            digest: [0; 32],
            logical_root: root,
            created_hlc: 1,
        });
        assert!(m.sidecar_queue().is_empty());
        m.segments_v2[1].hrki.as_mut().unwrap().logical_root = [0xEE; 32];
        assert_eq!(m.sidecar_queue(), vec![1]);

        // §146 — sem Parquet, todos na fila do lakehouse.
        assert_eq!(m.lakehouse_queue().len(), 4);
    }

    // ── Store ──────────────────────────────────────────────────────────────

    fn dir_teste(nome: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("hrkm-{}-{nome}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn commit_e_load() {
        let d = dir_teste("commit");
        let store = ManifestStore::open(&d).unwrap();
        assert!(
            store.load().unwrap().is_none(),
            "directório vazio não inventa manifesto"
        );

        let mut m = manifesto();
        let a = store.commit(&mut m).unwrap();
        assert_eq!(a.generation, 1);
        assert_eq!(m.manifest_generation, 1);

        let b = store.commit(&mut m).unwrap();
        assert_eq!(b.generation, 2);
        assert_ne!(
            a.digest, b.digest,
            "gerações diferentes, digests diferentes"
        );

        let carregado = store.load().unwrap().unwrap();
        assert_eq!(carregado.generation, 2);
        assert!(!carregado.recovered_by_scan);
        assert_eq!(carregado.manifest.segments_v2, m.segments_v2);
        assert_eq!(store.generations().unwrap(), vec![1, 2]);
    }

    #[test]
    fn geracao_de_manifesto_nunca_e_sobrescrita() {
        let d = dir_teste("imutavel");
        let store = ManifestStore::open(&d).unwrap();
        let mut m = manifesto();
        store.commit(&mut m).unwrap();
        // Forçar a colisão: pedir de novo a geração 1 depois de ela existir.
        m.manifest_generation = 1;
        let segunda = store.commit(&mut m).unwrap();
        assert_eq!(
            segunda.generation, 2,
            "o commit escolhe a próxima livre, não a pedida"
        );
    }

    #[test]
    fn crash_antes_de_trocar_current_mantem_a_geracao_anterior() {
        // §75: o manifesto antigo permanece válido durante toda a operação.
        let d = dir_teste("crash-current");
        let store = ManifestStore::open(&d).unwrap();
        let mut m = manifesto();
        store.commit(&mut m).unwrap();
        let bom = store.load().unwrap().unwrap();
        assert_eq!(bom.generation, 1);

        // Simula: manifest-2 escrito e renomeado, mas o processo morreu antes
        // de trocar o CURRENT.
        let mut m2 = m.clone();
        m2.cumulative_watermark = 999_999;
        m2.manifest_generation = 2;
        let bytes = encode_manifest(&m2).unwrap();
        std::fs::write(store.path_for(2), &bytes).unwrap();

        let apos = store.load().unwrap().unwrap();
        assert_eq!(apos.generation, 1, "CURRENT ainda aponta para a geração 1");
        assert_eq!(apos.manifest.cumulative_watermark, 3_000);
    }

    #[test]
    fn current_corrompido_recupera_por_varrimento() {
        let d = dir_teste("crash-scan");
        let store = ManifestStore::open(&d).unwrap();
        let mut m = manifesto();
        store.commit(&mut m).unwrap();
        store.commit(&mut m).unwrap();

        // CURRENT a apontar para um ficheiro que não existe.
        std::fs::write(store.current_path(), "manifest-0000000099.hrkm\n").unwrap();
        let l = store.load().unwrap().unwrap();
        assert_eq!(l.generation, 2);
        assert!(l.recovered_by_scan);

        // CURRENT com o digest errado: também cai para o varrimento em vez de
        // aceitar bytes que não são os que foram committed.
        std::fs::write(
            store.current_path(),
            "manifest-0000000001.hrkm\n0000000000000000000000000000000000000000000000000000000000000000\n",
        )
        .unwrap();
        let l = store.load().unwrap().unwrap();
        assert!(l.recovered_by_scan);
        assert_eq!(l.generation, 2);

        // CURRENT apagado.
        std::fs::remove_file(store.current_path()).unwrap();
        let l = store.load().unwrap().unwrap();
        assert_eq!(l.generation, 2);
        assert!(l.recovered_by_scan);
    }

    #[test]
    fn manifesto_corrompido_cai_para_a_geracao_anterior() {
        let d = dir_teste("corrompido");
        let store = ManifestStore::open(&d).unwrap();
        let mut m = manifesto();
        store.commit(&mut m).unwrap();
        m.cumulative_watermark = 4_000;
        store.commit(&mut m).unwrap();

        // Corromper a geração 2, para a qual o CURRENT aponta.
        let mut bytes = std::fs::read(store.path_for(2)).unwrap();
        bytes[HRKM_HEADER_LEN + 3] ^= 0xff;
        std::fs::write(store.path_for(2), &bytes).unwrap();

        let l = store.load().unwrap().unwrap();
        assert_eq!(l.generation, 1, "cai para a geração anterior, íntegra");
        assert!(l.recovered_by_scan);
        assert_eq!(l.manifest.cumulative_watermark, 3_000);
    }

    #[test]
    fn temporarios_orfaos_e_prune() {
        let d = dir_teste("prune");
        let store = ManifestStore::open(&d).unwrap();
        let mut m = manifesto();
        for _ in 0..5 {
            store.commit(&mut m).unwrap();
        }
        std::fs::write(d.join("manifest-0000000099.hrkm.tmp"), b"lixo").unwrap();
        assert_eq!(store.sweep_orphan_temps().unwrap().len(), 1);

        let removidos = store.prune_old_manifests(2).unwrap();
        assert_eq!(removidos.len(), 3);
        assert_eq!(store.generations().unwrap(), vec![4, 5]);
        // E o CURRENT continua a resolver.
        assert_eq!(store.load().unwrap().unwrap().generation, 5);

        // Mesmo com keep=0 a geração corrente sobrevive.
        store.prune_old_manifests(0).unwrap();
        assert_eq!(store.load().unwrap().unwrap().generation, 5);
    }

    // ── Máquina de estados ─────────────────────────────────────────────────

    fn footer_de(first: Lsn, count: u64, root: [u8; 32]) -> FooterV6 {
        FooterV6 {
            record_count: count,
            min_lsn: first,
            max_lsn: first + count - 1,
            min_hlc: 10,
            max_hlc: 10 + count,
            block_count: 0,
            flags: 0,
            block_directory_offset: 0,
            block_directory_len: 0,
            logical_root: root,
        }
    }

    #[test]
    fn registar_selado_e_depois_packar() {
        let mut m = DatabaseManifest::default();
        let root = [0xAB; 32];
        register_sealed_raw(
            &mut m,
            88,
            &footer_de(1, 500, root),
            1,
            "seg-88.hrkl",
            10_000,
            [1; 32],
            100 << 16,
        )
        .unwrap();
        assert_eq!(m.packing_queue(), vec![88]);
        assert_eq!(m.cumulative_watermark, 500);

        let receipt = PackReceipt {
            segment_id: 88,
            storage_namespace_id: [0; 16],
            source_generation: 0,
            source_physical_digest: [1; 32],
            target_generation: 1,
            target_physical_digest: [2; 32],
            logical_root: root,
            canonical_codec: 1,
            codec: CompressionCodec::Zstd,
            block_size: 262_144,
            first_lsn: 1,
            last_lsn: 500,
            record_count: 500,
            source_physical_size: 10_000,
            target_physical_size: 3_700,
            packer_version: 1,
            created_hlc: 100 << 16,
        };
        record_pack(&mut m, &receipt, "seg-88.g1.hrkl", 200 << 16).unwrap();

        let s = m.segment(88).unwrap();
        assert_eq!(s.active_generation, 1);
        assert_eq!(s.generation(0).unwrap().state, GenerationState::Superseded);
        assert_eq!(s.generation(0).unwrap().superseded_hlc, 200 << 16);
        assert_eq!(s.generation(1).unwrap().state, GenerationState::Active);
        // §73 — uma verdade, várias gerações.
        assert!(s.generations.iter().all(|_| true));
        assert_eq!(s.logical_root, root);
        assert!(m.packing_queue().is_empty());
        assert_eq!(m.sidecar_queue(), vec![88]);
    }

    #[test]
    fn recibo_com_raiz_diferente_nao_e_registado() {
        // §97: se o conjunto de CanonicalRecords difere, o output não substitui
        // o segmento canónico — nem sequer entra no catálogo.
        let mut m = DatabaseManifest::default();
        register_sealed_raw(
            &mut m,
            5,
            &footer_de(1, 10, [1; 32]),
            1,
            "a.hrkl",
            100,
            [9; 32],
            1 << 16,
        )
        .unwrap();
        let mut receipt = PackReceipt {
            segment_id: 5,
            storage_namespace_id: [0; 16],
            source_generation: 0,
            source_physical_digest: [9; 32],
            target_generation: 1,
            target_physical_digest: [8; 32],
            logical_root: [2; 32], // diferente!
            canonical_codec: 1,
            codec: CompressionCodec::Zstd,
            block_size: 1,
            first_lsn: 1,
            last_lsn: 10,
            record_count: 10,
            source_physical_size: 100,
            target_physical_size: 50,
            packer_version: 1,
            created_hlc: 1,
        };
        assert!(record_pack(&mut m, &receipt, "b.hrkl", 2 << 16).is_err());
        assert_eq!(m.segment(5).unwrap().generations.len(), 1);

        receipt.logical_root = [1; 32];
        assert!(record_pack(&mut m, &receipt, "b.hrkl", 2 << 16).is_ok());
        // E a mesma geração não pode ser registada duas vezes.
        assert!(record_pack(&mut m, &receipt, "b.hrkl", 3 << 16).is_err());
    }

    #[test]
    fn quarentena_reactiva_o_raw() {
        // §127: PACKED falha, RAW equivalente existe -> quarentena e reactivação.
        let mut m = DatabaseManifest::default();
        let root = [3; 32];
        register_sealed_raw(
            &mut m,
            7,
            &footer_de(1, 10, root),
            1,
            "a.hrkl",
            100,
            [9; 32],
            1 << 16,
        )
        .unwrap();
        let receipt = PackReceipt {
            segment_id: 7,
            storage_namespace_id: [0; 16],
            source_generation: 0,
            source_physical_digest: [9; 32],
            target_generation: 1,
            target_physical_digest: [8; 32],
            logical_root: root,
            canonical_codec: 1,
            codec: CompressionCodec::Zstd,
            block_size: 1,
            first_lsn: 1,
            last_lsn: 10,
            record_count: 10,
            source_physical_size: 100,
            target_physical_size: 50,
            packer_version: 1,
            created_hlc: 1,
        };
        record_pack(&mut m, &receipt, "b.hrkl", 2 << 16).unwrap();

        let reactivada = quarantine_generation(&mut m, 7, 1, 3 << 16).unwrap();
        assert_eq!(reactivada, 0);
        let s = m.segment(7).unwrap();
        assert_eq!(s.active_generation, 0);
        assert_eq!(s.generation(0).unwrap().state, GenerationState::Active);
        assert_eq!(s.generation(1).unwrap().state, GenerationState::Quarantined);

        // §128: sem outra cópia, é falha canónica explícita.
        assert!(quarantine_generation(&mut m, 7, 0, 4 << 16).is_err());
    }

    #[test]
    fn sidecar_e_parquet_exigem_a_raiz_certa() {
        let mut m = DatabaseManifest::default();
        let root = [4; 32];
        register_sealed_raw(
            &mut m,
            1,
            &footer_de(1, 10, root),
            1,
            "a.hrkl",
            100,
            [9; 32],
            1 << 16,
        )
        .unwrap();
        let mau = DerivedArtifactRef {
            location: "x".into(),
            size: 1,
            digest: [0; 32],
            logical_root: [0xEE; 32],
            created_hlc: 1,
        };
        assert!(attach_sidecar(&mut m, 1, mau.clone()).is_err());
        assert!(attach_parquet(&mut m, 1, mau).is_err());

        let bom = DerivedArtifactRef {
            location: "x".into(),
            size: 1,
            digest: [0; 32],
            logical_root: root,
            created_hlc: 1,
        };
        attach_sidecar(&mut m, 1, bom.clone()).unwrap();
        attach_parquet(&mut m, 1, bom).unwrap();
        assert_eq!(m.exported_through_lsn, 10);
        assert!(m.lakehouse_queue().is_empty());
    }

    #[test]
    fn watermark_de_exportacao_so_avanca_de_forma_contigua() {
        // Exportar o segmento 2 sem o 1 não pode fazer o watermark saltar por
        // cima de um buraco — um consumidor a ler "exportado até X" teria uma
        // lacuna silenciosa.
        let mut m = DatabaseManifest::default();
        for i in 0..3u64 {
            register_sealed_raw(
                &mut m,
                i,
                &footer_de(1 + i * 100, 100, [i as u8; 32]),
                1,
                "a.hrkl",
                100,
                [9; 32],
                1 << 16,
            )
            .unwrap();
        }
        let art = |root: [u8; 32]| DerivedArtifactRef {
            location: "p".into(),
            size: 1,
            digest: [0; 32],
            logical_root: root,
            created_hlc: 1,
        };
        attach_parquet(&mut m, 2, art([2; 32])).unwrap();
        assert_eq!(
            m.exported_through_lsn, 0,
            "buraco no início não avança o watermark"
        );
        attach_parquet(&mut m, 0, art([0; 32])).unwrap();
        assert_eq!(m.exported_through_lsn, 100);
        attach_parquet(&mut m, 1, art([1; 32])).unwrap();
        assert_eq!(m.exported_through_lsn, 300, "agora a cadeia está completa");
    }

    #[test]
    fn boot_nao_precisa_de_abrir_segmentos() {
        // §159 — tudo o que o arranque precisa sai do manifesto.
        let d = dir_teste("boot");
        let store = ManifestStore::open(&d).unwrap();
        let mut m = manifesto();
        store.commit(&mut m).unwrap();

        let loaded = store.load().unwrap().unwrap();
        let r = boot_report(&loaded);
        assert_eq!(r.segments, 4);
        assert_eq!(r.records, 4_000);
        assert_eq!(r.committed_lsn, 3_000);
        assert_eq!(r.packing_queue, vec![0, 1, 2, 3]);
        assert!(r.segments_without_authority.is_empty());
        assert!(r.canonical_bytes > 0);
        assert_eq!(r.derived_bytes, 0);
        assert!(!r.recovered_by_scan);
    }
}
