//! SPEC-0050 §124, §160–§161 — níveis de integridade e o scrubber.
//!
//! ```text
//! FAST      header/footer/catálogo
//! PHYSICAL  + CRC de todos os blocos
//! LOGICAL   + decode canónico + raiz de Merkle lógica
//! FORENSIC  + recibos, carimbos, réplicas/cópias em objecto
//! ```
//!
//! §159: verificação integral **não** faz parte de todo o boot. Arrancar com um
//! manifesto válido não pode exigir varrer cada segmento selado; a verificação
//! integral é background, explícita ou por amostragem.

use std::path::Path;

use heraclitus_core::Lsn;

use super::error::{corrupt, V6Result};
use super::footer::FooterV6;
use super::header::PhysicalLayout;
use super::merkle::{build_inclusion_proof, InclusionProof, MerkleAccumulatorV1};
use super::packed::{open_packed, ScanCounters};
use super::packer::CanonicalHasher;
use super::raw::{scan_raw_segment, RawScan};
use super::receipts::{attestation_for, AttestationEnvelopeV1};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum IntegrityLevel {
    Fast,
    Physical,
    Logical,
    Forensic,
}

/// O que uma verificação apurou.
#[derive(Debug, Clone)]
pub struct VerifyReport {
    pub level: IntegrityLevel,
    pub layout: PhysicalLayout,
    pub segment_id: u64,
    pub record_count: u64,
    pub min_lsn: Lsn,
    pub max_lsn: Lsn,
    pub block_count: u32,
    pub declared_root: [u8; 32],
    /// `Some` apenas em `LOGICAL`/`FORENSIC`.
    pub recomputed_root: Option<[u8; 32]>,
    pub physical_ok: bool,
    pub logical_ok: Option<bool>,
    pub counters: ScanCounters,
    pub notes: Vec<String>,
}

impl VerifyReport {
    pub fn is_ok(&self) -> bool {
        self.physical_ok && self.logical_ok.unwrap_or(true)
    }
}

/// Verifica um segmento `.hrkl` v6, RAW ou PACKED.
///
/// `hasher` só é necessário a partir de `LOGICAL`; passar `None` num nível que
/// o exige é erro de programação e devolve erro, não um "verificado" optimista.
pub fn verify_segment(
    path: &Path,
    level: IntegrityLevel,
    max_block_bytes: usize,
    hasher: Option<CanonicalHasher<'_>>,
) -> V6Result<VerifyReport> {
    const CTX: &str = "hrkl v6 verify";
    let head = read_head(path)?;
    match head {
        PhysicalLayout::Raw => verify_raw(path, level, hasher),
        PhysicalLayout::Packed => {
            if level >= IntegrityLevel::Logical && hasher.is_none() {
                return Err(corrupt(
                    CTX,
                    "LOGICAL verification requires a canonical hasher",
                ));
            }
            verify_packed(path, level, max_block_bytes, hasher)
        }
    }
}

fn read_head(path: &Path) -> V6Result<PhysicalLayout> {
    use std::io::Read;
    let mut f = std::fs::File::open(path)?;
    let mut buf = [0u8; super::header::FILE_HEADER_LEN];
    f.read_exact(&mut buf)?;
    Ok(super::header::FileHeaderV6::decode(&buf)?.physical_layout)
}

fn verify_raw(
    path: &Path,
    level: IntegrityLevel,
    hasher: Option<CanonicalHasher<'_>>,
) -> V6Result<VerifyReport> {
    const CTX: &str = "hrkl v6 verify raw";
    // O scan já valida o CRC-32C de cada registo: no RAW, físico e estrutural
    // são o mesmo percurso.
    let RawScan {
        header,
        records,
        footer,
        torn_at,
    } = scan_raw_segment(path)?;
    let mut notes = Vec::new();
    let footer = match footer {
        Some(f) => f,
        None => {
            notes.push("segment is not sealed (active tail)".into());
            FooterV6 {
                record_count: records.len() as u64,
                min_lsn: records.first().map(|r| r.lsn).unwrap_or(0),
                max_lsn: records.last().map(|r| r.lsn).unwrap_or(0),
                min_hlc: records.iter().map(|r| r.hlc).min().unwrap_or(0),
                max_hlc: records.iter().map(|r| r.hlc).max().unwrap_or(0),
                block_count: 0,
                flags: 0,
                block_directory_offset: 0,
                block_directory_len: 0,
                logical_root: [0u8; 32],
            }
        }
    };
    if let Some(at) = torn_at {
        notes.push(format!("torn tail at offset {at}"));
    }

    let mut report = VerifyReport {
        level,
        layout: PhysicalLayout::Raw,
        segment_id: header.segment_id,
        record_count: records.len() as u64,
        min_lsn: footer.min_lsn,
        max_lsn: footer.max_lsn,
        block_count: 0,
        declared_root: footer.logical_root,
        recomputed_root: None,
        physical_ok: true,
        logical_ok: None,
        counters: ScanCounters::default(),
        notes,
    };

    if level >= IntegrityLevel::Logical {
        let hasher = hasher
            .ok_or_else(|| corrupt(CTX, "LOGICAL verification requires a canonical hasher"))?;
        let mut acc = MerkleAccumulatorV1::new();
        for r in &records {
            acc.push_record_hash(&hasher(r.lsn, r.hlc, &r.payload)?);
        }
        let root = acc.finalize();
        report.recomputed_root = Some(root);
        report.logical_ok = Some(root == footer.logical_root);
    }
    Ok(report)
}

fn verify_packed(
    path: &Path,
    level: IntegrityLevel,
    max_block_bytes: usize,
    hasher: Option<CanonicalHasher<'_>>,
) -> V6Result<VerifyReport> {
    // §124: um PACKED válido exige header, footer, directório e ranges
    // coerentes — tudo verificado já no `open`.
    let reader = open_packed(path, max_block_bytes)?;
    let mut counters = ScanCounters::default();
    let mut notes = Vec::new();
    let mut logical_ok = None;
    let mut recomputed_root = None;
    let mut physical_ok = true;

    if level >= IntegrityLevel::Physical {
        // Ler cada bloco valida o CRC de §48 (header + payload comprimido).
        for i in 0..reader.block_count() {
            match reader.read_block(i, &mut counters) {
                Ok(_) => {}
                Err(e) => {
                    physical_ok = false;
                    notes.push(format!("block {i}: {e}"));
                }
            }
        }
    }

    if level >= IntegrityLevel::Logical && physical_ok {
        let hasher = hasher.expect("checked by the caller");
        let mut acc = MerkleAccumulatorV1::new();
        let mut n = 0u64;
        reader.for_each_record(&mut counters, |r| {
            acc.push_record_hash(&hasher(r.lsn, r.hlc, r.payload)?);
            n += 1;
            Ok(())
        })?;
        let root = acc.finalize();
        recomputed_root = Some(root);
        logical_ok = Some(root == reader.footer.logical_root && n == reader.footer.record_count);
    }

    if level >= IntegrityLevel::Forensic {
        // O envelope existe sempre; carimbos e réplicas são responsabilidade do
        // módulo de compliance (§98) e do de replicação (§184).
        notes.push(format!(
            "attestation imprint {}",
            hex32(
                &attestation_for(
                    reader.header.storage_namespace_id,
                    reader.header.segment_id,
                    &reader.footer
                )
                .imprint()
            )
        ));
    }

    Ok(VerifyReport {
        level,
        layout: PhysicalLayout::Packed,
        segment_id: reader.header.segment_id,
        record_count: reader.footer.record_count,
        min_lsn: reader.footer.min_lsn,
        max_lsn: reader.footer.max_lsn,
        block_count: reader.footer.block_count,
        declared_root: reader.footer.logical_root,
        recomputed_root,
        physical_ok,
        logical_ok,
        counters,
        notes,
    })
}

/// Prova pericial de um LSN (SPEC-0050 §122).
pub struct LsnProof {
    pub lsn: Lsn,
    pub canonical_record_hash: [u8; 32],
    pub proof: InclusionProof,
    pub logical_root: [u8; 32],
    pub envelope: AttestationEnvelopeV1,
}

/// `heraclitus prove --lsn X`.
///
/// Devolve o hash canónico do registo, a prova de inclusão, a raiz lógica do
/// segmento e o envelope de atestação — que é o que uma perícia precisa para
/// ligar o registo ao carimbo do tempo.
pub fn prove_lsn(
    path: &Path,
    lsn: Lsn,
    max_block_bytes: usize,
    hasher: CanonicalHasher<'_>,
) -> V6Result<Option<LsnProof>> {
    const CTX: &str = "hrkl v6 prove";
    let layout = read_head(path)?;
    let (hashes, index, footer, segment_id, namespace) = match layout {
        PhysicalLayout::Raw => {
            let scan = scan_raw_segment(path)?;
            let footer = scan
                .footer
                .ok_or_else(|| corrupt(CTX, "cannot prove against an unsealed segment"))?;
            let mut hashes = Vec::with_capacity(scan.records.len());
            let mut index = None;
            for (i, r) in scan.records.iter().enumerate() {
                if r.lsn == lsn {
                    index = Some(i);
                }
                hashes.push(hasher(r.lsn, r.hlc, &r.payload)?);
            }
            (
                hashes,
                index,
                footer,
                scan.header.segment_id,
                scan.header.storage_namespace_id,
            )
        }
        PhysicalLayout::Packed => {
            let reader = open_packed(path, max_block_bytes)?;
            let mut counters = ScanCounters::default();
            let mut hashes = Vec::with_capacity(reader.footer.record_count as usize);
            let mut index = None;
            reader.for_each_record(&mut counters, |r| {
                if r.lsn == lsn {
                    index = Some(hashes.len());
                }
                hashes.push(hasher(r.lsn, r.hlc, r.payload)?);
                Ok(())
            })?;
            (
                hashes,
                index,
                reader.footer,
                reader.header.segment_id,
                reader.header.storage_namespace_id,
            )
        }
    };
    let Some(index) = index else { return Ok(None) };
    let proof = build_inclusion_proof(&hashes, index)
        .ok_or_else(|| corrupt(CTX, "inclusion proof index out of range"))?;
    Ok(Some(LsnProof {
        lsn,
        canonical_record_hash: hashes[index],
        proof,
        logical_root: footer.logical_root,
        envelope: attestation_for(namespace, segment_id, &footer),
    }))
}

impl LsnProof {
    /// Fecha a prova contra a raiz declarada.
    pub fn verify(&self) -> bool {
        super::merkle::verify_inclusion_proof(
            &self.canonical_record_hash,
            &self.proof,
            &self.logical_root,
        ) && self.envelope.logical_root == self.logical_root
    }
}

/// Hex de 32 bytes, para relatórios de operação.
pub fn hex32(b: &[u8; 32]) -> String {
    let mut s = String::with_capacity(64);
    for x in b {
        s.push_str(&format!("{x:02x}"));
    }
    s
}

/// Resumo humano de um segmento — o `heraclitus inspect` de §119.
pub fn inspect(path: &Path, max_block_bytes: usize) -> V6Result<String> {
    let layout = read_head(path)?;
    let physical_size = std::fs::metadata(path)?.len();
    let mut out = String::new();
    out.push_str("HRKL Segment\n\n");
    match layout {
        PhysicalLayout::Raw => {
            let scan = scan_raw_segment(path)?;
            let logical: u64 = scan.records.iter().map(|r| r.payload.len() as u64).sum();
            out.push_str(&format!(
                "Format               v6\nPhysical Layout      RAW\nCanonical Codec      v{}\n\n",
                scan.header.canonical_codec
            ));
            out.push_str(&format!(
                "Segment ID           {}\n",
                scan.header.segment_id
            ));
            out.push_str(&format!("Records              {}\n", scan.records.len()));
            if let Some(f) = &scan.footer {
                out.push_str(&format!(
                    "LSN                  {}..{}\n",
                    f.min_lsn, f.max_lsn
                ));
                out.push_str(&format!(
                    "Logical Root         {}\n",
                    hex32(&f.logical_root)
                ));
                out.push_str("Sealed               yes\n");
            } else {
                out.push_str("Sealed               no (active)\n");
            }
            out.push_str(&format!(
                "Physical             {physical_size} B\nLogical/Raw          {logical} B\n"
            ));
            if let Some(at) = scan.torn_at {
                out.push_str(&format!("Torn tail at         {at}\n"));
            }
        }
        PhysicalLayout::Packed => {
            let r = open_packed(path, max_block_bytes)?;
            let stored = r.directory.total_stored_bytes();
            let uncompressed = r.directory.total_uncompressed_bytes();
            out.push_str(&format!("Format               v6\nPhysical Layout      PACKED\nCanonical Codec      v{}\n\n", r.header.canonical_codec));
            out.push_str(&format!("Segment ID           {}\n", r.header.segment_id));
            out.push_str(&format!("Records              {}\n", r.footer.record_count));
            out.push_str(&format!(
                "LSN                  {}..{}\n",
                r.footer.min_lsn, r.footer.max_lsn
            ));
            out.push_str(&format!(
                "HLC                  {}..{}\n\n",
                r.footer.min_hlc, r.footer.max_hlc
            ));
            out.push_str(&format!("Blocks               {}\n", r.footer.block_count));
            out.push_str(&format!(
                "Compressed           {stored} B\nLogical/Raw          {uncompressed} B\n"
            ));
            let ratio = if uncompressed == 0 {
                1.0
            } else {
                stored as f64 / uncompressed as f64
            };
            out.push_str(&format!("Ratio                {ratio:.3}\n\n"));
            out.push_str(&format!(
                "Logical Root         {}\n",
                hex32(&r.footer.logical_root)
            ));
            out.push_str(&format!(
                "Contiguous LSN       {}\n",
                r.footer.is_contiguous_lsn()
            ));
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::v6::packed::PackOptions;
    use crate::v6::packer::pack_segment;
    use crate::v6::raw::{RawSegmentWriter, SegmentInit};

    fn hasher(lsn: Lsn, hlc: u64, payload: &[u8]) -> V6Result<[u8; 32]> {
        let mut h = blake3::Hasher::new();
        h.update(b"TEST:OPAQUE");
        h.update(&lsn.to_le_bytes());
        h.update(&hlc.to_le_bytes());
        h.update(payload);
        Ok(*h.finalize().as_bytes())
    }

    fn dir_teste(nome: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("hrkl6-verify-{}-{nome}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn escreve_raw(path: &Path, n: u64) -> FooterV6 {
        let init = SegmentInit {
            segment_id: 5,
            created_hlc: 1,
            first_lsn: 500,
            writer_epoch: 1,
            storage_namespace_id: [0x9A; 16],
        };
        let mut w = RawSegmentWriter::create(path, init).unwrap();
        for i in 0..n {
            let p = format!("registo {i} com conteudo").into_bytes();
            w.append(500 + i, 10 + i, &p, &hasher(500 + i, 10 + i, &p).unwrap())
                .unwrap();
        }
        w.seal().unwrap()
    }

    #[test]
    fn verificacao_logica_fecha_em_raw_e_packed() {
        let d = dir_teste("niveis");
        let raw = d.join("s.hrkl");
        let packed = d.join("s.g1.hrkl");
        escreve_raw(&raw, 1_500);
        pack_segment(&raw, &packed, PackOptions::default(), 0, 1, &hasher).unwrap();

        for p in [&raw, &packed] {
            let r = verify_segment(p, IntegrityLevel::Logical, 1 << 26, Some(&hasher)).unwrap();
            assert!(r.is_ok(), "{:?} falhou: {:?}", p, r.notes);
            assert_eq!(r.recomputed_root, Some(r.declared_root));
            assert_eq!(r.record_count, 1_500);
        }
    }

    #[test]
    fn verificacao_logica_sem_hasher_e_erro_e_nao_um_ok_optimista() {
        let d = dir_teste("sem-hasher");
        let raw = d.join("s.hrkl");
        let packed = d.join("s.g1.hrkl");
        escreve_raw(&raw, 50);
        pack_segment(&raw, &packed, PackOptions::default(), 0, 1, &hasher).unwrap();
        assert!(verify_segment(&packed, IntegrityLevel::Logical, 1 << 26, None).is_err());
        // FAST/PHYSICAL não precisam de hasher.
        assert!(
            verify_segment(&packed, IntegrityLevel::Physical, 1 << 26, None)
                .unwrap()
                .is_ok()
        );
    }

    #[test]
    fn corrupcao_num_bloco_e_reportada_e_nao_escondida() {
        let d = dir_teste("corrupto");
        let raw = d.join("s.hrkl");
        let packed = d.join("s.g1.hrkl");
        escreve_raw(&raw, 400);
        pack_segment(&raw, &packed, PackOptions::default(), 0, 1, &hasher).unwrap();

        let mut bytes = std::fs::read(&packed).unwrap();
        let at = super::super::header::FILE_HEADER_LEN + super::super::block::BLOCK_HEADER_LEN + 3;
        bytes[at] ^= 0xff;
        std::fs::write(&packed, &bytes).unwrap();

        let r = verify_segment(&packed, IntegrityLevel::Physical, 1 << 26, None).unwrap();
        assert!(!r.physical_ok);
        assert!(!r.notes.is_empty());
    }

    #[test]
    fn prove_lsn_fecha_contra_a_raiz_em_ambos_os_layouts() {
        let d = dir_teste("prove");
        let raw = d.join("s.hrkl");
        let packed = d.join("s.g1.hrkl");
        let footer = escreve_raw(&raw, 777);
        pack_segment(&raw, &packed, PackOptions::default(), 0, 1, &hasher).unwrap();

        for p in [&raw, &packed] {
            for lsn in [500u64, 900, 1276] {
                let proof = prove_lsn(p, lsn, 1 << 26, &hasher).unwrap().unwrap();
                assert!(proof.verify(), "prova do lsn {lsn} não fecha em {p:?}");
                assert_eq!(proof.logical_root, footer.logical_root);
            }
            assert!(prove_lsn(p, 1, 1 << 26, &hasher).unwrap().is_none());
        }
    }

    #[test]
    fn inspect_produz_relatorio_para_os_dois_layouts() {
        let d = dir_teste("inspect");
        let raw = d.join("s.hrkl");
        let packed = d.join("s.g1.hrkl");
        escreve_raw(&raw, 300);
        pack_segment(&raw, &packed, PackOptions::default(), 0, 1, &hasher).unwrap();

        let a = inspect(&raw, 1 << 26).unwrap();
        assert!(a.contains("RAW") && a.contains("Logical Root"));
        let b = inspect(&packed, 1 << 26).unwrap();
        assert!(b.contains("PACKED") && b.contains("Blocks") && b.contains("Ratio"));
    }
}
