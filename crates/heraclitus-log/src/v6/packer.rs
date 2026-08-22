//! SPEC-0050 §21–§22, §88–§89 — a transacção de packing `RAW -> PACKED`.
//!
//! # A ordem é a garantia
//!
//! §88 fixa dezasseis passos. O que importa neles é **onde** está o commit do
//! manifesto: até esse ponto, o RAW continua a ser a autoridade, e um crash em
//! qualquer passo anterior deixa apenas ficheiros `.tmp` órfãos, removíveis no
//! recovery seguinte (§89). Nunca há um instante em que a única cópia
//! verificável de um `CanonicalRecord` esteja num ficheiro por sincronizar.
//!
//! ```text
//!  1. pin RAW source          9.  verify packed logical_root
//!  2. create packed temp     10.  publish immutable final object
//!  3. stream source records  11.  fsync parent / confirm object
//!  4. canonical verification 12.  append PackReceipt
//!  5. write blocks           13.  commit new HRKM
//!  6. write block directory  14.  mark RAW generation SUPERSEDED
//!  7. write footer           15.  release pin
//!  8. fsync packed temp      16.  GC only later
//! ```
//!
//! Os passos 1–12 vivem em [`pack_segment`], que devolve o recibo sem tocar em
//! nada mais. Os passos 13–14 (commit do HRKM, marcar a origem `SUPERSEDED`)
//! estão em [`pack_and_commit`], que fecha a transacção. O passo 16 — *GC only
//! later* — é deliberadamente de outra pessoa: quem decide o que pode
//! desaparecer é [`super::gc::plan_gc`], depois do grace period de §93.
//!
//! # O packer não reinterpreta payloads
//!
//! §42: a primeira entrega mantém o payload existente intacto e só aplica block
//! framing, remoção de LSN redundante, delta de HLC, compressão e directório.
//! Quem sabe descodificar um payload para `Episode` é o crate do log; o packer
//! recebe essa capacidade como um closure ([`CanonicalHasher`]) e mais nada.
//! §47: o packer trabalha sobre a representação **persistida**, nunca
//! decifrando campos nem extraindo plaintext para sidecars.

use std::path::{Path, PathBuf};

use heraclitus_core::runtime::DatabaseManifest;
use heraclitus_core::Lsn;

use super::canonical::CANONICAL_CODEC_V1;
use super::compress::CompressionCodec;
use super::error::{corrupt, V6Result};
use super::footer::FooterV6;
use super::header::PhysicalLayout;
use super::manifest::{record_pack, ManifestStore};
use super::packed::{open_packed, PackOptions, PackStats, PackedSegmentWriter, ScanCounters};
use super::raw::{scan_raw_segment, SegmentInit};
use super::receipts::{physical_digest_of_file, PackReceipt, PACKER_VERSION};

/// Calcula o `canonical_record_hash` de um registo a partir do que está
/// persistido.
///
/// É a única coisa que o packer precisa de saber sobre semântica — e recebe-a
/// de fora, para que este módulo não dependa de `bincode`, do `StoragePayload`
/// nem de qualquer geração de layout de payload.
pub type CanonicalHasher<'a> = &'a dyn Fn(Lsn, u64, &[u8]) -> V6Result<[u8; 32]>;

/// Resultado de um packing bem-sucedido.
pub struct PackOutcome {
    pub receipt: PackReceipt,
    pub footer: FooterV6,
    pub stats: PackStats,
    pub target_path: PathBuf,
}

/// Executa `RAW -> PACKED` segundo a transacção de §88.
///
/// `target` **não pode existir**: uma geração publicada nunca é sobrescrita
/// (§83). O trabalho acontece num `.tmp` ao lado, que só é renomeado depois de
/// a `logical_root` do PACKED ter sido reconferida contra a do RAW.
pub fn pack_segment(
    source: &Path,
    target: &Path,
    opts: PackOptions,
    source_generation: u32,
    target_generation: u32,
    hasher: CanonicalHasher<'_>,
) -> V6Result<PackOutcome> {
    const CTX: &str = "hrkl v6 packer";

    // 1. pin RAW source — aqui, ler o segmento inteiro; num motor a correr, o
    //    pin é a referência que impede o GC de mexer nele.
    let scan = scan_raw_segment(source)?;
    if scan.header.physical_layout != PhysicalLayout::Raw {
        return Err(corrupt(CTX, "source segment is not RAW"));
    }
    let Some(source_footer) = scan.footer else {
        // §22: só se packa depois do seal. Um segmento activo ainda cresce.
        return Err(corrupt(CTX, "refusing to pack an unsealed segment"));
    };
    if scan.torn_at.is_some() {
        return Err(corrupt(
            CTX,
            "sealed segment has trailing bytes after the footer",
        ));
    }
    if scan.header.canonical_codec != CANONICAL_CODEC_V1 {
        return Err(corrupt(
            CTX,
            format!(
                "unsupported canonical codec {}",
                scan.header.canonical_codec
            ),
        ));
    }
    if scan.records.len() as u64 != source_footer.record_count {
        return Err(corrupt(
            CTX,
            format!(
                "source has {} records, footer declares {}",
                scan.records.len(),
                source_footer.record_count
            ),
        ));
    }
    if target.exists() {
        return Err(corrupt(
            CTX,
            "target generation already exists; generations are immutable",
        ));
    }

    // 2. create packed temp
    let tmp = temp_path(target);
    let _ = std::fs::remove_file(&tmp);
    let init = SegmentInit {
        segment_id: scan.header.segment_id,
        created_hlc: scan.header.created_hlc,
        first_lsn: scan.header.first_lsn,
        writer_epoch: scan.header.writer_epoch,
        storage_namespace_id: scan.header.storage_namespace_id,
    };
    let mut writer = PackedSegmentWriter::create(&tmp, init, opts)?;

    // 3./4./5./6. stream + canonical verification + blocks + directory
    for r in &scan.records {
        let h = hasher(r.lsn, r.hlc, &r.payload)?;
        writer.push(r.lsn, r.hlc, r.payload.clone(), &h)?;
    }

    // 7./8. footer + fsync do temporário
    let (target_footer, stats) = writer.finish()?;

    // 9. verify packed logical_root — o passo que autoriza tudo o resto.
    //    §134/invariante 3: para o mesmo conjunto de CanonicalRecords v6,
    //    RAW logical_root == PACKED logical_root, obrigatoriamente.
    if target_footer.logical_root != source_footer.logical_root {
        let _ = std::fs::remove_file(&tmp);
        return Err(corrupt(
            CTX,
            "PACKED logical_root differs from RAW; refusing to publish a non-equivalent generation",
        ));
    }
    if target_footer.record_count != source_footer.record_count
        || target_footer.min_lsn != source_footer.min_lsn
        || target_footer.max_lsn != source_footer.max_lsn
    {
        let _ = std::fs::remove_file(&tmp);
        return Err(corrupt(CTX, "PACKED footer disagrees with RAW footer"));
    }

    // Releitura independente: o que ficou no disco tem de ser navegável e
    // reproduzir os mesmos registos. Verificar apenas o que o writer tinha em
    // memória provaria só que o writer é consistente consigo próprio.
    {
        let reader = open_packed(&tmp, opts.max_block_bytes)?;
        let mut counters = ScanCounters::default();
        let mut acc = super::merkle::MerkleAccumulatorV1::new();
        let mut n = 0u64;
        reader.for_each_record(&mut counters, |r| {
            acc.push_record_hash(&hasher(r.lsn, r.hlc, r.payload)?);
            n += 1;
            Ok(())
        })?;
        if n != source_footer.record_count || acc.finalize() != source_footer.logical_root {
            let _ = std::fs::remove_file(&tmp);
            return Err(corrupt(
                CTX,
                "re-read of the packed generation does not reproduce the canonical root",
            ));
        }
    }

    // 10./11. publicar a geração imutável
    std::fs::rename(&tmp, target)?;
    sync_parent_dir(target)?;

    // 12. PackReceipt
    let receipt = PackReceipt {
        segment_id: scan.header.segment_id,
        storage_namespace_id: scan.header.storage_namespace_id,
        source_generation,
        source_physical_digest: physical_digest_of_file(source)?,
        target_generation,
        target_physical_digest: physical_digest_of_file(target)?,
        logical_root: target_footer.logical_root,
        canonical_codec: CANONICAL_CODEC_V1,
        // O codec efectivo é decidido por bloco (§34); o recibo regista o do
        // perfil pedido, que é o que descreve a decisão, e o RAW fallback fica
        // visível no rácio de compressão.
        codec: if stats.block_count == 0 {
            CompressionCodec::Raw
        } else {
            opts.profile.codec()
        },
        block_size: opts.block_target_bytes as u32,
        first_lsn: target_footer.min_lsn,
        last_lsn: target_footer.max_lsn,
        record_count: target_footer.record_count,
        source_physical_size: std::fs::metadata(source)?.len(),
        target_physical_size: std::fs::metadata(target)?.len(),
        packer_version: PACKER_VERSION,
        created_hlc: scan.header.created_hlc,
    };

    Ok(PackOutcome {
        receipt,
        footer: target_footer,
        stats,
        target_path: target.to_path_buf(),
    })
}

/// SPEC-0050 §88 passos 1–14 — a transacção completa, incluindo o commit do
/// manifesto.
///
/// [`pack_segment`] faz os passos 1–12 e devolve o recibo; é o que se quer
/// quando o chamador gere o manifesto à sua maneira. Esta função fecha o ciclo:
/// regista a nova geração, marca a origem `SUPERSEDED` e faz commit de uma nova
/// geração de manifesto — **e só então** o packing conta como tendo acontecido.
///
/// A ordem é a de §88 e não é negociável: enquanto o manifesto não for
/// committed, o RAW continua a ser a autoridade. Se o processo morrer entre o
/// `rename` e o commit, o resultado é um ficheiro PACKED órfão — desperdício,
/// não perda —, e o packing repete-se na próxima passagem da fila de §144.
///
/// O passo 16 ("GC only later") fica deliberadamente de fora: quem decide o que
/// pode desaparecer é [`super::gc::plan_gc`], depois do grace period.
#[allow(clippy::too_many_arguments)]
pub fn pack_and_commit(
    store: &ManifestStore,
    manifest: &mut DatabaseManifest,
    source: &Path,
    target: &Path,
    opts: PackOptions,
    source_generation: u32,
    target_generation: u32,
    now_hlc: u64,
    hasher: CanonicalHasher<'_>,
) -> V6Result<PackOutcome> {
    let outcome = pack_segment(
        source,
        target,
        opts,
        source_generation,
        target_generation,
        hasher,
    )?;
    let location = target.to_string_lossy().to_string();
    // 13. commit do novo HRKM. Se `record_pack` recusar (raiz divergente,
    //     geração repetida), o ficheiro publicado fica órfão e o manifesto
    //     antigo continua correcto — que é o resultado seguro.
    record_pack(manifest, &outcome.receipt, &location, now_hlc)?;
    store.commit(manifest)?;
    Ok(outcome)
}

fn temp_path(target: &Path) -> PathBuf {
    let mut s = target.as_os_str().to_os_string();
    s.push(".tmp");
    PathBuf::from(s)
}

fn sync_parent_dir(path: &Path) -> V6Result<()> {
    // No Windows não é possível abrir um directório como ficheiro; o `rename`
    // do NTFS já é atómico e o `sync_all` do próprio ficheiro cobre os dados.
    #[cfg(unix)]
    if let Some(parent) = path.parent() {
        std::fs::File::open(parent)?.sync_all()?;
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

/// §89 — remove os `.tmp` órfãos de um packing interrompido.
///
/// Correr isto é sempre seguro: um `.tmp` nunca é referenciado pelo manifesto,
/// porque o manifesto só é actualizado depois do `rename`.
pub fn sweep_orphan_temps(dir: &Path) -> V6Result<Vec<PathBuf>> {
    let mut removed = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        let path = entry?.path();
        if path.extension().and_then(|e| e.to_str()) == Some("tmp") {
            std::fs::remove_file(&path)?;
            removed.push(path);
        }
    }
    Ok(removed)
}

/// §188/§189 — repack de uma geração PACKED para outra (outro compressor, outro
/// block size), preservando a `logical_root`.
///
/// §190: repacking **não é** compactação lógica. Não remove tombstones, não
/// remove episódios, não reordena LSN, não altera payloads e não colapsa
/// duplicados. A verificação de raiz no fim é o que o garante mecanicamente.
pub fn repack_segment(
    source: &Path,
    target: &Path,
    opts: PackOptions,
    source_generation: u32,
    target_generation: u32,
    hasher: CanonicalHasher<'_>,
) -> V6Result<PackOutcome> {
    const CTX: &str = "hrkl v6 repacker";
    if target.exists() {
        return Err(corrupt(
            CTX,
            "target generation already exists; generations are immutable",
        ));
    }
    let reader = open_packed(source, opts.max_block_bytes)?;
    let source_footer = reader.footer;
    let init = SegmentInit {
        segment_id: reader.header.segment_id,
        created_hlc: reader.header.created_hlc,
        first_lsn: reader.header.first_lsn,
        writer_epoch: reader.header.writer_epoch,
        storage_namespace_id: reader.header.storage_namespace_id,
    };
    let tmp = temp_path(target);
    let _ = std::fs::remove_file(&tmp);
    let mut writer = PackedSegmentWriter::create(&tmp, init, opts)?;
    let mut counters = ScanCounters::default();
    reader.for_each_record(&mut counters, |r| {
        let h = hasher(r.lsn, r.hlc, r.payload)?;
        writer.push(r.lsn, r.hlc, r.payload.to_vec(), &h)
    })?;
    let (target_footer, stats) = writer.finish()?;

    if target_footer.logical_root != source_footer.logical_root {
        let _ = std::fs::remove_file(&tmp);
        return Err(corrupt(
            CTX,
            "repacked generation has a different logical_root",
        ));
    }
    std::fs::rename(&tmp, target)?;
    sync_parent_dir(target)?;

    let receipt = PackReceipt {
        segment_id: reader.header.segment_id,
        storage_namespace_id: reader.header.storage_namespace_id,
        source_generation,
        source_physical_digest: physical_digest_of_file(source)?,
        target_generation,
        target_physical_digest: physical_digest_of_file(target)?,
        logical_root: target_footer.logical_root,
        canonical_codec: CANONICAL_CODEC_V1,
        codec: opts.profile.codec(),
        block_size: opts.block_target_bytes as u32,
        first_lsn: target_footer.min_lsn,
        last_lsn: target_footer.max_lsn,
        record_count: target_footer.record_count,
        source_physical_size: std::fs::metadata(source)?.len(),
        target_physical_size: std::fs::metadata(target)?.len(),
        packer_version: PACKER_VERSION,
        created_hlc: reader.header.created_hlc,
    };
    Ok(PackOutcome {
        receipt,
        footer: target_footer,
        stats,
        target_path: target.to_path_buf(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::v6::compress::PackingProfile;
    use crate::v6::raw::RawSegmentWriter;

    /// Hasher de teste: trata o payload como opaco, exactamente como a Fase
    /// inicial de §42 prevê.
    fn hasher_opaco(lsn: Lsn, hlc: u64, payload: &[u8]) -> V6Result<[u8; 32]> {
        let mut h = blake3::Hasher::new();
        h.update(b"TEST:OPAQUE");
        h.update(&lsn.to_le_bytes());
        h.update(&hlc.to_le_bytes());
        h.update(payload);
        Ok(*h.finalize().as_bytes())
    }

    fn dir_teste(nome: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("hrkl6-packer-{}-{nome}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn escreve_raw(path: &Path, n: u64) -> FooterV6 {
        let init = SegmentInit {
            segment_id: 88,
            created_hlc: 4242,
            first_lsn: 9_000_001,
            writer_epoch: 1,
            storage_namespace_id: [0x77; 16],
        };
        let mut w = RawSegmentWriter::create(path, init).unwrap();
        for i in 0..n {
            let payload = format!("evento numero {i} com algum conteudo repetido").into_bytes();
            let h = hasher_opaco(9_000_001 + i, 1_700_000 + i * 2, &payload).unwrap();
            w.append(9_000_001 + i, 1_700_000 + i * 2, &payload, &h)
                .unwrap();
        }
        w.seal().unwrap()
    }

    #[test]
    fn raw_e_packed_partilham_a_logical_root() {
        let d = dir_teste("root");
        let raw = d.join("0000000088.hrkl");
        let packed = d.join("0000000088.g1.hrkl");
        let raw_footer = escreve_raw(&raw, 3_000);

        let out = pack_segment(&raw, &packed, PackOptions::default(), 0, 1, &hasher_opaco).unwrap();
        // Invariante 3 da SPEC.
        assert_eq!(out.footer.logical_root, raw_footer.logical_root);
        assert_eq!(out.receipt.logical_root, raw_footer.logical_root);
        // ...e §7.3: os digests FÍSICOS têm de diferir.
        assert_ne!(
            out.receipt.source_physical_digest,
            out.receipt.target_physical_digest
        );
        assert!(out.receipt.target_physical_size < out.receipt.source_physical_size);
    }

    #[test]
    fn unpack_de_pack_devolve_os_mesmos_registos() {
        let d = dir_teste("roundtrip");
        let raw = d.join("seg.hrkl");
        let packed = d.join("seg.g1.hrkl");
        escreve_raw(&raw, 2_000);
        let originais = scan_raw_segment(&raw).unwrap().records;

        pack_segment(&raw, &packed, PackOptions::default(), 0, 1, &hasher_opaco).unwrap();
        let reader = open_packed(&packed, super::super::error::HARD_MAX_BLOCK_BYTES).unwrap();
        let mut c = ScanCounters::default();
        let lidos = reader.scan_all(&mut c).unwrap();

        assert_eq!(lidos.len(), originais.len());
        for (got, want) in lidos.iter().zip(&originais) {
            assert_eq!(got.0, want.lsn);
            assert_eq!(got.1, want.hlc);
            assert_eq!(got.2, want.payload);
        }
    }

    #[test]
    fn segmento_por_selar_nao_e_packado() {
        let d = dir_teste("unsealed");
        let raw = d.join("activo.hrkl");
        let init = SegmentInit {
            segment_id: 1,
            created_hlc: 1,
            first_lsn: 1,
            writer_epoch: 1,
            storage_namespace_id: [0u8; 16],
        };
        let mut w = RawSegmentWriter::create(&raw, init).unwrap();
        w.append(1, 1, b"a", &hasher_opaco(1, 1, b"a").unwrap())
            .unwrap();
        w.sync().unwrap();
        drop(w);
        let e = pack_segment(
            &raw,
            &d.join("out.hrkl"),
            PackOptions::default(),
            0,
            1,
            &hasher_opaco,
        );
        assert!(e.is_err(), "§22: só se packa depois do seal");
    }

    #[test]
    fn geracao_publicada_nunca_e_sobrescrita() {
        let d = dir_teste("imutavel");
        let raw = d.join("seg.hrkl");
        let packed = d.join("seg.g1.hrkl");
        escreve_raw(&raw, 100);
        pack_segment(&raw, &packed, PackOptions::default(), 0, 1, &hasher_opaco).unwrap();
        let e = pack_segment(&raw, &packed, PackOptions::default(), 0, 1, &hasher_opaco);
        assert!(e.is_err(), "§83: uma geração publicada não é sobrescrita");
    }

    #[test]
    fn hasher_divergente_aborta_e_nao_publica() {
        // Simula um packer com uma noção de identidade lógica diferente da do
        // writer: o `rename` NUNCA pode acontecer.
        let d = dir_teste("divergente");
        let raw = d.join("seg.hrkl");
        let packed = d.join("seg.g1.hrkl");
        escreve_raw(&raw, 200);

        let mau = |lsn: Lsn, hlc: u64, p: &[u8]| -> V6Result<[u8; 32]> {
            let mut h = hasher_opaco(lsn, hlc, p)?;
            h[0] ^= 0xff;
            Ok(h)
        };
        let e = pack_segment(&raw, &packed, PackOptions::default(), 0, 1, &mau);
        assert!(e.is_err());
        assert!(
            !packed.exists(),
            "não pode existir geração publicada após falha"
        );
        assert!(!temp_path(&packed).exists(), "o .tmp tem de ser limpo");
    }

    #[test]
    fn temporarios_orfaos_sao_varridos() {
        let d = dir_teste("orfaos");
        std::fs::write(d.join("seg.g1.hrkl.tmp"), b"lixo").unwrap();
        std::fs::write(d.join("seg.hrkl"), b"nao mexer").unwrap();
        let removidos = sweep_orphan_temps(&d).unwrap();
        assert_eq!(removidos.len(), 1);
        assert!(d.join("seg.hrkl").exists());
    }

    #[test]
    fn repack_preserva_a_raiz_com_outro_perfil_e_outro_block_size() {
        let d = dir_teste("repack");
        let raw = d.join("seg.hrkl");
        let g1 = d.join("seg.g1.hrkl");
        let g2 = d.join("seg.g2.hrkl");
        let raw_footer = escreve_raw(&raw, 2_500);

        let o1 = PackOptions {
            profile: PackingProfile::Fast,
            block_target_bytes: super::super::block::MIN_BLOCK_TARGET,
            ..PackOptions::default()
        };
        pack_segment(&raw, &g1, o1, 0, 1, &hasher_opaco).unwrap();

        let o2 = PackOptions {
            profile: PackingProfile::Archive,
            block_target_bytes: super::super::block::MAX_BLOCK_TARGET,
            ..PackOptions::default()
        };
        let out = repack_segment(&g1, &g2, o2, 1, 2, &hasher_opaco).unwrap();

        assert_eq!(out.footer.logical_root, raw_footer.logical_root);
        assert_ne!(
            out.receipt.source_physical_digest,
            out.receipt.target_physical_digest
        );
        // Block sizes diferentes => contagens de bloco diferentes, mesma verdade.
        let r1 = open_packed(&g1, super::super::error::HARD_MAX_BLOCK_BYTES).unwrap();
        let r2 = open_packed(&g2, super::super::error::HARD_MAX_BLOCK_BYTES).unwrap();
        assert!(r1.block_count() > r2.block_count());
        assert_eq!(r1.logical_root(), r2.logical_root());
    }

    #[test]
    fn crash_antes_do_rename_deixa_o_raw_como_autoridade() {
        // O `.tmp` é o único vestígio; o RAW continua completo e legível.
        let d = dir_teste("crash");
        let raw = d.join("seg.hrkl");
        let packed = d.join("seg.g1.hrkl");
        let footer = escreve_raw(&raw, 500);

        std::fs::write(temp_path(&packed), b"packing interrompido a meio").unwrap();
        assert!(!packed.exists());
        let scan = scan_raw_segment(&raw).unwrap();
        assert_eq!(scan.footer.unwrap().logical_root, footer.logical_root);
        assert_eq!(scan.records.len(), 500);

        sweep_orphan_temps(&d).unwrap();
        // E depois da limpeza o packing corre normalmente.
        let out = pack_segment(&raw, &packed, PackOptions::default(), 0, 1, &hasher_opaco).unwrap();
        assert_eq!(out.footer.logical_root, footer.logical_root);
    }
}
