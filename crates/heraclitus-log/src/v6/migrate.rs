//! SPEC-0050 §131–§132 — a ponte auditável entre um segmento v1–v5 e a sua
//! representação v6.
//!
//! ## O erro que este módulo existe para não cometer
//!
//! §131 é explícito: é **incorrecto** declarar `v5 physical root == v6 logical
//! root`. São conceitos diferentes —
//!
//! ```text
//! raiz legada (v1-v5)   BLAKE3 sobre BYTES FÍSICOS do registo
//! raiz lógica (v6)      BLAKE3 sobre o CanonicalRecordV1 (lsn, hlc, opaque_meta, Episode)
//! ```
//!
//! — e a tentação de as equiparar é forte, porque isso pouparia recomputar
//! tudo. Equipará-las tornaria toda a cadeia forense v6 indefensável: um
//! carimbo do tempo sobre a raiz legada passaria a ser apresentado como prova
//! sobre a identidade canónica, que ninguém calculou.
//!
//! Por isso a migração **recomputa** a raiz lógica registo a registo e emite um
//! [`LegacyMigrationReceipt`] que guarda as duas raízes **lado a lado**, sem as
//! confundir. É o recibo que liga o passado ao presente.
//!
//! ## O que a migração preserva, e o que não pode preservar
//!
//! | preservado | porquê |
//! |---|---|
//! | LSN, HLC, `EventId`, `Episode` completo | é o histórico; perdê-lo seria reescrever o passado |
//! | `opaque_meta` das gerações v3+ | faz parte da identidade canónica (§9) |
//!
//! | perdido, deliberadamente | porquê |
//! |---|---|
//! | `opaque_meta` das gerações v1/v2 | essas gerações **não o persistiam**; zero é a única representação honesta (ver [`crate::decode_episode_payload_with_meta`]) |
//! | a raiz legada como identidade | fica no recibo, nunca no footer v6 |
//!
//! ## Nunca destrói a origem
//!
//! A migração **lê** o segmento legado e **escreve** um ficheiro v6 novo. O
//! original fica intacto, byte a byte — o teste
//! `migrar_nao_toca_no_segmento_legado` prova-o. Apagar o legado é decisão do
//! operador, depois de o recibo ter sido verificado.

use std::path::Path;

use heraclitus_core::{Lsn, SegmentId};

use super::canonical::{canonical_record_hash, CanonicalRecordV1, CANONICAL_CODEC_V1};
use super::error::{corrupt, V6Result};
use super::footer::FooterV6;
use super::header::StorageNamespaceId;
use super::raw::{RawSegmentWriter, SegmentInit};
use super::receipts::{physical_digest_of_file, LegacyMigrationReceipt};
use crate::format::{self, Decoded};

/// O que uma migração produziu.
#[derive(Debug, Clone)]
pub struct MigrationOutcome {
    pub receipt: LegacyMigrationReceipt,
    pub footer: FooterV6,
    /// A raiz gravada no rodapé do segmento legado, quando ele estava selado.
    /// `None` para uma cauda activa — que é migrável, mas não tem raiz legada
    /// com que confrontar.
    pub legacy_sealed_root: Option<[u8; 32]>,
    /// A raiz legada **recomputada** a partir dos bytes, sempre presente.
    pub legacy_recomputed_root: [u8; 32],
    pub records: u64,
}

impl MigrationOutcome {
    /// A raiz legada gravada bate com a recomputada.
    ///
    /// `None` quando o segmento não estava selado (não há nada com que
    /// confrontar) — e nesse caso a migração continua a ser válida, porque a
    /// identidade v6 é recomputada do zero de qualquer maneira.
    pub fn legacy_root_ok(&self) -> Option<bool> {
        self.legacy_sealed_root
            .map(|r| r == self.legacy_recomputed_root)
    }
}

/// Parâmetros da migração. Um struct em vez de seis argumentos posicionais,
/// porque trocar `segment_id` com `writer_epoch` por engano produziria um
/// segmento v6 plausível e errado.
#[derive(Debug, Clone, Copy)]
pub struct MigrateOptions {
    pub target_segment_id: SegmentId,
    pub target_generation: u32,
    pub created_hlc: u64,
    pub writer_epoch: u64,
    pub storage_namespace_id: StorageNamespaceId,
}

/// Migra um segmento legado (`format_version` 1–5) para um RAW v6 selado.
///
/// `target` **não pode existir**: uma geração publicada nunca é sobrescrita
/// (§83), e isso vale igualmente para a primeira geração de um segmento
/// migrado.
///
/// A raiz lógica é recomputada registo a registo com o codec canónico v6 —
/// nunca herdada da raiz legada (§131).
pub fn migrate_legacy_segment(
    source: &Path,
    target: &Path,
    opts: MigrateOptions,
) -> V6Result<MigrationOutcome> {
    const CTX: &str = "hrkl v6 migrate";

    let bytes = std::fs::read(source)?;
    let header = format::SegmentHeader::decode(&bytes)?;
    if header.version > format::FORMAT_VERSION {
        return Err(corrupt(
            CTX,
            format!(
                "segmento na format_version {} — esta build lê até à {}",
                header.version,
                format::FORMAT_VERSION
            ),
        ));
    }

    // Varrer o legado com a regra **da geração dele** (CRC e folha Merkle
    // dependem da versão). Usar a regra do v5 num segmento v1 leria lixo.
    let mut cursor = format::HEADER_LEN;
    let mut legacy_leaves: Vec<[u8; 32]> = Vec::new();
    let mut registos: Vec<(Lsn, u64, Vec<u8>)> = Vec::new();
    let mut legacy_sealed_root = None;
    loop {
        if cursor >= bytes.len() {
            break;
        }
        match format::decode_record(header.version, &bytes[cursor..]) {
            Decoded::Record(lsn, hlc, payload, consumed) => {
                legacy_leaves.push(format::record_leaf(
                    header.version,
                    &bytes[cursor..cursor + consumed],
                ));
                registos.push((lsn, hlc, payload.to_vec()));
                cursor += consumed;
            }
            Decoded::Footer(f) => {
                legacy_sealed_root = Some(f.blake3_root);
                if f.record_count != registos.len() as u64 {
                    return Err(corrupt(
                        CTX,
                        format!(
                            "o rodapé legado declara {} registos, o varrimento encontrou {}",
                            f.record_count,
                            registos.len()
                        ),
                    ));
                }
                break;
            }
            // §208: uma cauda rasgada não é migrável em silêncio. Migrar
            // metade de um segmento produziria uma raiz lógica que nunca mais
            // se reconcilia com a origem.
            Decoded::Torn => {
                return Err(corrupt(
                    CTX,
                    format!(
                        "cauda rasgada ou corrupção no offset {cursor} do segmento legado \
                         (v{}); repare a origem antes de migrar",
                        header.version
                    ),
                ));
            }
        }
    }
    if registos.is_empty() {
        return Err(corrupt(CTX, "segmento legado sem registos"));
    }

    let legacy_recomputed_root = crate::merkle_root(&legacy_leaves);
    if let Some(gravada) = legacy_sealed_root {
        if gravada != legacy_recomputed_root {
            return Err(corrupt(
                CTX,
                "a raiz legada gravada no rodapé não bate com a recomputada; \
                 migrar um segmento cuja integridade já falhou propagaria a corrupção",
            ));
        }
    }

    // Escrever o v6 recomputando a identidade canónica de cada registo.
    let mut writer = RawSegmentWriter::create(
        target,
        SegmentInit {
            segment_id: opts.target_segment_id,
            created_hlc: opts.created_hlc,
            first_lsn: registos[0].0,
            writer_epoch: opts.writer_epoch,
            storage_namespace_id: opts.storage_namespace_id,
        },
    )?;
    for (lsn, hlc, payload_legado) in &registos {
        // O payload legado é reinterpretado sob a regra da SUA geração e
        // re-emitido no layout corrente. É aqui que v1/v2 perdem o
        // `opaque_meta` que nunca tiveram, e onde v1–v3 perdem valid time.
        let decoded = crate::decode_episode_payload_with_meta(header.version, payload_legado)?;
        let payload_v6 = crate::encode_storage_payload_for_version(
            format::FORMAT_VERSION,
            decoded.opaque_meta,
            &decoded.episode,
        )?;
        let h = canonical_record_hash(&CanonicalRecordV1 {
            lsn: *lsn,
            record_hlc: *hlc,
            opaque_meta: decoded.opaque_meta,
            episode: &decoded.episode,
        });
        writer.append(*lsn, *hlc, &payload_v6, &h)?;
    }
    let footer = writer.seal()?;

    let receipt = LegacyMigrationReceipt {
        legacy_format: header.version,
        legacy_segment_id: header.segment_id,
        legacy_root: legacy_recomputed_root,
        canonical_codec_v6: CANONICAL_CODEC_V1,
        v6_logical_root: footer.logical_root,
        target_generation: opts.target_generation,
        target_physical_digest: physical_digest_of_file(target)?,
        record_count: footer.record_count,
    };

    Ok(MigrationOutcome {
        receipt,
        footer,
        legacy_sealed_root,
        legacy_recomputed_root,
        records: footer.record_count,
    })
}

/// Confirma que um segmento v6 migrado contém exactamente o mesmo histórico
/// lógico que a origem legada.
///
/// Não compara raízes (§131 proíbe): compara **registo a registo** o LSN, o
/// HLC e o `Episode` reconstruído dos dois lados. É a única comparação
/// defensável entre duas noções de identidade diferentes.
pub fn verify_migration_equivalence(
    legacy_source: &Path,
    v6_target: &Path,
) -> V6Result<MigrationEquivalence> {
    const CTX: &str = "hrkl v6 migrate verify";
    let bytes = std::fs::read(legacy_source)?;
    let header = format::SegmentHeader::decode(&bytes)?;

    let mut legado: Vec<(Lsn, u64, heraclitus_core::Episode)> = Vec::new();
    let mut cursor = format::HEADER_LEN;
    while cursor < bytes.len() {
        match format::decode_record(header.version, &bytes[cursor..]) {
            Decoded::Record(lsn, hlc, payload, consumed) => {
                legado.push((
                    lsn,
                    hlc,
                    crate::decode_episode_payload(header.version, payload)?,
                ));
                cursor += consumed;
            }
            Decoded::Footer(_) => break,
            Decoded::Torn => return Err(corrupt(CTX, "origem legada rasgada")),
        }
    }

    let scan = super::raw::scan_raw_segment(v6_target)?;
    if scan.records.len() != legado.len() {
        return Ok(MigrationEquivalence {
            equivalente: false,
            registos: legado.len() as u64,
            divergencia: Some(format!(
                "contagens diferentes: legado {} vs v6 {}",
                legado.len(),
                scan.records.len()
            )),
        });
    }
    for (i, ((lsn, hlc, ep), r)) in legado.iter().zip(&scan.records).enumerate() {
        let novo = crate::decode_episode_payload(format::FORMAT_VERSION, &r.payload)?;
        let divergiu = if *lsn != r.lsn {
            Some(format!("LSN: {lsn} vs {}", r.lsn))
        } else if *hlc != r.hlc {
            Some(format!("HLC: {hlc} vs {}", r.hlc))
        } else if ep.id != novo.id {
            Some("EventId".to_string())
        } else if ep.content != novo.content {
            Some("content".to_string())
        } else if ep.attrs != novo.attrs {
            Some("attrs".to_string())
        } else if ep.kind != novo.kind {
            Some("kind".to_string())
        } else if ep.parents != novo.parents {
            Some("parents".to_string())
        } else {
            None
        };
        if let Some(d) = divergiu {
            return Ok(MigrationEquivalence {
                equivalente: false,
                registos: legado.len() as u64,
                divergencia: Some(format!("registo {i}: {d}")),
            });
        }
    }
    Ok(MigrationEquivalence {
        equivalente: true,
        registos: legado.len() as u64,
        divergencia: None,
    })
}

#[derive(Debug, Clone)]
pub struct MigrationEquivalence {
    pub equivalente: bool,
    pub registos: u64,
    pub divergencia: Option<String>,
}


// ---------------------------------------------------------------------------
// SPEC-0050 §129--§133 — migração de uma BASE inteira, não de um segmento
// ---------------------------------------------------------------------------

/// Parâmetros da migração de uma base completa.
#[derive(Debug, Clone, Copy)]
pub struct MigrateDatabaseOptions {
    /// Corre [`verify_migration_equivalence`] em cada segmento migrado.
    ///
    /// Ligado por omissão, e deliberadamente: a migração recomputa a
    /// identidade canónica do zero (§131), portanto um erro no codec produziria
    /// um segmento v6 **plausível** e errado, que só se descobriria quando
    /// alguém tentasse provar um LSN meses depois. Desligar isto troca minutos
    /// de CPU por uma classe inteira de falhas silenciosas.
    pub verify: bool,
    /// HLC de criação carimbado nos segmentos v6 e no manifesto.
    pub created_hlc: u64,
    /// Namespace do banco de destino. `None` gera um novo.
    ///
    /// Um banco migrado é um banco **novo**: reutilizar o namespace do original
    /// faria duas bases distintas reclamarem a mesma identidade de storage, e
    /// §20 existe precisamente para isso não acontecer.
    pub storage_namespace_id: Option<StorageNamespaceId>,
}

impl Default for MigrateDatabaseOptions {
    fn default() -> Self {
        Self {
            verify: true,
            created_hlc: 0,
            storage_namespace_id: None,
        }
    }
}

/// O que aconteceu a um segmento.
#[derive(Debug, Clone)]
pub struct SegmentMigration {
    pub legacy_path: std::path::PathBuf,
    pub legacy_format: u16,
    pub segment_id: SegmentId,
    pub location: String,
    pub first_lsn: Lsn,
    pub last_lsn: Lsn,
    pub records: u64,
    pub receipt: LegacyMigrationReceipt,
    pub receipt_path: std::path::PathBuf,
    /// `Some(false)` = a raiz gravada no rodapé legado não bate com a
    /// recomputada. `None` = o segmento não estava selado (cauda).
    pub legacy_root_ok: Option<bool>,
    /// `None` quando `verify` estava desligado.
    pub equivalence: Option<MigrationEquivalence>,
}

/// O resultado de migrar uma base.
#[derive(Debug, Clone)]
pub struct DatabaseMigrationReport {
    pub storage_namespace_id: StorageNamespaceId,
    pub segments: Vec<SegmentMigration>,
    pub records: u64,
    pub first_lsn: Lsn,
    pub last_lsn: Lsn,
    pub manifest_generation: u64,
    /// O último segmento legado não tinha rodapé (era a cauda activa) e foi
    /// migrado para um segmento v6 **selado**, conforme §130.
    pub legacy_tail_sealed: bool,
}

impl DatabaseMigrationReport {
    /// Nenhum segmento divergiu em nada.
    pub fn is_clean(&self) -> bool {
        self.segments.iter().all(|s| {
            s.legacy_root_ok != Some(false)
                && s.equivalence.as_ref().map(|e| e.equivalente) != Some(false)
        })
    }
}

/// SPEC-0050 §129--§133 — migra um diretório de log v1--v5 para uma raiz v6
/// nova, catalogada e pronta a abrir.
///
/// ## O que esta função garante
///
/// 1. **Nunca toca na origem.** Lê os `.hrkl` legados e escreve noutro sítio.
///    §133 põe `preserve legacy original = true` por omissão justamente porque
///    pode haver um carimbo RFC 3161, uma assinatura ou uma perícia a apontar
///    para o hash antigo. Apagar o legado é decisão do operador, depois de
///    verificar o recibo — nunca desta função.
/// 2. **O destino tem de não existir.** Uma geração publicada não é
///    sobrescrita (§83), e isso vale para a primeira geração de um banco
///    migrado tanto como para qualquer outra.
/// 3. **A identidade v6 é recomputada, nunca herdada** (§131). Cada segmento
///    produz um [`LegacyMigrationReceipt`] persistido em `<v6_root>/receipts/`,
///    com as duas raízes lado a lado.
/// 4. **A contiguidade de LSN é verificada, não assumida** (§5). Um buraco
///    entre segmentos legados é erro duro: em v6 a contiguidade é um
///    invariante do formato, e migrar um buraco produziria uma base que mente
///    sobre a sua própria história.
/// 5. **A cauda activa é selada** (§130). O último segmento legado, se não
///    tiver rodapé, é migrado para um segmento v6 selado; a base v6 abre depois
///    uma cauda nova e limpa. Nunca se continua a appendar v6 num ficheiro
///    legado.
///
/// ## O que esta função recusa fazer
///
/// Uma cauda **rasgada** (torn write no último registo) faz a migração falhar,
/// em vez de migrar metade. §130 manda "recover according to legacy rules", e
/// essa recuperação é destrutiva — trunca o registo parcial. Fazê-la aqui
/// violaria a garantia 1. O caminho correcto é o operador abrir a base uma vez
/// com o motor legado (que repara a cauda) e voltar a correr a migração.
pub fn migrate_database(
    legacy_dir: &Path,
    v6_root: &Path,
    opts: MigrateDatabaseOptions,
) -> V6Result<DatabaseMigrationReport> {
    const CTX: &str = "hrkl v6 migrate database";

    if !legacy_dir.is_dir() {
        return Err(corrupt(
            CTX,
            format!("origem não é um diretório: {}", legacy_dir.display()),
        ));
    }
    if v6_root.exists() && std::fs::read_dir(v6_root)?.next().is_some() {
        return Err(corrupt(
            CTX,
            format!(
                "destino {} já existe e não está vazio; migrar para dentro de um banco existente misturaria duas histórias",
                v6_root.display()
            ),
        ));
    }

    let mut ids: Vec<SegmentId> = std::fs::read_dir(legacy_dir)?
        .filter_map(|e| e.ok())
        .filter_map(|e| {
            let name = e.file_name().into_string().ok()?;
            name.strip_suffix(".hrkl")?.parse::<u64>().ok()
        })
        .collect();
    ids.sort_unstable();
    if ids.is_empty() {
        return Err(corrupt(
            CTX,
            format!("nenhum segmento `.hrkl` em {}", legacy_dir.display()),
        ));
    }

    let namespace = match opts.storage_namespace_id {
        Some(ns) => ns,
        None => super::engine::new_namespace(v6_root),
    };

    let segments_dir = v6_root.join("segments");
    let receipts_dir = v6_root.join("receipts");
    std::fs::create_dir_all(&segments_dir)?;
    let store = super::manifest::ManifestStore::open(v6_root.join("manifests"))?;
    let mut manifest = heraclitus_core::runtime::DatabaseManifest {
        storage_namespace_id: namespace,
        ..Default::default()
    };

    let mut saidas: Vec<SegmentMigration> = Vec::with_capacity(ids.len());
    let mut esperado_proximo: Option<Lsn> = None;
    let mut tail_sealed = false;
    let mut total = 0u64;

    for id in ids {
        let source = legacy_dir.join(format!("{id:020}.hrkl"));
        let location = format!("segments/{id:020}.g0000.raw.hrkl");
        let target = v6_root.join(&location);

        let legacy_format = {
            let head = std::fs::read(&source)?;
            format::SegmentHeader::decode(&head)?.version
        };

        let outcome = migrate_legacy_segment(
            &source,
            &target,
            MigrateOptions {
                target_segment_id: id,
                target_generation: 0,
                created_hlc: opts.created_hlc,
                writer_epoch: 0,
                storage_namespace_id: namespace,
            },
        )?;

        if outcome.records == 0 {
            // Um segmento vazio não representa história alguma; catalogá-lo
            // criaria um descritor com intervalo de LSN degenerado.
            std::fs::remove_file(&target)?;
            continue;
        }
        if outcome.legacy_sealed_root.is_none() {
            // §130 — era a cauda activa. Sai daqui SELADA.
            tail_sealed = true;
        }

        let footer = outcome.footer;
        if let Some(proximo) = esperado_proximo {
            if footer.min_lsn != proximo {
                return Err(corrupt(
                    CTX,
                    format!(
                        "buraco de LSN entre segmentos: esperava {proximo}, o segmento {id} \
                         começa em {}. A contiguidade de LSN é um invariante do formato v6 \
                         (§5); migrar um buraco produziria uma base que mente sobre a sua \
                         própria história.",
                        footer.min_lsn
                    ),
                ));
            }
        }
        esperado_proximo = Some(footer.max_lsn + 1);
        total += outcome.records;

        let receipt_path =
            super::receipts::persist_migration_receipt(&receipts_dir, &outcome.receipt)?;

        let equivalence = if opts.verify {
            let eq = verify_migration_equivalence(&source, &target)?;
            if !eq.equivalente {
                return Err(corrupt(
                    CTX,
                    format!(
                        "o segmento {id} migrado não é equivalente ao legado: {}",
                        eq.divergencia.unwrap_or_else(|| "?".into())
                    ),
                ));
            }
            Some(eq)
        } else {
            None
        };

        let physical_size = std::fs::metadata(&target)?.len();
        super::manifest::register_sealed_raw(
            &mut manifest,
            id,
            &footer,
            CANONICAL_CODEC_V1 as u16,
            &location,
            physical_size,
            outcome.receipt.target_physical_digest,
            opts.created_hlc,
        )?;

        saidas.push(SegmentMigration {
            legacy_path: source,
            legacy_format,
            segment_id: id,
            location,
            first_lsn: footer.min_lsn,
            last_lsn: footer.max_lsn,
            records: outcome.records,
            receipt: outcome.receipt.clone(),
            receipt_path,
            legacy_root_ok: outcome.legacy_root_ok(),
            equivalence,
        });
    }

    if saidas.is_empty() {
        return Err(corrupt(CTX, "todos os segmentos legados estavam vazios"));
    }

    let committed = store.commit(&mut manifest)?;

    Ok(DatabaseMigrationReport {
        storage_namespace_id: namespace,
        records: total,
        first_lsn: saidas.first().unwrap().first_lsn,
        last_lsn: saidas.last().unwrap().last_lsn,
        manifest_generation: committed.generation,
        legacy_tail_sealed: tail_sealed,
        segments: saidas,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use heraclitus_core::{Episode, EventKind};
    use std::io::Write;

    fn eps() -> Vec<Episode> {
        (0..5u64)
            .map(|i| {
                let mut e = Episode::new(
                    "mig",
                    EventKind::Custom(format!("K{i}")),
                    format!("payload-{i}").into_bytes(),
                );
                e.attrs.insert("uf".into(), "SP".into());
                e.valid_from = Some(100 + i);
                e
            })
            .collect()
    }

    fn escrever_legado(dir: &Path, version: u16, eps: &[Episode], selar: bool) -> std::path::PathBuf {
        let p = dir.join(format!("legado-v{version}.hrkl"));
        let mut f = std::fs::File::create(&p).unwrap();
        f.write_all(
            &format::SegmentHeader {
                version,
                segment_id: 42,
                created_hlc: 9,
            }
            .encode(),
        )
        .unwrap();
        let mut folhas = Vec::new();
        for (i, e) in eps.iter().enumerate() {
            let payload =
                crate::encode_storage_payload_for_version(version, e.id.0.to_bytes(), e).unwrap();
            let rec = format::encode_record(version, i as u64, 500 + i as u64, &payload);
            folhas.push(format::record_leaf(version, &rec));
            f.write_all(&rec).unwrap();
        }
        if selar {
            f.write_all(
                &format::SegmentFooter {
                    record_count: eps.len() as u64,
                    min_lsn: 0,
                    max_lsn: eps.len() as u64 - 1,
                    blake3_root: crate::merkle_root(&folhas),
                }
                .encode(),
            )
            .unwrap();
        }
        f.sync_all().unwrap();
        p
    }

    fn opts() -> MigrateOptions {
        MigrateOptions {
            target_segment_id: 42,
            target_generation: 0,
            created_hlc: 1_000,
            writer_epoch: 1,
            storage_namespace_id: [7u8; 16],
        }
    }

    #[test]
    fn migra_todas_as_geracoes_de_1_a_5() {
        for v in 1..=5u16 {
            let dir = tempfile::tempdir().unwrap();
            let eps = eps();
            let src = escrever_legado(dir.path(), v, &eps, true);
            let dst = dir.path().join(format!("v6-de-v{v}.hrkl"));

            let out = migrate_legacy_segment(&src, &dst, opts()).unwrap();
            assert_eq!(out.records, eps.len() as u64, "v{v}");
            assert_eq!(out.receipt.legacy_format, v);
            assert_eq!(out.legacy_root_ok(), Some(true), "v{v}");

            let eq = verify_migration_equivalence(&src, &dst).unwrap();
            assert!(eq.equivalente, "v{v}: {:?}", eq.divergencia);
            assert_eq!(eq.registos, eps.len() as u64);
        }
    }

    #[test]
    fn a_raiz_legada_nunca_e_reinterpretada_como_raiz_v6() {
        // §131 + §208 ("legacy roots nunca são silenciosamente reinterpretadas
        // como roots v6"). As duas raízes têm de ser DIFERENTES e ambas têm de
        // estar no recibo.
        let dir = tempfile::tempdir().unwrap();
        let eps = eps();
        let src = escrever_legado(dir.path(), 5, &eps, true);
        let dst = dir.path().join("v6.hrkl");
        let out = migrate_legacy_segment(&src, &dst, opts()).unwrap();

        assert_ne!(
            out.receipt.legacy_root, out.receipt.v6_logical_root,
            "as duas raízes coincidiram — ou o codec canónico degenerou no hash físico, \
             ou alguém copiou uma para a outra"
        );
        assert_eq!(out.receipt.legacy_root, out.legacy_recomputed_root);
        assert_eq!(out.receipt.v6_logical_root, out.footer.logical_root);
        assert_eq!(out.receipt.canonical_codec_v6, CANONICAL_CODEC_V1);
        // O recibo codifica as duas lado a lado, de forma determinística.
        assert_eq!(out.receipt.encode(), out.receipt.clone().encode());
    }

    #[test]
    fn migrar_nao_toca_no_segmento_legado() {
        let dir = tempfile::tempdir().unwrap();
        let eps = eps();
        let src = escrever_legado(dir.path(), 4, &eps, true);
        let antes = std::fs::read(&src).unwrap();
        let dst = dir.path().join("v6.hrkl");
        migrate_legacy_segment(&src, &dst, opts()).unwrap();
        assert_eq!(antes, std::fs::read(&src).unwrap());
    }

    #[test]
    fn v1_e_v2_migram_com_opaque_meta_zero_e_sem_valid_time() {
        // As gerações que não persistiam estes campos não podem ganhá-los na
        // migração: isso seria inventar passado.
        for v in [1u16, 2] {
            let dir = tempfile::tempdir().unwrap();
            let eps = eps();
            let src = escrever_legado(dir.path(), v, &eps, true);
            let dst = dir.path().join("v6.hrkl");
            migrate_legacy_segment(&src, &dst, opts()).unwrap();

            let scan = super::super::raw::scan_raw_segment(&dst).unwrap();
            for r in &scan.records {
                let d = crate::decode_episode_payload_with_meta(
                    format::FORMAT_VERSION,
                    &r.payload,
                )
                .unwrap();
                assert_eq!(d.opaque_meta, [0u8; 16], "v{v}: opaque_meta inventado");
                assert_eq!(d.episode.valid_from, None, "v{v}: valid time inventado");
                assert_eq!(d.episode.valid_to, None, "v{v}");
            }
        }
    }

    #[test]
    fn v3_em_diante_preserva_opaque_meta() {
        for v in [3u16, 4, 5] {
            let dir = tempfile::tempdir().unwrap();
            let eps = eps();
            let src = escrever_legado(dir.path(), v, &eps, true);
            let dst = dir.path().join("v6.hrkl");
            migrate_legacy_segment(&src, &dst, opts()).unwrap();

            let scan = super::super::raw::scan_raw_segment(&dst).unwrap();
            for (i, r) in scan.records.iter().enumerate() {
                let d = crate::decode_episode_payload_with_meta(
                    format::FORMAT_VERSION,
                    &r.payload,
                )
                .unwrap();
                assert_eq!(
                    d.opaque_meta,
                    eps[i].id.0.to_bytes(),
                    "v{v}: opaque_meta perdido na migração"
                );
            }
        }
    }

    #[test]
    fn cauda_rasgada_recusa_migrar_em_vez_de_migrar_metade() {
        let dir = tempfile::tempdir().unwrap();
        let eps = eps();
        let src = escrever_legado(dir.path(), 5, &eps, false);
        // Trunca a meio do último registo.
        let bytes = std::fs::read(&src).unwrap();
        std::fs::write(&src, &bytes[..bytes.len() - 5]).unwrap();

        let dst = dir.path().join("v6.hrkl");
        let e = migrate_legacy_segment(&src, &dst, opts()).unwrap_err();
        assert!(
            e.to_string().contains("rasgada"),
            "erro inesperado: {e}"
        );
    }

    #[test]
    fn raiz_legada_divergente_recusa_migrar() {
        let dir = tempfile::tempdir().unwrap();
        let eps = eps();
        let src = escrever_legado(dir.path(), 5, &eps, true);
        // Adultera a raiz gravada no rodapé.
        let mut bytes = std::fs::read(&src).unwrap();
        let n = bytes.len();
        bytes[n - 1] ^= 0xFF;
        std::fs::write(&src, &bytes).unwrap();

        let dst = dir.path().join("v6.hrkl");
        let e = migrate_legacy_segment(&src, &dst, opts()).unwrap_err();
        assert!(e.to_string().contains("não bate"), "erro inesperado: {e}");
    }

    #[test]
    fn nao_sobrescreve_um_alvo_existente() {
        let dir = tempfile::tempdir().unwrap();
        let eps = eps();
        let src = escrever_legado(dir.path(), 5, &eps, true);
        let dst = dir.path().join("v6.hrkl");
        migrate_legacy_segment(&src, &dst, opts()).unwrap();
        assert!(
            migrate_legacy_segment(&src, &dst, opts()).is_err(),
            "§83: uma geração publicada não é sobrescrita"
        );
    }

    #[test]
    fn a_equivalencia_deteta_um_v6_adulterado() {
        let dir = tempfile::tempdir().unwrap();
        let eps = eps();
        let src = escrever_legado(dir.path(), 5, &eps, true);
        let dst = dir.path().join("v6.hrkl");
        migrate_legacy_segment(&src, &dst, opts()).unwrap();
        assert!(verify_migration_equivalence(&src, &dst).unwrap().equivalente);

        // Migrar SÓ os primeiros registos para outro ficheiro: a equivalência
        // tem de recusar, mesmo que cada registo migrado esteja correcto.
        let outro = dir.path().join("outro");
        std::fs::create_dir_all(&outro).unwrap();
        let curto = escrever_legado(&outro, 5, &eps[..2], true);
        let eq = verify_migration_equivalence(&curto, &dst).unwrap();
        assert!(!eq.equivalente);
        assert!(eq.divergencia.unwrap().contains("contagens diferentes"));
    }
}
