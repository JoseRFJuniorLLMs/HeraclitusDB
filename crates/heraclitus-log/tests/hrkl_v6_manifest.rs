//! SPEC-0050 Fase 3 (§200) — testes de integração do manifesto `.hrkm`, das
//! gerações físicas e da política de GC.
//!
//! Três coisas são verificadas aqui e não nos testes unitários, porque só fazem
//! sentido de ponta a ponta:
//!
//! 1. **O ciclo real**: selar RAW → catalogar → packar → registar → coletar.
//! 2. **Crash injection do commit** (§162): morrer em qualquer ponto da
//!    transacção de §88 nunca pode perder um `CanonicalRecord` committed.
//! 3. **O invariante de §91 sob sequências arbitrárias** de operações.

use std::path::{Path, PathBuf};

use heraclitus_core::runtime::{
    DatabaseManifest, DerivedArtifactRef, GenerationState, PhysicalLayout,
};
use heraclitus_core::Lsn;
use heraclitus_log::v6::canonical::DOMAIN_CANONICAL_RECORD;
use heraclitus_log::v6::error::V6Result;
use heraclitus_log::v6::gc::{
    apply_gc, assert_gc_invariant, plan_gc, GcBlockReason, GcOptions, PinRegistry,
};
use heraclitus_log::v6::manifest::{
    boot_report, decode_manifest, encode_manifest, quarantine_generation, record_pack,
    register_sealed_raw, ManifestStore, HRKM_FOOTER_LEN, HRKM_HEADER_LEN,
};
use heraclitus_log::v6::packed::{open_packed, PackOptions};
use heraclitus_log::v6::packer::{pack_and_commit, pack_segment};
use heraclitus_log::v6::raw::{scan_raw_segment, RawSegmentWriter, SegmentInit};
use heraclitus_log::v6::receipts::physical_digest_of_file;

// ---------------------------------------------------------------------------
// Infra
// ---------------------------------------------------------------------------

const NAMESPACE: [u8; 16] = [0xC0; 16];

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// HLC deste motor: `millis << 16 | contador`.
fn hlc(segundos: u64) -> u64 {
    (segundos * 1_000) << 16
}

/// O hasher que o packer recebe (§42): dos bytes persistidos para a identidade
/// lógica, sem conhecer o layout do payload.
fn hasher(_lsn: Lsn, _hlc: u64, payload: &[u8]) -> V6Result<[u8; 32]> {
    let mut h = blake3::Hasher::new();
    h.update(DOMAIN_CANONICAL_RECORD);
    h.update(payload);
    Ok(*h.finalize().as_bytes())
}

fn dir_teste(nome: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("hrkm-it-{}-{nome}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// Escreve e sela um segmento RAW, devolvendo o caminho e o footer.
fn sela_raw(
    dir: &Path,
    segment_id: u64,
    first_lsn: Lsn,
    n: u64,
) -> (PathBuf, heraclitus_log::v6::FooterV6) {
    let path = dir.join(format!("{segment_id:020}.hrkl"));
    let init = SegmentInit {
        segment_id,
        created_hlc: hlc(1),
        first_lsn,
        writer_epoch: 1,
        storage_namespace_id: NAMESPACE,
    };
    let mut w = RawSegmentWriter::create(&path, init).unwrap();
    for i in 0..n {
        let payload =
            format!("segmento {segment_id} evento {i} com conteudo repetido").into_bytes();
        let lsn = first_lsn + i;
        let h = hasher(lsn, 0, &payload).unwrap();
        w.append(lsn, 1_000 + i, &payload, &h).unwrap();
    }
    let footer = w.seal().unwrap();
    (path, footer)
}

/// Sela um segmento e cataloga-o.
fn sela_e_cataloga(
    dir: &Path,
    m: &mut DatabaseManifest,
    segment_id: u64,
    first_lsn: Lsn,
    n: u64,
) -> PathBuf {
    let (path, footer) = sela_raw(dir, segment_id, first_lsn, n);
    register_sealed_raw(
        m,
        segment_id,
        &footer,
        1,
        &path.to_string_lossy(),
        std::fs::metadata(&path).unwrap().len(),
        physical_digest_of_file(&path).unwrap(),
        hlc(10),
    )
    .unwrap();
    path
}

// ---------------------------------------------------------------------------
// Golden vector do `.hrkm`
// ---------------------------------------------------------------------------

/// Bytes congelados de um manifesto com um segmento, duas gerações e um
/// sidecar. Como no `.hrkl`, um teste que falhe aqui é um aviso de mudança de
/// formato — a resposta é uma versão nova, não actualizar a constante.
const GOLDEN_HRKM: &str = include_str!("golden/hrkm-v1.hex");

#[test]
fn golden_vector_do_hrkm() {
    use heraclitus_core::runtime::{
        CompressionCodec, PhysicalGeneration, RetentionPolicy, SegmentDescriptorV2,
    };
    let g0 = PhysicalGeneration {
        generation: 0,
        layout: PhysicalLayout::Raw,
        compression: CompressionCodec::Raw,
        location: "seg-88.hrkl".into(),
        physical_size: 10_000,
        physical_digest: [0x11; 32],
        state: GenerationState::Superseded,
        created_hlc: 100,
        verified_hlc: 100,
        superseded_hlc: 200,
        verified_copies: 1,
    };
    let g1 = PhysicalGeneration {
        generation: 1,
        layout: PhysicalLayout::Packed,
        compression: CompressionCodec::Zstd,
        location: "seg-88.g1.hrkl".into(),
        physical_size: 3_700,
        physical_digest: [0x22; 32],
        state: GenerationState::Active,
        created_hlc: 200,
        verified_hlc: 200,
        superseded_hlc: 0,
        verified_copies: 2,
    };
    let s = SegmentDescriptorV2 {
        segment_id: 88,
        first_lsn: 1,
        last_lsn: 500,
        record_count: 500,
        canonical_codec: 1,
        logical_root: [0xAB; 32],
        min_hlc: 10,
        max_hlc: 510,
        active_generation: 1,
        generations: vec![g0, g1],
        hrki: Some(DerivedArtifactRef {
            location: "seg-88.hrki".into(),
            size: 4096,
            digest: [0x33; 32],
            logical_root: [0xAB; 32],
            created_hlc: 300,
        }),
        parquet: None,
        retention: RetentionPolicy {
            legal_hold: false,
            gc_grace_seconds: 86_400,
            min_verified_copies: 2,
            preserve_legacy_original: true,
        },
    };
    let m = DatabaseManifest {
        manifest_version: 1,
        format_identifier: *b"HRKM",
        segments: Vec::new(),
        cumulative_watermark: 500,
        statistics_root_hash: [0x5A; 32],
        storage_namespace_id: NAMESPACE,
        manifest_generation: 7,
        segments_v2: vec![s],
        exported_through_lsn: 0,
    };
    let bytes = encode_manifest(&m).unwrap();
    assert_eq!(hex(&bytes), GOLDEN_HRKM.trim());
    assert_eq!(decode_manifest(&bytes).unwrap().segments_v2, m.segments_v2);
    // O enquadramento é fixo; só o corpo é variável.
    assert_eq!(HRKM_HEADER_LEN, 64);
    assert_eq!(HRKM_FOOTER_LEN, 96);
}

// ---------------------------------------------------------------------------
// O ciclo completo
// ---------------------------------------------------------------------------

#[test]
fn ciclo_completo_selar_catalogar_packar_coletar() {
    let d = dir_teste("ciclo");
    let store = ManifestStore::open(d.join("manifests")).unwrap();
    let mut m = DatabaseManifest {
        storage_namespace_id: NAMESPACE,
        ..Default::default()
    };

    // 1. Três segmentos selados e catalogados.
    let mut raws = Vec::new();
    for i in 0..3u64 {
        raws.push(sela_e_cataloga(&d, &mut m, i, 1 + i * 1_000, 1_000));
    }
    store.commit(&mut m).unwrap();
    assert_eq!(m.packing_queue(), vec![0, 1, 2]);
    assert_eq!(m.cumulative_watermark, 3_000);

    // 2. Packar cada um, fechando a transacção de §88 até ao commit do HRKM.
    for (i, raw) in raws.iter().enumerate() {
        let target = d.join(format!("{i:020}.g1.hrkl"));
        pack_and_commit(
            &store,
            &mut m,
            raw,
            &target,
            PackOptions::default(),
            0,
            1,
            hlc(100),
            &hasher,
        )
        .unwrap();
    }
    assert!(m.packing_queue().is_empty(), "§144: nada por packar");
    assert_eq!(m.sidecar_queue(), vec![0, 1, 2], "§145: tudo por indexar");

    // A verdade lógica não mudou; as representações sim.
    for i in 0..3u64 {
        let s = m.segment(i).unwrap();
        assert_eq!(s.generations.len(), 2);
        assert_eq!(s.active_generation, 1);
        assert_eq!(s.generation(0).unwrap().state, GenerationState::Superseded);
        assert_eq!(s.generation(1).unwrap().state, GenerationState::Active);
        let packed = open_packed(Path::new(&s.generation(1).unwrap().location), 1 << 26).unwrap();
        assert_eq!(packed.logical_root(), s.logical_root);
    }

    // 3. Recarregar do disco: o catálogo sobreviveu.
    let recarregado = store.load().unwrap().unwrap();
    assert_eq!(recarregado.manifest.segments_v2, m.segments_v2);
    let boot = boot_report(&recarregado);
    assert_eq!(boot.records, 3_000);
    assert_eq!(boot.committed_lsn, 3_000);
    assert!(boot.segments_without_authority.is_empty());
    assert!(!boot.recovered_by_scan);

    // 4. GC: dentro do grace, nada. Passado o grace, as RAW.
    let pins = PinRegistry::new();
    let cedo = GcOptions {
        now_hlc: hlc(200),
        ..GcOptions::default()
    };
    assert!(plan_gc(&m, &pins, &cedo).generations.is_empty());

    let tarde = GcOptions {
        now_hlc: hlc(100 + 86_400 + 1),
        ..GcOptions::default()
    };
    let plano = plan_gc(&m, &pins, &tarde);
    assert_eq!(plano.generations.len(), 3);
    assert!(plano
        .generations
        .iter()
        .all(|c| c.layout == PhysicalLayout::Raw));
    assert_gc_invariant(&m, &plano).unwrap();

    // 5. Aplicar: ficheiros primeiro, manifesto depois.
    for c in &plano.generations {
        std::fs::remove_file(&c.location).unwrap();
    }
    apply_gc(&mut m, &plano).unwrap();
    store.commit(&mut m).unwrap();

    for i in 0..3u64 {
        let s = m.segment(i).unwrap();
        assert_eq!(s.generations.len(), 1);
        assert_eq!(s.generations[0].layout, PhysicalLayout::Packed);
        // E o segmento continua legível — que é a única coisa que importa.
        let packed = open_packed(Path::new(&s.generations[0].location), 1 << 26).unwrap();
        assert_eq!(packed.footer.record_count, 1_000);
    }
    // Nada ficou por packar nem ressuscitou na fila.
    assert!(m.packing_queue().is_empty());
}

// ---------------------------------------------------------------------------
// Crash injection (§162)
// ---------------------------------------------------------------------------

#[test]
fn crash_em_qualquer_etapa_nunca_perde_registos() {
    // §162 lista as etapas críticas. Para cada uma simula-se a morte do
    // processo imediatamente a seguir, e verifica-se que os 1000 registos
    // committed continuam recuperáveis.
    let etapas = [
        "apos_seal",
        "apos_packed_tmp",
        "apos_publish",
        "apos_receipt",
        "apos_manifest_commit",
    ];

    for etapa in etapas {
        let d = dir_teste(&format!("crash-{etapa}"));
        let store = ManifestStore::open(d.join("manifests")).unwrap();
        let mut m = DatabaseManifest {
            storage_namespace_id: NAMESPACE,
            ..Default::default()
        };

        let raw = sela_e_cataloga(&d, &mut m, 7, 1, 1_000);
        let root = m.segment(7).unwrap().logical_root;
        store.commit(&mut m).unwrap();
        if etapa == "apos_seal" {
            verifica_recuperavel(&store, 7, 1_000, root);
            continue;
        }

        // Um `.tmp` a meio, como um packing interrompido deixaria.
        let target = d.join("packed.g1.hrkl");
        let tmp = PathBuf::from(format!("{}.tmp", target.to_string_lossy()));
        std::fs::write(&tmp, b"packing interrompido").unwrap();
        if etapa == "apos_packed_tmp" {
            verifica_recuperavel(&store, 7, 1_000, root);
            // §89: o órfão não é referenciado por ninguém.
            let l = store.load().unwrap().unwrap();
            assert!(l
                .manifest
                .segment(7)
                .unwrap()
                .generations
                .iter()
                .all(|g| g.location != tmp.to_string_lossy()));
            continue;
        }
        std::fs::remove_file(&tmp).unwrap();

        let outcome = pack_segment(&raw, &target, PackOptions::default(), 0, 1, &hasher).unwrap();
        if etapa == "apos_publish" {
            // O ficheiro PACKED existe, o manifesto ainda não o conhece: é
            // desperdício, não perda. O RAW continua a ser a autoridade.
            let l = store.load().unwrap().unwrap();
            assert_eq!(l.manifest.segment(7).unwrap().generations.len(), 1);
            assert_eq!(
                l.manifest.segment(7).unwrap().active().unwrap().layout,
                PhysicalLayout::Raw
            );
            verifica_recuperavel(&store, 7, 1_000, root);
            continue;
        }

        record_pack(
            &mut m,
            &outcome.receipt,
            &target.to_string_lossy(),
            hlc(100),
        )
        .unwrap();
        if etapa == "apos_receipt" {
            // O recibo existe em memória mas o manifesto committed é o antigo.
            let l = store.load().unwrap().unwrap();
            assert_eq!(l.manifest.segment(7).unwrap().generations.len(), 1);
            verifica_recuperavel(&store, 7, 1_000, root);
            continue;
        }

        store.commit(&mut m).unwrap();
        // Agora sim: a geração PACKED é a activa, e o RAW continua lá.
        let l = store.load().unwrap().unwrap();
        let s = l.manifest.segment(7).unwrap();
        assert_eq!(s.generations.len(), 2);
        assert_eq!(s.active().unwrap().layout, PhysicalLayout::Packed);
        verifica_recuperavel(&store, 7, 1_000, root);
    }
}

/// Confirma que o segmento é recuperável a partir do que está committed: o
/// manifesto nomeia uma geração activa, o ficheiro existe e a raiz bate.
fn verifica_recuperavel(store: &ManifestStore, segment_id: u64, esperados: u64, root: [u8; 32]) {
    let l = store.load().unwrap().unwrap();
    let s = l.manifest.segment(segment_id).unwrap();
    assert_eq!(s.logical_root, root, "a identidade lógica mudou");
    assert_eq!(s.record_count, esperados);
    let g = s.active().unwrap();
    let path = Path::new(&g.location);
    assert!(
        path.exists(),
        "a geração activa aponta para um ficheiro que não existe"
    );
    match g.layout {
        PhysicalLayout::Raw => {
            let scan = scan_raw_segment(path).unwrap();
            assert_eq!(scan.records.len() as u64, esperados);
            assert_eq!(scan.footer.unwrap().logical_root, root);
        }
        PhysicalLayout::Packed => {
            let r = open_packed(path, 1 << 26).unwrap();
            assert_eq!(r.footer.record_count, esperados);
            assert_eq!(r.logical_root(), root);
        }
    }
}

// ---------------------------------------------------------------------------
// §91 sob sequências arbitrárias
// ---------------------------------------------------------------------------

#[test]
fn nenhuma_sequencia_de_operacoes_deixa_um_segmento_sem_autoridade() {
    // Um pequeno PRNG determinístico conduz uma sequência de packings,
    // quarentenas, holds e GCs. Em nenhum ponto pode existir um segmento
    // catalogado sem geração capaz de o reconstruir.
    let mut estado: u64 = 0x2545_F491_4F6C_DD1D;
    let mut proximo = move || {
        estado ^= estado << 13;
        estado ^= estado >> 7;
        estado ^= estado << 17;
        estado
    };

    let d = dir_teste("sequencias");
    let store = ManifestStore::open(d.join("manifests")).unwrap();
    let mut m = DatabaseManifest {
        storage_namespace_id: NAMESPACE,
        ..Default::default()
    };
    let pins = PinRegistry::new();

    let mut caminhos = Vec::new();
    for i in 0..6u64 {
        caminhos.push(sela_e_cataloga(&d, &mut m, i, 1 + i * 200, 200));
    }
    store.commit(&mut m).unwrap();

    let mut relogio = 100u64;
    for passo in 0..60 {
        relogio += 1 + proximo() % 50_000;
        let alvo = proximo() % 6;
        match proximo() % 5 {
            0 => {
                // Packar, se ainda não estiver packado.
                if !m.segment(alvo).unwrap().has_packed() {
                    let target = d.join(format!("{alvo:020}.g1.hrkl"));
                    if !target.exists() {
                        pack_and_commit(
                            &store,
                            &mut m,
                            &caminhos[alvo as usize],
                            &target,
                            PackOptions::default(),
                            0,
                            1,
                            hlc(relogio),
                            &hasher,
                        )
                        .unwrap();
                    }
                }
            }
            1 => {
                // Quarentena da geração activa, se houver alternativa.
                let s = m.segment(alvo).unwrap();
                let activa = s.active_generation;
                let alternativas = s
                    .canonical_authorities()
                    .filter(|g| g.generation != activa)
                    .count();
                if alternativas > 0 {
                    quarantine_generation(&mut m, alvo, activa, hlc(relogio)).unwrap();
                }
            }
            2 => {
                let hold = proximo() % 2 == 0;
                m.segment_mut(alvo).unwrap().retention.legal_hold = hold;
            }
            3 => {
                let _guard = pins.pin(alvo, (proximo() % 2) as u32);
                let plano = plan_gc(
                    &m,
                    &pins,
                    &GcOptions {
                        now_hlc: hlc(relogio),
                        ..Default::default()
                    },
                );
                assert_gc_invariant(&m, &plano).unwrap();
            }
            _ => {
                let plano = plan_gc(
                    &m,
                    &pins,
                    &GcOptions {
                        now_hlc: hlc(relogio),
                        ..Default::default()
                    },
                );
                assert_gc_invariant(&m, &plano)
                    .unwrap_or_else(|e| panic!("passo {passo}: plano inválido: {e}"));
                for c in &plano.generations {
                    let _ = std::fs::remove_file(&c.location);
                }
                apply_gc(&mut m, &plano).unwrap();
                store.commit(&mut m).unwrap();
            }
        }

        // O invariante, verificado a cada passo e não só no fim.
        for s in &m.segments_v2 {
            assert!(
                s.canonical_authorities().next().is_some(),
                "passo {passo}: segmento {} ficou sem autoridade canónica",
                s.segment_id
            );
            let g = s.active().unwrap_or_else(|| {
                panic!(
                    "passo {passo}: segmento {} aponta para uma geração inexistente",
                    s.segment_id
                )
            });
            assert!(
                Path::new(&g.location).exists(),
                "passo {passo}: segmento {} aponta para {} que não existe",
                s.segment_id,
                g.location
            );
        }
    }

    // No fim, tudo continua legível a partir do que está committed.
    let l = store.load().unwrap().unwrap();
    for s in &l.manifest.segments_v2 {
        verifica_recuperavel(&store, s.segment_id, s.record_count, s.logical_root);
    }
}

// ---------------------------------------------------------------------------
// §159 — arrancar sem varrer segmentos
// ---------------------------------------------------------------------------

#[test]
fn boot_com_hrkm_nao_abre_nenhum_segmento() {
    let d = dir_teste("boot");
    let store = ManifestStore::open(d.join("manifests")).unwrap();
    let mut m = DatabaseManifest {
        storage_namespace_id: NAMESPACE,
        ..Default::default()
    };
    for i in 0..8u64 {
        sela_e_cataloga(&d, &mut m, i, 1 + i * 500, 500);
    }
    store.commit(&mut m).unwrap();

    // Tornar os segmentos ilegíveis: se o boot os abrisse, falharia.
    for i in 0..8u64 {
        let p = d.join(format!("{i:020}.hrkl"));
        let mut bytes = std::fs::read(&p).unwrap();
        for b in bytes.iter_mut().take(64) {
            *b ^= 0xff;
        }
        std::fs::write(&p, &bytes).unwrap();
    }

    let l = store.load().unwrap().unwrap();
    let boot = boot_report(&l);
    assert_eq!(boot.segments, 8);
    assert_eq!(boot.records, 4_000);
    assert_eq!(boot.committed_lsn, 4_000);
    assert_eq!(boot.packing_queue.len(), 8);
    assert!(boot.canonical_bytes > 0);
}

// ---------------------------------------------------------------------------
// §90 — retenção de manifestos
// ---------------------------------------------------------------------------

#[test]
fn manifestos_antigos_sao_podados_sem_perder_o_corrente() {
    let d = dir_teste("retencao");
    let store = ManifestStore::open(&d).unwrap();
    let mut m = DatabaseManifest {
        storage_namespace_id: NAMESPACE,
        ..Default::default()
    };
    for _ in 0..10 {
        store.commit(&mut m).unwrap();
    }
    assert_eq!(store.generations().unwrap().len(), 10);
    store.prune_old_manifests(3).unwrap();
    assert_eq!(store.generations().unwrap(), vec![8, 9, 10]);
    let l = store.load().unwrap().unwrap();
    assert_eq!(l.generation, 10);
    assert!(!l.recovered_by_scan);
}

// ---------------------------------------------------------------------------
// §94 — LegalHold
// ---------------------------------------------------------------------------

#[test]
fn legal_hold_impede_o_gc_ate_ser_levantado() {
    let d = dir_teste("legalhold");
    let store = ManifestStore::open(d.join("manifests")).unwrap();
    let mut m = DatabaseManifest {
        storage_namespace_id: NAMESPACE,
        ..Default::default()
    };
    let raw = sela_e_cataloga(&d, &mut m, 1, 1, 300);
    store.commit(&mut m).unwrap();
    let target = d.join("um.g1.hrkl");
    pack_and_commit(
        &store,
        &mut m,
        &raw,
        &target,
        PackOptions::default(),
        0,
        1,
        hlc(10),
        &hasher,
    )
    .unwrap();

    m.segment_mut(1).unwrap().retention.legal_hold = true;
    let tarde = GcOptions {
        now_hlc: hlc(10_000_000),
        ..Default::default()
    };
    let plano = plan_gc(&m, &PinRegistry::new(), &tarde);
    assert!(plano.generations.is_empty());
    assert_eq!(
        plano
            .blocked
            .iter()
            .find(|b| b.generation == 0)
            .unwrap()
            .reason,
        GcBlockReason::LegalHold
    );
    assert!(raw.exists());

    m.segment_mut(1).unwrap().retention.legal_hold = false;
    let plano = plan_gc(&m, &PinRegistry::new(), &tarde);
    assert_eq!(plano.generations.len(), 1);
}
