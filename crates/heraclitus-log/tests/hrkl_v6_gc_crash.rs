//! SPEC-0050 §162 — boundary de crash do GC metadata-first.
//!
//! O HRKM tem de deixar de referenciar a geração superseded antes de o
//! ficheiro desaparecer. Se o processo cair nesse intervalo, o resultado
//! aceitável é apenas espaço desperdiçado: a PACKED activa continua legível e
//! o RAW restante é diagnosticado como órfão.

use heraclitus_core::{Episode, EventKind, FsyncPolicy, HeraclitusError};
use heraclitus_log::v6::{
    commit_gc, commit_gc_with_observer, doctor_storage, plan_gc, GcOptions, ManifestStore,
    PackingProfile, PackingStage, PhysicalLayout, PinRegistry, V6Log,
};

fn event(i: u64) -> Episode {
    Episode::new(
        "gc-crash-test",
        EventKind::Observation,
        format!("payload-{i}-{}", "x".repeat(256)).into_bytes(),
    )
}

fn prepare_packed(root: &std::path::Path) {
    let log = V6Log::open(root, 1 << 20, FsyncPolicy::Always).unwrap();
    for i in 0..32 {
        assert_eq!(log.append(event(i)).unwrap(), i);
    }
    log.seal_active().unwrap();
    let outcomes = log.pack_pending(PackingProfile::Balanced).unwrap();
    assert_eq!(outcomes.len(), 1);
}

#[test]
fn crash_after_gc_manifest_commit_leaves_only_a_safe_detectable_orphan() {
    let temp = tempfile::tempdir().unwrap();
    prepare_packed(temp.path());

    let store = ManifestStore::open(temp.path().join("manifests")).unwrap();
    let mut manifest = store.load().unwrap().unwrap().manifest;
    let segment = manifest.segment_mut(0).unwrap();
    segment.retention.gc_grace_seconds = 0;
    store.commit(&mut manifest).unwrap();

    let raw = manifest
        .segment(0)
        .unwrap()
        .generations
        .iter()
        .find(|generation| generation.layout == PhysicalLayout::Raw)
        .unwrap()
        .clone();
    let raw_path = temp.path().join(&raw.location);
    assert!(raw_path.is_file());

    let plan = plan_gc(
        &manifest,
        &PinRegistry::new(),
        &GcOptions {
            now_hlc: u64::MAX,
            ..GcOptions::default()
        },
    );
    assert_eq!(plan.generations.len(), 1);
    assert_eq!(plan.generations[0].generation, raw.generation);

    let error = commit_gc_with_observer(&store, &mut manifest, temp.path(), &plan, &mut |stage| {
        if stage == PackingStage::GcManifestCommitted {
            Err(HeraclitusError::StorageEngine(
                "injected crash after GC manifest commit".into(),
            ))
        } else {
            Ok(())
        }
    })
    .unwrap_err();
    assert!(error.to_string().contains("injected crash"));

    // O commit lógico sobreviveu: CURRENT já não referencia o RAW, embora
    // o unlink não tenha acontecido.
    let committed = store.load().unwrap().unwrap().manifest;
    let segment = committed.segment(0).unwrap();
    assert!(segment
        .generations
        .iter()
        .all(|generation| generation.generation != raw.generation));
    assert_eq!(segment.active().unwrap().layout, PhysicalLayout::Packed);
    assert!(raw_path.is_file(), "o crash foi injetado antes do unlink");

    let report = doctor_storage(temp.path()).unwrap();
    assert!(!report.has_critical(), "{}", report.render());
    let raw_canonical = std::fs::canonicalize(&raw_path).unwrap();
    assert!(report.findings.iter().any(|finding| {
        finding.code == "ORPHAN_GENERATION"
            && finding.path.as_deref() == Some(raw_canonical.as_path())
    }));

    // Reabrir é parte da garantia de crash safety: o órfão não pode
    // impedir que a autoridade PACKED committed sirva todo o histórico.
    let reopened = V6Log::open(temp.path(), 1 << 20, FsyncPolicy::Always).unwrap();
    for i in 0..32 {
        assert_eq!(
            reopened.read(i).unwrap().unwrap().1.content,
            event(i).content
        );
    }
    drop(reopened);

    // O retry é idempotente mesmo com o candidato já ausente do HRKM: apenas
    // conclui o unlink que o crash interrompeu.
    let mut committed = store.load().unwrap().unwrap().manifest;
    let execution = commit_gc(&store, &mut committed, temp.path(), &plan).unwrap();
    assert_eq!(execution.removed, vec![raw_canonical]);
    assert!(execution.orphaned.is_empty());
    assert!(!raw_path.exists());
    assert!(doctor_storage(temp.path()).unwrap().is_clean());
}

#[test]
fn unreferenced_raw_without_active_packed_authority_still_fails_boot() {
    let temp = tempfile::tempdir().unwrap();
    let log = V6Log::open(temp.path(), 1 << 20, FsyncPolicy::Always).unwrap();
    log.append(event(0)).unwrap();
    log.seal_active().unwrap();
    drop(log);

    let store = ManifestStore::open(temp.path().join("manifests")).unwrap();
    let mut manifest = store.load().unwrap().unwrap().manifest;
    manifest.segment_mut(0).unwrap().generations.clear();
    store.commit(&mut manifest).unwrap();

    let error = match V6Log::open(temp.path(), 1 << 20, FsyncPolicy::Always) {
        Ok(_) => panic!("boot não pode aceitar RAW órfão sem autoridade PACKED"),
        Err(error) => error,
    };
    assert!(error.to_string().contains("não é uma geração catalogada"));
}
