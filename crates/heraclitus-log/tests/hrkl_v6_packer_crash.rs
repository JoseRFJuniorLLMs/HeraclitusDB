//! SPEC-0050 §162 — processo termina exatamente em cada fronteira do packing.

use std::path::PathBuf;
use std::process::{Command, Stdio};

use heraclitus_core::{Episode, EventKind, FsyncPolicy};
use heraclitus_log::v6::{IntegrityLevel, PackingProfile, PackingStage, V6Log};

fn helper_bin() -> PathBuf {
    let mut path = std::env::current_exe().unwrap();
    path.pop(); // nome do teste
    path.pop(); // deps/
    path.push("examples");
    path.push(format!("crash_packer_v6{}", std::env::consts::EXE_SUFFIX));
    path
}

fn target_dir() -> PathBuf {
    let mut path = std::env::current_exe().unwrap();
    path.pop(); // nome do teste
    path.pop(); // deps/
    path.pop(); // debug/ | release/
    path
}

fn prepare(root: &std::path::Path) {
    let log = V6Log::open(root, 4_096, FsyncPolicy::Always).unwrap();
    for i in 0..32u64 {
        log.append(Episode::new(
            "crash-packer",
            EventKind::Observation,
            format!("committed-{i:04}-{}", "x".repeat(128)).into_bytes(),
        ))
        .unwrap();
    }
    log.seal_active().unwrap();
}

fn assert_history(log: &V6Log) {
    assert_eq!(log.head(), 32);
    for i in 0..32u64 {
        let (_, episode) = log.read(i).unwrap().expect("committed LSN");
        assert!(String::from_utf8_lossy(&episode.content).starts_with(&format!("committed-{i:04}")));
    }
}

#[test]
fn crash_real_em_todas_as_fronteiras_do_packing_nunca_perde_committed_record() {
    let status = Command::new(env!("CARGO"))
        .args([
            "build",
            "--offline",
            "--example",
            "crash_packer_v6",
            "-p",
            "heraclitus-log",
        ])
        .arg("--target-dir")
        .arg(target_dir())
        .status()
        .expect("build crash_packer_v6");
    assert!(status.success());

    let stages = [
        PackingStage::TempCreated,
        PackingStage::SourceStreamed,
        PackingStage::BlocksWritten,
        PackingStage::DirectoryWritten,
        PackingStage::FooterWritten,
        PackingStage::PackedSynced,
        PackingStage::LogicalVerified,
        PackingStage::Published,
        PackingStage::ParentSynced,
        PackingStage::ReceiptPersisted,
        PackingStage::ManifestCommitted,
    ];
    for stage in stages {
        let temp = tempfile::tempdir().unwrap();
        prepare(temp.path());
        let child = Command::new(helper_bin())
            .arg(temp.path())
            .arg(stage.as_str())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap();
        assert_eq!(child.code(), Some(86), "stage {stage:?} was not injected");

        // Primeiro boot: a história committed tem de estar inteira antes de
        // qualquer retry/cleanup adicional.
        let log = V6Log::open(temp.path(), 4_096, FsyncPolicy::Always).unwrap();
        assert_history(&log);
        log.verify_sealed(IntegrityLevel::Logical).unwrap();

        // Retry idempotente: pré-commit publica nova geração; pós-commit não
        // repacka. Nos dois casos a raiz e os LSNs permanecem iguais.
        log.pack_pending(PackingProfile::Balanced).unwrap();
        assert_history(&log);
        log.verify_sealed(IntegrityLevel::Logical).unwrap();
        drop(log);

        let reopened = V6Log::open(temp.path(), 4_096, FsyncPolicy::Always).unwrap();
        assert_history(&reopened);
        reopened.verify_sealed(IntegrityLevel::Logical).unwrap();
    }
}
