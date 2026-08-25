use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use heraclitus_core::{Episode, EventKind, FsyncPolicy, StorageFormat};
use heraclitus_log::v6::IntegrityLevel;
use heraclitus_log::{AnyLog, EpisodeLog};

fn event(payload: &str) -> Episode {
    Episode::new(
        "store-facade-test",
        EventKind::Observation,
        payload.as_bytes().to_vec(),
    )
}

fn assert_data_plane_contract(format: StorageFormat) {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("log");
    let log = AnyLog::open(format, &root, 1 << 20, FsyncPolicy::Always).unwrap();

    assert_eq!(log.format(), format);
    assert_eq!(log.head(), 0);
    let original = event(format.as_str());
    let original_id = original.id;
    let (lsn, stamped) = log.append_stamped(original).unwrap();
    assert_eq!(lsn, 0);
    assert_ne!(stamped.ts_hlc, 0);
    assert_eq!(stamped.id, original_id);
    log.flush().unwrap();

    let (_, persisted) = log.read(lsn).unwrap().unwrap();
    assert_eq!(persisted.id, stamped.id);
    assert_eq!(persisted.ts_hlc, stamped.ts_hlc);
    assert_eq!(persisted.content, stamped.content);
    assert_eq!(log.scan(0, log.head()).unwrap().len(), 1);
    assert_eq!(log.scan_capped(0, log.head(), 0).unwrap().len(), 0);
    // O legado devolve uma projecção do catálogo vivo; o v6 devolve o HRKM
    // persistido, que deliberadamente só publica a cauda ao selá-la.
    assert!(log.manifest().cumulative_watermark <= log.head());
    assert_eq!(log.dir(), root.as_path());

    let object: &dyn EpisodeLog = &log;
    assert_eq!(object.head(), 1);
    assert_eq!(
        object.as_legacy().is_some(),
        format == StorageFormat::Legacy
    );
    assert_eq!(
        object.legacy_arc().is_some(),
        format == StorageFormat::Legacy
    );

    // Contrato blanket: helpers genéricos podem receber `Arc<AnyLog>` sem
    // perder a capability do backend interior.
    let shared = Arc::new(log);
    assert_eq!(EpisodeLog::head(&shared), 1);
    assert_eq!(
        EpisodeLog::legacy_arc(&shared).is_some(),
        format == StorageFormat::Legacy
    );
}

#[test]
fn legacy_and_v6_obey_the_same_data_plane_contract() {
    assert_data_plane_contract(StorageFormat::Legacy);
    assert_data_plane_contract(StorageFormat::V6);
}

fn file_snapshot(root: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    fn visit(base: &Path, dir: &Path, out: &mut BTreeMap<PathBuf, Vec<u8>>) {
        for entry in std::fs::read_dir(dir).unwrap() {
            let entry = entry.unwrap();
            let path = entry.path();
            if entry.file_type().unwrap().is_dir() {
                visit(base, &path, out);
            } else {
                out.insert(
                    path.strip_prefix(base).unwrap().to_path_buf(),
                    std::fs::read(path).unwrap(),
                );
            }
        }
    }

    let mut out = BTreeMap::new();
    visit(root, root, &mut out);
    out
}

#[test]
fn selecting_v6_on_a_legacy_root_is_read_only_and_fails_closed() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("log");
    let legacy = AnyLog::open(StorageFormat::Legacy, &root, 1 << 20, FsyncPolicy::Always).unwrap();
    legacy.append(event("legacy")).unwrap();
    legacy.flush().unwrap();
    drop(legacy);

    let before = file_snapshot(&root);
    assert!(AnyLog::open(StorageFormat::V6, &root, 1 << 20, FsyncPolicy::Always).is_err());
    assert_eq!(file_snapshot(&root), before);
    assert!(!root.join("segments").exists());
    assert!(!root.join("manifests").exists());
}

#[test]
fn selecting_legacy_on_a_v6_root_is_read_only_and_fails_closed() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("log");
    let v6 = AnyLog::open(StorageFormat::V6, &root, 1 << 20, FsyncPolicy::Always).unwrap();
    v6.append(event("v6")).unwrap();
    v6.flush().unwrap();
    drop(v6);

    let before = file_snapshot(&root);
    assert!(AnyLog::open(StorageFormat::Legacy, &root, 1 << 20, FsyncPolicy::Always,).is_err());
    assert_eq!(file_snapshot(&root), before);
    assert!(!root.join("00000000000000000000.hrkl").exists());
}

#[test]
fn v6_point_verification_only_touches_the_requested_segment() {
    let temp = tempfile::tempdir().unwrap();
    let log = AnyLog::open(
        StorageFormat::V6,
        temp.path().join("log"),
        1 << 20,
        FsyncPolicy::Always,
    )
    .unwrap();
    log.append(event("verify")).unwrap();
    let v6 = log.v6_arc().unwrap();
    v6.seal_active().unwrap();

    assert_eq!(log.sealed_segment_ids(), vec![0]);
    assert_eq!(log.sealed_segment_count(), 1);
    let reports = v6
        .verify_segment(0, IntegrityLevel::Logical)
        .unwrap()
        .unwrap();
    assert_eq!(reports.len(), 1);
    assert!(reports.iter().all(|report| report.is_ok()));
    assert!(v6
        .verify_segment(999, IntegrityLevel::Logical)
        .unwrap()
        .is_none());
}
