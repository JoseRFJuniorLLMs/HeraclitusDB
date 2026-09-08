use heraclitus_core::{Episode, EventKind, FsyncPolicy};
use heraclitus_log::Log;
use heraclitus_query::{
    backend::{complete_query_rows, LogBackend, QueryBackend, QUERY_SCAN_CAP},
    execute,
};
use std::sync::Arc;

#[test]
fn label_lookup_includes_all_case_variants_and_recall_zero_is_empty() {
    let dir = tempfile::tempdir().unwrap();
    let log = Arc::new(Log::open(dir.path(), 1 << 20, FsyncPolicy::Always).unwrap());
    for kind in ["Alpha", "alpha", "ALPHA"] {
        log.append(Episode::new(
            "a",
            EventKind::Custom(kind.into()),
            b"searchable".to_vec(),
        ))
        .unwrap();
    }
    let backend = LogBackend::new(log);
    for label in ["Alpha", "alpha", "ALPHA"] {
        assert_eq!(
            execute(&format!("MATCH (n:{label}) RETURN n"), &backend)
                .unwrap()
                .as_array()
                .unwrap()
                .len(),
            3
        );
    }
    assert!(backend.recall("searchable", 0, None).unwrap().is_empty());
}

#[test]
fn materialization_limit_never_silently_truncates() {
    assert_eq!(
        complete_query_rows(vec![(); QUERY_SCAN_CAP]).unwrap().len(),
        QUERY_SCAN_CAP
    );
    assert!(complete_query_rows(vec![(); QUERY_SCAN_CAP + 1])
        .unwrap_err()
        .to_string()
        .contains("no partial result"));
}

#[test]
fn envelope_timestamp_is_not_shadowed_by_an_attribute_index() {
    let dir = tempfile::tempdir().unwrap();
    let log = Arc::new(Log::open(dir.path(), 1 << 20, FsyncPolicy::Always).unwrap());
    let mut episode = Episode::new("a", EventKind::Observation, vec![]);
    episode.attrs.insert("ts_hlc".into(), "42".into());
    let lsn = log.append(episode).unwrap();
    let native = log.read(lsn).unwrap().unwrap().1.ts_hlc;
    let backend = LogBackend::new(log);
    assert_eq!(
        execute(
            &format!("MATCH (n) WHERE n.ts_hlc = {native} RETURN n"),
            &backend
        )
        .unwrap()
        .as_array()
        .unwrap()
        .len(),
        1
    );
}
