//! SPEC-011/024 wiring — DatabaseManifest e SegmentCatalog derivados do Log real.

use heraclitus_core::contracts::SegmentCatalog;
use heraclitus_core::runtime::SegmentState;
use heraclitus_core::{Episode, EventKind, FsyncPolicy};
use heraclitus_log::Log;

fn ep(i: usize) -> Episode {
    Episode::new(
        "a",
        EventKind::Observation,
        format!("e{i:04}-xxxxxxxxxxxxxxxxxxxxxxxxxxxx").into_bytes(),
    )
}

#[test]
fn manifest_reflects_segments_and_watermark() {
    let dir = tempfile::tempdir().unwrap();
    // Segmentos pequenos → vários selados + um ativo.
    let log = Log::open(dir.path(), 2048, FsyncPolicy::Always).unwrap();
    for i in 0..120 {
        log.append(ep(i)).unwrap();
    }
    let sealed = log.sealed_segments();
    assert!(sealed.len() >= 2, "precisa de segmentos selados");

    let m = log.manifest();
    assert_eq!(m.format_identifier, *b"HRKL");
    assert_eq!(m.cumulative_watermark, log.head());
    // Selados vêm Frozen com Merkle root; o ativo (se tem eventos) vem Active.
    let frozen: Vec<_> = m.segments.iter().filter(|s| s.state == SegmentState::Frozen).collect();
    assert_eq!(frozen.len(), sealed.len());
    assert!(frozen.iter().all(|s| s.payload_hash != [0; 32]), "Merkle nos selados");
    // Cobertura contígua: soma de event_count = head.
    let total: u64 = m.segments.iter().map(|s| s.event_count).sum();
    assert_eq!(total, log.head());

    // SPEC-024: o contrato SegmentCatalog resolve visibilidade por snapshot.
    let first_seg_end = frozen[0].last_lsn;
    let visible = SegmentCatalog::resolve_visible(&log, first_seg_end);
    assert!(!visible.is_empty());
    let all = SegmentCatalog::resolve_visible(&log, u64::MAX);
    assert_eq!(all.len(), m.segments.len(), "snapshot no infinito vê tudo");
    assert!(visible.len() <= all.len());
}
