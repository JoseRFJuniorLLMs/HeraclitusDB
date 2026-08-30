//! Deterministic replay primitives shared by live workers and tests.

use crate::cursor::{CursorStore, SentinelCursor};
use crate::error::SentinelError;
use heraclitus_core::{Episode, Lsn};
use heraclitus_log::EpisodeLog;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ReplayReport {
    pub first_lsn: Option<Lsn>,
    pub last_lsn: Option<Lsn>,
    pub processed: usize,
}

/// Process a bounded exclusive range.  The cursor is committed only after the
/// callback returns successfully, so a crash before that point causes a safe
/// replay rather than silent evidence loss.
pub fn replay<L, F>(
    log: &L,
    store: &CursorStore,
    cursor: &mut SentinelCursor,
    to_exclusive: Lsn,
    batch: usize,
    mut process: F,
) -> Result<ReplayReport, SentinelError>
where
    L: EpisodeLog + ?Sized,
    F: FnMut(Lsn, &Episode) -> Result<(), SentinelError>,
{
    if batch == 0 {
        return Err(SentinelError::Config(
            "replay batch must be greater than zero".into(),
        ));
    }
    let rows = log.scan_capped(cursor.next_lsn, to_exclusive, batch)?;
    let mut report = ReplayReport::default();
    for (lsn, episode) in rows {
        if report.first_lsn.is_none() {
            report.first_lsn = Some(lsn);
        }
        process(lsn, &episode)?;
        cursor.next_lsn = lsn.saturating_add(1);
        store.commit(*cursor)?;
        report.last_lsn = Some(lsn);
        report.processed += 1;
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use heraclitus_core::{Episode, EventKind, FsyncPolicy};
    use heraclitus_log::Log;

    #[test]
    fn replay_commits_only_after_callback() {
        let temp = tempfile::tempdir().unwrap();
        let log = Log::open(temp.path().join("log"), 1 << 20, FsyncPolicy::Always).unwrap();
        for n in 0..3 {
            log.append(Episode::new("a", EventKind::Observation, vec![n]))
                .unwrap();
        }
        let store = CursorStore::new(temp.path().join("cursor.json"));
        let mut cursor = SentinelCursor::new(1);
        let report = replay(&log, &store, &mut cursor, log.head(), 10, |_, _| Ok(())).unwrap();
        assert_eq!(report.processed, 3);
        assert_eq!(store.load(1).unwrap().next_lsn, 3);
    }
}
