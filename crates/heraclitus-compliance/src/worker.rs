//! The asynchronous watermark-timestamping daemon.
//!
//! Never on the append path: a background task wakes every `interval`, checks
//! whether the sealed watermark advanced by at least `min_lsn_step` since the
//! last anchor, and — if so — anchors the state (commitment → TSA → receipt).
//! The (possibly blocking) network call to a real ACT runs on the blocking
//! pool, so it can never stall the runtime or the writers.

use crate::{anchor, commit::current_watermark, LegalReceipt, TsaClient};
use crate::{CompError, WorkerConfig, WorkerState};
use heraclitus_log::Log;
use std::future::Future;
use std::pin::pin;
use std::sync::Arc;

/// One deterministic tick: anchor iff the watermark advanced enough. Returns the
/// receipt when an anchor was made, `None` when nothing was due. Pure and
/// synchronous so it can be unit-tested without a runtime.
pub fn tick(
    log: &Log,
    tsa: &dyn TsaClient,
    cfg: &WorkerConfig,
    state: &mut WorkerState,
) -> Result<Option<LegalReceipt>, CompError> {
    let wm = current_watermark(log);
    // Nothing sealed yet, or not enough new sealed events since last anchor.
    if wm == 0 || wm <= state.last_lsn || wm < state.last_lsn.saturating_add(cfg.min_lsn_step) {
        return Ok(None);
    }
    let receipt = anchor(log, tsa, &cfg.receipts_dir, Some(wm))?;
    state.last_lsn = wm;
    Ok(Some(receipt))
}

/// Run the daemon until `shutdown` resolves. Spawn it with `tokio::spawn`.
pub async fn run_worker(
    log: Arc<Log>,
    tsa: Arc<dyn TsaClient + Send + Sync>,
    cfg: WorkerConfig,
    shutdown: impl Future<Output = ()> + Send,
) {
    let mut state = WorkerState::default();
    let mut shutdown = pin!(shutdown);
    tracing::info!(
        interval_s = cfg.interval.as_secs(),
        min_lsn_step = cfg.min_lsn_step,
        policy = tsa.policy_name(),
        "compliance: worker de carimbo de tempo iniciado"
    );
    loop {
        tokio::select! {
            _ = tokio::time::sleep(cfg.interval) => {}
            _ = &mut shutdown => {
                tracing::info!("compliance: worker encerrado");
                break;
            }
        }
        // The anchor may do blocking I/O (real ACT) — keep it off the runtime.
        let log2 = log.clone();
        let tsa2 = tsa.clone();
        let cfg2 = cfg.clone();
        let mut st = state;
        let joined = tokio::task::spawn_blocking(move || {
            let r = tick(&log2, tsa2.as_ref(), &cfg2, &mut st);
            (r, st)
        })
        .await;
        match joined {
            Ok((Ok(Some(r)), st)) => {
                state = st;
                tracing::info!(
                    lsn = r.lsn,
                    segments = r.segments,
                    policy = %r.policy,
                    "compliance: estado ancorado e carimbado"
                );
            }
            Ok((Ok(None), st)) => state = st,
            Ok((Err(e), _)) => tracing::warn!("compliance: falha ao ancorar: {e}"),
            Err(e) => tracing::warn!("compliance: tarefa de anchor falhou: {e}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{load_manifest, verify_receipt, LocalTsa};
    use heraclitus_core::{Episode, EventKind, FsyncPolicy};
    use std::time::Duration;

    fn append_n(log: &Log, n: usize) {
        for i in 0..n {
            log.append(Episode::new(
                "auditor",
                EventKind::Observation,
                format!("ev #{i}").into_bytes(),
            ))
            .unwrap();
        }
    }

    #[test]
    fn tick_anchors_only_when_watermark_advances() {
        let dir = tempfile::tempdir().unwrap();
        let receipts = tempfile::tempdir().unwrap();
        let log = Log::open(dir.path(), 256, FsyncPolicy::Always).unwrap();
        let tsa = LocalTsa::generate("ACT-dev");
        let cfg = WorkerConfig {
            interval: Duration::from_millis(10),
            min_lsn_step: 1,
            receipts_dir: receipts.path().to_path_buf(),
        };
        let mut state = WorkerState::default();

        // empty log: nothing to anchor
        assert!(tick(&log, &tsa, &cfg, &mut state).unwrap().is_none());

        append_n(&log, 200);
        let first = tick(&log, &tsa, &cfg, &mut state).unwrap();
        assert!(first.is_some(), "deveria ancorar após selar segmentos");

        // no new sealed events → no second anchor
        assert!(tick(&log, &tsa, &cfg, &mut state).unwrap().is_none());

        // more events → another anchor at the higher watermark
        append_n(&log, 200);
        let second = tick(&log, &tsa, &cfg, &mut state).unwrap();
        assert!(second.is_some());
        assert!(second.unwrap().lsn > first.unwrap().lsn);

        // every persisted receipt re-verifies against the live log
        for r in load_manifest(receipts.path()).unwrap() {
            verify_receipt(&log, receipts.path(), &r).unwrap();
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn daemon_fires_and_shuts_down() {
        let dir = tempfile::tempdir().unwrap();
        let receipts = tempfile::tempdir().unwrap();
        let log = Arc::new(Log::open(dir.path(), 256, FsyncPolicy::Always).unwrap());
        append_n(&log, 200);

        let tsa: Arc<dyn TsaClient + Send + Sync> = Arc::new(LocalTsa::generate("ACT-dev"));
        let cfg = WorkerConfig {
            interval: Duration::from_millis(20),
            min_lsn_step: 1,
            receipts_dir: receipts.path().to_path_buf(),
        };
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        let handle = tokio::spawn(run_worker(log.clone(), tsa, cfg, async move {
            let _ = rx.await;
        }));

        // give it a couple of ticks, then stop
        tokio::time::sleep(Duration::from_millis(120)).await;
        let _ = tx.send(());
        handle.await.unwrap();

        assert!(
            !load_manifest(receipts.path()).unwrap().is_empty(),
            "o daemon devia ter ancorado ao menos uma vez"
        );
    }
}
