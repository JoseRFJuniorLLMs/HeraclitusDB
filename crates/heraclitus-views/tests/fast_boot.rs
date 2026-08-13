//! Fast boot (C0.1, 2026-07-02): uma view com checkpoint+restore restaura o
//! estado do snapshot e o catch_up replaya SÓ a cauda `(watermark, head]` —
//! a lição operacional da carga massiva que tornou o boot impossível por
//! replay total do log.

use heraclitus_core::{Episode, EventKind, FsyncPolicy, HeraclitusError, Lsn};
use heraclitus_log::Log;
use heraclitus_views::{ckpt, View, ViewRegistry};
use std::path::Path;
use std::sync::{Arc, Mutex};

/// View determinística com snapshot: conta eventos e regista quantos `apply`
/// aconteceram NESTA sessão (para provar que o replay foi só a cauda).
struct SnapView {
    count: u64,
    wm: Lsn,
    applied_this_session: Arc<Mutex<u64>>,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct SnapState {
    count: u64,
    wm: Lsn,
}

impl View for SnapView {
    fn name(&self) -> &str {
        "snap"
    }
    fn apply(&mut self, lsn: Lsn, _e: &Episode) {
        self.count += 1;
        self.wm = lsn;
        *self.applied_this_session.lock().unwrap() += 1;
    }
    fn watermark(&self) -> Lsn {
        self.wm
    }
    fn checkpoint(&self, dir: &Path) -> Result<(), HeraclitusError> {
        ckpt::save(
            dir,
            "snap",
            &SnapState {
                count: self.count,
                wm: self.wm,
            },
        )
    }
    fn restore(&mut self, dir: &Path) -> Result<bool, HeraclitusError> {
        match ckpt::load::<SnapState>(dir, "snap")? {
            Some(s) => {
                self.count = s.count;
                self.wm = s.wm;
                Ok(true)
            }
            None => Ok(false),
        }
    }
    fn reset(&mut self) {
        self.count = 0;
        self.wm = 0;
    }
}

fn append_n(log: &Log, n: usize) {
    for i in 0..n {
        log.append(Episode::new(
            "a",
            EventKind::Observation,
            format!("e{i}").into_bytes(),
        ))
        .unwrap();
    }
}

#[test]
fn restore_replays_only_the_tail() {
    let dir = tempfile::tempdir().unwrap();
    let log = Log::open(dir.path().join("log"), 1 << 20, FsyncPolicy::Always).unwrap();
    append_n(&log, 100);

    // 1ª sessão: replay completo (não há checkpoint) + checkpoint no fim.
    let applied1 = Arc::new(Mutex::new(0u64));
    {
        let mut reg = ViewRegistry::open(dir.path()).unwrap();
        reg.register(Box::new(SnapView {
            count: 0,
            wm: 0,
            applied_this_session: applied1.clone(),
        }));
        reg.catch_up(&log).unwrap();
        reg.checkpoint().unwrap();
    }
    assert_eq!(*applied1.lock().unwrap(), 100, "1º boot: replay completo");

    // Crescem mais 10 eventos depois do checkpoint (a "cauda").
    append_n(&log, 10);

    // 2ª sessão: restaura o snapshot e replaya SÓ os 10 da cauda.
    let applied2 = Arc::new(Mutex::new(0u64));
    let mut reg2 = ViewRegistry::open(dir.path()).unwrap();
    reg2.register(Box::new(SnapView {
        count: 0,
        wm: 0,
        applied_this_session: applied2.clone(),
    }));
    reg2.catch_up(&log).unwrap();

    assert_eq!(
        *applied2.lock().unwrap(),
        10,
        "2º boot: só a cauda (watermark, head] é replayada"
    );
    let v = reg2.get("snap").unwrap();
    assert_eq!(v.watermark(), 109);
}
