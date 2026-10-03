//! boot.md P1-C (conferido em 2026-10-02): o arranque varria e decifrava o
//! log duas vezes — uma para as views, outra só para o índice de atributos.
//! `catch_up_com` alimenta um índice extra na MESMA passagem; este teste fixa
//! que o extra recebe exactamente o que o seu laço antigo recebia (todos os
//! eventos a partir do seu cursor, excepto frames H-VM) e que as views
//! registadas continuam a receber o mesmo de sempre.

use heraclitus_core::{Episode, EventKind, FsyncPolicy, Lsn};
use heraclitus_log::Log;
use heraclitus_views::{View, ViewRegistry};
use std::sync::{Arc, Mutex};

struct Contador {
    nome: &'static str,
    vistos: Arc<Mutex<Vec<Lsn>>>,
    wm: Lsn,
}

impl View for Contador {
    fn name(&self) -> &str {
        self.nome
    }
    fn apply(&mut self, lsn: Lsn, _e: &Episode) {
        self.vistos.lock().unwrap().push(lsn);
        self.wm = self.wm.max(lsn);
    }
    fn watermark(&self) -> Lsn {
        self.wm
    }
    fn reset(&mut self) {
        self.vistos.lock().unwrap().clear();
        self.wm = 0;
    }
}

#[test]
fn o_extra_recebe_a_sua_cauda_na_mesma_passagem_das_views() {
    let dir = tempfile::tempdir().unwrap();
    let log = Log::open(dir.path().join("log"), 1 << 20, FsyncPolicy::Always).unwrap();
    for i in 0..6u8 {
        log.append(Episode::new("a", EventKind::Observation, vec![i]))
            .unwrap();
    }
    // LSN 6: frame H-VM — fora das views e do índice extra.
    log.append(Episode::new(
        "hvm",
        EventKind::Custom(heraclitus_log::vm_bridge::HVM_KIND.into()),
        vec![0],
    ))
    .unwrap();
    // LSN 7: evento normal depois do frame.
    log.append(Episode::new("a", EventKind::Observation, vec![7]))
        .unwrap();
    assert_eq!(log.head(), 8);

    let das_views = Arc::new(Mutex::new(Vec::new()));
    let mut registry = ViewRegistry::open(dir.path()).unwrap();
    registry.register(Box::new(Contador {
        nome: "views",
        vistos: das_views.clone(),
        wm: 0,
    }));
    let do_extra = Arc::new(Mutex::new(Vec::new()));
    let mut extra = Contador {
        nome: "extra",
        vistos: do_extra.clone(),
        wm: 0,
    };
    registry
        .catch_up_com(&log, Some((&mut extra, 3)))
        .unwrap();

    assert_eq!(*das_views.lock().unwrap(), vec![0, 1, 2, 3, 4, 5, 7]);
    assert_eq!(
        *do_extra.lock().unwrap(),
        vec![3, 4, 5, 7],
        "o extra começa no seu cursor e salta só o frame H-VM"
    );
}
