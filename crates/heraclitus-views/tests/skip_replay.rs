//! Regressão: arrancar com o replay SALTADO não pode deixar eventos órfãos.

use heraclitus_core::{Episode, EventKind, FsyncPolicy, HeraclitusError, Lsn};
use heraclitus_log::Log;
use heraclitus_views::{View, ViewRegistry};
use std::sync::{Arc, Mutex};

/// View que PERSISTE (como as reais), com o estado exposto ao teste. É
/// necessária para reproduzir o bug: um snapshot vazio-mas-presente faz
/// `restore()` devolver `true`, e o watermark antigo sobrevive — por isso a
/// verificação TEM de ser sobre o que a view indexou, não sobre o watermark
/// (é o watermark que mente).
struct PersistView {
    seen: Arc<Mutex<Vec<Lsn>>>,
    wm: Lsn,
}

impl View for PersistView {
    fn name(&self) -> &str {
        "persist"
    }
    fn apply(&mut self, lsn: Lsn, _e: &Episode) {
        self.seen.lock().unwrap().push(lsn);
        self.wm = self.wm.max(lsn);
    }
    fn watermark(&self) -> Lsn {
        self.wm
    }
    fn reset(&mut self) {
        self.seen.lock().unwrap().clear();
        self.wm = 0;
    }
    fn checkpoint(&self, dir: &std::path::Path) -> Result<(), HeraclitusError> {
        let seen = self.seen.lock().unwrap().clone();
        heraclitus_views::ckpt::save(dir, "persist", &(seen, self.wm))
    }
    fn restore(&mut self, dir: &std::path::Path) -> Result<bool, HeraclitusError> {
        match heraclitus_views::ckpt::load::<(Vec<Lsn>, Lsn)>(dir, "persist")? {
            Some((seen, wm)) => {
                *self.seen.lock().unwrap() = seen;
                self.wm = wm;
                Ok(true)
            }
            None => Ok(false),
        }
    }
}

fn view_with(state: &Arc<Mutex<Vec<Lsn>>>) -> Box<PersistView> {
    Box::new(PersistView { seen: state.clone(), wm: 0 })
}

/// PERDA DE DADOS SILENCIOSA (corrigida): arrancar com `HERACLITUS_SKIP_VIEW_REPLAY`
/// deixava as views VAZIAS mas com os watermarks altos carregados do disco. Um
/// checkpoint nesse estado (o periódico — 300 s por omissão — ou o de shutdown)
/// gravava snapshots VAZIOS sob esses watermarks. Como `restore()` devolve
/// `true` para um snapshot vazio-mas-presente, o arranque normal seguinte
/// mantinha o watermark e replayava só `(W, head]`: TUDO ≤ W ficava invisível
/// às views PARA SEMPRE (só recuperável com um `view rebuild` explícito).
///
/// Nota: verificar o watermark NÃO apanha o bug (ele fica "certo" nos dois
/// casos, e é essa a mentira); a asserção é sobre os eventos indexados.
#[test]
fn skip_replay_then_checkpoint_does_not_orphan_events() {
    let dir = tempfile::tempdir().unwrap();
    let log = Log::open(dir.path().join("log"), 1 << 20, FsyncPolicy::Always).unwrap();
    for i in 0..30 {
        log.append(Episode::new(
            "a",
            EventKind::Observation,
            format!("e{i}").into_bytes(),
        ))
        .unwrap();
    }
    let head = log.head();

    // 1) Arranque normal: materializa as views e faz checkpoint (estado bom).
    {
        let st = Arc::new(Mutex::new(Vec::new()));
        let mut r = ViewRegistry::open(dir.path()).unwrap();
        r.register(view_with(&st));
        r.catch_up(&log).unwrap();
        r.checkpoint().unwrap();
        assert_eq!(st.lock().unwrap().len() as u64, head, "setup: a view devia ver tudo");
    }

    // 2) Arranque com o replay SALTADO, seguido de um checkpoint (o periódico
    //    ou o de shutdown) — o caminho que corrompia o estado em disco.
    {
        let st = Arc::new(Mutex::new(Vec::new()));
        let mut r = ViewRegistry::open(dir.path()).unwrap();
        r.register(view_with(&st));
        r.reset_watermarks(); // a correção: views vazias ⇒ watermark 0
        r.checkpoint().unwrap();
    }

    // 3) Arranque normal seguinte: a view TEM de voltar a conter o log inteiro.
    let st = Arc::new(Mutex::new(Vec::new()));
    let mut r = ViewRegistry::open(dir.path()).unwrap();
    r.register(view_with(&st));
    r.catch_up(&log).unwrap();
    let indexados = st.lock().unwrap().len() as u64;
    assert_eq!(
        indexados, head,
        "views órfãs: só {indexados} de {head} eventos ficaram indexados"
    );
}
