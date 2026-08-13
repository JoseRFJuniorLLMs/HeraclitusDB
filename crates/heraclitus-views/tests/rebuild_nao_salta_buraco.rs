//! Regressao (invariante I6): o rebuild do LSN 0 nao pode saltar um buraco.
//!
//! Um registo com CRC-32C violado era SALTADO em silencio pelo `scan_capped`,
//! por isso o `ViewRegistry::rebuild` — o caminho oficial "reconstroi sempre a
//! partir do LSN 0", de que o invariante I6 depende — terminava `Ok` com o
//! episodio AUSENTE de todas as views, e o watermark persistido avancava PARA
//! ALEM do buraco, garantindo que aquele LSN nunca mais seria reaplicado.
//! Entretanto uma leitura pontual do MESMO LSN devolvia `Corruption`: os dois
//! caminhos discordavam. Repro original de um agente verificador da auditoria,
//! com as asercoes invertidas para exigir o comportamento correto.

use heraclitus_core::{Episode, EventKind, FsyncPolicy, HeraclitusError, Lsn};
use heraclitus_log::Log;
use heraclitus_views::{View, ViewRegistry};
use std::io::{Read, Seek, SeekFrom, Write};
use std::sync::{Arc, Mutex};

struct SpyView {
    seen: Arc<Mutex<Vec<Lsn>>>,
    wm: Lsn,
}

impl View for SpyView {
    fn name(&self) -> &str {
        "spy"
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
    fn checkpoint(&self, _dir: &std::path::Path) -> Result<(), HeraclitusError> {
        Ok(())
    }
    fn restore(&mut self, _dir: &std::path::Path) -> Result<bool, HeraclitusError> {
        Ok(false)
    }
}

#[test]
fn rebuild_falha_alto_em_vez_de_saltar_registo_corrompido() {
    let dir = tempfile::tempdir().unwrap();
    let log = Log::open(dir.path().join("log"), 1 << 20, FsyncPolicy::Always).unwrap();
    for i in 0..5u8 {
        log.append(Episode::new(
            "a",
            EventKind::Observation,
            format!("MARKER_EPISODE_{i}").into_bytes(),
        ))
        .unwrap();
    }

    // Runtime bit rot: flip one payload byte of episode #2 on disk.
    let seg = std::fs::read_dir(dir.path().join("log"))
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .find(|p| p.extension().map(|x| x == "hrkl").unwrap_or(false))
        .unwrap();
    let mut bytes = Vec::new();
    std::fs::File::open(&seg)
        .unwrap()
        .read_to_end(&mut bytes)
        .unwrap();
    let pos = bytes
        .windows(16)
        .position(|w| w == b"MARKER_EPISODE_2")
        .unwrap();
    let mut f = std::fs::OpenOptions::new().write(true).open(&seg).unwrap();
    f.seek(SeekFrom::Start(pos as u64)).unwrap();
    f.write_all(&[bytes[pos] ^ 0x01]).unwrap();
    f.sync_all().unwrap();
    drop(f);

    // The official "always works from LSN 0" rebuild path.
    let st = Arc::new(Mutex::new(Vec::new()));
    let mut reg = ViewRegistry::open(dir.path()).unwrap();
    reg.register(Box::new(SpyView {
        seen: st.clone(),
        wm: 0,
    }));
    // O rebuild TEM de falhar alto — nunca terminar Ok com um historico furado.
    let r = reg.rebuild(&log, None);
    let seen = st.lock().unwrap().clone();
    assert!(
        r.is_err(),
        "rebuild devolveu Ok saltando o registo corrompido (views aplicadas: {seen:?})"
    );

    // E a leitura pontual continua a reportar a corrupcao (os dois caminhos
    // de leitura concordam).
    let err = log.read(2).unwrap_err();
    assert!(format!("{err}").contains("corruption"));
}
