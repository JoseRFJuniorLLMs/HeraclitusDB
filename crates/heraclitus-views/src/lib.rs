//! heraclitus-views — the replay engine (§3.5).
//!
//! Every index in HeraclitusDB is a [`View`]: derived, asynchronous and
//! rebuildable from LSN 0 by deterministic replay. View application must be
//! deterministic — no wall-clock reads, no unseeded RNG.
//!
//! v0 persistence note (RFC-002): watermarks and checkpoints are stored as
//! plain files under `<data_dir>/views/`. RocksDB-backed checkpoints are a
//! planned optimization; correctness never depends on them, because the
//! recovery story is *always* "rebuild from LSN 0".

use heraclitus_core::{Episode, HeraclitusError, Lsn};
use heraclitus_log::Log;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// Helpers partilhados de checkpoint (§fast boot): cada view persiste um
/// snapshot bincode do estado derivado em `<views>/<nome>.ckpt` com escrita
/// atómica (tmp + fsync + rename). A correção NUNCA depende disto — sem
/// checkpoint a view reconstrói-se do LSN 0; com ele, o boot replaya só a
/// cauda `(watermark, head]` em vez do log inteiro (a lição operacional da
/// carga massiva de 2026-07-02: replay total não escala).
pub mod ckpt {
    use super::HeraclitusError;
    use std::io::Write as _;
    use std::path::Path;

    pub fn save<T: serde::Serialize>(
        dir: &Path,
        name: &str,
        value: &T,
    ) -> Result<(), HeraclitusError> {
        let bytes = bincode::serde::encode_to_vec(value, bincode::config::standard())
            .map_err(|e| HeraclitusError::Serialization(e.to_string()))?;
        let tmp = dir.join(format!("{name}.ckpt.tmp"));
        {
            let mut f = std::fs::File::create(&tmp)?;
            f.write_all(&bytes)?;
            f.sync_all()?;
        }
        std::fs::rename(&tmp, dir.join(format!("{name}.ckpt")))?;
        Ok(())
    }

    /// `Ok(None)` = sem checkpoint OU checkpoint ilegível (formato antigo /
    /// corrompido) — a view nasce vazia e o registry força replay desde 0.
    /// Um snapshot ilegível NUNCA pode impedir o boot: o estado é derivado e
    /// o log é a verdade; degradar para rebuild é correto por construção.
    pub fn load<T: serde::de::DeserializeOwned>(
        dir: &Path,
        name: &str,
    ) -> Result<Option<T>, HeraclitusError> {
        let bytes = match std::fs::read(dir.join(format!("{name}.ckpt"))) {
            Ok(b) => b,
            Err(_) => return Ok(None),
        };
        match bincode::serde::decode_from_slice::<T, _>(&bytes, bincode::config::standard()) {
            Ok((value, _)) => Ok(Some(value)),
            Err(_) => Ok(None),
        }
    }
}

/// A materialized view over the log.
pub trait View: Send + Sync {
    fn name(&self) -> &str;
    /// Apply one event. MUST be deterministic in (lsn, event).
    fn apply(&mut self, lsn: Lsn, event: &Episode);
    /// Highest LSN applied.
    fn watermark(&self) -> Lsn;
    /// Persist derived state (optional; views may be RAM-only).
    fn checkpoint(&self, _dir: &Path) -> Result<(), HeraclitusError> {
        Ok(())
    }
    /// Restaura o estado derivado persistido por [`checkpoint`](View::checkpoint).
    /// Devolve `true` se restaurou (o watermark persistido passa a ser válido) ou
    /// `false` (default) se a view nasce vazia — nesse caso o registry FORÇA o
    /// replay desde 0 para não perder `(0, watermark]`. Sem este par
    /// checkpoint+restore, confiar no watermark persistido esvazia a view no restart.
    fn restore(&mut self, _dir: &Path) -> Result<bool, HeraclitusError> {
        Ok(false)
    }
    /// Canonical BLAKE3 digest of the view's derived state (Fase 1.3 / M8–M18
    /// acceptance gate). Default `None` = the view opts out. Any view that
    /// implements it MUST be deterministic: the digest is bit-identical after a
    /// wipe + rebuild-from-0, independent of thread count or CPU architecture.
    fn state_hash(&self) -> Option<[u8; 32]> {
        None
    }
    /// Reset internal state ahead of a rebuild from `lsn`.
    fn reset(&mut self);
}

/// Owns the registered views, their watermarks and the replay loop.
pub struct ViewRegistry {
    dir: PathBuf,
    views: Vec<Box<dyn View>>,
    watermarks: HashMap<String, Lsn>,
}

impl ViewRegistry {
    pub fn open(data_dir: impl Into<PathBuf>) -> Result<Self, HeraclitusError> {
        let dir = data_dir.into().join("views");
        std::fs::create_dir_all(&dir)?;
        let wm_path = dir.join("watermarks.json");
        let watermarks = match std::fs::read_to_string(&wm_path) {
            Ok(raw) => serde_json::from_str(&raw)
                .map_err(|e| HeraclitusError::Serialization(e.to_string()))?,
            Err(_) => HashMap::new(),
        };
        Ok(Self {
            dir,
            views: Vec::new(),
            watermarks,
        })
    }

    pub fn register(&mut self, view: Box<dyn View>) {
        self.views.push(view);
    }

    pub fn view_names(&self) -> Vec<String> {
        self.views.iter().map(|v| v.name().to_string()).collect()
    }

    /// Apply one live tail event to every view.
    pub fn apply(&mut self, lsn: Lsn, event: &Episode) {
        // Frames H-VM (`hvm_isa`) são bytecode do ledger soberano — vivem no
        // replay determinístico do VM, NÃO nas views derivadas. Excluí-los aqui
        // e nos replays de boot (`catch_up`/`rebuild`) mantém as views (e o
        // `state_hash`) idênticas quer sejam construídas ao vivo quer por replay.
        if heraclitus_log::vm_bridge::is_hvm(event) {
            return;
        }
        for v in self.views.iter_mut() {
            v.apply(lsn, event);
            // Avanço-só (max): dois appends concorrentes podem aplicar 6 antes
            // de 5; um insert cru regredia o watermark para 5, e um checkpoint
            // nesse estado fazia o restart re-replayar o 6 (duplicação em views
            // não-idempotentes). O max preserva "tudo ≤ wm foi aplicado".
            let w = self.watermarks.entry(v.name().to_string()).or_insert(0);
            *w = (*w).max(lsn);
        }
    }

    /// Watermarks por view (introspecção: `heraclitus_state()`).
    pub fn watermarks(&self) -> &HashMap<String, Lsn> {
        &self.watermarks
    }

    /// Descarta os watermarks carregados do disco — OBRIGATÓRIO quando as views
    /// ficam VAZIAS por se saltar o replay (`HERACLITUS_SKIP_VIEW_REPLAY` /
    /// `LOG_ONLY`). Sem isto o registo fica a afirmar "tudo ≤ W já foi
    /// aplicado" com as views vazias; um checkpoint (periódico ou de shutdown)
    /// grava então snapshots VAZIOS sob esses watermarks altos, e como
    /// `restore()` devolve `true` para um snapshot vazio-mas-presente, o
    /// arranque seguinte mantinha o watermark e replayava só `(W, head]` —
    /// TODOS os eventos ≤ W ficavam permanentemente invisíveis às views.
    pub fn reset_watermarks(&mut self) {
        self.watermarks.clear();
    }

    /// Minimum watermark across views (safe prune point for the memtable).
    pub fn min_watermark(&self) -> Lsn {
        self.views
            .iter()
            .map(|v| self.watermarks.get(v.name()).copied().unwrap_or(0))
            .min()
            .unwrap_or(0)
    }

    /// On startup: replay `(watermark, head]` for each view.
    pub fn catch_up(&mut self, log: &Log) -> Result<u64, HeraclitusError> {
        // Correção de correção (não só perf): um watermark persistido só é válido
        // se o ESTADO da view também tiver sido restaurado. Views que nascem vazias
        // (restore()==false, o default) têm o watermark forçado a 0 aqui, senão o
        // replay `(watermark, head]` deixá-las-ia sem `(0, watermark]` no restart.
        let dir = self.dir.clone();
        let mut to_reset = Vec::new();
        for v in self.views.iter_mut() {
            if !v.restore(&dir)? {
                to_reset.push(v.name().to_string());
            }
        }
        for name in to_reset {
            self.watermarks.remove(&name);
        }

        let from = self
            .views
            .iter()
            .map(|v| self.watermarks.get(v.name()).map(|w| w + 1).unwrap_or(0))
            .min()
            .unwrap_or(0);
        // Paginado: varre o log em janelas de 100k (NÃO materializa milhões de
        // episódios num único Vec — limita o pico de RAM do arranque, que era o
        // `alloc` gigante que estourava em logs grandes).
        let head = log.head();
        let mut applied = 0u64;
        let mut cur = from;
        while cur <= head {
            let batch = log.scan_capped(cur, head + 1, 100_000)?;
            if batch.is_empty() {
                break;
            }
            let last = batch.last().unwrap().0;
            for (lsn, ep) in &batch {
                if heraclitus_log::vm_bridge::is_hvm(ep) {
                    continue; // H-VM frame — não indexar nas views (ver `apply`).
                }
                for v in self.views.iter_mut() {
                    let wm = self.watermarks.get(v.name()).copied();
                    if wm.is_none() || *lsn > wm.unwrap() {
                        v.apply(*lsn, ep);
                        self.watermarks.insert(v.name().to_string(), *lsn);
                        applied += 1;
                    }
                }
            }
            cur = last + 1;
        }
        self.persist_watermarks()?;
        Ok(applied)
    }

    /// `heraclitus-cli view rebuild --view X` — must always work from LSN 0.
    pub fn rebuild(&mut self, log: &Log, view_name: Option<&str>) -> Result<(), HeraclitusError> {
        for v in self.views.iter_mut() {
            if view_name.map(|n| n == v.name()).unwrap_or(true) {
                v.reset();
                self.watermarks.remove(v.name());
            }
        }
        // R10: paginado como o `catch_up` — o scan sem teto materializava o log
        // INTEIRO num único Vec (o alloc gigante que estourava em logs grandes),
        // e o rebuild é justamente o fluxo oficial pós bulk-ingest.
        let head = log.head();
        let mut cur = 0u64;
        while cur < head {
            let batch = log.scan_capped(cur, head, 100_000)?;
            let Some(&(last, _)) = batch.last() else {
                break;
            };
            for (lsn, ep) in &batch {
                if heraclitus_log::vm_bridge::is_hvm(ep) {
                    continue; // H-VM frame — não indexar nas views (ver `apply`).
                }
                for v in self.views.iter_mut() {
                    if view_name.map(|n| n == v.name()).unwrap_or(true) {
                        v.apply(*lsn, ep);
                        self.watermarks.insert(v.name().to_string(), *lsn);
                    }
                }
            }
            cur = last + 1;
        }
        self.persist_watermarks()?;
        Ok(())
    }

    pub fn checkpoint(&self) -> Result<(), HeraclitusError> {
        for v in &self.views {
            v.checkpoint(&self.dir)?;
        }
        self.persist_watermarks()
    }

    fn persist_watermarks(&self) -> Result<(), HeraclitusError> {
        let raw = serde_json::to_string_pretty(&self.watermarks)
            .map_err(|e| HeraclitusError::Serialization(e.to_string()))?;
        // Audit #8: atomic write — tmp + fsync + rename. A power cut can
        // never leave a half-written watermarks.json behind.
        let tmp = self.dir.join("watermarks.json.tmp");
        {
            use std::io::Write as _;
            let mut f = std::fs::File::create(&tmp)?;
            f.write_all(raw.as_bytes())?;
            f.sync_all()?;
        }
        std::fs::rename(&tmp, self.dir.join("watermarks.json"))?;
        Ok(())
    }

    /// Borrow a registered view for querying.
    pub fn get(&self, name: &str) -> Option<&dyn View> {
        self.views
            .iter()
            .find(|v| v.name() == name)
            .map(|v| v.as_ref())
    }

    pub fn get_mut(&mut self, name: &str) -> Option<&mut Box<dyn View>> {
        self.views.iter_mut().find(|v| v.name() == name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use heraclitus_core::{EventKind, FsyncPolicy};

    use std::sync::{Arc, Mutex};

    /// Toy deterministic view: counts events and folds their LSNs into a
    /// state cell shared with the test.
    struct CountView {
        state: Arc<Mutex<(u64, u64)>>, // (count, fold)
        wm: Lsn,
    }

    impl View for CountView {
        fn name(&self) -> &str {
            "count"
        }
        fn apply(&mut self, lsn: Lsn, _e: &Episode) {
            let mut s = self.state.lock().unwrap();
            s.0 += 1;
            s.1 = s.1.wrapping_mul(31).wrapping_add(lsn);
            self.wm = lsn;
        }
        fn watermark(&self) -> Lsn {
            self.wm
        }
        fn reset(&mut self) {
            *self.state.lock().unwrap() = (0, 0);
            self.wm = 0;
        }
    }

    #[test]
    fn wipe_and_replay_is_deterministic() {
        // M2 acceptance gate: rebuild from LSN 0 yields bit-identical state.
        let dir = tempfile::tempdir().unwrap();
        let log = Log::open(dir.path().join("log"), 1 << 20, FsyncPolicy::Always).unwrap();
        for i in 0..50 {
            log.append(Episode::new(
                "a",
                EventKind::Observation,
                format!("e{i}").into_bytes(),
            ))
            .unwrap();
        }

        let state = Arc::new(Mutex::new((0u64, 0u64)));
        let mut reg = ViewRegistry::open(dir.path()).unwrap();
        reg.register(Box::new(CountView {
            state: state.clone(),
            wm: 0,
        }));
        reg.catch_up(&log).unwrap();
        let first = *state.lock().unwrap();

        reg.rebuild(&log, Some("count")).unwrap();
        let second = *state.lock().unwrap();

        assert_eq!(first.0, 50);
        assert_eq!(first, second, "replay must be deterministic");
    }

    #[test]
    fn empty_view_replays_from_zero_despite_persisted_watermark() {
        // Regressão: watermarks.json persiste watermarks avançados, mas se a view
        // nasce vazia (restore()==false) e catch_up confiasse no watermark, ela
        // ficaria sem `(0, watermark]` no restart. O fix força replay desde 0.
        let dir = tempfile::tempdir().unwrap();
        let log = Log::open(dir.path().join("log"), 1 << 20, FsyncPolicy::Always).unwrap();
        for i in 0..50 {
            log.append(Episode::new(
                "a",
                EventKind::Observation,
                format!("e{i}").into_bytes(),
            ))
            .unwrap();
        }

        // 1ª sessão: aplica tudo e persiste watermarks.json (= head).
        {
            let state = Arc::new(Mutex::new((0u64, 0u64)));
            let mut reg = ViewRegistry::open(dir.path()).unwrap();
            reg.register(Box::new(CountView {
                state: state.clone(),
                wm: 0,
            }));
            reg.catch_up(&log).unwrap();
            assert_eq!(state.lock().unwrap().0, 50);
        }

        // Restart: NOVO registry lê watermarks.json (avançado), view NASCE VAZIA.
        let state2 = Arc::new(Mutex::new((0u64, 0u64)));
        let mut reg2 = ViewRegistry::open(dir.path()).unwrap();
        reg2.register(Box::new(CountView {
            state: state2.clone(),
            wm: 0,
        }));
        reg2.catch_up(&log).unwrap();

        // Sem o fix isto seria 0 (view vazia, replay saltado). Com o fix: 50.
        assert_eq!(
            state2.lock().unwrap().0,
            50,
            "view vazia (restore=false) tem de replayar TODO o histórico desde 0"
        );
    }
}
