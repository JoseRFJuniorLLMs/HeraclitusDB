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
use heraclitus_log::EpisodeLog;
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
    names: Vec<String>,
    watermarks: HashMap<String, Lsn>,
    watermarks_vec: Vec<Lsn>,
}

impl ViewRegistry {
    pub fn open(data_dir: impl Into<PathBuf>) -> Result<Self, HeraclitusError> {
        let dir = data_dir.into().join("views");
        std::fs::create_dir_all(&dir)?;
        let wm_path = dir.join("watermarks.json");
        // Um `watermarks.json` ilegível NÃO pode matar o arranque. As
        // watermarks são estado derivado — dizem só até onde as views já foram
        // materializadas — e perdê-las custa um rebuild, que é lento mas
        // correcto. A assimetria era o defeito: o ficheiro ausente dava mapa
        // vazio e arrancava, um checkpoint corrompido degradava para rebuild,
        // mas um JSON malformado propagava o erro e o servidor não abria de
        // todo, exigindo intervenção manual para apagar um ficheiro
        // reconstruível.
        let watermarks = match std::fs::read_to_string(&wm_path) {
            Ok(raw) => match serde_json::from_str(&raw) {
                Ok(mapa) => mapa,
                Err(error) => {
                    tracing::warn!(
                        error = %error,
                        path = %wm_path.display(),
                        "watermarks.json ilegível; as views vão ser reconstruídas do LSN 0"
                    );
                    HashMap::new()
                }
            },
            Err(_) => HashMap::new(),
        };
        Ok(Self {
            dir,
            views: Vec::new(),
            names: Vec::new(),
            watermarks,
            watermarks_vec: Vec::new(),
        })
    }

    pub fn register(&mut self, view: Box<dyn View>) {
        let name = view.name().to_string();
        let wm = self.watermarks.get(&name).copied().unwrap_or(0);
        self.names.push(name);
        self.watermarks_vec.push(wm);
        self.views.push(view);
    }

    pub fn view_names(&self) -> Vec<String> {
        self.names.clone()
    }

    /// Sincroniza o vetor de watermarks rápido com o HashMap interno para persistência.
    fn sync_watermarks_map(&mut self) {
        for (i, name) in self.names.iter().enumerate() {
            self.watermarks.insert(name.clone(), self.watermarks_vec[i]);
        }
    }

    /// Apply one live tail event to every view sem alocações no hot path.
    pub fn apply(&mut self, lsn: Lsn, event: &Episode) {
        if heraclitus_log::vm_bridge::is_hvm(event) {
            return;
        }
        for (i, v) in self.views.iter_mut().enumerate() {
            v.apply(lsn, event);
            if lsn > self.watermarks_vec[i] {
                self.watermarks_vec[i] = lsn;
            }
        }
    }

    /// Watermarks por view (introspecção: `heraclitus_state()`).
    pub fn watermarks(&mut self) -> &HashMap<String, Lsn> {
        self.sync_watermarks_map();
        &self.watermarks
    }

    pub fn reset_watermarks(&mut self) {
        self.watermarks.clear();
        for wm in self.watermarks_vec.iter_mut() {
            *wm = 0;
        }
    }

    /// Minimum watermark across views (safe prune point for the memtable).
    pub fn min_watermark(&self) -> Lsn {
        self.watermarks_vec.iter().copied().min().unwrap_or(0)
    }

    /// On startup: replay `(watermark, head]` for each view com vetores diretos.
    pub fn catch_up<L: EpisodeLog + ?Sized>(&mut self, log: &L) -> Result<u64, HeraclitusError> {
        let dir = self.dir.clone();
        for (i, v) in self.views.iter_mut().enumerate() {
            if !v.restore(&dir)? {
                self.watermarks_vec[i] = 0;
                self.watermarks.remove(&self.names[i]);
            } else {
                let name = &self.names[i];
                self.watermarks_vec[i] = self.watermarks.get(name).copied().unwrap_or(0);
            }
        }

        let from = self
            .watermarks_vec
            .iter()
            .copied()
            .map(|w| if w > 0 { w + 1 } else { 0 })
            .min()
            .unwrap_or(0);

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
                    continue;
                }
                for (i, v) in self.views.iter_mut().enumerate() {
                    let wm = self.watermarks_vec[i];
                    if wm == 0 || *lsn > wm {
                        v.apply(*lsn, ep);
                        self.watermarks_vec[i] = *lsn;
                        applied += 1;
                    }
                }
            }
            cur = last + 1;
        }
        self.sync_watermarks_map();
        self.persist_watermarks()?;
        Ok(applied)
    }

    /// `heraclitus-cli view rebuild --view X` — must always work from LSN 0.
    pub fn rebuild<L: EpisodeLog + ?Sized>(
        &mut self,
        log: &L,
        view_name: Option<&str>,
    ) -> Result<(), HeraclitusError> {
        for (i, v) in self.views.iter_mut().enumerate() {
            if view_name
                .map(|n| n == self.names[i].as_str())
                .unwrap_or(true)
            {
                v.reset();
                self.watermarks_vec[i] = 0;
                self.watermarks.remove(&self.names[i]);
            }
        }
        let head = log.head();
        let mut cur = 0u64;
        while cur < head {
            let batch = log.scan_capped(cur, head, 100_000)?;
            let Some(&(last, _)) = batch.last() else {
                break;
            };
            for (lsn, ep) in &batch {
                if heraclitus_log::vm_bridge::is_hvm(ep) {
                    continue;
                }
                for (i, v) in self.views.iter_mut().enumerate() {
                    if view_name
                        .map(|n| n == self.names[i].as_str())
                        .unwrap_or(true)
                    {
                        v.apply(*lsn, ep);
                        self.watermarks_vec[i] = *lsn;
                    }
                }
            }
            cur = last + 1;
        }
        self.sync_watermarks_map();
        self.persist_watermarks()?;
        Ok(())
    }

    pub fn checkpoint(&mut self) -> Result<(), HeraclitusError> {
        for v in &self.views {
            v.checkpoint(&self.dir)?;
        }
        self.sync_watermarks_map();
        self.persist_watermarks()
    }

    fn persist_watermarks(&self) -> Result<(), HeraclitusError> {
        let raw = serde_json::to_string_pretty(&self.watermarks)
            .map_err(|e| HeraclitusError::Serialization(e.to_string()))?;
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
        let log = heraclitus_log::Log::open(dir.path().join("log"), 1 << 20, FsyncPolicy::Always)
            .unwrap();
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
        let log = heraclitus_log::Log::open(dir.path().join("log"), 1 << 20, FsyncPolicy::Always)
            .unwrap();
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
