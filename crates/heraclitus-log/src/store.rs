//! Fachada explícita para os motores HRKL legado (v1--v5) e v6.
//!
//! Este módulo não detecta nem converte formatos. O chamador escolhe
//! [`StorageFormat`] e os dois motores recusam uma raiz que já pertença ao
//! outro formato. Assim, mudar configuração nunca é uma migração de bytes.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use heraclitus_core::{
    DatabaseManifest, Episode, FsyncPolicy, HeraclitusError, Lsn, SegmentId, StorageFormat,
};
use heraclitus_crypto::KeyStore;
use tokio::sync::broadcast;

use crate::v6::V6Log;
use crate::Log;

/// Contadores neutros do pruning de um scan. Ficam na fachada comum para o
/// planner e o `EXPLAIN` não precisarem conhecer o layout v6.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PrunedScanStats {
    pub segments_total: u64,
    pub segments_candidate: u64,
    pub manifest_pruned: u64,
    pub segments_pruned: u64,
    pub hrki_pruned: u64,
    pub segments_read: u64,
    pub hrki_used: u64,
    pub hrki_misses: u64,
    pub hrki_ignored: u64,
    pub blocks_candidate: u64,
    pub blocks_pruned: u64,
    pub blocks_read: u64,
    pub bytes_candidate: u64,
    pub bytes_pruned: u64,
    pub bytes_physical_read: u64,
    pub bytes_decompressed: u64,
}

/// Plano de dados comum aos dois formatos de armazenamento.
///
/// A trait é object-safe para permitir que consumidores independentes do
/// formato recebam `&dyn EpisodeLog`. `as_legacy` e `legacy_arc` são
/// capabilities explícitas: uma optimização exclusiva do motor antigo deve
/// testar a capability, nunca presumir o backend.
/// Resultado de um scan com pruning: as linhas e o que foi saltado para as
/// obter.
///
/// As estatísticas viajam com as linhas de propósito. O `EXPLAIN` precisa de
/// dizer quantos blocos e bytes foram evitados nesta consulta em concreto, e
/// um contador global do processo não responde a isso — misturaria consultas
/// concorrentes.
pub type PrunedScan = Option<(Vec<(Lsn, Episode)>, PrunedScanStats)>;

pub trait EpisodeLog: Send + Sync {
    fn append(&self, episode: Episode) -> Result<Lsn, HeraclitusError>;

    fn append_stamped(&self, episode: Episode) -> Result<(Lsn, Episode), HeraclitusError>;

    fn append_replicated(&self, lsn: Lsn, episode: Episode) -> Result<Lsn, HeraclitusError>;

    fn flush(&self) -> Result<(), HeraclitusError>;

    fn head(&self) -> Lsn;

    fn tail_subscribe(&self) -> broadcast::Receiver<(Lsn, Arc<Episode>)>;

    fn read(&self, lsn: Lsn) -> Result<Option<(Lsn, Episode)>, HeraclitusError>;

    fn scan_capped(
        &self,
        from: Lsn,
        to: Lsn,
        max: usize,
    ) -> Result<Vec<(Lsn, Episode)>, HeraclitusError>;

    fn scan(&self, from: Lsn, to: Lsn) -> Result<Vec<(Lsn, Episode)>, HeraclitusError> {
        self.scan_capped(from, to, usize::MAX)
    }

    fn manifest(&self) -> DatabaseManifest;

    fn dir(&self) -> &Path;

    /// Scan optimizado por igualdade em campos built-in. `None` significa
    /// ausência da capability e obriga o planner ao scan conservador.
    fn scan_builtin_eq_capped(
        &self,
        _field: &str,
        _value: &str,
        _from: Lsn,
        _to: Lsn,
        _max: usize,
    ) -> Result<PrunedScan, HeraclitusError> {
        Ok(None)
    }

    fn as_legacy(&self) -> Option<&Log> {
        None
    }

    fn legacy_arc(&self) -> Option<Arc<Log>> {
        None
    }
}

impl EpisodeLog for Log {
    fn append(&self, episode: Episode) -> Result<Lsn, HeraclitusError> {
        Log::append(self, episode)
    }

    fn append_stamped(&self, episode: Episode) -> Result<(Lsn, Episode), HeraclitusError> {
        Log::append_stamped(self, episode)
    }

    fn append_replicated(&self, lsn: Lsn, episode: Episode) -> Result<Lsn, HeraclitusError> {
        Log::append_replicated(self, lsn, episode)
    }

    fn flush(&self) -> Result<(), HeraclitusError> {
        Log::flush(self)
    }

    fn head(&self) -> Lsn {
        Log::head(self)
    }

    fn tail_subscribe(&self) -> broadcast::Receiver<(Lsn, Arc<Episode>)> {
        Log::tail_subscribe(self)
    }

    fn read(&self, lsn: Lsn) -> Result<Option<(Lsn, Episode)>, HeraclitusError> {
        Log::read(self, lsn)
    }

    fn scan_capped(
        &self,
        from: Lsn,
        to: Lsn,
        max: usize,
    ) -> Result<Vec<(Lsn, Episode)>, HeraclitusError> {
        Log::scan_capped(self, from, to, max)
    }

    fn manifest(&self) -> DatabaseManifest {
        Log::manifest(self)
    }

    fn dir(&self) -> &Path {
        Log::dir(self)
    }

    fn as_legacy(&self) -> Option<&Log> {
        Some(self)
    }
}

impl EpisodeLog for V6Log {
    fn append(&self, episode: Episode) -> Result<Lsn, HeraclitusError> {
        V6Log::append(self, episode)
    }

    fn append_stamped(&self, episode: Episode) -> Result<(Lsn, Episode), HeraclitusError> {
        V6Log::append_stamped(self, episode)
    }

    fn append_replicated(&self, lsn: Lsn, episode: Episode) -> Result<Lsn, HeraclitusError> {
        V6Log::append_replicated(self, lsn, episode)
    }

    fn flush(&self) -> Result<(), HeraclitusError> {
        V6Log::flush(self)
    }

    fn head(&self) -> Lsn {
        V6Log::head(self)
    }

    fn tail_subscribe(&self) -> broadcast::Receiver<(Lsn, Arc<Episode>)> {
        V6Log::tail_subscribe(self)
    }

    fn read(&self, lsn: Lsn) -> Result<Option<(Lsn, Episode)>, HeraclitusError> {
        V6Log::read(self, lsn)
    }

    fn scan_capped(
        &self,
        from: Lsn,
        to: Lsn,
        max: usize,
    ) -> Result<Vec<(Lsn, Episode)>, HeraclitusError> {
        V6Log::scan_capped(self, from, to, max)
    }

    fn manifest(&self) -> DatabaseManifest {
        V6Log::manifest(self)
    }

    fn dir(&self) -> &Path {
        V6Log::dir(self)
    }

    fn scan_builtin_eq_capped(
        &self,
        field: &str,
        value: &str,
        from: Lsn,
        to: Lsn,
        max: usize,
    ) -> Result<Option<(Vec<(Lsn, Episode)>, PrunedScanStats)>, HeraclitusError> {
        V6Log::scan_builtin_eq_capped(self, field, value, from, to, max)
    }
}

/// Faz `Arc<T>` continuar utilizável por helpers genéricos sobre
/// [`EpisodeLog`], sem esconder a capability do valor interior.
impl<T: EpisodeLog + ?Sized> EpisodeLog for Arc<T> {
    fn append(&self, episode: Episode) -> Result<Lsn, HeraclitusError> {
        (**self).append(episode)
    }

    fn append_stamped(&self, episode: Episode) -> Result<(Lsn, Episode), HeraclitusError> {
        (**self).append_stamped(episode)
    }

    fn append_replicated(&self, lsn: Lsn, episode: Episode) -> Result<Lsn, HeraclitusError> {
        (**self).append_replicated(lsn, episode)
    }

    fn flush(&self) -> Result<(), HeraclitusError> {
        (**self).flush()
    }

    fn head(&self) -> Lsn {
        (**self).head()
    }

    fn tail_subscribe(&self) -> broadcast::Receiver<(Lsn, Arc<Episode>)> {
        (**self).tail_subscribe()
    }

    fn read(&self, lsn: Lsn) -> Result<Option<(Lsn, Episode)>, HeraclitusError> {
        (**self).read(lsn)
    }

    fn scan_capped(
        &self,
        from: Lsn,
        to: Lsn,
        max: usize,
    ) -> Result<Vec<(Lsn, Episode)>, HeraclitusError> {
        (**self).scan_capped(from, to, max)
    }

    fn manifest(&self) -> DatabaseManifest {
        (**self).manifest()
    }

    fn dir(&self) -> &Path {
        (**self).dir()
    }

    fn scan_builtin_eq_capped(
        &self,
        field: &str,
        value: &str,
        from: Lsn,
        to: Lsn,
        max: usize,
    ) -> Result<Option<(Vec<(Lsn, Episode)>, PrunedScanStats)>, HeraclitusError> {
        (**self).scan_builtin_eq_capped(field, value, from, to, max)
    }

    fn as_legacy(&self) -> Option<&Log> {
        (**self).as_legacy()
    }

    fn legacy_arc(&self) -> Option<Arc<Log>> {
        (**self).legacy_arc()
    }
}

/// Backend seleccionado explicitamente pela configuração do processo.
#[derive(Clone)]
pub enum AnyLog {
    Legacy(Arc<Log>),
    V6(Arc<V6Log>),
}

impl AnyLog {
    pub fn open(
        format: StorageFormat,
        dir: impl Into<PathBuf>,
        segment_max_bytes: u64,
        fsync: FsyncPolicy,
    ) -> Result<Self, HeraclitusError> {
        Self::open_with_keystore(format, dir, segment_max_bytes, fsync, None)
    }

    pub fn open_with_keystore(
        format: StorageFormat,
        dir: impl Into<PathBuf>,
        segment_max_bytes: u64,
        fsync: FsyncPolicy,
        keystore: Option<Arc<KeyStore>>,
    ) -> Result<Self, HeraclitusError> {
        let dir = dir.into();
        match format {
            StorageFormat::Legacy => {
                Log::open_with_keystore(dir, segment_max_bytes, fsync, keystore)
                    .map(Arc::new)
                    .map(Self::Legacy)
            }
            StorageFormat::V6 => V6Log::open_with_keystore(dir, segment_max_bytes, fsync, keystore)
                .map(Arc::new)
                .map(Self::V6),
        }
    }

    pub fn format(&self) -> StorageFormat {
        match self {
            Self::Legacy(_) => StorageFormat::Legacy,
            Self::V6(_) => StorageFormat::V6,
        }
    }

    pub fn legacy_arc(&self) -> Option<Arc<Log>> {
        match self {
            Self::Legacy(log) => Some(log.clone()),
            Self::V6(_) => None,
        }
    }

    /// Leituras pontuais servidas por este log, quando há instrumento.
    ///
    /// `None` no v6 — o contador vive no log legado (`Log::leituras`) e não foi
    /// replicado no motor v6, que pertence a outro caminho. Serve para um teste
    /// asseverar quantas leituras um caminho de query faz; como esse caminho é
    /// o mesmo nos dois formatos, medi-lo no legado chega para o provar
    /// (auditoria 2026-09-05, A56).
    pub fn leituras_efectuadas(&self) -> Option<u64> {
        match self {
            Self::Legacy(log) => Some(log.leituras_efectuadas()),
            Self::V6(_) => None,
        }
    }

    pub fn v6_arc(&self) -> Option<Arc<V6Log>> {
        match self {
            Self::Legacy(_) => None,
            Self::V6(log) => Some(log.clone()),
        }
    }

    pub fn sealed_segment_ids(&self) -> Vec<SegmentId> {
        match self {
            Self::Legacy(log) => log
                .sealed_segments()
                .into_iter()
                .map(|segment| segment.id)
                .collect(),
            Self::V6(log) => log
                .manifest()
                .segments_v2
                .into_iter()
                .map(|segment| segment.segment_id)
                .collect(),
        }
    }

    pub fn sealed_segment_count(&self) -> usize {
        match self {
            Self::Legacy(log) => log.sealed_segments().len(),
            Self::V6(log) => log.manifest().segments_v2.len(),
        }
    }

    pub fn append(&self, episode: Episode) -> Result<Lsn, HeraclitusError> {
        EpisodeLog::append(self, episode)
    }

    pub fn append_stamped(&self, episode: Episode) -> Result<(Lsn, Episode), HeraclitusError> {
        EpisodeLog::append_stamped(self, episode)
    }

    pub fn append_replicated(&self, lsn: Lsn, episode: Episode) -> Result<Lsn, HeraclitusError> {
        EpisodeLog::append_replicated(self, lsn, episode)
    }

    pub fn flush(&self) -> Result<(), HeraclitusError> {
        EpisodeLog::flush(self)
    }

    pub fn head(&self) -> Lsn {
        EpisodeLog::head(self)
    }

    pub fn tail_subscribe(&self) -> broadcast::Receiver<(Lsn, Arc<Episode>)> {
        EpisodeLog::tail_subscribe(self)
    }

    pub fn read(&self, lsn: Lsn) -> Result<Option<(Lsn, Episode)>, HeraclitusError> {
        EpisodeLog::read(self, lsn)
    }

    pub fn scan(&self, from: Lsn, to: Lsn) -> Result<Vec<(Lsn, Episode)>, HeraclitusError> {
        EpisodeLog::scan(self, from, to)
    }

    pub fn scan_capped(
        &self,
        from: Lsn,
        to: Lsn,
        max: usize,
    ) -> Result<Vec<(Lsn, Episode)>, HeraclitusError> {
        EpisodeLog::scan_capped(self, from, to, max)
    }

    pub fn manifest(&self) -> DatabaseManifest {
        EpisodeLog::manifest(self)
    }

    pub fn dir(&self) -> &Path {
        EpisodeLog::dir(self)
    }
}

impl EpisodeLog for AnyLog {
    fn append(&self, episode: Episode) -> Result<Lsn, HeraclitusError> {
        match self {
            Self::Legacy(log) => log.append(episode),
            Self::V6(log) => log.append(episode),
        }
    }

    fn append_stamped(&self, episode: Episode) -> Result<(Lsn, Episode), HeraclitusError> {
        match self {
            Self::Legacy(log) => log.append_stamped(episode),
            Self::V6(log) => log.append_stamped(episode),
        }
    }

    fn append_replicated(&self, lsn: Lsn, episode: Episode) -> Result<Lsn, HeraclitusError> {
        match self {
            Self::Legacy(log) => log.append_replicated(lsn, episode),
            Self::V6(log) => log.append_replicated(lsn, episode),
        }
    }

    fn flush(&self) -> Result<(), HeraclitusError> {
        match self {
            Self::Legacy(log) => log.flush(),
            Self::V6(log) => log.flush(),
        }
    }

    fn head(&self) -> Lsn {
        match self {
            Self::Legacy(log) => log.head(),
            Self::V6(log) => log.head(),
        }
    }

    fn tail_subscribe(&self) -> broadcast::Receiver<(Lsn, Arc<Episode>)> {
        match self {
            Self::Legacy(log) => log.tail_subscribe(),
            Self::V6(log) => log.tail_subscribe(),
        }
    }

    fn read(&self, lsn: Lsn) -> Result<Option<(Lsn, Episode)>, HeraclitusError> {
        match self {
            Self::Legacy(log) => log.read(lsn),
            Self::V6(log) => log.read(lsn),
        }
    }

    fn scan_capped(
        &self,
        from: Lsn,
        to: Lsn,
        max: usize,
    ) -> Result<Vec<(Lsn, Episode)>, HeraclitusError> {
        match self {
            Self::Legacy(log) => log.scan_capped(from, to, max),
            Self::V6(log) => log.scan_capped(from, to, max),
        }
    }

    fn manifest(&self) -> DatabaseManifest {
        match self {
            Self::Legacy(log) => log.manifest(),
            Self::V6(log) => log.manifest(),
        }
    }

    fn dir(&self) -> &Path {
        match self {
            Self::Legacy(log) => log.dir(),
            Self::V6(log) => log.dir(),
        }
    }

    fn scan_builtin_eq_capped(
        &self,
        field: &str,
        value: &str,
        from: Lsn,
        to: Lsn,
        max: usize,
    ) -> Result<Option<(Vec<(Lsn, Episode)>, PrunedScanStats)>, HeraclitusError> {
        match self {
            Self::Legacy(log) => log.scan_builtin_eq_capped(field, value, from, to, max),
            Self::V6(log) => log.scan_builtin_eq_capped(field, value, from, to, max),
        }
    }

    fn as_legacy(&self) -> Option<&Log> {
        match self {
            Self::Legacy(log) => Some(log.as_ref()),
            Self::V6(_) => None,
        }
    }

    fn legacy_arc(&self) -> Option<Arc<Log>> {
        AnyLog::legacy_arc(self)
    }
}
