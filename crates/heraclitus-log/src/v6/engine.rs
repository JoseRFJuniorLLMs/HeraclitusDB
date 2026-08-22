//! Caminho vivo e explícito do HRKL v6.
//!
//! O [`V6Log`] é deliberadamente um motor separado de [`crate::Log`]. O log
//! legado tem uma API concorrente, um catálogo próprio e segmentos v1--v5; fazer
//! `Log::open` mudar silenciosamente de backend colocaria uma migração de disco
//! no caminho de arranque de bases existentes. Em vez disso este tipo abre um
//! directório v6 novo, com layout próprio e um protocolo de recovery que pode
//! ser exercitado isoladamente.
//!
//! ```text
//! <root>/segments/00000000000000000000.active.hrkl
//! <root>/segments/00000000000000000000.g0000.raw.hrkl
//! <root>/segments/00000000000000000000.g0001.packed.hrkl
//! <root>/manifests/CURRENT
//! <root>/manifests/manifest-0000000001.hrkm
//! ```
//!
//! O nome `.active` é parte da garantia de recovery: só ele pode sofrer
//! `repair_active_tail`. Um `.raw` final é uma geração selada mesmo se o seu
//! footer estiver danificado; nesse caso o motor falha alto em vez de truncar
//! história.

use std::collections::BTreeSet;
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use heraclitus_core::runtime::{DatabaseManifest, PhysicalLayout};
use heraclitus_core::{Episode, FsyncPolicy, HeraclitusError, Hlc, Lsn, SegmentId};
use heraclitus_crypto::KeyStore;
use tokio::sync::broadcast;

use super::canonical::CANONICAL_CODEC_V1;
use super::compress::PackingProfile;
use super::error::{corrupt, V6Result, HARD_MAX_BLOCK_BYTES};
use super::header::FileHeaderV6;
use super::manifest::{record_pack, register_sealed_raw, ManifestStore, HRKM_MAGIC};
use super::packed::{open_packed, PackOptions, ScanCounters};
use super::packer::{pack_segment, PackOutcome};
use super::raw::{read_footer, repair_active_tail, scan_raw_segment, RawSegmentWriter, SegmentInit};
use super::receipts::physical_digest_of_file;
use super::verify::{verify_segment, IntegrityLevel, VerifyReport};

const SEGMENTS_DIR: &str = "segments";
const MANIFESTS_DIR: &str = "manifests";
const RAW_GENERATION: u32 = 0;

/// Escritor/reader v6 com manifesto `.hrkm` persistente.
///
/// A implementação prioriza a semântica de armazenamento e recuperação. O
/// writer é serializado por mutex e faz I/O síncrono; o motor legado permanece
/// a opção de throughput até a substituição do pipeline ser medida e aprovada
/// pelo gate de desempenho da SPEC.
pub struct V6Log {
    root: PathBuf,
    segments_dir: PathBuf,
    manifest_store: ManifestStore,
    state: Mutex<V6State>,
    hlc: Arc<Hlc>,
    fsync: FsyncPolicy,
    segment_max_bytes: u64,
    keystore: Option<Arc<KeyStore>>,
    tail_tx: broadcast::Sender<(Lsn, Arc<Episode>)>,
}

struct V6State {
    manifest: DatabaseManifest,
    active: Option<ActiveSegment>,
    next_lsn: Lsn,
    last_sync: Instant,
}

struct ActiveSegment {
    id: SegmentId,
    path: PathBuf,
    writer: RawSegmentWriter,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SegmentFile {
    Active(SegmentId),
    Raw(SegmentId),
    Packed(SegmentId, u32),
}

#[derive(Default)]
struct Inventory {
    active: Vec<(SegmentId, PathBuf)>,
    raw: Vec<(SegmentId, PathBuf)>,
    packed: Vec<(SegmentId, u32, PathBuf)>,
}

impl V6Log {
    /// Abre um directório exclusivo do v6. Um directório legado com ficheiros
    /// `000...hrkl` na raiz é recusado para que a migração nunca seja implícita.
    pub fn open(
        root: impl Into<PathBuf>,
        segment_max_bytes: u64,
        fsync: FsyncPolicy,
    ) -> Result<Self, HeraclitusError> {
        Self::open_with_keystore(root, segment_max_bytes, fsync, None)
    }

    /// Variante que mantém a mesma cifra-at-rest do log legado. O hash
    /// canónico é calculado sobre o `StoragePayload` já cifrado, para que
    /// packing/verificação nunca dependam de plaintext.
    pub fn open_with_keystore(
        root: impl Into<PathBuf>,
        segment_max_bytes: u64,
        fsync: FsyncPolicy,
        keystore: Option<Arc<KeyStore>>,
    ) -> Result<Self, HeraclitusError> {
        if segment_max_bytes == 0 {
            return Err(HeraclitusError::Config(
                "segment_max_bytes do V6Log não pode ser zero".into(),
            ));
        }
        let root = root.into();
        std::fs::create_dir_all(&root)?;
        reject_legacy_root(&root)?;
        let segments_dir = root.join(SEGMENTS_DIR);
        std::fs::create_dir_all(&segments_dir)?;
        let manifest_store = ManifestStore::open(root.join(MANIFESTS_DIR))?;
        // `.tmp` nunca é apontado por CURRENT, portanto é seguro varrê-lo
        // antes de decidir quais gerações são visíveis.
        let _ = manifest_store.sweep_orphan_temps()?;
        let _ = super::packer::sweep_orphan_temps(&segments_dir)?;

        let hlc = Arc::new(Hlc::new());
        let loaded = manifest_store.load()?;
        let loaded_manifest = loaded.as_ref().map(|l| l.manifest.clone());
        let inventory = discover(&segments_dir)?;
        if inventory.active.len() > 1 {
            return Err(corrupt(
                "hrkl v6 boot",
                "more than one active RAW tail; refusing ambiguous recovery",
            ));
        }

        let namespace = match &loaded_manifest {
            Some(m) => m.storage_namespace_id,
            None => discover_namespace(&inventory)?.unwrap_or_else(|| new_namespace(&root)),
        };
        let mut manifest = loaded_manifest.unwrap_or_else(|| empty_manifest(namespace));
        if manifest.storage_namespace_id != namespace {
            return Err(corrupt("hrkl v6 boot", "manifest namespace disagrees with storage"));
        }

        // RAW final é sempre selado. Se um crash aconteceu depois do rename e
        // antes do commit do HRKM, este passo o torna visível sem perder a
        // geração que já estava fsync'd.
        let mut manifest_changed = false;
        for (id, path) in &inventory.raw {
            manifest_changed |= reconcile_raw(
                &mut manifest,
                &root,
                *id,
                path,
                namespace,
            )?;
        }
        validate_manifest_ranges(&manifest)?;
        validate_catalogued_generations(&root, &manifest, namespace)?;

        // Um active com footer válido caiu entre seal e rename. Promovê-lo
        // para RAW final antes do manifesto fecha essa janela sem truncamento.
        let mut active_from_disk = inventory.active.into_iter().next();
        if let Some((id, path)) = active_from_disk.as_ref() {
            let header = read_v6_header(path)?;
            check_header_identity(&header, *id, namespace, PhysicalLayout::Raw)?;
            if read_footer(path)?.is_some() {
                let final_path = raw_path(&segments_dir, *id);
                if final_path.exists() {
                    return Err(corrupt(
                        "hrkl v6 boot",
                        "active file with footer collides with an existing RAW generation",
                    ));
                }
                std::fs::rename(path, &final_path)?;
                manifest_changed |= reconcile_raw(
                    &mut manifest,
                    &root,
                    *id,
                    &final_path,
                    namespace,
                )?;
                active_from_disk = None;
            }
        }

        if manifest_changed {
            manifest_store.commit(&mut manifest)?;
        }
        validate_manifest_ranges(&manifest)?;

        let mut next_lsn = next_lsn_from_manifest(&manifest)?;
        let active = match active_from_disk {
            Some((id, path)) => {
                // A extensão `.active` é a autorização explícita para reparar.
                // Um footer com magic completo mas CRC inválido é recusado pelo
                // helper; ele é possível bit rot de uma geração selada.
                repair_active_tail(&path)?;
                let scan = scan_raw_segment(&path)?;
                check_header_identity(&scan.header, id, namespace, PhysicalLayout::Raw)?;
                validate_active_records(&scan, next_lsn)?;
                if let Some(max_hlc) = scan.records.iter().map(|r| r.hlc).max() {
                    hlc.observe(max_hlc);
                }
                let writer = RawSegmentWriter::resume(&path, &persisted_hasher)?;
                if writer.next_expected_lsn() < next_lsn {
                    return Err(corrupt(
                        "hrkl v6 boot",
                        "active tail ends before catalogued history",
                    ));
                }
                next_lsn = writer.next_expected_lsn();
                ActiveSegment { id, path, writer }
            }
            None => create_active(&segments_dir, next_segment_id(&manifest), next_lsn, namespace, &hlc, manifest.manifest_generation)?,
        };

        let (tail_tx, _) = broadcast::channel(4096);
        Ok(Self {
            root,
            segments_dir,
            manifest_store,
            state: Mutex::new(V6State {
                manifest,
                active: Some(active),
                next_lsn,
                last_sync: Instant::now(),
            }),
            hlc,
            fsync,
            segment_max_bytes,
            keystore,
            tail_tx,
        })
    }

    /// Apensa um episódio e devolve o LSN. O HLC é carimbado dentro da secção
    /// crítica que também decide o LSN, mantendo a ordem monotónica por LSN.
    pub fn append(&self, mut episode: Episode) -> Result<Lsn, HeraclitusError> {
        episode.ts_hlc = self.hlc.now();
        self.append_inner(episode, None)
    }

    /// Apêndice replicado: preserva LSN e HLC do líder. Repetir o mesmo evento
    /// já gravado é idempotente; tentar outro evento no mesmo LSN é divergência.
    pub fn append_replicated(
        &self,
        lsn: Lsn,
        episode: Episode,
    ) -> Result<Lsn, HeraclitusError> {
        self.hlc.observe(episode.ts_hlc);
        let head = self.head();
        if lsn < head {
            return match self.read(lsn)? {
                Some((_, existing)) if existing.id == episode.id => Ok(lsn),
                _ => Err(HeraclitusError::CasConflict {
                    expected: lsn,
                    head,
                }),
            };
        }
        self.append_inner(episode, Some(lsn))
    }

    /// Força a barreira física do segmento activo.
    pub fn flush(&self) -> Result<(), HeraclitusError> {
        let mut state = self.lock_state()?;
        let active = state
            .active
            .as_mut()
            .ok_or_else(|| HeraclitusError::StorageEngine("V6Log sem segmento ativo".into()))?;
        active.writer.sync()?;
        state.last_sync = Instant::now();
        Ok(())
    }

    /// Sela o segmento activo, publica a geração RAW no HRKM e abre um novo
    /// tail. Um segmento vazio é descartado: não representa história alguma.
    pub fn seal_active(&self) -> Result<(), HeraclitusError> {
        let mut state = self.lock_state()?;
        self.seal_active_locked(&mut state)
    }

    pub fn head(&self) -> Lsn {
        self.state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .next_lsn
    }

    pub fn tail_subscribe(&self) -> broadcast::Receiver<(Lsn, Arc<Episode>)> {
        self.tail_tx.subscribe()
    }

    /// Uma cópia consistente do catálogo persistido. O tail ainda activo não
    /// entra nele até ser selado — exactamente para o boot não precisar tratar
    /// bytes mutáveis como geração canónica.
    pub fn manifest(&self) -> DatabaseManifest {
        self.state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .manifest
            .clone()
    }

    pub fn dir(&self) -> &Path {
        &self.root
    }

    /// Lê um único episódio v6, de RAW ou PACKED, usando o HRKM como primeiro
    /// nível de localização. O path activo só é consultado para LSNs ainda não
    /// selados.
    pub fn read(&self, lsn: Lsn) -> Result<Option<(Lsn, Episode)>, HeraclitusError> {
        let source = {
            let state = self.lock_state()?;
            if lsn >= state.next_lsn {
                return Ok(None);
            }
            let active = state.active.as_ref().ok_or_else(|| {
                HeraclitusError::StorageEngine("V6Log sem segmento ativo".into())
            })?;
            if lsn >= active.writer.header().first_lsn {
                ReadSource::Active(active.path.clone())
            } else {
                let desc = state.manifest.find_segment_for_lsn(lsn).ok_or_else(|| {
                    HeraclitusError::Corruption {
                        context: "hrkl v6 read".into(),
                        detail: format!("LSN {lsn} não está presente no manifesto"),
                    }
                })?;
                let generation = desc.active().ok_or_else(|| HeraclitusError::Corruption {
                    context: "hrkl v6 read".into(),
                    detail: format!("segmento {} sem geração ativa", desc.segment_id),
                })?;
                ReadSource::Sealed(
                    resolve_location(&self.root, &generation.location)?,
                    generation.layout,
                )
            }
        };

        let found = match source {
            ReadSource::Active(path) => scan_raw_segment(&path)?
                .records
                .into_iter()
                .find(|r| r.lsn == lsn)
                .map(|r| (r.lsn, r.payload)),
            ReadSource::Sealed(path, PhysicalLayout::Raw) => scan_raw_segment(&path)?
                .records
                .into_iter()
                .find(|r| r.lsn == lsn)
                .map(|r| (r.lsn, r.payload)),
            ReadSource::Sealed(path, PhysicalLayout::Packed) => {
                let reader = open_packed(&path, HARD_MAX_BLOCK_BYTES)?;
                let mut counters = ScanCounters::default();
                reader.get(lsn, &mut counters)?.map(|(_, payload)| (lsn, payload))
            }
        };
        let Some((found_lsn, payload)) = found else {
            return Ok(None);
        };
        let mut episode = crate::decode_episode_payload_with_meta(
            crate::format::FORMAT_VERSION,
            &payload,
        )?
        .episode;
        crate::decrypt_storage_episode_in_place(&mut episode, self.keystore.as_deref())?;
        Ok(Some((found_lsn, episode)))
    }

    pub fn scan(&self, from: Lsn, to: Lsn) -> Result<Vec<(Lsn, Episode)>, HeraclitusError> {
        self.scan_capped(from, to, usize::MAX)
    }

    /// Varredura correcta e limitada; o optimizador de range pode substituir
    /// esta implementação sem alterar a semântica pública.
    pub fn scan_capped(
        &self,
        from: Lsn,
        to: Lsn,
        max: usize,
    ) -> Result<Vec<(Lsn, Episode)>, HeraclitusError> {
        let end = to.min(self.head());
        if from >= end || max == 0 {
            return Ok(Vec::new());
        }
        let mut out = Vec::with_capacity(max.min(1024));
        let mut lsn = from;
        while lsn < end && out.len() < max {
            let record = self.read(lsn)?.ok_or_else(|| HeraclitusError::Corruption {
                context: "hrkl v6 scan".into(),
                detail: format!("LSN contíguo {lsn} ausente"),
            })?;
            out.push(record);
            lsn = lsn.saturating_add(1);
        }
        Ok(out)
    }

    /// Executa verificação física/lógica sobre as gerações activas seladas.
    /// A cauda activa não é reportada como prova forense porque ainda não tem
    /// footer/manifesto; chama-se `seal_active` antes de uma auditoria final.
    pub fn verify_sealed(
        &self,
        level: IntegrityLevel,
    ) -> Result<Vec<VerifyReport>, HeraclitusError> {
        let manifest = self.manifest();
        let mut reports = Vec::with_capacity(manifest.segments_v2.len());
        for desc in &manifest.segments_v2 {
            let generation = desc.active().ok_or_else(|| HeraclitusError::Corruption {
                context: "hrkl v6 verify".into(),
                detail: format!("segmento {} sem geração ativa", desc.segment_id),
            })?;
            let path = resolve_location(&self.root, &generation.location)?;
            let report = verify_segment(
                &path,
                level,
                HARD_MAX_BLOCK_BYTES,
                (level >= IntegrityLevel::Logical).then_some(&persisted_hasher),
            )?;
            if !report.is_ok() {
                return Err(HeraclitusError::Corruption {
                    context: format!("hrkl v6 verify segmento {}", desc.segment_id),
                    detail: report.notes.join("; "),
                });
            }
            reports.push(report);
        }
        Ok(reports)
    }

    /// Processa a fila persistida de RAW selados. Por agora é intencionalmente
    /// invocado pelo operador/worker, não pelo hot path de append (§22).
    pub fn pack_pending(&self, profile: PackingProfile) -> Result<Vec<PackOutcome>, HeraclitusError> {
        let mut state = self.lock_state()?;
        let queue = state.manifest.packing_queue();
        let mut outcomes = Vec::with_capacity(queue.len());
        for id in queue {
            let desc = state.manifest.segment(id).cloned().ok_or_else(|| {
                HeraclitusError::Corruption {
                    context: "hrkl v6 pack".into(),
                    detail: format!("segmento {id} desapareceu da fila"),
                }
            })?;
            let source = desc
                .generations
                .iter()
                .find(|g| g.layout == PhysicalLayout::Raw)
                .ok_or_else(|| HeraclitusError::Corruption {
                    context: "hrkl v6 pack".into(),
                    detail: format!("segmento {id} sem geração RAW"),
                })?;
            let source_path = resolve_location(&self.root, &source.location)?;
            let target_generation = next_physical_generation(&self.segments_dir, &desc)?;
            let target_path = packed_path(&self.segments_dir, id, target_generation);
            let options = PackOptions {
                profile,
                ..PackOptions::default()
            };
            let outcome = pack_segment(
                &source_path,
                &target_path,
                options,
                source.generation,
                target_generation,
                &persisted_hasher,
            )?;
            let before = state.manifest.clone();
            let location = packed_location(id, target_generation);
            if let Err(err) = record_pack(
                &mut state.manifest,
                &outcome.receipt,
                &location,
                self.hlc.now(),
            ) {
                state.manifest = before;
                return Err(err);
            }
            if let Err(err) = self.manifest_store.commit(&mut state.manifest) {
                // O PACKED publicado fica deliberadamente órfão e legível; o
                // retry escolhe outra geração física em vez de sobrescrevê-lo.
                state.manifest = before;
                return Err(err);
            }
            outcomes.push(outcome);
        }
        Ok(outcomes)
    }

    fn append_inner(
        &self,
        episode: Episode,
        expected_lsn: Option<Lsn>,
    ) -> Result<Lsn, HeraclitusError> {
        let opaque_meta = episode.id.0.to_bytes();
        let payload = crate::encode_storage_payload_v6(
            opaque_meta,
            &episode,
            self.keystore.as_deref(),
        )?;
        let mut state = self.lock_state()?;
        if let Some(expected) = expected_lsn {
            if expected != state.next_lsn {
                return Err(HeraclitusError::CasConflict {
                    expected,
                    head: state.next_lsn,
                });
            }
        }
        let lsn = state.next_lsn;
        let hash = persisted_hasher(lsn, episode.ts_hlc, &payload)?;
        let record_len = super::raw::RAW_RECORD_HEADER_LEN as u64 + payload.len() as u64;
        let needs_roll = state
            .active
            .as_ref()
            .map(|a| a.writer.record_count() > 0 && a.writer.bytes_written() + record_len > self.segment_max_bytes)
            .unwrap_or(false);
        if needs_roll {
            self.seal_active_locked(&mut state)?;
        }
        let sync_now = should_sync(&self.fsync, state.last_sync);
        {
            let active = state.active.as_mut().ok_or_else(|| {
                HeraclitusError::StorageEngine("V6Log sem segmento ativo".into())
            })?;
            if lsn != active.writer.next_expected_lsn() {
                return Err(corrupt(
                    "hrkl v6 append",
                    "engine LSN does not match the active writer",
                ));
            }
            active.writer.append(lsn, episode.ts_hlc, &payload, &hash)?;
            if sync_now {
                active.writer.sync()?;
            }
        }
        if sync_now {
            state.last_sync = Instant::now();
        }
        state.next_lsn = state.next_lsn.saturating_add(1);
        let _ = self.tail_tx.send((lsn, Arc::new(episode)));
        Ok(lsn)
    }

    fn seal_active_locked(&self, state: &mut V6State) -> Result<(), HeraclitusError> {
        let active = state
            .active
            .take()
            .ok_or_else(|| HeraclitusError::StorageEngine("V6Log sem segmento ativo".into()))?;
        if active.writer.record_count() == 0 {
            drop(active.writer);
            std::fs::remove_file(&active.path)?;
            state.active = Some(create_active(
                &self.segments_dir,
                active.id,
                state.next_lsn,
                state.manifest.storage_namespace_id,
                &self.hlc,
                state.manifest.manifest_generation,
            )?);
            return Ok(());
        }

        let footer = active.writer.seal()?;
        let final_path = raw_path(&self.segments_dir, active.id);
        if final_path.exists() {
            return Err(corrupt(
                "hrkl v6 seal",
                "immutable RAW generation path already exists",
            ));
        }
        std::fs::rename(&active.path, &final_path)?;
        let before = state.manifest.clone();
        let namespace = state.manifest.storage_namespace_id;
        let changed = reconcile_raw(
            &mut state.manifest,
            &self.root,
            active.id,
            &final_path,
            namespace,
        )?;
        if !changed || state.manifest.segment(active.id).map(|s| s.logical_root) != Some(footer.logical_root) {
            state.manifest = before;
            return Err(corrupt(
                "hrkl v6 seal",
                "sealed RAW was not coherently registered in the manifest",
            ));
        }
        if let Err(err) = self.manifest_store.commit(&mut state.manifest) {
            state.manifest = before;
            return Err(err);
        }
        state.active = Some(create_active(
            &self.segments_dir,
            active.id.saturating_add(1),
            state.next_lsn,
            state.manifest.storage_namespace_id,
            &self.hlc,
            state.manifest.manifest_generation,
        )?);
        state.last_sync = Instant::now();
        Ok(())
    }

    fn lock_state(&self) -> Result<std::sync::MutexGuard<'_, V6State>, HeraclitusError> {
        self.state
            .lock()
            .map_err(|_| HeraclitusError::StorageEngine("mutex do V6Log envenenado".into()))
    }
}

enum ReadSource {
    Active(PathBuf),
    Sealed(PathBuf, PhysicalLayout),
}

fn persisted_hasher(lsn: Lsn, hlc: u64, payload: &[u8]) -> V6Result<[u8; 32]> {
    crate::canonical_hash_storage_payload_v6(lsn, hlc, payload)
}

fn should_sync(policy: &FsyncPolicy, last_sync: Instant) -> bool {
    match policy {
        FsyncPolicy::Always => true,
        FsyncPolicy::GroupCommit { interval_ms } => {
            last_sync.elapsed() >= Duration::from_millis(*interval_ms)
        }
    }
}

fn empty_manifest(namespace: [u8; 16]) -> DatabaseManifest {
    DatabaseManifest {
        manifest_version: 1,
        format_identifier: HRKM_MAGIC,
        storage_namespace_id: namespace,
        ..Default::default()
    }
}

fn create_active(
    segments_dir: &Path,
    id: SegmentId,
    first_lsn: Lsn,
    namespace: [u8; 16],
    hlc: &Hlc,
    manifest_generation: u64,
) -> V6Result<ActiveSegment> {
    let path = active_path(segments_dir, id);
    if path.exists() {
        return Err(corrupt(
            "hrkl v6 create active",
            "active generation path already exists",
        ));
    }
    let writer = RawSegmentWriter::create(
        &path,
        SegmentInit {
            segment_id: id,
            created_hlc: hlc.now(),
            first_lsn,
            writer_epoch: manifest_generation.saturating_add(1),
            storage_namespace_id: namespace,
        },
    )?;
    Ok(ActiveSegment { id, path, writer })
}

fn reconcile_raw(
    manifest: &mut DatabaseManifest,
    root: &Path,
    id: SegmentId,
    path: &Path,
    namespace: [u8; 16],
) -> V6Result<bool> {
    let scan = scan_raw_segment(path)?;
    check_header_identity(&scan.header, id, namespace, PhysicalLayout::Raw)?;
    let footer = scan
        .footer
        .ok_or_else(|| corrupt("hrkl v6 boot", "final RAW generation has no valid footer"))?;
    if scan.torn_at.is_some() {
        return Err(corrupt(
            "hrkl v6 boot",
            "final RAW generation has a torn tail",
        ));
    }
    let report = verify_segment(
        path,
        IntegrityLevel::Logical,
        HARD_MAX_BLOCK_BYTES,
        Some(&persisted_hasher),
    )?;
    if !report.is_ok() {
        return Err(corrupt(
            "hrkl v6 boot",
            "final RAW generation failed canonical verification",
        ));
    }
    let location = raw_location(id);
    let digest = physical_digest_of_file(path)?;
    if let Some(existing) = manifest.segment(id) {
        let raw = existing
            .generations
            .iter()
            .find(|g| g.generation == RAW_GENERATION)
            .ok_or_else(|| corrupt("hrkl v6 boot", "catalogued segment has no RAW generation"))?;
        if existing.logical_root != footer.logical_root
            || raw.location != location
            || raw.physical_digest != digest
            || raw.physical_size != std::fs::metadata(path)?.len()
        {
            return Err(corrupt(
                "hrkl v6 boot",
                "RAW file disagrees with its catalogued generation",
            ));
        }
        return Ok(false);
    }
    let _ = root; // locations são relativos por design; raiz só documenta a fronteira.
    register_sealed_raw(
        manifest,
        id,
        &footer,
        scan.header.canonical_codec as u16,
        &location,
        std::fs::metadata(path)?.len(),
        digest,
        footer.max_hlc,
    )?;
    Ok(true)
}

fn validate_manifest_ranges(manifest: &DatabaseManifest) -> V6Result<()> {
    let mut ids = BTreeSet::new();
    let mut expected_lsn = 0u64;
    for desc in &manifest.segments_v2 {
        if !ids.insert(desc.segment_id) {
            return Err(corrupt("hrkl v6 manifest", "duplicate segment_id"));
        }
        if desc.record_count == 0 {
            return Err(corrupt("hrkl v6 manifest", "empty segment was catalogued"));
        }
        if desc.first_lsn != expected_lsn {
            return Err(corrupt(
                "hrkl v6 manifest",
                format!(
                    "LSN ranges must be contiguous: expected {expected_lsn}, found {}",
                    desc.first_lsn
                ),
            ));
        }
        expected_lsn = desc
            .last_lsn
            .checked_add(1)
            .ok_or_else(|| corrupt("hrkl v6 manifest", "last LSN overflows u64"))?;
    }
    if !manifest.segments_v2.is_empty()
        && manifest.cumulative_watermark != expected_lsn.saturating_sub(1)
    {
        return Err(corrupt(
            "hrkl v6 manifest",
            "cumulative watermark disagrees with sealed LSN ranges",
        ));
    }
    Ok(())
}

fn next_lsn_from_manifest(manifest: &DatabaseManifest) -> V6Result<Lsn> {
    validate_manifest_ranges(manifest)?;
    manifest
        .segments_v2
        .last()
        .map(|s| {
            s.last_lsn
                .checked_add(1)
                .ok_or_else(|| corrupt("hrkl v6 manifest", "last LSN overflows u64"))
        })
        .transpose()
        .map(|v| v.unwrap_or(0))
}

fn next_segment_id(manifest: &DatabaseManifest) -> SegmentId {
    manifest
        .segments_v2
        .iter()
        .map(|s| s.segment_id)
        .max()
        .map(|id| id.saturating_add(1))
        .unwrap_or(0)
}

fn next_physical_generation(
    segments_dir: &Path,
    desc: &heraclitus_core::runtime::SegmentDescriptorV2,
) -> V6Result<u32> {
    let mut maximum = desc.generations.iter().map(|g| g.generation).max().unwrap_or(0);
    for (id, generation, _) in discover(segments_dir)?.packed {
        if id == desc.segment_id {
            maximum = maximum.max(generation);
        }
    }
    maximum
        .checked_add(1)
        .ok_or_else(|| corrupt("hrkl v6 pack", "generation number exhausted"))
}

fn validate_catalogued_generations(
    root: &Path,
    manifest: &DatabaseManifest,
    namespace: [u8; 16],
) -> V6Result<()> {
    for desc in &manifest.segments_v2 {
        for generation in &desc.generations {
            let path = resolve_location(root, &generation.location)?;
            if !path.is_file() {
                return Err(corrupt(
                    "hrkl v6 boot",
                    format!("catalogued generation is missing: {}", path.display()),
                ));
            }
            let header = read_v6_header(&path)?;
            check_header_identity(&header, desc.segment_id, namespace, generation.layout)?;
            if physical_digest_of_file(&path)? != generation.physical_digest {
                return Err(corrupt(
                    "hrkl v6 boot",
                    "catalogued generation physical digest mismatch",
                ));
            }
        }
    }
    Ok(())
}

fn validate_active_records(scan: &super::raw::RawScan, expected_first: Lsn) -> V6Result<()> {
    if scan.footer.is_some() || scan.torn_at.is_some() {
        return Err(corrupt(
            "hrkl v6 boot",
            "active scan must be repaired and unsealed before resume",
        ));
    }
    let mut expected = expected_first;
    for record in &scan.records {
        if record.lsn != expected {
            return Err(corrupt(
                "hrkl v6 boot",
                format!("active tail LSN {} != expected {expected}", record.lsn),
            ));
        }
        expected = expected
            .checked_add(1)
            .ok_or_else(|| corrupt("hrkl v6 boot", "LSN overflow in active tail"))?;
    }
    if scan.header.first_lsn != expected_first {
        return Err(corrupt(
            "hrkl v6 boot",
            "active header first_lsn disagrees with catalogued history",
        ));
    }
    Ok(())
}

fn check_header_identity(
    header: &FileHeaderV6,
    id: SegmentId,
    namespace: [u8; 16],
    layout: PhysicalLayout,
) -> V6Result<()> {
    if header.segment_id != id
        || header.storage_namespace_id != namespace
        || header.physical_layout != layout
        || header.canonical_codec != CANONICAL_CODEC_V1
    {
        return Err(corrupt(
            "hrkl v6 boot",
            "segment filename/header/namespace/layout disagree",
        ));
    }
    Ok(())
}

fn read_v6_header(path: &Path) -> V6Result<FileHeaderV6> {
    use std::io::Read;
    let mut file = std::fs::File::open(path)?;
    let mut bytes = [0u8; super::header::FILE_HEADER_LEN];
    file.read_exact(&mut bytes)?;
    FileHeaderV6::decode(&bytes)
}

fn discover_namespace(inventory: &Inventory) -> V6Result<Option<[u8; 16]>> {
    let mut namespace = None;
    for (_, path) in inventory
        .raw
        .iter()
        .chain(inventory.active.iter())
        .map(|(_, p)| ((), p))
    {
        let found = read_v6_header(path)?.storage_namespace_id;
        if let Some(existing) = namespace {
            if existing != found {
                return Err(corrupt(
                    "hrkl v6 boot",
                    "storage namespace differs between on-disk segments",
                ));
            }
        } else {
            namespace = Some(found);
        }
    }
    Ok(namespace)
}

fn new_namespace(root: &Path) -> [u8; 16] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"HERACLITUS:HRKL:V6:NAMESPACE\0");
    hasher.update(root.to_string_lossy().as_bytes());
    hasher.update(&std::process::id().to_le_bytes());
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos()
        .to_le_bytes();
    hasher.update(&nanos);
    let mut namespace = [0u8; 16];
    namespace.copy_from_slice(&hasher.finalize().as_bytes()[..16]);
    namespace
}

fn discover(segments_dir: &Path) -> V6Result<Inventory> {
    let mut out = Inventory::default();
    for entry in std::fs::read_dir(segments_dir)? {
        let entry = entry?;
        if !entry.file_type()?.is_file() {
            continue;
        }
        let path = entry.path();
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        if name.ends_with(".tmp") {
            continue;
        }
        match parse_segment_file(name) {
            Some(SegmentFile::Active(id)) => out.active.push((id, path)),
            Some(SegmentFile::Raw(id)) => out.raw.push((id, path)),
            Some(SegmentFile::Packed(id, generation)) => out.packed.push((id, generation, path)),
            None if name.ends_with(".hrkl") => {
                return Err(corrupt(
                    "hrkl v6 boot",
                    format!("unrecognised HRKL v6 filename {name}"),
                ));
            }
            None => {}
        }
    }
    out.active.sort_by_key(|(id, _)| *id);
    out.raw.sort_by_key(|(id, _)| *id);
    out.packed.sort_by_key(|(id, generation, _)| (*id, *generation));
    Ok(out)
}

fn parse_segment_file(name: &str) -> Option<SegmentFile> {
    if let Some(id) = name.strip_suffix(".active.hrkl").and_then(parse_id) {
        return Some(SegmentFile::Active(id));
    }
    if let Some(id) = name.strip_suffix(".g0000.raw.hrkl").and_then(parse_id) {
        return Some(SegmentFile::Raw(id));
    }
    let stem = name.strip_suffix(".packed.hrkl")?;
    let (id, generation) = stem.split_once(".g")?;
    let id = parse_id(id)?;
    if generation.len() != 4 || !generation.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let generation = generation.parse().ok()?;
    Some(SegmentFile::Packed(id, generation))
}

fn parse_id(value: &str) -> Option<SegmentId> {
    (value.len() == 20 && value.bytes().all(|b| b.is_ascii_digit()))
        .then(|| value.parse().ok())
        .flatten()
}

fn reject_legacy_root(root: &Path) -> V6Result<()> {
    for entry in std::fs::read_dir(root)? {
        let entry = entry?;
        if !entry.file_type()?.is_file() {
            continue;
        }
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        if name.strip_suffix(".hrkl").and_then(|id| id.parse::<u64>().ok()).is_some() {
            return Err(corrupt(
                "hrkl v6 open",
                "legacy HRKL files found at root; use a new v6 directory or an explicit migration",
            ));
        }
    }
    Ok(())
}

fn resolve_location(root: &Path, location: &str) -> V6Result<PathBuf> {
    let relative = Path::new(location);
    if relative.is_absolute()
        || relative.components().any(|component| {
            matches!(component, Component::ParentDir | Component::RootDir | Component::Prefix(_))
        })
    {
        return Err(corrupt(
            "hrkl v6 manifest",
            "generation location must be a safe relative path",
        ));
    }
    Ok(root.join(relative))
}

fn active_path(segments_dir: &Path, id: SegmentId) -> PathBuf {
    segments_dir.join(format!("{id:020}.active.hrkl"))
}

fn raw_path(segments_dir: &Path, id: SegmentId) -> PathBuf {
    segments_dir.join(format!("{id:020}.g0000.raw.hrkl"))
}

fn packed_path(segments_dir: &Path, id: SegmentId, generation: u32) -> PathBuf {
    segments_dir.join(format!("{id:020}.g{generation:04}.packed.hrkl"))
}

fn raw_location(id: SegmentId) -> String {
    format!("segments/{id:020}.g0000.raw.hrkl")
}

fn packed_location(id: SegmentId, generation: u32) -> String {
    format!("segments/{id:020}.g{generation:04}.packed.hrkl")
}

#[cfg(test)]
mod tests {
    use super::*;
    use heraclitus_core::EventKind;

    fn event(i: u64) -> Episode {
        Episode::new(
            "v6-engine-test",
            EventKind::Observation,
            format!("payload-{i}").into_bytes(),
        )
    }

    #[test]
    fn writer_v6_seals_commits_and_reopens() {
        let dir = tempfile::tempdir().unwrap();
        let log = V6Log::open(dir.path(), 160, FsyncPolicy::Always).unwrap();
        for i in 0..40 {
            assert_eq!(log.append(event(i)).unwrap(), i);
        }
        log.flush().unwrap();
        log.seal_active().unwrap();
        let manifest = log.manifest();
        assert!(!manifest.segments_v2.is_empty());
        assert!(manifest
            .segments_v2
            .iter()
            .all(|s| s.active().unwrap().layout == PhysicalLayout::Raw));
        drop(log);

        let reopened = V6Log::open(dir.path(), 160, FsyncPolicy::Always).unwrap();
        assert_eq!(reopened.head(), 40);
        for i in 0..40 {
            assert_eq!(reopened.read(i).unwrap().unwrap().1.content, format!("payload-{i}").into_bytes());
        }
        let reports = reopened.verify_sealed(IntegrityLevel::Logical).unwrap();
        assert!(!reports.is_empty());
    }

    #[test]
    fn restart_repairs_and_resumes_active_tail() {
        let dir = tempfile::tempdir().unwrap();
        let log = V6Log::open(dir.path(), 1 << 20, FsyncPolicy::Always).unwrap();
        for i in 0..12 {
            log.append(event(i)).unwrap();
        }
        log.flush().unwrap();
        drop(log);

        let reopened = V6Log::open(dir.path(), 1 << 20, FsyncPolicy::Always).unwrap();
        assert_eq!(reopened.head(), 12);
        assert_eq!(reopened.append(event(12)).unwrap(), 12);
        assert_eq!(reopened.read(0).unwrap().unwrap().1.content, b"payload-0");
        assert_eq!(reopened.read(12).unwrap().unwrap().1.content, b"payload-12");
    }

    #[test]
    fn restart_truncates_only_a_partial_active_record() {
        let dir = tempfile::tempdir().unwrap();
        let log = V6Log::open(dir.path(), 1 << 20, FsyncPolicy::Always).unwrap();
        for i in 0..8 {
            log.append(event(i)).unwrap();
        }
        log.flush().unwrap();
        drop(log);

        let active = active_path(&dir.path().join(SEGMENTS_DIR), 0);
        let torn = super::super::raw::encode_raw_record(8, 99, b"torn-tail");
        {
            use std::io::Write as _;
            std::fs::OpenOptions::new()
                .append(true)
                .open(&active)
                .unwrap()
                .write_all(&torn[..11])
                .unwrap();
        }

        let reopened = V6Log::open(dir.path(), 1 << 20, FsyncPolicy::Always).unwrap();
        assert_eq!(reopened.head(), 8);
        assert_eq!(reopened.append(event(8)).unwrap(), 8);
    }

    #[test]
    fn sealed_raw_orphan_is_reconciled_on_boot() {
        let dir = tempfile::tempdir().unwrap();
        let log = V6Log::open(dir.path(), 1 << 20, FsyncPolicy::Always).unwrap();
        for i in 0..6 {
            log.append(event(i)).unwrap();
        }
        log.flush().unwrap();
        drop(log);

        // Simula morte entre `seal+fsync` e o rename/commit do HRKM.
        let segments = dir.path().join(SEGMENTS_DIR);
        let active = active_path(&segments, 0);
        let writer = RawSegmentWriter::resume(&active, &persisted_hasher).unwrap();
        writer.seal().unwrap();
        std::fs::rename(&active, raw_path(&segments, 0)).unwrap();

        let reopened = V6Log::open(dir.path(), 1 << 20, FsyncPolicy::Always).unwrap();
        assert_eq!(reopened.head(), 6);
        assert_eq!(reopened.manifest().segments_v2.len(), 1);
        assert_eq!(reopened.read(5).unwrap().unwrap().1.content, b"payload-5");
    }

    #[test]
    fn packing_switches_reader_to_packed_without_changing_events() {
        let dir = tempfile::tempdir().unwrap();
        let log = V6Log::open(dir.path(), 170, FsyncPolicy::Always).unwrap();
        for i in 0..50 {
            log.append(event(i)).unwrap();
        }
        log.seal_active().unwrap();
        let outcomes = log.pack_pending(PackingProfile::Balanced).unwrap();
        assert!(!outcomes.is_empty());
        let manifest = log.manifest();
        assert!(manifest
            .segments_v2
            .iter()
            .all(|s| s.active().unwrap().layout == PhysicalLayout::Packed));
        for i in 0..50 {
            assert_eq!(log.read(i).unwrap().unwrap().1.content, format!("payload-{i}").into_bytes());
        }
    }

    #[test]
    fn rejects_legacy_files_instead_of_migrating_silently() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("00000000000000000000.hrkl"), b"legacy").unwrap();
        assert!(V6Log::open(dir.path(), 1024, FsyncPolicy::Always).is_err());
    }

    #[test]
    fn persisted_payload_hasher_preserves_opaque_meta() {
        let episode = event(7);
        let payload_a = crate::encode_storage_payload_v6([0x11; 16], &episode, None).unwrap();
        let payload_b = crate::encode_storage_payload_v6([0x22; 16], &episode, None).unwrap();
        let decoded = crate::decode_episode_payload_with_meta(
            crate::format::FORMAT_VERSION,
            &payload_a,
        )
        .unwrap();
        assert_eq!(decoded.opaque_meta, [0x11; 16]);
        assert_eq!(decoded.episode.id, episode.id);
        assert_ne!(
            persisted_hasher(9, 10, &payload_a).unwrap(),
            persisted_hasher(9, 10, &payload_b).unwrap(),
            "opaque_meta tem de fazer parte da identidade canónica"
        );
    }
}
