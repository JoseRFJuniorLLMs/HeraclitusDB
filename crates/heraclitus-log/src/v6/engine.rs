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
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use heraclitus_core::runtime::{DatabaseManifest, DerivedArtifactRef, PhysicalLayout};
use heraclitus_core::{Episode, FsyncPolicy, HeraclitusError, Hlc, Lsn, SegmentId};
use heraclitus_crypto::KeyStore;
use tokio::sync::broadcast;

use super::canonical::CANONICAL_CODEC_V1;
use super::compress::PackingProfile;
use super::error::{corrupt, V6Result, HARD_MAX_BLOCK_BYTES};
use super::header::FileHeaderV6;
use super::hrki::{caminho_sidecar, construir_para_packed, Hrki, IndexPolicySet};
use super::manifest::{
    attach_parquet, attach_sidecar, quarantine_generation as quarantine_manifest_generation,
    record_pack, register_sealed_raw, set_legal_hold, ManifestStore, HRKM_MAGIC,
};
use super::packed::{open_packed, PackOptions, ScanCounters};
use super::packer::{pack_segment, PackOutcome};
use super::raw::{
    read_footer, repair_active_tail, scan_raw_segment, RawSegmentWriter, SegmentInit,
};
use super::receipts::{persist_pack_receipt, physical_digest_of_file};
use super::verify::{verify_segment as verify_segment_file, IntegrityLevel, VerifyReport};

const SEGMENTS_DIR: &str = "segments";
const MANIFESTS_DIR: &str = "manifests";
const RAW_GENERATION: u32 = 0;

/// Escritor/reader v6 com manifesto `.hrkm` persistente.
///
/// A implementação prioriza a semântica de armazenamento e recuperação. O
/// writer é serializado por mutex e faz I/O síncrono; o motor legado permanece
/// a opção de throughput até a substituição do pipeline ser medida e aprovada
/// pelo gate de desempenho da SPEC.
/// Opções de uma passagem de GC (SPEC-0050 §90, §127).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GcRunOptions {
    /// Quantas gerações do manifesto manter (§90).
    pub keep_manifests: usize,
    /// §127 — uma geração em quarentena é evidência de um problema. Coletá-la
    /// exige um pedido explícito, para que um scrub automático não destrua o
    /// ficheiro que a perícia quer ver. **Nunca ligar isto numa task de fundo.**
    pub collect_quarantined: bool,
}

impl Default for GcRunOptions {
    fn default() -> Self {
        Self {
            keep_manifests: 3,
            collect_quarantined: false,
        }
    }
}

pub struct V6Log {
    root: PathBuf,
    segments_dir: PathBuf,
    manifest_store: ManifestStore,
    state: Mutex<V6State>,
    /// Serializa workers de packing sem tomar o mutex do writer. O trabalho
    /// pesado (leitura+Zstd+fsync) nunca bloqueia append; só o publish curto do
    /// HRKM volta a tomar `state`.
    packing_lock: Mutex<()>,
    /// Serializa a reconstrução/publicação de sidecars derivados.
    sidecar_lock: Mutex<()>,
    hlc: Arc<Hlc>,
    fsync: FsyncPolicy,
    segment_max_bytes: u64,
    keystore: Option<Arc<KeyStore>>,
    tail_tx: broadcast::Sender<(Lsn, Arc<Episode>)>,
    metrics: V6Metrics,
    /// SPEC-0050 §92 — leitores pinados que o GC tem de respeitar.
    pins: super::gc::PinRegistry,
}

#[derive(Default)]
struct V6Metrics {
    append_bytes: AtomicU64,
    pack_nanos: AtomicU64,
    pack_source_bytes: AtomicU64,
    pack_target_bytes: AtomicU64,
    blocks_read: AtomicU64,
    blocks_pruned: AtomicU64,
    bytes_pruned: AtomicU64,
    decompressed_bytes: AtomicU64,
    hrki_hits: AtomicU64,
    hrki_misses: AtomicU64,
    hrki_rebuilds: AtomicU64,
    canonical_verify_failures: AtomicU64,
    physical_crc_failures: AtomicU64,
}

/// Snapshot operacional da SPEC-0050 §150. Gauges de bytes/filas são
/// derivados do HRKM atual; contadores representam a vida deste processo.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct V6MetricsSnapshot {
    pub hrkl_append_bytes_total: u64,
    pub hrkl_raw_bytes: u64,
    pub hrkl_packed_bytes: u64,
    pub hrkl_compression_ratio: f64,
    pub hrkl_pack_queue_depth: u64,
    pub hrkl_pack_seconds: f64,
    pub hrkl_pack_throughput_bytes_sec: f64,
    pub hrkl_blocks_total: u64,
    pub hrkl_blocks_read: u64,
    pub hrkl_blocks_pruned: u64,
    pub hrkl_bytes_pruned: u64,
    pub hrkl_decompressed_bytes: u64,
    pub hrki_hits: u64,
    pub hrki_misses: u64,
    pub hrki_rebuilds: u64,
    pub cold_range_reads: u64,
    pub cold_bytes_downloaded: u64,
    pub parquet_export_lag_lsn: u64,
    pub canonical_verify_failures: u64,
    pub physical_crc_failures: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HrkiBuildOutcome {
    pub segment_id: SegmentId,
    pub generation: u32,
    pub path: PathBuf,
    pub size: u64,
    pub digest: [u8; 32],
}

/// Os cinco parâmetros de um scan por igualdade em campo built-in.
///
/// Agrupados num tipo porque viajam sempre juntos e sempre na mesma ordem —
/// cinco argumentos posicionais do mesmo par de tipos (`&str`, `&str`, `u64`,
/// `u64`, `usize`) são um convite a trocar `from` com `to` sem o compilador
/// dizer nada.
#[derive(Debug, Clone, Copy)]
struct BuiltinEqCriteria<'a> {
    field: &'a str,
    value: &'a str,
    from: Lsn,
    to: Lsn,
    max: usize,
}

/// SPEC-0050 §146/§203 — um segmento canónico à espera de projecção lakehouse.
///
/// Só a **fronteira** vive aqui. O `heraclitus-log` não conhece Parquet,
/// Iceberg, Delta nem `object_store`: entrega o caminho do PACKED activo e a
/// identidade lógica que a projecção tem de preservar, e é o `heraclitus-tier`
/// que materializa. É a mesma divisão da Fase 5 — o log expõe
/// [`crate::v6::BlockSource`], o tier implementa-a sobre range GETs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LakehousePending {
    pub segment_id: SegmentId,
    pub generation: u32,
    pub logical_root: [u8; 32],
    pub first_lsn: Lsn,
    pub last_lsn: Lsn,
    /// Caminho local do `.hrkl` PACKED activo desta geração.
    pub packed: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackedGenerationSource {
    pub segment_id: SegmentId,
    pub generation: u32,
    pub source_generation: Option<u32>,
    pub created_hlc: u64,
    pub path: PathBuf,
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
        let mut inventory = discover(&segments_dir)?;

        // Um ficheiro activo demasiado curto para conter um header é um toco de
        // crash, não um segmento: os registos vêm DEPOIS do header, portanto um
        // ficheiro sem header completo não pode conter um único registo
        // committed. Removê-lo não perde nada; não o remover para o arranque.
        //
        // Isto TEM de acontecer aqui — antes da guarda de ambiguidade e antes
        // da primeira leitura de cabeçalho — por duas razões que a primeira
        // versão desta correcção falhou, por a ter posto 40 linhas abaixo:
        //
        //  1. Um toco não é uma cauda activa, logo não pode contar para o
        //     "more than one active RAW tail". A contar, um toco ao lado de um
        //     activo legítimo fazia o arranque recusar por ambiguidade.
        //  2. Quando não há manifesto — uma base nova antes do primeiro seal,
        //     ou uma cujas gerações se perderam — o `discover_namespace` logo
        //     a seguir lê o header de cada segmento do inventário, e num
        //     ficheiro de zero bytes o `read_exact` devolve `UnexpectedEof` e
        //     aborta o arranque. O sintoma era o de sempre (a base não abre)
        //     com diagnóstico pior: um erro de I/O cru, sem o "short header".
        //     É o caminho onde o `reconcile_raw` reconstrói o catálogo a partir
        //     dos RAW selados, portanto era também onde se perdia acesso a
        //     dados duráveis.
        //
        // A condição é deliberadamente só o comprimento. Um header completo com
        // bytes errados NÃO entra aqui: isso é corrupção e tem de falhar alto.
        let mut tocos = Vec::new();
        for (id, path) in &inventory.active {
            if super::raw::is_crash_stub(path).unwrap_or(false) {
                tocos.push((*id, path.clone()));
            }
        }
        for (id, path) in &tocos {
            tracing::warn!(
                segment = id,
                path = %path.display(),
                "segmento activo sem header completo: toco de um crash durante a criação; removido"
            );
            std::fs::remove_file(path)?;
        }
        if !tocos.is_empty() {
            inventory
                .active
                .retain(|(id, _)| !tocos.iter().any(|(toco, _)| toco == id));
        }

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
            return Err(corrupt(
                "hrkl v6 boot",
                "manifest namespace disagrees with storage",
            ));
        }

        // RAW final é sempre selado. Se um crash aconteceu depois do rename e
        // antes do commit do HRKM, este passo o torna visível sem perder a
        // geração que já estava fsync'd.
        let mut manifest_changed = false;
        for (id, path) in &inventory.raw {
            if manifest.segment(*id).is_some() {
                // Um RAW já apontado pelo HRKM não é revarrido no boot. Um
                // RAW que deixou de ser apontado pode ser o órfão seguro de um
                // crash entre o commit metadata-first do GC e o unlink; nesse
                // caso só é tolerado se houver PACKED activa e autoritativa.
                // O catálogo, header, footer e tamanho da autoridade activa
                // são validados abaixo; CRCs e hash físico pertencem ao
                // scrubber ou a `verify_sealed`.
                ensure_catalogued_raw_generation(&manifest, *id, path)?;
            } else {
                // Este é o único RAW que precisa de varrimento: foi selado e
                // renomeado antes de o processo conseguir publicar o HRKM.
                // A reconciliação é recovery de órfão, não o caminho normal.
                manifest_changed |= reconcile_raw(&mut manifest, &root, *id, path, namespace)?;
            }
        }
        validate_manifest_ranges(&manifest)?;
        validate_catalogued_generations(&root, &manifest, namespace)?;

        // Um active com footer válido caiu entre seal e rename. Promovê-lo
        // para RAW final antes do manifesto fecha essa janela sem truncamento.
        // O toco de crash já saiu do inventário lá em cima, antes da primeira
        // leitura de cabeçalho; aqui o activo, se existir, tem header completo.
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
                manifest_changed |=
                    reconcile_raw(&mut manifest, &root, *id, &final_path, namespace)?;
                active_from_disk = None;
            }
        }

        if manifest_changed {
            manifest_store.commit(&mut manifest)?;
        }
        validate_manifest_ranges(&manifest)?;

        // O HLC do processo novo nunca pode arrancar atrás do histórico já
        // selado. Isto é especialmente importante quando `seal_active` deixou
        // uma cauda nova mas vazia: não há records activos cujo timestamp possa
        // ser observado abaixo, porém `AS OF TIMESTAMP` continua a depender de
        // `ts_hlc` não-decrescente por LSN em todo o histórico.
        if let Some(max_hlc) = manifest.segments_v2.iter().map(|s| s.max_hlc).max() {
            hlc.observe(max_hlc);
        }

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
            None => create_active(
                &segments_dir,
                next_segment_id(&manifest),
                next_lsn,
                namespace,
                &hlc,
                manifest.manifest_generation,
            )?,
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
            packing_lock: Mutex::new(()),
            sidecar_lock: Mutex::new(()),
            hlc,
            fsync,
            segment_max_bytes,
            keystore,
            tail_tx,
            metrics: V6Metrics::default(),
            pins: super::gc::PinRegistry::new(),
        })
    }

    /// Apensa um episódio e devolve o LSN. O HLC é carimbado dentro da secção
    /// crítica que também decide o LSN, mantendo a ordem monotónica por LSN.
    pub fn append(&self, episode: Episode) -> Result<Lsn, HeraclitusError> {
        self.append_stamped(episode).map(|(lsn, _)| lsn)
    }

    /// Como [`V6Log::append`], devolvendo também o episódio exacto que foi
    /// persistido. O carimbo acontece sob o mesmo mutex que atribui o LSN:
    /// appends concorrentes não conseguem inverter a ordem HLC/LSN.
    pub fn append_stamped(&self, mut episode: Episode) -> Result<(Lsn, Episode), HeraclitusError> {
        let mut state = self.lock_state()?;
        episode.ts_hlc = self.hlc.now();
        let stamped = episode.clone();
        let lsn = self.append_inner_locked(&mut state, episode, None)?;
        Ok((lsn, stamped))
    }

    /// Apêndice replicado: preserva LSN e HLC do líder. Repetir o mesmo evento
    /// já gravado é idempotente; tentar outro evento no mesmo LSN é divergência.
    pub fn append_replicated(&self, lsn: Lsn, episode: Episode) -> Result<Lsn, HeraclitusError> {
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

    pub fn metrics_snapshot(&self) -> Result<V6MetricsSnapshot, HeraclitusError> {
        let manifest = self.manifest();
        let mut raw_bytes = 0u64;
        let mut packed_bytes = 0u64;
        let mut blocks_total = 0u64;
        for segment in &manifest.segments_v2 {
            for generation in &segment.generations {
                match generation.layout {
                    PhysicalLayout::Raw => {
                        raw_bytes = raw_bytes.saturating_add(generation.physical_size)
                    }
                    PhysicalLayout::Packed => {
                        packed_bytes = packed_bytes.saturating_add(generation.physical_size)
                    }
                }
            }
            if let Some(active) = segment
                .active()
                .filter(|generation| generation.layout == PhysicalLayout::Packed)
            {
                let path = resolve_location(&self.root, &active.location)?;
                if let Ok(Some(footer)) = read_footer(&path) {
                    blocks_total = blocks_total.saturating_add(footer.block_count as u64);
                }
            }
        }
        if let Some(active_path) = self
            .state
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .active
            .as_ref()
            .map(|active| active.path.clone())
        {
            raw_bytes = raw_bytes.saturating_add(std::fs::metadata(active_path)?.len());
        }

        let pack_nanos = self.metrics.pack_nanos.load(Ordering::Relaxed);
        let pack_source = self.metrics.pack_source_bytes.load(Ordering::Relaxed);
        let pack_target = self.metrics.pack_target_bytes.load(Ordering::Relaxed);
        let pack_seconds = pack_nanos as f64 / 1_000_000_000.0;
        Ok(V6MetricsSnapshot {
            hrkl_append_bytes_total: self.metrics.append_bytes.load(Ordering::Relaxed),
            hrkl_raw_bytes: raw_bytes,
            hrkl_packed_bytes: packed_bytes,
            hrkl_compression_ratio: if pack_source == 0 {
                if raw_bytes == 0 {
                    1.0
                } else {
                    packed_bytes as f64 / raw_bytes as f64
                }
            } else {
                pack_target as f64 / pack_source as f64
            },
            hrkl_pack_queue_depth: manifest.packing_queue().len() as u64,
            hrkl_pack_seconds: pack_seconds,
            hrkl_pack_throughput_bytes_sec: if pack_seconds > 0.0 {
                pack_source as f64 / pack_seconds
            } else {
                0.0
            },
            hrkl_blocks_total: blocks_total,
            hrkl_blocks_read: self.metrics.blocks_read.load(Ordering::Relaxed),
            hrkl_blocks_pruned: self.metrics.blocks_pruned.load(Ordering::Relaxed),
            hrkl_bytes_pruned: self.metrics.bytes_pruned.load(Ordering::Relaxed),
            hrkl_decompressed_bytes: self.metrics.decompressed_bytes.load(Ordering::Relaxed),
            hrki_hits: self.metrics.hrki_hits.load(Ordering::Relaxed),
            hrki_misses: self.metrics.hrki_misses.load(Ordering::Relaxed),
            hrki_rebuilds: self.metrics.hrki_rebuilds.load(Ordering::Relaxed),
            // O tier adiciona estes dois contadores ao endpoint do servidor;
            // o log local não executa range GETs.
            cold_range_reads: 0,
            cold_bytes_downloaded: 0,
            parquet_export_lag_lsn: manifest
                .cumulative_watermark
                .saturating_sub(manifest.exported_through_lsn),
            canonical_verify_failures: self
                .metrics
                .canonical_verify_failures
                .load(Ordering::Relaxed),
            physical_crc_failures: self.metrics.physical_crc_failures.load(Ordering::Relaxed),
        })
    }

    fn observe_pruned_scan(&self, stats: &crate::store::PrunedScanStats) {
        self.metrics
            .blocks_read
            .fetch_add(stats.blocks_read, Ordering::Relaxed);
        self.metrics
            .blocks_pruned
            .fetch_add(stats.blocks_pruned, Ordering::Relaxed);
        self.metrics
            .bytes_pruned
            .fetch_add(stats.bytes_pruned, Ordering::Relaxed);
        self.metrics
            .decompressed_bytes
            .fetch_add(stats.bytes_decompressed, Ordering::Relaxed);
        self.metrics
            .hrki_hits
            .fetch_add(stats.hrki_used, Ordering::Relaxed);
        self.metrics
            .hrki_misses
            .fetch_add(stats.hrki_misses, Ordering::Relaxed);
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
            let active = state
                .active
                .as_ref()
                .ok_or_else(|| HeraclitusError::StorageEngine("V6Log sem segmento ativo".into()))?;
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
                reader
                    .get(lsn, &mut counters)?
                    .map(|(_, payload)| (lsn, payload))
            }
        };
        let Some((found_lsn, payload)) = found else {
            return Ok(None);
        };
        let mut episode =
            crate::decode_episode_payload_with_meta(crate::format::FORMAT_VERSION, &payload)?
                .episode;
        crate::decrypt_storage_episode_in_place(&mut episode, self.keystore.as_deref())?;
        Ok(Some((found_lsn, episode)))
    }

    pub fn scan(&self, from: Lsn, to: Lsn) -> Result<Vec<(Lsn, Episode)>, HeraclitusError> {
        self.scan_capped(from, to, usize::MAX)
    }

    /// Varredura sequencial otimizada por lote de segmentos; lê blocos sequencialmente
    /// sem transformar a faixa de LSNs em point lookups individuais.
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
        let manifest = self.manifest();
        let candidates: Vec<_> = manifest
            .segments_for_lsn_range(from, end.saturating_sub(1))
            .collect();
        let mut out = Vec::with_capacity(max.min(1024));
        let mut counters = ScanCounters::default();

        for desc in candidates {
            if out.len() >= max {
                break;
            }
            let generation = desc.active().ok_or_else(|| HeraclitusError::Corruption {
                context: "hrkl v6 scan_capped".into(),
                detail: format!("segmento {} sem geração ativa", desc.segment_id),
            })?;
            let path = resolve_location(&self.root, &generation.location)?;
            let seg_from = from.max(desc.first_lsn);
            let seg_to = end.min(desc.first_lsn.saturating_add(desc.record_count));

            match generation.layout {
                PhysicalLayout::Raw => {
                    let scan = scan_raw_segment(&path)?;
                    for r in scan.records {
                        if r.lsn >= seg_from && r.lsn < seg_to {
                            let mut episode = crate::decode_episode_payload_with_meta(
                                crate::format::FORMAT_VERSION,
                                &r.payload,
                            )?
                            .episode;
                            crate::decrypt_storage_episode_in_place(
                                &mut episode,
                                self.keystore.as_deref(),
                            )?;
                            out.push((r.lsn, episode));
                            if out.len() >= max {
                                break;
                            }
                        }
                    }
                }
                PhysicalLayout::Packed => {
                    let reader = open_packed(&path, HARD_MAX_BLOCK_BYTES)?;
                    let rows = reader.scan_lsn_range(seg_from, seg_to, &mut counters)?;
                    for (lsn, _timestamp, payload) in rows {
                        let mut episode = crate::decode_episode_payload_with_meta(
                            crate::format::FORMAT_VERSION,
                            &payload,
                        )?
                        .episode;
                        crate::decrypt_storage_episode_in_place(
                            &mut episode,
                            self.keystore.as_deref(),
                        )?;
                        out.push((lsn, episode));
                        if out.len() >= max {
                            break;
                        }
                    }
                }
            }
        }

        // Se ainda não atingiu o limite max e o intervalo se estende para o segmento ativo (raw)
        if out.len() < max {
            let active_info = {
                let state = self.lock_state()?;
                state
                    .active
                    .as_ref()
                    .map(|active| (active.path.clone(), active.writer.header().first_lsn))
            };
            if let Some((path, active_first_lsn)) = active_info {
                if end > active_first_lsn {
                    let seg_from = from.max(active_first_lsn);
                    let scan = scan_raw_segment(&path)?;
                    for r in scan.records {
                        if r.lsn >= seg_from && r.lsn < end {
                            // Evitar duplicados caso já tenha sido incluído por um candidato selado
                            if out.last().map(|(l, _)| *l >= r.lsn).unwrap_or(false) {
                                continue;
                            }
                            let mut episode = crate::decode_episode_payload_with_meta(
                                crate::format::FORMAT_VERSION,
                                &r.payload,
                            )?
                            .episode;
                            crate::decrypt_storage_episode_in_place(
                                &mut episode,
                                self.keystore.as_deref(),
                            )?;
                            out.push((r.lsn, episode));
                            if out.len() >= max {
                                break;
                            }
                        }
                    }
                }
            }
        }

        Ok(out)
    }

    /// Fonte local exacta que pode ser publicada no cold tier v6.
    pub fn active_packed_generation(
        &self,
        segment_id: SegmentId,
    ) -> Result<Option<PackedGenerationSource>, HeraclitusError> {
        let state = self.lock_state()?;
        let Some(desc) = state.manifest.segment(segment_id) else {
            return Ok(None);
        };
        let active = desc.active().ok_or_else(|| HeraclitusError::Corruption {
            context: "hrkl v6 demotion source".into(),
            detail: format!("segmento {segment_id} sem geração ativa"),
        })?;
        if active.layout != PhysicalLayout::Packed {
            return Ok(None);
        }
        let source_generation = desc
            .generations
            .iter()
            .filter(|g| g.layout == PhysicalLayout::Raw && g.generation < active.generation)
            .map(|g| g.generation)
            .max();
        Ok(Some(PackedGenerationSource {
            segment_id,
            generation: active.generation,
            source_generation,
            created_hlc: active.created_hlc,
            path: resolve_location(&self.root, &active.location)?,
        }))
    }

    /// Igualdade exacta sobre built-ins com pruning conservador por HRKI.
    ///
    /// O Bloom só elimina um segmento quando prova ausência. Sidecar ausente,
    /// corrompido ou construído sob uma política sem o campo cai no scan do
    /// `.hrkl`; por isso a optimização nunca participa da correcção.
    pub fn scan_builtin_eq_capped(
        &self,
        field: &str,
        value: &str,
        from: Lsn,
        to: Lsn,
        max: usize,
    ) -> Result<crate::store::PrunedScan, HeraclitusError> {
        if !matches!(field, "agent_id" | "session_id") {
            return Ok(None);
        }
        let end = to.min(self.head());
        if from >= end || max == 0 {
            return Ok(Some((Vec::new(), Default::default())));
        }

        let criterio = BuiltinEqCriteria {
            field,
            value,
            from,
            to: end,
            max,
        };
        let manifest = self.manifest();
        let mut stats = crate::store::PrunedScanStats {
            segments_total: manifest.segments_v2.len() as u64,
            ..Default::default()
        };
        let mut out = Vec::with_capacity(max.min(1024));
        let candidates: Vec<_> = manifest
            .segments_for_lsn_range(from, end.saturating_sub(1))
            .collect();
        stats.manifest_pruned = stats.segments_total.saturating_sub(candidates.len() as u64);
        for desc in candidates {
            if out.len() >= max {
                break;
            }
            stats.segments_candidate += 1;
            let generation = desc.active().ok_or_else(|| HeraclitusError::Corruption {
                context: "hrkl v6 pruned scan".into(),
                detail: format!("segmento {} sem geração ativa", desc.segment_id),
            })?;
            let path = resolve_location(&self.root, &generation.location)?;
            stats.bytes_candidate += generation.physical_size;
            match generation.layout {
                PhysicalLayout::Raw => {
                    let scan = scan_raw_segment(&path)?;
                    stats.segments_read += 1;
                    stats.blocks_candidate += 1;
                    stats.blocks_read += 1;
                    stats.bytes_physical_read += std::fs::metadata(&path)?.len();
                    self.collect_builtin_matches(
                        scan.records.iter().map(|r| (r.lsn, r.payload.as_slice())),
                        &criterio,
                        &mut out,
                    )?;
                }
                PhysicalLayout::Packed => {
                    let reader = open_packed(&path, HARD_MAX_BLOCK_BYTES)?;
                    let sidecar_path = caminho_sidecar(&path);
                    let sidecar_declared = desc.hrki.as_ref();
                    let sidecar = sidecar_declared.and_then(|artifact| {
                        let catalog_path = resolve_location(&self.root, &artifact.location).ok()?;
                        if catalog_path != sidecar_path
                            || artifact.logical_root != desc.logical_root
                            || physical_digest_of_file(&sidecar_path).ok()? != artifact.digest
                        {
                            return None;
                        }
                        Hrki::ler_validado(&path, desc.segment_id, &desc.logical_root)
                    });
                    if let Some(hrki) = sidecar {
                        stats.hrki_used += 1;
                        if !hrki.talvez_contenha(field, value.as_bytes()) {
                            stats.segments_pruned += 1;
                            stats.hrki_pruned += 1;
                            stats.blocks_candidate += reader.block_count() as u64;
                            stats.blocks_pruned += reader.block_count() as u64;
                            stats.bytes_pruned += generation.physical_size;
                            continue;
                        }
                    } else if sidecar_declared.is_some() || sidecar_path.is_file() {
                        stats.hrki_ignored += 1;
                        stats.hrki_misses += 1;
                    } else {
                        stats.hrki_misses += 1;
                    }

                    let mut packed = ScanCounters::default();
                    let rows = reader.scan_lsn_range(
                        from.max(desc.first_lsn),
                        end.saturating_sub(1).min(desc.last_lsn),
                        &mut packed,
                    )?;
                    stats.segments_read += 1;
                    stats.blocks_candidate += packed.blocks_candidate;
                    stats.blocks_pruned += packed.blocks_pruned;
                    stats.blocks_read += packed.blocks_read;
                    stats.bytes_pruned += packed.bytes_pruned;
                    stats.bytes_physical_read += packed.bytes_physical_read;
                    stats.bytes_decompressed += packed.bytes_decompressed;
                    self.collect_builtin_matches(
                        rows.iter()
                            .map(|(lsn, _, payload)| (*lsn, payload.as_slice())),
                        &criterio,
                        &mut out,
                    )?;
                }
            }
        }

        if out.len() < max {
            // O tail é mutável: lê-se sob o mesmo mutex do writer para nunca
            // interpretar um frame parcialmente escrito.
            let state = self.lock_state()?;
            if let Some(active) = state.active.as_ref() {
                let first = active.writer.header().first_lsn;
                if first < end && state.next_lsn > from {
                    stats.segments_total += 1;
                    stats.segments_candidate += 1;
                    stats.segments_read += 1;
                    stats.blocks_candidate += 1;
                    stats.blocks_read += 1;
                    let active_bytes = std::fs::metadata(&active.path)?.len();
                    stats.bytes_candidate += active_bytes;
                    stats.bytes_physical_read += active_bytes;
                    let scan = scan_raw_segment(&active.path)?;
                    self.collect_builtin_matches(
                        scan.records.iter().map(|r| (r.lsn, r.payload.as_slice())),
                        &criterio,
                        &mut out,
                    )?;
                }
            }
        }
        self.observe_pruned_scan(&stats);
        Ok(Some((out, stats)))
    }

    /// Verifica a cauda RAW activa sob o mutex do writer.
    ///
    /// A cauda ainda não possui footer/Merkle por definição, mas não pode ser
    /// omitida por uma verificação operacional do banco: validamos header,
    /// CRC/framing, continuidade de LSN, HLC do frame versus payload e o número
    /// exacto de records esperado pelo estado em memória. Uma cauda rasgada só
    /// é reparada no boot; enquanto o processo está vivo ela é corrupção.
    pub fn verify_active_tail(&self) -> Result<u64, HeraclitusError> {
        let result: Result<u64, HeraclitusError> = (|| {
            let state = self.lock_state()?;
            let active = state
                .active
                .as_ref()
                .ok_or_else(|| HeraclitusError::StorageEngine("V6Log sem segmento ativo".into()))?;
            let expected_first = next_lsn_from_manifest(&state.manifest)?;
            let scan = scan_raw_segment(&active.path)?;
            check_header_identity(
                &scan.header,
                active.id,
                state.manifest.storage_namespace_id,
                PhysicalLayout::Raw,
            )?;
            validate_active_records(&scan, expected_first)?;
            let scanned_next = expected_first
                .checked_add(scan.records.len() as u64)
                .ok_or_else(|| corrupt("hrkl v6 verify active", "record count overflows LSN"))?;
            if scanned_next != state.next_lsn {
                return Err(corrupt(
                    "hrkl v6 verify active",
                    format!(
                        "active tail reaches LSN {scanned_next}, in-memory head is {}",
                        state.next_lsn
                    ),
                ));
            }
            for record in &scan.records {
                let decoded = crate::decode_episode_payload_with_meta(
                    crate::format::FORMAT_VERSION,
                    &record.payload,
                )?;
                if decoded.episode.ts_hlc != record.hlc {
                    return Err(corrupt(
                        "hrkl v6 verify active",
                        format!(
                            "LSN {} has frame HLC {} but payload HLC {}",
                            record.lsn, record.hlc, decoded.episode.ts_hlc
                        ),
                    ));
                }
            }
            Ok(scan.records.len() as u64)
        })();
        if result.is_err() {
            self.metrics
                .physical_crc_failures
                .fetch_add(1, Ordering::Relaxed);
        }
        result
    }

    /// Executa verificação física/lógica sobre todas as gerações seladas
    /// catalogadas. A cauda activa não entra porque ainda não tem
    /// footer/manifesto; chama-se `seal_active` antes de uma auditoria final.
    ///
    /// Isso inclui RAW `Superseded`: continua a ser uma autoridade canónica
    /// até ao GC, logo o seu digest não pode deixar de ser confrontado apenas
    /// porque uma PACKED mais nova passou a ser a geração de leitura.
    pub fn verify_sealed(
        &self,
        level: IntegrityLevel,
    ) -> Result<Vec<VerifyReport>, HeraclitusError> {
        let manifest = self.manifest();
        let generation_count = manifest
            .segments_v2
            .iter()
            .map(|desc| desc.canonical_authorities().count())
            .sum();
        let mut reports = Vec::with_capacity(generation_count);
        for desc in &manifest.segments_v2 {
            if desc.active().is_none() {
                return Err(HeraclitusError::Corruption {
                    context: "hrkl v6 verify".into(),
                    detail: format!("segmento {} sem geração ativa", desc.segment_id),
                });
            }
            for generation in desc.canonical_authorities() {
                let path = resolve_location(&self.root, &generation.location)?;
                if level >= IntegrityLevel::Physical
                    && physical_digest_of_file(&path)? != generation.physical_digest
                {
                    self.metrics
                        .physical_crc_failures
                        .fetch_add(1, Ordering::Relaxed);
                    return Err(HeraclitusError::Corruption {
                        context: format!(
                            "hrkl v6 verify segmento {} geração {}",
                            desc.segment_id, generation.generation
                        ),
                        detail: "catalogued physical digest mismatch".into(),
                    });
                }
                let report = match verify_segment_file(
                    &path,
                    level,
                    HARD_MAX_BLOCK_BYTES,
                    (level >= IntegrityLevel::Logical).then_some(&persisted_hasher),
                ) {
                    Ok(report) => report,
                    Err(error) => {
                        if level >= IntegrityLevel::Physical {
                            self.metrics
                                .physical_crc_failures
                                .fetch_add(1, Ordering::Relaxed);
                        }
                        return Err(error);
                    }
                };
                if !report.is_ok() {
                    if !report.physical_ok {
                        self.metrics
                            .physical_crc_failures
                            .fetch_add(1, Ordering::Relaxed);
                    }
                    if report.logical_ok == Some(false) {
                        self.metrics
                            .canonical_verify_failures
                            .fetch_add(1, Ordering::Relaxed);
                    }
                    return Err(HeraclitusError::Corruption {
                        context: format!(
                            "hrkl v6 verify segmento {} geração {}",
                            desc.segment_id, generation.generation
                        ),
                        detail: report.notes.join("; "),
                    });
                }
                reports.push(report);
            }
        }
        Ok(reports)
    }

    /// Verifica somente o segmento lógico solicitado, uma entrada por geração
    /// física ainda catalogada. `None` distingue "segmento desconhecido" de um
    /// segmento conhecido com relatório vazio; a cauda activa não é
    /// catalogada nem verificável como geração selada.
    pub fn verify_segment(
        &self,
        id: SegmentId,
        level: IntegrityLevel,
    ) -> Result<Option<Vec<VerifyReport>>, HeraclitusError> {
        let manifest = self.manifest();
        let Some(desc) = manifest.segment(id) else {
            return Ok(None);
        };
        if desc.active().is_none() {
            return Err(HeraclitusError::Corruption {
                context: "hrkl v6 verify".into(),
                detail: format!("segmento {id} sem geração ativa"),
            });
        }

        let mut reports = Vec::with_capacity(desc.canonical_authorities().count());
        for generation in desc.canonical_authorities() {
            let path = resolve_location(&self.root, &generation.location)?;
            if level >= IntegrityLevel::Physical
                && physical_digest_of_file(&path)? != generation.physical_digest
            {
                self.metrics
                    .physical_crc_failures
                    .fetch_add(1, Ordering::Relaxed);
                return Err(HeraclitusError::Corruption {
                    context: format!(
                        "hrkl v6 verify segmento {id} geração {}",
                        generation.generation
                    ),
                    detail: "catalogued physical digest mismatch".into(),
                });
            }
            let report = match verify_segment_file(
                &path,
                level,
                HARD_MAX_BLOCK_BYTES,
                (level >= IntegrityLevel::Logical).then_some(&persisted_hasher),
            ) {
                Ok(report) => report,
                Err(error) => {
                    if level >= IntegrityLevel::Physical {
                        self.metrics
                            .physical_crc_failures
                            .fetch_add(1, Ordering::Relaxed);
                    }
                    return Err(error);
                }
            };
            if !report.is_ok() {
                if !report.physical_ok {
                    self.metrics
                        .physical_crc_failures
                        .fetch_add(1, Ordering::Relaxed);
                }
                if report.logical_ok == Some(false) {
                    self.metrics
                        .canonical_verify_failures
                        .fetch_add(1, Ordering::Relaxed);
                }
                return Err(HeraclitusError::Corruption {
                    context: format!(
                        "hrkl v6 verify segmento {id} geração {}",
                        generation.generation
                    ),
                    detail: report.notes.join("; "),
                });
            }
            reports.push(report);
        }
        Ok(Some(reports))
    }

    /// Marca uma geração física conhecida como corrompida e publica no HRKM
    /// a melhor autoridade restante. A geração não é apagada: fica auditável
    /// e só o GC, sob política explícita, poderá recolhê-la.
    pub fn quarantine_generation(
        &self,
        segment_id: SegmentId,
        generation: u32,
    ) -> Result<u32, HeraclitusError> {
        let mut state = self.lock_state()?;
        let before = state.manifest.clone();
        let reactivated = match quarantine_manifest_generation(
            &mut state.manifest,
            segment_id,
            generation,
            self.hlc.now(),
        ) {
            Ok(generation) => generation,
            Err(err) => {
                state.manifest = before;
                return Err(err);
            }
        };
        if let Err(err) = self.manifest_store.commit(&mut state.manifest) {
            state.manifest = before;
            return Err(err);
        }
        Ok(reactivated)
    }

    /// Fluxo operacional de §127: quarentena o PACKED mau, reactiva o RAW
    /// equivalente e cria uma nova geração PACKED sem tocar no histórico
    /// lógico. O retorno inclui todos os jobs que estavam pendentes na fila.
    pub fn quarantine_and_repack(
        &self,
        segment_id: SegmentId,
        generation: u32,
        profile: PackingProfile,
    ) -> Result<Vec<PackOutcome>, HeraclitusError> {
        self.quarantine_generation(segment_id, generation)?;
        self.pack_pending(profile)
    }

    /// Processa a fila persistida de RAW selados fora do hot path de append.
    ///
    /// O mutex `state` é mantido apenas para fotografar um job e para publicar
    /// a nova geração no HRKM. Compressão, hashes e fsync acontecem sem ele;
    /// portanto appends continuam enquanto o PACKED é produzido.
    pub fn pack_pending(
        &self,
        profile: PackingProfile,
    ) -> Result<Vec<PackOutcome>, HeraclitusError> {
        let _packing = self
            .packing_lock
            .lock()
            .map_err(|_| HeraclitusError::StorageEngine("v6 packing lock poisoned".into()))?;
        let queue = self.lock_state()?.manifest.packing_queue();
        let mut outcomes = Vec::with_capacity(queue.len());
        for id in queue {
            let (desc, source_location, source_generation) = {
                let state = self.lock_state()?;
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
                (desc.clone(), source.location.clone(), source.generation)
            };
            let source_path = resolve_location(&self.root, &source_location)?;
            let target_generation = next_physical_generation(&self.segments_dir, &desc)?;
            let target_path = packed_path(&self.segments_dir, id, target_generation);
            let options = PackOptions {
                profile,
                ..PackOptions::default()
            };
            // Deliberadamente SEM `state`: esta é a parte cara.
            let pack_started = Instant::now();
            let outcome = pack_segment(
                &source_path,
                &target_path,
                options,
                source_generation,
                target_generation,
                &persisted_hasher,
            )?;
            self.metrics
                .pack_nanos
                .fetch_add(saturating_nanos(pack_started.elapsed()), Ordering::Relaxed);
            self.metrics
                .pack_source_bytes
                .fetch_add(outcome.receipt.source_physical_size, Ordering::Relaxed);
            self.metrics
                .pack_target_bytes
                .fetch_add(outcome.receipt.target_physical_size, Ordering::Relaxed);

            // §88 passo 12: a evidência imutável e fsyncada existe antes de o
            // HRKM tornar a geração PACKED ativa. Crash aqui deixa somente
            // PACKED+recibo órfãos; o RAW committed segue como autoridade.
            persist_pack_receipt(&self.root.join("receipts"), &outcome.receipt)?;

            let mut state = self.lock_state()?;
            let current =
                state
                    .manifest
                    .segment(id)
                    .ok_or_else(|| HeraclitusError::Corruption {
                        context: "hrkl v6 pack".into(),
                        detail: format!("segmento {id} desapareceu antes do publish"),
                    })?;
            if current.logical_root != desc.logical_root
                || current.record_count != desc.record_count
                || current.generation(source_generation).is_none()
            {
                return Err(corrupt(
                    "hrkl v6 pack",
                    format!("segmento {id} mudou enquanto era empacotado"),
                ));
            }
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

    /// Variante assíncrona para workers Tokio. O I/O/CPU síncrono é sempre
    /// deslocado para `spawn_blocking`; o executor async nunca é bloqueado.
    pub async fn pack_pending_async(
        self: Arc<Self>,
        profile: PackingProfile,
    ) -> Result<Vec<PackOutcome>, HeraclitusError> {
        tokio::task::spawn_blocking(move || self.pack_pending(profile))
            .await
            .map_err(|e| HeraclitusError::StorageEngine(format!("v6 packing worker: {e}")))?
    }

    /// Reconstrói a fila persistida `PACKED sem HRKI` fora do hot path.
    pub fn build_pending_hrki(
        &self,
        policy: &IndexPolicySet,
        index_key: Option<[u8; 32]>,
        fpr: f64,
    ) -> Result<Vec<HrkiBuildOutcome>, HeraclitusError> {
        let _building = self
            .sidecar_lock
            .lock()
            .map_err(|_| HeraclitusError::StorageEngine("v6 sidecar lock poisoned".into()))?;
        let manifest = self.lock_state()?.manifest.clone();
        let mut queue: BTreeSet<SegmentId> = manifest.sidecar_queue().into_iter().collect();
        let expected_policy = policy.hash();
        for desc in &manifest.segments_v2 {
            let Some(active) = desc.active() else {
                continue;
            };
            if active.layout != PhysicalLayout::Packed {
                continue;
            }
            let packed = resolve_location(&self.root, &active.location)?;
            let sidecar_path = caminho_sidecar(&packed);
            let valid = desc.hrki.as_ref().is_some_and(|artifact| {
                let Ok(catalog_path) = resolve_location(&self.root, &artifact.location) else {
                    return false;
                };
                catalog_path == sidecar_path
                    && artifact.logical_root == desc.logical_root
                    && physical_digest_of_file(&sidecar_path).ok() == Some(artifact.digest)
                    && Hrki::ler_validado(&packed, desc.segment_id, &desc.logical_root)
                        .is_some_and(|h| h.header.index_policy_hash == expected_policy)
            });
            if !valid {
                queue.insert(desc.segment_id);
            }
        }
        let mut outcomes = Vec::with_capacity(queue.len());
        for id in queue {
            let (logical_root, generation, location) = {
                let state = self.lock_state()?;
                let Some(desc) = state.manifest.segment(id) else {
                    continue;
                };
                let Some(active) = desc.active() else {
                    return Err(corrupt(
                        "hrkl v6 hrki build",
                        format!("segmento {id} sem geração ativa"),
                    ));
                };
                if active.layout != PhysicalLayout::Packed {
                    // Depois de uma quarentena pode existir PACKED histórico
                    // enquanto o reader voltou ao RAW. As fronteiras de bloco
                    // do sidecar têm de pertencer ao layout activo.
                    continue;
                }
                (
                    desc.logical_root,
                    active.generation,
                    active.location.clone(),
                )
            };
            let packed = resolve_location(&self.root, &location)?;
            let decode = |payload: &[u8]| {
                let mut episode =
                    crate::decode_episode_payload(crate::format::FORMAT_VERSION, payload).ok()?;
                crate::decrypt_storage_episode_in_place(&mut episode, self.keystore.as_deref())
                    .ok()?;
                Some(episode)
            };
            construir_para_packed(
                &packed,
                policy,
                index_key,
                fpr,
                HARD_MAX_BLOCK_BYTES,
                &decode,
            )?;
            let path = caminho_sidecar(&packed);
            let size = std::fs::metadata(&path)?.len();
            let digest = physical_digest_of_file(&path)?;
            let created_hlc = self.hlc.now();

            let mut state = self.lock_state()?;
            let current = state.manifest.segment(id).ok_or_else(|| {
                corrupt("hrkl v6 hrki publish", format!("segmento {id} desapareceu"))
            })?;
            if current.logical_root != logical_root
                || current.active_generation != generation
                || current
                    .active()
                    .is_none_or(|g| g.layout != PhysicalLayout::Packed)
            {
                // O ficheiro fica órfão e reconstruível; nunca se liga
                // metadata calculada para outra geração física.
                continue;
            }
            let before = state.manifest.clone();
            let artifact = DerivedArtifactRef {
                location: format!("segments/{id:020}.g{generation:04}.packed.hrki"),
                size,
                digest,
                logical_root,
                created_hlc,
            };
            if let Err(err) = attach_sidecar(&mut state.manifest, id, artifact) {
                state.manifest = before;
                return Err(err);
            }
            if let Err(err) = self.manifest_store.commit(&mut state.manifest) {
                state.manifest = before;
                return Err(err);
            }
            outcomes.push(HrkiBuildOutcome {
                segment_id: id,
                generation,
                path,
                size,
                digest,
            });
            self.metrics.hrki_rebuilds.fetch_add(1, Ordering::Relaxed);
        }
        Ok(outcomes)
    }

    pub async fn build_pending_hrki_async(
        self: Arc<Self>,
        policy: IndexPolicySet,
        index_key: Option<[u8; 32]>,
        fpr: f64,
    ) -> Result<Vec<HrkiBuildOutcome>, HeraclitusError> {
        tokio::task::spawn_blocking(move || self.build_pending_hrki(&policy, index_key, fpr))
            .await
            .map_err(|e| HeraclitusError::StorageEngine(format!("v6 HRKI worker: {e}")))?
    }

    /// SPEC-0050 §146 — segmentos canónicos sem projecção Parquet válida.
    ///
    /// A fila nasce do HRKM (`lakehouse_queue`), logo sobrevive a restart sem
    /// estado próprio. Filtra-se aqui o que o exportador não consegue ler: a
    /// projecção deriva do layout **PACKED**, portanto um segmento ainda por
    /// empacotar fica na fila até o packer passar. Isso faz a exportação
    /// atrasar-se em relação ao packing — que é o comportamento correcto, e é
    /// exactamente o que `parquet_export_lag_lsn` mede.
    pub fn lakehouse_pending(&self) -> Result<Vec<LakehousePending>, HeraclitusError> {
        let manifest = self.lock_state()?.manifest.clone();
        let queue: BTreeSet<SegmentId> = manifest.lakehouse_queue().into_iter().collect();
        let mut out = Vec::with_capacity(queue.len());
        for desc in &manifest.segments_v2 {
            if !queue.contains(&desc.segment_id) {
                continue;
            }
            let Some(active) = desc.active() else {
                continue;
            };
            if active.layout != PhysicalLayout::Packed {
                continue;
            }
            out.push(LakehousePending {
                segment_id: desc.segment_id,
                generation: active.generation,
                logical_root: desc.logical_root,
                first_lsn: desc.first_lsn,
                last_lsn: desc.last_lsn,
                packed: resolve_location(&self.root, &active.location)?,
            });
        }
        Ok(out)
    }

    /// SPEC-0050 §104/§146 — regista a projecção Parquet e deixa o HRKM
    /// recalcular o watermark contíguo.
    ///
    /// Repete-se aqui a re-validação que o worker do HRKI faz: entre calcular
    /// o artefacto e comitá-lo, um repack pode ter publicado outra geração
    /// física. Ligar metadata derivada de bytes que já não são os activos
    /// daria um watermark a mentir. Quando a geração se moveu, devolve-se
    /// `Ok(false)` — o ficheiro exportado fica órfão e reexportável, e nada no
    /// manifesto é tocado.
    ///
    /// §209, "nenhuma projecção lakehouse participa da durabilidade do
    /// append": esta função só corre **depois** de o segmento estar selado e
    /// empacotado, e falhar aqui nunca propaga para o caminho de escrita.
    pub fn attach_parquet_projection(
        &self,
        segment_id: SegmentId,
        generation: u32,
        logical_root: [u8; 32],
        artifact: DerivedArtifactRef,
    ) -> Result<bool, HeraclitusError> {
        if artifact.logical_root != logical_root {
            return Err(corrupt(
                "hrkl v6 parquet publish",
                "artefacto Parquet nao carrega a raiz logica que diz exportar",
            ));
        }
        let mut state = self.lock_state()?;
        let Some(current) = state.manifest.segment(segment_id) else {
            return Err(corrupt(
                "hrkl v6 parquet publish",
                format!("segmento {segment_id} desapareceu do manifesto"),
            ));
        };
        if current.logical_root != logical_root
            || current.active_generation != generation
            || current
                .active()
                .is_none_or(|g| g.layout != PhysicalLayout::Packed)
        {
            return Ok(false);
        }
        let before = state.manifest.clone();
        if let Err(err) = attach_parquet(&mut state.manifest, segment_id, artifact) {
            state.manifest = before;
            return Err(err);
        }
        if let Err(err) = self.manifest_store.commit(&mut state.manifest) {
            state.manifest = before;
            return Err(err);
        }
        Ok(true)
    }

    /// Apply or remove a legal hold from every sealed segment intersecting an
    /// inclusive LSN range.  The HRKM update is committed atomically; callers
    /// may safely retry after a crash.
    pub fn set_legal_hold_range(
        &self,
        lsn_start: Lsn,
        lsn_end: Lsn,
        hold: bool,
    ) -> Result<usize, HeraclitusError> {
        if lsn_start > lsn_end {
            return Err(HeraclitusError::Config(
                "legal hold possui intervalo LSN invertido".into(),
            ));
        }
        let mut state = self.lock_state()?;
        let segment_ids: Vec<_> = state
            .manifest
            .segments_v2
            .iter()
            .filter(|segment| lsn_start <= segment.last_lsn && segment.first_lsn <= lsn_end)
            .map(|segment| segment.segment_id)
            .collect();
        if segment_ids.is_empty() {
            return Ok(0);
        }
        let before = state.manifest.clone();
        for segment_id in &segment_ids {
            if let Err(error) = set_legal_hold(&mut state.manifest, *segment_id, hold) {
                state.manifest = before;
                return Err(error);
            }
        }
        if let Err(error) = self.manifest_store.commit(&mut state.manifest) {
            state.manifest = before;
            return Err(error);
        }
        Ok(segment_ids.len())
    }

    /// Rebuild all per-segment HRKM flags from the active event-sourced legal
    /// hold ranges.  This closes the crash/restart window and protects segments
    /// that were sealed after a hold was first recorded.
    pub fn reconcile_legal_hold_ranges(
        &self,
        active_ranges: &[(Lsn, Lsn)],
    ) -> Result<usize, HeraclitusError> {
        if active_ranges.iter().any(|(start, end)| start > end) {
            return Err(HeraclitusError::Config(
                "legal hold possui intervalo LSN invertido".into(),
            ));
        }
        let mut state = self.lock_state()?;
        let desired: Vec<_> = state
            .manifest
            .segments_v2
            .iter()
            .map(|segment| {
                let hold = active_ranges
                    .iter()
                    .any(|(start, end)| *start <= segment.last_lsn && segment.first_lsn <= *end);
                (segment.segment_id, hold)
            })
            .collect();
        let changed = desired
            .iter()
            .filter(|(segment_id, hold)| {
                state
                    .manifest
                    .segment(*segment_id)
                    .is_some_and(|segment| segment.retention.legal_hold != *hold)
            })
            .count();
        if changed == 0 {
            return Ok(0);
        }
        let before = state.manifest.clone();
        for (segment_id, hold) in desired {
            if let Err(error) = set_legal_hold(&mut state.manifest, segment_id, hold) {
                state.manifest = before;
                return Err(error);
            }
        }
        if let Err(error) = self.manifest_store.commit(&mut state.manifest) {
            state.manifest = before;
            return Err(error);
        }
        Ok(changed)
    }

    // -----------------------------------------------------------------
    // SPEC-0050 §90–§97 — garbage collection
    // -----------------------------------------------------------------

    /// O registo de pins de §92.
    ///
    /// **Nenhum leitor interno pina hoje**, e vale dizer porquê em vez de
    /// deixar isso implícito. O que §92 protege é remover uma geração que
    /// alguém está a ler, e o `commit_gc` já é seguro nos dois sistemas onde
    /// isto corre: em Unix o `unlink` de um ficheiro aberto deixa o descritor
    /// válido, e em Windows o `remove_file` falha com sharing violation e a
    /// geração é reportada como `orphaned` — nunca como removida — para uma
    /// passagem posterior. O invariante que impede perda de dados é o §91, que
    /// é verificado por `assert_gc_invariant` e não por pins.
    ///
    /// O registo existe e é honrado pelo plano: quem tiver um leitor de longa
    /// duração (um recall frio, uma exportação) deve pinar por aqui.
    pub fn pins(&self) -> &super::gc::PinRegistry {
        &self.pins
    }

    /// SPEC-0050 §93/§94 — lê a política de retenção de um segmento.
    pub fn retention(
        &self,
        segment_id: SegmentId,
    ) -> Result<Option<heraclitus_core::runtime::RetentionPolicy>, HeraclitusError> {
        Ok(self
            .lock_state()?
            .manifest
            .segment(segment_id)
            .map(|s| s.retention))
    }

    /// Define a política de retenção de um segmento e comita o HRKM.
    ///
    /// Existe porque §93 e §94 são política **por segmento** e até aqui não
    /// tinham superfície nenhuma: o grace period e o legal hold estavam no
    /// formato e no `plan_gc`, e não havia como um operador os definir.
    pub fn set_retention(
        &self,
        segment_id: SegmentId,
        retention: heraclitus_core::runtime::RetentionPolicy,
    ) -> Result<(), HeraclitusError> {
        let mut state = self.lock_state()?;
        let before = state.manifest.clone();
        let Some(desc) = state.manifest.segment_mut(segment_id) else {
            return Err(corrupt(
                "hrkm retention",
                format!("segmento {segment_id} não está catalogado"),
            ));
        };
        desc.retention = retention;
        if let Err(err) = self.manifest_store.commit(&mut state.manifest) {
            state.manifest = before;
            return Err(err);
        }
        Ok(())
    }

    /// SPEC-0050 §94 — legal hold. Bloqueia GC de geração canónica, migração
    /// destrutiva, crypto-shredding e purga de arquivo.
    ///
    /// Separado do [`Self::set_retention`] genérico de propósito: é a operação
    /// que alguém executa sob pressão, com um advogado ao telefone, e tem de
    /// ser impossível de confundir com «ajustar a retenção».
    pub fn set_legal_hold(&self, segment_id: SegmentId, hold: bool) -> Result<(), HeraclitusError> {
        let atual = self.retention(segment_id)?.ok_or_else(|| {
            corrupt(
                "hrkm legal_hold",
                format!("segmento {segment_id} não está catalogado"),
            )
        })?;
        self.set_retention(
            segment_id,
            heraclitus_core::runtime::RetentionPolicy {
                legal_hold: hold,
                ..atual
            },
        )
    }

    /// O plano de GC, sem remover nada (§90). É o que o `--dry-run` mostra.
    ///
    /// Devolve candidatos **e** bloqueados com a razão de cada bloqueio: um GC
    /// que não sabe explicar o que não apagou não é auditável.
    pub fn gc_plan(&self, opts: GcRunOptions) -> Result<super::gc::GcPlan, HeraclitusError> {
        let state = self.lock_state()?;
        Ok(super::gc::plan_gc(
            &state.manifest,
            &self.pins,
            &super::gc::GcOptions {
                now_hlc: self.hlc.now(),
                keep_manifests: opts.keep_manifests,
                collect_quarantined: opts.collect_quarantined,
            },
        ))
    }

    /// Bytes que um GC recuperaria agora, sem executar nada.
    ///
    /// Existe para o arranque poder dizer o número em voz alta. O estado que
    /// esta função mede — gerações RAW superseded que nunca são coletadas —
    /// era invisível: o `record_pack` marca a origem `Superseded` (§88 passo
    /// 13) e, sem ninguém a chamar o GC, ela fica em disco para sempre. Um
    /// banco acaba com RAW **e** PACKED de tudo.
    pub fn gc_reclaimable_bytes(&self) -> Result<u64, HeraclitusError> {
        Ok(self.gc_plan(GcRunOptions::default())?.reclaimable_bytes())
    }

    /// Executa uma passagem de GC (§90–§97).
    ///
    /// A ordem é a do `commit_gc` e não é negociável: validar tudo → publicar
    /// um HRKM que já não referencia os candidatos → remover os bytes. Um
    /// crash entre os dois últimos passos deixa espaço desperdiçado e um
    /// manifesto auto-consistente; a ordem inversa deixaria o HRKM a apontar
    /// para ficheiros ausentes.
    ///
    /// Partilha o `packing_lock` com o packer de propósito: empacotar publica
    /// gerações e o GC remove-as, e as duas coisas a decidir ao mesmo tempo
    /// sobre o mesmo segmento é a corrida que produziria um plano calculado
    /// sobre um manifesto que já mudou.
    pub fn collect_garbage(
        &self,
        opts: GcRunOptions,
    ) -> Result<super::gc::GcExecution, HeraclitusError> {
        let _packing = self
            .packing_lock
            .lock()
            .map_err(|_| HeraclitusError::StorageEngine("v6 packing lock poisoned".into()))?;
        let mut state = self.lock_state()?;
        let plan = super::gc::plan_gc(
            &state.manifest,
            &self.pins,
            &super::gc::GcOptions {
                now_hlc: self.hlc.now(),
                keep_manifests: opts.keep_manifests,
                collect_quarantined: opts.collect_quarantined,
            },
        );
        if plan.is_empty() {
            return Ok(super::gc::GcExecution {
                manifest_generation: state.manifest.manifest_generation,
                removed: Vec::new(),
                orphaned: Vec::new(),
                lakehouse_detached: Vec::new(),
                cold_detached: Vec::new(),
            });
        }
        // O commit do HRKM é sob o lock — muda o estado do motor. Os
        // `unlink` não, e mantê-los aqui dentro parava os appends durante a
        // passagem inteira: irrelevante em regime, mas a PRIMEIRA passagem de
        // um banco que nunca correu GC são milhares de ficheiros.
        let pending = super::gc::commit_gc_manifest(
            &self.manifest_store,
            &mut state.manifest,
            &self.root,
            &plan,
        )?;
        drop(state);
        let execution = super::gc::unlink_gc_targets(pending, &mut |_| Ok(()))?;
        // §90 — manifestos antigos também são lixo, e o `keep` vem da mesma
        // opção para que um operador não tenha dois botões a dizer a mesma
        // coisa.
        self.manifest_store
            .prune_old_manifests(opts.keep_manifests)?;
        Ok(execution)
    }

    /// Variante para workers Tokio: o I/O síncrono sai para `spawn_blocking`,
    /// como no `pack_pending_async`.
    pub async fn collect_garbage_async(
        self: Arc<Self>,
        opts: GcRunOptions,
    ) -> Result<super::gc::GcExecution, HeraclitusError> {
        tokio::task::spawn_blocking(move || self.collect_garbage(opts))
            .await
            .map_err(|e| HeraclitusError::StorageEngine(format!("v6 gc worker: {e}")))?
    }
    /// O HLC do log, para carimbar artefactos derivados com o mesmo relogio
    /// que carimba os canonicos.
    pub fn now_hlc(&self) -> u64 {
        self.hlc.now()
    }

    fn collect_builtin_matches<'a>(
        &self,
        records: impl Iterator<Item = (Lsn, &'a [u8])>,
        criterio: &BuiltinEqCriteria<'_>,
        out: &mut Vec<(Lsn, Episode)>,
    ) -> Result<(), HeraclitusError> {
        let &BuiltinEqCriteria {
            field,
            value,
            from,
            to,
            max,
        } = criterio;
        for (lsn, payload) in records {
            if lsn < from || lsn >= to || out.len() >= max {
                continue;
            }
            let mut episode =
                crate::decode_episode_payload(crate::format::FORMAT_VERSION, payload)?;
            crate::decrypt_storage_episode_in_place(&mut episode, self.keystore.as_deref())?;
            let matches = match field {
                "agent_id" => episode.agent_id == value,
                "session_id" => episode.session_id == value,
                _ => false,
            };
            if matches {
                out.push((lsn, episode));
            }
        }
        Ok(())
    }

    fn append_inner(
        &self,
        episode: Episode,
        expected_lsn: Option<Lsn>,
    ) -> Result<Lsn, HeraclitusError> {
        let mut state = self.lock_state()?;
        self.append_inner_locked(&mut state, episode, expected_lsn)
    }

    fn append_inner_locked(
        &self,
        state: &mut V6State,
        episode: Episode,
        expected_lsn: Option<Lsn>,
    ) -> Result<Lsn, HeraclitusError> {
        let opaque_meta = episode.id.0.to_bytes();
        let payload =
            crate::encode_storage_payload_v6(opaque_meta, &episode, self.keystore.as_deref())?;
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
            .map(|a| {
                a.writer.record_count() > 0
                    && a.writer.bytes_written() + record_len > self.segment_max_bytes
            })
            .unwrap_or(false);
        if needs_roll {
            self.seal_active_locked(state)?;
        }
        let sync_now = should_sync(&self.fsync, state.last_sync);
        {
            let active = state
                .active
                .as_mut()
                .ok_or_else(|| HeraclitusError::StorageEngine("V6Log sem segmento ativo".into()))?;
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
        self.metrics
            .append_bytes
            .fetch_add(record_len, Ordering::Relaxed);
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
        if !changed
            || state.manifest.segment(active.id).map(|s| s.logical_root)
                != Some(footer.logical_root)
        {
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

/// Hash canónico de um payload v6 tal como foi persistido. Exposto para que a
/// verificação do cold tier use exactamente a mesma identidade do writer.
pub fn persisted_record_hash(lsn: Lsn, hlc: u64, payload: &[u8]) -> V6Result<[u8; 32]> {
    persisted_hasher(lsn, hlc, payload)
}

fn should_sync(policy: &FsyncPolicy, last_sync: Instant) -> bool {
    match policy {
        FsyncPolicy::Always => true,
        FsyncPolicy::GroupCommit { interval_ms } => {
            last_sync.elapsed() >= Duration::from_millis(*interval_ms)
        }
    }
}

fn saturating_nanos(duration: Duration) -> u64 {
    u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX)
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
    let report = verify_segment_file(
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

/// Confere que um RAW encontrado no directório pertence ao segmento descrito
/// pelo HRKM, ou que é um órfão seguro deixado pelo GC metadata-first.
///
/// O segundo caso é deliberadamente estreito: apenas uma geração PACKED
/// activa e autoritativa permite ignorar o RAW. A validação normal do boot
/// confronta depois header/footer/layout/raiz dessa PACKED com o descritor.
/// Sem essa autoridade, esconder um RAW não catalogado mascararia corrupção.
fn ensure_catalogued_raw_generation(
    manifest: &DatabaseManifest,
    id: SegmentId,
    path: &Path,
) -> V6Result<()> {
    let expected = raw_location(id);
    let Some(desc) = manifest.segment(id) else {
        return Err(corrupt("hrkl v6 boot", "RAW sem segmento no manifesto"));
    };
    let known = desc.generations.iter().any(|generation| {
        generation.generation == RAW_GENERATION
            && generation.layout == PhysicalLayout::Raw
            && generation.location == expected
    });
    if !known {
        let has_active_packed_authority = desc.active().is_some_and(|generation| {
            generation.layout == PhysicalLayout::Packed && generation.is_canonical_authority()
        });
        if has_active_packed_authority {
            return Ok(());
        }
        return Err(corrupt(
            "hrkl v6 boot",
            format!(
                "RAW {} não é uma geração catalogada do segmento {id}",
                path.display()
            ),
        ));
    }
    Ok(())
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
    let mut maximum = desc
        .generations
        .iter()
        .map(|g| g.generation)
        .max()
        .unwrap_or(0);
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
            if generation.state == heraclitus_core::runtime::GenerationState::Quarantined {
                // O HRKM já reconheceu que estes bytes não são autoridade.
                // Podem continuar no disco para perícia ou já ter sido
                // recolhidos pelo GC; nenhum dos casos pode impedir o boot da
                // geração canónica reactivada.
                continue;
            }
            let path = resolve_location(root, &generation.location)?;
            if !path.is_file() {
                return Err(corrupt(
                    "hrkl v6 boot",
                    format!("catalogued generation is missing: {}", path.display()),
                ));
            }
            let size = std::fs::metadata(&path)?.len();
            if size != generation.physical_size {
                return Err(corrupt(
                    "hrkl v6 boot",
                    format!(
                        "catalogued generation size mismatch for segment {} generation {}",
                        desc.segment_id, generation.generation
                    ),
                ));
            }
            let header = read_v6_header(&path)?;
            check_header_identity(&header, desc.segment_id, namespace, generation.layout)?;
            let footer = read_footer(&path)?.ok_or_else(|| {
                corrupt(
                    "hrkl v6 boot",
                    format!(
                        "catalogued generation has no valid footer: {}",
                        path.display()
                    ),
                )
            })?;
            if footer.record_count != desc.record_count
                || footer.min_lsn != desc.first_lsn
                || footer.max_lsn != desc.last_lsn
                || footer.min_hlc != desc.min_hlc
                || footer.max_hlc != desc.max_hlc
                || footer.logical_root != desc.logical_root
            {
                return Err(corrupt(
                    "hrkl v6 boot",
                    "catalogued generation footer disagrees with manifest",
                ));
            }
            match generation.layout {
                PhysicalLayout::Raw
                    if footer.block_count != 0
                        || footer.block_directory_offset != 0
                        || footer.block_directory_len != 0 =>
                {
                    return Err(corrupt(
                        "hrkl v6 boot",
                        "RAW generation declares PACKED block metadata",
                    ));
                }
                PhysicalLayout::Packed if footer.block_count == 0 => {
                    return Err(corrupt("hrkl v6 boot", "PACKED generation has no blocks"));
                }
                _ => {}
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

/// Gerador único de namespaces v6.
///
/// `pub(crate)` para que a migração (§129) o reutilize em vez de ter o seu
/// próprio: dois geradores de identidade de storage acabariam por divergir, e
/// a identidade é a última coisa que se quer ver a divergir.
pub(crate) fn new_namespace(root: &Path) -> [u8; 16] {
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
    out.packed
        .sort_by_key(|(id, generation, _)| (*id, *generation));
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
        if name
            .strip_suffix(".hrkl")
            .and_then(|id| id.parse::<u64>().ok())
            .is_some()
        {
            // Agora que o v6 é o formato por omissão, esta é a mensagem que um
            // operador vê ao actualizar o binário sem migrar. Tem de dizer o
            // que fazer, e não apenas que se recusa: um erro que descreve o
            // problema sem indicar a saída obriga a ir ler o código-fonte.
            return Err(corrupt(
                "hrkl v6 open",
                format!(
                    "esta pasta contém um log v1--v5 ({}), e o HRKL v6 nunca converte dados implicitamente.
                     
                     Duas saídas:
                       1. migrar (a origem NÃO é alterada):
                            heraclitus migrate-v6 {} <destino-novo>
                          e depois apontar `data_dir` ao destino;
                       2. continuar no formato antigo:
                       storage_format = \"legacy\"   (ou HERACLITUS_STORAGE_FORMAT=legacy)",
                    name,
                    root.display()
                ),
            ));
        }
    }
    Ok(())
}

fn resolve_location(root: &Path, location: &str) -> V6Result<PathBuf> {
    let relative = Path::new(location);
    if relative.is_absolute()
        || relative.components().any(|component| {
            matches!(
                component,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
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
            assert_eq!(
                reopened.read(i).unwrap().unwrap().1.content,
                format!("payload-{i}").into_bytes()
            );
        }
        let reports = reopened.verify_sealed(IntegrityLevel::Logical).unwrap();
        assert!(!reports.is_empty());
    }

    #[test]
    fn boot_uses_catalogue_metadata_and_explicit_verify_detects_bitrot() {
        // §159: arrancar com HRKM não pode reler/re-hashear todos os bytes de
        // uma geração selada. Um flip de payload preserva header, footer e
        // tamanho, portanto o boot pode reconstruir o estado a partir do
        // catálogo; a verificação física explícita continua a apanhá-lo.
        let dir = tempfile::tempdir().unwrap();
        let log = V6Log::open(dir.path(), 1 << 20, FsyncPolicy::Always).unwrap();
        for i in 0..4 {
            log.append(event(i)).unwrap();
        }
        log.seal_active().unwrap();
        drop(log);

        let raw = raw_path(&dir.path().join(SEGMENTS_DIR), 0);
        {
            use std::io::{Read as _, Seek as _, SeekFrom, Write as _};

            // 64 bytes de header + 24 do cabeçalho RAW: este byte pertence ao
            // payload do primeiro record, não ao header nem ao footer.
            let offset = (super::super::header::FILE_HEADER_LEN
                + super::super::raw::RAW_RECORD_HEADER_LEN
                + 1) as u64;
            let mut file = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(&raw)
                .unwrap();
            file.seek(SeekFrom::Start(offset)).unwrap();
            let mut byte = [0u8; 1];
            file.read_exact(&mut byte).unwrap();
            file.seek(SeekFrom::Start(offset)).unwrap();
            file.write_all(&[byte[0] ^ 0x01]).unwrap();
            file.sync_all().unwrap();
        }

        let reopened = V6Log::open(dir.path(), 1 << 20, FsyncPolicy::Always)
            .expect("boot deve usar HRKM, não re-hash integral");
        assert!(
            reopened.verify_sealed(IntegrityLevel::Physical).is_err(),
            "a verificacao fisica explicita tem de confrontar o digest do manifesto"
        );
        assert_eq!(
            reopened.metrics_snapshot().unwrap().physical_crc_failures,
            1,
            "a falha física precisa ser observável operacionalmente"
        );
    }

    #[test]
    fn explicit_active_tail_verify_detects_crc_corruption() {
        let dir = tempfile::tempdir().unwrap();
        let log = V6Log::open(dir.path(), 1 << 20, FsyncPolicy::Always).unwrap();
        log.append(event(0)).unwrap();
        assert_eq!(log.verify_active_tail().unwrap(), 1);

        let active = active_path(&dir.path().join(SEGMENTS_DIR), 0);
        {
            use std::io::{Read as _, Seek as _, SeekFrom, Write as _};
            let offset = (super::super::header::FILE_HEADER_LEN
                + super::super::raw::RAW_RECORD_HEADER_LEN
                + 1) as u64;
            let mut file = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(active)
                .unwrap();
            file.seek(SeekFrom::Start(offset)).unwrap();
            let mut byte = [0u8; 1];
            file.read_exact(&mut byte).unwrap();
            file.seek(SeekFrom::Start(offset)).unwrap();
            file.write_all(&[byte[0] ^ 1]).unwrap();
            file.sync_all().unwrap();
        }

        assert!(log.verify_active_tail().is_err());
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
    fn restart_observes_hlc_from_sealed_manifest_when_active_tail_is_empty() {
        let dir = tempfile::tempdir().unwrap();
        let log = V6Log::open(dir.path(), 1 << 20, FsyncPolicy::Always).unwrap();
        let physical_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        let future_hlc = physical_ms.saturating_add(1_000_000) << 16;
        let mut replicated = event(0);
        replicated.ts_hlc = future_hlc;
        assert_eq!(log.append_replicated(0, replicated).unwrap(), 0);
        log.seal_active().unwrap();
        drop(log);

        // O tail criado pelo seal está vazio. Só o max_hlc do HRKM pode
        // avançar o relógio desta nova instância além do evento selado.
        let reopened = V6Log::open(dir.path(), 1 << 20, FsyncPolicy::Always).unwrap();
        let (lsn, stamped) = reopened.append_stamped(event(1)).unwrap();
        assert_eq!(lsn, 1);
        assert!(
            stamped.ts_hlc > future_hlc,
            "HLC reiniciou atrás do histórico selado: {} <= {future_hlc}",
            stamped.ts_hlc
        );
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
        // Um boot posterior só toca header/footer/metadados das duas gerações
        // (RAW superseded + PACKED activa) e continua a escolher a PACKED.
        drop(log);
        let log = V6Log::open(dir.path(), 170, FsyncPolicy::Always).unwrap();
        assert!(log
            .manifest()
            .segments_v2
            .iter()
            .all(|s| s.active().unwrap().layout == PhysicalLayout::Packed));
        let expected_reports: usize = log
            .manifest()
            .segments_v2
            .iter()
            .map(|segment| segment.generations.len())
            .sum();
        assert_eq!(
            log.verify_sealed(IntegrityLevel::Physical).unwrap().len(),
            expected_reports,
            "a auditoria física inclui o RAW superseded e a PACKED activa"
        );
        for i in 0..50 {
            assert_eq!(
                log.read(i).unwrap().unwrap().1.content,
                format!("payload-{i}").into_bytes()
            );
        }
    }

    #[test]
    fn hrki_prunes_consulta_e_sidecar_corrupto_e_reconstruido() {
        use super::super::hrki::{IndexPolicy, IndexPolicySet};

        let dir = tempfile::tempdir().unwrap();
        let log = V6Log::open(dir.path(), 420, FsyncPolicy::Always).unwrap();
        for i in 0..30 {
            let mut e = event(i);
            e.agent_id = "alice".into();
            log.append(e).unwrap();
        }
        for i in 30..60 {
            let mut e = event(i);
            e.agent_id = "bob".into();
            log.append(e).unwrap();
        }
        log.seal_active().unwrap();
        log.pack_pending(PackingProfile::Balanced).unwrap();

        let policy = IndexPolicySet::new().com("agent_id", IndexPolicy::PublicTechnical);
        let built = log.build_pending_hrki(&policy, None, 0.01).unwrap();
        assert!(!built.is_empty());
        assert!(log.manifest().sidecar_queue().is_empty());

        let (alice, stats) = log
            .scan_builtin_eq_capped("agent_id", "alice", 0, log.head(), usize::MAX)
            .unwrap()
            .unwrap();
        assert_eq!(alice.len(), 30);
        assert!(stats.hrki_used > 0);
        assert!(stats.segments_pruned > 0, "nenhum segmento bob foi podado");

        let victim = built[0].path.clone();
        std::fs::write(&victim, b"hrki-corrompido").unwrap();
        let (none, degraded) = log
            .scan_builtin_eq_capped("agent_id", "ninguém", 0, log.head(), usize::MAX)
            .unwrap()
            .unwrap();
        assert!(none.is_empty());
        assert_eq!(degraded.hrki_ignored, 1);
        assert!(
            degraded.blocks_read > 0,
            "fallback não leu o segmento sem sidecar válido"
        );

        let rebuilt = log.build_pending_hrki(&policy, None, 0.01).unwrap();
        assert_eq!(rebuilt.len(), 1, "o digest/CRC corrupto não entrou na fila");
        let (_, restored) = log
            .scan_builtin_eq_capped("agent_id", "ninguém", 0, log.head(), usize::MAX)
            .unwrap()
            .unwrap();
        assert_eq!(restored.hrki_ignored, 0);
        assert_eq!(
            restored.blocks_read, 0,
            "todos os segmentos deviam ser podados"
        );
    }

    #[test]
    fn packed_corrupto_e_quarentenado_raw_reativado_e_repackado() {
        use std::io::{Read as _, Seek as _, SeekFrom, Write as _};

        let dir = tempfile::tempdir().unwrap();
        let log = V6Log::open(dir.path(), 1 << 20, FsyncPolicy::Always).unwrap();
        for i in 0..40 {
            log.append(event(i)).unwrap();
        }
        log.seal_active().unwrap();
        log.pack_pending(PackingProfile::Balanced).unwrap();
        let source = log.active_packed_generation(0).unwrap().unwrap();
        assert_eq!(source.generation, 1);

        let offset = (super::super::header::FILE_HEADER_LEN
            + super::super::block::BLOCK_HEADER_LEN
            + 1) as u64;
        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&source.path)
            .unwrap();
        file.seek(SeekFrom::Start(offset)).unwrap();
        let mut byte = [0u8; 1];
        file.read_exact(&mut byte).unwrap();
        file.seek(SeekFrom::Start(offset)).unwrap();
        file.write_all(&[byte[0] ^ 1]).unwrap();
        file.sync_all().unwrap();
        drop(file);
        assert!(log.read(0).is_err(), "CRC do PACKED adulterado não falhou");

        let rebuilt = log
            .quarantine_and_repack(0, source.generation, PackingProfile::Balanced)
            .unwrap();
        assert_eq!(rebuilt.len(), 1);
        let manifest = log.manifest();
        let desc = manifest.segment(0).unwrap();
        assert_eq!(desc.active_generation, 2);
        assert_eq!(
            desc.generation(1).unwrap().state,
            heraclitus_core::runtime::GenerationState::Quarantined
        );
        assert_eq!(
            desc.active().unwrap().layout,
            PhysicalLayout::Packed,
            "RAW foi reactivado antes de gerar o PACKED novo"
        );
        for i in 0..40 {
            assert_eq!(
                log.read(i).unwrap().unwrap().1.content,
                format!("payload-{i}").into_bytes()
            );
        }
        assert_eq!(log.verify_sealed(IntegrityLevel::Logical).unwrap().len(), 2);

        drop(log);
        let reopened = V6Log::open(dir.path(), 1 << 20, FsyncPolicy::Always).unwrap();
        assert_eq!(reopened.read(39).unwrap().unwrap().1.content, b"payload-39");
        assert_eq!(reopened.manifest().segment(0).unwrap().active_generation, 2);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn asynchronous_packer_publishes_without_running_on_async_executor() {
        let dir = tempfile::tempdir().unwrap();
        let log = Arc::new(V6Log::open(dir.path(), 170, FsyncPolicy::Always).unwrap());
        for i in 0..50 {
            log.append(event(i)).unwrap();
        }
        log.seal_active().unwrap();

        let outcomes = log
            .clone()
            .pack_pending_async(PackingProfile::Balanced)
            .await
            .unwrap();
        assert!(!outcomes.is_empty());
        assert!(log
            .manifest()
            .segments_v2
            .iter()
            .all(|s| s.active().unwrap().layout == PhysicalLayout::Packed));
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
        let decoded =
            crate::decode_episode_payload_with_meta(crate::format::FORMAT_VERSION, &payload_a)
                .unwrap();
        assert_eq!(decoded.opaque_meta, [0x11; 16]);
        assert_eq!(decoded.episode.id, episode.id);
        assert_ne!(
            persisted_hasher(9, 10, &payload_a).unwrap(),
            persisted_hasher(9, 10, &payload_b).unwrap(),
            "opaque_meta tem de fazer parte da identidade canónica"
        );
    }

    /// O toco de crash tem de sair do inventário ANTES da primeira leitura de
    /// cabeçalho — e o caminho que prova isso é o que não tem manifesto.
    ///
    /// Com manifesto, o `open` toma o ramo `Some(m)` e nunca chama
    /// `discover_namespace`. Sem manifesto — uma base nova antes do primeiro
    /// seal — chama, e o `discover_namespace` lê o header de cada segmento do
    /// inventário. Num ficheiro de zero bytes isso é um `UnexpectedEof` que
    /// aborta o arranque dezenas de linhas antes de qualquer filtro de toco.
    #[test]
    fn um_toco_sem_manifesto_nao_impede_o_arranque() {
        let dir = tempfile::tempdir().unwrap();
        let segments = dir.path().join(SEGMENTS_DIR);
        std::fs::create_dir_all(&segments).unwrap();

        // Exactamente o que o `create_new` deixa quando o processo morre antes
        // do `write_all` do cabeçalho, e sem uma única geração no disco.
        std::fs::write(active_path(&segments, 0), b"").unwrap();
        assert!(!dir.path().join(MANIFESTS_DIR).join("CURRENT").exists());

        let log = V6Log::open(dir.path(), 4096, FsyncPolicy::Always)
            .expect("um toco de crash nao pode impedir o arranque sem manifesto");
        assert_eq!(log.head(), 0);
        assert_eq!(log.append(event(0)).unwrap(), 0);
    }

    /// A variante que perde dados: gerações seladas no disco, o manifesto
    /// desaparecido, e um toco ao lado. O `reconcile_raw` existe precisamente
    /// para reconstruir o catálogo a partir dos RAW selados — mas só corre se o
    /// arranque chegar lá, e o toco matava-o antes.
    #[test]
    fn um_toco_nao_bloqueia_a_reconstrucao_do_catalogo() {
        let dir = tempfile::tempdir().unwrap();
        let log = V6Log::open(dir.path(), 160, FsyncPolicy::Always).unwrap();
        for i in 0..12 {
            log.append(event(i)).unwrap();
        }
        log.flush().unwrap();
        log.seal_active().unwrap();
        drop(log);

        // O manifesto perde-se (restauro parcial, disco, migração falhada).
        std::fs::remove_dir_all(dir.path().join(MANIFESTS_DIR)).unwrap();

        // E um toco fica ao lado dos segmentos selados.
        let segments = dir.path().join(SEGMENTS_DIR);
        std::fs::write(active_path(&segments, 999), b"").unwrap();

        let log = V6Log::open(dir.path(), 160, FsyncPolicy::Always)
            .expect("o toco bloqueou a reconstrucao do catalogo a partir dos RAW selados");
        assert_eq!(
            log.head(),
            12,
            "registos duraveis ficaram inacessiveis por causa do toco"
        );
        assert_eq!(
            log.read(0).unwrap().unwrap().1.content,
            b"payload-0".to_vec()
        );
    }
}
