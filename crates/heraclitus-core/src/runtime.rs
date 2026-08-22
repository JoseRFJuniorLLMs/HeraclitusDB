//! SPEC-011 — runtime infrastructure contracts.
//!
//! Storage abstraction, the atomic database manifest, the derived-artifact
//! lifecycle, and the execution sandbox (budgets + cancellation). These are the
//! *contracts* (traits + plain data); concrete engines implement them in their
//! own crates (`heraclitus-log`, `heraclitus-analytics`, …).
//!
//! Adapted to the real codebase: `Lsn`/`SegmentId` are `u64` aliases, not the
//! draft's newtypes; nothing here pulls Arrow into `core`.

use crate::{Lsn, SegmentId};
use std::sync::atomic::{AtomicBool, Ordering};

// ── §1.1 Database manifest — atomic macro-state ─────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SegmentState {
    Active,
    Frozen,
    Archived,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SegmentDescriptor {
    pub segment_id: SegmentId,
    pub first_lsn: Lsn,
    pub last_lsn: Lsn,
    pub event_count: u64,
    pub payload_hash: [u8; 32],
    pub state: SegmentState,
}

/// The root of storage metadata, swapped atomically on every macro-state change.
///
/// SPEC-0050 §68/§69 — este é **o** catálogo do storage, e o ficheiro `.hrkm`
/// é a sua representação persistente. Os campos `segments_v2` e seguintes são a
/// evolução pedida por §69/§70; `segments` mantém-se como vista legada (v1)
/// para os consumidores de SPEC-011 que só precisam de LSN e estado.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct DatabaseManifest {
    pub manifest_version: u32,
    pub format_identifier: [u8; 4],
    pub segments: Vec<SegmentDescriptor>,
    /// Highest stabilized+audited LSN.
    pub cumulative_watermark: Lsn,
    pub statistics_root_hash: [u8; 32],

    // ── SPEC-0050 §70 ──────────────────────────────────────────────────────
    /// Namespace criptográfico do banco (§20). Imutável durante a existência
    /// lógica da base; um segmento com outro namespace não é nativo.
    pub storage_namespace_id: [u8; 16],
    /// Número da geração deste manifesto (§74). Cada macro-alteração produz
    /// uma nova, e `CURRENT` aponta para a válida.
    pub manifest_generation: u64,
    /// O catálogo v2: identidade lógica separada das representações físicas.
    pub segments_v2: Vec<SegmentDescriptorV2>,
    /// Watermark da projecção analítica (§104/§107). Nunca participa da
    /// durabilidade do append (invariante 6).
    pub exported_through_lsn: Lsn,
}

impl DatabaseManifest {
    /// Segments visible under a read snapshot pinned at `target_lsn`.
    pub fn visible_segments(&self, target_lsn: Lsn) -> impl Iterator<Item = &SegmentDescriptor> {
        self.segments
            .iter()
            .filter(move |s| s.first_lsn <= target_lsn)
    }
}
// ── SPEC-0050 §76–§79, §144–§146 — consultas sobre o catálogo v2 ───────────
//
// Tudo aqui é leitura pura sobre dados já em memória: nenhuma destas funções
// abre um segmento. É o que torna §159 possível — arrancar com um HRKM válido
// não exige varrer cada segmento selado.

impl DatabaseManifest {
    pub fn segment(&self, segment_id: SegmentId) -> Option<&SegmentDescriptorV2> {
        self.segments_v2.iter().find(|s| s.segment_id == segment_id)
    }

    pub fn segment_mut(&mut self, segment_id: SegmentId) -> Option<&mut SegmentDescriptorV2> {
        self.segments_v2
            .iter_mut()
            .find(|s| s.segment_id == segment_id)
    }

    /// Insere ou substitui um descritor, mantendo `segments_v2` ordenado por
    /// `first_lsn` — é essa ordem que torna [`Self::find_segment_for_lsn`] uma
    /// busca binária.
    pub fn upsert_segment(&mut self, desc: SegmentDescriptorV2) {
        match self
            .segments_v2
            .iter()
            .position(|s| s.segment_id == desc.segment_id)
        {
            Some(i) => self.segments_v2[i] = desc,
            None => {
                let at = self
                    .segments_v2
                    .partition_point(|s| s.first_lsn < desc.first_lsn);
                self.segments_v2.insert(at, desc);
            }
        }
    }

    /// SPEC-0050 §78 — `AS OF LSN`: o planner elimina de imediato os segmentos
    /// cujo `first_lsn` é posterior ao alvo.
    pub fn visible_segments_v2(&self, target_lsn: Lsn) -> impl Iterator<Item = &SegmentDescriptorV2> {
        self.segments_v2
            .iter()
            .filter(move |s| s.visible_at(target_lsn))
    }

    /// SPEC-0050 §77 — primeiro nível do point lookup: do LSN ao segmento, por
    /// busca binária no manifesto.
    pub fn find_segment_for_lsn(&self, lsn: Lsn) -> Option<&SegmentDescriptorV2> {
        let idx = self.segments_v2.partition_point(|s| s.last_lsn < lsn);
        let s = self.segments_v2.get(idx)?;
        (s.record_count > 0 && lsn >= s.first_lsn && lsn <= s.last_lsn).then_some(s)
    }

    /// SPEC-0050 §79 — `AS OF TIMESTAMP`: segmentos cujo intervalo de HLC pode
    /// intersectar `[lo, hi]`. Conservador (invariante 8): nunca exclui um
    /// segmento que possa conter registos no intervalo.
    pub fn segments_for_hlc_range(
        &self,
        lo: u64,
        hi: u64,
    ) -> impl Iterator<Item = &SegmentDescriptorV2> {
        self.segments_v2
            .iter()
            .filter(move |s| s.may_contain_hlc_range(lo, hi))
    }

    pub fn segments_for_lsn_range(
        &self,
        lo: Lsn,
        hi: Lsn,
    ) -> impl Iterator<Item = &SegmentDescriptorV2> {
        self.segments_v2
            .iter()
            .filter(move |s| s.may_contain_lsn_range(lo, hi))
    }

    /// SPEC-0050 §144 — a fila de packing **reconstruída do manifesto**, não
    /// da memória: depois de um restart, "SEALED_RAW sem PACKED" continua a ser
    /// a resposta certa sem que nada tenha sobrevivido ao processo anterior.
    pub fn packing_queue(&self) -> Vec<SegmentId> {
        self.segments_v2
            .iter()
            .filter(|s| s.has_raw() && !s.has_packed())
            .map(|s| s.segment_id)
            .collect()
    }

    /// SPEC-0050 §145 — PACKED sem `.hrki`, ou com um `.hrki` cuja
    /// `logical_root` já não corresponde (§56).
    pub fn sidecar_queue(&self) -> Vec<SegmentId> {
        self.segments_v2
            .iter()
            .filter(|s| {
                s.has_packed()
                    && s.hrki
                        .as_ref()
                        .map(|h| h.logical_root != s.logical_root)
                        .unwrap_or(true)
            })
            .map(|s| s.segment_id)
            .collect()
    }

    /// SPEC-0050 §146 — segmentos canónicos ainda sem projecção Parquet
    /// válida. Nenhuma destas filas afecta a correcção do storage.
    pub fn lakehouse_queue(&self) -> Vec<SegmentId> {
        self.segments_v2
            .iter()
            .filter(|s| {
                s.parquet
                    .as_ref()
                    .map(|p| p.logical_root != s.logical_root)
                    .unwrap_or(true)
            })
            .map(|s| s.segment_id)
            .collect()
    }

    /// SPEC-0050 §181 — amplificação de armazenamento, separada em canónica e
    /// derivada. Devolve `(bytes canónicos, bytes derivados)`.
    pub fn storage_bytes(&self) -> (u64, u64) {
        let mut canonical = 0u64;
        let mut derived = 0u64;
        for s in &self.segments_v2 {
            for g in &s.generations {
                canonical += g.physical_size;
            }
            derived += s.hrki.as_ref().map(|h| h.size).unwrap_or(0);
            derived += s.parquet.as_ref().map(|p| p.size).unwrap_or(0);
        }
        (canonical, derived)
    }

    /// Total de registos canónicos catalogados.
    pub fn total_records(&self) -> u64 {
        self.segments_v2.iter().map(|s| s.record_count).sum()
    }
}

// ── §1.1b SPEC-0050 §70–§72 — catálogo v2: uma verdade, várias gerações ─────
//
// A SPEC-0050 §69 é explícita: *não deverá surgir um segundo catálogo
// concorrente ao `DatabaseManifest`*. Por isso o v2 não é um tipo novo ao lado
// deste — são campos **deste** manifesto, e o ficheiro `.hrkm` é a sua
// representação persistente (o codec vive em `heraclitus-log::v6::manifest`,
// porque é uma questão de bytes; a forma do catálogo é um contrato e vive aqui).
//
// O vocabulário físico (`PhysicalLayout`, `CompressionCodec`) também vive aqui
// pela mesma razão: são IDs publicados e estáveis que o manifesto, o packer, o
// tier e a CLI têm de interpretar da mesma maneira. Uma segunda definição em
// qualquer um deles seria uma segunda verdade.

/// Como os bytes de uma geração física estão organizados (SPEC-0050 §24).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum PhysicalLayout {
    Raw = 0,
    Packed = 1,
}

impl PhysicalLayout {
    pub fn from_u8(v: u8) -> Result<Self, crate::HeraclitusError> {
        match v {
            0 => Ok(PhysicalLayout::Raw),
            1 => Ok(PhysicalLayout::Packed),
            other => Err(crate::HeraclitusError::Corruption {
                context: "physical layout".into(),
                detail: format!("unknown physical_layout {other}"),
            }),
        }
    }
    pub fn as_str(self) -> &'static str {
        match self {
            PhysicalLayout::Raw => "RAW",
            PhysicalLayout::Packed => "PACKED",
        }
    }
}

/// Codecs de compressão de bloco (SPEC-0050 §32). Um ID publicado **nunca** é
/// reutilizado com outro significado.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum CompressionCodec {
    Raw = 0,
    Zstd = 1,
    Lz4Raw = 2,
}

impl CompressionCodec {
    pub fn from_u8(v: u8) -> Result<Self, crate::HeraclitusError> {
        match v {
            0 => Ok(CompressionCodec::Raw),
            1 => Ok(CompressionCodec::Zstd),
            2 => Ok(CompressionCodec::Lz4Raw),
            other => Err(crate::HeraclitusError::Corruption {
                context: "compression codec".into(),
                detail: format!("unknown compression codec {other}"),
            }),
        }
    }
    pub fn as_str(self) -> &'static str {
        match self {
            CompressionCodec::Raw => "RAW",
            CompressionCodec::Zstd => "ZSTD",
            CompressionCodec::Lz4Raw => "LZ4_RAW",
        }
    }
}

/// Estado de uma geração física (SPEC-0050 §72).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum GenerationState {
    Writing = 0,
    Verified = 1,
    Active = 2,
    Superseded = 3,
    Archived = 4,
    Quarantined = 5,
}

impl GenerationState {
    pub fn from_u8(v: u8) -> Result<Self, crate::HeraclitusError> {
        match v {
            0 => Ok(GenerationState::Writing),
            1 => Ok(GenerationState::Verified),
            2 => Ok(GenerationState::Active),
            3 => Ok(GenerationState::Superseded),
            4 => Ok(GenerationState::Archived),
            5 => Ok(GenerationState::Quarantined),
            other => Err(crate::HeraclitusError::Corruption {
                context: "generation state".into(),
                detail: format!("unknown generation state {other}"),
            }),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            GenerationState::Writing => "WRITING",
            GenerationState::Verified => "VERIFIED",
            GenerationState::Active => "ACTIVE",
            GenerationState::Superseded => "SUPERSEDED",
            GenerationState::Archived => "ARCHIVED",
            GenerationState::Quarantined => "QUARANTINED",
        }
    }

    /// SPEC-0050 §91 — uma geração neste estado é capaz de reconstruir as
    /// `CanonicalRecord`s do segmento, e o GC nunca pode remover a última.
    ///
    /// **`Superseded` conta.** É o ponto subtil e vale a pena ser explícito:
    /// "superseded" quer dizer *existe uma representação preferível*, não
    /// *estes bytes deixaram de servir*. Uma geração RAW superseded por uma
    /// PACKED continua verificada e legível — é precisamente por isso que §127
    /// pode pôr a PACKED em quarentena e **reactivar a RAW**, e é precisamente
    /// por isso que §93 impõe um grace period antes de a coletar. Se
    /// `Superseded` não contasse, o primeiro packing bem-sucedido deixaria o
    /// segmento com uma única autoridade e a rede de segurança de §91
    /// bloquearia o GC que ela devia autorizar.
    ///
    /// `Writing` não conta (ainda não foi verificada) e `Quarantined` não conta
    /// (foi explicitamente marcada como não confiável).
    pub fn is_canonical_authority(self) -> bool {
        matches!(
            self,
            GenerationState::Verified
                | GenerationState::Active
                | GenerationState::Superseded
                | GenerationState::Archived
        )
    }
}

/// Uma representação física de um segmento (SPEC-0050 §71).
///
/// Várias gerações coexistem com a **mesma** `logical_root` do segmento e
/// `physical_digest` diferentes — é essa a assimetria de §7.3 que autoriza
/// substituir RAW por PACKED sem perder identidade.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PhysicalGeneration {
    pub generation: u32,
    pub layout: PhysicalLayout,
    pub compression: CompressionCodec,
    /// Caminho local ou chave de object storage. Nunca sobrescrita (§83).
    pub location: String,
    pub physical_size: u64,
    pub physical_digest: [u8; 32],
    pub state: GenerationState,
    pub created_hlc: u64,
    /// Quando a verificação lógica passou. `0` = nunca verificada.
    pub verified_hlc: u64,
    /// Quando passou a `Superseded`. `0` = não aplicável. É o relógio do grace
    /// period de §93 — sem ele não há como saber se já passou tempo suficiente.
    pub superseded_hlc: u64,
    /// Cópias canónicas verificadas conhecidas (locais + réplicas + objecto).
    /// SPEC-0050 §184: o GC local só é permitido depois de satisfeita a
    /// política de durabilidade.
    pub verified_copies: u32,
}

impl PhysicalGeneration {
    pub fn is_canonical_authority(&self) -> bool {
        self.state.is_canonical_authority()
    }
}

/// Referência a um artefacto derivado (`.hrki`, projecção Parquet).
///
/// Guarda a `logical_root` do segmento a que corresponde: SPEC-0050 §56 — um
/// sidecar cuja raiz não bate é **ignorado e reconstruído**, nunca tratado
/// como corrupção do `.hrkl`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DerivedArtifactRef {
    pub location: String,
    pub size: u64,
    pub digest: [u8; 32],
    pub logical_root: [u8; 32],
    pub created_hlc: u64,
}

/// Política de retenção por segmento (SPEC-0050 §93, §94, §184).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetentionPolicy {
    /// SPEC-0050 §94 — bloqueia GC de geração canónica, migração destrutiva,
    /// crypto shredding e purga de arquivo.
    pub legal_hold: bool,
    /// SPEC-0050 §93 — quanto tempo uma geração superseded permanece antes de
    /// poder ser coletada.
    pub gc_grace_seconds: u64,
    /// SPEC-0050 §184 — cópias canónicas verificadas exigidas antes de o GC
    /// local poder remover uma geração superseded.
    pub min_verified_copies: u32,
    /// SPEC-0050 §133 — preservar o original legado v1–v5 mesmo depois de
    /// existir a representação v6. Default `true`.
    pub preserve_legacy_original: bool,
}

/// 24h, o valor sugerido em §93. O default definitivo é operacional.
pub const DEFAULT_GC_GRACE_SECONDS: u64 = 86_400;

impl Default for RetentionPolicy {
    fn default() -> Self {
        Self {
            legal_hold: false,
            gc_grace_seconds: DEFAULT_GC_GRACE_SECONDS,
            min_verified_copies: 1,
            preserve_legacy_original: true,
        }
    }
}

/// Descritor de segmento v2 (SPEC-0050 §70).
///
/// A diferença essencial face ao [`SegmentDescriptor`] v1: a identidade
/// (`logical_root`) está separada das representações (`generations`). O v1
/// tinha um único `payload_hash`, o que tornava impossível dizer "isto é o
/// mesmo segmento, noutros bytes".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SegmentDescriptorV2 {
    pub segment_id: SegmentId,
    pub first_lsn: Lsn,
    pub last_lsn: Lsn,
    pub record_count: u64,
    pub canonical_codec: u16,
    pub logical_root: [u8; 32],
    /// Intervalo de HLC do segmento. SPEC-0050 §79 exige-o no manifesto para
    /// que `AS OF TIMESTAMP` possa podar segmentos sem os abrir.
    pub min_hlc: u64,
    pub max_hlc: u64,
    pub active_generation: u32,
    pub generations: Vec<PhysicalGeneration>,
    pub hrki: Option<DerivedArtifactRef>,
    pub parquet: Option<DerivedArtifactRef>,
    pub retention: RetentionPolicy,
}

impl SegmentDescriptorV2 {
    /// A geração que os leitores devem usar.
    pub fn active(&self) -> Option<&PhysicalGeneration> {
        self.generations
            .iter()
            .find(|g| g.generation == self.active_generation)
    }

    pub fn generation(&self, generation: u32) -> Option<&PhysicalGeneration> {
        self.generations.iter().find(|g| g.generation == generation)
    }

    pub fn generation_mut(&mut self, generation: u32) -> Option<&mut PhysicalGeneration> {
        self.generations
            .iter_mut()
            .find(|g| g.generation == generation)
    }

    /// Gerações capazes de reconstruir as `CanonicalRecord`s (§91).
    pub fn canonical_authorities(&self) -> impl Iterator<Item = &PhysicalGeneration> {
        self.generations.iter().filter(|g| g.is_canonical_authority())
    }

    /// `true` se existe pelo menos um layout `PACKED` autoritativo. Usado pela
    /// fila de packing de §144.
    pub fn has_packed(&self) -> bool {
        self.canonical_authorities()
            .any(|g| g.layout == PhysicalLayout::Packed)
    }

    pub fn has_raw(&self) -> bool {
        self.canonical_authorities()
            .any(|g| g.layout == PhysicalLayout::Raw)
    }

    pub fn next_generation_number(&self) -> u32 {
        self.generations
            .iter()
            .map(|g| g.generation)
            .max()
            .map(|m| m + 1)
            .unwrap_or(0)
    }

    /// SPEC-0050 §78 — o planner elimina imediatamente segmentos cujo
    /// `first_lsn` é posterior ao alvo.
    pub fn visible_at(&self, target_lsn: Lsn) -> bool {
        self.first_lsn <= target_lsn
    }

    /// SPEC-0050 §79 — pruning por intervalo de HLC. Conservador: `false` só
    /// sai quando os intervalos são comprovadamente disjuntos.
    pub fn may_contain_hlc_range(&self, lo: u64, hi: u64) -> bool {
        self.record_count == 0 || (self.max_hlc >= lo && self.min_hlc <= hi)
    }

    pub fn may_contain_lsn_range(&self, lo: Lsn, hi: Lsn) -> bool {
        self.record_count == 0 || (self.last_lsn >= lo && self.first_lsn <= hi)
    }
}

// ── §1.2 Storage engine contract ────────────────────────────────────────────

/// Isolates physical persistence (files, mmap, S3) from planners and replay.
pub trait StorageEngine: Send + Sync {
    fn append_raw(&self, payload: &[u8]) -> Result<Lsn, String>;
    fn fetch_segment(&self, segment_id: SegmentId) -> Result<Vec<u8>, String>;
    fn write_manifest(&self, manifest: &DatabaseManifest) -> Result<(), String>;
    fn sync_active_segment(&self) -> Result<(), String>;
}

// ── §3 Derived-artifact lifecycle ───────────────────────────────────────────

/// A logical-intent hash identifying the structural need of a query.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct QueryFingerprint {
    pub logical_intent_hash: [u8; 32],
    pub applicable_snapshot: Lsn,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArtifactType {
    CompressedSparseRow,
    RoaringBitmapFilter,
    VectorCacheHnsw,
    ArrowColumnarBatch,
    /// Per-segment min/max summary used for skip-I/O (SPEC-010).
    ZoneMap,
}

/// Homogeneous lifecycle contract for any accelerator structure (CSR, HNSW
/// cache, roaring filter, Arrow batch) so the manager can treat them uniformly.
pub trait DerivedExecutionArtifact: Send + Sync {
    fn artifact_type(&self) -> ArtifactType;
    fn estimated_memory_usage(&self) -> usize;
    fn query_fingerprint(&self) -> &QueryFingerprint;
}

// ── §4 Execution sandbox — budgets & cancellation ───────────────────────────

/// RAM budget with an explicit OOM guard: reservations that would exceed the
/// cap are rejected instead of aborting the process.
#[derive(Debug)]
pub struct MemoryBudget {
    pub allowed_bytes: usize,
    pub used_bytes: usize,
}

impl MemoryBudget {
    pub fn new(allowed_bytes: usize) -> Self {
        Self {
            allowed_bytes,
            used_bytes: 0,
        }
    }

    /// Reserve `bytes`, or `Err` if it would blow the cap (caller then falls
    /// back to the imperative/streaming path instead of OOM-ing).
    pub fn try_reserve(&mut self, bytes: usize) -> Result<(), String> {
        match self.used_bytes.checked_add(bytes) {
            Some(total) if total <= self.allowed_bytes => {
                self.used_bytes = total;
                Ok(())
            }
            _ => Err(format!(
                "MemoryBudget exceeded: used {} + {} > cap {}",
                self.used_bytes, bytes, self.allowed_bytes
            )),
        }
    }

    pub fn release(&mut self, bytes: usize) {
        self.used_bytes = self.used_bytes.saturating_sub(bytes);
    }
}

#[derive(Debug)]
pub struct CpuBudget {
    pub max_microseconds: u64,
}

/// Cooperative cancellation flag threaded through long operations.
#[derive(Debug, Default)]
pub struct CancellationToken {
    cancelled: AtomicBool,
}

impl CancellationToken {
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
    }
    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }
}

/// Mandatory isolation object for a runtime task: read point + resource limits.
pub struct ExecutionContext {
    pub snapshot_lsn: Lsn,
    pub memory_budget: std::sync::Mutex<MemoryBudget>,
    pub cpu_budget: CpuBudget,
    pub cancellation: std::sync::Arc<CancellationToken>,
}

impl ExecutionContext {
    pub fn new(snapshot_lsn: Lsn, mem_cap: usize, cpu_micros: u64) -> Self {
        Self {
            snapshot_lsn,
            memory_budget: std::sync::Mutex::new(MemoryBudget::new(mem_cap)),
            cpu_budget: CpuBudget {
                max_microseconds: cpu_micros,
            },
            cancellation: std::sync::Arc::new(CancellationToken::default()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_visibility_by_snapshot() {
        let seg = |id, f, l| SegmentDescriptor {
            segment_id: id,
            first_lsn: f,
            last_lsn: l,
            event_count: l - f + 1,
            payload_hash: [0; 32],
            state: SegmentState::Frozen,
        };
        let m = DatabaseManifest {
            segments: vec![seg(0, 0, 9), seg(1, 10, 19), seg(2, 20, 29)],
            cumulative_watermark: 29,
            ..Default::default()
        };
        // A snapshot at LSN 15 sees the first two segments only.
        let ids: Vec<_> = m.visible_segments(15).map(|s| s.segment_id).collect();
        assert_eq!(ids, vec![0, 1]);
    }

    #[test]
    fn memory_budget_guards_oom() {
        let mut b = MemoryBudget::new(1000);
        assert!(b.try_reserve(600).is_ok());
        assert!(
            b.try_reserve(600).is_err(),
            "must reject over-cap reservation"
        );
        assert_eq!(b.used_bytes, 600);
        b.release(600);
        assert!(b.try_reserve(1000).is_ok());
    }

    #[test]
    fn cancellation_token_flips_once() {
        let ctx = ExecutionContext::new(42, 4096, 1_000_000);
        assert!(!ctx.cancellation.is_cancelled());
        ctx.cancellation.cancel();
        assert!(ctx.cancellation.is_cancelled());
        assert_eq!(ctx.snapshot_lsn, 42);
    }

    /// A trivial in-memory `StorageEngine` proves the contract is implementable.
    #[test]
    fn storage_engine_contract_is_implementable() {
        use std::sync::Mutex;
        #[derive(Default)]
        struct MemStore {
            log: Mutex<Vec<Vec<u8>>>,
        }
        impl StorageEngine for MemStore {
            fn append_raw(&self, payload: &[u8]) -> Result<Lsn, String> {
                let mut l = self.log.lock().unwrap();
                l.push(payload.to_vec());
                Ok((l.len() - 1) as Lsn)
            }
            fn fetch_segment(&self, segment_id: SegmentId) -> Result<Vec<u8>, String> {
                self.log
                    .lock()
                    .unwrap()
                    .get(segment_id as usize)
                    .cloned()
                    .ok_or_else(|| "no such segment".into())
            }
            fn write_manifest(&self, _m: &DatabaseManifest) -> Result<(), String> {
                Ok(())
            }
            fn sync_active_segment(&self) -> Result<(), String> {
                Ok(())
            }
        }
        let s = MemStore::default();
        let lsn = s.append_raw(b"hello").unwrap();
        assert_eq!(s.fetch_segment(lsn).unwrap(), b"hello");
    }
}
