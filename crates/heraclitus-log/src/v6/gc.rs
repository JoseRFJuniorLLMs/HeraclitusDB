//! SPEC-0050 §90–§97, §182, §184 — política de garbage collection.
//!
//! # O invariante que organiza o módulo
//!
//! §91, textual:
//!
//! > GC jamais pode remover a última geração física VERIFIED capaz de
//! > reconstruir todas as CanonicalRecords daquele segmento.
//!
//! Tudo o resto — pins, grace period, LegalHold, política de réplicas — são
//! camadas **adicionais** de cautela por cima deste chão. Por isso este módulo
//! não devolve "apaga isto"; devolve um [`GcPlan`] com candidatos **e** com os
//! bloqueados e a razão de cada bloqueio. Um GC que não sabe explicar o que não
//! apagou é um GC que ninguém pode auditar.
//!
//! E, como rede final, [`assert_gc_invariant`] simula o plano contra o
//! manifesto e recusa-o se algum segmento ficar sem autoridade canónica. É
//! redundante de propósito: a lógica de decisão e a lógica de verificação são
//! escritas separadamente, para que um erro numa não passe pela outra.
//!
//! # O que o GC nunca faz
//!
//! §95: apagar um registo. Delete semântico é um evento *tombstone*; o registo
//! antigo permanece no HRKL. §96/§97: uma compactação cujo conjunto de
//! `CanonicalRecord`s difere do input **não** é uma nova representação
//! canónica — é uma projecção, e [`classify_compaction`] existe para que
//! ninguém a registe como geração.

use std::collections::HashMap;
use std::sync::Mutex;

use heraclitus_core::runtime::{DatabaseManifest, GenerationState, PhysicalLayout};
use heraclitus_core::SegmentId;

use super::error::{corrupt, V6Result};

/// O HLC deste motor é `millis << 16 | contador`. O grace period é configurado
/// em segundos, por isso a comparação passa por aqui — e não por uma subtracção
/// crua de HLCs, que compararia contadores lógicos com tempo de parede.
#[inline]
pub fn hlc_millis(hlc: u64) -> u64 {
    hlc >> 16
}

/// `canonical_codec` de um segmento cujos bytes originais precedem o
/// `CanonicalRecordCodecV1` — ou seja, um segmento v1–v5 migrado (§131/§132).
pub const CANONICAL_CODEC_LEGACY: u16 = 0;

// ---------------------------------------------------------------------------
// Pins de leitores (§92)
// ---------------------------------------------------------------------------

/// Contagem de leitores activos por `(segmento, geração)`.
///
/// §92 exige `reader_pin_count == 0` antes de remover uma geração superseded.
/// A chave inclui a geração de propósito: um leitor pinado na geração 1 não
/// deve impedir a coleta da geração 0, e vice-versa.
#[derive(Default)]
pub struct PinRegistry {
    inner: Mutex<HashMap<(SegmentId, u32), u32>>,
}

impl PinRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Pina uma geração enquanto o guard viver.
    pub fn pin(&self, segment_id: SegmentId, generation: u32) -> PinGuard<'_> {
        *self
            .inner
            .lock()
            .unwrap()
            .entry((segment_id, generation))
            .or_insert(0) += 1;
        PinGuard {
            registry: self,
            key: (segment_id, generation),
        }
    }

    pub fn count(&self, segment_id: SegmentId, generation: u32) -> u32 {
        self.inner
            .lock()
            .unwrap()
            .get(&(segment_id, generation))
            .copied()
            .unwrap_or(0)
    }

    pub fn total(&self) -> u32 {
        self.inner.lock().unwrap().values().sum()
    }
}

/// Solta o pin no `Drop`. Um pin largado por `?` a meio de uma leitura seria
/// um segmento eternamente incoletável.
pub struct PinGuard<'a> {
    registry: &'a PinRegistry,
    key: (SegmentId, u32),
}

impl Drop for PinGuard<'_> {
    fn drop(&mut self) {
        let mut m = self.registry.inner.lock().unwrap();
        if let Some(c) = m.get_mut(&self.key) {
            *c = c.saturating_sub(1);
            if *c == 0 {
                m.remove(&self.key);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Plano
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GcOptions {
    /// Relógio de referência para o grace period.
    pub now_hlc: u64,
    /// Quantas gerações de manifesto manter (§90).
    pub keep_manifests: usize,
    /// §127 — gerações em quarentena são evidência de um problema. Coletá-las
    /// exige um pedido explícito, para que um scrub automático não destrua o
    /// ficheiro que a perícia quer ver.
    pub collect_quarantined: bool,
}

impl Default for GcOptions {
    fn default() -> Self {
        Self {
            now_hlc: 0,
            keep_manifests: 3,
            collect_quarantined: false,
        }
    }
}

/// Porque é que uma geração **não** vai ser coletada.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GcBlockReason {
    /// Está em uso: é a geração activa ou ainda não foi substituída.
    NotSuperseded,
    /// §94 — legal hold sobre o segmento.
    LegalHold,
    /// §91 — é a última capaz de reconstruir as CanonicalRecords.
    LastCanonicalAuthority,
    /// §92 — há leitores pinados.
    ReaderPinned { pins: u32 },
    /// §93 — ainda dentro do grace period.
    GracePeriod { remaining_seconds: u64 },
    /// §184 — não há cópias verificadas suficientes.
    InsufficientVerifiedCopies { have: u32, need: u32 },
    /// §127 — em quarentena e `collect_quarantined` desligado.
    Quarantined,
    /// §133 — original legado preservado por política.
    LegacyOriginalPreserved,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GcCandidate {
    pub segment_id: SegmentId,
    pub generation: u32,
    pub location: String,
    pub physical_size: u64,
    pub layout: PhysicalLayout,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GcBlocked {
    pub segment_id: SegmentId,
    pub generation: u32,
    pub location: String,
    pub reason: GcBlockReason,
}

/// Artefacto derivado obsoleto (§90): `.hrki` ou Parquet cuja `logical_root`
/// deixou de corresponder ao segmento.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StaleArtifact {
    pub segment_id: SegmentId,
    pub location: String,
    pub size: u64,
    pub kind: ArtifactKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArtifactKind {
    Hrki,
    Parquet,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GcPlan {
    pub generations: Vec<GcCandidate>,
    pub blocked: Vec<GcBlocked>,
    pub stale_artifacts: Vec<StaleArtifact>,
}

impl GcPlan {
    pub fn reclaimable_bytes(&self) -> u64 {
        self.generations
            .iter()
            .map(|c| c.physical_size)
            .sum::<u64>()
            + self.stale_artifacts.iter().map(|a| a.size).sum::<u64>()
    }
    pub fn is_empty(&self) -> bool {
        self.generations.is_empty() && self.stale_artifacts.is_empty()
    }
}

/// Constrói o plano de GC. **Não** remove nada — só decide e explica.
pub fn plan_gc(m: &DatabaseManifest, pins: &PinRegistry, opts: &GcOptions) -> GcPlan {
    let mut plan = GcPlan::default();

    for s in &m.segments_v2 {
        // Quantas autoridades canónicas sobram se removermos uma dada geração.
        let autoridades: Vec<u32> = s.canonical_authorities().map(|g| g.generation).collect();

        for g in &s.generations {
            let bloqueio = if g.generation == s.active_generation {
                Some(GcBlockReason::NotSuperseded)
            } else if g.state == GenerationState::Quarantined && !opts.collect_quarantined {
                Some(GcBlockReason::Quarantined)
            } else if !matches!(
                g.state,
                GenerationState::Superseded | GenerationState::Quarantined
            ) {
                Some(GcBlockReason::NotSuperseded)
            } else if s.retention.legal_hold {
                // §94 antes de tudo o resto: um legal hold não é negociável
                // por tempo decorrido nem por número de cópias.
                Some(GcBlockReason::LegalHold)
            } else if s.retention.preserve_legacy_original
                && s.canonical_codec == CANONICAL_CODEC_LEGACY
                && g.generation == 0
            {
                // §133 — quando há RFC3161, assinatura, legal hold ou processo
                // pericial a referir o hash antigo, os bytes originais do
                // segmento legado ficam.
                Some(GcBlockReason::LegacyOriginalPreserved)
            } else if autoridades.contains(&g.generation) && autoridades.len() <= 1 {
                Some(GcBlockReason::LastCanonicalAuthority)
            } else {
                let pinned = pins.count(s.segment_id, g.generation);
                if pinned > 0 {
                    Some(GcBlockReason::ReaderPinned { pins: pinned })
                } else if let Some(faltam) =
                    grace_remaining(g.superseded_hlc, opts.now_hlc, s.retention.gc_grace_seconds)
                {
                    Some(GcBlockReason::GracePeriod {
                        remaining_seconds: faltam,
                    })
                } else if melhor_contagem(s, g.generation) < s.retention.min_verified_copies {
                    Some(GcBlockReason::InsufficientVerifiedCopies {
                        have: melhor_contagem(s, g.generation),
                        need: s.retention.min_verified_copies,
                    })
                } else {
                    None
                }
            };

            match bloqueio {
                Some(reason) => plan.blocked.push(GcBlocked {
                    segment_id: s.segment_id,
                    generation: g.generation,
                    location: g.location.clone(),
                    reason,
                }),
                None => plan.generations.push(GcCandidate {
                    segment_id: s.segment_id,
                    generation: g.generation,
                    location: g.location.clone(),
                    physical_size: g.physical_size,
                    layout: g.layout,
                }),
            }
        }

        // §90 — derivados obsoletos. Nunca bloqueiam nada: um `.hrki` cuja raiz
        // não bate já é ignorado pelo leitor (§56), e o Parquet é regenerável
        // por definição (§126).
        if let Some(h) = &s.hrki {
            if h.logical_root != s.logical_root {
                plan.stale_artifacts.push(StaleArtifact {
                    segment_id: s.segment_id,
                    location: h.location.clone(),
                    size: h.size,
                    kind: ArtifactKind::Hrki,
                });
            }
        }
        if let Some(p) = &s.parquet {
            if p.logical_root != s.logical_root {
                plan.stale_artifacts.push(StaleArtifact {
                    segment_id: s.segment_id,
                    location: p.location.clone(),
                    size: p.size,
                    kind: ArtifactKind::Parquet,
                });
            }
        }
    }

    plan
}

/// Cópias verificadas que *sobrariam* se esta geração desaparecesse: a soma das
/// outras autoridades canónicas do mesmo segmento (§184).
fn melhor_contagem(s: &heraclitus_core::runtime::SegmentDescriptorV2, excluir: u32) -> u32 {
    s.generations
        .iter()
        .filter(|g| g.generation != excluir && g.is_canonical_authority())
        .map(|g| g.verified_copies)
        .max()
        .unwrap_or(0)
}

/// Segundos que faltam para o grace period expirar, ou `None` se já expirou.
fn grace_remaining(superseded_hlc: u64, now_hlc: u64, grace_seconds: u64) -> Option<u64> {
    if superseded_hlc == 0 {
        // Sem carimbo não há como afirmar que o tempo passou. Tratar como
        // "ainda dentro" é a leitura conservadora.
        return Some(grace_seconds);
    }
    let decorrido_ms = hlc_millis(now_hlc).saturating_sub(hlc_millis(superseded_hlc));
    let necessario_ms = grace_seconds.saturating_mul(1_000);
    if decorrido_ms >= necessario_ms {
        None
    } else {
        Some((necessario_ms - decorrido_ms).div_ceil(1_000))
    }
}

/// Rede de segurança de §91, escrita independentemente de [`plan_gc`].
///
/// Simula a aplicação do plano e recusa-o se algum segmento ficar sem geração
/// autoritativa. Chamar isto antes de apagar seja o que for é barato e é a
/// diferença entre um bug de política e perda de histórico.
pub fn assert_gc_invariant(m: &DatabaseManifest, plan: &GcPlan) -> V6Result<()> {
    const CTX: &str = "hrkl v6 gc";
    for s in &m.segments_v2 {
        let a_remover: Vec<u32> = plan
            .generations
            .iter()
            .filter(|c| c.segment_id == s.segment_id)
            .map(|c| c.generation)
            .collect();
        let antes = s.canonical_authorities().count();
        let sobram = s
            .canonical_authorities()
            .filter(|g| !a_remover.contains(&g.generation))
            .count();
        // Um segmento que JÁ chegou aqui sem autoridade é uma falha canónica
        // de §128, não um plano mau — e aparece em
        // `BootReport::segments_without_authority`. O que este invariante
        // proíbe é o plano *causar* a perda.
        if antes > 0 && sobram == 0 {
            return Err(corrupt(
                CTX,
                format!(
                    "plan would leave segment {} without a canonical authority",
                    s.segment_id
                ),
            ));
        }
        if a_remover.contains(&s.active_generation) {
            return Err(corrupt(
                CTX,
                format!(
                    "plan would remove the active generation of segment {}",
                    s.segment_id
                ),
            ));
        }
    }
    Ok(())
}

/// Aplica o plano ao manifesto **em memória**, removendo as gerações coletadas.
///
/// Não toca no disco: quem chama remove os ficheiros e só depois faz commit do
/// manifesto novo. A ordem importa — se o manifesto fosse committed primeiro e
/// a remoção falhasse, ficariam ficheiros que ninguém sabe que existem.
pub fn apply_gc(m: &mut DatabaseManifest, plan: &GcPlan) -> V6Result<()> {
    assert_gc_invariant(m, plan)?;
    for c in &plan.generations {
        if let Some(s) = m.segment_mut(c.segment_id) {
            s.generations.retain(|g| g.generation != c.generation);
        }
    }
    for a in &plan.stale_artifacts {
        if let Some(s) = m.segment_mut(a.segment_id) {
            match a.kind {
                ArtifactKind::Hrki => s.hrki = None,
                ArtifactKind::Parquet => s.parquet = None,
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// §96/§97 — o que é e o que não é uma representação canónica
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompactionClass {
    /// Mesmas `CanonicalRecord`s: pode substituir a geração canónica.
    Canonical,
    /// Conjunto diferente: é uma projecção analítica e **nunca** substitui o
    /// segmento original (§96/§97).
    Projection,
}

/// Classifica o output de uma compactação comparando raízes lógicas.
///
/// Existe para que uma operação equivalente a `compact_cold(... is_deleted ...)`
/// — que produz um `.hrkl` omitindo registos — não possa ser registada como
/// geração canónica por distracção.
pub fn classify_compaction(input_root: &[u8; 32], output_root: &[u8; 32]) -> CompactionClass {
    if input_root == output_root {
        CompactionClass::Canonical
    } else {
        CompactionClass::Projection
    }
}

// ---------------------------------------------------------------------------
// §182 — espaço temporário de packing
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PackingSpace {
    Ok,
    /// Adiar o packing local. §182: nunca apagar o RAW primeiro à espera de que
    /// o pack corra bem depois.
    Defer {
        need_bytes: u64,
        free_bytes: u64,
    },
}

/// Verifica se há espaço para manter RAW **e** PACKED durante o packing.
///
/// `safety_factor` é a margem sobre o tamanho da fonte; 1.0 seria assumir
/// compressão perfeita e zero fragmentação.
pub fn check_packing_space(source_size: u64, free_bytes: u64, safety_factor: f64) -> PackingSpace {
    let need = (source_size as f64 * safety_factor).ceil() as u64;
    if free_bytes >= need {
        PackingSpace::Ok
    } else {
        PackingSpace::Defer {
            need_bytes: need,
            free_bytes,
        }
    }
}

/// Margem sugerida: espaço para a geração PACKED mais 25%.
pub const DEFAULT_PACKING_SAFETY_FACTOR: f64 = 1.25;

#[cfg(test)]
mod tests {
    use super::*;
    use heraclitus_core::runtime::{
        CompressionCodec, DerivedArtifactRef, PhysicalGeneration, RetentionPolicy,
        SegmentDescriptorV2,
    };

    /// HLC a partir de segundos de parede, no layout deste motor.
    fn hlc(segundos: u64) -> u64 {
        (segundos * 1_000) << 16
    }

    fn generation(
        n: u32,
        layout: PhysicalLayout,
        state: GenerationState,
        superseded_s: u64,
    ) -> PhysicalGeneration {
        PhysicalGeneration {
            generation: n,
            layout,
            compression: if layout == PhysicalLayout::Packed {
                CompressionCodec::Zstd
            } else {
                CompressionCodec::Raw
            },
            location: format!("seg/g{n}.hrkl"),
            physical_size: 1_000 * (n as u64 + 1),
            physical_digest: [n as u8; 32],
            state,
            created_hlc: hlc(0),
            verified_hlc: hlc(0),
            superseded_hlc: if superseded_s == 0 {
                0
            } else {
                hlc(superseded_s)
            },
            verified_copies: 1,
        }
    }

    /// Segmento típico depois de um packing: RAW superseded + PACKED activa.
    fn segmento_packado(id: SegmentId, superseded_s: u64) -> SegmentDescriptorV2 {
        SegmentDescriptorV2 {
            segment_id: id,
            first_lsn: 1,
            last_lsn: 100,
            record_count: 100,
            canonical_codec: 1,
            logical_root: [id as u8; 32],
            min_hlc: 1,
            max_hlc: 2,
            active_generation: 1,
            generations: vec![
                generation(
                    0,
                    PhysicalLayout::Raw,
                    GenerationState::Superseded,
                    superseded_s,
                ),
                generation(1, PhysicalLayout::Packed, GenerationState::Active, 0),
            ],
            hrki: None,
            parquet: None,
            retention: RetentionPolicy::default(),
        }
    }

    fn manifesto(segs: Vec<SegmentDescriptorV2>) -> DatabaseManifest {
        DatabaseManifest {
            segments_v2: segs,
            ..Default::default()
        }
    }

    fn opts_apos(segundos: u64) -> GcOptions {
        GcOptions {
            now_hlc: hlc(segundos),
            ..GcOptions::default()
        }
    }

    #[test]
    fn raw_superseded_e_coletavel_depois_do_grace() {
        let m = manifesto(vec![segmento_packado(1, 10)]);
        let pins = PinRegistry::new();

        // Dentro do grace de 24h: bloqueado, e a razão é explicável.
        let plano = plan_gc(&m, &pins, &opts_apos(100));
        assert!(plano.generations.is_empty());
        assert!(matches!(
            plano
                .blocked
                .iter()
                .find(|b| b.generation == 0)
                .unwrap()
                .reason,
            GcBlockReason::GracePeriod { .. }
        ));

        // Passadas 24h + 10s: coletável.
        let plano = plan_gc(&m, &pins, &opts_apos(10 + 86_400 + 1));
        assert_eq!(plano.generations.len(), 1);
        assert_eq!(plano.generations[0].generation, 0);
        assert_eq!(plano.reclaimable_bytes(), 1_000);
        assert_gc_invariant(&m, &plano).unwrap();
    }

    #[test]
    fn a_geracao_activa_nunca_e_candidata() {
        let m = manifesto(vec![segmento_packado(1, 10)]);
        let pins = PinRegistry::new();
        let plano = plan_gc(&m, &pins, &opts_apos(1_000_000));
        assert!(plano.generations.iter().all(|c| c.generation != 1));
        assert!(matches!(
            plano
                .blocked
                .iter()
                .find(|b| b.generation == 1)
                .unwrap()
                .reason,
            GcBlockReason::NotSuperseded
        ));
    }

    #[test]
    fn ultima_autoridade_canonica_e_intocavel() {
        // §91 — o chão de tudo. Um segmento com uma só geração, mesmo marcada
        // superseded por engano, nunca é coletado.
        let mut s = segmento_packado(1, 10);
        s.generations.retain(|g| g.generation == 0);
        s.active_generation = 0;
        s.generations[0].state = GenerationState::Superseded;
        let m = manifesto(vec![s]);
        let plano = plan_gc(&m, &PinRegistry::new(), &opts_apos(1_000_000));
        assert!(plano.generations.is_empty());
        assert_gc_invariant(&m, &plano).unwrap();
    }

    #[test]
    fn legal_hold_vence_tudo() {
        // §94 — nem tempo decorrido nem número de cópias desbloqueiam.
        let mut s = segmento_packado(1, 10);
        s.retention.legal_hold = true;
        let m = manifesto(vec![s]);
        let plano = plan_gc(&m, &PinRegistry::new(), &opts_apos(10_000_000));
        assert!(plano.generations.is_empty());
        assert_eq!(
            plano
                .blocked
                .iter()
                .find(|b| b.generation == 0)
                .unwrap()
                .reason,
            GcBlockReason::LegalHold
        );
    }

    #[test]
    fn leitor_pinado_bloqueia_e_desbloqueia_no_drop() {
        // §92 — e o `Drop` importa: um pin largado a meio de um `?` seria um
        // segmento eternamente incoletável.
        let m = manifesto(vec![segmento_packado(1, 10)]);
        let pins = PinRegistry::new();
        let opts = opts_apos(1_000_000);
        {
            let _guard = pins.pin(1, 0);
            assert_eq!(pins.count(1, 0), 1);
            let plano = plan_gc(&m, &pins, &opts);
            assert!(plano.generations.is_empty());
            assert_eq!(
                plano
                    .blocked
                    .iter()
                    .find(|b| b.generation == 0)
                    .unwrap()
                    .reason,
                GcBlockReason::ReaderPinned { pins: 1 }
            );
        }
        assert_eq!(pins.count(1, 0), 0);
        assert_eq!(plan_gc(&m, &pins, &opts).generations.len(), 1);
    }

    #[test]
    fn pin_noutra_geracao_nao_bloqueia_esta() {
        let m = manifesto(vec![segmento_packado(1, 10)]);
        let pins = PinRegistry::new();
        let _g = pins.pin(1, 1); // pinado na PACKED activa
        let plano = plan_gc(&m, &pins, &opts_apos(1_000_000));
        assert_eq!(
            plano.generations.len(),
            1,
            "a RAW superseded continua coletável"
        );
        assert_eq!(pins.total(), 1);
    }

    #[test]
    fn politica_de_replicas_bloqueia_ate_haver_copias() {
        // §184 — GC local só depois de satisfeita a durabilidade.
        let mut s = segmento_packado(1, 10);
        s.retention.min_verified_copies = 3;
        let m = manifesto(vec![s]);
        let plano = plan_gc(&m, &PinRegistry::new(), &opts_apos(1_000_000));
        assert_eq!(
            plano
                .blocked
                .iter()
                .find(|b| b.generation == 0)
                .unwrap()
                .reason,
            GcBlockReason::InsufficientVerifiedCopies { have: 1, need: 3 }
        );

        let mut s = segmento_packado(1, 10);
        s.retention.min_verified_copies = 3;
        s.generations[1].verified_copies = 3;
        let m = manifesto(vec![s]);
        assert_eq!(
            plan_gc(&m, &PinRegistry::new(), &opts_apos(1_000_000))
                .generations
                .len(),
            1
        );
    }

    #[test]
    fn sem_carimbo_de_superseded_o_grace_nunca_expira() {
        // Conservador de propósito: sem saber quando passou a superseded, não
        // há como afirmar que o tempo passou.
        let mut s = segmento_packado(1, 0);
        s.generations[0].superseded_hlc = 0;
        let m = manifesto(vec![s]);
        let plano = plan_gc(&m, &PinRegistry::new(), &opts_apos(10_000_000));
        assert!(plano.generations.is_empty());
        assert!(matches!(
            plano.blocked[0].reason,
            GcBlockReason::GracePeriod {
                remaining_seconds: 86_400
            }
        ));
    }

    #[test]
    fn quarentena_exige_pedido_explicito() {
        // §127 — a geração em quarentena é evidência; um scrub automático não a
        // destrói.
        let mut s = segmento_packado(1, 10);
        s.generations[1].state = GenerationState::Quarantined;
        // `quarantine_generation` carimba o momento; sem carimbo o grace nunca
        // expira e o teste estaria a medir outra coisa.
        s.generations[1].superseded_hlc = hlc(10);
        s.active_generation = 0;
        s.generations[0].state = GenerationState::Active;
        let m = manifesto(vec![s]);

        let plano = plan_gc(&m, &PinRegistry::new(), &opts_apos(1_000_000));
        assert_eq!(
            plano
                .blocked
                .iter()
                .find(|b| b.generation == 1)
                .unwrap()
                .reason,
            GcBlockReason::Quarantined
        );

        let opts = GcOptions {
            collect_quarantined: true,
            ..opts_apos(1_000_000)
        };
        let plano = plan_gc(&m, &PinRegistry::new(), &opts);
        assert_eq!(plano.generations.len(), 1);
        assert_eq!(plano.generations[0].generation, 1);
    }

    #[test]
    fn original_legado_e_preservado() {
        // §133 — quando há evidência externa a referir o hash antigo.
        let mut s = segmento_packado(1, 10);
        s.canonical_codec = CANONICAL_CODEC_LEGACY;
        let m = manifesto(vec![s]);
        let plano = plan_gc(&m, &PinRegistry::new(), &opts_apos(10_000_000));
        assert_eq!(
            plano
                .blocked
                .iter()
                .find(|b| b.generation == 0)
                .unwrap()
                .reason,
            GcBlockReason::LegacyOriginalPreserved
        );

        let mut s = segmento_packado(1, 10);
        s.canonical_codec = CANONICAL_CODEC_LEGACY;
        s.retention.preserve_legacy_original = false;
        let m = manifesto(vec![s]);
        assert_eq!(
            plan_gc(&m, &PinRegistry::new(), &opts_apos(10_000_000))
                .generations
                .len(),
            1
        );
    }

    #[test]
    fn derivados_obsoletos_sao_coletados_e_nunca_bloqueiam() {
        let mut s = segmento_packado(1, 10);
        s.hrki = Some(DerivedArtifactRef {
            location: "s.hrki".into(),
            size: 4_096,
            digest: [0; 32],
            logical_root: [0xEE; 32], // não corresponde
            created_hlc: 0,
        });
        s.parquet = Some(DerivedArtifactRef {
            location: "s.parquet".into(),
            size: 8_192,
            digest: [0; 32],
            logical_root: s.logical_root, // corresponde
            created_hlc: 0,
        });
        let m = manifesto(vec![s]);
        let plano = plan_gc(&m, &PinRegistry::new(), &opts_apos(100));
        assert_eq!(plano.stale_artifacts.len(), 1);
        assert_eq!(plano.stale_artifacts[0].kind, ArtifactKind::Hrki);
        // Derivados são coletáveis mesmo dentro do grace das gerações.
        assert!(plano.generations.is_empty());
        assert_eq!(plano.reclaimable_bytes(), 4_096);
    }

    #[test]
    fn o_invariante_apanha_um_plano_mau() {
        // A rede de segurança tem de funcionar mesmo que a decisão erre: aqui
        // fabrica-se à mão um plano que remove a única autoridade.
        let mut s = segmento_packado(1, 10);
        s.generations.retain(|g| g.generation == 0);
        s.active_generation = 0;
        let m = manifesto(vec![s]);
        let plano_mau = GcPlan {
            generations: vec![GcCandidate {
                segment_id: 1,
                generation: 0,
                location: "seg/g0.hrkl".into(),
                physical_size: 1_000,
                layout: PhysicalLayout::Raw,
            }],
            ..Default::default()
        };
        assert!(assert_gc_invariant(&m, &plano_mau).is_err());
        let mut m2 = m.clone();
        assert!(apply_gc(&mut m2, &plano_mau).is_err());
        assert_eq!(
            m2.segment(1).unwrap().generations.len(),
            1,
            "nada foi removido"
        );
    }

    #[test]
    fn aplicar_o_plano_remove_do_catalogo() {
        let mut m = manifesto(vec![segmento_packado(1, 10), segmento_packado(2, 10)]);
        let plano = plan_gc(&m, &PinRegistry::new(), &opts_apos(1_000_000));
        assert_eq!(plano.generations.len(), 2);
        apply_gc(&mut m, &plano).unwrap();
        for id in [1, 2] {
            let s = m.segment(id).unwrap();
            assert_eq!(s.generations.len(), 1);
            assert_eq!(s.generations[0].generation, 1);
            assert_eq!(s.active_generation, 1);
        }
        // Idempotente: correr outra vez não encontra nada.
        assert!(plan_gc(&m, &PinRegistry::new(), &opts_apos(1_000_000))
            .generations
            .is_empty());
    }

    #[test]
    fn nenhum_plano_gerado_viola_o_invariante() {
        // Varredura da matriz de decisão: qualquer combinação de estados,
        // holds, pins e tempos tem de produzir um plano que passa §91.
        let estados = [
            GenerationState::Writing,
            GenerationState::Verified,
            GenerationState::Active,
            GenerationState::Superseded,
            GenerationState::Archived,
            GenerationState::Quarantined,
        ];
        let pins = PinRegistry::new();
        for e0 in estados {
            for e1 in estados {
                for hold in [false, true] {
                    for quarentena in [false, true] {
                        for activa in [0u32, 1] {
                            let mut s = segmento_packado(1, 10);
                            s.generations[0].state = e0;
                            s.generations[1].state = e1;
                            s.active_generation = activa;
                            s.retention.legal_hold = hold;
                            let m = manifesto(vec![s]);
                            let opts = GcOptions {
                                now_hlc: hlc(10_000_000),
                                collect_quarantined: quarentena,
                                ..GcOptions::default()
                            };
                            let plano = plan_gc(&m, &pins, &opts);
                            assert_gc_invariant(&m, &plano).unwrap_or_else(|err| {
                                panic!("plano inválido para {e0:?}/{e1:?} hold={hold} q={quarentena} act={activa}: {err}")
                            });
                            let mut m2 = m.clone();
                            apply_gc(&mut m2, &plano).unwrap();
                            // Depois de aplicar, o segmento continua a ter uma
                            // geração activa resolúvel.
                            let s2 = m2.segment(1).unwrap();
                            assert!(
                                s2.generations.is_empty() || s2.active().is_some(),
                                "active_generation deixou de resolver"
                            );
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn classificacao_de_compactacao() {
        // §96/§97 — a única coisa que distingue uma nova geração canónica de
        // uma projecção é a raiz.
        let a = [1u8; 32];
        let b = [2u8; 32];
        assert_eq!(classify_compaction(&a, &a), CompactionClass::Canonical);
        assert_eq!(classify_compaction(&a, &b), CompactionClass::Projection);
    }

    #[test]
    fn espaco_de_packing() {
        // §182 — nunca apagar o RAW primeiro à espera de que o pack corra bem.
        assert_eq!(
            check_packing_space(1_000, 2_000, DEFAULT_PACKING_SAFETY_FACTOR),
            PackingSpace::Ok
        );
        assert_eq!(
            check_packing_space(1_000, 1_000, DEFAULT_PACKING_SAFETY_FACTOR),
            PackingSpace::Defer {
                need_bytes: 1_250,
                free_bytes: 1_000
            }
        );
    }

    #[test]
    fn conversao_de_hlc_para_milissegundos() {
        assert_eq!(hlc_millis(hlc(1)), 1_000);
        assert_eq!(
            hlc_millis((1_234u64 << 16) | 0xFFFF),
            1_234,
            "o contador lógico não conta como tempo"
        );
    }
}
