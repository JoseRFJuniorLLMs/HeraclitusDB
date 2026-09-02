//! Diagnóstico read-only do storage HRKL v6 (SPEC-0050 §210).
//!
//! Este módulo nunca abre [`super::V6Log`]: o boot vivo pode criar diretórios,
//! varrer `.tmp`, reparar a cauda ACTIVE e reconciliar RAW órfão. Um doctor que
//! alterasse justamente o estado que pretende diagnosticar produziria prova
//! inválida.

use std::collections::BTreeSet;
use std::path::{Component, Path, PathBuf};

use heraclitus_core::runtime::GenerationState;

use super::error::{corrupt, V6Result, HARD_MAX_BLOCK_BYTES};
use super::hrki::Hrki;
use super::manifest::ManifestStore;
use super::receipts::physical_digest_of_file;
use super::verify::{verify_segment, IntegrityLevel};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DoctorSeverity {
    Warning,
    Critical,
}

impl DoctorSeverity {
    fn as_str(self) -> &'static str {
        match self {
            Self::Warning => "WARNING",
            Self::Critical => "CRITICAL",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DoctorFinding {
    pub severity: DoctorSeverity,
    pub code: &'static str,
    pub path: Option<PathBuf>,
    pub detail: String,
}

#[derive(Debug, Clone, Default)]
pub struct StorageDoctorReport {
    pub manifest_generation: u64,
    pub segments: usize,
    pub generations: usize,
    pub sidecars: usize,
    /// SPEC-0050 §146 — projecções lakehouse referenciadas pelo HRKM.
    pub projections: usize,
    pub recovered_manifest_by_scan: bool,
    pub findings: Vec<DoctorFinding>,
}

impl StorageDoctorReport {
    pub fn is_clean(&self) -> bool {
        self.findings.is_empty()
    }

    pub fn has_critical(&self) -> bool {
        self.findings
            .iter()
            .any(|finding| finding.severity == DoctorSeverity::Critical)
    }

    pub fn render(&self) -> String {
        let mut out = format!(
            "HRKL v6 storage doctor\nmanifest generation: {}\nsegments: {}\ngenerations: {}\nsidecars: {}\nprojections: {}\nstatus: {}\n",
            self.manifest_generation,
            self.segments,
            self.generations,
            self.sidecars,
            self.projections,
            if self.is_clean() {
                "CLEAN"
            } else if self.has_critical() {
                "CRITICAL"
            } else {
                "WARNINGS"
            }
        );
        for finding in &self.findings {
            let path = finding
                .path
                .as_ref()
                .map(|path| format!(" [{}]", path.display()))
                .unwrap_or_default();
            out.push_str(&format!(
                "{} {}{}: {}\n",
                finding.severity.as_str(),
                finding.code,
                path,
                finding.detail
            ));
        }
        out
    }
}

/// Compara HRKM, gerações físicas e sidecars sem escrever um único byte.
pub fn doctor_storage(root: &Path) -> V6Result<StorageDoctorReport> {
    if !root.is_dir() {
        return Err(corrupt(
            "hrkl v6 storage doctor",
            format!("storage root does not exist: {}", root.display()),
        ));
    }
    let root = std::fs::canonicalize(root)?;
    let store = ManifestStore::open_read_only(root.join("manifests"))?;
    let loaded = store.load()?.ok_or_else(|| {
        corrupt(
            "hrkl v6 storage doctor",
            "no valid HRKM generation could be loaded",
        )
    })?;
    let manifest = &loaded.manifest;
    let mut report = StorageDoctorReport {
        manifest_generation: loaded.generation,
        segments: manifest.segments_v2.len(),
        recovered_manifest_by_scan: loaded.recovered_by_scan,
        ..Default::default()
    };
    if loaded.recovered_by_scan {
        finding(
            &mut report,
            DoctorSeverity::Warning,
            "CURRENT_DIVERGENCE",
            Some(store.current_path()),
            "CURRENT was missing/invalid; a valid HRKM was recovered by directory scan",
        );
    }

    let mut referenced_generations = BTreeSet::new();
    let mut referenced_sidecars = BTreeSet::new();
    for segment in &manifest.segments_v2 {
        if segment.canonical_authorities().next().is_none() {
            finding(
                &mut report,
                DoctorSeverity::Critical,
                "NO_CANONICAL_AUTHORITY",
                None,
                format!("segment {} has no canonical authority", segment.segment_id),
            );
        }
        let Some(active) = segment.active() else {
            finding(
                &mut report,
                DoctorSeverity::Critical,
                "ACTIVE_GENERATION_MISSING",
                None,
                format!(
                    "segment {} points to absent generation {}",
                    segment.segment_id, segment.active_generation
                ),
            );
            continue;
        };
        if !active.is_canonical_authority() {
            finding(
                &mut report,
                DoctorSeverity::Critical,
                "ACTIVE_NOT_AUTHORITATIVE",
                None,
                format!(
                    "segment {} active generation {} is {:?}",
                    segment.segment_id, active.generation, active.state
                ),
            );
        }

        for generation in &segment.generations {
            report.generations += 1;
            let path = match resolve_declared(&root, &generation.location) {
                Ok(path) => path,
                Err(error) => {
                    finding(
                        &mut report,
                        DoctorSeverity::Critical,
                        "UNSAFE_GENERATION_PATH",
                        None,
                        error.to_string(),
                    );
                    continue;
                }
            };
            referenced_generations.insert(path.clone());
            let quarantined = generation.state == GenerationState::Quarantined;
            let severity = if quarantined {
                DoctorSeverity::Warning
            } else {
                DoctorSeverity::Critical
            };
            let Ok(metadata) = std::fs::metadata(&path) else {
                finding(
                    &mut report,
                    severity,
                    "GENERATION_MISSING",
                    Some(path),
                    format!(
                        "segment {} generation {} is catalogued but absent",
                        segment.segment_id, generation.generation
                    ),
                );
                continue;
            };
            if metadata.len() != generation.physical_size {
                finding(
                    &mut report,
                    severity,
                    "GENERATION_SIZE_MISMATCH",
                    Some(path.clone()),
                    format!(
                        "HRKM={} bytes; disk={} bytes",
                        generation.physical_size,
                        metadata.len()
                    ),
                );
            }
            match physical_digest_of_file(&path) {
                Ok(digest) if digest == generation.physical_digest => {}
                Ok(_) => finding(
                    &mut report,
                    severity,
                    "GENERATION_DIGEST_MISMATCH",
                    Some(path.clone()),
                    "physical digest differs from HRKM",
                ),
                Err(error) => finding(
                    &mut report,
                    severity,
                    "GENERATION_UNREADABLE",
                    Some(path.clone()),
                    error.to_string(),
                ),
            }
            match verify_segment(&path, IntegrityLevel::Fast, HARD_MAX_BLOCK_BYTES, None) {
                Ok(verified)
                    if verified.segment_id == segment.segment_id
                        && verified.layout == generation.layout
                        && verified.declared_root == segment.logical_root => {}
                Ok(_) => finding(
                    &mut report,
                    severity,
                    "MANIFEST_SEGMENT_DIVERGENCE",
                    Some(path),
                    "header/footer identity differs from HRKM",
                ),
                Err(error) => finding(
                    &mut report,
                    severity,
                    "GENERATION_INVALID",
                    Some(path),
                    error.to_string(),
                ),
            }
        }

        if let Some(sidecar) = &segment.hrki {
            report.sidecars += 1;
            let path = match resolve_declared(&root, &sidecar.location) {
                Ok(path) => path,
                Err(error) => {
                    finding(
                        &mut report,
                        DoctorSeverity::Warning,
                        "UNSAFE_SIDECAR_PATH",
                        None,
                        error.to_string(),
                    );
                    continue;
                }
            };
            referenced_sidecars.insert(path.clone());
            let packed_path = resolve_declared(&root, &active.location)?;
            let valid = std::fs::metadata(&path)
                .ok()
                .filter(|metadata| metadata.len() == sidecar.size)
                .and_then(|_| physical_digest_of_file(&path).ok())
                .filter(|digest| *digest == sidecar.digest)
                .and_then(|_| {
                    Hrki::ler_validado(&packed_path, segment.segment_id, &segment.logical_root)
                })
                .is_some();
            if !valid {
                finding(
                    &mut report,
                    DoctorSeverity::Warning,
                    "INVALID_HRKI",
                    Some(path),
                    "sidecar is missing, corrupt, stale or disagrees with its packed segment",
                );
            }
        }

        // SPEC-0050 §146/§176 — a projecção lakehouse é verificada pelo que o
        // HRKM sabe dela, e não abrindo o objecto.
        //
        // Deliberadamente não se vai ao object store: o doctor é um comando
        // local e read-only, e uma URI `s3://` transformaria um diagnóstico
        // instantâneo numa operação de rede que pode falhar por credenciais
        // sem que nada esteja errado com o armazenamento. O que o manifesto
        // sozinho prova chega para apanhar a divergência que interessa: uma
        // projecção que já não descreve a verdade lógica activa do segmento —
        // o repack aconteceu e a tabela ficou para trás.
        if let Some(projection) = &segment.parquet {
            report.projections += 1;
            if projection.logical_root != segment.logical_root {
                finding(
                    &mut report,
                    DoctorSeverity::Warning,
                    "STALE_PARQUET_PROJECTION",
                    None,
                    format!(
                        "`{}` exporta uma raiz logica que ja nao e a do segmento {}",
                        projection.location, segment.segment_id
                    ),
                );
            }
        }
    }

    let segments_dir = root.join("segments");
    if segments_dir.is_dir() {
        for entry in std::fs::read_dir(&segments_dir)? {
            let path = entry?.path();
            if !path.is_file() {
                continue;
            }
            let name = path
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("");
            if path.extension().and_then(|ext| ext.to_str()) == Some("hrki") {
                if !referenced_sidecars.contains(&path) {
                    finding(
                        &mut report,
                        DoctorSeverity::Warning,
                        "ORPHAN_SIDECAR",
                        Some(path),
                        "sidecar is not referenced by the current HRKM",
                    );
                }
            } else if name.ends_with(".tmp") {
                finding(
                    &mut report,
                    DoctorSeverity::Warning,
                    "ORPHAN_TEMP",
                    Some(path),
                    "temporary object survived an interrupted transaction",
                );
            } else if name.ends_with(".hrkl")
                && !name.ends_with(".active.hrkl")
                && !referenced_generations.contains(&path)
            {
                finding(
                    &mut report,
                    DoctorSeverity::Warning,
                    "ORPHAN_GENERATION",
                    Some(path),
                    "sealed generation is not referenced by the current HRKM",
                );
            }
        }
    }
    Ok(report)
}

fn resolve_declared(root: &Path, location: &str) -> V6Result<PathBuf> {
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
            "hrkl v6 storage doctor",
            format!("unsafe manifest location: {location}"),
        ));
    }
    Ok(root.join(relative))
}

fn finding(
    report: &mut StorageDoctorReport,
    severity: DoctorSeverity,
    code: &'static str,
    path: Option<PathBuf>,
    detail: impl Into<String>,
) {
    report.findings.push(DoctorFinding {
        severity,
        code,
        path,
        detail: detail.into(),
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::v6::hrki::{caminho_sidecar, IndexPolicy, IndexPolicySet};
    use crate::v6::{PackingProfile, V6Log};
    use heraclitus_core::{Episode, EventKind, FsyncPolicy};

    fn prepared() -> (tempfile::TempDir, V6Log) {
        let root = tempfile::tempdir().unwrap();
        let log = V6Log::open(root.path(), 2_048, FsyncPolicy::Always).unwrap();
        for i in 0..20 {
            log.append(Episode::new(
                if i < 10 { "alice" } else { "bob" },
                EventKind::Observation,
                vec![b'x'; 256],
            ))
            .unwrap();
        }
        log.seal_active().unwrap();
        log.pack_pending(PackingProfile::Balanced).unwrap();
        log.build_pending_hrki(
            &IndexPolicySet::new().com("agent_id", IndexPolicy::PublicTechnical),
            None,
            0.01,
        )
        .unwrap();
        (root, log)
    }

    #[test]
    fn clean_storage_and_common_findings_are_detected_read_only() {
        let (root, log) = prepared();
        let clean = doctor_storage(root.path()).unwrap();
        assert!(clean.is_clean(), "{}", clean.render());

        let manifest = log.manifest();
        let active = manifest.segments_v2[0].active().unwrap();
        let packed = root.path().join(&active.location);
        let orphan = root.path().join("segments/orphan.g9999.packed.hrkl");
        std::fs::copy(&packed, &orphan).unwrap();
        let report = doctor_storage(root.path()).unwrap();
        assert!(report
            .findings
            .iter()
            .any(|finding| finding.code == "ORPHAN_GENERATION"));

        std::fs::remove_file(orphan).unwrap();
        let hrki = caminho_sidecar(&packed);
        let before_manifest = std::fs::read(root.path().join("manifests/CURRENT")).unwrap();
        std::fs::write(&hrki, b"corrupt sidecar").unwrap();
        let report = doctor_storage(root.path()).unwrap();
        assert!(report
            .findings
            .iter()
            .any(|finding| finding.code == "INVALID_HRKI"));
        assert_eq!(
            std::fs::read(root.path().join("manifests/CURRENT")).unwrap(),
            before_manifest,
            "doctor must not repair or rewrite CURRENT"
        );
    }

    /// SPEC-0050 §210 — o doctor tem de ver a camada lakehouse, não só o log.
    ///
    /// Uma projecção obsoleta não corrompe nada: o `.hrkl` continua a ser a
    /// autoridade e a tabela é regenerável (§126). Mas é exactamente por não
    /// partir nada que passa despercebida — um `SELECT` no lakehouse devolve
    /// números de uma geração que já foi substituída, sem qualquer sinal de
    /// erro. Por isso é `WARNING` e não `CRITICAL`, e por isso tem de aparecer.
    ///
    /// O doctor lê isto do HRKM e não abre o objecto: numa tabela em `s3://`,
    /// ir buscar os bytes trocaria um diagnóstico local instantâneo por uma
    /// chamada de rede que falha por credenciais sem nada estar errado.
    #[test]
    fn projeccao_lakehouse_obsoleta_aparece_no_diagnostico() {
        let (root, log) = prepared();
        assert!(doctor_storage(root.path()).unwrap().is_clean());

        // Uma projecção em dia: contada, e sem queixa.
        let manifest = log.manifest();
        let segmento = manifest.segments_v2[0].segment_id;
        let raiz = manifest.segments_v2[0].logical_root;
        let geracao = manifest.segments_v2[0].active_generation;
        log.attach_parquet_projection(
            segmento,
            geracao,
            raiz,
            heraclitus_core::runtime::DerivedArtifactRef {
                location: "file:///bucket/episodios/data/seg-0.parquet".into(),
                size: 1_024,
                digest: [7; 32],
                logical_root: raiz,
                created_hlc: 1,
            },
        )
        .unwrap();
        let em_dia = doctor_storage(root.path()).unwrap();
        assert_eq!(em_dia.projections, 1);
        assert!(em_dia.is_clean(), "{}", em_dia.render());
        assert!(em_dia.render().contains("projections: 1"));

        // Agora o mesmo manifesto com a raiz da projecção desactualizada — o
        // estado em que um repack deixa a tabela.
        let store = ManifestStore::open(root.path().join("manifests")).unwrap();
        let mut m = store.load().unwrap().unwrap().manifest;
        m.segment_mut(segmento)
            .unwrap()
            .parquet
            .as_mut()
            .unwrap()
            .logical_root = [0xEE; 32];
        store.commit(&mut m).unwrap();

        let report = doctor_storage(root.path()).unwrap();
        assert_eq!(report.projections, 1);
        assert!(
            report
                .findings
                .iter()
                .any(|f| f.code == "STALE_PARQUET_PROJECTION"
                    && f.severity == DoctorSeverity::Warning),
            "{}",
            report.render()
        );
        assert!(!report.has_critical(), "obsoleto não é corrupção");
    }

    #[test]
    fn current_divergence_and_missing_generation_are_visible() {
        let (root, log) = prepared();
        std::fs::write(root.path().join("manifests/CURRENT"), b"broken\n").unwrap();
        let report = doctor_storage(root.path()).unwrap();
        assert!(report.recovered_manifest_by_scan);
        assert!(report
            .findings
            .iter()
            .any(|finding| finding.code == "CURRENT_DIVERGENCE"));

        let path = root
            .path()
            .join(&log.manifest().segments_v2[0].active().unwrap().location);
        std::fs::remove_file(path).unwrap();
        let report = doctor_storage(root.path()).unwrap();
        assert!(report.has_critical());
        assert!(report
            .findings
            .iter()
            .any(|finding| finding.code == "GENERATION_MISSING"));
    }
}
