//! SPEC-0074 §17 — Evidence Bundle v1.
//!
//! # O que um bundle é
//!
//! Um ZIP que um perito abre numa máquina que não é a nossa, sem rede, sem o
//! Heraclitus instalado, e a partir do qual consegue decidir uma coisa: **este
//! histórico foi alterado depois de gravado, sim ou não?**
//!
//! Daí três decisões de formato:
//!
//! 1. **NDJSON e JSON, não um formato binário nosso.** Se o verificador
//!    desaparecesse, um perito com Python ainda leria tudo.
//! 2. **Os digests estão em dois sítios** — `manifest.json` (autoritativo, com
//!    as raízes lógicas) e `SHA256SUMS` (o formato que `sha256sum -c` já sabe
//!    ler). O segundo é conveniência; o primeiro é a prova.
//! 3. **Escrita atómica.** Um bundle interrompido a meio nunca aparece como
//!    concluído (§17): escreve-se para `<destino>.tmp` e só depois se renomeia.
//!
//! # O que um bundle NÃO prova
//!
//! Que a decisão foi correcta (§16.2). Prova inclusão e integridade. A
//! diferença é exactamente a que separa "o agente fez X sob a policy P com a
//! aprovação de H" de "fazer X estava certo".

use crate::canonical::hex32;
use crate::evidence::CaptureModeV1;
use crate::projection::{
    self, ApprovalSummary, IdentitiesProjection, PolicyDecisionSummary, RunSummary, ToolCallSummary,
};
use crate::store::{EvidenceLog, ProofAvailability, StorageProof, StoredEvidence};
use crate::zip::{ZipError, ZipWriter};
use heraclitus_core::HeraclitusError;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Versão do formato do bundle. Um verificador que não conheça o número
/// recusa-se a afirmar verificação em vez de adivinhar.
pub const BUNDLE_FORMAT_V1: u16 = 1;
/// Versão mínima do verificador exigida por este formato.
pub const VERIFIER_MIN_VERSION: &str = "1.0.0";

pub const FILE_MANIFEST: &str = "manifest.json";
pub const FILE_TIMELINE: &str = "timeline.ndjson";
pub const FILE_IDENTITIES: &str = "identities.json";
pub const FILE_TOOL_CALLS: &str = "tool-calls.json";
pub const FILE_APPROVALS: &str = "approvals.json";
pub const FILE_POLICY: &str = "policy-decisions.json";
pub const FILE_ROOTS: &str = "roots.json";
pub const FILE_SUMS: &str = "SHA256SUMS";
pub const FILE_README: &str = "README.txt";
pub const DIR_PROOFS: &str = "proofs";
pub const DIR_ATTESTATIONS: &str = "attestations";

/// Como a selecção foi feita — viaja no manifesto para que a auditoria saiba se
/// um bundle é parcial por desenho ou por omissão.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum BundleSelectionV1 {
    Run {
        run_id: String,
    },
    TimeWindow {
        from_unix_nanos: u64,
        to_unix_nanos: u64,
    },
    LsnRange {
        from_lsn: u64,
        to_lsn: u64,
    },
    EvidenceIds {
        evidence_ids: Vec<String>,
    },
    Everything,
}

impl BundleSelectionV1 {
    fn matches(&self, row: &StoredEvidence) -> bool {
        match self {
            Self::Run { run_id } => row.evidence.effective_run_id() == Some(run_id.as_str()),
            Self::TimeWindow {
                from_unix_nanos,
                to_unix_nanos,
            } => {
                let t = row.evidence.observed_at_unix_nanos;
                t >= *from_unix_nanos && t <= *to_unix_nanos
            }
            Self::LsnRange { from_lsn, to_lsn } => row.lsn >= *from_lsn && row.lsn <= *to_lsn,
            Self::EvidenceIds { evidence_ids } => evidence_ids.contains(&row.evidence.evidence_id),
            Self::Everything => true,
        }
    }
}

/// Digest de um ficheiro do bundle.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BundleFileDigestV1 {
    pub path: String,
    pub bytes: u64,
    /// SHA-256 em hex minúsculo — o mesmo que `sha256sum` imprime.
    pub sha256: String,
}

/// O manifesto (§17).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceBundleManifestV1 {
    pub format_version: u16,
    pub bundle_id: String,
    pub created_at: String,
    pub tenant_id: String,

    pub selection: BundleSelectionV1,

    pub record_count: u64,
    pub first_lsn: u64,
    pub last_lsn: u64,

    /// As raízes lógicas dos segmentos tocados pela selecção.
    pub logical_roots: Vec<String>,
    pub files: Vec<BundleFileDigestV1>,

    pub privacy_profile: String,
    pub capture_mode: String,
    pub verifier_min_version: String,

    /// Quantas evidências têm prova de inclusão dentro do bundle. Menos do que
    /// `record_count` significa `PARTIAL`, e o manifesto di-lo em vez de o
    /// esconder.
    pub proofs_present: u64,
    /// Evidências cujo segmento ainda não estava selado quando o bundle foi
    /// feito. Não é adulteração; é tempo.
    pub pending_seal: u64,
    pub producer: String,
}

/// Raiz lógica de um segmento tocado pela selecção.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BundleRootV1 {
    pub segment_id: u64,
    pub generation: u32,
    pub logical_root: String,
    pub first_lsn: u64,
    pub last_lsn: u64,
}

/// Opções da exportação.
#[derive(Debug, Clone)]
pub struct ExportOptions {
    pub tenant_id: String,
    pub selection: BundleSelectionV1,
    pub privacy_profile: String,
    pub capture_mode: CaptureModeV1,
    /// Tecto de registos no bundle. Um `export` sem tecto sobre um log grande é
    /// uma forma acidental de negação de serviço a si próprio.
    pub max_records: usize,
    /// Relógio da criação, em nanos Unix. Explícito para que a exportação seja
    /// testável e reprodutível.
    pub created_at_unix_nanos: u64,
}

impl Default for ExportOptions {
    fn default() -> Self {
        Self {
            tenant_id: "default".to_string(),
            selection: BundleSelectionV1::Everything,
            privacy_profile: "default".to_string(),
            capture_mode: CaptureModeV1::MetadataOnly,
            max_records: 200_000,
            created_at_unix_nanos: now_unix_nanos(),
        }
    }
}

/// O resultado da exportação.
#[derive(Debug, Clone)]
pub struct BundleOutcome {
    pub path: PathBuf,
    pub bundle_id: String,
    pub record_count: u64,
    pub proofs_present: u64,
    pub pending_seal: u64,
    pub bytes: u64,
}

#[derive(Debug, thiserror::Error)]
pub enum BundleError {
    #[error(transparent)]
    Zip(#[from] ZipError),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("serialização: {0}")]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Engine(#[from] HeraclitusError),
    #[error("selecção vazia: nenhuma evidência corresponde")]
    EmptySelection,
}

/// Constrói um Evidence Bundle a partir do log.
///
/// A escrita é atómica: um ficheiro temporário no mesmo directório e um
/// `rename` no fim. Se o processo morrer a meio, fica um `.tmp` — nunca um
/// bundle que parece completo e não está.
pub fn build_bundle(
    log: &dyn EvidenceLog,
    destination: &Path,
    opts: &ExportOptions,
) -> Result<BundleOutcome, BundleError> {
    let head = log.head();
    let all = log.scan_evidence(0, head)?;
    let mut rows: Vec<StoredEvidence> = all
        .into_iter()
        .filter(|r| r.evidence.tenant_id == opts.tenant_id || opts.tenant_id.is_empty())
        .filter(|r| opts.selection.matches(r))
        .collect();
    rows.sort_by_key(|r| r.lsn);
    rows.truncate(opts.max_records);
    if rows.is_empty() {
        return Err(BundleError::EmptySelection);
    }

    let mut proofs: BTreeMap<String, StorageProof> = BTreeMap::new();
    let mut roots: BTreeMap<u64, BundleRootV1> = BTreeMap::new();
    let mut pending_seal = 0u64;
    for row in &rows {
        match log.prove(row.lsn)? {
            ProofAvailability::Available(p) => {
                roots.entry(p.segment_id).or_insert_with(|| BundleRootV1 {
                    segment_id: p.segment_id,
                    generation: p.generation,
                    logical_root: p.logical_root.clone(),
                    first_lsn: row.lsn,
                    last_lsn: row.lsn,
                });
                if let Some(r) = roots.get_mut(&p.segment_id) {
                    r.first_lsn = r.first_lsn.min(row.lsn);
                    r.last_lsn = r.last_lsn.max(row.lsn);
                }
                proofs.insert(row.evidence.evidence_id.clone(), p);
            }
            ProofAvailability::PendingSeal => pending_seal += 1,
            ProofAvailability::NotFound => pending_seal += 1,
        }
    }

    let bundle_id = ulid::Ulid::new().to_string();
    let first_lsn = rows.first().map(|r| r.lsn).unwrap_or(0);
    let last_lsn = rows.last().map(|r| r.lsn).unwrap_or(0);

    // ── conteúdo ────────────────────────────────────────────────────────────
    let mut files: BTreeMap<String, Vec<u8>> = BTreeMap::new();

    let mut timeline = Vec::new();
    for row in &rows {
        let mut line = serde_json::to_vec(row)?;
        line.push(b'\n');
        timeline.extend_from_slice(&line);
    }
    files.insert(FILE_TIMELINE.to_string(), timeline);

    let identities: IdentitiesProjection = projection::project_identities(&rows);
    files.insert(
        FILE_IDENTITIES.to_string(),
        serde_json::to_vec_pretty(&identities)?,
    );

    let tool_calls: Vec<ToolCallSummary> = projection::project_tool_calls(&rows);
    files.insert(
        FILE_TOOL_CALLS.to_string(),
        serde_json::to_vec_pretty(&tool_calls)?,
    );

    let approvals: Vec<ApprovalSummary> = projection::project_approvals(&rows);
    files.insert(
        FILE_APPROVALS.to_string(),
        serde_json::to_vec_pretty(&approvals)?,
    );

    let policy: Vec<PolicyDecisionSummary> = projection::project_policy_decisions(&rows);
    files.insert(FILE_POLICY.to_string(), serde_json::to_vec_pretty(&policy)?);

    let roots_vec: Vec<BundleRootV1> = roots.into_values().collect();
    files.insert(
        FILE_ROOTS.to_string(),
        serde_json::to_vec_pretty(&roots_vec)?,
    );

    for (evidence_id, proof) in &proofs {
        files.insert(
            format!("{DIR_PROOFS}/{}.json", sanitize(evidence_id)),
            serde_json::to_vec_pretty(proof)?,
        );
    }
    // A pasta de atestações existe sempre, mesmo vazia: um bundle sem
    // `attestations/` levantaria a pergunta "foi removida?"; com um ficheiro
    // que diz "RFC 3161 não configurado" a resposta está no pacote.
    files.insert(
        format!("{DIR_ATTESTATIONS}/README.txt"),
        attestations_note(&proofs).into_bytes(),
    );

    let runs: Vec<RunSummary> = projection::project_runs(&rows);
    let readme = readme_text(&bundle_id, &rows, &runs, proofs.len() as u64, pending_seal);
    files.insert(FILE_README.to_string(), readme.into_bytes());

    // ── digests + manifesto ─────────────────────────────────────────────────
    let mut digests: Vec<BundleFileDigestV1> = files
        .iter()
        .map(|(path, data)| BundleFileDigestV1 {
            path: path.clone(),
            bytes: data.len() as u64,
            sha256: sha256_hex(data),
        })
        .collect();
    digests.sort_by(|a, b| a.path.cmp(&b.path));

    let manifest = EvidenceBundleManifestV1 {
        format_version: BUNDLE_FORMAT_V1,
        bundle_id: bundle_id.clone(),
        created_at: rfc3339_utc(opts.created_at_unix_nanos),
        tenant_id: opts.tenant_id.clone(),
        selection: opts.selection.clone(),
        record_count: rows.len() as u64,
        first_lsn,
        last_lsn,
        logical_roots: roots_vec.iter().map(|r| r.logical_root.clone()).collect(),
        files: digests.clone(),
        privacy_profile: opts.privacy_profile.clone(),
        capture_mode: opts.capture_mode.label().to_string(),
        verifier_min_version: VERIFIER_MIN_VERSION.to_string(),
        proofs_present: proofs.len() as u64,
        pending_seal,
        producer: format!("heraclitus-agent {}", env!("CARGO_PKG_VERSION")),
    };

    let sums = digests
        .iter()
        .map(|d| format!("{}  {}\n", d.sha256, d.path))
        .collect::<String>();

    // ── escrita atómica ─────────────────────────────────────────────────────
    let mut zw = ZipWriter::new(Vec::new());
    // O manifesto primeiro: quem abrir o ZIP em stream encontra-o sem ler tudo.
    zw.add(FILE_MANIFEST, &serde_json::to_vec_pretty(&manifest)?)?;
    for (path, data) in &files {
        zw.add(path, data)?;
    }
    zw.add(FILE_SUMS, sums.as_bytes())?;
    let bytes = zw.finish()?;

    if let Some(parent) = destination.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    let tmp = destination.with_extension("zip.tmp");
    std::fs::write(&tmp, &bytes)?;
    std::fs::rename(&tmp, destination)?;

    Ok(BundleOutcome {
        path: destination.to_path_buf(),
        bundle_id,
        record_count: rows.len() as u64,
        proofs_present: proofs.len() as u64,
        pending_seal,
        bytes: bytes.len() as u64,
    })
}

fn attestations_note(proofs: &BTreeMap<String, StorageProof>) -> String {
    let anchored = proofs
        .values()
        .filter(|p| p.timestamp_receipt.is_some())
        .count();
    if anchored == 0 {
        "RFC 3161: NOT CONFIGURED\n\n\
         Nenhuma prova neste pacote tem recibo de tempo externo. As provas de\n\
         Merkle continuam válidas: provam INTEGRIDADE e INCLUSÃO, não a hora.\n\
         Para ancorar no tempo, configure [agent_black_box.evidence] rfc3161.\n"
            .to_string()
    } else {
        format!("RFC 3161: {anchored} recibo(s) presente(s) nas provas.\n")
    }
}

fn readme_text(
    bundle_id: &str,
    rows: &[StoredEvidence],
    runs: &[RunSummary],
    proofs: u64,
    pending: u64,
) -> String {
    let mut s = String::new();
    s.push_str("Heraclitus Agent Black Box — Evidence Bundle v1\n");
    s.push_str("===============================================\n\n");
    s.push_str(&format!("Bundle:  {bundle_id}\n"));
    s.push_str(&format!("Records: {}\n", rows.len()));
    s.push_str(&format!("Runs:    {}\n", runs.len()));
    s.push_str(&format!("Proofs:  {proofs} (pending seal: {pending})\n\n"));
    s.push_str("Como verificar\n--------------\n\n");
    s.push_str("  heraclitus agent verify <este-ficheiro>.zip\n");
    s.push_str("  heraclitus agent verify <este-ficheiro>.zip --json\n\n");
    s.push_str("Sem o binário do Heraclitus, os digests continuam conferíveis:\n\n");
    s.push_str("  unzip -d bundle <este-ficheiro>.zip && cd bundle && sha256sum -c SHA256SUMS\n\n");
    s.push_str("O que este pacote prova\n-----------------------\n\n");
    s.push_str("Que os registos aqui incluídos estavam no histórico append-only com\n");
    s.push_str("o conteúdo exacto que aqui aparece, e que esse histórico não foi\n");
    s.push_str("alterado depois. NÃO prova que as decisões registadas foram correctas.\n\n");
    if pending > 0 {
        s.push_str(&format!(
            "Nota: {pending} registo(s) ainda estavam no segmento activo (por selar)\n\
             quando o pacote foi criado e por isso não trazem prova de inclusão.\n\
             O resultado da verificação será PARTIAL, não VERIFIED.\n\n"
        ));
    }
    s.push_str("Privacidade\n-----------\n\n");
    s.push_str("Por omissão este produto captura METADATA_ONLY: prompts, completions e\n");
    s.push_str("corpos de ferramenta NÃO são persistidos. Credenciais (Authorization,\n");
    s.push_str("Cookie, chaves de API) nunca são persistidas, em modo nenhum.\n");
    s
}

fn sanitize(id: &str) -> String {
    id.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

pub fn sha256_hex(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
    let out = h.finalize();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&out);
    hex32(&arr)
}

pub fn now_unix_nanos() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}

/// `2026-09-14T08:41:02Z` a partir de nanos Unix.
///
/// Escrito à mão (algoritmo civil-from-days de Howard Hinnant) porque a única
/// coisa que precisamos de uma biblioteca de datas é esta função, e um formato
/// de data num artefacto pericial não deve mudar porque uma dependência mudou.
pub fn rfc3339_utc(unix_nanos: u64) -> String {
    let secs = (unix_nanos / 1_000_000_000) as i64;
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    let (hh, mm, ss) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    format!("{y:04}-{m:02}-{d:02}T{hh:02}:{mm:02}:{ss:02}Z")
}

fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc3339_formata_a_epoca() {
        assert_eq!(rfc3339_utc(0), "1970-01-01T00:00:00Z");
        assert_eq!(
            rfc3339_utc(1_700_000_000_000_000_000),
            "2023-11-14T22:13:20Z"
        );
    }

    #[test]
    fn sha256_bate_com_o_vector_conhecido() {
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn sanitize_nao_deixa_escapar_caminho() {
        assert_eq!(sanitize("../../x"), "______x");
        assert_eq!(sanitize("E01ABC-1_2"), "E01ABC-1_2");
    }
}
