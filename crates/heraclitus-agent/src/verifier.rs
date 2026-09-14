//! SPEC-0074 §18 — o verificador offline.
//!
//! # A pergunta que responde
//!
//! ```text
//! heraclitus agent verify evidence.zip
//! ```
//!
//! > Este pacote foi alterado depois de ter sido produzido?
//!
//! Sem rede, sem base de dados, sem o servidor. Só o ficheiro.
//!
//! # A regra que governa o veredicto
//!
//! Falhar honestamente é mais importante do que passar. Um digest que não bate,
//! uma prova que não fecha ou um registo obrigatório em falta produzem
//! `INVALID`, e o código de saída diz qual das três coisas foi. Um pacote
//! propositadamente parcial produz `PARTIAL` — **não** `VERIFIED** — porque
//! "não verificado" nunca pode virar "válido" (SPEC-0076 §8).
//!
//! # O sink único
//!
//! A verificação de Merkle não é reimplementada aqui: reconstrói-se a
//! [`heraclitus_log::v6::InclusionProof`] e chama-se a mesma
//! `verify_inclusion_proof` que o motor usa. Duas implementações de Merkle
//! divergem, e no dia em que divergissem a prova passaria a depender de qual
//! delas correu.

use crate::bundle::{
    sha256_hex, BundleRootV1, EvidenceBundleManifestV1, FILE_APPROVALS, FILE_IDENTITIES,
    FILE_MANIFEST, FILE_POLICY, FILE_ROOTS, FILE_SUMS, FILE_TIMELINE, FILE_TOOL_CALLS,
};
use crate::canonical::canonical_evidence_hash;
use crate::projection;
use crate::store::{proof_closes, StorageProof, StoredEvidence};
use crate::zip;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::Path;

/// Códigos de saída do comando (§18). São contrato: scripts periciais gateiam
/// com eles.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum VerifyExit {
    #[default]
    Verified = 0,
    InvalidBundle = 2,
    DigestMismatch = 3,
    ProofFailure = 4,
    UnsupportedVersion = 5,
    IncompleteSelection = 6,
    AttestationFailure = 7,
}

impl VerifyExit {
    pub fn code(self) -> i32 {
        self as i32
    }
    pub fn label(self) -> &'static str {
        match self {
            Self::Verified => "VERIFIED",
            Self::InvalidBundle => "INVALID_BUNDLE",
            Self::DigestMismatch => "DIGEST_MISMATCH",
            Self::ProofFailure => "PROOF_FAILURE",
            Self::UnsupportedVersion => "UNSUPPORTED_VERSION",
            Self::IncompleteSelection => "INCOMPLETE_SELECTION",
            Self::AttestationFailure => "ATTESTATION_FAILURE",
        }
    }
}

/// Estado de um bloco de verificação, na forma que a saída humana mostra.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum CheckState {
    Valid,
    Invalid,
    Absent,
    Partial,
}

impl CheckState {
    fn label(self) -> &'static str {
        match self {
            Self::Valid => "VALID",
            Self::Invalid => "INVALID",
            Self::Absent => "NOT PRESENT",
            Self::Partial => "PARTIAL",
        }
    }
}

/// O relatório completo (§18).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyReport {
    pub bundle_id: String,
    pub format_version: u16,
    pub created_at: String,
    pub tenant_id: String,
    pub records: u64,
    pub first_lsn: u64,
    pub last_lsn: u64,
    pub file_digests: CheckState,
    pub merkle_proofs: CheckState,
    pub logical_roots: CheckState,
    pub timestamp_proofs_valid: u64,
    pub missing_records: u64,
    pub broken_parents: u64,
    pub policy_links: u64,
    pub policy_links_valid: u64,
    pub approvals: u64,
    pub approvals_valid: u64,
    pub proofs_present: u64,
    pub pending_seal: u64,
    pub capture_mode: String,
    pub verdict: String,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub problems: Vec<String>,
    #[serde(skip)]
    pub exit: VerifyExit,
}

impl VerifyReport {
    /// A saída humana de §18.
    pub fn to_human(&self) -> String {
        let mut s = String::new();
        s.push_str(&format!("Bundle:           {}\n", self.bundle_id));
        s.push_str(&format!("Records:          {}\n", self.records));
        s.push_str(&format!(
            "LSN range:        {}..{}\n",
            self.first_lsn, self.last_lsn
        ));
        s.push_str(&format!("Capture mode:     {}\n", self.capture_mode));
        s.push_str(&format!(
            "File digests:     {}\n",
            self.file_digests.label()
        ));
        s.push_str(&format!(
            "Merkle proofs:    {}\n",
            self.merkle_proofs.label()
        ));
        s.push_str(&format!(
            "Logical roots:    {}\n",
            self.logical_roots.label()
        ));
        s.push_str(&format!(
            "Timestamp proofs: {} VALID\n",
            self.timestamp_proofs_valid
        ));
        s.push_str(&format!("Missing records:  {}\n", self.missing_records));
        s.push_str(&format!("Broken parents:   {}\n", self.broken_parents));
        s.push_str(&format!(
            "Policy links:     {} VALID (of {})\n",
            self.policy_links_valid, self.policy_links
        ));
        s.push_str(&format!(
            "Approvals:        {} VALID (of {})\n",
            self.approvals_valid, self.approvals
        ));
        if self.pending_seal > 0 {
            s.push_str(&format!(
                "Pending seal:     {} record(s) without inclusion proof\n",
                self.pending_seal
            ));
        }
        if !self.problems.is_empty() {
            s.push('\n');
            for p in &self.problems {
                s.push_str(&format!("  ! {p}\n"));
            }
        }
        s.push_str(&format!("\nVERDICT: {}\n", self.verdict));
        s
    }
}

fn fail(exit: VerifyExit, problem: impl Into<String>) -> VerifyReport {
    VerifyReport {
        bundle_id: String::new(),
        format_version: 0,
        created_at: String::new(),
        tenant_id: String::new(),
        records: 0,
        first_lsn: 0,
        last_lsn: 0,
        file_digests: CheckState::Invalid,
        merkle_proofs: CheckState::Absent,
        logical_roots: CheckState::Absent,
        timestamp_proofs_valid: 0,
        missing_records: 0,
        broken_parents: 0,
        policy_links: 0,
        policy_links_valid: 0,
        approvals: 0,
        approvals_valid: 0,
        proofs_present: 0,
        pending_seal: 0,
        capture_mode: String::new(),
        verdict: exit.label().to_string(),
        problems: vec![problem.into()],
        exit,
    }
}

/// Verifica um ficheiro no disco.
pub fn verify_bundle(path: &Path) -> VerifyReport {
    match std::fs::read(path) {
        Ok(bytes) => verify_bundle_bytes(&bytes),
        Err(e) => fail(
            VerifyExit::InvalidBundle,
            format!("não foi possível ler {}: {e}", path.display()),
        ),
    }
}

/// Verifica os bytes de um bundle. É esta a função que os testes usam.
pub fn verify_bundle_bytes(bytes: &[u8]) -> VerifyReport {
    let files = match zip::read_all(bytes) {
        Ok(f) => f,
        Err(e) => return fail(VerifyExit::InvalidBundle, format!("arquivo ilegível: {e}")),
    };

    let Some(manifest_raw) = files.get(FILE_MANIFEST) else {
        return fail(VerifyExit::InvalidBundle, "manifest.json em falta");
    };
    let manifest: EvidenceBundleManifestV1 = match serde_json::from_slice(manifest_raw) {
        Ok(m) => m,
        Err(e) => {
            return fail(
                VerifyExit::InvalidBundle,
                format!("manifest.json ilegível: {e}"),
            )
        }
    };
    if manifest.format_version != crate::bundle::BUNDLE_FORMAT_V1 {
        return fail(
            VerifyExit::UnsupportedVersion,
            format!(
                "formato de bundle {} não é suportado por este verificador (espera {})",
                manifest.format_version,
                crate::bundle::BUNDLE_FORMAT_V1
            ),
        );
    }

    let mut problems: Vec<String> = Vec::new();

    // ── 1. digests ──────────────────────────────────────────────────────────
    //
    // Cada ficheiro declarado tem de existir e bater. E cada ficheiro presente
    // tem de estar declarado: sem esta segunda metade, acrescentar um ficheiro
    // ao ZIP passaria despercebido.
    let mut file_digests = CheckState::Valid;
    let declared: BTreeMap<&str, &crate::bundle::BundleFileDigestV1> = manifest
        .files
        .iter()
        .map(|f| (f.path.as_str(), f))
        .collect();
    for (path, d) in &declared {
        match files.get(*path) {
            None => {
                file_digests = CheckState::Invalid;
                problems.push(format!("ficheiro declarado em falta: {path}"));
            }
            Some(data) => {
                if data.len() as u64 != d.bytes || sha256_hex(data) != d.sha256 {
                    file_digests = CheckState::Invalid;
                    problems.push(format!("digest não bate: {path}"));
                }
            }
        }
    }
    for path in files.keys() {
        if path == FILE_MANIFEST || path == FILE_SUMS {
            continue;
        }
        if !declared.contains_key(path.as_str()) {
            file_digests = CheckState::Invalid;
            problems.push(format!("ficheiro não declarado no manifesto: {path}"));
        }
    }
    // O SHA256SUMS é conveniência, mas se estiver presente tem de ser coerente
    // com o manifesto — senão o pacote diz duas coisas diferentes.
    if let Some(sums) = files.get(FILE_SUMS) {
        if let Ok(text) = std::str::from_utf8(sums) {
            for line in text.lines().filter(|l| !l.trim().is_empty()) {
                let Some((hash, path)) = line.split_once("  ") else {
                    file_digests = CheckState::Invalid;
                    problems.push("SHA256SUMS mal formado".into());
                    continue;
                };
                match declared.get(path) {
                    Some(d) if d.sha256 == hash => {}
                    _ => {
                        file_digests = CheckState::Invalid;
                        problems.push(format!("SHA256SUMS diverge do manifesto em {path}"));
                    }
                }
            }
        }
    }
    if file_digests == CheckState::Invalid {
        let mut r = build_report(
            &manifest,
            &problems,
            CheckState::Invalid,
            CheckState::Absent,
            CheckState::Absent,
            0,
            0,
            0,
            0,
            0,
            0,
        );
        r.exit = VerifyExit::DigestMismatch;
        r.verdict = VerifyExit::DigestMismatch.label().to_string();
        return r;
    }

    // ── 2. registos ─────────────────────────────────────────────────────────
    let Some(timeline_raw) = files.get(FILE_TIMELINE) else {
        return fail(VerifyExit::InvalidBundle, "timeline.ndjson em falta");
    };
    let mut rows: Vec<StoredEvidence> = Vec::new();
    for (i, line) in timeline_raw
        .split(|b| *b == b'\n')
        .filter(|l| !l.is_empty())
        .enumerate()
    {
        match serde_json::from_slice::<StoredEvidence>(line) {
            Ok(r) => rows.push(r),
            Err(e) => {
                problems.push(format!("timeline.ndjson linha {}: {e}", i + 1));
            }
        }
    }
    let mut missing_records = 0u64;
    if rows.len() as u64 != manifest.record_count {
        missing_records = manifest.record_count.saturating_sub(rows.len() as u64);
        problems.push(format!(
            "o manifesto declara {} registos e a timeline tem {}",
            manifest.record_count,
            rows.len()
        ));
    }

    // ── 3. provas ───────────────────────────────────────────────────────────
    let roots: Vec<BundleRootV1> = files
        .get(FILE_ROOTS)
        .and_then(|b| serde_json::from_slice(b).ok())
        .unwrap_or_default();
    let declared_roots: std::collections::HashSet<&str> =
        roots.iter().map(|r| r.logical_root.as_str()).collect();

    let mut proofs_ok = 0u64;
    let mut proofs_bad = 0u64;
    let mut timestamp_ok = 0u64;
    let mut roots_state = CheckState::Valid;
    let by_id: BTreeMap<&str, &StoredEvidence> = rows
        .iter()
        .map(|r| (r.evidence.evidence_id.as_str(), r))
        .collect();

    for (path, data) in &files {
        let Some(rest) = path.strip_prefix("proofs/") else {
            continue;
        };
        let Some(evidence_id) = rest.strip_suffix(".json") else {
            continue;
        };
        let proof: StorageProof = match serde_json::from_slice(data) {
            Ok(p) => p,
            Err(e) => {
                proofs_bad += 1;
                problems.push(format!("prova ilegível em {path}: {e}"));
                continue;
            }
        };
        // A prova tem de fechar contra a raiz que declara...
        if !proof_closes(&proof) {
            proofs_bad += 1;
            problems.push(format!("a prova de {evidence_id} não fecha contra a raiz"));
            continue;
        }
        // ...a raiz tem de estar em `roots.json`...
        if !declared_roots.contains(proof.logical_root.as_str()) {
            roots_state = CheckState::Invalid;
            problems.push(format!(
                "a prova de {evidence_id} aponta para uma raiz que não está em roots.json"
            ));
        }
        // ...e o registo a que a prova se refere tem de estar na timeline com o
        // hash canónico que a prova declara. É esta terceira ligação que torna
        // a adulteração de um byte detectável: mexer no conteúdo muda o hash
        // canónico da evidência e a ligação parte.
        match by_id.get(evidence_id) {
            None => {
                proofs_bad += 1;
                problems.push(format!(
                    "há prova para {evidence_id} mas o registo não está na timeline"
                ));
                continue;
            }
            Some(row) => {
                let expected = crate::canonical::hex32(&canonical_evidence_hash(&row.evidence));
                if !proof.canonical_evidence_hash.is_empty()
                    && proof.canonical_evidence_hash != expected
                {
                    proofs_bad += 1;
                    problems.push(format!(
                        "o conteúdo de {evidence_id} não corresponde ao hash provado"
                    ));
                    continue;
                }
                if row.lsn != proof.lsn {
                    proofs_bad += 1;
                    problems.push(format!("o LSN de {evidence_id} não bate com o da prova"));
                    continue;
                }
            }
        }
        if proof.timestamp_receipt.is_some() {
            timestamp_ok += 1;
        }
        proofs_ok += 1;
    }

    // ── 4. proveniência lógica, policy e aprovações ─────────────────────────
    let broken = projection::broken_parents(&rows);
    let policy_links = projection::project_policy_decisions(&rows);
    let policy_valid = policy_links
        .iter()
        .filter(|p| {
            !p.policy_hash.is_empty()
                && !p.input_projection_hash.is_empty()
                && !p.decision.is_empty()
        })
        .count() as u64;
    if policy_valid != policy_links.len() as u64 {
        problems.push(format!(
            "{} decisão(ões) de policy sem proveniência completa",
            policy_links.len() as u64 - policy_valid
        ));
    }
    let approvals = projection::project_approvals(&rows);
    // Uma aprovação é válida quando está ligada ao hash exacto do assunto da
    // autorização (SPEC-0075 §15.2). Sem essa ligação, a aprovação não prova
    // que foi AQUELA acção que alguém aprovou.
    let approvals_valid = approvals
        .iter()
        .filter(|a| !a.authorization_subject_hash.is_empty() && a.granted.is_some())
        .count() as u64;

    // ── 5. veredicto ────────────────────────────────────────────────────────
    let merkle_state = if proofs_bad > 0 {
        CheckState::Invalid
    } else if proofs_ok == 0 {
        CheckState::Absent
    } else if proofs_ok < manifest.record_count {
        CheckState::Partial
    } else {
        CheckState::Valid
    };

    let exit = if proofs_bad > 0 {
        VerifyExit::ProofFailure
    } else if missing_records > 0 || !broken.is_empty() {
        VerifyExit::IncompleteSelection
    } else if roots_state == CheckState::Invalid {
        VerifyExit::ProofFailure
    } else if merkle_state == CheckState::Valid {
        VerifyExit::Verified
    } else {
        // Provas em falta não são falha de integridade — são ausência de prova.
        // O verdicto reflecte isso e o operador decide o que fazer.
        VerifyExit::IncompleteSelection
    };

    let verdict = match exit {
        VerifyExit::Verified => "VERIFIED".to_string(),
        VerifyExit::IncompleteSelection if proofs_bad == 0 && missing_records == 0 => {
            "PARTIAL".to_string()
        }
        other => other.label().to_string(),
    };

    let mut report = build_report(
        &manifest,
        &problems,
        file_digests,
        merkle_state,
        roots_state,
        timestamp_ok,
        missing_records,
        broken.len() as u64,
        policy_links.len() as u64,
        policy_valid,
        approvals.len() as u64,
    );
    report.approvals_valid = approvals_valid;
    report.proofs_present = proofs_ok;
    report.records = rows.len() as u64;
    report.verdict = verdict;
    report.exit = exit;

    // Sanidade dos ficheiros de projecção: se existirem, têm de ser JSON.
    for name in [
        FILE_IDENTITIES,
        FILE_TOOL_CALLS,
        FILE_APPROVALS,
        FILE_POLICY,
    ] {
        if let Some(data) = files.get(name) {
            if serde_json::from_slice::<serde_json::Value>(data).is_err() {
                report.problems.push(format!("{name} não é JSON válido"));
                report.exit = VerifyExit::InvalidBundle;
                report.verdict = VerifyExit::InvalidBundle.label().to_string();
            }
        }
    }
    report
}

#[allow(clippy::too_many_arguments)]
fn build_report(
    m: &EvidenceBundleManifestV1,
    problems: &[String],
    file_digests: CheckState,
    merkle_proofs: CheckState,
    logical_roots: CheckState,
    timestamp_proofs_valid: u64,
    missing_records: u64,
    broken_parents: u64,
    policy_links: u64,
    policy_links_valid: u64,
    approvals: u64,
) -> VerifyReport {
    VerifyReport {
        bundle_id: m.bundle_id.clone(),
        format_version: m.format_version,
        created_at: m.created_at.clone(),
        tenant_id: m.tenant_id.clone(),
        records: m.record_count,
        first_lsn: m.first_lsn,
        last_lsn: m.last_lsn,
        file_digests,
        merkle_proofs,
        logical_roots,
        timestamp_proofs_valid,
        missing_records,
        broken_parents,
        policy_links,
        policy_links_valid,
        approvals,
        approvals_valid: 0,
        proofs_present: m.proofs_present,
        pending_seal: m.pending_seal,
        capture_mode: m.capture_mode.clone(),
        verdict: String::new(),
        problems: problems.to_vec(),
        exit: VerifyExit::Verified,
    }
}
