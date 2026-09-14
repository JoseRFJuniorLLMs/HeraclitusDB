//! SPEC-0074 §7.3 e §18, SPEC-0076 §22–§23 — os subcomandos `heraclitus agent`.
//!
//! > Preferir subcomandos da CLI já existente. Não criar binário novo sem
//! > necessidade (§7.3).
//!
//! Por isso não há `heraclitus-agent-verify`: há `heraclitus agent verify`, no
//! mesmo binário que já faz `verify`, `prove` e `storage doctor`. Quem receber
//! um Evidence Bundle recebe também um comando que já existe na máquina onde o
//! Heraclitus está instalado.
//!
//! # Os códigos de saída são contrato
//!
//! ```text
//! 0 VERIFIED   2 INVALID_BUNDLE   3 DIGEST_MISMATCH   4 PROOF_FAILURE
//! 5 UNSUPPORTED_VERSION   6 INCOMPLETE_SELECTION   7 ATTESTATION_FAILURE
//! ```
//!
//! Um script pericial gateia com eles (`heraclitus agent verify x.zip && ...`),
//! portanto mudá-los é uma alteração incompatível.

use heraclitus_agent::bundle::{self, BundleSelectionV1, ExportOptions};
use heraclitus_agent::config::{AgentBlackBoxConfig, AgentGatewayConfig};
use heraclitus_agent::policy::DeterministicAgentPolicyEngine;
use heraclitus_agent::store::{AnyLogEvidenceStore, EvidenceLog};
use heraclitus_agent::verifier::verify_bundle;
#[cfg(test)]
use heraclitus_agent::verifier::VerifyExit;
use heraclitus_agent::{demo, projection, zip};
use heraclitus_core::{FsyncPolicy, HeraclitusError, StorageFormat};
use heraclitus_log::AnyLog;
use std::path::Path;
use std::sync::Arc;

/// Onde vive o log dentro de um directório de dados.
///
/// # Porque isto precisa de três casos e não de dois
///
/// O servidor usa sempre `<data_dir>/log`. A primeira versão desta função dizia
/// "se `<data_dir>/log` existir, usa-o; senão usa `<data_dir>`" — e num
/// directório VAZIO isso escolhia `<data_dir>`. O resultado: `heraclitus agent
/// demo ./data` criava o log em `./data`, o servidor apontado a `./data`
/// procurava em `./data/log`, e a Consola mostrava zero runs sobre dados que
/// existiam mesmo ali. Nada falhava; simplesmente não aparecia nada.
///
/// A regra certa reconhece o que está lá:
///
/// | o que existe | onde o log é aberto |
/// |---|---|
/// | `<dir>/log` | `<dir>/log` — é um directório de dados |
/// | `<dir>/segments` ou `<dir>/manifests` | `<dir>` — apontaram-nos ao log |
/// | nada (directório novo ou vazio) | `<dir>/log` — o layout do servidor |
fn log_dir_for(data_dir: &Path) -> std::path::PathBuf {
    if data_dir.join("log").exists() {
        return data_dir.join("log");
    }
    if data_dir.join("segments").exists() || data_dir.join("manifests").exists() {
        return data_dir.to_path_buf();
    }
    data_dir.join("log")
}

/// Abre o log de evidência de um directório de dados.
///
/// Aceita tanto o directório de dados (`.../data`) como o próprio directório do
/// log (`.../data/log`): quem corre um comando forense às três da manhã não
/// devia ter de adivinhar qual dos dois a ferramenta espera.
///
/// # Um escritor de cada vez
///
/// O HRKL não tem trinco entre processos — o resto desta CLI (`gc`,
/// `rebuild-index`, `export`) assume a mesma convenção: o servidor está parado,
/// ou usa-se a API dele. Abrir o directório de um servidor a correr é o mesmo
/// que abrir o mesmo ficheiro com dois editores.
fn open_log(data_dir: &Path) -> Result<Arc<AnyLog>, HeraclitusError> {
    Ok(Arc::new(AnyLog::open(
        StorageFormat::V6,
        log_dir_for(data_dir),
        8 * 1024 * 1024,
        FsyncPolicy::Always,
    )?))
}

/// `heraclitus agent verify <bundle> [--json]`.
///
/// Devolve `(saída, código)`. O `main` propaga o código: é a única função desta
/// CLI que precisa de mais do que 0/1.
pub fn verify(path: &Path, json: bool) -> (String, i32) {
    let report = verify_bundle(path);
    let saida = if json {
        serde_json::to_string_pretty(&report).unwrap_or_else(|e| format!("{{\"error\":\"{e}\"}}"))
    } else {
        report.to_human()
    };
    (saida, report.exit.code())
}

/// `heraclitus agent inspect <bundle>` — o que está lá dentro, sem verificar.
///
/// Existe separado do `verify` de propósito: quando um bundle falha a
/// verificação, a primeira pergunta é "o que é que ele tem?", e essa pergunta
/// não deve exigir que a verificação passe.
pub fn inspect(path: &Path) -> Result<String, String> {
    let bytes = std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let files = zip::read_all(&bytes).map_err(|e| e.to_string())?;
    let mut out = format!("Bundle: {}\n\n", path.display());

    if let Some(raw) = files.get(bundle::FILE_MANIFEST) {
        match serde_json::from_slice::<bundle::EvidenceBundleManifestV1>(raw) {
            Ok(m) => {
                out.push_str(&format!("bundle id:        {}\n", m.bundle_id));
                out.push_str(&format!("format version:   {}\n", m.format_version));
                out.push_str(&format!("created at:       {}\n", m.created_at));
                out.push_str(&format!("tenant:           {}\n", m.tenant_id));
                out.push_str(&format!("selection:        {:?}\n", m.selection));
                out.push_str(&format!("records:          {}\n", m.record_count));
                out.push_str(&format!(
                    "LSN range:        {}..{}\n",
                    m.first_lsn, m.last_lsn
                ));
                out.push_str(&format!("capture mode:     {}\n", m.capture_mode));
                out.push_str(&format!("privacy profile:  {}\n", m.privacy_profile));
                out.push_str(&format!("proofs present:   {}\n", m.proofs_present));
                out.push_str(&format!("pending seal:     {}\n", m.pending_seal));
                out.push_str(&format!("producer:         {}\n", m.producer));
                out.push_str(&format!("verifier min:     {}\n", m.verifier_min_version));
                if !m.logical_roots.is_empty() {
                    out.push_str("logical roots:\n");
                    for r in &m.logical_roots {
                        out.push_str(&format!("  {r}\n"));
                    }
                }
            }
            Err(e) => out.push_str(&format!("manifest.json ilegível: {e}\n")),
        }
    } else {
        out.push_str("manifest.json EM FALTA\n");
    }

    out.push_str("\nfiles:\n");
    for (name, data) in &files {
        out.push_str(&format!("  {:<44} {:>10} bytes\n", name, data.len()));
    }

    if let Some(raw) = files.get(bundle::FILE_TIMELINE) {
        let linhas = raw.split(|b| *b == b'\n').filter(|l| !l.is_empty()).count();
        out.push_str(&format!("\ntimeline entries: {linhas}\n"));
    }
    out.push_str("\nPara verificar a integridade:\n  heraclitus agent verify ");
    out.push_str(&path.display().to_string());
    out.push('\n');
    Ok(out)
}

/// `heraclitus agent export <data-dir> --to <file>`.
pub fn export(
    data_dir: &Path,
    to: &Path,
    run_id: Option<String>,
    from: Option<u64>,
    ate: Option<u64>,
    tenant: &str,
) -> Result<String, String> {
    let log = open_log(data_dir).map_err(|e| e.to_string())?;
    let store = AnyLogEvidenceStore::new(log);
    let selection = match (run_id, from, ate) {
        (Some(run_id), _, _) => BundleSelectionV1::Run { run_id },
        (None, Some(f), Some(t)) => BundleSelectionV1::TimeWindow {
            from_unix_nanos: f,
            to_unix_nanos: t,
        },
        _ => BundleSelectionV1::Everything,
    };
    let outcome = bundle::build_bundle(
        &store,
        to,
        &ExportOptions {
            tenant_id: tenant.to_string(),
            selection,
            ..Default::default()
        },
    )
    .map_err(|e| e.to_string())?;
    Ok(format!(
        "Bundle:         {}\nFicheiro:       {}\nRegistos:       {}\nProvas:         {}\nPor selar:      {}\nBytes:          {}\n\nVerificar:\n  heraclitus agent verify {}\n",
        outcome.bundle_id,
        outcome.path.display(),
        outcome.record_count,
        outcome.proofs_present,
        outcome.pending_seal,
        outcome.bytes,
        outcome.path.display()
    ))
}

/// `heraclitus agent demo` (SPEC-0076 §22).
///
/// Sem chave de API externa, sem serviço pago, sem rede.
pub fn run_demo(data_dir: &Path, console_url: &str) -> Result<String, String> {
    let log = open_log(data_dir).map_err(|e| e.to_string())?;
    let store = AnyLogEvidenceStore::new(log.clone());
    let run_id = ulid::Ulid::new().to_string();
    let agora = bundle::now_unix_nanos();
    let run = demo::build_demo_run(agora, &run_id);
    let n = run.evidences.len();
    for e in &run.evidences {
        store.append_evidence(e).map_err(|e| e.to_string())?;
    }
    store.flush().map_err(|e| e.to_string())?;

    // Selar torna a evidência provável já a seguir, em vez de o utilizador ter
    // de esperar pelo worker de packing para ver `VERIFIED`.
    if let Some(v6) = log.v6_arc() {
        v6.seal_active().map_err(|e| e.to_string())?;
    }

    let rows = store
        .scan_evidence(0, store.head())
        .map_err(|e| e.to_string())?;
    let do_run: Vec<_> = rows
        .into_iter()
        .filter(|r| r.evidence.effective_run_id() == Some(run_id.as_str()))
        .collect();
    let mut integridade = projection::EvidenceIntegritySummary::default();
    for r in &do_run {
        match store.prove(r.lsn) {
            Ok(a) => integridade.observe(&a),
            Err(_) => integridade.observe(&heraclitus_agent::store::ProofAvailability::NotFound),
        }
    }

    Ok(format!(
        "Demo run created: {run_id}\nEvidence records: {n}\nConsole: {}/runs/{run_id}\nEvidence integrity: {}\n\nA seguir:\n  heraclitus agent export {} --to evidence.zip --run {run_id}\n  heraclitus agent verify evidence.zip\n",
        console_url.trim_end_matches('/'),
        integridade.state().label(),
        data_dir.display()
    ))
}

/// `heraclitus agent doctor` (SPEC-0076 §23).
pub fn doctor(
    data_dir: &Path,
    config_path: Option<&Path>,
    json: bool,
) -> Result<(String, i32), String> {
    let (black_box, gateway, production) = match config_path {
        None => (
            AgentBlackBoxConfig::default(),
            AgentGatewayConfig::default(),
            false,
        ),
        Some(p) => {
            let raw = std::fs::read_to_string(p).map_err(|e| format!("{}: {e}", p.display()))?;
            let doc: toml::Value = toml::from_str(&raw).map_err(|e| e.to_string())?;
            let bb = doc
                .get("agent_black_box")
                .cloned()
                .map(|v| v.try_into::<AgentBlackBoxConfig>())
                .transpose()
                .map_err(|e| format!("[agent_black_box]: {e}"))?
                .unwrap_or_default();
            let gw = doc
                .get("agent_gateway")
                .cloned()
                .map(|v| v.try_into::<AgentGatewayConfig>())
                .transpose()
                .map_err(|e| format!("[agent_gateway]: {e}"))?
                .unwrap_or_default();
            let prod = doc
                .get("production_mode")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            (bb, gw, prod)
        }
    };

    // O log é opcional: `doctor` tem de funcionar antes de haver dados, que é
    // exactamente quando alguém o corre pela primeira vez.
    let log = open_log(data_dir).ok().map(AnyLogEvidenceStore::new);
    let report = heraclitus_agent::doctor::run(
        data_dir,
        &black_box,
        &gateway,
        log.as_ref().map(|l| l as &dyn EvidenceLog),
        production,
    );
    let saida = if json {
        serde_json::to_string_pretty(&report).map_err(|e| e.to_string())?
    } else {
        report.to_human()
    };
    Ok((saida, report.exit_code()))
}

/// `heraclitus agent policy validate <file>`.
pub fn policy_validate(path: &Path) -> Result<String, String> {
    let raw = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let engine = DeterministicAgentPolicyEngine::parse(&raw).map_err(|e| e.to_string())?;
    let doc = engine.document();
    let mut out = format!(
        "VALIDATED\n\npolicy id:        {}\nrevision:         {}\nhash:             {}\ndefault:          {}\nrules:            {}\n\n",
        doc.id,
        doc.revision,
        engine.hash(),
        doc.default_decision.label(),
        doc.rules.len()
    );
    for r in &doc.rules {
        out.push_str(&format!(
            "  {:<24} {:<18} {}/{}\n",
            r.id,
            r.decision.label(),
            r.matcher.server.as_deref().unwrap_or("*"),
            r.matcher.tool.as_deref().unwrap_or("*")
        ));
    }
    Ok(out)
}

/// `heraclitus agent policy simulate <file> --data-dir <dir>` (SPEC-0075 §23).
pub fn policy_simulate(
    path: &Path,
    data_dir: &Path,
    active_path: Option<&Path>,
    from: Option<u64>,
    ate: Option<u64>,
) -> Result<String, String> {
    let raw = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let candidate = DeterministicAgentPolicyEngine::parse(&raw).map_err(|e| e.to_string())?;
    let active = match active_path {
        Some(p) => {
            let raw = std::fs::read_to_string(p).map_err(|e| format!("{}: {e}", p.display()))?;
            DeterministicAgentPolicyEngine::parse(&raw).map_err(|e| e.to_string())?
        }
        // Sem policy activa declarada, a comparação é contra o default do
        // produto — negar tudo. É honesto: é o que o gateway faria hoje.
        None => DeterministicAgentPolicyEngine::deny_all(),
    };

    let log = open_log(data_dir).map_err(|e| e.to_string())?;
    let store = AnyLogEvidenceStore::new(log);
    let rows = store
        .scan_evidence(0, store.head())
        .map_err(|e| e.to_string())?;

    let mut historical = 0u64;
    let (mut allow, mut deny, mut approval, mut outras, mut changed) =
        (0u64, 0u64, 0u64, 0u64, 0u64);
    let mut amostras = Vec::new();
    for row in &rows {
        let e = &row.evidence;
        if e.kind != heraclitus_agent::evidence::AgentEvidenceKindV1::ToolRequested {
            continue;
        }
        if let Some(f) = from {
            if e.observed_at_unix_nanos < f {
                continue;
            }
        }
        if let Some(t) = ate {
            if e.observed_at_unix_nanos > t {
                continue;
            }
        }
        historical += 1;
        let input = policy_input(e);
        let novo = candidate.evaluate(&input);
        let velho = active.evaluate(&input);
        match novo.decision.label() {
            "allow" => allow += 1,
            "deny" => deny += 1,
            "require_approval" => approval += 1,
            _ => outras += 1,
        }
        if novo.decision.label() != velho.decision.label() {
            changed += 1;
            if amostras.len() < 20 {
                amostras.push(format!(
                    "  {:<24} {:<16} -> {:<16} ({})",
                    e.subject.tool_name.clone().unwrap_or_default(),
                    velho.decision.label(),
                    novo.decision.label(),
                    novo.rule_id.clone().unwrap_or_else(|| "default".into())
                ));
            }
        }
    }

    let mut out = format!(
        "candidate:           {} / {} ({})\nactive:              {} / {} ({})\n\nhistorical tool calls: {historical}\nALLOW:               {allow}\nDENY:                {deny}\nREQUIRE_APPROVAL:    {approval}\nOTHER:               {outras}\nchanged vs active:   {changed}\n",
        candidate.document().id,
        candidate.revision(),
        &candidate.hash()[..16],
        active.document().id,
        active.revision(),
        &active.hash()[..16],
    );
    if !amostras.is_empty() {
        out.push_str("\nchanged:\n");
        for a in amostras {
            out.push_str(&a);
            out.push('\n');
        }
    }
    out.push_str("\nNada foi activado. Para activar:\n  POST /api/v1/agent/policies/activate\n");
    Ok(out)
}

fn policy_input(
    e: &heraclitus_agent::evidence::AgentEvidenceV1,
) -> heraclitus_agent::policy::PolicyInput {
    use heraclitus_agent::policy::{PolicyInput, PolicyValueV1};
    let mut fields = std::collections::BTreeMap::new();
    for (k, v) in &e.content.fields {
        if v == heraclitus_agent::privacy::REDACTED_MARKER {
            continue;
        }
        fields.insert(
            k.clone(),
            match v.parse::<i64>() {
                Ok(i) => PolicyValueV1::Int(i),
                Err(_) => PolicyValueV1::Str(v.clone()),
            },
        );
    }
    PolicyInput {
        server_id: e.subject.server_id.clone().unwrap_or_default(),
        tool_name: e.subject.tool_name.clone().unwrap_or_default(),
        agent_subject: e.agent.agent_id.clone(),
        environment: None,
        protocol: e.subject.protocol.clone(),
        fields,
        now_unix_seconds: e.observed_at_unix_nanos / 1_000_000_000,
    }
}

/// Os códigos de saída de §18, para quem quiser documentá-los.
pub fn verify_exit_codes() -> &'static str {
    "0 VERIFIED\n2 INVALID_BUNDLE\n3 DIGEST_MISMATCH\n4 PROOF_FAILURE\n5 UNSUPPORTED_VERSION\n6 INCOMPLETE_SELECTION\n7 ATTESTATION_FAILURE\n"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn o_demo_produz_um_bundle_que_verifica() {
        let dir = tempfile::tempdir().unwrap();
        let saida = run_demo(dir.path(), "http://localhost:8080").unwrap();
        assert!(saida.contains("Demo run created"), "{saida}");
        assert!(saida.contains("Evidence integrity: VERIFIED"), "{saida}");

        let zip_path = dir.path().join("evidence.zip");
        let run_id = saida
            .lines()
            .next()
            .unwrap()
            .rsplit(' ')
            .next()
            .unwrap()
            .to_string();
        let out = export(
            dir.path(),
            &zip_path,
            Some(run_id),
            None,
            None,
            demo::DEMO_TENANT,
        )
        .unwrap();
        assert!(out.contains("Bundle:"), "{out}");

        let (texto, codigo) = verify(&zip_path, false);
        assert_eq!(codigo, VerifyExit::Verified.code(), "{texto}");
        assert!(texto.contains("VERDICT: VERIFIED"), "{texto}");

        let inspecao = inspect(&zip_path).unwrap();
        assert!(inspecao.contains("timeline.ndjson"), "{inspecao}");
        assert!(inspecao.contains("bundle id:"), "{inspecao}");
    }

    #[test]
    fn um_byte_alterado_da_codigo_de_saida_nao_zero() {
        let dir = tempfile::tempdir().unwrap();
        run_demo(dir.path(), "http://localhost:8080").unwrap();
        let zip_path = dir.path().join("evidence.zip");
        export(dir.path(), &zip_path, None, None, None, demo::DEMO_TENANT).unwrap();
        assert_eq!(verify(&zip_path, false).1, 0);

        let mut bytes = std::fs::read(&zip_path).unwrap();
        let alvo = demo::DEMO_APPROVER.as_bytes();
        let pos = bytes.windows(alvo.len()).position(|w| w == alvo).unwrap();
        bytes[pos] = b'X';
        std::fs::write(&zip_path, &bytes).unwrap();
        let (texto, codigo) = verify(&zip_path, false);
        assert_ne!(codigo, 0, "{texto}");
    }

    #[test]
    fn o_json_de_verify_e_legivel_por_maquina() {
        let dir = tempfile::tempdir().unwrap();
        run_demo(dir.path(), "http://localhost:8080").unwrap();
        let zip_path = dir.path().join("evidence.zip");
        export(dir.path(), &zip_path, None, None, None, demo::DEMO_TENANT).unwrap();
        let (texto, _) = verify(&zip_path, true);
        let v: serde_json::Value = serde_json::from_str(&texto).unwrap();
        assert_eq!(v["verdict"], "VERIFIED");
        assert!(v["records"].as_u64().unwrap() > 0);
    }

    #[test]
    fn verificar_um_ficheiro_que_nao_existe_nao_entra_em_panico() {
        let (texto, codigo) = verify(Path::new("nao-existe-de-certeza.zip"), false);
        assert_eq!(codigo, VerifyExit::InvalidBundle.code());
        assert!(texto.contains("INVALID_BUNDLE"), "{texto}");
    }

    #[test]
    fn a_policy_do_demo_valida() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("policy.yaml");
        std::fs::write(&p, demo::DEMO_POLICY).unwrap();
        let out = policy_validate(&p).unwrap();
        assert!(out.contains("VALIDATED"), "{out}");
        assert!(out.contains("finance-large"), "{out}");
    }

    #[test]
    fn simular_contra_o_historico_do_demo() {
        let dir = tempfile::tempdir().unwrap();
        run_demo(dir.path(), "http://localhost:8080").unwrap();
        let p = dir.path().join("policy.yaml");
        std::fs::write(&p, demo::DEMO_POLICY).unwrap();
        let out = policy_simulate(&p, dir.path(), None, None, None).unwrap();
        assert!(out.contains("historical tool calls: 2"), "{out}");
        assert!(out.contains("Nada foi activado"), "{out}");
    }

    #[test]
    fn o_demo_escreve_onde_o_servidor_procura() {
        // O defeito que este teste fecha: `agent demo ./data` num directório
        // novo criava o log em `./data`, e o servidor — que abre sempre
        // `./data/log` — mostrava zero runs sobre dados que existiam.
        let dir = tempfile::tempdir().unwrap();
        run_demo(dir.path(), "http://localhost:8080").unwrap();
        assert!(
            dir.path().join("log").join("segments").exists(),
            "o log tem de ficar em <data_dir>/log, como o servidor espera"
        );
    }

    #[test]
    fn apontar_directamente_ao_log_tambem_funciona() {
        let dir = tempfile::tempdir().unwrap();
        run_demo(dir.path(), "http://localhost:8080").unwrap();
        // Agora o caminho do LOG, e não o do data-dir.
        let zip = dir.path().join("do-log.zip");
        let out = export(
            &dir.path().join("log"),
            &zip,
            None,
            None,
            None,
            demo::DEMO_TENANT,
        )
        .unwrap();
        assert!(out.contains("Registos:"), "{out}");
        assert_eq!(verify(&zip, false).1, 0);
    }

    #[test]
    fn o_doctor_corre_sem_configuracao() {
        let dir = tempfile::tempdir().unwrap();
        let (texto, _) = doctor(dir.path(), None, false).unwrap();
        assert!(texto.contains("heraclitus agent doctor"), "{texto}");
    }
}
