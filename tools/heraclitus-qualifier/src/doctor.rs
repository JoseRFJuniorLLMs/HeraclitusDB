//! Configuration qualification — `heraclitus doctor` equivalent
//! (SPEC-0049 §138–§140).
//!
//! §138 makes a point that is easy to miss: *a qualified release does not mean
//! every configuration of it is safe*. The binary that passed six trials will
//! happily serve a government database over plaintext with no credentials if
//! someone writes that config. So the config is qualified separately.
//!
//! The checks read the TOML generically instead of deserialising into
//! `HeraclitusConfig`. That is deliberate. A typed parse silently drops keys
//! the compiled struct does not know, which is exactly the case that hurts: an
//! operator who writes `tls_key` instead of `tls_key_path` would get a clean
//! bill of health for a server running without TLS. Reading raw lets the doctor
//! say "this key does nothing".

use std::collections::BTreeSet;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::Serialize;
use toml::Value;

/// §115 severity. `Blocking` prevents a government release.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Informational,
    Warning,
    Blocking,
}

#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    /// §139 area this belongs to, so a report can be read area by area.
    pub area: &'static str,
    pub severity: Severity,
    pub message: String,
    pub remedy: &'static str,
}

#[derive(Debug, Serialize)]
pub struct DoctorReport {
    pub schema_version: u32,
    pub generator: String,
    pub config_path: String,
    pub config_sha256: String,
    pub production_mode: bool,
    pub findings: Vec<Finding>,
    pub blocking: usize,
    pub warnings: usize,
    /// §140 — with `production_mode = true`, a blocking finding means the
    /// server must refuse to start rather than serve unsafely.
    pub safe_to_start: bool,
}

fn finding(
    area: &'static str,
    severity: Severity,
    message: String,
    remedy: &'static str,
) -> Finding {
    Finding {
        area,
        severity,
        message,
        remedy,
    }
}

fn string(config: &Value, key: &str) -> Option<String> {
    config.get(key)?.as_str().map(ToOwned::to_owned)
}

fn boolean(config: &Value, key: &str) -> Option<bool> {
    config.get(key)?.as_bool()
}

fn integer(config: &Value, key: &str) -> Option<i64> {
    config.get(key)?.as_integer()
}

/// Every key the server actually reads at the top level. A key outside this set
/// is inert, and an inert security key is the most dangerous kind of typo.
const KNOWN_KEYS: &[&str] = &[
    "data_dir",
    "storage_format",
    "segment_max_bytes",
    "fsync",
    "memtable_cap",
    "compaction_max_cores",
    "activation_decay",
    "grpc_addr",
    "rest_addr",
    "cold_tier_path",
    "tier_compaction_interval_secs",
    "distill_interval_secs",
    "auth_token",
    "access_credentials",
    "tls_cert_path",
    "tls_key_path",
    "tls_client_ca_path",
    "production_mode",
    "rest_basic_auth",
    "rest_cors_origins",
    "rest_allow_erasure",
    "checkpoint_interval_secs",
    "audit_queries",
    "encryption_at_rest",
    "compliance_enabled",
    "compliance_interval_secs",
    "compliance_min_lsn_step",
    "compliance_tsa_mode",
    "compliance_tsa_url",
    "compliance_tsa_policy",
    "compliance_tsa_policy_oid",
    "compliance_trust_store_dir",
    "compliance_sovereignty_mode",
    "compliance_crl_dir",
    "compliance_crl_max_staleness_secs",
    "compliance_crl_exigir_next_update",
    "flight_addr",
    "telemetry_interval_secs",
    "replication",
    "sentinel",
    "v6_packing_interval_secs",
    "v6_hrki_interval_secs",
    "v6_hrki_bloom_fpr",
    "v6_hrki_index_agent_id",
    "v6_hrki_index_session_id",
    "v6_lakehouse_interval_secs",
    "v6_lakehouse_path",
    "v6_lakehouse_table",
];

fn is_loopback_bind(address: &str) -> Option<bool> {
    let socket: SocketAddr = address.parse().ok()?;
    Some(socket.ip().is_loopback())
}

fn check_listener(
    findings: &mut Vec<Finding>,
    production: bool,
    key: &'static str,
    address: Option<&str>,
    tls_configured: bool,
) {
    let Some(address) = address else {
        return;
    };
    match is_loopback_bind(address) {
        None => findings.push(finding(
            "ports",
            Severity::Blocking,
            format!("{key} = {address:?} is not a valid host:port"),
            "write an explicit address such as 127.0.0.1:7474",
        )),
        Some(false) if production && !tls_configured => findings.push(finding(
            "tls",
            Severity::Blocking,
            format!("{key} listens on {address} without TLS in production_mode"),
            "set tls_cert_path and tls_key_path, or bind to loopback behind a terminating proxy",
        )),
        Some(false) => findings.push(finding(
            "ports",
            Severity::Warning,
            format!("{key} listens on {address}, reachable beyond this host"),
            "confirm the network path is intended and firewalled",
        )),
        Some(true) => {}
    }
}

pub fn diagnose(config: &Value, config_dir: &Path) -> Vec<Finding> {
    let mut findings = Vec::new();
    let production = boolean(config, "production_mode").unwrap_or(false);

    // ---- inert keys -------------------------------------------------------
    if let Some(table) = config.as_table() {
        let known = KNOWN_KEYS.iter().copied().collect::<BTreeSet<_>>();
        for key in table.keys() {
            if !known.contains(key.as_str()) {
                findings.push(finding(
                    "configuration",
                    Severity::Blocking,
                    format!("key {key:?} is not read by the server and has no effect"),
                    "remove the key or correct its spelling; an inert security key is worse than a missing one",
                ));
            }
        }
    }

    // ---- TLS and mTLS -----------------------------------------------------
    let cert = string(config, "tls_cert_path");
    let key = string(config, "tls_key_path");
    let client_ca = string(config, "tls_client_ca_path");
    let tls_configured = cert.is_some() && key.is_some();
    if cert.is_some() != key.is_some() {
        findings.push(finding(
            "tls",
            Severity::Blocking,
            "tls_cert_path and tls_key_path must be set together".to_owned(),
            "set both, or neither",
        ));
    }
    for (label, path) in [
        ("tls_cert_path", cert.as_ref()),
        ("tls_key_path", key.as_ref()),
        ("tls_client_ca_path", client_ca.as_ref()),
    ] {
        if let Some(path) = path {
            let resolved = resolve(config_dir, path);
            if !resolved.is_file() {
                findings.push(finding(
                    "tls",
                    Severity::Blocking,
                    format!(
                        "{label} points at {} which does not exist",
                        resolved.display()
                    ),
                    "install the PEM material before starting the server",
                ));
            }
        }
    }
    if production && !tls_configured {
        findings.push(finding(
            "tls",
            Severity::Blocking,
            "production_mode is on but no TLS material is configured".to_owned(),
            "configure tls_cert_path and tls_key_path",
        ));
    }
    if production && client_ca.is_none() {
        findings.push(finding(
            "mtls",
            Severity::Warning,
            "no tls_client_ca_path, so clients are not authenticated by certificate".to_owned(),
            "set tls_client_ca_path to require mTLS, or record the compensating control",
        ));
    }

    // ---- RBAC and authentication -----------------------------------------
    let credentials = config
        .get("access_credentials")
        .and_then(Value::as_array)
        .map(|array| array.len())
        .unwrap_or(0);
    let token = string(config, "auth_token");
    if credentials == 0 && token.is_none() {
        findings.push(finding(
            "rbac",
            if production {
                Severity::Blocking
            } else {
                Severity::Warning
            },
            "gRPC has neither access_credentials nor auth_token; anyone who reaches the port is trusted"
                .to_owned(),
            "define access_credentials with per-principal roles",
        ));
    } else if credentials == 0 {
        findings.push(finding(
            "rbac",
            Severity::Warning,
            "auth_token authenticates but carries no role; every caller is equally privileged"
                .to_owned(),
            "migrate to access_credentials so Reader, Writer, Auditor and Admin differ",
        ));
    }
    check_listener(
        &mut findings,
        production,
        "grpc_addr",
        string(config, "grpc_addr").as_deref(),
        tls_configured,
    );
    check_listener(
        &mut findings,
        production,
        "flight_addr",
        string(config, "flight_addr").as_deref(),
        tls_configured,
    );
    // The admin REST has its own transport story: it is Basic-auth only and
    // expected on loopback, so it is judged by the rule below, not by TLS.
    if let Some(address) = string(config, "rest_addr") {
        if is_loopback_bind(&address).is_none() {
            findings.push(finding(
                "ports",
                Severity::Blocking,
                format!("rest_addr = {address:?} is not a valid host:port"),
                "write an explicit address such as 127.0.0.1:7475",
            ));
        }
    }

    let rest_addr = string(config, "rest_addr");
    let rest_public = rest_addr
        .as_deref()
        .and_then(is_loopback_bind)
        .map(|loopback| !loopback)
        .unwrap_or(false);
    if rest_public && string(config, "rest_basic_auth").is_none() {
        findings.push(finding(
            "rbac",
            Severity::Blocking,
            "the admin REST surface is not on loopback and has no rest_basic_auth".to_owned(),
            "set rest_basic_auth, or bind rest_addr to 127.0.0.1",
        ));
    }
    if boolean(config, "rest_allow_erasure").unwrap_or(false) {
        findings.push(finding(
            "rbac",
            Severity::Warning,
            "rest_allow_erasure exposes irreversible crypto-shred behind Basic auth only"
                .to_owned(),
            "leave it false and perform erasure over gRPC with an Admin credential",
        ));
    }
    for origin in config
        .get("rest_cors_origins")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
    {
        if origin == "*" {
            findings.push(finding(
                "rbac",
                Severity::Blocking,
                "rest_cors_origins contains \"*\"; this REST surface has write routes".to_owned(),
                "list exact origins, or serve panel and API from one origin",
            ));
        }
    }

    // ---- storage and filesystem ------------------------------------------
    match string(config, "data_dir") {
        None => findings.push(finding(
            "storage",
            Severity::Warning,
            "data_dir is not set; the built-in default will be used".to_owned(),
            "state the data directory explicitly in the config",
        )),
        Some(dir) => {
            let resolved = resolve(config_dir, &dir);
            if !resolved.exists() {
                findings.push(finding(
                    "storage",
                    Severity::Informational,
                    format!("data_dir {} does not exist yet", resolved.display()),
                    "the server creates it at boot; confirm the volume is the intended one",
                ));
            }
        }
    }
    match string(config, "storage_format").as_deref() {
        Some("legacy") => findings.push(finding(
            "storage",
            Severity::Warning,
            "storage_format = \"legacy\" excludes packing, HRKI, cold tier and lakehouse".to_owned(),
            "migrate with `heraclitus migrate-v6` when the recipients of existing receipts allow it",
        )),
        Some("v6") | None => {}
        Some(other) => findings.push(finding(
            "storage",
            Severity::Blocking,
            format!("storage_format = {other:?} is not a format this server opens"),
            "use \"v6\" or \"legacy\"",
        )),
    }
    if let Some(segment) = integer(config, "segment_max_bytes") {
        // The measured window from docs/md/auditorias/append-lento-com-o-crescimento.md.
        if !(4 * 1024 * 1024..=16 * 1024 * 1024).contains(&segment) {
            findings.push(finding(
                "storage",
                Severity::Warning,
                format!("segment_max_bytes = {segment} is outside the measured 4-16 MiB window"),
                "outside this window append throughput degrades or sealing overhead dominates; \
                 keep the measurement that justified the value",
            ));
        }
    }
    if let Some(mode) = config
        .get("fsync")
        .and_then(|fsync| fsync.get("mode"))
        .and_then(Value::as_str)
    {
        if production && mode != "always" {
            findings.push(finding(
                "storage",
                Severity::Warning,
                format!("fsync mode is {mode:?}; acknowledgement is not power-loss durable"),
                "declare the durability contract to operators, or set mode = \"always\"",
            ));
        }
    }

    // ---- encryption, audit, compliance -----------------------------------
    if production && !boolean(config, "encryption_at_rest").unwrap_or(false) {
        findings.push(finding(
            "storage",
            Severity::Blocking,
            "production_mode is on with encryption_at_rest = false".to_owned(),
            "enable encryption at rest before storing personal data",
        ));
    }
    if production && !boolean(config, "audit_queries").unwrap_or(false) {
        findings.push(finding(
            "compliance",
            Severity::Warning,
            "audit_queries is off; reads leave no trail".to_owned(),
            "enable it where the regime requires read auditability",
        ));
    }
    let compliance_enabled = boolean(config, "compliance_enabled").unwrap_or(false);
    if production && !compliance_enabled {
        findings.push(finding(
            "compliance",
            Severity::Blocking,
            "production_mode is on but compliance_enabled is false".to_owned(),
            "enable compliance and configure the external ACT path",
        ));
    }
    if compliance_enabled {
        let mode = string(config, "compliance_tsa_mode").unwrap_or_default();
        let url = string(config, "compliance_tsa_url").unwrap_or_default();
        if mode != "offline" && url.trim().is_empty() {
            findings.push(finding(
                "compliance",
                Severity::Blocking,
                format!("compliance is enabled in {mode:?} mode with no compliance_tsa_url"),
                "set the timestamp authority URL, or use the offline mode",
            ));
        }
        if mode != "offline" && !url.trim().is_empty() {
            findings.push(finding(
                "airgap",
                Severity::Warning,
                format!("compliance will reach {url} — incompatible with an air-gapped install"),
                "use the offline TSA mode inside an air gap",
            ));
        }
        if production && (mode != "https" || !url.starts_with("https://")) {
            findings.push(finding(
                "compliance",
                Severity::Blocking,
                format!("production ACT must use mode=https and an https:// URL, got {mode:?} / {url:?}"),
                "set compliance_tsa_mode = \"https\" and an authenticated HTTPS endpoint",
            ));
        }
        if production
            && string(config, "compliance_sovereignty_mode").as_deref() != Some("controlled")
        {
            findings.push(finding(
                "airgap",
                Severity::Blocking,
                "production online ACT is not guarded by compliance_sovereignty_mode = \"controlled\""
                    .to_owned(),
                "set the sovereignty mode to controlled so the exact ACT endpoint is allowlisted",
            ));
        }
        let policy_oid = string(config, "compliance_tsa_policy_oid");
        if production && policy_oid.as_deref().is_none_or(str::is_empty) {
            findings.push(finding(
                "compliance",
                Severity::Blocking,
                "production ACT has no compliance_tsa_policy_oid".to_owned(),
                "configure the exact RFC 3161 policy OID approved for this ACT",
            ));
        }
        for (key, remedy) in [
            (
                "compliance_trust_store_dir",
                "install the operator-approved ICP-Brasil roots before qualification",
            ),
            (
                "compliance_crl_dir",
                "install current issuer CRLs before qualification",
            ),
        ] {
            match string(config, key) {
                None if production => findings.push(finding(
                    "compliance",
                    Severity::Blocking,
                    format!("production ACT has no {key}"),
                    remedy,
                )),
                Some(path) => {
                    let resolved = resolve(config_dir, &path);
                    let has_file = resolved
                        .read_dir()
                        .ok()
                        .into_iter()
                        .flatten()
                        .filter_map(Result::ok)
                        .any(|entry| entry.path().is_file());
                    if !has_file {
                        findings.push(finding(
                            "compliance",
                            if production {
                                Severity::Blocking
                            } else {
                                Severity::Warning
                            },
                            format!("{key} {} has no readable files", resolved.display()),
                            remedy,
                        ));
                    }
                }
                None => {}
            }
        }
    }

    // ---- air gap ----------------------------------------------------------
    if integer(config, "telemetry_interval_secs").unwrap_or(0) > 0 {
        findings.push(finding(
            "airgap",
            Severity::Warning,
            "telemetry_interval_secs is non-zero; §97 forbids telemetry inside an air gap"
                .to_owned(),
            "set it to 0 for air-gapped deployments",
        ));
    }
    if let Some(path) = string(config, "v6_lakehouse_path") {
        if path.contains("://") && !path.starts_with("file://") {
            findings.push(finding(
                "airgap",
                Severity::Warning,
                format!("the lakehouse target {path} is remote"),
                "point it at a local path for air-gapped deployments",
            ));
        }
    }

    // ---- replication ------------------------------------------------------
    if let Some(replication) = config.get("replication") {
        let peers = replication
            .get("peers")
            .and_then(Value::as_array)
            .map(|array| array.len())
            .unwrap_or(0);
        // A two-node cluster cannot form a majority after losing one node, so
        // §55's "fail closed" becomes "always closed" on the first fault.
        if peers > 0 && (peers + 1) % 2 == 0 {
            findings.push(finding(
                "replication",
                Severity::Warning,
                format!("{} nodes cannot hold quorum after a single loss", peers + 1),
                "run an odd number of voting members",
            ));
        }
    }

    // ---- Sentinel ---------------------------------------------------------
    if let Some(sentinel) = config.get("sentinel") {
        let enabled = sentinel
            .get("enabled")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let mode = sentinel
            .get("mode")
            .and_then(Value::as_str)
            .unwrap_or("disabled");
        if enabled != (mode != "disabled") {
            findings.push(finding(
                "sentinel",
                Severity::Blocking,
                format!("sentinel.enabled = {enabled} contradicts mode = {mode:?}"),
                "the server refuses this configuration at boot; make them agree",
            ));
        }
        if mode == "autonomous" {
            findings.push(finding(
                "sentinel",
                Severity::Blocking,
                "sentinel.mode = \"autonomous\" lets the security plane act without a human"
                    .to_owned(),
                "keep assist or below until the SPEC-0045 autonomy gates and false-positive \
                 benchmark are attested",
            ));
        }
    }

    // ---- clock ------------------------------------------------------------
    // Nothing in a config file proves the host clock is disciplined, and
    // guessing would be worse than saying so.
    findings.push(finding(
        "clock",
        Severity::Informational,
        "clock discipline and NTP policy cannot be read from a config file".to_owned(),
        "attach the host time-sync attestation to the runbooks gate",
    ));

    findings.sort_by(|left, right| {
        right
            .severity
            .cmp(&left.severity)
            .then_with(|| left.area.cmp(right.area))
            .then_with(|| left.message.cmp(&right.message))
    });
    findings
}

fn resolve(base: &Path, value: &str) -> PathBuf {
    let path = PathBuf::from(value);
    if path.is_absolute() {
        path
    } else {
        base.join(path)
    }
}

pub fn run(config_path: &Path) -> Result<DoctorReport> {
    let text = std::fs::read_to_string(config_path)
        .with_context(|| format!("read configuration {}", config_path.display()))?;
    let config: Value = toml::from_str(&text)
        .with_context(|| format!("parse configuration {}", config_path.display()))?;
    let config_dir = config_path.parent().unwrap_or(Path::new("."));
    let findings = diagnose(&config, config_dir);
    let blocking = findings
        .iter()
        .filter(|finding| finding.severity == Severity::Blocking)
        .count();
    let warnings = findings
        .iter()
        .filter(|finding| finding.severity == Severity::Warning)
        .count();
    Ok(DoctorReport {
        schema_version: 1,
        generator: format!("heraclitus-qualifier/{}", env!("CARGO_PKG_VERSION")),
        config_path: config_path.to_string_lossy().into_owned(),
        config_sha256: crate::evidence::sha256_bytes(text.as_bytes()),
        production_mode: config
            .get("production_mode")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        findings,
        blocking,
        warnings,
        safe_to_start: blocking == 0,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn diagnose_text(text: &str) -> Vec<Finding> {
        diagnose(&toml::from_str(text).unwrap(), Path::new("."))
    }

    fn has(findings: &[Finding], severity: Severity, needle: &str) -> bool {
        findings
            .iter()
            .any(|finding| finding.severity == severity && finding.message.contains(needle))
    }

    #[test]
    fn a_production_config_without_tls_or_rbac_is_blocked() {
        let findings = diagnose_text(
            "production_mode = true\ngrpc_addr = \"0.0.0.0:7474\"\nrest_addr = \"127.0.0.1:7475\"\n",
        );
        assert!(has(&findings, Severity::Blocking, "no TLS material"));
        assert!(has(
            &findings,
            Severity::Blocking,
            "neither access_credentials"
        ));
        assert!(has(
            &findings,
            Severity::Blocking,
            "encryption_at_rest = false"
        ));
        assert!(has(
            &findings,
            Severity::Blocking,
            "without TLS in production_mode"
        ));
    }

    #[test]
    fn production_compliance_exige_politica_guarda_ancoras_e_crls() {
        let findings = diagnose_text(
            "production_mode = true\ncompliance_enabled = true\ncompliance_tsa_mode = \"https\"\ncompliance_tsa_url = \"https://act.example/tsa\"\n",
        );
        for esperado in [
            "sovereignty_mode",
            "compliance_tsa_policy_oid",
            "compliance_trust_store_dir",
            "compliance_crl_dir",
        ] {
            assert!(
                has(&findings, Severity::Blocking, esperado),
                "não encontrou {esperado}: {findings:#?}"
            );
        }
    }

    #[test]
    fn a_misspelled_security_key_is_blocking_not_ignored() {
        // The whole reason the doctor reads raw TOML.
        let findings = diagnose_text("tls_key = \"/etc/heraclitus/server.key\"\n");
        assert!(has(&findings, Severity::Blocking, "\"tls_key\""));
    }

    #[test]
    fn a_public_admin_rest_without_basic_auth_is_blocked() {
        let findings = diagnose_text("rest_addr = \"0.0.0.0:7475\"\nauth_token = \"t\"\n");
        assert!(has(&findings, Severity::Blocking, "no rest_basic_auth"));
    }

    #[test]
    fn wildcard_cors_is_blocked_because_this_rest_writes() {
        let findings = diagnose_text("rest_cors_origins = [\"*\"]\n");
        assert!(has(&findings, Severity::Blocking, "write routes"));
    }

    #[test]
    fn a_contradictory_sentinel_block_is_blocked_and_autonomy_is_refused() {
        let contradictory = diagnose_text("[sentinel]\nenabled = false\nmode = \"observe\"\n");
        assert!(has(&contradictory, Severity::Blocking, "contradicts mode"));
        let autonomous = diagnose_text("[sentinel]\nenabled = true\nmode = \"autonomous\"\n");
        assert!(has(&autonomous, Severity::Blocking, "without a human"));
    }

    #[test]
    fn an_even_cluster_is_flagged_because_it_cannot_survive_one_loss() {
        let findings = diagnose_text("[replication]\nnode_id = 1\npeers = [\"a\"]\n");
        assert!(has(&findings, Severity::Warning, "cannot hold quorum"));
    }

    #[test]
    fn a_loopback_development_config_has_no_blocking_finding() {
        let findings = diagnose_text(
            "data_dir = \"data\"\ngrpc_addr = \"127.0.0.1:7474\"\nrest_addr = \"127.0.0.1:7475\"\nauth_token = \"t\"\nsegment_max_bytes = 8388608\n",
        );
        assert_eq!(
            findings
                .iter()
                .filter(|finding| finding.severity == Severity::Blocking)
                .count(),
            0,
            "{findings:#?}"
        );
    }

    #[test]
    fn the_shipped_reference_config_stays_free_of_blocking_findings() {
        // The preflight plan gates on this file, so a change that makes it
        // unsafe must break here rather than in someone's qualification run.
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../qa/qualification/configs/reference-loopback.toml");
        let report = run(&path).unwrap();
        assert!(report.safe_to_start, "{:#?}", report.findings);
        assert_eq!(report.blocking, 0);
    }

    #[test]
    fn the_clock_is_always_reported_as_unverifiable_from_a_file() {
        let findings = diagnose_text("data_dir = \"data\"\n");
        assert!(has(
            &findings,
            Severity::Informational,
            "cannot be read from a config file"
        ));
    }
}
