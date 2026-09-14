//! SPEC-0076 §23 — `heraclitus agent doctor`.
//!
//! # O que um doctor tem de ser
//!
//! Orientado a acção. Um relatório que diz "OTLP listener: FAIL" e nada mais
//! obriga o operador a adivinhar; um que diz "a porta 4318 está ocupada — pare
//! o outro coletor ou mude `otlp.http_addr`" resolve o problema.
//!
//! Cada verificação devolve um estado, uma frase sobre o que foi observado e,
//! quando não está bem, o que fazer a seguir.

use crate::config::{AgentBlackBoxConfig, AgentGatewayConfig, GatewayMode};
use crate::policy::DeterministicAgentPolicyEngine;
use crate::store::EvidenceLog;
use serde::Serialize;
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum CheckStatus {
    Ok,
    Warn,
    Fail,
    Skipped,
}

#[derive(Debug, Clone, Serialize)]
pub struct Check {
    pub name: &'static str,
    pub status: CheckStatus,
    pub observed: String,
    /// O que fazer. Vazio quando está bem.
    pub action: String,
}

impl Check {
    fn ok(name: &'static str, observed: impl Into<String>) -> Self {
        Self {
            name,
            status: CheckStatus::Ok,
            observed: observed.into(),
            action: String::new(),
        }
    }
    fn warn(name: &'static str, observed: impl Into<String>, action: impl Into<String>) -> Self {
        Self {
            name,
            status: CheckStatus::Warn,
            observed: observed.into(),
            action: action.into(),
        }
    }
    fn fail(name: &'static str, observed: impl Into<String>, action: impl Into<String>) -> Self {
        Self {
            name,
            status: CheckStatus::Fail,
            observed: observed.into(),
            action: action.into(),
        }
    }
    fn skipped(name: &'static str, observed: impl Into<String>) -> Self {
        Self {
            name,
            status: CheckStatus::Skipped,
            observed: observed.into(),
            action: String::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct DoctorReport {
    pub checks: Vec<Check>,
    pub failures: usize,
    pub warnings: usize,
}

impl DoctorReport {
    pub fn to_human(&self) -> String {
        let mut s = String::from("heraclitus agent doctor\n=======================\n\n");
        for c in &self.checks {
            let marca = match c.status {
                CheckStatus::Ok => "[  OK  ]",
                CheckStatus::Warn => "[ WARN ]",
                CheckStatus::Fail => "[ FAIL ]",
                CheckStatus::Skipped => "[ SKIP ]",
            };
            s.push_str(&format!("{marca} {:<26} {}\n", c.name, c.observed));
            if !c.action.is_empty() {
                s.push_str(&format!("         {:<26} -> {}\n", "", c.action));
            }
        }
        s.push_str(&format!(
            "\n{} verificações, {} falhas, {} avisos\n",
            self.checks.len(),
            self.failures,
            self.warnings
        ));
        s
    }

    pub fn exit_code(&self) -> i32 {
        if self.failures > 0 {
            1
        } else {
            0
        }
    }
}

/// Corre as verificações de §23.
pub fn run(
    data_dir: &Path,
    config: &AgentBlackBoxConfig,
    gateway: &AgentGatewayConfig,
    log: Option<&dyn EvidenceLog>,
    production: bool,
) -> DoctorReport {
    let mut checks = Vec::new();

    // ── directório de dados ─────────────────────────────────────────────────
    checks.push(match writable(data_dir) {
        Ok(()) => Check::ok(
            "data directory",
            format!("{} é gravável", data_dir.display()),
        ),
        Err(e) => Check::fail(
            "data directory",
            format!("{}: {e}", data_dir.display()),
            "crie o directório e dê permissão de escrita ao utilizador do serviço",
        ),
    });

    // ── HRKL ────────────────────────────────────────────────────────────────
    match log {
        None => checks.push(Check::skipped(
            "evidence log",
            "nenhum log aberto neste contexto",
        )),
        Some(log) => {
            let head = log.head();
            checks.push(Check::ok(
                "evidence log",
                format!("HRKL aberto, head LSN {head}"),
            ));
            match log.scan_evidence(0, head) {
                Ok(rows) => {
                    let n = rows.len();
                    let mut provadas = 0usize;
                    let mut por_selar = 0usize;
                    let mut partidas = 0usize;
                    for r in rows.iter().rev().take(64) {
                        match log.prove(r.lsn) {
                            Ok(crate::store::ProofAvailability::Available(p)) => {
                                if p.verified {
                                    provadas += 1
                                } else {
                                    partidas += 1
                                }
                            }
                            Ok(crate::store::ProofAvailability::PendingSeal) => por_selar += 1,
                            _ => {}
                        }
                    }
                    checks.push(if partidas > 0 {
                        Check::fail(
                            "current integrity",
                            format!("{partidas} registo(s) da amostra com prova que não fecha"),
                            "não represente esta evidência como verificada; corra `heraclitus storage doctor`",
                        )
                    } else if provadas == 0 && por_selar > 0 {
                        Check::warn(
                            "current integrity",
                            format!("{n} registos; nenhum segmento selado ainda ({por_selar} por selar)"),
                            "a prova aparece quando o segmento sela; `v6_packing_interval_secs` controla a cadência",
                        )
                    } else {
                        Check::ok(
                            "current integrity",
                            format!("{n} registos; {provadas} da amostra com prova válida"),
                        )
                    });
                }
                Err(e) => checks.push(Check::fail(
                    "current integrity",
                    e.to_string(),
                    "corra `heraclitus storage doctor` no directório de dados",
                )),
            }
        }
    }

    // ── listeners ───────────────────────────────────────────────────────────
    checks.push(if !config.enabled {
        Check::warn(
            "OTLP listener",
            "o Agent Black Box está desligado",
            "ponha `[agent_black_box] enabled = true` na configuração",
        )
    } else if config.otlp.http_addr.is_empty() {
        Check::fail(
            "OTLP listener",
            "sem `otlp.http_addr`",
            "defina `otlp.http_addr = \"0.0.0.0:4318\"`",
        )
    } else {
        Check::ok(
            "OTLP listener",
            format!("HTTP em {}", config.otlp.http_addr),
        )
    });

    checks.push(if config.otlp.grpc_addr.is_empty() {
        // Não é falha: o default do exporter OTel para
        // `OTEL_EXPORTER_OTLP_ENDPOINT=http://host:4318` é `http/protobuf`.
        // Quem tiver o exporter fixado em gRPC precisa deste endereço.
        Check::skipped(
            "OTLP/gRPC",
            "não configurado (o HTTP cobre o default do exporter OTel)",
        )
    } else {
        Check::ok("OTLP/gRPC", format!("gRPC em {}", config.otlp.grpc_addr))
    });

    checks.push(if config.console.enabled {
        Check::ok("console", format!("em {}", config.console.addr))
    } else {
        Check::warn(
            "console",
            "desligada",
            "sem consola, a evidência só é visível pela API e pelo bundle",
        )
    });

    // ── gateway ─────────────────────────────────────────────────────────────
    checks.push(if !gateway.enabled {
        Check::skipped("gateway mode", "o Policy Gateway está desligado")
    } else {
        match gateway.mode {
            GatewayMode::Observe => Check::warn(
                "gateway mode",
                "observe — a policy não é avaliada",
                "passe a `shadow` para ver o que seria bloqueado antes de bloquear",
            ),
            GatewayMode::Shadow => {
                Check::ok("gateway mode", "shadow — avalia e regista, não bloqueia")
            }
            GatewayMode::Enforce => Check::ok("gateway mode", "enforce — bloqueia"),
        }
    });

    if gateway.enabled {
        checks.push(if gateway.bypass_protection_configured {
            Check::ok("bypass protection", "declarada como configurada")
        } else {
            Check::warn(
                "bypass protection",
                "UNKNOWN",
                "enquanto o agente puder chamar o upstream directamente, o gateway não impõe nada; \
                 restrinja o egress e ponha `bypass_protection_configured = true` quando for verdade",
            )
        });
    }

    // ── policy ──────────────────────────────────────────────────────────────
    checks.push(if gateway.policy.active.is_empty() {
        if gateway.enabled && gateway.mode != GatewayMode::Observe {
            Check::warn(
                "active policy",
                "nenhuma policy configurada — o default é negar tudo",
                "aponte `[agent_gateway.policy] active` para um ficheiro agent-policy-v1",
            )
        } else {
            Check::skipped("active policy", "sem policy configurada")
        }
    } else {
        match std::fs::read_to_string(&gateway.policy.active) {
            Err(e) => Check::fail(
                "active policy",
                format!("{}: {e}", gateway.policy.active),
                "corrija o caminho ou as permissões do ficheiro de policy",
            ),
            Ok(raw) => match DeterministicAgentPolicyEngine::parse(&raw) {
                Ok(engine) => Check::ok(
                    "active policy",
                    format!(
                        "{} / {} · {} regras · hash {}",
                        engine.document().id,
                        engine.revision(),
                        engine.document().rules.len(),
                        &engine.hash()[..16]
                    ),
                ),
                Err(e) => Check::fail(
                    "active policy",
                    e.to_string(),
                    "corrija o documento; enquanto estiver inválido o gateway nega tudo",
                ),
            },
        }
    });

    // ── identidade ──────────────────────────────────────────────────────────
    checks.push(if gateway.identity.mode == "oidc" {
        if gateway.identity.jwks_path.is_empty() {
            Check::fail(
                "identity provider",
                "modo oidc sem `jwks_path`",
                "aponte `identity.jwks_path` para um ficheiro JWKS do seu emissor",
            )
        } else {
            match std::fs::read_to_string(&gateway.identity.jwks_path) {
                Err(e) => Check::fail(
                    "identity provider",
                    format!("{}: {e}", gateway.identity.jwks_path),
                    "descarregue o JWKS do emissor e guarde-o neste caminho",
                ),
                Ok(raw) => match crate::identity::KeySet::from_jwks(&raw) {
                    Ok(ks) if !ks.is_empty() => Check::ok(
                        "identity provider",
                        format!("JWKS com {} chave(s)", ks.len()),
                    ),
                    Ok(_) => Check::fail(
                        "identity provider",
                        "o JWKS não tem chaves RSA nem EC P-256",
                        "confirme o `jwks_uri` do emissor; só RS256 e ES256 são validáveis aqui",
                    ),
                    Err(e) => Check::fail(
                        "identity provider",
                        e.to_string(),
                        "o ficheiro não é um JWKS válido",
                    ),
                },
            }
        }
    } else if production {
        Check::fail(
            "identity provider",
            "modo dev_local num perfil de produção",
            "configure `[agent_gateway.identity] mode = \"oidc\"`",
        )
    } else {
        Check::warn(
            "identity provider",
            "dev_local — sem autenticação",
            "não use este perfil fora de uma máquina de desenvolvimento",
        )
    });

    // ── TLS / produção ──────────────────────────────────────────────────────
    checks.push(match config.validate(production, false, false) {
        Ok(()) => Check::ok(
            "TLS / production gates",
            "a configuração passa os gates de §23",
        ),
        Err(e) => Check::warn(
            "TLS / production gates",
            e.to_string(),
            "configure TLS e autenticação, ou ligue os listeners a loopback",
        ),
    });

    // ── captura ─────────────────────────────────────────────────────────────
    checks.push(match config.capture_mode() {
        crate::evidence::CaptureModeV1::FullExplicit => Check::warn(
            "capture mode",
            "FULL_EXPLICIT — corpos completos são persistidos",
            "confirme que é isso que quer; o default seguro é metadata_only",
        ),
        m => Check::ok("capture mode", m.label()),
    });

    // ── relógio e disco ─────────────────────────────────────────────────────
    let agora = crate::bundle::now_unix_nanos() / 1_000_000_000;
    checks.push(if agora < 1_600_000_000 {
        Check::fail(
            "clock",
            format!("o relógio diz {agora}, o que é antes de 2020"),
            "sincronize o relógio: carimbos de tempo errados tornam a evidência difícil de defender",
        )
    } else {
        Check::ok("clock", "plausível")
    });

    checks.push(match free_space(data_dir) {
        Some(bytes) if bytes < 512 * 1024 * 1024 => Check::warn(
            "disk space",
            format!("{} MiB livres", bytes / (1024 * 1024)),
            "um log append-only que fica sem disco deixa de aceitar evidência",
        ),
        Some(bytes) => Check::ok(
            "disk space",
            format!("{} MiB livres", bytes / (1024 * 1024)),
        ),
        None => Check::skipped("disk space", "não foi possível medir nesta plataforma"),
    });

    let failures = checks
        .iter()
        .filter(|c| c.status == CheckStatus::Fail)
        .count();
    let warnings = checks
        .iter()
        .filter(|c| c.status == CheckStatus::Warn)
        .count();
    DoctorReport {
        checks,
        failures,
        warnings,
    }
}

fn writable(dir: &Path) -> Result<(), String> {
    if !dir.exists() {
        std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    }
    let probe = dir.join(".heraclitus-agent-doctor");
    std::fs::write(&probe, b"ok").map_err(|e| e.to_string())?;
    std::fs::remove_file(&probe).map_err(|e| e.to_string())?;
    Ok(())
}

/// Espaço livre. Sem dependência nova: usa o que o sistema de ficheiros já
/// expõe através de uma escrita de sonda quando não há API portátil.
fn free_space(_dir: &Path) -> Option<u64> {
    // `std` não expõe `statvfs`/`GetDiskFreeSpaceEx` de forma portátil e não
    // vale uma dependência nova só para isto. Reportar `None` é honesto;
    // inventar um número não é.
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn o_relatorio_nomeia_a_accao_quando_falha() {
        let dir = tempfile::tempdir().unwrap();
        let config = AgentBlackBoxConfig::default();
        let gateway = AgentGatewayConfig::default();
        let r = run(dir.path(), &config, &gateway, None, false);
        let texto = r.to_human();
        assert!(texto.contains("heraclitus agent doctor"));
        // Com o produto desligado, o doctor avisa em vez de fingir que está bem.
        assert!(r.warnings > 0, "{texto}");
        for c in &r.checks {
            if c.status == CheckStatus::Fail || c.status == CheckStatus::Warn {
                assert!(!c.action.is_empty(), "{} não diz o que fazer", c.name);
            }
        }
    }

    #[test]
    fn policy_invalida_e_falha_e_nao_aviso() {
        let dir = tempfile::tempdir().unwrap();
        let caminho = dir.path().join("policy.yaml");
        std::fs::write(&caminho, "version: \"agent-policy-v9\"\n").unwrap();
        let gateway = AgentGatewayConfig {
            enabled: true,
            policy: crate::config::PolicyConfig {
                active: caminho.display().to_string(),
                default_decision: "deny".into(),
            },
            ..Default::default()
        };
        let r = run(
            dir.path(),
            &AgentBlackBoxConfig::default(),
            &gateway,
            None,
            false,
        );
        let policy = r.checks.iter().find(|c| c.name == "active policy").unwrap();
        assert_eq!(policy.status, CheckStatus::Fail, "{policy:?}");
    }

    #[test]
    fn enforce_sem_bypass_protection_avisa() {
        let dir = tempfile::tempdir().unwrap();
        let gateway = AgentGatewayConfig {
            enabled: true,
            mode: GatewayMode::Enforce,
            ..Default::default()
        };
        let r = run(
            dir.path(),
            &AgentBlackBoxConfig::default(),
            &gateway,
            None,
            false,
        );
        let c = r
            .checks
            .iter()
            .find(|c| c.name == "bypass protection")
            .unwrap();
        assert_eq!(c.status, CheckStatus::Warn);
        assert!(c.action.contains("egress"), "{}", c.action);
    }

    #[test]
    fn o_codigo_de_saida_reflecte_falhas() {
        let dir = tempfile::tempdir().unwrap();
        let r = run(
            dir.path(),
            &AgentBlackBoxConfig::default(),
            &AgentGatewayConfig::default(),
            None,
            false,
        );
        assert_eq!(r.exit_code(), if r.failures > 0 { 1 } else { 0 });
    }
}
