//! SPEC-0074 §22, SPEC-0076 §14 — a ligação do Agent Black Box ao servidor.
//!
//! # Porque a configuração do plano de agentes é lida à parte
//!
//! `HeraclitusConfig` vive no `heraclitus-core`, e o `heraclitus-agent` depende
//! do core. Pôr `AgentBlackBoxConfig` dentro de `HeraclitusConfig` fecharia o
//! ciclo `core -> agent -> core`.
//!
//! A alternativa seria duplicar a forma dos tipos no core e converter — e
//! duplicar a forma é criar duas fontes de verdade que divergem no dia em que
//! alguém acrescentar um campo a uma e esquecer a outra. Ler as secções
//! `[agent_black_box]` e `[agent_gateway]` do MESMO ficheiro, com os MESMOS
//! tipos, não tem esse problema.
//!
//! # As variáveis de ambiente existem para o quickstart
//!
//! ```bash
//! docker run -e HERACLITUS_AGENT_ENABLED=1 ...
//! ```
//!
//! Sem elas, a imagem de Docker de §20 da 0076 exigiria um ficheiro de
//! configuração montado — e o gate de cinco minutos morreria aí.

use heraclitus_agent::config::{AgentBlackBoxConfig, AgentGatewayConfig, GatewayMode};
use heraclitus_agent::evidence::AgentEvidenceV1;
use heraclitus_agent::store::{
    AnyLogEvidenceStore, EvidenceLog, ProofAvailability, StoredEvidence,
};
use heraclitus_agent_gateway::runtime::AgentRuntime;
use heraclitus_core::{HeraclitusConfig, HeraclitusError, Lsn};
use std::path::Path;
use std::sync::Arc;

/// As duas secções de configuração do plano de agentes.
#[derive(Debug, Clone, Default)]
pub struct AgentPlane {
    pub black_box: AgentBlackBoxConfig,
    pub gateway: AgentGatewayConfig,
}

impl AgentPlane {
    /// Lê `[agent_black_box]` e `[agent_gateway]` do TOML e aplica o ambiente.
    pub fn load(path: Option<&Path>) -> Result<Self, HeraclitusError> {
        let mut plane = match path {
            None => Self::default(),
            Some(p) => {
                let raw = std::fs::read_to_string(p)?;
                let doc: toml::Value = toml::from_str(&raw)
                    .map_err(|e| HeraclitusError::Config(format!("{}: {e}", p.display())))?;
                Self {
                    black_box: doc
                        .get("agent_black_box")
                        .cloned()
                        .map(|v| v.try_into())
                        .transpose()
                        .map_err(|e| HeraclitusError::Config(format!("[agent_black_box]: {e}")))?
                        .unwrap_or_default(),
                    gateway: doc
                        .get("agent_gateway")
                        .cloned()
                        .map(|v| v.try_into())
                        .transpose()
                        .map_err(|e| HeraclitusError::Config(format!("[agent_gateway]: {e}")))?
                        .unwrap_or_default(),
                }
            }
        };
        plane.apply_env()?;
        Ok(plane)
    }

    fn apply_env(&mut self) -> Result<(), HeraclitusError> {
        let truthy =
            |v: &str| matches!(v.to_ascii_lowercase().as_str(), "1" | "true" | "on" | "yes");
        if let Ok(v) = std::env::var("HERACLITUS_AGENT_ENABLED") {
            self.black_box.enabled = truthy(&v);
        }
        if let Ok(v) = std::env::var("HERACLITUS_AGENT_TENANT") {
            self.black_box.tenant_id = v;
        }
        if let Ok(v) = std::env::var("HERACLITUS_AGENT_CAPTURE_MODE") {
            if heraclitus_agent::evidence::CaptureModeV1::parse(&v).is_none() {
                return Err(HeraclitusError::Config(format!(
                    "HERACLITUS_AGENT_CAPTURE_MODE=`{v}` não existe \
                     (metadata_only|hash_only|redacted|full_explicit)"
                )));
            }
            self.black_box.capture_mode = v;
        }
        if let Ok(v) = std::env::var("HERACLITUS_AGENT_OTLP_HTTP_ADDR") {
            self.black_box.otlp.http_addr = v;
        }
        if let Ok(v) = std::env::var("HERACLITUS_AGENT_OTLP_GRPC_ADDR") {
            self.black_box.otlp.grpc_addr = v;
        }
        if let Ok(v) = std::env::var("HERACLITUS_AGENT_CONSOLE_ADDR") {
            self.black_box.console.addr = v;
        }
        // A credencial partilhada. Deliberadamente NAO ha default: uma senha
        // por omissao seria uma porta aberta com aparencia de fechada.
        if let Ok(v) = std::env::var("HERACLITUS_AGENT_CONSOLE_BASIC_AUTH") {
            self.black_box.console.basic_auth = v;
        }
        if let Ok(v) = std::env::var("HERACLITUS_AGENT_OTLP_REQUIRE_AUTH") {
            self.black_box.otlp.require_auth = truthy(&v);
        }
        if let Ok(v) = std::env::var("HERACLITUS_AGENT_GATEWAY_ENABLED") {
            self.gateway.enabled = truthy(&v);
        }
        if let Ok(v) = std::env::var("HERACLITUS_AGENT_GATEWAY_MODE") {
            self.gateway.mode = GatewayMode::parse(&v).ok_or_else(|| {
                HeraclitusError::Config(format!(
                    "HERACLITUS_AGENT_GATEWAY_MODE=`{v}` não existe (observe|shadow|enforce)"
                ))
            })?;
        }
        if let Ok(v) = std::env::var("HERACLITUS_AGENT_GATEWAY_UPSTREAM") {
            self.gateway.upstream_url = v;
        }
        if let Ok(v) = std::env::var("HERACLITUS_AGENT_POLICY") {
            self.gateway.policy.active = v;
        }
        Ok(())
    }

    pub fn enabled(&self) -> bool {
        self.black_box.enabled || self.gateway.enabled
    }

    /// Os gates de §23 da 0074 e §29 da 0075, contra o perfil do host.
    pub fn validate(&self, host: &HeraclitusConfig) -> Result<(), HeraclitusError> {
        let tls = host.tls_cert_path.is_some() && host.tls_key_path.is_some();

        // AUTH TRUTH: cada superfície conta apenas a credencial que ela
        // realmente consome. `rest_basic_auth` nunca protege a Console/OTLP.
        let agent_console_auth = self.black_box.console.has_basic_auth()
            || (self.gateway.identity.mode == "oidc"
                && !self.gateway.identity.issuer.is_empty()
                && !self.gateway.identity.audience.is_empty()
                && !self.gateway.identity.jwks_path.is_empty());
        self.black_box
            .validate(host.production_mode, tls, agent_console_auth)
            .map_err(|e| HeraclitusError::Config(e.to_string()))?;
        self.gateway
            .validate(host.production_mode, tls)
            .map_err(|e| HeraclitusError::Config(e.to_string()))?;

        // SPEC-0084: loopback is not a trust boundary when the threat is a
        // compromised LOCAL agent. `enforce` would be a false promise if that
        // process could simply skip MCP and talk anonymously to Core gRPC/REST.
        if self.gateway.enabled && self.gateway.mode == GatewayMode::Enforce {
            let grpc_auth = host.auth_token.is_some() || !host.access_credentials.is_empty();
            let rest_auth = host.rest_basic_auth.is_some() || !host.access_credentials.is_empty();
            if !grpc_auth || !rest_auth {
                return Err(HeraclitusError::Config(format!(
                    "agent_gateway mode=enforce exige autenticação nas DUAS superfícies Core:                      gRPC={} REST={}. Loopback não é fronteira de confiança contra agente local                      comprometido (SPEC-0084)",
                    if grpc_auth { "protected" } else { "OPEN" },
                    if rest_auth { "protected" } else { "OPEN" }
                )));
            }
        }
        Ok(())
    }
}

/// Log de evidência sobre o `Engine` do servidor.
///
/// # Porque não escrever directamente no `AnyLog`
///
/// Porque o `Engine` mantém memtable, views e índices coerentes com o head do
/// log. Um append que o contorne deixa o watermark das views atrás do log, e o
/// próximo checkpoint grava um snapshot que mente sobre o que já viu. A
/// leitura e a prova, essas, vão direitas ao log — não mexem em estado nenhum.
pub struct EngineEvidenceStore {
    engine: Arc<crate::engine::Engine>,
    direct: AnyLogEvidenceStore,
}

impl EngineEvidenceStore {
    pub fn new(engine: Arc<crate::engine::Engine>) -> Self {
        let direct = AnyLogEvidenceStore::new(engine.log.clone());
        Self { engine, direct }
    }
}

impl EvidenceLog for EngineEvidenceStore {
    fn append_evidence(&self, e: &AgentEvidenceV1) -> Result<Lsn, HeraclitusError> {
        let stamped;
        let e = if e.dedupe_key.is_empty() {
            stamped = heraclitus_agent::dedupe::stamp(e.clone());
            &stamped
        } else {
            e
        };
        self.engine
            .append(heraclitus_agent::store::evidence_to_episode(e)?)
    }

    fn scan_evidence(&self, from: Lsn, to: Lsn) -> Result<Vec<StoredEvidence>, HeraclitusError> {
        self.direct.scan_evidence(from, to)
    }

    fn read_evidence(&self, lsn: Lsn) -> Result<Option<StoredEvidence>, HeraclitusError> {
        self.direct.read_evidence(lsn)
    }

    fn head(&self) -> Lsn {
        self.engine.head()
    }

    fn flush(&self) -> Result<(), HeraclitusError> {
        self.direct.flush()
    }

    fn prove(&self, lsn: Lsn) -> Result<ProofAvailability, HeraclitusError> {
        self.direct.prove(lsn)
    }
}

/// Constrói o runtime que serve o porto da consola.
///
/// # Porque é que isto corre mesmo com o módulo de agentes DESLIGADO
///
/// SPEC-0077 §21/§48: a Platform Console é a superfície do HeraclitusDB, e o
/// HeraclitusDB não depende do módulo de agentes para existir. Com o módulo
/// desligado este runtime serve `/` e mais nada — nenhum listener OTLP, nenhum
/// proxy MCP, nenhuma rota de agente com conteúdo.
///
/// O que fica ATRÁS do interruptor é o trabalho caro: `warm()` percorre o log
/// inteiro (0..head) para reconstruir o índice de deduplicação. Correr isso no
/// arranque de quem nunca ligou agentes seria fazer toda a gente pagar por uma
/// funcionalidade que não pediu — num log de gigabytes, minutos de arranque.
pub fn build_runtime(
    engine: Arc<crate::engine::Engine>,
    plane: &AgentPlane,
    config: &HeraclitusConfig,
) -> Result<Arc<AgentRuntime>, HeraclitusError> {
    let ligado = plane.enabled();
    let fonte = Arc::new(crate::platform_source::EnginePlatformSource::new(
        engine.clone(),
        config,
        ligado,
    ));
    let store = Arc::new(EngineEvidenceStore::new(engine));
    let mut runtime = AgentRuntime::new(plane.black_box.clone(), plane.gateway.clone(), store)
        .with_bundles_dir(config.data_dir.join("agent-bundles"));
    runtime.load_validator()?;
    runtime.load_console_credential()?;
    let runtime = Arc::new(runtime.with_platform(fonte));
    if !ligado {
        tracing::info!("módulo de agentes desligado; a servir só a Platform Console");
        return Ok(runtime);
    }
    runtime.load_policy()?;
    // Reconstruir o índice de deduplicação a partir do log: sem isto, um
    // reinício seguido da retransmissão de um lote OTLP duplicaria a história
    // (SPEC-0074 §24).
    let n = runtime.warm()?;
    tracing::info!(
        evidencias = n,
        modo = runtime.config.capture_mode().label(),
        "plano de evidência de agentes pronto"
    );
    Ok(runtime)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn le_as_duas_seccoes_do_mesmo_ficheiro() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("heraclitus.toml");
        std::fs::write(
            &p,
            r#"
data_dir = "./data"

[agent_black_box]
enabled = true
capture_mode = "metadata_only"

[agent_black_box.otlp]
http_addr = "0.0.0.0:4318"
grpc_addr = "0.0.0.0:4317"

[agent_gateway]
enabled = true
mode = "shadow"
upstream_url = "http://mcp:9000"
"#,
        )
        .unwrap();
        let plane = AgentPlane::load(Some(&p)).unwrap();
        assert!(plane.black_box.enabled);
        assert_eq!(plane.black_box.otlp.http_addr, "0.0.0.0:4318");
        assert_eq!(plane.black_box.otlp.grpc_addr, "0.0.0.0:4317");
        assert_eq!(plane.gateway.mode, GatewayMode::Shadow);
        assert_eq!(plane.gateway.upstream_url, "http://mcp:9000");
    }

    #[test]
    fn um_ficheiro_sem_as_seccoes_da_o_default_desligado() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("heraclitus.toml");
        std::fs::write(&p, "data_dir = \"./data\"\n").unwrap();
        let plane = AgentPlane::load(Some(&p)).unwrap();
        assert!(!plane.enabled());
    }

    #[test]
    fn capture_mode_invalido_no_ambiente_e_recusado() {
        let mut plane = AgentPlane::default();
        // SAFETY: teste de processo único; a variável é removida a seguir.
        unsafe { std::env::set_var("HERACLITUS_AGENT_CAPTURE_MODE", "tudo") };
        let r = plane.apply_env();
        unsafe { std::env::remove_var("HERACLITUS_AGENT_CAPTURE_MODE") };
        assert!(r.is_err());
    }

    #[test]
    fn enforce_recusa_core_grpc_anonimo_mesmo_em_loopback() {
        let host = HeraclitusConfig {
            rest_basic_auth: Some("admin:0123456789abcdef".into()),
            ..Default::default()
        };
        let plane = AgentPlane {
            gateway: AgentGatewayConfig {
                enabled: true,
                mode: GatewayMode::Enforce,
                upstream_url: "http://127.0.0.1:9000".into(),
                ..Default::default()
            },
            ..Default::default()
        };
        let err = plane.validate(&host).unwrap_err().to_string();
        assert!(err.contains("gRPC=OPEN"), "{err}");
    }

    #[test]
    fn enforce_recusa_core_rest_anonimo_mesmo_em_loopback() {
        let host = HeraclitusConfig {
            auth_token: Some("0123456789abcdef0123456789abcdef".into()),
            ..Default::default()
        };
        let plane = AgentPlane {
            gateway: AgentGatewayConfig {
                enabled: true,
                mode: GatewayMode::Enforce,
                upstream_url: "http://127.0.0.1:9000".into(),
                ..Default::default()
            },
            ..Default::default()
        };
        let err = plane.validate(&host).unwrap_err().to_string();
        assert!(err.contains("REST=OPEN"), "{err}");
    }

    #[test]
    fn enforce_aceita_core_autenticado_nas_duas_superficies() {
        let host = HeraclitusConfig {
            auth_token: Some("0123456789abcdef0123456789abcdef".into()),
            rest_basic_auth: Some("admin:0123456789abcdef".into()),
            ..Default::default()
        };
        let plane = AgentPlane {
            gateway: AgentGatewayConfig {
                enabled: true,
                mode: GatewayMode::Enforce,
                upstream_url: "http://127.0.0.1:9000".into(),
                ..Default::default()
            },
            ..Default::default()
        };
        assert!(plane.validate(&host).is_ok());
    }

    #[test]
    fn shadow_preserva_perfil_dev_loopback_sem_auth() {
        let host = HeraclitusConfig::default();
        let plane = AgentPlane {
            gateway: AgentGatewayConfig {
                enabled: true,
                mode: GatewayMode::Shadow,
                upstream_url: "http://127.0.0.1:9000".into(),
                ..Default::default()
            },
            ..Default::default()
        };
        assert!(plane.validate(&host).is_ok());
    }

    #[test]
    fn producao_sem_tls_recusa_bind_publico() {
        let mut host = HeraclitusConfig {
            production_mode: true,
            ..Default::default()
        };
        host.tls_cert_path = None;
        let plane = AgentPlane {
            black_box: AgentBlackBoxConfig {
                enabled: true,
                ..Default::default()
            },
            gateway: AgentGatewayConfig::default(),
        };
        assert!(plane.validate(&host).is_err());
    }
}
