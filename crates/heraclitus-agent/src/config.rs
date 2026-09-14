//! SPEC-0074 §22 e SPEC-0075 §29 — a configuração.
//!
//! # O que os defaults dizem
//!
//! Cada default aqui é uma decisão de produto, não uma conveniência:
//!
//! | campo | default | porquê |
//! |---|---|---|
//! | `capture_mode` | `metadata_only` | observabilidade não pode virar fuga (§11) |
//! | `mcp.enabled` | `false` | um proxy não se liga sozinho no caminho de ninguém |
//! | `gateway.mode` | `shadow` | `observe -> shadow -> enforce` (§24) |
//! | `gateway.policy.default_decision` | `deny` | fail closed (§2.2) |
//! | `rfc3161` | `false` | ancoragem externa é uma decisão do operador |
//!
//! O endereço `0.0.0.0` nos listeners de ingestão é o que torna o quickstart de
//! Docker possível; [`AgentBlackBoxConfig::validate`] exige TLS e autenticação
//! quando o perfil é de produção e o bind não é loopback (§23).

use crate::evidence::CaptureModeV1;
use crate::otlp::IngestLimits;
use serde::{Deserialize, Serialize};

/// `[agent_black_box]`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AgentBlackBoxConfig {
    pub enabled: bool,
    /// `metadata_only` | `hash_only` | `redacted` | `full_explicit`.
    pub capture_mode: String,
    pub tenant_id: String,
    pub max_body_bytes: usize,
    pub otlp: OtlpConfig,
    pub mcp: McpCaptureConfig,
    pub redaction: RedactionConfig,
    pub evidence: EvidenceConfig,
    pub console: ConsoleConfig,
    pub limits: IngestLimits,
}

impl Default for AgentBlackBoxConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            capture_mode: "metadata_only".to_string(),
            tenant_id: "default".to_string(),
            max_body_bytes: 4 * 1024 * 1024,
            otlp: OtlpConfig::default(),
            mcp: McpCaptureConfig::default(),
            redaction: RedactionConfig::default(),
            evidence: EvidenceConfig::default(),
            console: ConsoleConfig::default(),
            limits: IngestLimits::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct OtlpConfig {
    pub http_addr: String,
    /// SPEC-0074 §30 permite adiar o OTLP/gRPC para a 0074.1 desde que o
    /// adiamento esteja documentado. Está: `docs/agent/otel.md`. Quando este
    /// campo estiver preenchido e o suporte existir, o servidor escuta aqui.
    pub grpc_addr: String,
}

impl Default for OtlpConfig {
    fn default() -> Self {
        Self {
            http_addr: "0.0.0.0:4318".to_string(),
            grpc_addr: String::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct McpCaptureConfig {
    pub enabled: bool,
    pub listen_addr: String,
    /// `observe` (só metadados do host) ou `proxy` (o tráfego passa por aqui).
    pub mode: String,
}

impl Default for McpCaptureConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            listen_addr: "127.0.0.1:8787".to_string(),
            mode: "observe".to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct RedactionConfig {
    pub profile: String,
    pub deny_headers: Vec<String>,
    pub deny_fields: Vec<String>,
    pub max_field_bytes: usize,
    pub max_fields: usize,
}

impl Default for RedactionConfig {
    fn default() -> Self {
        Self {
            profile: "default".to_string(),
            deny_headers: crate::privacy::DENY_HEADERS_DEFAULT
                .iter()
                .map(|s| s.to_string())
                .collect(),
            deny_fields: crate::privacy::DENY_FIELDS_DEFAULT
                .iter()
                .map(|s| s.to_string())
                .collect(),
            max_field_bytes: 1024,
            max_fields: 64,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct EvidenceConfig {
    pub rfc3161: bool,
    /// Tecto de registos por Evidence Bundle.
    pub max_bundle_records: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ConsoleConfig {
    pub enabled: bool,
    pub addr: String,
}

impl Default for ConsoleConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            addr: "0.0.0.0:8080".to_string(),
        }
    }
}

/// Modo do gateway (§24). A ordem é a ordem de adopção.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum GatewayMode {
    /// Só regista. Não avalia policy, não bloqueia.
    Observe,
    /// Avalia e regista `would deny` / `would require approval`. Não bloqueia.
    #[default]
    Shadow,
    /// Bloqueia.
    Enforce,
}

impl GatewayMode {
    pub fn label(self) -> &'static str {
        match self {
            Self::Observe => "observe",
            Self::Shadow => "shadow",
            Self::Enforce => "enforce",
        }
    }
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s.to_ascii_lowercase().as_str() {
            "observe" => Self::Observe,
            "shadow" => Self::Shadow,
            "enforce" => Self::Enforce,
            _ => return None,
        })
    }
    pub fn enforces(self) -> bool {
        self == Self::Enforce
    }
}

/// `[agent_gateway]`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AgentGatewayConfig {
    pub enabled: bool,
    pub mode: GatewayMode,
    pub listen_addr: String,
    /// Para onde o proxy encaminha em `enforce`/`shadow`.
    pub upstream_url: String,
    pub identity: IdentityConfig,
    pub policy: PolicyConfig,
    pub approval: ApprovalConfig,
    /// SPEC-0075 §20 — o operador declara que a topologia impede o agente de
    /// falar directamente com o upstream. A UI mostra
    /// `BYPASS PROTECTION: CONFIGURED / UNKNOWN` a partir daqui, e nunca
    /// afirma enforcement por conta própria.
    pub bypass_protection_configured: bool,
}

impl Default for AgentGatewayConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            mode: GatewayMode::Shadow,
            listen_addr: "0.0.0.0:8787".to_string(),
            upstream_url: String::new(),
            identity: IdentityConfig::default(),
            policy: PolicyConfig::default(),
            approval: ApprovalConfig::default(),
            bypass_protection_configured: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct IdentityConfig {
    /// `dev_local` ou `oidc`.
    pub mode: String,
    pub issuer: String,
    pub audience: String,
    /// Ficheiro JWKS local. Sem rede no caminho de validação: quem quiser
    /// rotação automática busca o JWKS fora e escreve o ficheiro.
    pub jwks_path: String,
    pub roles_claim: String,
    pub clock_skew_seconds: u64,
}

impl Default for IdentityConfig {
    fn default() -> Self {
        Self {
            mode: "dev_local".to_string(),
            issuer: String::new(),
            audience: String::new(),
            jwks_path: String::new(),
            roles_claim: "roles".to_string(),
            clock_skew_seconds: 60,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct PolicyConfig {
    pub active: String,
    pub default_decision: String,
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            active: String::new(),
            default_decision: "deny".to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ApprovalConfig {
    pub default_ttl_seconds: u64,
}

impl Default for ApprovalConfig {
    fn default() -> Self {
        Self {
            default_ttl_seconds: 300,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ConfigError {
    #[error("configuração inválida: {0}")]
    Invalid(String),
}

impl AgentBlackBoxConfig {
    pub fn capture_mode(&self) -> CaptureModeV1 {
        CaptureModeV1::parse(&self.capture_mode).unwrap_or_default()
    }

    pub fn redaction_profile(&self) -> crate::privacy::RedactionProfile {
        crate::privacy::RedactionProfile {
            profile_id: self.redaction.profile.clone(),
            capture_mode: self.capture_mode(),
            max_body_bytes: self.max_body_bytes.min(1 << 20),
            max_field_bytes: self.redaction.max_field_bytes,
            max_fields: self.redaction.max_fields,
            deny_headers: self.redaction.deny_headers.clone(),
            deny_fields: self.redaction.deny_fields.clone(),
        }
    }

    /// Gates de §23. `production` vem do host (`HeraclitusConfig::production_mode`).
    pub fn validate(
        &self,
        production: bool,
        tls_configured: bool,
        auth_configured: bool,
    ) -> Result<(), ConfigError> {
        if !self.enabled {
            return Ok(());
        }
        if CaptureModeV1::parse(&self.capture_mode).is_none() {
            return Err(ConfigError::Invalid(format!(
                "capture_mode `{}` não existe (metadata_only|hash_only|redacted|full_explicit)",
                self.capture_mode
            )));
        }
        if self.max_body_bytes == 0 {
            return Err(ConfigError::Invalid(
                "max_body_bytes = 0 recusaria todos os lotes".into(),
            ));
        }
        if production {
            if self.capture_mode() == CaptureModeV1::FullExplicit {
                // Não é proibido — §11 di-lo explicitamente possível — mas tem
                // de ser uma decisão administrativa, não um default herdado.
                // O gate é o `production_mode` obrigar a declarar TLS e auth.
                if !tls_configured || !auth_configured {
                    return Err(ConfigError::Invalid(
                        "capture_mode = full_explicit em produção exige TLS e autenticação \
                         configurados: os corpos capturados passam a ser dados sensíveis em repouso"
                            .into(),
                    ));
                }
            }
            for (nome, addr) in [
                ("otlp.http_addr", &self.otlp.http_addr),
                ("otlp.grpc_addr", &self.otlp.grpc_addr),
                ("console.addr", &self.console.addr),
            ] {
                if !addr.is_empty() && !is_loopback(addr) && (!tls_configured || !auth_configured) {
                    return Err(ConfigError::Invalid(format!(
                        "{nome} = `{addr}` não é loopback e o perfil é de produção: \
                         exige TLS e autenticação (SPEC-0074 §23)"
                    )));
                }
            }
        }
        Ok(())
    }
}

impl AgentGatewayConfig {
    pub fn validate(&self, production: bool, tls_configured: bool) -> Result<(), ConfigError> {
        if !self.enabled {
            return Ok(());
        }
        if self.mode != GatewayMode::Observe && self.upstream_url.is_empty() {
            return Err(ConfigError::Invalid(
                "o gateway em shadow/enforce precisa de `upstream_url`".into(),
            ));
        }
        if production {
            if self.identity.mode != "oidc" {
                return Err(ConfigError::Invalid(
                    "o perfil de produção exige identity.mode = \"oidc\": \
                     dev_local aceita qualquer chamador em loopback"
                        .into(),
                ));
            }
            if self.identity.issuer.is_empty() || self.identity.audience.is_empty() {
                return Err(ConfigError::Invalid(
                    "identity.issuer e identity.audience são obrigatórios em produção".into(),
                ));
            }
            if self.identity.jwks_path.is_empty() {
                return Err(ConfigError::Invalid(
                    "identity.jwks_path é obrigatório em produção: sem chaves não há validação"
                        .into(),
                ));
            }
            if !is_loopback(&self.listen_addr) && !tls_configured {
                return Err(ConfigError::Invalid(format!(
                    "agent_gateway.listen_addr = `{}` não é loopback e não há TLS configurado",
                    self.listen_addr
                )));
            }
            if self.mode == GatewayMode::Enforce && !self.bypass_protection_configured {
                // Não recusar seria pior do que recusar: o gateway em enforce
                // sem topologia que o garanta mostra "bloqueado" a quem pode
                // simplesmente chamar o upstream directamente (§20).
                return Err(ConfigError::Invalid(
                    "mode = \"enforce\" em produção exige bypass_protection_configured = true. \
                     Enquanto o agente puder falar directamente com o upstream, o gateway \
                     não impõe nada e dizer que impõe seria falso (SPEC-0075 §20)."
                        .into(),
                ));
            }
        }
        if self.approval.default_ttl_seconds == 0 {
            return Err(ConfigError::Invalid(
                "approval.default_ttl_seconds = 0 criaria aprovações já expiradas".into(),
            ));
        }
        Ok(())
    }
}

fn is_loopback(addr: &str) -> bool {
    let host = addr.rsplit_once(':').map(|(h, _)| h).unwrap_or(addr);
    let host = host.trim_matches(|c| c == '[' || c == ']');
    host == "127.0.0.1" || host == "localhost" || host == "::1" || host.starts_with("127.")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn os_defaults_sao_os_seguros() {
        let c = AgentBlackBoxConfig::default();
        assert!(!c.enabled);
        assert_eq!(c.capture_mode(), CaptureModeV1::MetadataOnly);
        assert!(!c.mcp.enabled);
        assert!(!c.evidence.rfc3161);
        let g = AgentGatewayConfig::default();
        assert!(!g.enabled);
        assert_eq!(g.mode, GatewayMode::Shadow);
        assert_eq!(g.policy.default_decision, "deny");
    }

    #[test]
    fn producao_sem_tls_recusa_bind_publico() {
        let mut c = AgentBlackBoxConfig {
            enabled: true,
            ..Default::default()
        };
        c.otlp.http_addr = "0.0.0.0:4318".into();
        assert!(c.validate(true, false, false).is_err());
        assert!(c.validate(true, true, true).is_ok());
        assert!(c.validate(false, false, false).is_ok(), "dev não é gateado");
    }

    #[test]
    fn loopback_em_producao_e_aceite_sem_tls() {
        let mut c = AgentBlackBoxConfig {
            enabled: true,
            ..Default::default()
        };
        c.otlp.http_addr = "127.0.0.1:4318".into();
        c.otlp.grpc_addr = String::new();
        c.console.addr = "127.0.0.1:8080".into();
        assert!(c.validate(true, false, false).is_ok());
    }

    #[test]
    fn full_explicit_em_producao_exige_tls_e_auth() {
        let mut c = AgentBlackBoxConfig {
            enabled: true,
            capture_mode: "full_explicit".into(),
            ..Default::default()
        };
        c.otlp.http_addr = "127.0.0.1:4318".into();
        c.console.addr = "127.0.0.1:8080".into();
        assert!(c.validate(true, false, false).is_err());
        assert!(c.validate(true, true, true).is_ok());
    }

    #[test]
    fn enforce_em_producao_exige_bypass_protection() {
        let g = AgentGatewayConfig {
            enabled: true,
            mode: GatewayMode::Enforce,
            listen_addr: "127.0.0.1:8787".into(),
            upstream_url: "http://mcp.interno:9000".into(),
            identity: IdentityConfig {
                mode: "oidc".into(),
                issuer: "https://id.example".into(),
                audience: "hg".into(),
                jwks_path: "/etc/heraclitus/jwks.json".into(),
                ..Default::default()
            },
            ..Default::default()
        };
        assert!(g.validate(true, true).is_err());
        let ok = AgentGatewayConfig {
            bypass_protection_configured: true,
            ..g
        };
        assert!(ok.validate(true, true).is_ok());
    }

    #[test]
    fn producao_exige_oidc() {
        let g = AgentGatewayConfig {
            enabled: true,
            mode: GatewayMode::Shadow,
            listen_addr: "127.0.0.1:8787".into(),
            upstream_url: "http://x".into(),
            ..Default::default()
        };
        assert!(g.validate(true, true).is_err());
    }

    #[test]
    fn shadow_sem_upstream_e_recusado() {
        let g = AgentGatewayConfig {
            enabled: true,
            mode: GatewayMode::Shadow,
            ..Default::default()
        };
        assert!(g.validate(false, false).is_err());
    }

    #[test]
    fn toml_ida_e_volta() {
        let c = AgentBlackBoxConfig::default();
        let text = toml::to_string(&c).unwrap();
        let back: AgentBlackBoxConfig = toml::from_str(&text).unwrap();
        assert_eq!(back.capture_mode, c.capture_mode);
        let g = AgentGatewayConfig::default();
        let text = toml::to_string(&g).unwrap();
        let back: AgentGatewayConfig = toml::from_str(&text).unwrap();
        assert_eq!(back.mode, g.mode);
    }

    #[test]
    fn o_exemplo_da_spec_e_lido() {
        let text = r#"
enabled = true
capture_mode = "metadata_only"
max_body_bytes = 4194304

[otlp]
http_addr = "0.0.0.0:4318"
grpc_addr = "0.0.0.0:4317"

[mcp]
enabled = false
listen_addr = "127.0.0.1:8787"

[redaction]
profile = "default"
deny_headers = ["authorization", "cookie", "set-cookie", "x-api-key"]

[evidence]
rfc3161 = false
"#;
        let c: AgentBlackBoxConfig = toml::from_str(text).unwrap();
        assert!(c.enabled);
        assert_eq!(c.otlp.http_addr, "0.0.0.0:4318");
        assert_eq!(c.redaction.deny_headers.len(), 4);
    }

    #[test]
    fn loopback_reconhece_as_formas_usuais() {
        assert!(is_loopback("127.0.0.1:4318"));
        assert!(is_loopback("localhost:8080"));
        assert!(is_loopback("[::1]:8080"));
        assert!(!is_loopback("0.0.0.0:4318"));
        assert!(!is_loopback("10.0.0.5:4318"));
    }
}
