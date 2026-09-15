from pathlib import Path

# --- Agent-plane host boundary -------------------------------------------------
p = Path('crates/heraclitus-server/src/agent_plane.rs')
s = p.read_text()
old = '''    pub fn validate(&self, host: &HeraclitusConfig) -> Result<(), HeraclitusError> {
        let tls = host.tls_cert_path.is_some() && host.tls_key_path.is_some();
        let auth = host.rest_basic_auth.is_some()
            || host.auth_token.is_some()
            || !host.access_credentials.is_empty();
        self.black_box
            .validate(host.production_mode, tls, auth)
            .map_err(|e| HeraclitusError::Config(e.to_string()))?;
        self.gateway
            .validate(host.production_mode, tls)
            .map_err(|e| HeraclitusError::Config(e.to_string()))?;
        Ok(())
    }
'''
new = '''    pub fn validate(&self, host: &HeraclitusConfig) -> Result<(), HeraclitusError> {
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
                    "agent_gateway mode=enforce exige autenticação nas DUAS superfícies Core: \
                     gRPC={} REST={}. Loopback não é fronteira de confiança contra agente local \
                     comprometido (SPEC-0084)",
                    if grpc_auth { "protected" } else { "OPEN" },
                    if rest_auth { "protected" } else { "OPEN" }
                )));
            }
        }
        Ok(())
    }
'''
if old not in s:
    raise SystemExit('AgentPlane::validate block not found')
s = s.replace(old, new, 1)

test_anchor = '''    #[test]
    fn producao_sem_tls_recusa_bind_publico() {
'''
tests = r'''    #[test]
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

'''
if 'enforce_recusa_core_grpc_anonimo' not in s:
    if test_anchor not in s:
        raise SystemExit('agent_plane test anchor not found')
    s = s.replace(test_anchor, tests + test_anchor, 1)
p.write_text(s)

# --- Agent Black Box own-listener auth truth ---------------------------------
p = Path('crates/heraclitus-agent/src/config.rs')
s = p.read_text()
needle = '''        if self.max_body_bytes == 0 {
            return Err(ConfigError::Invalid(
                "max_body_bytes = 0 recusaria todos os lotes".into(),
            ));
        }
        if production {
'''
replacement = '''        if self.max_body_bytes == 0 {
            return Err(ConfigError::Invalid(
                "max_body_bytes = 0 recusaria todos os lotes".into(),
            ));
        }
        // `require_auth=true` sem credencial era pior que `false`: parecia um
        // controlo ligado, mas `otlp_credential()` devolvia None e o ingest
        // deixava passar tudo. Tornar a configuração impossível fecha essa
        // diferença entre intenção e execução.
        if self.otlp.require_auth
            && (!self.otlp.http_addr.is_empty() || !self.otlp.grpc_addr.is_empty())
            && !self.console.has_basic_auth()
        {
            return Err(ConfigError::Invalid(
                "agent_black_box.otlp.require_auth=true exige \
                 agent_black_box.console.basic_auth=user:senha; sem a credencial a ingestão \
                 não estaria autenticada (SPEC-0084)"
                    .into(),
            ));
        }
        if production {
            for (nome, addr) in [
                ("otlp.http_addr", &self.otlp.http_addr),
                ("otlp.grpc_addr", &self.otlp.grpc_addr),
            ] {
                if !addr.is_empty() && !is_loopback(addr) && !self.otlp.require_auth {
                    return Err(ConfigError::Invalid(format!(
                        "{nome} = `{addr}` não é loopback em produção e \
                         agent_black_box.otlp.require_auth=false; a porta de ingestão ficaria \
                         aberta a injecção de evidência (SPEC-0084)"
                    )));
                }
            }
'''
if needle not in s:
    raise SystemExit('AgentBlackBox validation insertion point not found')
s = s.replace(needle, replacement, 1)

test_anchor = '''    #[test]
    fn producao_sem_tls_recusa_bind_publico() {
'''
tests = r'''    #[test]
    fn otlp_require_auth_sem_credencial_e_configuracao_invalida() {
        let mut c = AgentBlackBoxConfig {
            enabled: true,
            ..Default::default()
        };
        c.otlp.http_addr = "127.0.0.1:4318".into();
        c.otlp.grpc_addr = String::new();
        c.otlp.require_auth = true;
        c.console.basic_auth.clear();
        assert!(c.validate(false, false, false).is_err());
        c.console.basic_auth = "collector:a-strong-local-password".into();
        assert!(c.validate(false, false, true).is_ok());
    }

    #[test]
    fn producao_otlp_publico_exige_auth_na_propria_ingestao() {
        let mut c = AgentBlackBoxConfig {
            enabled: true,
            ..Default::default()
        };
        c.otlp.http_addr = "0.0.0.0:4318".into();
        c.otlp.grpc_addr = String::new();
        c.console.basic_auth = "collector:a-strong-local-password".into();
        c.otlp.require_auth = false;
        assert!(c.validate(true, true, true).is_err());
        c.otlp.require_auth = true;
        assert!(c.validate(true, true, true).is_ok());
    }

'''
if 'otlp_require_auth_sem_credencial' not in s:
    if test_anchor not in s:
        raise SystemExit('agent config test anchor not found')
    s = s.replace(test_anchor, tests + test_anchor, 1)
p.write_text(s)
