use crate::error::HeraclitusError;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Papéis de acesso aplicados por RPC. `Writer` inclui leitura; `Auditor`
/// inclui leitura + verificação; `Admin` pode executar qualquer operação.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AccessRole {
    Reader,
    Writer,
    Auditor,
    Admin,
}

impl AccessRole {
    pub fn allows(self, required: Self) -> bool {
        self == AccessRole::Admin
            || self == required
            || matches!(
                (self, required),
                (AccessRole::Writer, AccessRole::Reader)
                    | (AccessRole::Auditor, AccessRole::Reader)
            )
    }
}

/// Credencial sem segredo em claro. `token_blake3` é o BLAKE3 hexadecimal de
/// um token aleatório de pelo menos 32 bytes. O token real só existe no cliente.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccessCredential {
    pub principal: String,
    pub token_blake3: String,
    pub roles: Vec<AccessRole>,
}

/// Durability policy for the append path (§3.2).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum FsyncPolicy {
    /// fsync on every append. Slowest, strongest.
    Always,
    /// Group commit: fsync at most once per `interval_ms`.
    GroupCommit { interval_ms: u64 },
}

impl Default for FsyncPolicy {
    fn default() -> Self {
        FsyncPolicy::GroupCommit { interval_ms: 5 }
    }
}

/// Single config struct for the whole system. Loadable from TOML with
/// `HERACLITUS_*` environment overrides.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct HeraclitusConfig {
    pub data_dir: PathBuf,
    /// Tamanho a que o segmento rola e sela (default 8 MiB).
    ///
    /// **Isto não é só uma escolha de tamanho de ficheiro — governa o débito de
    /// escrita.** O índice do segmento ativo é publicado por copy-on-write a
    /// cada lote (`heraclitus-log/src/lib.rs:938`), portanto o custo por append
    /// cresce com as entradas JÁ acumuladas nesse segmento; selar reinicia-o.
    /// Um segmento maior deixa esse quadrático correr durante mais tempo.
    ///
    /// Medido a 1M de registos realistas (~487 B cada):
    ///
    /// | segmento | appends/s | 1M registos |
    /// |---|---|---|
    /// | 8 MiB | 12 798 (curva plana) | 78 s |
    /// | 256 MiB (o default antigo) | 399 (degrada 7,4×) | 42 min |
    ///
    /// **Ressalva:** segmentos pequenos não são grátis — cada selagem custa
    /// fsync, criação de ficheiro e sync do diretório-pai. Abaixo de ~50k
    /// registos por segmento o default antigo era mais rápido (a 20k: 18 393
    /// vs 10 109 app/s). Para bases pequenas e de escrita rara, subir este
    /// valor é legítimo.
    ///
    /// Ver `docs/md/auditorias/append-lento-com-o-crescimento.md`.
    pub segment_max_bytes: u64,
    pub fsync: FsyncPolicy,
    /// Memtable holds at most this many events above the view watermark.
    pub memtable_cap: usize,
    /// CPU budget for background compaction (distill).
    pub compaction_max_cores: usize,
    /// ACT-R decay parameter `d`.
    pub activation_decay: f64,
    /// gRPC bind address.
    pub grpc_addr: String,
    /// REST (admin) bind address.
    pub rest_addr: String,
    /// Cold tier root (object_store URL or local path).
    pub cold_tier_path: PathBuf,
    /// C2.6 — intervalo (segundos) da task de compaction do cold tier: a cada
    /// tick, segmentos demotados cuja fração de eventos logicamente apagados
    /// (tombstones semânticos) cruze a `CompactionPolicy` são reescritos sem
    /// eles, com novo recibo Merkle. `0` = desligado (default; requer a
    /// feature `tier`). Ignorada sob replicação (o object store é local ao nó).
    pub tier_compaction_interval_secs: u64,
    /// §3.9 (distill) — intervalo (segundos) da task de consolidação: a cada
    /// tick, os episódios de Observação novos (desde o cursor) são agrupados
    /// na variedade e cada cluster estável vira um `Fact` (`FactDerived`) no
    /// log via `Engine::append`. `0` = desligado (default; requer a feature
    /// `distill`). Ignorada sob replicação (v0: cursor é local ao nó).
    pub distill_interval_secs: u64,
    /// Optional bearer token required on every gRPC call. `None` = no auth
    /// (default; the server is reachable by anyone who can reach the port).
    pub auth_token: Option<String>,
    /// Credenciais multi-principal com RBAC. Podem vir do TOML ou de um JSON
    /// indicado por `HERACLITUS_CREDENTIALS_FILE`.
    pub access_credentials: Vec<AccessCredential>,
    /// Certificado/chain PEM e chave privada PEM do servidor gRPC.
    pub tls_cert_path: Option<PathBuf>,
    pub tls_key_path: Option<PathBuf>,
    /// CA de clientes. Quando presente, o gRPC exige certificado cliente (mTLS).
    pub tls_client_ca_path: Option<PathBuf>,
    /// Ativa gates estritos de operação para dados governamentais.
    pub production_mode: bool,
    /// HTTP Basic credentials (`"user:pass"`) required on every admin REST
    /// call (`/state`, `/verify`, ...). `None` = no auth (default — localhost
    /// bind). Prefer `HERACLITUS_REST_AUTH_FILE`; the legacy inline
    /// `HERACLITUS_REST_AUTH` remains available outside production.
    pub rest_basic_auth: Option<String>,
    /// Origens autorizadas a chamar o REST a partir de um browser (CORS).
    /// Vazio (default) = **nenhum** cabeçalho CORS, que é o comportamento
    /// histórico e o mais seguro.
    ///
    /// **Nunca aceita `*`, e é deliberado.** Este REST tem rotas que ESCREVEM
    /// (`/hvm/upsert`, `/hvm/delete`, `/tier/demote`) e liga-se tipicamente a
    /// `127.0.0.1`. Um `Access-Control-Allow-Origin: *` faria com que qualquer
    /// página que o operador visitasse pudesse falar com a base de dados local
    /// através do browser dele. A lista é explícita por isso.
    ///
    /// Exemplo: `rest_cors_origins = ["http://localhost:9337"]` para o painel
    /// forense em desenvolvimento. Em produção, o melhor continua a ser servir
    /// painel e API na **mesma origem** (nginx) e deixar isto vazio.
    pub rest_cors_origins: Vec<String>,
    /// Permite `POST /titular/:id/eliminar` (crypto-shred) pelo REST.
    /// **`false` por omissao, e deliberadamente.**
    ///
    /// A eliminacao e IRREVERSIVEL: destroi a chave do titular e o conteudo
    /// dele fica ilegivel para sempre. O REST so tem Basic auth, que e tudo-ou-
    /// nada — nao distingue papeis como o RBAC do gRPC. Expor uma operacao
    /// destrutiva atras disso, por omissao, seria pos a decisao mais grave do
    /// sistema atras da protecao mais fraca dele.
    ///
    /// Com `false`, o endpoint responde 403 e devolve o comando gRPC
    /// equivalente, que passa pelo RBAC. Ligue-se so onde isso for aceitavel.
    pub rest_allow_erasure: bool,
    /// Periodic view-checkpoint interval in seconds (fast boot): bounds the
    /// tail a crash-boot has to replay. `0` = checkpoint only at boot and on
    /// graceful shutdown. Default 300.
    pub checkpoint_interval_secs: u64,
    /// Append an `AuditQuery` event to the log for every executed GQL query
    /// (immudb-style access meta-audit: who queried what is itself evidence).
    /// Default `false` — it grows the log by one event per query.
    pub audit_queries: bool,
    /// Encrypt episode `content` at rest with a per-`agent_id` key (§3.10),
    /// enabling crypto-shredding. `false` = plaintext at rest (default).
    /// Keys live under `<data_dir>/keys`.
    pub encryption_at_rest: bool,

    /// Run the compliance watermark-timestamping daemon (RFC 3161 / ICP-Brasil).
    /// `false` = off (default; backward compatible). Receipts go under
    /// `<data_dir>/receipts`.
    pub compliance_enabled: bool,
    /// Daemon tick interval in seconds.
    pub compliance_interval_secs: u64,
    /// Minimum LSN advance between anchors.
    pub compliance_min_lsn_step: u64,
    /// `"local"` (in-process dev ACT) or `"http"` (external RFC 3161 token
    /// intake at `compliance_tsa_url`). The HTTP backend is not valid for a
    /// production compliance boundary: it has no TLS or trust-chain verifier.
    pub compliance_tsa_mode: String,
    /// ACT endpoint when `compliance_tsa_mode = "http"`.
    pub compliance_tsa_url: String,
    /// Authority/policy name recorded in each receipt.
    pub compliance_tsa_policy: String,

    /// SPEC-016 — endereço do servidor Arrow Flight (gRPC, feature `analytics`).
    /// `None` = desligado (default).
    pub flight_addr: Option<String>,

    /// SPEC-027 — endogenous telemetry: append `SystemMetric` episodes with the
    /// engine's vitals every N seconds, so the DB can query its own history via
    /// GQL (`WHERE n.kind = "SystemMetric"`). `0` = off (default; each tick
    /// grows the log by a few events, so it is an explicit opt-in).
    pub telemetry_interval_secs: u64,

    /// SPEC-015/021 — replicação por consenso Raft (opt-in). `None` = servidor
    /// autónomo de nó único (default). Quando presente, o servidor forma um
    /// cluster e as escritas passam pelo líder. Requer a feature `replication`
    /// no `heraclitus-server` (sem ela o campo é ignorado com um aviso).
    pub replication: Option<ReplicationConfig>,
}

/// Transporte de rede do consenso raft (SPEC-015/021). Ambos correm os mesmos
/// RPCs sobre os mesmos tipos serde; muda só o wire-format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum RaftTransport {
    /// Enquadramento TCP + bincode (transporte de referência, default).
    #[default]
    Tcp,
    /// gRPC/tonic sobre os mesmos tipos serde — a superfície unificada do
    /// servidor (requer a feature `replication`).
    Grpc,
}

/// Configuração de um nó no cluster de consenso (SPEC-015/021).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ReplicationConfig {
    /// Id deste nó (único no cluster).
    pub node_id: u64,
    /// Endereço TCP onde este nó serve os RPCs de raft (ex.: `127.0.0.1:8474`).
    ///
    /// **SEGURANÇA:** o transporte TCP legado só é permitido em loopback. Para
    /// cluster entre máquinas, usar gRPC com mTLS (certificado, chave e CA);
    /// `validate_security` recusa a combinação insegura.
    pub raft_addr: String,
    /// Todos os membros do cluster (incluindo este): `node_id -> raft_addr`.
    pub peers: std::collections::BTreeMap<u64, String>,
    /// Se `true`, este nó inicializa o cluster (semente). Exatamente UM nó deve
    /// ter `bootstrap = true` num arranque de raiz; os outros esperam para serem
    /// admitidos pela semente.
    pub bootstrap: bool,
    /// Diretório do raft-log durável (`FileRaftLog`). Vazio ⇒ `<data_dir>/raft`.
    pub raft_dir: PathBuf,
    /// Diretório do meta durável da máquina de estados. Vazio ⇒ `<data_dir>/raft-sm`.
    pub sm_dir: PathBuf,
    /// Transporte de rede do consenso (default `tcp`). `grpc` corre os mesmos
    /// RPCs de raft sobre tonic/gRPC — a superfície unificada do servidor.
    #[serde(default)]
    pub transport: RaftTransport,
    /// Identidade mTLS deste nó e CA comum do cluster. Obrigatórias sempre que
    /// Raft gRPC sai do loopback.
    pub tls_cert_path: Option<PathBuf>,
    pub tls_key_path: Option<PathBuf>,
    pub tls_ca_path: Option<PathBuf>,
    /// Nome DNS/SAN esperado nos certificados dos pares. Vazio usa o host do
    /// endereço anunciado pelo membro.
    pub tls_server_name: String,
}

impl Default for ReplicationConfig {
    fn default() -> Self {
        Self {
            node_id: 0,
            raft_addr: "127.0.0.1:8474".to_string(),
            peers: std::collections::BTreeMap::new(),
            bootstrap: false,
            raft_dir: PathBuf::new(),
            sm_dir: PathBuf::new(),
            transport: RaftTransport::Tcp,
            tls_cert_path: None,
            tls_key_path: None,
            tls_ca_path: None,
            tls_server_name: String::new(),
        }
    }
}

impl Default for HeraclitusConfig {
    fn default() -> Self {
        Self {
            data_dir: PathBuf::from("./data"),
            // 8 MiB: ver a doc do campo. Medido 32x mais rapido a 1M de registos.
            segment_max_bytes: 8 * 1024 * 1024,
            fsync: FsyncPolicy::default(),
            memtable_cap: 100_000,
            compaction_max_cores: 1,
            activation_decay: 0.5,
            grpc_addr: "127.0.0.1:7474".to_string(),
            rest_addr: "127.0.0.1:7475".to_string(),
            cold_tier_path: PathBuf::from("./data/cold"),
            tier_compaction_interval_secs: 0,
            distill_interval_secs: 0,
            auth_token: None,
            access_credentials: Vec::new(),
            tls_cert_path: None,
            tls_key_path: None,
            tls_client_ca_path: None,
            production_mode: false,
            rest_basic_auth: None,
            rest_cors_origins: Vec::new(),
            rest_allow_erasure: false,
            checkpoint_interval_secs: 300,
            audit_queries: false,
            encryption_at_rest: false,
            compliance_enabled: false,
            compliance_interval_secs: 300,
            compliance_min_lsn_step: 10_000,
            compliance_tsa_mode: "local".to_string(),
            compliance_tsa_url: String::new(),
            compliance_tsa_policy: "ACT-dev".to_string(),
            flight_addr: None,
            telemetry_interval_secs: 0,
            replication: None,
        }
    }
}

fn read_single_line_secret(path: &str, label: &str) -> Result<String, HeraclitusError> {
    let raw = std::fs::read_to_string(path)
        .map_err(|e| HeraclitusError::Config(format!("{label} file {path}: {e}")))?;
    let secret = raw.trim();
    if secret.is_empty() || secret.contains('\r') || secret.contains('\n') {
        return Err(HeraclitusError::Config(format!(
            "{label} file deve conter exatamente uma linha não vazia"
        )));
    }
    Ok(secret.to_owned())
}

impl HeraclitusConfig {
    /// Load from a TOML file, then apply environment overrides.
    pub fn load(path: Option<&std::path::Path>) -> Result<Self, HeraclitusError> {
        let mut cfg = match path {
            Some(p) => {
                let raw = std::fs::read_to_string(p)?;
                toml::from_str(&raw).map_err(|e| HeraclitusError::Config(e.to_string()))?
            }
            None => Self::default(),
        };
        cfg.apply_env()?;
        cfg.validate_security()?;
        Ok(cfg)
    }

    /// `HERACLITUS_DATA_DIR`, `HERACLITUS_GRPC_ADDR`, `HERACLITUS_REST_ADDR`,
    /// `HERACLITUS_FSYNC=always|group_commit:<ms>`.
    pub fn apply_env(&mut self) -> Result<(), HeraclitusError> {
        if let Ok(v) = std::env::var("HERACLITUS_DATA_DIR") {
            self.data_dir = PathBuf::from(v);
        }
        if let Ok(v) = std::env::var("HERACLITUS_GRPC_ADDR") {
            self.grpc_addr = v;
        }
        if let Ok(v) = std::env::var("HERACLITUS_REST_ADDR") {
            self.rest_addr = v;
        }
        if let Ok(v) = std::env::var("HERACLITUS_FSYNC") {
            if v == "always" {
                self.fsync = FsyncPolicy::Always;
            } else if let Some(ms) = v.strip_prefix("group_commit:") {
                if let Ok(ms) = ms.parse() {
                    self.fsync = FsyncPolicy::GroupCommit { interval_ms: ms };
                }
            }
        }
        if let Ok(v) = std::env::var("HERACLITUS_AUTH_TOKEN") {
            self.auth_token = if v.is_empty() { None } else { Some(v) };
        }
        if let Ok(v) = std::env::var("HERACLITUS_CREDENTIALS_FILE") {
            if !v.is_empty() {
                let raw = std::fs::read_to_string(&v)
                    .map_err(|e| HeraclitusError::Config(format!("credentials file {v}: {e}")))?;
                self.access_credentials = serde_json::from_str(&raw)
                    .map_err(|e| HeraclitusError::Config(format!("credentials file {v}: {e}")))?;
            }
        }
        if let Ok(v) = std::env::var("HERACLITUS_TLS_CERT") {
            self.tls_cert_path = (!v.is_empty()).then(|| PathBuf::from(v));
        }
        if let Ok(v) = std::env::var("HERACLITUS_TLS_KEY") {
            self.tls_key_path = (!v.is_empty()).then(|| PathBuf::from(v));
        }
        if let Ok(v) = std::env::var("HERACLITUS_TLS_CLIENT_CA") {
            self.tls_client_ca_path = (!v.is_empty()).then(|| PathBuf::from(v));
        }
        if let Ok(v) = std::env::var("HERACLITUS_PRODUCTION") {
            self.production_mode =
                matches!(v.to_ascii_lowercase().as_str(), "1" | "true" | "on" | "yes");
        }
        let inline_rest_auth = std::env::var("HERACLITUS_REST_AUTH")
            .ok()
            .filter(|value| !value.is_empty());
        let rest_auth_file = std::env::var("HERACLITUS_REST_AUTH_FILE")
            .ok()
            .filter(|value| !value.is_empty());
        if inline_rest_auth.is_some() && rest_auth_file.is_some() {
            return Err(HeraclitusError::Config(
                "configure apenas HERACLITUS_REST_AUTH_FILE; não combine com HERACLITUS_REST_AUTH"
                    .into(),
            ));
        }
        if let Some(path) = rest_auth_file {
            self.rest_basic_auth = Some(read_single_line_secret(&path, "REST auth")?);
        } else if let Some(value) = inline_rest_auth {
            self.rest_basic_auth = Some(value);
        }
        // Origens CORS por variável de ambiente, no mesmo estilo do resto.
        // Lista separada por vírgulas; vazio desliga (o default). A validação
        // do formato é feita onde a camada é montada (`rest.rs::aplicar_cors`),
        // que rejeita `*` e origens malformadas com aviso nomeando a entrada —
        // aqui só se separa, para uma entrada inválida ser reportada uma vez
        // e no sítio onde se percebe o efeito.
        if let Ok(v) = std::env::var("HERACLITUS_REST_CORS_ORIGINS") {
            self.rest_cors_origins = v
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
        }
        if let Ok(v) = std::env::var("HERACLITUS_REST_ALLOW_ERASURE") {
            self.rest_allow_erasure =
                matches!(v.to_ascii_lowercase().as_str(), "1" | "true" | "on" | "yes");
        }
        if let Ok(v) = std::env::var("HERACLITUS_CHECKPOINT_INTERVAL") {
            if let Ok(s) = v.parse() {
                self.checkpoint_interval_secs = s;
            }
        }
        if let Ok(v) = std::env::var("HERACLITUS_AUDIT_QUERIES") {
            self.audit_queries =
                matches!(v.to_ascii_lowercase().as_str(), "1" | "true" | "on" | "yes");
        }
        if let Ok(v) = std::env::var("HERACLITUS_ENCRYPTION") {
            self.encryption_at_rest =
                matches!(v.to_ascii_lowercase().as_str(), "1" | "true" | "on" | "yes");
        }
        if let Ok(v) = std::env::var("HERACLITUS_COMPLIANCE") {
            self.compliance_enabled =
                matches!(v.to_ascii_lowercase().as_str(), "1" | "true" | "on" | "yes");
        }
        if let Ok(v) = std::env::var("HERACLITUS_COMPLIANCE_INTERVAL") {
            if let Ok(s) = v.parse() {
                self.compliance_interval_secs = s;
            }
        }
        if let Ok(v) = std::env::var("HERACLITUS_COMPLIANCE_STEP") {
            if let Ok(s) = v.parse() {
                self.compliance_min_lsn_step = s;
            }
        }
        if let Ok(v) = std::env::var("HERACLITUS_FLIGHT_ADDR") {
            self.flight_addr = if v.is_empty() { None } else { Some(v) };
        }
        if let Ok(v) = std::env::var("HERACLITUS_TELEMETRY_INTERVAL") {
            if let Ok(s) = v.parse() {
                self.telemetry_interval_secs = s;
            }
        }
        if let Ok(v) = std::env::var("HERACLITUS_TIER_COMPACTION_INTERVAL") {
            if let Ok(s) = v.parse() {
                self.tier_compaction_interval_secs = s;
            }
        }
        if let Ok(v) = std::env::var("HERACLITUS_DISTILL_INTERVAL") {
            if let Ok(s) = v.parse() {
                self.distill_interval_secs = s;
            }
        }
        if let Ok(v) = std::env::var("HERACLITUS_COLD_TIER_PATH") {
            if !v.is_empty() {
                self.cold_tier_path = PathBuf::from(v);
            }
        }
        if let Ok(v) = std::env::var("HERACLITUS_COMPLIANCE_TSA_URL") {
            if !v.is_empty() {
                self.compliance_tsa_url = v;
                self.compliance_tsa_mode = "http".to_string();
            }
        }
        if let Ok(v) = std::env::var("HERACLITUS_COMPLIANCE_TSA_POLICY") {
            if !v.is_empty() {
                self.compliance_tsa_policy = v;
            }
        }
        Ok(())
    }

    pub fn validate_security(&self) -> Result<(), HeraclitusError> {
        let invalid = |message: String| HeraclitusError::Config(message);
        if self.tls_cert_path.is_some() != self.tls_key_path.is_some() {
            return Err(invalid(
                "HERACLITUS_TLS_CERT e HERACLITUS_TLS_KEY devem ser definidos juntos".into(),
            ));
        }
        if self.tls_client_ca_path.is_some() && self.tls_cert_path.is_none() {
            return Err(invalid(
                "TLS client CA requer certificado e chave do servidor".into(),
            ));
        }
        if self
            .auth_token
            .as_ref()
            .is_some_and(|token| token.len() < 32)
        {
            return Err(invalid(
                "auth_token legado deve conter ao menos 32 bytes aleatórios".into(),
            ));
        }
        let mut principals = std::collections::BTreeSet::new();
        let mut token_hashes = std::collections::BTreeSet::new();
        for cred in &self.access_credentials {
            if cred.principal.trim().is_empty() || !principals.insert(&cred.principal) {
                return Err(invalid(format!(
                    "principal RBAC vazio ou duplicado: {:?}",
                    cred.principal
                )));
            }
            if cred.roles.is_empty()
                || cred.token_blake3.len() != 64
                || !cred.token_blake3.bytes().all(|b| b.is_ascii_hexdigit())
            {
                return Err(invalid(format!(
                    "credencial RBAC inválida para {} (roles e token_blake3)",
                    cred.principal
                )));
            }
            if !token_hashes.insert(cred.token_blake3.to_ascii_lowercase()) {
                return Err(invalid(
                    "duas credenciais RBAC não podem compartilhar o mesmo token".into(),
                ));
            }
        }

        let grpc: std::net::SocketAddr = self
            .grpc_addr
            .parse()
            .map_err(|e| invalid(format!("grpc_addr: {e}")))?;
        let rest: std::net::SocketAddr = self
            .rest_addr
            .parse()
            .map_err(|e| invalid(format!("rest_addr: {e}")))?;
        if !rest.ip().is_loopback() {
            return Err(invalid(format!(
                "REST administrativo deve permanecer em loopback; recebido {rest}"
            )));
        }
        let has_auth = self.auth_token.is_some() || !self.access_credentials.is_empty();
        if !grpc.ip().is_loopback() && (!has_auth || self.tls_cert_path.is_none()) {
            return Err(invalid(format!(
                "gRPC não-loopback {grpc} exige autenticação e TLS"
            )));
        }

        if let Some(rep) = &self.replication {
            let tls_parts = usize::from(rep.tls_cert_path.is_some())
                + usize::from(rep.tls_key_path.is_some())
                + usize::from(rep.tls_ca_path.is_some());
            if tls_parts != 0 && tls_parts != 3 {
                return Err(invalid(
                    "raft TLS exige cert, key e CA configurados juntos".into(),
                ));
            }
            let raft: std::net::SocketAddr = rep
                .raft_addr
                .parse()
                .map_err(|e| invalid(format!("raft_addr: {e}")))?;
            if !raft.ip().is_loopback()
                && (rep.transport != RaftTransport::Grpc
                    || rep.tls_cert_path.is_none()
                    || rep.tls_key_path.is_none()
                    || rep.tls_ca_path.is_none())
            {
                return Err(invalid(format!(
                    "Raft não-loopback {raft} exige transporte gRPC com mTLS"
                )));
            }
        }

        if self.production_mode {
            if !matches!(self.fsync, FsyncPolicy::Always) {
                return Err(invalid("produção exige fsync = always".into()));
            }
            if !self.encryption_at_rest || !self.audit_queries {
                return Err(invalid(
                    "produção exige encryption_at_rest=true e audit_queries=true".into(),
                ));
            }
            if self.access_credentials.is_empty() || self.auth_token.is_some() {
                return Err(invalid(
                    "produção exige credenciais RBAC por hash; auth_token legado deve ficar vazio"
                        .into(),
                ));
            }
            let has_admin = self
                .access_credentials
                .iter()
                .any(|cred| cred.roles.contains(&AccessRole::Admin));
            let has_writer = self.access_credentials.iter().any(|cred| {
                cred.roles.contains(&AccessRole::Writer) && !cred.roles.contains(&AccessRole::Admin)
            });
            if self.access_credentials.len() < 2 || !has_admin || !has_writer {
                return Err(invalid(
                    "produção exige ao menos dois principals separados: admin e writer".into(),
                ));
            }
            let valid_rest_auth = self
                .rest_basic_auth
                .as_deref()
                .and_then(|value| value.split_once(':'))
                .is_some_and(|(user, password)| !user.is_empty() && password.len() >= 16);
            if !valid_rest_auth {
                return Err(invalid(
                    "produção exige HERACLITUS_REST_AUTH_FILE com user:senha e senha >= 16 bytes"
                        .into(),
                ));
            }
            if let Some(rep) = &self.replication {
                if rep.transport != RaftTransport::Grpc
                    || rep.tls_cert_path.is_none()
                    || rep.tls_key_path.is_none()
                    || rep.tls_ca_path.is_none()
                {
                    return Err(invalid(
                        "produção com replicação exige Raft gRPC mTLS".into(),
                    ));
                }
            }
            if !self.compliance_enabled
                || !self.compliance_tsa_mode.eq_ignore_ascii_case("http")
                || self.compliance_tsa_url.is_empty()
            {
                return Err(invalid(
                    "produção exige uma TSA externa configurada; LocalTsa não é evidência legal"
                        .into(),
                ));
            }
            if self.compliance_tsa_url.starts_with("http://") {
                return Err(invalid(
                    "produção proíbe TSA em HTTP puro; esta build não implementa transporte HTTPS seguro"
                        .into(),
                ));
            }
            if self.compliance_tsa_url.starts_with("https://") {
                return Err(invalid(
                    "produção com TSA HTTPS está bloqueada: esta build ainda não implementa HTTPS nem validação CMS/X.509/ICP-Brasil"
                        .into(),
                ));
            }
            return Err(invalid(
                "produção exige URL HTTPS para TSA externa, mas suporte HTTPS e validação de confiança ainda não estão implementados"
                    .into(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_roundtrip_toml() {
        let cfg = HeraclitusConfig::default();
        let s = toml::to_string(&cfg).unwrap();
        let back: HeraclitusConfig = toml::from_str(&s).unwrap();
        assert_eq!(back.segment_max_bytes, cfg.segment_max_bytes);
        assert_eq!(back.fsync, cfg.fsync);
    }

    #[test]
    fn secret_file_is_trimmed_and_multiline_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let valid = dir.path().join("rest-auth.txt");
        std::fs::write(&valid, "operator:a-strong-secret-value\r\n").unwrap();
        assert_eq!(
            read_single_line_secret(valid.to_str().unwrap(), "REST auth").unwrap(),
            "operator:a-strong-secret-value"
        );

        let multiline = dir.path().join("multiline.txt");
        std::fs::write(&multiline, "operator:first-line\nsecond-line").unwrap();
        assert!(read_single_line_secret(multiline.to_str().unwrap(), "REST auth").is_err());
    }

    #[test]
    fn security_validation_rejects_public_plaintext_surfaces() {
        let cfg = HeraclitusConfig {
            grpc_addr: "0.0.0.0:7474".into(),
            ..Default::default()
        };
        assert!(cfg
            .validate_security()
            .unwrap_err()
            .to_string()
            .contains("TLS"));

        let cfg = HeraclitusConfig {
            rest_addr: "0.0.0.0:7475".into(),
            ..Default::default()
        };
        assert!(cfg
            .validate_security()
            .unwrap_err()
            .to_string()
            .contains("loopback"));
    }

    #[test]
    fn production_profile_is_fail_closed() {
        let mut cfg = HeraclitusConfig {
            production_mode: true,
            ..Default::default()
        };
        assert!(cfg.validate_security().is_err());

        cfg.fsync = FsyncPolicy::Always;
        cfg.encryption_at_rest = true;
        cfg.audit_queries = true;
        cfg.rest_basic_auth = Some("admin:strong-local-secret".into());
        cfg.compliance_enabled = true;
        cfg.compliance_tsa_mode = "http".into();
        cfg.compliance_tsa_url = "https://tsa.example.invalid".into();
        cfg.access_credentials.push(AccessCredential {
            principal: "operator".into(),
            token_blake3: "a".repeat(64),
            roles: vec![AccessRole::Admin],
        });
        cfg.access_credentials.push(AccessCredential {
            principal: "forge".into(),
            token_blake3: "b".repeat(64),
            roles: vec![AccessRole::Writer],
        });
        let err = cfg.validate_security().unwrap_err().to_string();
        assert!(
            err.contains("HTTPS") && err.contains("bloqueada"),
            "configuração não pode alegar compliance de produção sem transporte e trust chain: {err}"
        );

        cfg.compliance_tsa_url = "http://tsa.example.invalid".into();
        assert!(cfg
            .validate_security()
            .unwrap_err()
            .to_string()
            .contains("HTTP puro"));

        cfg.rest_basic_auth = Some("admin:short".into());
        assert!(cfg.validate_security().is_err());
    }
}
