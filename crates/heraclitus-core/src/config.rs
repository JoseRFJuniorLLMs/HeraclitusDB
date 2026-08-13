use crate::error::HeraclitusError;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

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
    /// Segments roll at this size (default 256 MB).
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
    /// HTTP Basic credentials (`"user:pass"`) required on every admin REST
    /// call (`/state`, `/verify`, ...). `None` = no auth (default — localhost
    /// bind). Set via `HERACLITUS_REST_AUTH`.
    pub rest_basic_auth: Option<String>,
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
    /// `"local"` (in-process dev ACT) or `"http"` (real RFC 3161 ACT at
    /// `compliance_tsa_url`).
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
    /// **SEGURANÇA (R24):** a superfície de raft (TCP e gRPC) NÃO tem
    /// autenticação nem TLS — qualquer par que alcance a porta pode enviar
    /// AppendEntries/Vote/InstallSnapshot (injeção de entradas / hijack do
    /// cluster). Ligar SEMPRE a uma rede privada/localhost, nunca a uma
    /// interface pública. Auth mútua no transporte é trabalho futuro.
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
        }
    }
}

impl Default for HeraclitusConfig {
    fn default() -> Self {
        Self {
            data_dir: PathBuf::from("./data"),
            segment_max_bytes: 256 * 1024 * 1024,
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
            rest_basic_auth: None,
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
        cfg.apply_env();
        Ok(cfg)
    }

    /// `HERACLITUS_DATA_DIR`, `HERACLITUS_GRPC_ADDR`, `HERACLITUS_REST_ADDR`,
    /// `HERACLITUS_FSYNC=always|group_commit:<ms>`.
    pub fn apply_env(&mut self) {
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
        if let Ok(v) = std::env::var("HERACLITUS_REST_AUTH") {
            self.rest_basic_auth = if v.is_empty() { None } else { Some(v) };
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
}
