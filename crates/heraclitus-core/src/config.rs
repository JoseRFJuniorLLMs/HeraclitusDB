use crate::error::HeraclitusError;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Operational mode for the Heraclitus Sentinel security plane.
///
/// The enum lives in `heraclitus-core` so configuration parsing does not create
/// a dependency cycle (`server -> sentinel -> core`).  The Sentinel crate
/// re-exports it and adds the runtime implementation.  `Disabled` is the
/// default and is intentionally fail-safe: enabling the database never starts
/// security workers implicitly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum SentinelMode {
    #[default]
    Disabled,
    Observe,
    Shadow,
    Assist,
    Autonomous,
}

/// Configuration for the deterministic L1 rule plane.  The path is explicit:
/// no globbing or implicit rules are loaded by the server.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct SentinelL1Config {
    pub enabled: bool,
    pub rules_path: Option<PathBuf>,
    /// O contrato de lateness (SPEC-0072, pré-requisito do snapshot).
    ///
    /// O histórico L1 retém, a partir do evento mais recente, a maior janela
    /// que o ruleset consulta MAIS esta tolerância. Um evento que chegue com
    /// `observed_at` mais atrasado do que isso não participa em nenhuma
    /// correlação — é a promessa que torna o histórico limitável, e que antes
    /// não existia: sem ela o `rule_history` crescia sem tecto e cada evento
    /// ingerido custava Θ(regras × N).
    pub max_lateness_ms: u64,
    /// Tecto duro em linhas, independente do tempo. Zero desliga o tecto.
    pub history_capacity: usize,
}

impl Default for SentinelL1Config {
    fn default() -> Self {
        Self {
            enabled: false,
            rules_path: None,
            // Cinco minutos: a mesma cadência que a SPEC-0072 §44 usa para o
            // snapshot, e generosa para qualquer fonte de telemetria real. Não
            // é o default por ser certo para todos — é por ser um número
            // EXPLÍCITO em vez de nenhum.
            max_lateness_ms: 300_000,
            // A mesma escala do `memtable_cap`: o tecto existe para que um
            // ruleset com janelas de dias não devolva o histórico ao ilimitado.
            history_capacity: 100_000,
        }
    }
}

/// Configuration for the deterministic L2 behavioral adapter.  Numeric
/// scoring remains owned by `heraclitus-sentinel`; core only carries the
/// bounded, serializable controls needed by hosts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct SentinelL2Config {
    pub enabled: bool,
    /// Number of trusted observations required before an active profile can
    /// score a subject.
    pub minimum_support: u64,
    /// Extra observations kept in the shadow profile before promotion.
    pub learning_delay_events: u64,
    /// When true, profiles never promote automatically and L2 only learns in
    /// shadow mode.
    pub shadow_only: bool,
    /// Events at or above this severity are scored but cannot update the
    /// active baseline without trusted feedback.
    pub suspicious_severity: u8,
}

impl Default for SentinelL2Config {
    fn default() -> Self {
        Self {
            enabled: false,
            minimum_support: 20,
            learning_delay_events: 10,
            shadow_only: true,
            suspicious_severity: 7,
        }
    }
}

/// Configuration for deterministic L3 temporal correlation.  L3 remains
/// independently opt-in so existing Sentinel deployments do not start
/// retaining graph/incident state merely because L0 or L1 is enabled.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct SentinelL3Config {
    pub enabled: bool,
    /// Maximum directed graph traversal depth used while correlating signals.
    pub max_graph_hops: usize,
}

impl Default for SentinelL3Config {
    fn default() -> Self {
        Self {
            enabled: false,
            max_graph_hops: 6,
        }
    }
}

/// SPEC-0047 — configuração do plano de threat intelligence.
///
/// Opt-in pela mesma razão que o L2 e o L3: uma instalação que ligou o L0 não
/// deve começar a ingerir feeds externos e a manter índices de IOC só por
/// isso.
///
/// Um feed é **entrada não confiável** (§13, `source != truth`), e por isso a
/// política da fonte vive aqui e não no ficheiro do feed: quem decide a
/// confiança é o operador, não quem publica os indicadores.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct SentinelThreatConfig {
    pub enabled: bool,
    /// Directório de onde os bundles STIX 2.1 (`*.json`) são carregados no
    /// arranque. Um ficheiro que não importe é registado e ignorado — um feed
    /// malformado não pode impedir o servidor de arrancar.
    pub feeds_dir: String,
    /// Identidade da fonte, que liga os objectos importados a esta política.
    pub source_id: String,
    /// §10 — `untrusted` faz os indicadores entrarem em quarentena e pesarem
    /// exactamente zero; `community`, `commercial`, `institutional` e
    /// `internal` pesam progressivamente mais.
    pub trust_level: String,
    /// §10 — objectos abaixo desta confiança são recusados na admissão.
    pub minimum_confidence: u8,
    /// §12 — expiração aplicada quando o feed não declara nenhuma. `0` exige
    /// que o feed a declare, e recusa os objectos que não o façam.
    pub default_ttl_secs: u64,
}

impl Default for SentinelThreatConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            feeds_dir: String::new(),
            source_id: "threat-feed".to_string(),
            // O default é o mais desconfiado: um feed que ninguém classificou
            // entra em quarentena e não move nenhuma decisão. §13.
            trust_level: "untrusted".to_string(),
            minimum_confidence: 0,
            default_ttl_secs: 30 * 24 * 3_600,
        }
    }
}

/// Configuration shared by the host and the optional `heraclitus-sentinel`
/// runtime.  The core owns only serializable host controls; detector and graph
/// implementations remain in `heraclitus-sentinel`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct SentinelConfig {
    /// Starts the subscriber and workers when true.  `false` means no
    /// subscriber is attached and no background thread is created.
    pub enabled: bool,
    pub mode: SentinelMode,
    /// Maximum number of notification LSNs retained in memory.
    pub queue_capacity: usize,
    /// Number of worker threads.  Workers serialize cursor commits, while the
    /// bounded queue remains safe under a notification storm.
    pub worker_threads: usize,
    /// Version of the deterministic pipeline recorded in the cursor and in
    /// derived event attributes.
    pub pipeline_version: u32,
    /// Maximum number of log records consumed by one catch-up pass.
    pub catch_up_batch: usize,
    /// Optional fail-closed Sigma ruleset loaded by the Sentinel workers.
    pub l1: SentinelL1Config,
    /// Optional deterministic behavioral baseline adapter.
    pub l2: SentinelL2Config,
    /// Optional deterministic graph/incident adapter.
    pub l3: SentinelL3Config,
    /// SPEC-0047 — plano de threat intelligence (opt-in).
    pub threat: SentinelThreatConfig,
    /// SPEC-0072 §10 — tamanho do lote do replay janelado no arranque.
    ///
    /// O arranque materializava a base inteira num `Vec` (`log.scan(0, head)`).
    /// A §11 proíbe-o: a memória do replay tem de ficar limitada ao estado
    /// materializado mais o lote corrente. Este é o lote.
    pub replay_batch_events: usize,
    /// SPEC-0072 §17 — o que fazer quando o cursor diverge do log canónico.
    pub recovery: SentinelRecoveryConfig,
}

impl Default for SentinelConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            mode: SentinelMode::Disabled,
            queue_capacity: 65_536,
            worker_threads: 4,
            pipeline_version: 1,
            catch_up_batch: 1_024,
            l1: SentinelL1Config::default(),
            l2: SentinelL2Config::default(),
            l3: SentinelL3Config::default(),
            threat: SentinelThreatConfig::default(),
            // SPEC-0072 §10: "Default inicial 8192. O valor final deve ser
            // definido por benchmark." Fica o valor da spec até haver medida.
            replay_batch_events: 8_192,
            recovery: SentinelRecoveryConfig::default(),
        }
    }
}

/// SPEC-0072 §17 — política de recuperação quando o cursor persistido está à
/// frente do log canónico.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum CursorPolicy {
    /// `cursor > head` aborta o arranque. Para ambientes forenses em que
    /// nenhuma recuperação automática pode ocorrer sem um humano.
    Strict,
    /// `cursor > head` reconstrói o estado derivado a partir do log canónico.
    ///
    /// É o default recomendado pela spec, e a razão está no INV-4: nada do que
    /// o Sentinel persiste fora do log é source of truth. Recusar arrancar por
    /// causa de um artefacto derivado seria deixar a base indisponível para
    /// proteger uma cópia.
    #[default]
    Rebuild,
}

/// SPEC-0072 §17 — `[sentinel.recovery]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct SentinelRecoveryConfig {
    pub cursor_policy: CursorPolicy,
}

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

/// On-disk log format selected when the database is opened.
///
/// **HRKL v6 é o formato por omissão.** É o motor completo da SPEC-0050:
/// registos canónicos, blocos PACKED com Zstd (4.5x medido em corpus
/// operacional), manifesto `.hrkm` com gerações e GC, sidecars `.hrki` com
/// zone maps e Bloom, tier frio por range reads, projecção lakehouse e
/// ancoragem de compliance pela raiz **lógica** — que, ao contrário da raiz
/// física do legado, sobrevive a um repack sem invalidar recibos.
///
/// O legado (`storage_format = "legacy"`) continua legível e suportado, e
/// **nunca** é convertido implicitamente: os dois layouts recusam abrir a raiz
/// um do outro antes de qualquer escrita. Uma instalação com dados v1--v5
/// converte-os com `heraclitus migrate-v6 <origem> <destino>`, que não toca na
/// origem.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum StorageFormat {
    /// Formato v1--v5. Continua legível; nunca é migrado implicitamente.
    Legacy,
    /// HRKL v6 — o formato por omissão (SPEC-0050).
    #[default]
    V6,
}

impl StorageFormat {
    /// Stable configuration spelling used in diagnostics and operator-facing
    /// status output.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Legacy => "legacy",
            Self::V6 => "v6",
        }
    }
}

/// Single config struct for the whole system. Loadable from TOML with
/// `HERACLITUS_*` environment overrides.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct HeraclitusConfig {
    pub data_dir: PathBuf,
    /// On-disk log format. Defaults to [`StorageFormat::V6`]; changing it
    /// never performs an implicit migration of existing data.
    pub storage_format: StorageFormat,
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
    /// SPEC-0050 — intervalo do worker assíncrono que transforma RAWs v6
    /// selados em gerações PACKED. `0` desliga; ignorado no formato legado.
    pub v6_packing_interval_secs: u64,
    /// SPEC-0050 §90–§97 — intervalo do GC de gerações físicas. `0` desliga.
    ///
    /// **Ligado por omissão (300 s), e a escolha merece justificação.** O
    /// precedente desta config é o lakehouse, que fica em `0` porque ligá-lo
    /// duplicaria o disco de toda a gente sem pedir licença. O GC é o
    /// contrário: *não* o correr é que custa. O `record_pack` marca a geração
    /// RAW como `Superseded` (§88 passo 13) e, sem GC, ela fica em disco para
    /// sempre — cada banco guarda RAW **e** PACKED de tudo. Com o rácio
    /// `packed/raw` de 21,95% medido no gate de §207, isso é 5,5× o disco que
    /// o formato promete.
    ///
    /// O que torna o default seguro não é otimismo, são quatro camadas
    /// independentes: §91 nunca remove a última autoridade canónica (e o
    /// `assert_gc_invariant` volta a verificá-lo por um caminho separado), §93
    /// impõe 24 h de grace period, §94 respeita legal hold e §184 exige as
    /// cópias verificadas configuradas. Uma geração em quarentena (§127) só
    /// sai com pedido explícito, que a task de fundo nunca faz.
    pub v6_gc_interval_secs: u64,
    /// SPEC-0050 §90 — quantas gerações do HRKM manter em cada passagem de GC.
    pub v6_gc_keep_manifests: usize,
    /// SPEC-0050 Fase 4 — intervalo da reconstrução de `.hrki` para PACKEDs
    /// que ainda não têm sidecar válido. `0` desliga.
    pub v6_hrki_interval_secs: u64,
    /// Taxa de falso positivo alvo dos Bloom filters HRKI.
    pub v6_hrki_bloom_fpr: f64,
    /// Política explícita para built-ins. `attrs.*` continuam DO_NOT_INDEX.
    pub v6_hrki_index_agent_id: bool,
    pub v6_hrki_index_session_id: bool,
    /// SPEC-0050 Fase 6 — intervalo do worker que projecta segmentos PACKED
    /// em Parquet/Iceberg/Delta. `0` desliga (default).
    ///
    /// Fica desligado de origem por uma razão que não é timidez: a projecção
    /// escreve para um destino **fora** do banco, e escolher esse destino é
    /// uma decisão do operador. Um default que começasse a materializar
    /// gigabytes numa pasta adivinhada seria pior do que não correr.
    pub v6_lakehouse_interval_secs: u64,
    /// Destino da tabela lakehouse (caminho local ou URL de object store).
    /// Vazio com o intervalo ligado é erro de configuração, não um default.
    pub v6_lakehouse_path: String,
    /// Nome da tabela publicada nos catálogos Iceberg/Delta.
    pub v6_lakehouse_table: String,
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
    /// `"local"` (ACT de desenvolvimento em processo), `"http"` (RFC 3161 em
    /// claro) ou `"https"` (SPEC-0046 §10 — `SecureTsaClient` com validação de
    /// cadeia).
    ///
    /// `"http"` não é uma fronteira de conformidade válida: não tem TLS nem
    /// verificador de cadeia. `"https"` só é aceite com
    /// `compliance_trust_store_dir` povoado — sem âncoras o cliente nem se
    /// constrói, por decisão de §11.
    pub compliance_tsa_mode: String,
    /// ACT endpoint when `compliance_tsa_mode = "http"`.
    pub compliance_tsa_url: String,
    /// Authority/policy name recorded in each receipt.
    pub compliance_tsa_policy: String,
    /// OID da política RFC 3161 que a ACT tem de aplicar ao carimbo.
    ///
    /// É separado de `compliance_tsa_policy`, que é apenas o rótulo humano
    /// persistido no recibo. Em produção este campo é obrigatório: sem ele o
    /// pedido sai sem `reqPolicy` e um token emitido sob qualquer política da
    /// mesma ACT seria aceite.
    pub compliance_tsa_policy_oid: Option<String>,
    /// SPEC-0046 §11 — pasta com as âncoras de confiança (PEM/DER) que o órgão
    /// instalou. É a MESMA confiança usada para o TLS da ACT e para a cadeia do
    /// carimbo, de propósito: se fossem duas, o sistema autenticaria o canal
    /// contra um conjunto e o carimbo contra outro, e a divergência só
    /// apareceria no dia em que uma das duas falhasse.
    ///
    /// Não há default e não há fallback para as raízes do sistema operativo:
    /// "ainda não disse em quem confiar" não pode significar "confia em
    /// qualquer um".
    pub compliance_trust_store_dir: Option<PathBuf>,
    /// SPEC-0046 — guarda de egresso à frente da ACT: `"off"` (default),
    /// `"controlled"` ou `"strict-air-gap"`.
    ///
    /// Fora de produção, o default é `"off"` e isso é deliberado. A alternativa seria instalar a
    /// guarda com uma política que autoriza tudo, o que daria a APARÊNCIA de um
    /// controlo de egresso sem o controlo — pior do que não ter guarda nenhuma,
    /// porque um auditor veria o componente na configuração e concluiria que
    /// alguém decide o que sai. Aqui, `off` significa off e vê-se.
    ///
    /// `"controlled"` autoriza exactamente um destino: o
    /// `compliance_tsa_url`. `"strict-air-gap"` nega o carimbo em linha — a
    /// ancoragem passa a ter de ir pelo caminho diferido (`deferred`). O perfil
    /// de produção com ACT em linha exige `"controlled"`.
    pub compliance_sovereignty_mode: String,
    /// SPEC-0046 §9 — pasta com as CRLs (`.crl`/`.pem`/`.der`) das ACs.
    ///
    /// `None` (default, fora de produção) mantém o comportamento anterior: a revogação NÃO é
    /// consultada e `revocation_checked` fica `false` no resultado, para que
    /// nenhum relatório construído a partir dele possa afirmar mais do que foi
    /// feito. Com a pasta definida, cada certificado da cadeia passa a exigir
    /// uma CRL assinada pelo seu emissor — e a verificação FALHA se ela faltar,
    /// porque "pedi consulta e não a consegui fazer" não pode devolver um
    /// resultado que se leia como limpo. O perfil de produção exige uma pasta
    /// não vazia e o carregamento profundo do servidor recusa material inválido.
    pub compliance_crl_dir: Option<PathBuf>,
    /// Quantos segundos depois de `nextUpdate` uma CRL ainda é aceite.
    ///
    /// Zero (default) recusa CRLs expiradas. Um órgão em air-gap que só recebe
    /// CRLs periodicamente alarga isto — e ao alargá-lo está a declarar quanto
    /// risco aceita, em vez de o sistema decidir por ele em silêncio.
    pub compliance_crl_max_staleness_secs: u64,
    /// Exigir que cada CRL declare `nextUpdate` (default `true`).
    ///
    /// Sem `nextUpdate` a CRL escapa por completo à política de frescura: uma
    /// de 2019 responderia "não revogado" com a mesma autoridade de uma de
    /// hoje. A RFC 5280 diz que ACs conformes DEVEM emitir o campo, portanto
    /// exigi-lo não recusa nada de legítimo — desligá-lo é uma decisão sobre
    /// quanto risco se aceita, e por isso é explícita.
    pub compliance_crl_exigir_next_update: bool,

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
    /// SPEC-0045 Fase 0 — plano de segurança derivado, desligado por omissão.
    /// O host pode iniciar o Sentinel sem alterar o caminho de append.
    pub sentinel: SentinelConfig,
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
            storage_format: StorageFormat::V6,
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
            v6_lakehouse_interval_secs: 0,
            v6_lakehouse_path: String::new(),
            v6_lakehouse_table: "episodios".to_string(),
            v6_packing_interval_secs: 30,
            v6_gc_interval_secs: 300,
            v6_gc_keep_manifests: 3,
            v6_hrki_interval_secs: 45,
            v6_hrki_bloom_fpr: 0.01,
            v6_hrki_index_agent_id: true,
            v6_hrki_index_session_id: true,
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
            compliance_tsa_policy_oid: None,
            compliance_trust_store_dir: None,
            compliance_sovereignty_mode: "off".to_string(),
            compliance_crl_dir: None,
            compliance_crl_max_staleness_secs: 0,
            compliance_crl_exigir_next_update: true,
            flight_addr: None,
            telemetry_interval_secs: 0,
            replication: None,
            sentinel: SentinelConfig::default(),
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

fn parse_strict_bool(name: &str, value: &str) -> Result<bool, HeraclitusError> {
    match value {
        "1" | "true" | "on" | "yes" => Ok(true),
        "0" | "false" | "off" | "no" => Ok(false),
        _ => Err(HeraclitusError::Config(format!(
            "{name} deve ser true/false (ou 1/0; on/off; yes/no), veio `{value}`"
        ))),
    }
}

/// Validação sintática barata de um OID decimal pontuado.
///
/// A descodificação normativa continua no crate de compliance. O core faz
/// esta verificação para que um erro de configuração apareça antes de abrir o
/// log, sem puxar ASN.1/X.509 para a camada de configuração.
fn oid_decimal_valido(value: &str) -> bool {
    let arcs: Vec<&str> = value.split('.').collect();
    if arcs.len() < 2
        || arcs
            .iter()
            .any(|arc| arc.is_empty() || !arc.bytes().all(|b| b.is_ascii_digit()))
        || arcs.iter().any(|arc| arc.len() > 1 && arc.starts_with('0'))
    {
        return false;
    }
    let Ok(first) = arcs[0].parse::<u8>() else {
        return false;
    };
    let Ok(second) = arcs[1].parse::<u64>() else {
        return false;
    };
    if first > 2 || (first < 2 && second > 39) {
        return false;
    }
    arcs[2..].iter().all(|arc| arc.parse::<u64>().is_ok())
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

    /// `HERACLITUS_DATA_DIR`, `HERACLITUS_STORAGE_FORMAT=legacy|v6`,
    /// `HERACLITUS_GRPC_ADDR`, `HERACLITUS_REST_ADDR`, and
    /// `HERACLITUS_FSYNC=always|group_commit:<ms>`.
    pub fn apply_env(&mut self) -> Result<(), HeraclitusError> {
        if let Ok(v) = std::env::var("HERACLITUS_DATA_DIR") {
            self.data_dir = PathBuf::from(v);
        }
        if let Ok(v) = std::env::var("HERACLITUS_STORAGE_FORMAT") {
            self.storage_format = match v.as_str() {
                "legacy" => StorageFormat::Legacy,
                "v6" => StorageFormat::V6,
                _ => {
                    return Err(HeraclitusError::Config(format!(
                        "HERACLITUS_STORAGE_FORMAT deve ser legacy ou v6; recebido {v:?}"
                    )))
                }
            };
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
        if let Ok(v) = std::env::var("HERACLITUS_SENTINEL_ENABLED") {
            self.sentinel.enabled = parse_strict_bool("HERACLITUS_SENTINEL_ENABLED", &v)?;
            if !self.sentinel.enabled {
                self.sentinel.mode = SentinelMode::Disabled;
            } else if self.sentinel.mode == SentinelMode::Disabled {
                self.sentinel.mode = SentinelMode::Observe;
            }
        }
        if let Ok(v) = std::env::var("HERACLITUS_SENTINEL_MODE") {
            self.sentinel.mode = match v.to_ascii_lowercase().as_str() {
                "disabled" | "off" => SentinelMode::Disabled,
                "observe" => SentinelMode::Observe,
                "shadow" => SentinelMode::Shadow,
                "assist" => SentinelMode::Assist,
                "autonomous" => SentinelMode::Autonomous,
                _ => {
                    return Err(HeraclitusError::Config(format!(
                        "HERACLITUS_SENTINEL_MODE inválido: {v:?}"
                    )))
                }
            };
            self.sentinel.enabled = self.sentinel.mode != SentinelMode::Disabled;
        }
        if let Ok(v) = std::env::var("HERACLITUS_SENTINEL_QUEUE_CAPACITY") {
            self.sentinel.queue_capacity = v.parse().map_err(|e| {
                HeraclitusError::Config(format!(
                    "HERACLITUS_SENTINEL_QUEUE_CAPACITY deve ser inteiro positivo: {e}"
                ))
            })?;
        }
        if let Ok(v) = std::env::var("HERACLITUS_SENTINEL_WORKERS") {
            self.sentinel.worker_threads = v.parse().map_err(|e| {
                HeraclitusError::Config(format!(
                    "HERACLITUS_SENTINEL_WORKERS deve ser inteiro positivo: {e}"
                ))
            })?;
        }
        if let Ok(v) = std::env::var("HERACLITUS_SENTINEL_PIPELINE_VERSION") {
            self.sentinel.pipeline_version = v.parse().map_err(|e| {
                HeraclitusError::Config(format!(
                    "HERACLITUS_SENTINEL_PIPELINE_VERSION deve ser inteiro: {e}"
                ))
            })?;
        }
        if let Ok(v) = std::env::var("HERACLITUS_SENTINEL_CATCH_UP_BATCH") {
            self.sentinel.catch_up_batch = v.parse().map_err(|e| {
                HeraclitusError::Config(format!(
                    "HERACLITUS_SENTINEL_CATCH_UP_BATCH deve ser inteiro positivo: {e}"
                ))
            })?;
        }
        if let Ok(v) = std::env::var("HERACLITUS_SENTINEL_L1_ENABLED") {
            self.sentinel.l1.enabled = parse_strict_bool("HERACLITUS_SENTINEL_L1_ENABLED", &v)?;
        }
        if let Ok(v) = std::env::var("HERACLITUS_SENTINEL_L1_RULES_PATH") {
            if !v.trim().is_empty() {
                self.sentinel.l1.rules_path = Some(PathBuf::from(v));
            }
        }
        if let Ok(v) = std::env::var("HERACLITUS_SENTINEL_L2_ENABLED") {
            self.sentinel.l2.enabled = parse_strict_bool("HERACLITUS_SENTINEL_L2_ENABLED", &v)?;
        }
        if let Ok(v) = std::env::var("HERACLITUS_SENTINEL_L2_MINIMUM_SUPPORT") {
            self.sentinel.l2.minimum_support = v.parse().map_err(|e| {
                HeraclitusError::Config(format!(
                    "HERACLITUS_SENTINEL_L2_MINIMUM_SUPPORT deve ser inteiro positivo: {e}"
                ))
            })?;
        }
        if let Ok(v) = std::env::var("HERACLITUS_SENTINEL_L2_LEARNING_DELAY_EVENTS") {
            self.sentinel.l2.learning_delay_events = v.parse().map_err(|e| {
                HeraclitusError::Config(format!(
                    "HERACLITUS_SENTINEL_L2_LEARNING_DELAY_EVENTS deve ser inteiro positivo: {e}"
                ))
            })?;
        }
        if let Ok(v) = std::env::var("HERACLITUS_SENTINEL_L2_SHADOW_ONLY") {
            self.sentinel.l2.shadow_only =
                parse_strict_bool("HERACLITUS_SENTINEL_L2_SHADOW_ONLY", &v)?;
        }
        if let Ok(v) = std::env::var("HERACLITUS_SENTINEL_L2_SUSPICIOUS_SEVERITY") {
            self.sentinel.l2.suspicious_severity = v.parse().map_err(|e| {
                HeraclitusError::Config(format!(
                    "HERACLITUS_SENTINEL_L2_SUSPICIOUS_SEVERITY deve ser inteiro entre 0 e 10: {e}"
                ))
            })?;
        }
        if let Ok(v) = std::env::var("HERACLITUS_SENTINEL_L3_ENABLED") {
            self.sentinel.l3.enabled = parse_strict_bool("HERACLITUS_SENTINEL_L3_ENABLED", &v)?;
        }
        if let Ok(v) = std::env::var("HERACLITUS_SENTINEL_L3_MAX_GRAPH_HOPS") {
            self.sentinel.l3.max_graph_hops = v.parse().map_err(|e| {
                HeraclitusError::Config(format!(
                    "HERACLITUS_SENTINEL_L3_MAX_GRAPH_HOPS deve ser inteiro positivo: {e}"
                ))
            })?;
        }
        if let Ok(v) = std::env::var("HERACLITUS_TIER_COMPACTION_INTERVAL") {
            if let Ok(s) = v.parse() {
                self.tier_compaction_interval_secs = s;
            }
        }
        if let Ok(v) = std::env::var("HERACLITUS_V6_PACKING_INTERVAL") {
            self.v6_packing_interval_secs = v.parse().map_err(|e| {
                HeraclitusError::Config(format!(
                    "HERACLITUS_V6_PACKING_INTERVAL deve ser inteiro em segundos: {e}"
                ))
            })?;
        }
        if let Ok(v) = std::env::var("HERACLITUS_V6_GC_INTERVAL") {
            self.v6_gc_interval_secs = v.parse().map_err(|e| {
                HeraclitusError::Config(format!(
                    "HERACLITUS_V6_GC_INTERVAL deve ser inteiro em segundos: {e}"
                ))
            })?;
        }
        if let Ok(v) = std::env::var("HERACLITUS_V6_GC_KEEP_MANIFESTS") {
            self.v6_gc_keep_manifests = v.parse().map_err(|e| {
                HeraclitusError::Config(format!(
                    "HERACLITUS_V6_GC_KEEP_MANIFESTS deve ser inteiro: {e}"
                ))
            })?;
        }
        if let Ok(v) = std::env::var("HERACLITUS_V6_HRKI_INTERVAL") {
            self.v6_hrki_interval_secs = v.parse().map_err(|e| {
                HeraclitusError::Config(format!(
                    "HERACLITUS_V6_HRKI_INTERVAL deve ser inteiro em segundos: {e}"
                ))
            })?;
        }
        if let Ok(v) = std::env::var("HERACLITUS_V6_LAKEHOUSE_INTERVAL") {
            self.v6_lakehouse_interval_secs = v.parse().map_err(|e| {
                HeraclitusError::Config(format!(
                    "HERACLITUS_V6_LAKEHOUSE_INTERVAL deve ser inteiro em segundos: {e}"
                ))
            })?;
        }
        if let Ok(v) = std::env::var("HERACLITUS_V6_LAKEHOUSE_PATH") {
            if !v.is_empty() {
                self.v6_lakehouse_path = v;
            }
        }
        if let Ok(v) = std::env::var("HERACLITUS_V6_LAKEHOUSE_TABLE") {
            if !v.is_empty() {
                self.v6_lakehouse_table = v;
            }
        }
        if let Ok(v) = std::env::var("HERACLITUS_V6_HRKI_BLOOM_FPR") {
            self.v6_hrki_bloom_fpr = v.parse().map_err(|e| {
                HeraclitusError::Config(format!(
                    "HERACLITUS_V6_HRKI_BLOOM_FPR deve ser número: {e}"
                ))
            })?;
        }
        if let Ok(v) = std::env::var("HERACLITUS_V6_HRKI_INDEX_AGENT_ID") {
            self.v6_hrki_index_agent_id =
                parse_strict_bool("HERACLITUS_V6_HRKI_INDEX_AGENT_ID", &v)?;
        }
        if let Ok(v) = std::env::var("HERACLITUS_V6_HRKI_INDEX_SESSION_ID") {
            self.v6_hrki_index_session_id =
                parse_strict_bool("HERACLITUS_V6_HRKI_INDEX_SESSION_ID", &v)?;
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
                // O modo vem do ESQUEMA, não é fixo em "http". Antes, pôr um
                // URL `https://` aqui deixava o modo em "http" e entregava o
                // cliente em claro a quem tinha pedido TLS — falhava só na
                // primeira tentativa de carimbo, com uma mensagem sobre o
                // esquema não suportado que não apontava para a causa.
                self.compliance_tsa_mode = if v.starts_with("https://") {
                    "https".to_string()
                } else {
                    "http".to_string()
                };
                self.compliance_tsa_url = v;
            }
        }
        if let Ok(v) = std::env::var("HERACLITUS_COMPLIANCE_TRUST_STORE") {
            if !v.is_empty() {
                self.compliance_trust_store_dir = Some(PathBuf::from(v));
            }
        }
        if let Ok(v) = std::env::var("HERACLITUS_COMPLIANCE_SOVEREIGNTY") {
            if !v.is_empty() {
                self.compliance_sovereignty_mode = v;
            }
        }
        if let Ok(v) = std::env::var("HERACLITUS_COMPLIANCE_CRL_DIR") {
            if !v.is_empty() {
                self.compliance_crl_dir = Some(PathBuf::from(v));
            }
        }
        if let Ok(v) = std::env::var("HERACLITUS_COMPLIANCE_CRL_MAX_STALENESS") {
            if let Ok(n) = v.parse::<u64>() {
                self.compliance_crl_max_staleness_secs = n;
            }
        }
        if let Ok(v) = std::env::var("HERACLITUS_COMPLIANCE_CRL_ALLOW_NO_NEXT_UPDATE") {
            self.compliance_crl_exigir_next_update =
                !matches!(v.to_ascii_lowercase().as_str(), "1" | "true" | "on" | "yes");
        }
        if let Ok(v) = std::env::var("HERACLITUS_COMPLIANCE_TSA_POLICY") {
            if !v.is_empty() {
                self.compliance_tsa_policy = v;
            }
        }
        if let Ok(v) = std::env::var("HERACLITUS_COMPLIANCE_TSA_POLICY_OID") {
            self.compliance_tsa_policy_oid = (!v.is_empty()).then_some(v);
        }
        Ok(())
    }

    pub fn validate_security(&self) -> Result<(), HeraclitusError> {
        let invalid = |message: String| HeraclitusError::Config(message);
        if self.sentinel.enabled && self.sentinel.mode == SentinelMode::Disabled {
            return Err(invalid(
                "sentinel.enabled=true exige sentinel.mode diferente de disabled".into(),
            ));
        }
        if !self.sentinel.enabled && self.sentinel.mode != SentinelMode::Disabled {
            return Err(invalid(
                "sentinel.mode ativo exige sentinel.enabled=true".into(),
            ));
        }
        if self.sentinel.mode == SentinelMode::Autonomous {
            return Err(invalid(
                "sentinel.mode=autonomous está bloqueado: exige permit verificado dos gates e executor qualificado"
                    .into(),
            ));
        }
        if self.sentinel.enabled && self.sentinel.queue_capacity == 0 {
            return Err(invalid(
                "sentinel.queue_capacity deve ser maior que zero".into(),
            ));
        }
        if self.sentinel.enabled && self.sentinel.worker_threads == 0 {
            return Err(invalid(
                "sentinel.worker_threads deve ser maior que zero".into(),
            ));
        }
        if self.sentinel.enabled && self.sentinel.catch_up_batch == 0 {
            return Err(invalid(
                "sentinel.catch_up_batch deve ser maior que zero".into(),
            ));
        }
        if self.sentinel.l1.enabled && !self.sentinel.enabled {
            return Err(invalid(
                "sentinel.l1.enabled=true exige sentinel.enabled=true".into(),
            ));
        }
        if self.sentinel.l1.enabled && self.sentinel.l1.rules_path.is_none() {
            return Err(invalid(
                "sentinel.l1.enabled=true exige sentinel.l1.rules_path".into(),
            ));
        }
        if self.sentinel.l2.enabled && !self.sentinel.enabled {
            return Err(invalid(
                "sentinel.l2.enabled=true exige sentinel.enabled=true".into(),
            ));
        }
        if self.sentinel.l2.enabled
            && (self.sentinel.l2.minimum_support == 0
                || self.sentinel.l2.learning_delay_events == 0)
        {
            return Err(invalid(
                "sentinel.l2 minimum_support e learning_delay_events devem ser maiores que zero"
                    .into(),
            ));
        }
        if self.sentinel.l2.suspicious_severity > 10 {
            return Err(invalid(
                "sentinel.l2.suspicious_severity deve estar entre 0 e 10".into(),
            ));
        }
        if self.sentinel.l3.enabled && !self.sentinel.enabled {
            return Err(invalid(
                "sentinel.l3.enabled=true exige sentinel.enabled=true".into(),
            ));
        }
        if self.sentinel.l3.enabled && !(1..=32).contains(&self.sentinel.l3.max_graph_hops) {
            return Err(invalid(
                "sentinel.l3.max_graph_hops deve estar entre 1 e 32".into(),
            ));
        }
        if !(1e-6..=0.5).contains(&self.v6_hrki_bloom_fpr) {
            return Err(invalid(format!(
                "v6_hrki_bloom_fpr deve estar entre 0.000001 e 0.5; veio {}",
                self.v6_hrki_bloom_fpr
            )));
        }
        // SPEC-0050 Fase 6 — ligar o worker sem dizer para onde exportar é um
        // erro de configuração, não um convite a adivinhar um destino.
        if self.v6_lakehouse_interval_secs > 0 && self.v6_lakehouse_path.trim().is_empty() {
            return Err(invalid(
                "v6_lakehouse_interval_secs > 0 exige v6_lakehouse_path".into(),
            ));
        }
        if self.v6_lakehouse_interval_secs > 0 && self.v6_lakehouse_table.trim().is_empty() {
            return Err(invalid(
                "v6_lakehouse_interval_secs > 0 exige v6_lakehouse_table".into(),
            ));
        }
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
            if !self.compliance_enabled || self.compliance_tsa_url.is_empty() {
                return Err(invalid(
                    "produção exige uma TSA externa configurada; LocalTsa não é evidência legal"
                        .into(),
                ));
            }
            if self.compliance_tsa_url.starts_with("http://")
                || self.compliance_tsa_mode.eq_ignore_ascii_case("http")
            {
                return Err(invalid(
                    "produção proíbe TSA em HTTP puro: o digest do que se está a ancorar atravessaria a rede em claro e sem autenticar o servidor"
                        .into(),
                ));
            }
            if !self.compliance_tsa_mode.eq_ignore_ascii_case("https")
                || !self.compliance_tsa_url.starts_with("https://")
            {
                return Err(invalid(format!(
                    "produção exige compliance_tsa_mode=https com URL https:// (está `{}` / `{}`)",
                    self.compliance_tsa_mode, self.compliance_tsa_url
                )));
            }
            if !self
                .compliance_sovereignty_mode
                .eq_ignore_ascii_case("controlled")
            {
                return Err(invalid(
                    "produção com ACT em linha exige HERACLITUS_COMPLIANCE_SOVEREIGNTY=controlled: `off` não aplica a allowlist e `strict-air-gap` proíbe a própria ligação"
                        .into(),
                ));
            }
            let Some(policy_oid) = self.compliance_tsa_policy_oid.as_deref() else {
                return Err(invalid(
                    "produção exige HERACLITUS_COMPLIANCE_TSA_POLICY_OID: sem o OID esperado o pedido sai sem reqPolicy e qualquer política da ACT seria aceite"
                        .into(),
                ));
            };
            if !oid_decimal_valido(policy_oid) {
                return Err(invalid(format!(
                    "HERACLITUS_COMPLIANCE_TSA_POLICY_OID inválido: `{policy_oid}`"
                )));
            }
            // §11 — sem âncoras o `SecureTsaClient` nem se constrói, e um
            // recibo produzido sem elas é `ExternalTokenUnvalidated`. Deixar
            // arrancar assim daria um sistema que se diz em produção e emite
            // evidência que não vale como evidência.
            let Some(dir) = self.compliance_trust_store_dir.as_ref() else {
                return Err(invalid(
                    "produção exige HERACLITUS_COMPLIANCE_TRUST_STORE com as âncoras ICP-Brasil do órgão (§11): sem elas o carimbo não é validado contra autoridade nenhuma"
                        .into(),
                ));
            };
            // Verificação superficial de propósito: este crate não conhece
            // X.509. Que os ficheiros sejam âncoras auto-emitidas e utilizáveis
            // é decidido ao carregar, no arranque do servidor, que recusa
            // arrancar se o conjunto vier vazio. Aqui apanha-se só o erro
            // comum — a pasta errada ou vazia — e apanha-se antes de o
            // processo abrir o log.
            let ficheiros = std::fs::read_dir(dir)
                .map_err(|e| invalid(format!("trust store `{}`: {e}", dir.display())))?
                .filter_map(Result::ok)
                .filter(|e| e.path().is_file())
                .count();
            if ficheiros == 0 {
                return Err(invalid(format!(
                    "trust store `{}` não tem ficheiros: produção exige pelo menos uma âncora",
                    dir.display()
                )));
            }
            let Some(crl_dir) = self.compliance_crl_dir.as_ref() else {
                return Err(invalid(
                    "produção exige HERACLITUS_COMPLIANCE_CRL_DIR: uma cadeia válida sem consulta de revogação não é evidência pronta para produção"
                        .into(),
                ));
            };
            let crl_files = std::fs::read_dir(crl_dir)
                .map_err(|e| invalid(format!("CRLs `{}`: {e}", crl_dir.display())))?
                .filter_map(Result::ok)
                .filter(|e| e.path().is_file())
                .count();
            if crl_files == 0 {
                return Err(invalid(format!(
                    "pasta de CRLs `{}` não tem ficheiros: produção exige informação de revogação",
                    crl_dir.display()
                )));
            }
            return Ok(());
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
        assert_eq!(cfg.storage_format, StorageFormat::V6, "v6 é o default");
        let s = toml::to_string(&cfg).unwrap();
        let back: HeraclitusConfig = toml::from_str(&s).unwrap();
        assert_eq!(back.segment_max_bytes, cfg.segment_max_bytes);
        assert_eq!(back.fsync, cfg.fsync);
        assert_eq!(back.storage_format, StorageFormat::V6);
    }

    /// O legado continua acessível, e só por escolha explícita.
    ///
    /// Um default que se pudesse obter por omissão dos dois lados tornaria
    /// impossível a um operador saber que formato tem sem ir ao disco.
    #[test]
    fn toml_selects_each_storage_format_explicitly() {
        let v6: HeraclitusConfig = toml::from_str("storage_format = \"v6\"").unwrap();
        assert_eq!(v6.storage_format, StorageFormat::V6);
        assert_eq!(v6.storage_format.as_str(), "v6");

        let legado: HeraclitusConfig = toml::from_str("storage_format = \"legacy\"").unwrap();
        assert_eq!(legado.storage_format, StorageFormat::Legacy);
        assert_eq!(legado.storage_format.as_str(), "legacy");
    }

    #[test]
    fn sentinel_config_roundtrips_and_defaults_to_disabled() {
        let cfg = HeraclitusConfig::default();
        assert!(!cfg.sentinel.enabled);
        assert_eq!(cfg.sentinel.mode, SentinelMode::Disabled);
        let text = toml::to_string(&cfg).unwrap();
        let back: HeraclitusConfig = toml::from_str(&text).unwrap();
        assert_eq!(back.sentinel, cfg.sentinel);

        let enabled: HeraclitusConfig = toml::from_str(
            r#"[sentinel]
enabled = true
mode = "observe"
queue_capacity = 8
worker_threads = 1
pipeline_version = 2
catch_up_batch = 16

[sentinel.l1]
enabled = true
rules_path = "rules"

[sentinel.l2]
enabled = true
minimum_support = 4
learning_delay_events = 2
shadow_only = false
suspicious_severity = 8

[sentinel.l3]
enabled = true
max_graph_hops = 6
"#,
        )
        .unwrap();
        assert!(enabled.sentinel.enabled);
        assert_eq!(enabled.sentinel.mode, SentinelMode::Observe);
        assert_eq!(enabled.sentinel.queue_capacity, 8);
        assert!(enabled.sentinel.l1.enabled);
        assert!(enabled.sentinel.l2.enabled);
        assert_eq!(enabled.sentinel.l2.minimum_support, 4);
        assert!(!enabled.sentinel.l2.shadow_only);
        assert!(enabled.sentinel.l3.enabled);
        assert_eq!(enabled.sentinel.l3.max_graph_hops, 6);
        assert_eq!(
            enabled.sentinel.l1.rules_path.as_deref(),
            Some(std::path::Path::new("rules"))
        );
    }

    #[test]
    fn sentinel_l3_is_fail_closed_and_bounds_graph_traversal() {
        let mut cfg = HeraclitusConfig::default();
        cfg.sentinel.l3.enabled = true;
        assert!(cfg.validate_security().is_err());

        cfg.sentinel.enabled = true;
        cfg.sentinel.mode = SentinelMode::Observe;
        cfg.sentinel.l3.max_graph_hops = 0;
        assert!(cfg.validate_security().is_err());
        cfg.sentinel.l3.max_graph_hops = 33;
        assert!(cfg.validate_security().is_err());
        cfg.sentinel.l3.max_graph_hops = 6;
        assert!(cfg.validate_security().is_ok());
    }

    #[test]
    fn sentinel_l2_is_opt_in_and_bounds_baseline_controls() {
        let mut cfg = HeraclitusConfig::default();
        cfg.sentinel.l2.enabled = true;
        assert!(cfg.validate_security().is_err());

        cfg.sentinel.enabled = true;
        cfg.sentinel.mode = SentinelMode::Observe;
        cfg.sentinel.l2.minimum_support = 0;
        assert!(cfg.validate_security().is_err());
        cfg.sentinel.l2.minimum_support = 2;
        cfg.sentinel.l2.learning_delay_events = 0;
        assert!(cfg.validate_security().is_err());
        cfg.sentinel.l2.learning_delay_events = 1;
        cfg.sentinel.l2.suspicious_severity = 11;
        assert!(cfg.validate_security().is_err());
        cfg.sentinel.l2.suspicious_severity = 7;
        assert!(cfg.validate_security().is_ok());
    }

    #[test]
    fn autonomous_mode_is_not_a_configuration_bypass() {
        let mut cfg = HeraclitusConfig::default();
        cfg.sentinel.enabled = true;
        cfg.sentinel.mode = SentinelMode::Autonomous;
        let error = cfg.validate_security().unwrap_err().to_string();
        assert!(error.contains("autonomous") && error.contains("bloqueado"));
    }

    #[test]
    fn invalid_storage_format_env_is_a_config_error() {
        const NAME: &str = "HERACLITUS_STORAGE_FORMAT";
        let previous = std::env::var_os(NAME);
        std::env::set_var(NAME, "V6");

        let err = HeraclitusConfig::default()
            .apply_env()
            .expect_err("environment selection must be strict");

        match previous {
            Some(value) => std::env::set_var(NAME, value),
            None => std::env::remove_var(NAME),
        }
        assert!(matches!(err, HeraclitusError::Config(_)));
        assert!(err.to_string().contains("legacy ou v6"));
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
        // O MODO manda, não o esquema do URL: `mode=http` com um URL `https://`
        // continua a ser o cliente em claro, e é recusado.
        let err = cfg.validate_security().unwrap_err().to_string();
        assert!(err.contains("HTTP puro"), "{err}");

        cfg.compliance_tsa_url = "http://tsa.example.invalid".into();
        assert!(cfg
            .validate_security()
            .unwrap_err()
            .to_string()
            .contains("HTTP puro"));

        // §10 — HTTPS existe desde o Marco 0, mas sem âncoras o carimbo não é
        // validado contra autoridade nenhuma, e um recibo assim não vale como
        // evidência. A recusa aqui é sobre o trust store, não sobre a falta de
        // implementação: a mensagem que dizia "esta build não implementa
        // HTTPS" sobreviveu à implementação e mandava corrigir a coisa errada.
        cfg.compliance_tsa_mode = "https".into();
        cfg.compliance_tsa_url = "https://tsa.example.invalid".into();
        let err = cfg.validate_security().unwrap_err().to_string();
        assert!(err.contains("SOVEREIGNTY=controlled"), "{err}");

        cfg.compliance_sovereignty_mode = "controlled".into();
        let err = cfg.validate_security().unwrap_err().to_string();
        assert!(err.contains("TSA_POLICY_OID"), "{err}");

        cfg.compliance_tsa_policy_oid = Some("OID-invalido".into());
        let err = cfg.validate_security().unwrap_err().to_string();
        assert!(err.contains("inválido"), "{err}");

        cfg.compliance_tsa_policy_oid = Some("2.16.76.1.7.1.1.2.3".into());
        let err = cfg.validate_security().unwrap_err().to_string();
        assert!(err.contains("TRUST_STORE"), "{err}");

        // Pasta indicada mas vazia: o erro comum, apanhado antes de o processo
        // abrir o log.
        let dir = tempfile::tempdir().unwrap();
        cfg.compliance_trust_store_dir = Some(dir.path().to_path_buf());
        let err = cfg.validate_security().unwrap_err().to_string();
        assert!(err.contains("não tem ficheiros"), "{err}");

        // Com uma âncora instalada, o perfil de produção PASSA. É a mudança
        // desta ronda: antes, todos os caminhos devolviam erro e não havia
        // configuração nenhuma que arrancasse em produção.
        //
        // Que o ficheiro seja um certificado auto-emitido utilizável é
        // decidido ao CARREGAR, no arranque do servidor — este crate não
        // conhece X.509 e não finge conhecer.
        std::fs::write(dir.path().join("raiz.pem"), b"-----BEGIN CERTIFICATE-----").unwrap();
        let err = cfg.validate_security().unwrap_err().to_string();
        assert!(err.contains("COMPLIANCE_CRL_DIR"), "{err}");

        let crls = tempfile::tempdir().unwrap();
        cfg.compliance_crl_dir = Some(crls.path().to_path_buf());
        let err = cfg.validate_security().unwrap_err().to_string();
        assert!(err.contains("não tem ficheiros"), "{err}");
        std::fs::write(crls.path().join("ac.crl"), b"fixture validado no servidor").unwrap();
        cfg.validate_security()
            .expect("perfil de produção completo tem de arrancar");

        // E continua fail-closed noutro eixo: uma senha curta derruba tudo
        // outra vez, para que o sucesso acima não se leia como "a guarda
        // deixou de guardar".
        cfg.rest_basic_auth = Some("admin:short".into());
        assert!(cfg.validate_security().is_err());
    }

    #[test]
    fn policy_oid_decimal_e_validado_sem_asn1_no_core() {
        assert!(oid_decimal_valido("2.16.76.1.7.1.1.2.3"));
        assert!(oid_decimal_valido("1.2.840.113549.1.9.16.1.4"));
        for invalido in ["", "1", ".1.2", "3.1", "1.40", "1..2", "1.02.3", "a.b"] {
            assert!(!oid_decimal_valido(invalido), "{invalido}");
        }
    }
}
