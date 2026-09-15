//! SPEC-0077 — a superfície da **plataforma**.
//!
//! # Porque é que este módulo existe
//!
//! As SPEC-0074/75/76 puseram a Agent Console na raiz (`/`) do porto da
//! consola. O efeito colateral foi transformar a identidade do produto: quem
//! abria o HeraclitusDB via um monitor de agentes de IA, e não um banco de
//! dados temporal verificável com um módulo de agentes. A SPEC-0077 revoga esse
//! posicionamento — a capacidade fica, o pivô de produto sai.
//!
//! Este módulo é a metade que faltava: o que `/` mostra quando não é a Agent
//! Console.
//!
//! # Porque é que fica NESTE crate
//!
//! Porque é este crate que possui o listener do porto da consola. Pôr a
//! Platform Console noutro sítio obrigaria ou a um segundo porto (e a explicar
//! a um operador porque é que o produto tem duas moradas), ou a mover o
//! listener para o `heraclitus-server` (uma refactorização grande a meio de uma
//! correcção de posicionamento). A SPEC-0077 §36 é explícita em que isto é
//! sobretudo *routing, surface e composição de produto* — não um redesenho.
//!
//! O nome do crate ficou mais estreito do que aquilo que ele serve. É dívida
//! reconhecida, não descuido: renomeá-lo agora partia o `Cargo.toml` de quem
//! embebe o motor, para ganhar estética.
//!
//! # A regra que governa tudo aqui
//!
//! SPEC-0077 §33: **é proibido inventar métricas**. Nenhum número desta
//! superfície é estimado, arredondado para ficar bonito ou preenchido com um
//! valor plausível. Quando o motor não sabe responder, o campo vem `null` e a
//! UI escreve `N/A`. É por isso que [`PlatformSource`] é um *trait* e não uma
//! struct de dados: quem não tem motor por trás (o gateway autónomo, os testes)
//! não consegue acidentalmente produzir um número — não há nada que o produza.

use axum::extract::State;
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Serialize;
use std::sync::Arc;

use crate::runtime::AgentRuntime;

const INDEX_HTML: &str = include_str!("../../../ui/platform-console/index.html");
const PLATFORM_CSS: &str = include_str!("../../../ui/platform-console/platform.css");
const PLATFORM_JS: &str = include_str!("../../../ui/platform-console/platform.js");

// ── os estados honestos ─────────────────────────────────────────────────────

/// Integridade do log, com os mesmos estados que a SPEC-0076 §33 fixou para a
/// evidência de agentes.
///
/// `Unverified` **nunca** promove a `Verified`. A distinção entre "não
/// verificado" e "válido" é a razão de existir do produto; colapsá-la na UI da
/// plataforma desfaria na home o cuidado que o módulo de agentes tem.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum IntegrityState {
    Verified,
    Unverified,
    Partial,
    Broken,
    NotConfigured,
    /// Não há motor por trás desta superfície. Não é "saudável" nem "avariado":
    /// é ausência de informação, e diz-se assim.
    Unavailable,
}

/// Estado de um módulo (§18, §38).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum ModuleState {
    Enabled,
    Disabled,
    Degraded,
    NotConfigured,
    /// Compilado para fora por uma feature do Cargo. §38 é explícita: não
    /// inferir disponibilidade de um 404. Uma rota que não existe porque o
    /// código não foi compilado é diferente de uma rota desligada na
    /// configuração, e o operador precisa de saber qual das duas tem à frente —
    /// uma resolve-se no ficheiro de configuração, a outra exige recompilar.
    NotBuilt,
}

#[derive(Debug, Clone, Serialize)]
pub struct ModuleStatus {
    pub id: String,
    pub name: String,
    pub summary: String,
    pub state: ModuleState,
    /// Uma linha que explica o estado. `None` quando não há nada de útil a
    /// acrescentar — melhor vazio do que uma frase de encher.
    pub detail: Option<String>,
    /// Rota interna da consola do módulo, quando existe.
    pub href: Option<String>,
}

/// Uma fonte de dados realmente presente no log.
#[derive(Debug, Clone, Serialize)]
pub struct SourceRow {
    pub id: String,
    pub events: u64,
    pub first_ms: Option<u64>,
    pub last_ms: Option<u64>,
    pub first_lsn: Option<u64>,
    pub last_lsn: Option<u64>,
}

/// Cardinalidade de um índice. O nome é o do índice, não uma etiqueta de
/// marketing.
#[derive(Debug, Clone, Serialize)]
pub struct IndexRow {
    pub id: String,
    pub label: String,
    pub count: u64,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct StorageRow {
    pub raw_bytes: Option<u64>,
    pub packed_bytes: Option<u64>,
    pub compression_ratio: Option<f64>,
    pub append_bytes_total: Option<u64>,
    /// Porque é que o resto vem a `None`, quando vem.
    pub unavailable_reason: Option<String>,
}

/// Tudo o que a Platform Console mostra, e nada mais.
///
/// Cada `Option` é uma pergunta a que o motor pode honestamente não saber
/// responder. O default é o estado "não há motor": tudo vazio, integridade
/// `Unavailable`.
#[derive(Debug, Clone, Serialize)]
pub struct PlatformSnapshot {
    pub product: &'static str,
    pub tagline: &'static str,
    pub version: &'static str,
    pub last_lsn: Option<u64>,
    pub storage_format: Option<String>,
    pub memtable_pending: Option<u64>,
    pub integrity: IntegrityState,
    pub integrity_detail: Option<String>,
    pub indexes: Vec<IndexRow>,
    pub views: Vec<String>,
    pub sources: Vec<SourceRow>,
    pub oldest_event_ms: Option<u64>,
    pub newest_event_ms: Option<u64>,
    pub storage: StorageRow,
    pub modules: Vec<ModuleStatus>,
    /// `dev_local` | `basic` | `oidc`. Preenchido pelo handler, não pela fonte:
    /// quem sabe como a porta está fechada é o runtime HTTP, não o motor.
    pub auth: &'static str,
    /// §28 da 0076 — uma senha partilhada fecha a porta e não identifica
    /// pessoas. A Platform Console põe o mesmo aviso que a Agent Console.
    pub auth_identifies_people: bool,
}

impl Default for PlatformSnapshot {
    fn default() -> Self {
        Self {
            product: "HeraclitusDB",
            tagline: "Temporal, Verifiable Data & Intelligence Platform",
            version: env!("CARGO_PKG_VERSION"),
            last_lsn: None,
            storage_format: None,
            memtable_pending: None,
            integrity: IntegrityState::Unavailable,
            integrity_detail: None,
            indexes: Vec::new(),
            views: Vec::new(),
            sources: Vec::new(),
            oldest_event_ms: None,
            newest_event_ms: None,
            storage: StorageRow::default(),
            modules: Vec::new(),
            auth: "dev_local",
            auth_identifies_people: false,
        }
    }
}

/// Quem sabe responder pelo estado da plataforma.
///
/// Implementado pelo `heraclitus-server` sobre o `Engine`. Este crate não
/// conhece o motor — e é de propósito: assim não há caminho pelo qual a
/// Platform Console possa fabricar um número sem alguém, algures, o ter ido
/// buscar ao log.
pub trait PlatformSource: Send + Sync + 'static {
    fn snapshot(&self) -> PlatformSnapshot;
}

// ── os assets ───────────────────────────────────────────────────────────────

fn security_headers() -> [(header::HeaderName, &'static str); 4] {
    [
        (
            header::CONTENT_SECURITY_POLICY,
            "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; \
             connect-src 'self'; form-action 'none'; frame-ancestors 'none'; base-uri 'none'",
        ),
        (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
        (header::REFERRER_POLICY, "no-referrer"),
        (header::CACHE_CONTROL, "no-store"),
    ]
}

pub async fn index(State(runtime): State<Arc<AgentRuntime>>, headers: HeaderMap) -> Response {
    if let Err(r) = crate::console::gate(&runtime, &headers) {
        return r;
    }
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        security_headers(),
        INDEX_HTML,
    )
        .into_response()
}

pub async fn css(State(runtime): State<Arc<AgentRuntime>>, headers: HeaderMap) -> Response {
    if let Err(r) = crate::console::gate(&runtime, &headers) {
        return r;
    }
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/css; charset=utf-8")],
        security_headers(),
        PLATFORM_CSS,
    )
        .into_response()
}

pub async fn js(State(runtime): State<Arc<AgentRuntime>>, headers: HeaderMap) -> Response {
    if let Err(r) = crate::console::gate(&runtime, &headers) {
        return r;
    }
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/javascript; charset=utf-8")],
        security_headers(),
        PLATFORM_JS,
    )
        .into_response()
}

// ── a API ───────────────────────────────────────────────────────────────────

/// `GET /api/v1/platform/summary` — §37.
///
/// Uma agregação, e não quinze pedidos. O formato reflecte tipos reais: o que
/// não existe vem `null`, nunca zero. Zero é um facto sobre o log; `null` é a
/// ausência de facto — trocá-los faria a home afirmar "0 eventos" sobre um
/// banco que ela não conseguiu sequer consultar.
pub async fn summary(State(runtime): State<Arc<AgentRuntime>>, headers: HeaderMap) -> Response {
    if let Err(r) = crate::console::gate(&runtime, &headers) {
        return r;
    }
    let mut snapshot = match runtime.platform() {
        Some(fonte) => fonte.snapshot(),
        None => PlatformSnapshot {
            integrity_detail: Some(
                "esta superfície está a correr sem motor por trás (gateway autónomo); \
                 nenhum estado do log pode ser afirmado"
                    .to_string(),
            ),
            modules: modulos_sem_motor(&runtime),
            ..PlatformSnapshot::default()
        },
    };
    let modo = runtime.auth_mode();
    snapshot.auth = modo.label();
    snapshot.auth_identifies_people = modo.identifies_people();
    (StatusCode::OK, Json(snapshot)).into_response()
}

/// O único módulo sobre o qual um gateway sem motor pode falar é o seu próprio.
fn modulos_sem_motor(runtime: &Arc<AgentRuntime>) -> Vec<ModuleStatus> {
    vec![ModuleStatus {
        id: "agent".into(),
        name: "Agent Evidence & Control".into(),
        summary: "Capture and control AI-agent activity.".into(),
        state: if runtime.config.enabled {
            ModuleState::Enabled
        } else {
            ModuleState::Disabled
        },
        detail: None,
        href: runtime.config.enabled.then(|| "/agent".to_string()),
    }]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_home_e_do_heraclitusdb_e_nao_do_modulo_de_agentes() {
        // SPEC-0077 §39 — o teste obrigatório. Se alguém voltar a pôr a Agent
        // Console na raiz, falha aqui e não seis meses depois numa demo.
        assert!(INDEX_HTML.contains("HeraclitusDB"));
        let cabecalho = INDEX_HTML
            .split("<main")
            .next()
            .expect("o shell tem de ter um <main>");
        assert!(
            !cabecalho.contains("Agent Black Box"),
            "a identidade da home voltou a ser o módulo de agentes"
        );
    }

    #[test]
    fn a_platform_console_nao_carrega_nada_de_fora() {
        for linha in INDEX_HTML.lines() {
            if linha.contains("src=\"http") || linha.contains("href=\"http") {
                panic!("a Platform Console referencia um recurso externo: {linha}");
            }
        }
    }

    #[test]
    fn o_javascript_escapa_o_que_vem_da_api() {
        // O nome de uma fonte vem de dados carregados pelo utilizador.
        assert!(PLATFORM_JS.contains("function esc("));
    }

    #[test]
    fn sem_motor_nao_ha_um_unico_numero() {
        // §33. O modo de falha que isto impede: uma home que, sem conseguir ler
        // o log, escreve `0 events / 0 datasets / VERIFIED` e passa por saudável.
        let s = PlatformSnapshot::default();
        assert_eq!(s.integrity, IntegrityState::Unavailable);
        assert!(s.last_lsn.is_none());
        assert!(s.memtable_pending.is_none());
        assert!(s.storage.raw_bytes.is_none());
        assert!(s.indexes.is_empty());
        assert!(s.sources.is_empty());

        let j = serde_json::to_value(&s).unwrap();
        assert!(j["last_lsn"].is_null());
        assert_eq!(j["integrity"], "UNAVAILABLE");
    }

    #[test]
    fn os_estados_vao_para_a_rede_em_maiusculas() {
        // A UI compara strings; se a serialização mudar de forma, o painel
        // deixa de reconhecer os estados e pinta tudo de cinzento em silêncio.
        for (estado, esperado) in [
            (IntegrityState::Verified, "VERIFIED"),
            (IntegrityState::Unverified, "UNVERIFIED"),
            (IntegrityState::Partial, "PARTIAL"),
            (IntegrityState::Broken, "BROKEN"),
            (IntegrityState::NotConfigured, "NOTCONFIGURED"),
            (IntegrityState::Unavailable, "UNAVAILABLE"),
        ] {
            assert_eq!(serde_json::to_value(estado).unwrap(), esperado);
        }
        for (estado, esperado) in [
            (ModuleState::Enabled, "ENABLED"),
            (ModuleState::Disabled, "DISABLED"),
            (ModuleState::Degraded, "DEGRADED"),
            (ModuleState::NotConfigured, "NOTCONFIGURED"),
            (ModuleState::NotBuilt, "NOTBUILT"),
        ] {
            assert_eq!(serde_json::to_value(estado).unwrap(), esperado);
        }
    }
}
