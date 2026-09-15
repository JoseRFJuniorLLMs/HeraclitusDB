//! SPEC-0077 §39/§48 — os testes obrigatórios de routing e de identidade.
//!
//! ```text
//! GET /                 => Platform Console, e o título é HeraclitusDB
//! GET /agent            => Agent Console (módulo ligado)
//! GET /agent            => 404 honesto (módulo desligado)
//! GET /api/v1/agent/*   => preservada
//! módulo desligado      => `/` continua a funcionar
//! sem motor             => nenhum número, nem um
//! ```
//!
//! O primeiro é o que impede a regressão que a 0077 existe para corrigir. Não é
//! um teste de estética: uma home que se apresenta como monitor de agentes de
//! IA é um produto diferente daquele que este repositório contém, e a diferença
//! só se nota quando alguém de fora abre a página — normalmente tarde demais.

use heraclitus_agent::config::{
    AgentBlackBoxConfig, AgentGatewayConfig, ConsoleConfig, OtlpConfig,
};
use heraclitus_agent::store::AnyLogEvidenceStore;
use heraclitus_agent_gateway::api;
use heraclitus_agent_gateway::runtime::AgentRuntime;
use heraclitus_core::{FsyncPolicy, StorageFormat};
use heraclitus_log::AnyLog;
use std::sync::Arc;

struct Fixo {
    _dir: tempfile::TempDir,
    url: String,
}

async fn arrancar(modulo_ligado: bool) -> Fixo {
    let dir = tempfile::tempdir().unwrap();
    let config = AgentBlackBoxConfig {
        enabled: modulo_ligado,
        tenant_id: "acme".into(),
        otlp: OtlpConfig {
            http_addr: String::new(),
            grpc_addr: String::new(),
            ..Default::default()
        },
        console: ConsoleConfig {
            enabled: false,
            addr: String::new(),
            ..Default::default()
        },
        ..Default::default()
    };
    let log = Arc::new(
        AnyLog::open(
            StorageFormat::V6,
            dir.path().join("log"),
            64 * 1024,
            FsyncPolicy::Always,
        )
        .unwrap(),
    );
    let runtime = Arc::new(
        AgentRuntime::new(
            config,
            AgentGatewayConfig::default(),
            Arc::new(AnyLogEvidenceStore::new(log)),
        )
        .with_bundles_dir(dir.path().join("bundles")),
    );
    runtime.load_policy().unwrap();

    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", l.local_addr().unwrap());
    let app = api::router(runtime);
    tokio::spawn(async move {
        let _ = axum::serve(l, app).await;
    });
    Fixo { _dir: dir, url }
}

async fn get(url: &str) -> (u16, String) {
    use http_body_util::{BodyExt, Full};
    use hyper_util::client::legacy::Client;
    use hyper_util::rt::TokioExecutor;

    let client: Client<
        hyper_util::client::legacy::connect::HttpConnector,
        Full<hyper::body::Bytes>,
    > = Client::builder(TokioExecutor::new()).build_http();
    let resp = client
        .request(
            hyper::Request::builder()
                .method("GET")
                .uri(url)
                .body(Full::new(hyper::body::Bytes::new()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status().as_u16();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    (status, String::from_utf8_lossy(&bytes).to_string())
}

/// O `<title>` da página, que é o que um humano vê na aba e um motor de busca
/// indexa.
fn titulo(html: &str) -> String {
    html.split("<title>")
        .nth(1)
        .and_then(|s| s.split("</title>").next())
        .unwrap_or("")
        .to_string()
}

#[tokio::test]
async fn a_raiz_e_do_heraclitusdb() {
    // §39, o teste nomeado na SPEC.
    let f = arrancar(true).await;
    let (status, html) = get(&f.url).await;
    assert_eq!(status, 200);

    assert!(
        html.contains("HeraclitusDB"),
        "a raiz não se identifica como HeraclitusDB"
    );
    let t = titulo(&html);
    assert_eq!(t, "HeraclitusDB", "o título da raiz é `{t}`");

    // E o mais importante: a raiz não pode apresentar o produto INTEIRO como
    // sendo o módulo de agentes. A palavra pode aparecer no corpo (há um cartão
    // de módulo com esse nome); o que não pode é ser a identidade da página.
    let cabecalho = html.split("<main").next().unwrap();
    assert!(
        !cabecalho.contains("Agent Black Box"),
        "a identidade da home voltou a ser o módulo de agentes"
    );
}

#[tokio::test]
async fn a_agent_console_vive_em_agent() {
    let f = arrancar(true).await;
    for caminho in ["/agent", "/agent/", "/agent/runs/abc"] {
        let (status, html) = get(&format!("{}{caminho}", f.url)).await;
        assert_eq!(status, 200, "{caminho}");
        assert!(html.contains("Agent Evidence"), "{caminho}");
        // §19/§44 — dentro do módulo, o produto continua a ser nomeado.
        assert!(html.contains("HeraclitusDB"), "{caminho}");
    }
}

#[tokio::test]
async fn com_o_modulo_desligado_a_plataforma_continua_a_servir() {
    // §48 "Module disabled → platform still boots → platform console works".
    let f = arrancar(false).await;

    let (status, html) = get(&f.url).await;
    assert_eq!(
        status, 200,
        "a Platform Console caiu com o módulo desligado"
    );
    assert_eq!(titulo(&html), "HeraclitusDB");

    // E `/agent` não finge que existe.
    let (status, html) = get(&format!("{}/agent", f.url)).await;
    assert_eq!(status, 404);
    assert!(
        html.contains("enabled = true"),
        "um 404 mudo manda o operador procurar no changelog uma funcionalidade \
         que ele tem instalada: {html}"
    );
}

#[tokio::test]
async fn a_api_de_agentes_nao_foi_renomeada() {
    // §30 — "Não renomear API apenas por estética". Quem integrou contra
    // `/api/v1/agent/status` não pode descobrir numa correcção de branding que
    // o caminho mudou.
    let f = arrancar(true).await;
    let (status, corpo) = get(&format!("{}/api/v1/agent/status", f.url)).await;
    assert_eq!(status, 200);
    let j: serde_json::Value = serde_json::from_str(&corpo).unwrap();
    assert_eq!(j["product"], "Heraclitus Agent Black Box");
    assert!(j["engine"].as_str().unwrap().starts_with("HeraclitusDB"));
}

#[tokio::test]
async fn sem_motor_a_home_nao_afirma_um_unico_numero() {
    // §33 — a regra absoluta. Este harness não tem `Engine` por trás, portanto
    // o `PlatformSource` é `None`: tudo o que a home puder dizer sobre o log
    // tem de vir `null`.
    let f = arrancar(true).await;
    let (status, corpo) = get(&format!("{}/api/v1/platform/summary", f.url)).await;
    assert_eq!(status, 200);
    let j: serde_json::Value = serde_json::from_str(&corpo).unwrap();

    assert_eq!(j["product"], "HeraclitusDB");
    assert_eq!(j["integrity"], "UNAVAILABLE");
    for campo in [
        "last_lsn",
        "storage_format",
        "memtable_pending",
        "oldest_event_ms",
        "newest_event_ms",
    ] {
        assert!(
            j[campo].is_null(),
            "`{campo}` devia ser null, é {}",
            j[campo]
        );
    }
    assert!(j["storage"]["raw_bytes"].is_null());
    assert_eq!(j["indexes"].as_array().unwrap().len(), 0);
    assert_eq!(j["sources"].as_array().unwrap().len(), 0);

    // O único módulo sobre o qual um gateway sem motor pode falar é o seu.
    let mods = j["modules"].as_array().unwrap();
    assert_eq!(mods.len(), 1);
    assert_eq!(mods[0]["id"], "agent");
    assert_eq!(mods[0]["state"], "ENABLED");
}

#[tokio::test]
async fn os_assets_das_duas_consolas_nao_colidem() {
    // As duas superfícies têm folhas e scripts próprios. Se `/platform.js`
    // servisse o JS da Agent Console, a home carregaria e ficaria em branco —
    // uma falha silenciosa, sem erro no servidor.
    let f = arrancar(true).await;

    let (status, css) = get(&format!("{}/platform.css", f.url)).await;
    assert_eq!(status, 200);
    assert!(css.contains("Platform Console"));

    let (status, js) = get(&format!("{}/platform.js", f.url)).await;
    assert_eq!(status, 200);
    assert!(js.contains("/api/v1/platform/summary"));

    let (status, js) = get(&format!("{}/console.js", f.url)).await;
    assert_eq!(status, 200);
    assert!(js.contains("/api/v1/agent/status"));
}
