//! SPEC-0076 §28 — a credencial partilhada da Consola.
//!
//! O que estes testes fixam:
//!
//! ```text
//! sem credencial      o shell e a API respondem 401 COM WWW-Authenticate
//! com a credencial    200
//! senha errada        401
//! modo `basic`        auth_identifies_people == false
//! OTLP require_auth   fecha 4318 com a MESMA credencial
//! ```
//!
//! O quarto é o mais importante. Uma senha partilhada fecha a porta e não diz
//! quem entrou: os papéis `approver` e `policy_admin`, que a 0076 separa de
//! propósito, passam a ser a mesma pessoa. O produto tem de o declarar — um
//! cadeado que mente sobre o que prova é pior do que não ter cadeado, porque
//! alguém vai assinar um relatório a dizer que a aprovação foi de fulano.

use heraclitus_agent::config::{
    AgentBlackBoxConfig, AgentGatewayConfig, ConsoleConfig, OtlpConfig,
};
use heraclitus_agent::store::AnyLogEvidenceStore;
use heraclitus_agent_gateway::runtime::AgentRuntime;
use heraclitus_agent_gateway::{api, ingest};
use heraclitus_core::{FsyncPolicy, StorageFormat};
use heraclitus_log::AnyLog;
use std::sync::Arc;

const UTILIZADOR: &str = "admin";
const SENHA: &str = "debian23";

struct Fixo {
    _dir: tempfile::TempDir,
    api_url: String,
    otlp_url: String,
}

/// `basic_auth` vazio = consola aberta; não vazio = consola fechada.
async fn arrancar(basic_auth: &str, otlp_require_auth: bool) -> Fixo {
    let dir = tempfile::tempdir().unwrap();
    let config = AgentBlackBoxConfig {
        enabled: true,
        tenant_id: "acme".into(),
        otlp: OtlpConfig {
            http_addr: String::new(),
            grpc_addr: String::new(),
            require_auth: otlp_require_auth,
        },
        console: ConsoleConfig {
            enabled: false,
            addr: String::new(),
            basic_auth: basic_auth.to_string(),
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
    let mut runtime = AgentRuntime::new(
        config,
        AgentGatewayConfig::default(),
        Arc::new(AnyLogEvidenceStore::new(log)),
    )
    .with_bundles_dir(dir.path().join("bundles"));
    runtime.load_console_credential().unwrap();
    let runtime = Arc::new(runtime);
    runtime.load_policy().unwrap();

    let l1 = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let api_url = format!("http://{}", l1.local_addr().unwrap());
    let app = api::router(runtime.clone());
    tokio::spawn(async move {
        let _ = axum::serve(l1, app).await;
    });

    let l2 = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let otlp_url = format!("http://{}", l2.local_addr().unwrap());
    let otlp_app = ingest::router(runtime.clone());
    tokio::spawn(async move {
        let _ = axum::serve(l2, otlp_app).await;
    });

    Fixo {
        _dir: dir,
        api_url,
        otlp_url,
    }
}

/// Devolve `(status, WWW-Authenticate, corpo)`.
async fn pedir(
    metodo: &str,
    url: &str,
    auth: Option<&str>,
    corpo: &str,
    content_type: &str,
) -> (u16, Option<String>, String) {
    use http_body_util::{BodyExt, Full};
    use hyper_util::client::legacy::Client;
    use hyper_util::rt::TokioExecutor;

    let client: Client<
        hyper_util::client::legacy::connect::HttpConnector,
        Full<hyper::body::Bytes>,
    > = Client::builder(TokioExecutor::new()).build_http();
    let mut req = hyper::Request::builder()
        .method(metodo)
        .uri(url)
        .header("content-type", content_type);
    if let Some(a) = auth {
        req = req.header("authorization", a);
    }
    let body = hyper::body::Bytes::copy_from_slice(corpo.as_bytes());
    let resp = client
        .request(req.body(Full::new(body)).unwrap())
        .await
        .unwrap();
    let status = resp.status().as_u16();
    let desafio = resp
        .headers()
        .get("www-authenticate")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    (status, desafio, String::from_utf8_lossy(&bytes).to_string())
}

/// Base64 RFC 4648 com padding.
///
/// Escrito à mão de propósito: o teste tem de construir o cabeçalho pelo
/// caminho de FORA, como um browser o construiria. Se reutilizasse o `b64` do
/// `auth.rs`, um erro nesse codificador cancelava-se a si próprio e o teste
/// passaria com os dois lados errados da mesma maneira.
fn basic(utilizador: &str, senha: &str) -> String {
    const AB: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let input = format!("{utilizador}:{senha}").into_bytes();
    let mut out = String::from("Basic ");
    for chunk in input.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        out.push(AB[(n >> 18) as usize & 63] as char);
        out.push(AB[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            AB[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            AB[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

#[test]
fn o_codificador_do_teste_esta_certo() {
    // Um vector conhecido, para que o teste não valide a si próprio.
    assert_eq!(basic("admin", "debian23"), "Basic YWRtaW46ZGViaWFuMjM=");
    assert_eq!(basic("a", "b"), "Basic YTpi");
    assert_eq!(basic("ab", "c"), "Basic YWI6Yw==");
}

#[tokio::test]
async fn sem_credencial_o_shell_pede_utilizador_e_senha() {
    let f = arrancar(&format!("{UTILIZADOR}:{SENHA}"), false).await;

    // O `WWW-Authenticate` NÃO é decorativo: é ele que faz o browser abrir a
    // caixa. Sem ele o utilizador vê uma página de erro e não tem por onde
    // autenticar-se — o cadeado ficaria fechado também para quem sabe a senha.
    let (status, desafio, _) = pedir("GET", &f.api_url, None, "", "text/html").await;
    assert_eq!(status, 401, "o shell da consola tem de recusar");
    let d = desafio.expect("401 sem WWW-Authenticate não abre a caixa do browser");
    assert!(d.starts_with("Basic realm="), "{d}");

    // E a API também, senão bastava ler /api/v1/... directamente.
    let url = format!("{}/api/v1/agent/status", f.api_url);
    let (status, desafio, _) = pedir("GET", &url, None, "", "application/json").await;
    assert_eq!(status, 401);
    assert!(desafio.is_some());
}

#[tokio::test]
async fn com_a_credencial_certa_entra() {
    let f = arrancar(&format!("{UTILIZADOR}:{SENHA}"), false).await;
    let auth = basic(UTILIZADOR, SENHA);

    // A raiz é a Platform Console (SPEC-0077 §30); a Agent Console está sob
    // `/agent`. As duas passam pelo mesmo portão.
    let (status, _, corpo) = pedir("GET", &f.api_url, Some(&auth), "", "text/html").await;
    assert_eq!(status, 200);
    assert!(corpo.contains("HeraclitusDB"), "{corpo}");

    let url_agente = format!("{}/agent", f.api_url);
    let (status, _, corpo) = pedir("GET", &url_agente, Some(&auth), "", "text/html").await;
    assert_eq!(status, 200);
    assert!(corpo.contains("Agent Evidence"), "{corpo}");

    let url = format!("{}/api/v1/agent/status", f.api_url);
    let (status, _, corpo) = pedir("GET", &url, Some(&auth), "", "application/json").await;
    assert_eq!(status, 200);
    let j: serde_json::Value = serde_json::from_str(&corpo).unwrap();
    assert_eq!(j["auth"], "basic");
    assert_eq!(j["principal"]["subject"], UTILIZADOR);
}

#[tokio::test]
async fn a_senha_errada_nao_entra() {
    let f = arrancar(&format!("{UTILIZADOR}:{SENHA}"), false).await;
    for mau in [
        basic(UTILIZADOR, "debian24"),
        basic("root", SENHA),
        // Um prefixo da senha certa. Se a comparação saísse no primeiro byte
        // diferente, o tempo de resposta diria quantos bytes acertaram.
        basic(UTILIZADOR, "debian2"),
        "Basic".to_string(),
        "Bearer debian23".to_string(),
    ] {
        let (status, _, _) = pedir("GET", &f.api_url, Some(&mau), "", "text/html").await;
        assert_eq!(status, 401, "entrou com `{mau}`");
    }
}

#[tokio::test]
async fn uma_senha_partilhada_nao_identifica_pessoas() {
    // §28: `approver` e `policy_admin` são papéis SEPARADOS de propósito —
    // quem aprova não deve ser quem escreve a política. Com uma senha
    // partilhada os dois são o mesmo sujeito no log, e nenhuma aprovação pode
    // ser atribuída a uma pessoa. O produto declara-o; não o esconde atrás de
    // um cadeado verde.
    let f = arrancar(&format!("{UTILIZADOR}:{SENHA}"), false).await;
    let url = format!("{}/api/v1/agent/status", f.api_url);
    let (status, _, corpo) = pedir(
        "GET",
        &url,
        Some(&basic(UTILIZADOR, SENHA)),
        "",
        "application/json",
    )
    .await;
    assert_eq!(status, 200);
    let j: serde_json::Value = serde_json::from_str(&corpo).unwrap();
    assert_eq!(
        j["auth_identifies_people"], false,
        "uma senha partilhada nunca pode declarar que identifica pessoas"
    );

    // E o contrário também: sem credencial nenhuma, o modo é `dev_local` e a
    // Consola põe o banner de desenvolvimento.
    let aberta = arrancar("", false).await;
    let url = format!("{}/api/v1/agent/status", aberta.api_url);
    let (status, _, corpo) = pedir("GET", &url, None, "", "application/json").await;
    assert_eq!(status, 200);
    let j: serde_json::Value = serde_json::from_str(&corpo).unwrap();
    assert_eq!(j["auth"], "dev_local");
    assert_eq!(j["auth_identifies_people"], false);
}

#[tokio::test]
async fn credencial_malformada_e_erro_de_arranque() {
    // Aceitar `admin` sem `:` e não proteger nada deixaria o operador a olhar
    // para uma consola aberta convencido de que a tinha fechado. Falhar no
    // arranque é o único modo de falha honesto.
    for mau in ["admin", "admin:", ":debian23", ":"] {
        let dir = tempfile::tempdir().unwrap();
        let config = AgentBlackBoxConfig {
            console: ConsoleConfig {
                basic_auth: mau.to_string(),
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
        let mut runtime = AgentRuntime::new(
            config,
            AgentGatewayConfig::default(),
            Arc::new(AnyLogEvidenceStore::new(log)),
        );
        assert!(
            runtime.load_console_credential().is_err(),
            "`{mau}` foi aceite como credencial"
        );
    }
}

#[tokio::test]
async fn a_porta_otlp_fecha_com_a_mesma_credencial() {
    // Fechar a Consola e deixar 4318 aberta protege a LEITURA e não a ESCRITA:
    // quem alcançar a porta injecta evidência num log append-only que ninguém
    // apaga depois.
    let f = arrancar(&format!("{UTILIZADOR}:{SENHA}"), true).await;
    let url = format!("{}/v1/traces", f.otlp_url);

    let (status, desafio, corpo) = pedir("POST", &url, None, "{}", "application/json").await;
    assert_eq!(status, 401, "{corpo}");
    assert!(desafio.is_some());

    let (status, _, corpo) = pedir(
        "POST",
        &url,
        Some(&basic(UTILIZADOR, SENHA)),
        r#"{"resourceSpans":[]}"#,
        "application/json",
    )
    .await;
    assert_eq!(status, 200, "{corpo}");
}

#[tokio::test]
async fn por_omissao_a_porta_otlp_fica_aberta() {
    // Ligar autenticação na ingestão sem aviso partiria toda a instrumentação
    // já instalada: os exporters do OpenTelemetry não levam credencial por
    // omissão, e o operador veria spans a desaparecer sem erro do lado dele.
    // O interruptor existe e é explícito; o default não muda o que já corria.
    let f = arrancar(&format!("{UTILIZADOR}:{SENHA}"), false).await;
    let url = format!("{}/v1/traces", f.otlp_url);
    let (status, _, corpo) = pedir(
        "POST",
        &url,
        None,
        r#"{"resourceSpans":[]}"#,
        "application/json",
    )
    .await;
    assert_eq!(status, 200, "{corpo}");
}
