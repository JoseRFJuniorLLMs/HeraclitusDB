//! SPEC-0074 §11 — um segredo nunca é persistido, venha por onde vier.
//!
//! # O defeito que estes testes travam
//!
//! O proxy MCP inseria os argumentos de um `tools/call` directamente em
//! `content.fields`, sem os passar pelo portão de privacidade. Ao mesmo tempo, o
//! preview da tela de aprovação — efémero, que um humano olha uma vez e fecha —
//! passava. O permanente ficava em claro e o efémero protegido, exactamente ao
//! contrário.
//!
//! Encontrado a correr o plano de `black-box-in-action.md` §19 contra um
//! upstream MCP real: um `tools/call` com `{"api_key": "sk-live-..."}` escrevia
//! o segredo no HRKL. Num log append-only isso não se apaga — corrige-se
//! acrescentando, e o segredo fica lá para sempre na versão anterior.
//!
//! # O que estes testes NÃO provam
//!
//! Que o sistema é impenetrável. Provam uma coisa estreita e verificável: que
//! este caminho de escrita concreto passa pelo portão. Um caminho NOVO que não
//! passe continua a ser possível — é por isso que a função tem nome
//! (`argumentos_para_persistir`) em vez de ser três linhas inline.

use heraclitus_agent::config::{
    AgentBlackBoxConfig, AgentGatewayConfig, ConsoleConfig, GatewayMode, OtlpConfig, PolicyConfig,
};
use heraclitus_agent::store::AnyLogEvidenceStore;
use heraclitus_agent_gateway::runtime::AgentRuntime;
use heraclitus_agent_gateway::{gateway, GatewayState, UpstreamClient};
use heraclitus_core::{FsyncPolicy, StorageFormat};
use heraclitus_log::AnyLog;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

const POLICY: &str = r#"
version: "agent-policy-v1"
id: "privacidade"
revision: "v1"

defaults:
  decision: deny

rules:
  - id: tudo
    match:
      tool: guardar_nota
    decision: allow
"#;

type Hits = Arc<AtomicUsize>;

/// Um upstream MCP mínimo que responde a tudo com sucesso.
async fn upstream(hits: Hits) -> String {
    use axum::routing::post;
    use axum::{Json, Router};

    let app = Router::new().fallback(post(move |corpo: Json<serde_json::Value>| {
        let hits = hits.clone();
        async move {
            hits.fetch_add(1, Ordering::SeqCst);
            let id = corpo.0.get("id").cloned().unwrap_or(serde_json::Value::Null);
            Json(serde_json::json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": { "content": [{ "type": "text", "text": "ok" }], "isError": false }
            }))
        }
    }));
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", l.local_addr().unwrap());
    tokio::spawn(async move {
        let _ = axum::serve(l, app).await;
    });
    url
}

struct Fixo {
    _dir: tempfile::TempDir,
    runtime: Arc<AgentRuntime>,
    gateway_url: String,
}

async fn arrancar(modo: &str) -> Fixo {
    let dir = tempfile::tempdir().unwrap();
    let politica = dir.path().join("policy.yaml");
    std::fs::write(&politica, POLICY).unwrap();

    let config = AgentBlackBoxConfig {
        enabled: true,
        capture_mode: modo.to_string(),
        tenant_id: "acme".into(),
        otlp: OtlpConfig {
            http_addr: String::new(),
            grpc_addr: String::new(),
            require_auth: false,
        },
        console: ConsoleConfig {
            enabled: false,
            addr: String::new(),
            basic_auth: String::new(),
        },
        ..Default::default()
    };
    let upstream_url = upstream(Arc::new(AtomicUsize::new(0))).await;
    let gw = AgentGatewayConfig {
        enabled: true,
        mode: GatewayMode::Shadow,
        listen_addr: "127.0.0.1:0".into(),
        upstream_url: upstream_url.clone(),
        policy: PolicyConfig {
            active: politica.display().to_string(),
            default_decision: "deny".into(),
        },
        bypass_protection_configured: true,
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
        AgentRuntime::new(config, gw, Arc::new(AnyLogEvidenceStore::new(log)))
            .with_bundles_dir(dir.path().join("bundles")),
    );
    runtime.load_policy().unwrap();

    let cliente = Arc::new(UpstreamClient::new(&upstream_url, 10, 1 << 20).unwrap());
    let state = Arc::new(GatewayState {
        runtime: runtime.clone(),
        upstream: Some(cliente),
    });
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let gateway_url = format!("http://{}", l.local_addr().unwrap());
    let app = gateway::router(state);
    tokio::spawn(async move {
        let _ = axum::serve(l, app).await;
    });

    Fixo {
        _dir: dir,
        runtime,
        gateway_url,
    }
}

async fn tool_call(f: &Fixo, argumentos: serde_json::Value) {
    use http_body_util::{BodyExt, Full};
    use hyper_util::client::legacy::Client;
    use hyper_util::rt::TokioExecutor;

    let corpo = serde_json::json!({
        "jsonrpc": "2.0",
        "id": "tc-1",
        "method": "tools/call",
        "params": { "name": "guardar_nota", "arguments": argumentos }
    })
    .to_string();

    let client: Client<
        hyper_util::client::legacy::connect::HttpConnector,
        Full<hyper::body::Bytes>,
    > = Client::builder(TokioExecutor::new()).build_http();
    let req = hyper::Request::builder()
        .method("POST")
        .uri(format!("{}/mcp", f.gateway_url))
        .header("content-type", "application/json")
        .header("x-heraclitus-agent", "claude-code")
        .header("x-heraclitus-user", "jose")
        .header("authorization", "Bearer sk-ant-CABECALHO-SECRETO")
        .body(Full::new(hyper::body::Bytes::from(corpo)))
        .unwrap();
    let resp = client.request(req).await.unwrap();
    let _ = resp.into_body().collect().await.unwrap();
    let _ = f.runtime.flush();
}

/// Tudo o que ficou GRAVADO, como texto. É o que uma perícia veria.
fn evidencia_em_texto(f: &Fixo) -> String {
    f.runtime
        .scan()
        .unwrap()
        .iter()
        .map(|r| serde_json::to_string(&r.evidence).unwrap())
        .collect::<Vec<_>>()
        .join("\n")
}

#[tokio::test]
async fn um_segredo_nos_argumentos_nao_chega_ao_log() {
    let f = arrancar("metadata_only").await;
    tool_call(
        &f,
        serde_json::json!({
            "api_key": "sk-live-ESTE-VALOR-NAO-PODE-SER-PERSISTIDO",
            "password": "debian23",
            "nota": "um campo normal, este pode ficar"
        }),
    )
    .await;

    let gravado = evidencia_em_texto(&f);
    assert!(
        !gravado.contains("sk-live-ESTE-VALOR-NAO-PODE-SER-PERSISTIDO"),
        "a chave de API foi persistida:\n{gravado}"
    );
    assert!(
        !gravado.contains("debian23"),
        "a senha foi persistida:\n{gravado}"
    );
    // O cabeçalho Authorization já era removido antes; o teste guarda-o para
    // que uma correcção futura não o desfaça ao mexer no mesmo sítio.
    assert!(
        !gravado.contains("sk-ant-CABECALHO-SECRETO"),
        "o cabeçalho Authorization foi persistido:\n{gravado}"
    );

    // E o que NÃO é segredo continua a aparecer. Uma redacção que apaga tudo
    // é tão inútil como uma que não apaga nada: a evidência tem de continuar a
    // dizer o que a ferramenta fez.
    assert!(
        gravado.contains("um campo normal"),
        "a redacção comeu um campo inócuo:\n{gravado}"
    );
    // O NOME do campo é inócuo e fica, com o valor substituído — é isso que diz
    // a uma auditoria "aqui passou um segredo" sem o guardar.
    assert!(gravado.contains("api_key"), "{gravado}");
}

#[tokio::test]
async fn nem_sequer_em_full_explicit() {
    // §11 é uma invariante, não um default: `full_explicit` é o modo em que o
    // operador pediu explicitamente para guardar corpos, e MESMO assim uma
    // credencial não passa. Se algum dia passar, é porque alguém confundiu
    // "o operador aceitou o risco de guardar conteúdo" com "o operador aceitou
    // guardar as chaves de outra pessoa".
    let f = arrancar("full_explicit").await;
    tool_call(
        &f,
        serde_json::json!({ "api_key": "sk-live-NEM-ASSIM", "texto": "conteúdo do utilizador" }),
    )
    .await;

    let gravado = evidencia_em_texto(&f);
    assert!(
        !gravado.contains("sk-live-NEM-ASSIM"),
        "full_explicit persistiu uma credencial:\n{gravado}"
    );
}

#[tokio::test]
async fn a_redaccao_nao_muda_aquilo_a_que_a_aprovacao_se_vincula() {
    // O modo de falha que isto apanha: alguém "corrige" a privacidade redigindo
    // os argumentos ANTES de calcular o hash canónico. A partir daí, aprovar
    // uma acção e executá-la passam a comparar hashes de coisas diferentes — e
    // ou nada executa, ou (muito pior) o binding deixa de distinguir argumentos
    // que deviam ser distintos, porque ambos redigem para `[REDACTED]`.
    let f = arrancar("metadata_only").await;
    tool_call(&f, serde_json::json!({ "api_key": "sk-live-AAA", "x": "1" })).await;
    let primeiro = evidencia_em_texto(&f);

    let g = arrancar("metadata_only").await;
    tool_call(&g, serde_json::json!({ "api_key": "sk-live-BBB", "x": "1" })).await;
    let segundo = evidencia_em_texto(&g);

    let hash = |s: &str| -> String {
        let v: serde_json::Value = s
            .lines()
            .map(|l| serde_json::from_str::<serde_json::Value>(l).unwrap())
            .find(|v| v["kind"] == "ToolRequested")
            .expect("não há ToolRequested");
        v["content"]["canonical_content_hash"]
            .as_str()
            .unwrap()
            .to_string()
    };

    assert_ne!(
        hash(&primeiro),
        hash(&segundo),
        "dois argumentos DIFERENTES deram o mesmo hash canónico: a redacção \
         entrou no caminho do binding e destruiu a distinção"
    );
    // E nenhum dos dois segredos ficou gravado, apesar de os distinguirmos.
    assert!(!primeiro.contains("sk-live-AAA"), "{primeiro}");
    assert!(!segundo.contains("sk-live-BBB"), "{segundo}");
}
