//! SPEC-0076 §15 — a Consola, embutida no binário.
//!
//! > one container / one volume / **no Node runtime in production**
//!
//! Os três ficheiros de `ui/agent-console/` entram no binário por
//! [`include_str!`]. Não há passo de build, não há bundler, não há
//! `node_modules` numa imagem de produção e não há um segundo processo para
//! servir estáticos.
//!
//! O custo é real e vale a pena dizê-lo: a Consola é JavaScript simples, sem
//! framework. Para cinco telas (§4) isso é uma vantagem; para uma aplicação
//! grande não seria. Se a superfície crescer ao ponto de precisar de um
//! framework, o sítio certo para o discutir é o momento em que §4 deixar de
//! chegar — não antes.

use crate::runtime::AgentRuntime;
use axum::extract::State;
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use std::sync::Arc;

const INDEX_HTML: &str = include_str!("../../../ui/agent-console/index.html");
const CONSOLE_CSS: &str = include_str!("../../../ui/agent-console/console.css");
const CONSOLE_JS: &str = include_str!("../../../ui/agent-console/console.js");

/// Cabeçalhos de segurança da Consola.
///
/// A CSP é restritiva de propósito: a Consola não carrega nada de fora, não
/// executa `eval` e não embute scripts inline. Uma página que mostra evidência
/// forense não deve poder ser transformada num veículo de exfiltração por um
/// nome de ferramenta com HTML lá dentro.
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

/// O portao do shell da Consola.
///
/// Porque e que o gate esta AQUI e nao so na API: se o HTML carregasse sem
/// credencial e so o `fetch` levasse 401, o browser nao abriria a caixa de
/// utilizador/senha de forma fiavel — o utilizador veria uma consola vazia sem
/// perceber porque. Pedindo no proprio documento, o browser pergunta primeiro e
/// passa a mandar o `Authorization` em todos os pedidos da mesma origem.
///
/// Nao ha aqui nenhuma decisao de papeis: quem sabe a senha ve o shell. O que
/// o shell mostra continua a ser decidido pela API, pedido a pedido.
#[allow(clippy::result_large_err)]
pub(crate) fn gate(runtime: &Arc<AgentRuntime>, headers: &HeaderMap) -> Result<(), Response> {
    let Some(credencial) = runtime.console_credential() else {
        return Ok(());
    };
    let cabecalho = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok());
    if credencial.matches(cabecalho) {
        return Ok(());
    }
    Err((
        StatusCode::UNAUTHORIZED,
        [(header::WWW_AUTHENTICATE, crate::auth::BASIC_REALM)],
        security_headers(),
        "esta consola exige utilizador e senha",
    )
        .into_response())
}

/// O que `/agent` responde quando o módulo está desligado.
///
/// SPEC-0077 §18/§38 — não é um 404 mudo. Um 404 mudo faz o operador pensar
/// que a rota não existe nesta versão, e mandá-lo procurar no changelog uma
/// funcionalidade que ele tem instalada e apenas não ligou. Dizer qual é o
/// interruptor custa duas linhas e poupa-lhe a tarde.
const MODULO_DESLIGADO: &str = concat!(
    "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\">",
    "<title>Agent Evidence — disabled</title>",
    "<link rel=\"stylesheet\" href=\"/platform.css\"></head><body>",
    "<main><h1>Agent Evidence &amp; Control</h1>",
    "<p class=\"muted\">This module is not enabled on this server.</p>",
    "<div class=\"notice\">Enable it with <span class=\"mono\">[agent_black_box] enabled = true</span>",
    " in heraclitus.toml, or <span class=\"mono\">HERACLITUS_AGENT_ENABLED=1</span>, then restart.</div>",
    "<p class=\"gap-md\"><a href=\"/\">&larr; HeraclitusDB</a></p>",
    "</main></body></html>",
);

pub async fn index(State(runtime): State<Arc<AgentRuntime>>, headers: HeaderMap) -> Response {
    if let Err(r) = gate(&runtime, &headers) {
        return r;
    }
    if !runtime.config.enabled {
        return (
            StatusCode::NOT_FOUND,
            [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
            security_headers(),
            MODULO_DESLIGADO,
        )
            .into_response();
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
    if let Err(r) = gate(&runtime, &headers) {
        return r;
    }
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/css; charset=utf-8")],
        security_headers(),
        CONSOLE_CSS,
    )
        .into_response()
}

pub async fn js(State(runtime): State<Arc<AgentRuntime>>, headers: HeaderMap) -> Response {
    if let Err(r) = gate(&runtime, &headers) {
        return r;
    }
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/javascript; charset=utf-8")],
        security_headers(),
        CONSOLE_JS,
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn os_assets_estao_mesmo_embutidos() {
        assert!(INDEX_HTML.contains("Agent Evidence"));
        // SPEC-0077 §19/§44 — a Consola do módulo diz a que produto pertence.
        // Sem isto, um screenshot desta tela volta a ser indistinguível de
        // "o produto chama-se Agent Black Box".
        assert!(INDEX_HTML.contains("HeraclitusDB"));
        assert!(
            INDEX_HTML.contains("href=\"/\""),
            "falta o caminho de volta a /"
        );
        assert!(CONSOLE_CSS.contains("--verified"));
        assert!(CONSOLE_JS.contains("/api/v1/agent/status"));
    }

    #[test]
    fn a_consola_nao_carrega_nada_de_fora() {
        // §15: sem CDN, sem fontes remotas, sem script de terceiros. Se isto
        // falhar, a CSP `default-src 'none'` também falharia — mas em runtime,
        // no computador do utilizador, em vez de aqui.
        for linha in INDEX_HTML.lines() {
            if linha.contains("src=\"http") || linha.contains("href=\"http") {
                panic!("a Consola referencia um recurso externo: {linha}");
            }
        }
    }

    #[test]
    fn a_csp_nao_permite_inline_nem_eval() {
        let csp = security_headers()[0].1;
        assert!(!csp.contains("unsafe-inline"), "{csp}");
        assert!(!csp.contains("unsafe-eval"), "{csp}");
        assert!(csp.contains("default-src 'none'"), "{csp}");
        assert!(csp.contains("frame-ancestors 'none'"), "{csp}");
    }

    #[test]
    fn o_javascript_escapa_o_que_vem_da_api() {
        // Um nome de ferramenta é conteúdo escrito por terceiros.
        assert!(CONSOLE_JS.contains("function esc("));
        assert!(CONSOLE_JS.contains("replace(/</g, '&lt;')"));
    }
}
