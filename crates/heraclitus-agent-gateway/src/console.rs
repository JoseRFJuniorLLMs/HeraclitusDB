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

use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};

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

pub async fn index() -> Response {
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        security_headers(),
        INDEX_HTML,
    )
        .into_response()
}

pub async fn css() -> Response {
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/css; charset=utf-8")],
        security_headers(),
        CONSOLE_CSS,
    )
        .into_response()
}

pub async fn js() -> Response {
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
        assert!(INDEX_HTML.contains("Agent Black Box"));
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
