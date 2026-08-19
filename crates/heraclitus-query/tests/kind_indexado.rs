//! `n.tipo` / `n.kind` tem de ser servido pelo ÍNDICE e devolver exatamente o
//! mesmo que o varrimento.
//!
//! Contexto (2026-08-19). `is_builtin_field` classificava `kind`/`tipo` como
//! campo de envelope, logo incapaz de usar índice: cada `MATCH (n:Contrato)`
//! resolvia-se por varrimento do log com pós-filtro. Como `n.tipo` é o
//! predicado mais usado da camada de grafo, isso tinha duas consequências
//! medidas sobre o log real de 10 093 244 eventos:
//!
//! - achar os 13 891 nós de kind `Contrato` levava **7m27s**;
//! - o `edge-builder`, que precisa de 21 kinds, re-varria o log 21 vezes e
//!   **nunca terminava** — a construção do grafo parava na prática nos ~250 mil
//!   eventos (o `QUERY_SCAN_CAP`).
//!
//! A correção indexa o kind como pseudo-atributo `_kind` (índice de atributos
//! v4) e traduz `kind`/`tipo` → `_kind` no planner. O risco que isso introduz é
//! o rótulo: se o índice gravar `"Contrato"` e a query procurar por outra
//! coisa, a resposta é **zero linhas sobre dados que existem** — uma resposta
//! errada silenciosa, que num banco de auditoria é pior que um erro. Daí a
//! definição única `EventKind::label()` no core, e daí estes testes.

use heraclitus_core::{Episode, EventKind, FsyncPolicy};
use heraclitus_log::Log;
use heraclitus_query::backend::LogBackend;
use heraclitus_query::execute;
use std::sync::Arc;

fn ep(kind: &str, marca: &str) -> Episode {
    let mut e = Episode::new("ag", EventKind::Custom(kind.into()), marca.as_bytes().to_vec());
    e.attrs.insert("marca".into(), marca.into());
    e
}

fn linhas(v: &serde_json::Value) -> usize {
    v.as_array().map(|a| a.len()).unwrap_or(0)
}

/// O caso que estava partido: filtrar por kind tem de encontrar tudo.
#[test]
fn tipo_encontra_todos_os_nos_do_kind() {
    let dir = tempfile::tempdir().unwrap();
    let log = Arc::new(Log::open(dir.path(), 1 << 20, FsyncPolicy::Always).unwrap());

    for i in 0..40 {
        log.append(ep("Contrato", &format!("c{i}"))).unwrap();
    }
    for i in 0..25 {
        log.append(ep("Licitacao", &format!("l{i}"))).unwrap();
    }
    for i in 0..10 {
        log.append(ep("ItemContrato", &format!("i{i}"))).unwrap();
    }

    let be = LogBackend::new(log.clone());

    let v = execute(r#"MATCH (n) WHERE n.tipo = "Contrato" RETURN n"#, &be).unwrap();
    assert_eq!(linhas(&v), 40, "n.tipo tem de achar os 40 contratos");

    let v = execute(r#"MATCH (n) WHERE n.kind = "Licitacao" RETURN n"#, &be).unwrap();
    assert_eq!(linhas(&v), 25, "n.kind e alias de n.tipo");

    let v = execute(r#"MATCH (n) WHERE n.tipo = "ItemContrato" RETURN n"#, &be).unwrap();
    assert_eq!(linhas(&v), 10);

    // Um kind inexistente devolve vazio — e não o log inteiro.
    let v = execute(r#"MATCH (n) WHERE n.tipo = "NaoExiste" RETURN n"#, &be).unwrap();
    assert_eq!(linhas(&v), 0);
}

/// Os kinds do enum (não-`Custom`) usam o rótulo `{:?}`. Se o índice e a query
/// discordassem aqui, `Observation` devolveria zero.
#[test]
fn kinds_do_enum_tambem_sao_indexados() {
    let dir = tempfile::tempdir().unwrap();
    let log = Arc::new(Log::open(dir.path(), 1 << 20, FsyncPolicy::Always).unwrap());

    for _ in 0..7 {
        log.append(Episode::new("ag", EventKind::Observation, vec![]))
            .unwrap();
    }
    for _ in 0..3 {
        log.append(Episode::new("ag", EventKind::Action, vec![]))
            .unwrap();
    }

    let be = LogBackend::new(log);
    let v = execute(r#"MATCH (n) WHERE n.tipo = "Observation" RETURN n"#, &be).unwrap();
    assert_eq!(linhas(&v), 7, "EventKind::Observation -> rotulo Observation");
    let v = execute(r#"MATCH (n) WHERE n.tipo = "Action" RETURN n"#, &be).unwrap();
    assert_eq!(linhas(&v), 3);
}

/// O índice é um ATALHO, não uma fonte alternativa de verdade: combinar o kind
/// com outro predicado tem de continuar a dar a interseção correta. Se o
/// atalho devolvesse o conjunto errado, o pós-filtro esconderia o erro em
/// alguns casos e não noutros — por isso o teste cruza os dois.
#[test]
fn tipo_combinado_com_outro_atributo() {
    let dir = tempfile::tempdir().unwrap();
    let log = Arc::new(Log::open(dir.path(), 1 << 20, FsyncPolicy::Always).unwrap());

    for i in 0..30 {
        let mut e = ep("Contrato", &format!("c{i}"));
        e.attrs
            .insert("uf".into(), if i % 3 == 0 { "SP" } else { "RJ" }.into());
        log.append(e).unwrap();
    }
    for i in 0..12 {
        let mut e = ep("Licitacao", &format!("l{i}"));
        e.attrs.insert("uf".into(), "SP".into());
        log.append(e).unwrap();
    }

    let be = LogBackend::new(log);

    // 10 contratos com uf=SP (i divisível por 3 em 0..30).
    let v = execute(
        r#"MATCH (n) WHERE n.tipo = "Contrato" AND n.uf = "SP" RETURN n"#,
        &be,
    )
    .unwrap();
    assert_eq!(linhas(&v), 10, "intersecao kind x atributo");

    // O total de uf=SP inclui as licitações: 10 + 12.
    let v = execute(r#"MATCH (n) WHERE n.uf = "SP" RETURN n"#, &be).unwrap();
    assert_eq!(linhas(&v), 22, "o filtro por kind nao pode 'vazar' para ca");
}

/// Eventos appendados DEPOIS da primeira query têm de entrar no índice. Um
/// pseudo-atributo que só cobrisse o que existia no arranque daria respostas
/// que encolhem com o tempo relativo à verdade.
#[test]
fn kind_indexado_cobre_appends_posteriores() {
    let dir = tempfile::tempdir().unwrap();
    let log = Arc::new(Log::open(dir.path(), 1 << 20, FsyncPolicy::Always).unwrap());
    log.append(ep("Contrato", "c0")).unwrap();

    let be = LogBackend::new(log.clone());
    let v = execute(r#"MATCH (n) WHERE n.tipo = "Contrato" RETURN n"#, &be).unwrap();
    assert_eq!(linhas(&v), 1);

    for i in 1..15 {
        log.append(ep("Contrato", &format!("c{i}"))).unwrap();
    }
    let v = execute(r#"MATCH (n) WHERE n.tipo = "Contrato" RETURN n"#, &be).unwrap();
    assert_eq!(linhas(&v), 15, "appends posteriores tem de entrar no indice");
}
