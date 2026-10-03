//! falta_fazer.md:101 (conferido em 2026-10-02): NEAREST/RECALL com AS OF
//! sobre-buscavam um múltiplo FIXO (k*4) e pós-filtravam por LSN. Quando mais
//! de 3/4 dos vizinhos mais próximos eram posteriores ao AS OF, a resposta
//! saía com menos de `k` linhas — ou nenhuma — sem aviso, embora existissem
//! candidatos válidos mais abaixo no ranking.
//!
//! Um `k` absurdo (`NEAREST(.., 4000000000)`) tem de ser aceite sem rebentar.
//! Nota honesta (revisão de 2026-10-03): este teste NÃO mede o tecto
//! `MAX_TOP_K` em si — com 65 pontos, devolver no máximo 65 também acontecia
//! sem tecto. Medi-lo exigiria um índice com mais de 10 000 pontos.

use heraclitus_core::{Episode, EventKind, FsyncPolicy, HeraclitusConfig, ProductPoint};
use heraclitus_server::engine::Engine;

fn com_embedding(x: f32, i: usize) -> Episode {
    let mut e = Episode::new(
        "ana",
        EventKind::Observation,
        format!("ponto {i}").into_bytes(),
    );
    e.embedding = Some(ProductPoint {
        hyp: vec![x, (i as f32) * 1e-4],
        sph: vec![],
        euc: vec![],
    });
    e
}

fn linhas(engine: &Engine, gql: &str) -> usize {
    heraclitus_query::execute(gql, engine)
        .unwrap()
        .as_array()
        .map(|a| a.len())
        .unwrap_or(0)
}

#[test]
fn nearest_as_of_devolve_k_linhas_mesmo_com_os_vizinhos_todos_depois_do_corte() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = HeraclitusConfig {
        data_dir: dir.path().to_path_buf(),
        fsync: FsyncPolicy::Always,
        ..HeraclitusConfig::default()
    };
    let engine = Engine::open(&cfg).unwrap();
    // LSN 0..5: longe do ponto de consulta. Depois, 60 eventos muito perto.
    for i in 0..5 {
        engine.append(com_embedding(-0.5, i)).unwrap();
    }
    let corte = engine.head();
    for i in 0..60 {
        engine.append(com_embedding(0.5, i)).unwrap();
    }

    // Sem AS OF: os 5 mais próximos são eventos novos.
    assert_eq!(linhas(&engine, "NEAREST([0.5, 0.0], 5)"), 5);
    // Com AS OF: só os 5 antigos são visíveis — os 20 primeiros candidatos
    // (k*4) são todos posteriores ao corte, e mesmo assim a resposta tem de
    // trazer os 5.
    let gql = format!("NEAREST([0.5, 0.0], 5) AS OF LSN {corte}");
    assert_eq!(linhas(&engine, &gql), 5, "AS OF não pode encolher o top-k");

    // `k` absurdo: aceite sem rebentar (não prova o tecto — ver o topo).
    let n = linhas(&engine, "NEAREST([0.5, 0.0], 4000000000)");
    assert!(n <= 65, "{n}");
}
