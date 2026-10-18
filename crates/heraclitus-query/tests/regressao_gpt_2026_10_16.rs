//! Regressão G4: comparações exatas de HLC pelo backend real.
use heraclitus_core::{Episode, EventKind, FsyncPolicy};
use heraclitus_log::Log;
use heraclitus_query::{backend::LogBackend, execute};
use std::sync::Arc;

#[test]
fn regressao_g4_hlc_distintos_viram_iguais_e_invertem_top1() {
    let dir = tempfile::tempdir().unwrap();
    let log = Arc::new(Log::open(dir.path(), 1 << 20, FsyncPolicy::Always).unwrap());
    let base = 1_800_000_000_000u64 << 16;
    for i in 0..2 {
        let mut e = Episode::new("audit", EventKind::Observation, vec![]);
        e.ts_hlc = base + i;
        log.append_replicated(i, e).unwrap();
    }
    assert_eq!(log.read(0).unwrap().unwrap().1.ts_hlc, base);
    assert_eq!(log.read(1).unwrap().unwrap().1.ts_hlc, base + 1);
    let backend = LogBackend::new(log);
    let eq = execute(
        &format!("MATCH (n) WHERE n.ts_hlc = \"{base}\" RETURN n"),
        &backend,
    )
    .unwrap();
    let ordered = execute(
        "MATCH (n) RETURN n ORDER BY n.ts_hlc DESC LIMIT 1",
        &backend,
    )
    .unwrap();
    eprintln!(
        "G4: HLC reais=[{base}, {}], igualdade retornou {} linhas; DESC LIMIT 1 escolheu LSN={}",
        base + 1,
        eq.as_array().unwrap().len(),
        ordered[0]["lsn"]
    );
    assert_eq!(
        eq.as_array().unwrap().len(),
        1,
        "igualdade de HLC deve ser exata"
    );
    assert_eq!(ordered[0]["lsn"], 1, "sonda: top1 escolheu o menor HLC");
}

#[test]
fn inteiros_adjacentes_limites_filtros_e_ordenacao() {
    let dir = tempfile::tempdir().unwrap();
    let log = Arc::new(Log::open(dir.path(), 1 << 20, FsyncPolicy::Always).unwrap());
    let base = 1_800_000_000_000u64 << 16;
    let values = [
        (1u64 << 53) - 1,
        1u64 << 53,
        (1u64 << 53) + 1,
        base,
        base + 1,
        u64::MAX - 1,
        u64::MAX,
    ];
    for (i, value) in values.iter().enumerate() {
        let mut e = Episode::new("audit", EventKind::Observation, vec![]);
        e.ts_hlc = *value;
        log.append_replicated(i as u64, e).unwrap();
    }
    let backend = LogBackend::new(log);
    for (i, value) in values.iter().enumerate() {
        for literal in [value.to_string(), format!("\"{value}\"")] {
            for (op, expected) in [
                ("=", 1),
                ("!=", values.len() - 1),
                ("<", i),
                ("<=", i + 1),
                (">", values.len() - i - 1),
                (">=", values.len() - i),
            ] {
                let rows = execute(
                    &format!("MATCH (n) WHERE n.ts_hlc {op} {literal} RETURN n"),
                    &backend,
                )
                .unwrap();
                assert_eq!(
                    rows.as_array().unwrap().len(),
                    expected,
                    "{value} {op} {literal}"
                );
            }
        }
    }
    for (direction, expected) in [("ASC", 0), ("DESC", values.len() - 1)] {
        let rows = execute(
            &format!("MATCH (n) RETURN n ORDER BY n.ts_hlc {direction} LIMIT 1"),
            &backend,
        )
        .unwrap();
        assert_eq!(rows[0]["lsn"], expected);
    }
    execute("CREATE (n:Limite {valor: 18446744073709551615})", &backend).unwrap();
    let rows = execute(
        "MATCH (n:Limite) WHERE n.valor = 18446744073709551615 RETURN n",
        &backend,
    )
    .unwrap();
    assert_eq!(rows.as_array().unwrap().len(), 1);
}
