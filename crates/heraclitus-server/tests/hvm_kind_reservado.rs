//! Regressão: o kind `hvm_isa` é reservado ao ledger soberano.

use heraclitus_core::{Episode, EventKind, HeraclitusConfig};
use heraclitus_server::engine::Engine;

fn engine(dir: &std::path::Path) -> Engine {
    let cfg = HeraclitusConfig {
        data_dir: dir.to_path_buf(),
        ..HeraclitusConfig::default()
    };
    Engine::open(&cfg).unwrap()
}

/// ENVENENAMENTO IRREVERSÍVEL DO LEDGER (corrigido): qualquer cliente podia
/// fazer um Append normal com `kind: "hvm_isa"`. O episódio ficava invisível a
/// todas as queries (views/attr/memtable saltam `is_hvm`) E entrava no replay do
/// H-VM, onde bytes arbitrários não decodificam como instrução ISA. Como o log é
/// imutável, o estrago era permanente.
#[test]
fn append_publico_recusa_o_kind_reservado() {
    let dir = tempfile::tempdir().unwrap();
    let eng = engine(dir.path());

    let mau = Episode::new(
        "atacante",
        EventKind::Custom("hvm_isa".into()),
        b"ola".to_vec(),
    );
    let r = eng.append(mau);
    assert!(
        r.is_err(),
        "o kind reservado hvm_isa foi aceite pelo append público"
    );

    // O caminho H-VM legítimo continua a funcionar.
    eng.hvm_upsert(b"k".to_vec(), b"v".to_vec()).unwrap();
    let st = eng.hvm_state().unwrap();
    assert!(
        !st.memory_layers.is_empty(),
        "o upsert legítimo não entrou no ledger"
    );

    // E um append normal continua a funcionar.
    eng.append(Episode::new("a", EventKind::Observation, b"x".to_vec()))
        .unwrap();
}
