//! Auditoria boot.md P1-C/P1-F (residual, conferido em 2026-10-02): o índice de
//! atributos era regravado INTEIRO em cada arranque e em cada checkpoint
//! periódico, mesmo sem um único evento novo.
//!
//! Causa: a cauda do arranque começava em `idx.watermark()`, que é o último
//! LSN já aplicado (inclusivo). O primeiro lote nunca vinha vazio, o arranque
//! marcava "construído" e gravava o ficheiro todo — escrita completa e
//! `sync_all` por nada. O `checkpoint_attr` periódico também gravava sem
//! condição.
//!
//! Este teste fixa as duas metades: um arranque/checkpoint sem eventos novos
//! não toca no ficheiro, e um evento novo continua a ser indexado e
//! persistido (a cauda não pode saltar o LSN seguinte ao watermark).

use heraclitus_core::{Episode, EventKind, FsyncPolicy, HeraclitusConfig};
use heraclitus_server::engine::Engine;

fn abrir(dir: &std::path::Path) -> Engine {
    let cfg = HeraclitusConfig {
        data_dir: dir.to_path_buf(),
        fsync: FsyncPolicy::Always,
        ..HeraclitusConfig::default()
    };
    Engine::open(&cfg).unwrap()
}

fn episodio(i: usize, dossie: &str) -> Episode {
    let mut e = Episode::new(
        "ana",
        EventKind::Observation,
        format!("registo {i}").into_bytes(),
    );
    e.attrs.insert("dossie".into(), dossie.into());
    e
}

fn contar(engine: &Engine, dossie: &str) -> usize {
    heraclitus_query::execute(
        &format!("MATCH (n) WHERE n.dossie = \"{dossie}\" RETURN n"),
        engine,
    )
    .unwrap()
    .as_array()
    .map(|a| a.len())
    .unwrap_or(0)
}

fn carimbo(path: &std::path::Path) -> (std::time::SystemTime, Vec<u8>) {
    (
        std::fs::metadata(path).unwrap().modified().unwrap(),
        std::fs::read(path).unwrap(),
    )
}

#[test]
fn arranque_e_checkpoint_sem_eventos_novos_nao_regravam_o_indice_de_atributos() {
    let dir = tempfile::tempdir().unwrap();
    let snapshot = dir.path().join("views").join("attr_index.bin");

    {
        let engine = abrir(dir.path());
        for i in 0..20 {
            engine.append(episodio(i, "alfa")).unwrap();
        }
        engine.checkpoint_views().unwrap();
    }
    assert!(snapshot.is_file(), "montagem: checkpoint tem de existir");
    let antes = carimbo(&snapshot);

    // Resolução de mtime do sistema de ficheiros: sem esta pausa uma
    // regravação podia cair no mesmo tick e passar despercebida (os bytes
    // seriam iguais — o conteúdo não muda, só a escrita é que é inútil).
    std::thread::sleep(std::time::Duration::from_millis(1100));

    {
        let engine = abrir(dir.path());
        engine.checkpoint_views().unwrap();
        assert_eq!(contar(&engine, "alfa"), 20);
    }
    let depois = carimbo(&snapshot);
    assert_eq!(
        antes.0, depois.0,
        "arranque + checkpoint sem eventos novos não pode regravar attr_index.bin"
    );
    assert_eq!(antes.1, depois.1);

    // Um evento novo tem de entrar no índice e no checkpoint seguinte.
    {
        let engine = abrir(dir.path());
        engine.append(episodio(20, "beta")).unwrap();
        engine.checkpoint_views().unwrap();
    }
    let com_novo = carimbo(&snapshot);
    assert_ne!(antes.1, com_novo.1, "evento novo tem de chegar ao checkpoint");

    let engine = abrir(dir.path());
    assert_eq!(contar(&engine, "alfa"), 20);
    assert_eq!(contar(&engine, "beta"), 1);
}

#[test]
fn cauda_do_arranque_indexa_o_lsn_seguinte_ao_watermark() {
    // O checkpoint fica para trás (gravado aos 5 eventos); os seguintes só
    // existem no log. O arranque tem de os replayar a partir de watermark+1 —
    // nem saltar o primeiro, nem depender de regravar o ficheiro.
    let dir = tempfile::tempdir().unwrap();
    {
        let engine = abrir(dir.path());
        for i in 0..5 {
            engine.append(episodio(i, "alfa")).unwrap();
        }
        engine.checkpoint_views().unwrap();
        for i in 5..8 {
            engine.append(episodio(i, "gama")).unwrap();
        }
    }
    let engine = abrir(dir.path());
    assert_eq!(contar(&engine, "alfa"), 5);
    assert_eq!(contar(&engine, "gama"), 3);
}
