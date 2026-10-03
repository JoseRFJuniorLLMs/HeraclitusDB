//! Conferência de 2026-10-02: os checkpoints das views (vector, text, graph,
//! tgraph, entity, activation, telemetria) eram bincode cru — sem magic, sem
//! versão, sem CRC — e lidos com `fs::read` inteiro. Um bit trocado dentro de
//! uma posting descodificava sem erro e a view servia resultados errados com
//! aspecto válido.

use heraclitus_views::ckpt;

#[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug)]
struct Estado {
    postings: Vec<u64>,
    nome: String,
}

fn estado() -> Estado {
    Estado {
        postings: (0..10_000).collect(),
        nome: "texto".into(),
    }
}

#[test]
fn ida_e_volta() {
    let dir = tempfile::tempdir().unwrap();
    ckpt::save(dir.path(), "v", &estado()).unwrap();
    assert_eq!(ckpt::load::<Estado>(dir.path(), "v").unwrap(), Some(estado()));
}

#[test]
fn ausente_e_none() {
    let dir = tempfile::tempdir().unwrap();
    assert_eq!(ckpt::load::<Estado>(dir.path(), "v").unwrap(), None);
}

#[test]
fn um_byte_trocado_no_corpo_e_recusado_em_vez_de_servir_postings_errados() {
    let dir = tempfile::tempdir().unwrap();
    ckpt::save(dir.path(), "v", &estado()).unwrap();
    let path = dir.path().join("v.ckpt");
    let mut bytes = std::fs::read(&path).unwrap();
    // Um byte a meio das postings: continua a ser bincode válido (varints),
    // portanto sem CRC descodificaria para outro estado.
    let meio = bytes.len() / 2;
    bytes[meio] ^= 0x01;
    std::fs::write(&path, &bytes).unwrap();
    assert_eq!(
        ckpt::load::<Estado>(dir.path(), "v").unwrap(),
        None,
        "corpo corrompido tem de degradar para rebuild, não descodificar"
    );
}

#[test]
fn ficheiro_truncado_e_recusado() {
    let dir = tempfile::tempdir().unwrap();
    ckpt::save(dir.path(), "v", &estado()).unwrap();
    let path = dir.path().join("v.ckpt");
    let bytes = std::fs::read(&path).unwrap();
    std::fs::write(&path, &bytes[..bytes.len() - 7]).unwrap();
    assert_eq!(ckpt::load::<Estado>(dir.path(), "v").unwrap(), None);
}

#[test]
fn formato_antigo_sem_cabecalho_continua_a_ler_se() {
    // Os checkpoints gravados antes desta mudança não podem forçar um rebuild
    // integral no primeiro arranque depois da actualização.
    let dir = tempfile::tempdir().unwrap();
    let antigo = bincode::serde::encode_to_vec(estado(), bincode::config::standard()).unwrap();
    std::fs::write(dir.path().join("v.ckpt"), antigo).unwrap();
    assert_eq!(ckpt::load::<Estado>(dir.path(), "v").unwrap(), Some(estado()));
}

#[test]
fn versao_desconhecida_e_recusada() {
    let dir = tempfile::tempdir().unwrap();
    ckpt::save(dir.path(), "v", &estado()).unwrap();
    let path = dir.path().join("v.ckpt");
    let mut bytes = std::fs::read(&path).unwrap();
    bytes[4] = 0xEE;
    std::fs::write(&path, &bytes).unwrap();
    assert_eq!(ckpt::load::<Estado>(dir.path(), "v").unwrap(), None);
}
