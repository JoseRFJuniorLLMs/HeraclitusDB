//! Envelope AEAD v2 (item `aead-aad`) ponta a ponta, nos dois backends.
//!
//! - A escrita cifrada grava só envelopes `HRKLENC2` (AAD com `event_id`).
//! - Um log cifrado pela geração anterior (`HRKLENC1`, AAD só com o agente)
//!   continua legível sem migração, e o crypto-shred apaga as duas versões.
//!
//! O log v1 é fabricado com os MESMOS bytes que o escritor antigo punha em
//! disco: o escritor sem cifra persiste `content`/`attrs` tal como recebe, e o
//! escritor cifrado antigo persistia `content = HRKLENC1...` e o envelope de
//! atributos hex em `__heraclitus_encrypted_fields_v1`. A troca de ciphertexts
//! entre eventos é provada nos testes unitários de `heraclitus-log` (aqui os
//! checksums dos frames recusariam a adulteração antes da AEAD).

use heraclitus_core::{Episode, EventKind, FsyncPolicy, HeraclitusError, ProductPoint};
use heraclitus_crypto::{KeyStore, SHREDDED};
use heraclitus_log::Log;
use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;

const AGENTE: &str = "titular:hmac-sha256:abc";
const ATRIBUTOS_CIFRADOS: &str = "__heraclitus_encrypted_fields_v1";

/// Espelho de `SensitiveFields` (privado em `heraclitus-log`): mesma ordem de
/// campos, logo o mesmo bincode.
#[derive(serde::Serialize)]
struct CamposSensiveis {
    attrs: BTreeMap<String, String>,
    embedding: Option<ProductPoint>,
}

fn contem(palheiro: &[u8], agulha: &[u8]) -> bool {
    palheiro.windows(agulha.len()).any(|w| w == agulha)
}

/// Algum ficheiro sob `dir` (recursivo: o v6 guarda segmentos em subpastas)
/// contém `agulha`?
fn algum_ficheiro_contem(dir: &Path, agulha: &[u8]) -> bool {
    std::fs::read_dir(dir).unwrap().flatten().any(|e| {
        let p = e.path();
        if p.is_dir() {
            algum_ficheiro_contem(&p, agulha)
        } else {
            contem(&std::fs::read(&p).unwrap(), agulha)
        }
    })
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Episódio com os bytes exactos de um registo cifrado pela geração v1.
fn registo_v1(chave: &[u8; 32]) -> Episode {
    let mut ep = Episode::new(
        AGENTE,
        EventKind::Custom("OperationalFact".into()),
        heraclitus_crypto::seal_v1(chave, b"conteudo cifrado em 2025", AGENTE.as_bytes()),
    );
    let sensiveis = CamposSensiveis {
        attrs: [("actor_name".to_string(), "Carlos Silva".to_string())].into(),
        embedding: Some(ProductPoint {
            hyp: vec![0.25],
            sph: vec![],
            euc: vec![7.0],
        }),
    };
    let codificado =
        bincode::serde::encode_to_vec(&sensiveis, bincode::config::standard()).unwrap();
    let mut aad = AGENTE.as_bytes().to_vec();
    aad.extend_from_slice(b"\0fields-v1");
    ep.attrs.insert(
        ATRIBUTOS_CIFRADOS.into(),
        hex(&heraclitus_crypto::seal_v1(chave, &codificado, &aad)),
    );
    ep
}

macro_rules! v1_legivel_v2_escrito_e_shred {
    ($abrir:expr) => {{
        let abrir = $abrir;
        let dir = tempfile::tempdir().unwrap();
        let log_dir = dir.path().join("log");
        let keys_dir = dir.path().join("keys");

        // 1. Um log cifrado pela geração v1.
        let chave = KeyStore::open(&keys_dir)
            .unwrap()
            .get_or_create(AGENTE)
            .unwrap();
        let log = abrir(&log_dir, None);
        let lsn_v1 = log.append(registo_v1(&chave)).unwrap();
        drop(log);
        assert!(algum_ficheiro_contem(&log_dir, b"HRKLENC1"));

        // 2. Reaberto pela build nova, com a cifra ligada: lê o v1 sem migrar.
        let keys = KeyStore::open(&keys_dir).unwrap();
        let log = abrir(&log_dir, Some(keys.clone()));
        let (_, lido) = log.read(lsn_v1).unwrap().unwrap();
        assert_eq!(lido.content, b"conteudo cifrado em 2025");
        assert_eq!(lido.attrs["actor_name"], "Carlos Silva");
        assert!(lido.embedding.is_some());
        assert!(!lido.attrs.contains_key(ATRIBUTOS_CIFRADOS));

        // 3. A escrita nova sela em v2 e lê-se de volta.
        let mut novo = Episode::new(
            AGENTE,
            EventKind::Custom("OperationalFact".into()),
            b"conteudo novo".to_vec(),
        );
        novo.attrs.insert("actor_name".into(), "Ana Sousa".into());
        let lsn_v2 = log.append(novo).unwrap();
        log.flush().unwrap();
        let (_, lido) = log.read(lsn_v2).unwrap().unwrap();
        assert_eq!(lido.content, b"conteudo novo");
        assert_eq!(lido.attrs["actor_name"], "Ana Sousa");
        assert!(algum_ficheiro_contem(&log_dir, b"HRKLENC2"));
        assert!(!algum_ficheiro_contem(&log_dir, b"conteudo novo"));
        assert!(!algum_ficheiro_contem(&log_dir, b"Ana Sousa"));

        // 4. O crypto-shred apaga as duas gerações; o scan atravessa ambas.
        assert!(keys.shred(AGENTE).unwrap());
        for lsn in [lsn_v1, lsn_v2] {
            let (_, ep) = log.read(lsn).unwrap().unwrap();
            assert_eq!(ep.content, SHREDDED);
            assert!(!ep.attrs.contains_key("actor_name"));
            assert!(ep.embedding.is_none());
        }
        let todos = log.scan(0, u64::MAX).unwrap();
        assert_eq!(todos.len(), 2);
        assert!(todos.iter().all(|(_, ep)| ep.content == SHREDDED));
    }};
}

#[test]
fn log_v1_cifrado_continua_legivel_escrita_nova_e_v2_e_shred_apaga_ambos() {
    v1_legivel_v2_escrito_e_shred!(|dir: &Path, keys: Option<Arc<KeyStore>>| {
        Log::open_with_keystore(dir, 1 << 20, FsyncPolicy::Always, keys).unwrap()
    });
}

#[test]
fn log_v1_cifrado_continua_legivel_escrita_nova_e_v2_e_shred_apaga_ambos_v6() {
    v1_legivel_v2_escrito_e_shred!(|dir: &Path, keys: Option<Arc<KeyStore>>| {
        Log::open_v6_with_keystore(dir, 1 << 20, FsyncPolicy::Always, keys).unwrap()
    });
}

/// Um blob v1 adulterado (último byte da tag) num agente nunca shredded
/// continua a ser erro de integridade, não tombstone nem lixo.
#[test]
fn blob_v1_adulterado_continua_a_ser_erro() {
    let dir = tempfile::tempdir().unwrap();
    let log_dir = dir.path().join("log");
    let keys_dir = dir.path().join("keys");
    let chave = KeyStore::open(&keys_dir)
        .unwrap()
        .get_or_create(AGENTE)
        .unwrap();
    let mut ep = registo_v1(&chave);
    *ep.content.last_mut().unwrap() ^= 0x01;
    let log = Log::open_with_keystore(&log_dir, 1 << 20, FsyncPolicy::Always, None).unwrap();
    let lsn = log.append(ep).unwrap();
    drop(log);

    let log = Log::open_with_keystore(
        &log_dir,
        1 << 20,
        FsyncPolicy::Always,
        Some(KeyStore::open(&keys_dir).unwrap()),
    )
    .unwrap();
    assert!(matches!(log.read(lsn), Err(HeraclitusError::Crypto(_))));
}
