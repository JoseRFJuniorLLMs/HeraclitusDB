//! Sonda da auditoria 2026-10-16 (nao faz parte do repositorio).
use heraclitus_crypto::KeyStore;

#[test]
fn sonda_agent_id_longo_falha_get_or_create() {
    let dir = tempfile::tempdir().unwrap();
    let ks = KeyStore::open(dir.path().join("keys")).unwrap();
    assert!(ks.get_or_create(&"a".repeat(100)).is_ok());
    let r = ks.get_or_create(&"a".repeat(130));
    eprintln!("agent_id 130 bytes: {:?}", r.as_ref().map(|_| ()).map_err(|e| e.to_string()));
    assert!(r.is_err(), "nao reproduziu");
}
