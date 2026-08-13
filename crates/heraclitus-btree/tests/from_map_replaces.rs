//! Regressão: `from_map` materializa um ESTADO, não um delta.

use heraclitus_btree::BEpsilonTree;
use std::collections::BTreeMap;

/// RESSURREIÇÃO DE DADOS (corrigida): `from_map` abria a árvore EXISTENTE e
/// fazia upsert só das chaves vivas. Uma chave apagada do ledger H-VM entre
/// dois `POST /hvm/checkpoint` sobrevivia no ficheiro do checkpoint anterior —
/// ou seja, o checkpoint durável ressuscitava um registo apagado, e o endpoint
/// respondia `{"ok":true}`. O contrato correto é: o ficheiro reflete EXATAMENTE
/// o mapa recebido.
#[test]
fn from_map_reflete_exatamente_o_mapa_e_nao_ressuscita() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("hvm.hbt");

    // 1.º checkpoint: duas chaves.
    let mut m1: BTreeMap<Vec<u8>, Vec<u8>> = BTreeMap::new();
    m1.insert(b"user:1".to_vec(), b"alice".to_vec());
    m1.insert(b"user:2".to_vec(), b"bob".to_vec());
    {
        let t = BEpsilonTree::from_map(&path, m1).unwrap();
        assert_eq!(t.get(b"user:1").as_deref(), Some(&b"alice"[..]));
    }

    // 2.º checkpoint: `user:1` foi APAGADO do ledger — o mapa vivo já não o tem.
    let mut m2: BTreeMap<Vec<u8>, Vec<u8>> = BTreeMap::new();
    m2.insert(b"user:2".to_vec(), b"bob".to_vec());
    let t = BEpsilonTree::from_map(&path, m2).unwrap();

    assert_eq!(
        t.get(b"user:1"),
        None,
        "chave apagada ressuscitou no checkpoint"
    );
    assert_eq!(t.get(b"user:2").as_deref(), Some(&b"bob"[..]));
}
