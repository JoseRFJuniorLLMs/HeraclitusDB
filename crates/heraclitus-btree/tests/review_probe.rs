//! Guarda de regressão da revisão de código 2026-07-16 (docs/md/falta.md,
//! secção "REVISÃO DE CÓDIGO RUST", R2). Nasceu como sonda que FALHAVA com
//! "Estouro físico da Página"; verde desde que o cascade cria cadeias overflow.

use heraclitus_btree::BEpsilonTree;

/// Valores grandes (> OVERFLOW_THRESHOLD) inseridos DEPOIS de a árvore ganhar
/// profundidade (raiz interna) têm de continuar a funcionar — o caminho
/// buffer→cascade→folha tem de criar cadeia overflow como o caminho raiz-folha.
#[test]
fn probe_big_value_after_tree_grows() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("probe.hbt");
    let mut t = BEpsilonTree::open(&path, 1000, 128).unwrap();

    // Muitas chaves pequenas para forçar split da raiz (raiz vira interna).
    for i in 0..400u32 {
        let k = format!("chave-{i:06}").into_bytes();
        t.upsert(k, b"v".to_vec()).unwrap();
    }
    t.commit().unwrap();

    // Agora um valor de 2 KB — vai pelo buffer da raiz interna e cascata.
    let big = vec![0xABu8; 6144];
    t.upsert(b"zzz-grande".to_vec(), big.clone())
        .expect("upsert de valor grande apos split nao pode falhar");
    t.commit().expect("commit apos valor grande nao pode falhar");

    assert_eq!(
        t.get(b"zzz-grande"),
        Some(big),
        "valor grande legivel de volta"
    );
}
