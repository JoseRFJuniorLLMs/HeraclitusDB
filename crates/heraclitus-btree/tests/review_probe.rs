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
    t.commit()
        .expect("commit apos valor grande nao pode falhar");

    assert_eq!(
        t.get(b"zzz-grande"),
        Some(big),
        "valor grande legivel de volta"
    );
}

/// Auditoria 2026-09-05 (A45): apagar uma chave cujo valor vivia em cadeia
/// overflow deixava o slot fantasma com FLAG_OVERFLOW ligada e
/// `overflow_page = 0` — exactamente a combinação que `verify_tree_integrity`
/// classifica como árvore corrompida. Uma árvore sã (o delete aplicou-se, as
/// vizinhas leem-se todas) era declarada corrompida pelo próprio verificador,
/// e um operador podia deitar fora um checkpoint bom.
///
/// A asserção é na MESMA instância, sem drop+load. Quando este teste nasceu um
/// `verify_tree_integrity` depois de `load` devolvia false em qualquer árvore,
/// por outra razão (contabilidade de páginas) alheia a este defeito — foi o
/// R40 da vaga 2 da Auditoria 2026-09-05 que a corrigiu; a contabilidade tem
/// agora os seus próprios testes em `tests/integridade_contabilidade.rs`.
#[test]
fn apagar_valor_com_cadeia_overflow_no_cascade_deixa_a_arvore_integra() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("del_ov.hbt");
    let mut t = BEpsilonTree::open(&path, 1000, 128).unwrap();

    // Muitas chaves pequenas para a raiz partir: o delete passa então pelo
    // buffer da raiz interna e pelo cascade, onde não há compactação que
    // mascare o slot fantasma (o caminho raiz-folha é compactado e esconde-o).
    for i in 0..400u32 {
        t.upsert(format!("chave-{i:06}").into_bytes(), b"v".to_vec())
            .unwrap();
    }
    t.commit().unwrap();

    t.upsert(b"zzz-grande".to_vec(), vec![0xABu8; 6144])
        .unwrap();
    t.commit().unwrap();
    assert!(
        t.verify_tree_integrity().unwrap(),
        "integra antes de apagar"
    );

    t.delete_key(b"zzz-grande").unwrap();
    // Limpar a flag SEM limpar o valor em memória faria o serialize
    // inline-izar de novo os 6144 B e rebentar a página aqui.
    t.commit()
        .expect("commit apos apagar valor com cadeia overflow");

    assert_eq!(t.get(b"zzz-grande"), None, "a chave foi mesmo apagada");
    assert_eq!(
        t.get(b"chave-000200"),
        Some(b"v".to_vec()),
        "vizinhas intactas"
    );
    assert!(
        t.verify_tree_integrity().unwrap(),
        "slot fantasma nao pode continuar a dizer que tem cadeia"
    );

    // E reescrever a mesma chave com outra cadeia continua a funcionar.
    t.upsert(b"zzz-grande".to_vec(), vec![0x11u8; 5000])
        .unwrap();
    t.commit().unwrap();
    assert_eq!(t.get(b"zzz-grande").map(|v| v.len()), Some(5000));
}

/// R41/A45 — ramo gémeo raiz-folha (`push_msg`), que até aqui não tinha um
/// único teste que morresse ao revertê-lo: o probe do A45 insere 400 chaves de
/// propósito para a raiz partir, logo exercita SÓ o ramo do
/// `partial_flush_cascade`. Duas cadeias overflow na MESMA raiz-folha: com a
/// outra cadeia ainda viva, `calculate_fragmentation_ratio` devolve 0.0 (o
/// `slot.length` do overflow vivo satura o `saturating_sub`), a compactação NÃO
/// corre e o slot fantasma vai mesmo para o disco. É o contra-exemplo à nota
/// "aqui a compactação mascara o defeito antes de alguém o ver".
#[test]
fn apagar_uma_de_duas_cadeias_na_raiz_folha_nao_corrompe() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("del_ov_raiz.hbt");
    let mut t = BEpsilonTree::open(&path, 1000, 128).unwrap();

    t.upsert(b"g1".to_vec(), vec![0xCDu8; 6144]).unwrap();
    t.upsert(b"g2".to_vec(), vec![0xEFu8; 6144]).unwrap();
    t.commit().unwrap();
    assert!(
        t.verify_tree_integrity().unwrap(),
        "integra antes de apagar"
    );

    t.delete_key(b"g1").unwrap();
    // Limpar a flag SEM limpar o valor em memória faz o serialize
    // inline-izar de novo os 6144 B e rebentar a página aqui.
    t.commit()
        .expect("commit apos apagar valor com cadeia na raiz-folha");

    assert_eq!(t.get(b"g1"), None, "a chave foi mesmo apagada");
    assert_eq!(t.get(b"g2").map(|v| v.len()), Some(6144), "vizinha intacta");
    assert!(
        t.verify_tree_integrity().unwrap(),
        "slot fantasma nao pode continuar a dizer que tem cadeia"
    );
}
