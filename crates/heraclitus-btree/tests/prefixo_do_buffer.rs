//! Guarda de regressão da Auditoria recursiva 2026-09-05, achado A42.
//!
//! O prefixo comum da página era calculado só sobre os separadores
//! (`self.keys`), mas o desserializador reconstrói SEMPRE `prefixo ++ sufixo`.
//! Uma chave do buffer fora do prefixo era gravada inteira e voltava do disco
//! como `prefixo ++ chave` — a mensagem passava a encaminhar para o ramo
//! errado e a chave original desaparecia. Perda SILENCIOSA: o CRC32 e o
//! Blake3 da página continuam válidos, porque o dano é semântico.

use heraclitus_btree::BEpsilonTree;

/// Gerador determinista (LCG de Numerical Recipes) — a ordem de inserção tem
/// de ser aleatória mas reprodutível: com inserção ordenada os buffers dos
/// nós internos partilham sempre o prefixo dos separadores e o defeito fica
/// latente.
fn proximo(estado: &mut u32) -> u32 {
    *estado = estado.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
    *estado
}

#[test]
fn chaves_sobrevivem_a_carga_aleatoria_e_reload() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("prefixo.hbt");
    // node_cap/buffer_cap pequenos forçam muitos nós internos com um único
    // separador — o caso em que o prefixo comum é a chave separadora INTEIRA.
    let mut t = BEpsilonTree::open(&path, 64, 8).unwrap();

    let total = 6000u32;
    let mut chaves: Vec<Vec<u8>> = (0..total)
        .map(|i| format!("k{i:05}").into_bytes())
        .collect();
    let mut estado = 42u32;
    for i in (1..chaves.len()).rev() {
        let j = (proximo(&mut estado) as usize) % (i + 1);
        chaves.swap(i, j);
    }
    for k in &chaves {
        t.upsert(k.clone(), b"v".to_vec()).unwrap();
    }
    t.commit().unwrap();
    drop(t);

    let t2 = BEpsilonTree::load(&path).unwrap();
    let perdidas: Vec<String> = (0..total)
        .map(|i| format!("k{i:05}"))
        .filter(|k| t2.get(k.as_bytes()).is_none())
        .collect();
    assert!(
        perdidas.is_empty(),
        "chaves perdidas após reload ({}): {:?}",
        perdidas.len(),
        &perdidas[..perdidas.len().min(8)]
    );
}
