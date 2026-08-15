//! Regressão: um intervalo vazio não pode panicar (envenenava o Mutex do índice).
use heraclitus_core::{Episode, EventKind};
use heraclitus_index_attr::AttrIndex;
use heraclitus_views::View;
use std::ops::Bound;

fn idx_com_valor() -> AttrIndex {
    let mut idx = AttrIndex::new();
    let mut e = Episode::new("a", EventKind::Observation, b"x".to_vec());
    e.attrs.insert("valor".into(), "50".into());
    idx.apply(1, &e);
    idx
}

/// `WHERE n.valor > 100 AND n.valor < 10` — sintaxe VÁLIDA, intervalo vazio.
/// Antes: panic dentro de `BTreeMap::range` com o Mutex do índice bloqueado ⇒
/// Mutex envenenado ⇒ nenhum append voltava a funcionar até reiniciar o nó.
#[test]
fn intervalo_invertido_devolve_vazio_em_vez_de_panicar() {
    let idx = idx_com_valor();
    assert!(idx
        .lookup_range("valor", Bound::Excluded(100.0), Bound::Excluded(10.0))
        .is_empty());
    assert!(idx
        .lookup_range("valor", Bound::Included(100.0), Bound::Included(10.0))
        .is_empty());
    assert!(idx
        .lookup_range("valor", Bound::Excluded(50.0), Bound::Excluded(50.0))
        .is_empty());
    assert_eq!(
        idx.lookup_range("valor", Bound::Included(0.0), Bound::Included(100.0)),
        vec![1]
    );
}
