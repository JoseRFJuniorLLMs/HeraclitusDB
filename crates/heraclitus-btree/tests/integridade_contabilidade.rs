//! Auditoria recursiva 2026-09-05, vaga 2 (R40): a contabilidade de páginas do
//! `verify_tree_integrity`. O verificador declarava CORROMPIDA uma árvore sã
//! por duas razões independentes — os ids guardados EM LOTE dentro das páginas
//! de spill da free list nunca eram contados, e a free list drenada no fim do
//! `commit` nunca chegava a nenhum superbloco durável (fuga de espaço tratada
//! como corrupção). Um operador que use o verificador deita fora um checkpoint
//! bom; é o mesmo efeito que justificou o A45.

use std::collections::BTreeMap;
use std::sync::atomic::Ordering;

use heraclitus_btree::{BEpsilonTree, FilePageStore, PageStore, PAGE_SIZE};

/// Gerador determinista (LCG de Numerical Recipes): a sonda tem de produzir
/// exactamente a mesma carga em cada execução — um flake aqui é indistinguível
/// de uma regressão de contabilidade.
struct Lcg(u64);

impl Lcg {
    fn proximo(&mut self) -> u64 {
        self.0 = self.0.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        self.0 >> 16
    }
}

/// Carga mista determinista: `ciclos` lotes de 1500 operações (1 em cada 5 é um
/// `delete_key`) sobre um espaço de 4000 chaves, com `commit()` no fim de cada
/// lote. Recicla páginas suficientes para a free list transbordar do superbloco
/// (MAX_SB_FREE_LIST = 32) e passar a usar páginas de spill. Devolve o oráculo.
fn carga_mista(t: &mut BEpsilonTree, ciclos: usize) -> BTreeMap<Vec<u8>, Vec<u8>> {
    let mut oraculo: BTreeMap<Vec<u8>, Vec<u8>> = BTreeMap::new();
    let mut rng = Lcg(0x5EED_1234);
    for _ in 0..ciclos {
        for _ in 0..1500 {
            let k = format!("k{:08}", rng.proximo() % 4000).into_bytes();
            if rng.proximo().is_multiple_of(5) {
                t.delete_key(&k).unwrap();
                oraculo.remove(&k);
            } else {
                let n = 3 + (rng.proximo() % 900) as usize;
                let v = vec![(rng.proximo() & 0xFF) as u8; n];
                t.upsert(k.clone(), v.clone()).unwrap();
                oraculo.insert(k, v);
            }
        }
        t.commit().unwrap();
    }
    oraculo
}

fn conferir_oraculo(t: &BEpsilonTree, oraculo: &BTreeMap<Vec<u8>, Vec<u8>>, onde: &str) {
    let mut errados = 0usize;
    for (k, v) in oraculo {
        if t.get(k).as_ref() != Some(v) {
            errados += 1;
        }
    }
    assert_eq!(errados, 0, "{onde}: {errados} chaves lidas erradas");
}

/// R40 CAUSA A — uma página de spill da free list guarda até MAX_SB_FREE_LIST
/// ids EM LOTE dentro do seu próprio payload (count no offset 9, ids a partir
/// do 11), exactamente como `allocate_id` os relê. A varredura do verificador
/// só seguia o ponteiro `next` e contava a página da cadeia, escondendo 32
/// páginas por cada spill: a partir da 33.ª página libertada (trivial — o CoW
/// da raiz recicla uma página por upsert) a soma dava menos que as páginas
/// físicas e o verificador gritava corrupção sobre uma árvore intacta.
#[test]
fn spill_da_free_list_nao_e_corrupcao() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("contab_spill.hbt");
    let mut t = BEpsilonTree::open(&path, 128, 1000).unwrap();

    let oraculo = carga_mista(&mut t, 2);
    conferir_oraculo(&t, &oraculo, "arvore viva");

    // Sem spill o cenário não mede nada: falharia por vacuidade se o layout
    // da free list mudasse e o transbordo deixasse de acontecer.
    assert!(
        t.superblock.read().unwrap().free_list_head != 0,
        "a carga nao chegou a transbordar a free list — a sonda nao mede nada"
    );
    let r = t.verify_tree_integrity_report().unwrap();
    assert!(
        r.integra,
        "arvore sa (todos os valores conferem com o oraculo) dada como corrompida: {} fisicas, {} contabilizadas",
        r.paginas_fisicas, r.contabilizadas
    );
    // O nucleo do R40 CAUSA A: numa arvore VIVA nao ha uma unica pagina por
    // explicar — arvore, cadeias overflow, free list (incluindo os ids EM LOTE
    // dentro das paginas de spill), `pending_recycle`, superblocos e genese
    // fecham a contabilidade. Sem contar os ids em lote sobram ~32 orfas por
    // spill, e e isso que esta assercao mata (o relaxamento `>` do passo 2
    // sozinho esconderia-as atras de um `integra: true`).
    assert_eq!(
        r.orfas, 0,
        "arvore viva com {} paginas por explicar — os ids EM LOTE das paginas de spill nao estao a ser contabilizados",
        r.orfas
    );
}

/// R40 CAUSA B — `commit()` escreve o superbloco e SÓ DEPOIS drena o
/// `pending_recycle` para a free list (ordem exigida pelo shadow paging). A
/// free list resultante nunca entrava no superbloco DAQUELE commit e o commit
/// seguinte voltava a consumi-la antes de gravar, pelo que o superbloco durável
/// ficava sistematicamente com a free list vazia e as páginas recicladas
/// ficavam órfãs. Depois de `drop` + `load` o verificador via menos páginas
/// contabilizadas que físicas e devolvia `false` — uma FUGA DE ESPAÇO segura e
/// documentada (R8) a ser reportada como CORRUPÇÃO.
#[test]
fn verify_apos_reload_nao_acusa_fuga() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("contab_reload.hbt");

    let oraculo = {
        let mut t = BEpsilonTree::open(&path, 128, 1000).unwrap();
        let o = carga_mista(&mut t, 2);
        assert!(
            t.verify_tree_integrity().unwrap(),
            "integra antes do reload"
        );
        o
    };

    let mut t2 = BEpsilonTree::load(&path).unwrap();
    conferir_oraculo(&t2, &oraculo, "apos reload");

    let r = t2.verify_tree_integrity_report().unwrap();
    assert!(
        r.integra,
        "fuga de espaco reportada como corrupcao apos reload: {} fisicas, {} contabilizadas, {} orfas",
        r.paginas_fisicas, r.contabilizadas, r.orfas
    );
    // Anti-vacuidade: se nao houvesse orfas o cenario nao exercitava o
    // relaxamento de `!=` para `>` e o teste passava por acaso.
    assert!(
        r.orfas > 0,
        "sem paginas orfas o cenario nao mede a fuga que o R40 descreve"
    );
    assert_eq!(
        r.contabilizadas + r.orfas,
        r.paginas_fisicas as usize,
        "o relatorio tem de fechar a contabilidade"
    );
    assert_eq!(
        t2.metrics.orphan_pages.load(Ordering::Relaxed),
        r.orfas,
        "a metrica tem de espelhar o relatorio"
    );
}

/// R40, guarda do relaxamento — passar de `!=` para `>` nao pode cegar a
/// deteccao de reuso cruzado de id. Paginas a MAIS que as fisicas continuam a
/// ser corrupcao: aqui o id da raiz VIVA e injectado tambem na free list do
/// superbloco, ficando contado nos dois conjuntos.
#[test]
fn paginas_a_mais_sao_corrupcao() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("contab_dupla.hbt");
    let mut t = BEpsilonTree::open(&path, 128, 1000).unwrap();

    let _ = carga_mista(&mut t, 1);
    assert!(t.verify_tree_integrity().unwrap(), "sa antes da injeccao");

    let root_id = {
        let mut sb = t.superblock.write().unwrap();
        let slot = sb.free_list_len as usize;
        assert!(slot < sb.free_list.len(), "free list do superbloco cheia");
        sb.free_list[slot] = sb.root_id;
        sb.free_list_len += 1;
        sb.root_id
    };

    let r = t.verify_tree_integrity_report().unwrap();
    assert!(
        !r.integra,
        "a raiz {root_id} viva E na free list e reuso cruzado de id: {} fisicas, {} contabilizadas",
        r.paginas_fisicas, r.contabilizadas
    );
}

/// R40, guarda do layout de spill — o laco novo le `count` no offset 9 e os
/// ids a partir do 11, exactamente como `allocate_id`. Uma pagina de spill
/// adulterada tem de sair como CORRUPCAO (`Ok(false)`), nunca como `Err` nem
/// como arvore sa. Sem estas assercoes, ler os ids no offset errado passava
/// despercebido: a CONTAGEM fechava na mesma e so os ids e que eram lixo.
#[test]
fn spill_adulterado_e_corrupcao_e_nao_excepcao() {
    for (caso, adulterar) in [
        // `count` impossivel: mais ids do que cabem no array do superbloco.
        (
            "count",
            (|p: &mut [u8]| p[9..11].copy_from_slice(&0xFFFFu16.to_le_bytes())) as fn(&mut [u8]),
        ),
        // Duplo-free: o mesmo id duas vezes no lote.
        ("duplo-free", |p: &mut [u8]| {
            let id0 = p[11..19].to_vec();
            p[19..27].copy_from_slice(&id0);
        }),
        // Id fora de alcance (o efeito de ler o lote no offset errado).
        ("fora-de-alcance", |p: &mut [u8]| {
            p[11..19].copy_from_slice(&u64::MAX.to_le_bytes())
        }),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("contab_spill_mau.hbt");
        let mut t = BEpsilonTree::open(&path, 128, 1000).unwrap();
        let _ = carga_mista(&mut t, 2);

        let head = t.superblock.read().unwrap().free_list_head;
        assert!(head != 0, "{caso}: sem spill nao ha o que adulterar");
        assert!(t.verify_tree_integrity().unwrap(), "{caso}: sa antes");

        // Segundo handle sobre o mesmo ficheiro: as paginas da free list sao
        // lidas do disco pelo verificador, nunca do cache de nos.
        let store = FilePageStore::open(&path).unwrap();
        let mut pagina = vec![0u8; PAGE_SIZE];
        store.read_page(head, &mut pagina).unwrap();
        adulterar(&mut pagina);
        store.write_page(head, &pagina).unwrap();
        store.sync().unwrap();

        assert_eq!(
            t.verify_tree_integrity().ok(),
            Some(false),
            "{caso}: pagina de spill adulterada tem de dar corrupcao, nem excepcao nem arvore sa"
        );
    }
}
