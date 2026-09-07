//! Guarda de regressão da Auditoria recursiva 2026-09-05, achado A24.
//!
//! Shadow paging: entre dois `commit()` NENHUMA página alcançável pelo
//! superbloco durável pode mudar de conteúdo. O ficheiro não tem WAL nem
//! journal de página, por isso uma escrita in-place sobre uma página do
//! último estado durável corrompe o que já estava commitado se o processo
//! cair antes da troca do superbloco.

use heraclitus_btree::{BEpsilonTree, DiskNode, Superblock, PAGE_SIZE};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::atomic::Ordering;

/// LCG determinista: os tamanhos de valor têm de ser VARIÁVEIS para que o
/// guarda de orçamento de `merge_or_borrow_cascade` deixe a fusão passar —
/// com valores uniformes o merge é sempre recusado e o teste seria vácuo.
fn proximo(estado: &mut u32) -> u32 {
    *estado = estado.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
    *estado
}

/// Lê do ficheiro o conjunto de páginas alcançáveis pelo superbloco DURÁVEL
/// (o de maior geração entre as páginas 0 e 1), com os respectivos bytes.
fn paginas_duraveis(bytes: &[u8]) -> HashMap<u64, Vec<u8>> {
    let pagina = |id: u64| -> Option<&[u8]> {
        let ini = id as usize * PAGE_SIZE;
        bytes.get(ini..ini + PAGE_SIZE)
    };
    let s0 = Superblock::deserialize(pagina(0).unwrap());
    let s1 = Superblock::deserialize(pagina(1).unwrap());
    // Mesma regra de desempate do `BEpsilonTree::open`.
    let sb = match (s0, s1) {
        (Ok(a), Ok(b)) => {
            if a.generation >= b.generation {
                a
            } else {
                b
            }
        }
        (Ok(a), Err(_)) => a,
        (Err(_), Ok(b)) => b,
        _ => panic!("nenhum superbloco legível"),
    };

    let mut out = HashMap::new();
    let mut vistos = HashSet::new();
    let mut pilha = vec![sb.root_id];
    while let Some(id) = pilha.pop() {
        if !vistos.insert(id) {
            continue;
        }
        let Some(p) = pagina(id) else { continue };
        let Ok(no) = DiskNode::deserialize(id, p) else {
            continue;
        };
        pilha.extend(no.children.iter().copied());
        out.insert(id, p.to_vec());
    }
    out
}

/// Oráculo: o último valor escrito por chave. Serve o segundo lado do fix —
/// re-identificar o irmão esquerdo sem re-apontar o pai perde as chaves.
fn escreve(
    t: &mut BEpsilonTree,
    estado: &mut u32,
    oraculo: &mut BTreeMap<Vec<u8>, Vec<u8>>,
    n: usize,
) {
    for _ in 0..n {
        let r = proximo(estado);
        let k = format!("k{:06}", r % 100_000).into_bytes();
        let v = vec![0x5Au8; (r % 700) as usize + 4];
        t.upsert(k.clone(), v.clone()).unwrap();
        oraculo.insert(k, v);
    }
}

#[test]
fn escrita_pre_commit_nao_toca_paginas_do_estado_duravel() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("shadow.hbt");
    let mut t = BEpsilonTree::open(&path, 1000, 128).unwrap();

    let mut estado = 1u32;
    let mut oraculo: BTreeMap<Vec<u8>, Vec<u8>> = BTreeMap::new();

    escreve(&mut t, &mut estado, &mut oraculo, 2000);
    t.commit().unwrap();

    let antes = paginas_duraveis(&std::fs::read(&path).unwrap());
    assert!(antes.len() > 8, "árvore demasiado rasa para o cenário");
    let merges_antes = t.metrics.merges_cascade.load(Ordering::Relaxed);

    // Escritas SEM commit: tudo o que toquem tem de ser páginas novas (CoW).
    escreve(&mut t, &mut estado, &mut oraculo, 600);

    let depois = std::fs::read(&path).unwrap();
    let mut alteradas: Vec<u64> = antes
        .iter()
        .filter(|(id, bytes)| {
            let ini = **id as usize * PAGE_SIZE;
            depois
                .get(ini..ini + PAGE_SIZE)
                .is_none_or(|agora| agora != bytes.as_slice())
        })
        .map(|(id, _)| *id)
        .collect();
    alteradas.sort_unstable();

    // Guarda anti-vacuidade: sem merges o caminho acusado nem sequer correu.
    assert!(
        t.metrics.merges_cascade.load(Ordering::Relaxed) > merges_antes,
        "o cenário não exercitou merge_or_borrow_cascade — teste vácuo"
    );
    assert!(
        alteradas.is_empty(),
        "o estado durável não pode mudar antes da troca do superbloco; páginas sobrescritas: {alteradas:?}"
    );

    // E o CoW do irmão esquerdo tem de deixar o pai a apontar para a página
    // nova: senão o merge publica um ramo órfão e as chaves fundidas somem.
    t.commit().unwrap();
    drop(t);
    let t2 = BEpsilonTree::load(&path).unwrap();
    let mut errados = 0usize;
    let mut ausentes: Vec<String> = Vec::new();
    for (k, v) in &oraculo {
        match t2.get(k) {
            Some(lido) if &lido == v => {}
            Some(_) => errados += 1,
            None => ausentes.push(String::from_utf8_lossy(k).into_owned()),
        }
    }
    assert!(
        errados == 0 && ausentes.is_empty(),
        "após o merge + commit + reabertura: {errados} valores errados, {} chaves ausentes (ex.: {:?})",
        ausentes.len(),
        &ausentes[..ausentes.len().min(8)]
    );
}
