//! heraclitus-index-text — derived BM25 inverted index (§3.6).

use heraclitus_core::{Episode, EventId, Lsn};
use heraclitus_memtable::tokenize;
use heraclitus_views::View;
use std::collections::HashMap;

const K1: f32 = 1.2;
const B: f32 = 0.75;

#[derive(Default)]
pub struct TextIndex {
    postings: HashMap<String, Vec<(u32, u32)>>, // term -> [(doc, tf)]
    doc_len: Vec<u32>,
    ids: Vec<EventId>,
    lsns: Vec<Lsn>,
    by_event: HashMap<EventId, u32>,
    total_len: u64,
    watermark: Lsn,
}

#[derive(Debug, Clone)]
pub struct TextHit {
    pub id: EventId,
    pub lsn: Lsn,
    pub score: f32,
}

/// Acumulador de scores BM25 denso, com marcas de época.
///
/// # Porque não um `HashMap<u32, f32>`
///
/// A versão anterior fazia `*scores.entry(doc).or_default() += s` uma vez por
/// **posting**, e um termo comum tem tantos postings quantos os documentos que
/// o contêm. Cada uma dessas operações é um hash mais uma sondagem, e o mapa
/// inteiro é construído e destruído a cada consulta.
///
/// Aqui o score de um documento é uma escrita indexada. A época diz quais das
/// entradas pertencem a ESTA consulta, o que evita limpar o vector entre
/// consultas; e `tocados` guarda quais foram escritos, o que evita percorrer
/// todos os documentos no fim para recolher os resultados — sem essa lista, um
/// índice com um milhão de documentos pagaria um milhão de leituras para
/// devolver dez resultados.
///
/// O transbordo da época é tratado como no índice vectorial: ao dar a volta, as
/// marcas são limpas uma vez, porque uma marca antiga a coincidir com a época
/// nova faria um documento aparecer com o score de uma consulta anterior.
#[derive(Debug, Default)]
struct AcumuladorBm25 {
    scores: Vec<f32>,
    marcas: Vec<u32>,
    tocados: Vec<u32>,
    epoca: u32,
}

impl AcumuladorBm25 {
    fn preparar(&mut self, n: usize) {
        if self.marcas.len() < n {
            self.marcas.resize(n, 0);
            self.scores.resize(n, 0.0);
        }
        self.tocados.clear();
        self.epoca = self.epoca.wrapping_add(1);
        if self.epoca == 0 {
            self.marcas.iter_mut().for_each(|m| *m = 0);
            self.epoca = 1;
        }
    }

    #[inline]
    fn somar(&mut self, doc: u32, s: f32) {
        let i = doc as usize;
        if i >= self.marcas.len() {
            return;
        }
        if self.marcas[i] == self.epoca {
            self.scores[i] += s;
        } else {
            self.marcas[i] = self.epoca;
            self.scores[i] = s;
            self.tocados.push(doc);
        }
    }
}

thread_local! {
    /// Scratch por thread, reutilizado entre consultas. `search` recebe `&self`
    /// e não é reentrante, pelo que manter o empréstimo durante a consulta é
    /// seguro.
    static ACUMULADOR: std::cell::RefCell<AcumuladorBm25> =
        const {
            std::cell::RefCell::new(AcumuladorBm25 {
                scores: Vec::new(),
                marcas: Vec::new(),
                tocados: Vec::new(),
                epoca: 0,
            })
        };
}

impl TextIndex {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.ids.len()
    }

    pub fn is_empty(&self) -> bool {
        self.ids.is_empty()
    }

    pub fn search(&self, query: &str, k: usize) -> Vec<TextHit> {
        let n = self.ids.len() as f32;
        if n == 0.0 {
            return Vec::new();
        }
        let avgdl = (self.total_len as f32 / n).max(1.0);
        ACUMULADOR.with(|acc| {
        let mut acc = acc.borrow_mut();
        acc.preparar(self.ids.len());
        for term in tokenize(query) {
            let Some(plist) = self.postings.get(&term) else {
                continue;
            };
            let df = plist.len() as f32;
            let idf = ((n - df + 0.5) / (df + 0.5) + 1.0).ln();
            for &(doc, tf) in plist {
                let dl = self.doc_len[doc as usize] as f32;
                let tf = tf as f32;
                let s = idf * (tf * (K1 + 1.0)) / (tf + K1 * (1.0 - B + B * dl / avgdl));
                acc.somar(doc, s);
            }
        }
        let mut hits: Vec<TextHit> = acc
            .tocados
            .iter()
            .map(|&doc| TextHit {
                id: self.ids[doc as usize],
                lsn: self.lsns[doc as usize],
                score: acc.scores[doc as usize],
            })
            .collect();
        // Desempate por LSN: a ordem por que os documentos foram TOCADOS
        // depende da ordem dos postings, não do conteúdo — sem este desempate,
        // docs com score igual entravam e saíam do top-k conforme a consulta.
        let ordem = |a: &TextHit, b: &TextHit| {
            b.score.total_cmp(&a.score).then_with(|| a.lsn.cmp(&b.lsn))
        };
        // Selecção parcial: para devolver `k` de `n` não é preciso ordenar os
        // `n`. Resultado idêntico porque o comparador é uma ordem total.
        if k < hits.len() {
            hits.select_nth_unstable_by(k, ordem);
            hits.truncate(k);
        }
        hits.sort_by(ordem);
        hits
        })
    }
}

/// Snapshot serializável do índice (fast boot): `by_event` é reconstruído de
/// `ids` no restore, por isso não é persistido.
#[derive(serde::Serialize, serde::Deserialize)]
struct TextSnapshot {
    postings: HashMap<String, Vec<(u32, u32)>>,
    doc_len: Vec<u32>,
    ids: Vec<EventId>,
    lsns: Vec<Lsn>,
    total_len: u64,
    watermark: Lsn,
}

impl View for TextIndex {
    fn name(&self) -> &str {
        "text"
    }

    fn checkpoint(&self, dir: &std::path::Path) -> Result<(), heraclitus_core::HeraclitusError> {
        heraclitus_views::ckpt::save(
            dir,
            "text",
            &TextSnapshot {
                postings: self.postings.clone(),
                doc_len: self.doc_len.clone(),
                ids: self.ids.clone(),
                lsns: self.lsns.clone(),
                total_len: self.total_len,
                watermark: self.watermark,
            },
        )
    }

    fn restore(&mut self, dir: &std::path::Path) -> Result<bool, heraclitus_core::HeraclitusError> {
        let Some(snap) = heraclitus_views::ckpt::load::<TextSnapshot>(dir, "text")? else {
            return Ok(false);
        };
        self.by_event = snap
            .ids
            .iter()
            .enumerate()
            .map(|(i, id)| (*id, i as u32))
            .collect();
        self.postings = snap.postings;
        self.doc_len = snap.doc_len;
        self.ids = snap.ids;
        self.lsns = snap.lsns;
        self.total_len = snap.total_len;
        self.watermark = snap.watermark;
        Ok(true)
    }

    fn apply(&mut self, lsn: Lsn, event: &Episode) {
        // Avanço-só: uma entrega fora de ordem (appends concorrentes) não pode
        // regredir o watermark persistido — o replay pós-restart cobriria a
        // lacuna e o dedup por `by_event` absorve a sobreposição.
        self.watermark = self.watermark.max(lsn);
        if self.by_event.contains_key(&event.id) {
            return; // idempotent replay
        }
        let text = String::from_utf8_lossy(&event.content);
        let tokens = tokenize(&text);
        let doc = self.ids.len() as u32;
        self.by_event.insert(event.id, doc);
        self.ids.push(event.id);
        self.lsns.push(lsn);
        self.doc_len.push(tokens.len() as u32);
        self.total_len += tokens.len() as u64;

        let mut tf: HashMap<String, u32> = HashMap::new();
        for t in tokens {
            *tf.entry(t).or_default() += 1;
        }
        for (term, count) in tf {
            self.postings.entry(term).or_default().push((doc, count));
        }
    }

    fn watermark(&self) -> Lsn {
        self.watermark
    }

    fn reset(&mut self) {
        *self = TextIndex::default();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use heraclitus_core::EventKind;

    #[test]
    fn bm25_ranks_relevance() {
        let mut idx = TextIndex::new();
        let docs = [
            "the river flows into the sea",
            "no one steps in the same river twice",
            "fire is the element of change",
        ];
        let mut ids = Vec::new();
        for (i, d) in docs.iter().enumerate() {
            let e = Episode::new("a", EventKind::Observation, d.as_bytes().to_vec());
            ids.push(e.id);
            idx.apply(i as u64, &e);
        }
        let hits = idx.search("river", 3);
        assert_eq!(hits.len(), 2);
        assert!(hits.iter().all(|h| h.id == ids[0] || h.id == ids[1]));
        let fire = idx.search("fire change", 3);
        assert_eq!(fire[0].id, ids[2]);
    }
}

#[cfg(test)]
mod testes_acumulador {
    use super::*;
    use heraclitus_core::EventKind;
    use std::collections::HashMap;

    struct Rng(u64);
    impl Rng {
        fn proximo(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }
    }

    /// A implementacao anterior, palavra por palavra, so como referencia de
    /// teste: um acumulador denso que devolvesse outra coisa nao seria uma
    /// optimizacao.
    fn search_referencia(idx: &TextIndex, query: &str, k: usize) -> Vec<TextHit> {
        let n = idx.ids.len() as f32;
        if n == 0.0 {
            return Vec::new();
        }
        let avgdl = (idx.total_len as f32 / n).max(1.0);
        let mut scores: HashMap<u32, f32> = HashMap::new();
        for term in tokenize(query) {
            let Some(plist) = idx.postings.get(&term) else {
                continue;
            };
            let df = plist.len() as f32;
            let idf = ((n - df + 0.5) / (df + 0.5) + 1.0).ln();
            for &(doc, tf) in plist {
                let dl = idx.doc_len[doc as usize] as f32;
                let tf = tf as f32;
                let s = idf * (tf * (K1 + 1.0)) / (tf + K1 * (1.0 - B + B * dl / avgdl));
                *scores.entry(doc).or_default() += s;
            }
        }
        let mut hits: Vec<TextHit> = scores
            .into_iter()
            .map(|(doc, score)| TextHit {
                id: idx.ids[doc as usize],
                lsn: idx.lsns[doc as usize],
                score,
            })
            .collect();
        hits.sort_by(|a, b| b.score.total_cmp(&a.score).then_with(|| a.lsn.cmp(&b.lsn)));
        hits.truncate(k);
        hits
    }

    fn corpus(n: usize, semente: u64) -> TextIndex {
        const PALAVRAS: [&str; 12] = [
            "rio", "fogo", "mudanca", "mesmo", "duas", "vezes", "agua", "pedra",
            "tempo", "medida", "alma", "logos",
        ];
        let mut rng = Rng(semente);
        let mut idx = TextIndex::new();
        for i in 0..n {
            let quantas = 3 + (rng.proximo() % 12) as usize;
            let texto: Vec<&str> = (0..quantas)
                .map(|_| PALAVRAS[(rng.proximo() % 12) as usize])
                .collect();
            let e = Episode::new("a", EventKind::Observation, texto.join(" ").into_bytes());
            idx.apply(i as u64, &e);
        }
        idx
    }

    /// A prova de que o acumulador denso nao mudou a resposta: mesmos
    /// documentos, mesma ordem, mesmos scores.
    #[test]
    fn o_acumulador_denso_concorda_com_o_hashmap() {
        for semente in [1u64, 7, 99] {
            let idx = corpus(300, semente);
            for consulta in ["rio", "fogo mudanca", "mesmo rio duas vezes", "logos", "inexistente"] {
                for k in [1usize, 5, 50, 400] {
                    let novo = idx.search(consulta, k);
                    let ref_ = search_referencia(&idx, consulta, k);
                    assert_eq!(
                        novo.len(),
                        ref_.len(),
                        "semente {semente} consulta {consulta:?} k={k}"
                    );
                    for (i, (a, b)) in novo.iter().zip(ref_.iter()).enumerate() {
                        assert_eq!(a.id, b.id, "posicao {i} de {consulta:?} k={k}");
                        assert!(
                            (a.score - b.score).abs() < 1e-5,
                            "score em {i}: {} vs {}",
                            a.score,
                            b.score
                        );
                    }
                }
            }
        }
    }

    /// O caso subtil que o acumulador por epoca introduz: ao dar a volta ao
    /// `u32`, uma marca antiga coincidiria com a epoca nova e um documento
    /// apareceria com o score de uma consulta anterior.
    #[test]
    fn o_transbordo_da_epoca_nao_traz_scores_de_outra_consulta() {
        let mut a = AcumuladorBm25::default();
        a.preparar(4);
        a.epoca = u32::MAX;
        a.somar(2, 5.0);
        assert_eq!(a.tocados, vec![2]);
        assert_eq!(a.scores[2], 5.0);

        a.preparar(4);
        assert_eq!(a.epoca, 1, "recomeca em 1, nao em 0");
        assert!(a.tocados.is_empty(), "a consulta nova comeca sem tocados");
        a.somar(2, 1.0);
        assert_eq!(
            a.scores[2], 1.0,
            "sem a limpeza, o 5.0 da consulta anterior teria sido somado"
        );
    }

    /// Somar duas vezes o mesmo documento na MESMA consulta acumula; em
    /// consultas diferentes, nao.
    #[test]
    fn somar_acumula_dentro_da_consulta_e_reinicia_entre_consultas() {
        let mut a = AcumuladorBm25::default();
        a.preparar(8);
        a.somar(3, 1.5);
        a.somar(3, 2.5);
        assert_eq!(a.scores[3], 4.0);
        assert_eq!(a.tocados, vec![3], "tocado uma so vez apesar de somado duas");
        a.preparar(8);
        a.somar(3, 1.0);
        assert_eq!(a.scores[3], 1.0);
    }
}

#[cfg(test)]
mod medicao_bm25 {
    use super::*;
    use heraclitus_core::EventKind;
    use std::time::Instant;

    /// `cargo test -p heraclitus-index-text --lib medicao -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn custo_da_consulta() {
        const PALAVRAS: [&str; 8] =
            ["rio", "fogo", "mudanca", "agua", "pedra", "tempo", "alma", "logos"];
        for n in [5_000usize, 50_000] {
            let mut idx = TextIndex::new();
            for i in 0..n {
                let texto: Vec<&str> = (0..8).map(|j| PALAVRAS[(i + j) % 8]).collect();
                let e = Episode::new("a", EventKind::Observation, texto.join(" ").into_bytes());
                idx.apply(i as u64, &e);
            }
            for _ in 0..5 {
                idx.search("rio fogo", 10);
            }
            let t0 = Instant::now();
            let mut total = 0usize;
            for _ in 0..100 {
                total += idx.search("rio fogo agua", 10).len();
            }
            let dt = t0.elapsed();
            println!(
                "n={n:>7}  100 consultas em {:>10.3?}  ({:>9.1?}/consulta, {total} hits)",
                dt,
                dt / 100
            );
        }
    }
}
