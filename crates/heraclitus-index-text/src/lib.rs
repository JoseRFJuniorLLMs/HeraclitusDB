//! heraclitus-index-text — derived BM25 inverted index (§3.6).

use heraclitus_core::{Episode, EventId, Lsn};
use heraclitus_memtable::tokenize;
use heraclitus_views::View;
use std::cmp::Ordering;
use std::collections::{BinaryHeap, HashMap};

const K1: f32 = 1.2;
const B: f32 = 0.75;
const POSTING_BLOCK_SIZE: usize = 128;

type TermId = u32;

/// Estatisticas suficientes para um limite superior BM25 seguro dentro de um
/// bloco. O limite usa `max_tf` e `min_doc_len`, mesmo que venham de documentos
/// diferentes: isso o torna deliberadamente conservador, nunca optimista.
#[derive(Debug, Clone, Copy)]
struct PostingBlock {
    start_doc_byte: usize,
    start_tf_byte: usize,
    count: u16,
    end_doc: u32,
    max_tf: u32,
    min_doc_len: u32,
}

/// Posting list residente em blocos delta-varint. O primeiro DocId de cada
/// bloco é absoluto; os restantes são deltas monotónicos. TFs usam o mesmo
/// codec em outro fluxo, para que o WAND possa saltar blocos sem decodificá-los.
/// O layout anterior gastava oito bytes por posting (`u32` DocId + `u32` TF);
/// texto real costuma gastar um byte por delta e um por TF.
#[derive(Debug, Clone, Default)]
struct PostingList {
    doc_bytes: Vec<u8>,
    tf_bytes: Vec<u8>,
    blocks: Vec<PostingBlock>,
    len: usize,
    last_doc: u32,
    max_tf: u32,
    min_doc_len: u32,
}

impl PostingList {
    fn push(&mut self, doc: u32, tf: u32, doc_len: u32) {
        debug_assert!(self.len == 0 || self.last_doc < doc);

        let starts_block = self.len.is_multiple_of(POSTING_BLOCK_SIZE);
        if starts_block {
            self.blocks.push(PostingBlock {
                start_doc_byte: self.doc_bytes.len(),
                start_tf_byte: self.tf_bytes.len(),
                count: 0,
                end_doc: doc,
                max_tf: tf,
                min_doc_len: doc_len,
            });
            encode_varint(doc, &mut self.doc_bytes);
        } else {
            encode_varint(doc - self.last_doc, &mut self.doc_bytes);
        }
        encode_varint(tf, &mut self.tf_bytes);

        if self.len == 0 {
            self.max_tf = tf;
            self.min_doc_len = doc_len;
        } else {
            self.max_tf = self.max_tf.max(tf);
            self.min_doc_len = self.min_doc_len.min(doc_len);
        }
        if let Some(block) = self.blocks.last_mut() {
            block.count += 1;
            block.end_doc = doc;
            block.max_tf = block.max_tf.max(tf);
            block.min_doc_len = block.min_doc_len.min(doc_len);
        }
        self.last_doc = doc;
        self.len += 1;
    }

    fn from_pairs(mut pairs: Vec<(u32, u32)>, doc_lens: &[u32]) -> Self {
        pairs.sort_unstable_by_key(|(doc, _)| *doc);
        let mut out = Self::default();
        for (doc, tf) in pairs {
            let dl = doc_lens.get(doc as usize).copied().unwrap_or_default();
            out.push(doc, tf, dl);
        }
        out
    }

    fn pairs(&self) -> Vec<(u32, u32)> {
        self.iter().collect()
    }

    fn iter(&self) -> PostingIter<'_> {
        PostingIter::new(self)
    }

    #[inline]
    fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Bytes do payload residente, sem contar a metadata de bloco.
    #[cfg(test)]
    fn encoded_payload_bytes(&self) -> usize {
        self.doc_bytes.len() + self.tf_bytes.len()
    }
}

#[inline]
fn encode_varint(mut value: u32, out: &mut Vec<u8>) {
    while value >= 0x80 {
        out.push((value as u8 & 0x7f) | 0x80);
        value >>= 7;
    }
    out.push(value as u8);
}

#[inline(always)]
fn decode_varint(bytes: &[u8], offset: &mut usize) -> u32 {
    // Doc deltas e TFs reais quase sempre cabem num byte. Manter esse caso
    // fora do laço reduz o decode comum a uma leitura, um incremento e um teste.
    let first = bytes[*offset];
    *offset += 1;
    if first < 0x80 {
        return u32::from(first);
    }
    let mut value = u32::from(first & 0x7f);

    let second = bytes[*offset];
    *offset += 1;
    value |= u32::from(second & 0x7f) << 7;
    if second < 0x80 {
        return value;
    }

    let third = bytes[*offset];
    *offset += 1;
    value |= u32::from(third & 0x7f) << 14;
    if third < 0x80 {
        return value;
    }

    let fourth = bytes[*offset];
    *offset += 1;
    value |= u32::from(fourth & 0x7f) << 21;
    if fourth < 0x80 {
        return value;
    }

    let fifth = bytes[*offset];
    *offset += 1;
    debug_assert_eq!(fifth & 0xf0, 0, "varint interno excede u32");
    value | (u32::from(fifth) << 28)
}

struct PostingIter<'a> {
    list: &'a PostingList,
    block: usize,
    within: u16,
    doc_offset: usize,
    tf_offset: usize,
    previous_doc: u32,
    remaining: usize,
}

impl<'a> PostingIter<'a> {
    fn new(list: &'a PostingList) -> Self {
        let (doc_offset, tf_offset) = list
            .blocks
            .first()
            .map_or((0, 0), |block| (block.start_doc_byte, block.start_tf_byte));
        Self {
            list,
            block: 0,
            within: 0,
            doc_offset,
            tf_offset,
            previous_doc: 0,
            remaining: list.len,
        }
    }
}

impl Iterator for PostingIter<'_> {
    type Item = (u32, u32);

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }
        let block = self.list.blocks[self.block];
        if self.within == block.count {
            self.block += 1;
            let block = self.list.blocks[self.block];
            self.within = 0;
            self.doc_offset = block.start_doc_byte;
            self.tf_offset = block.start_tf_byte;
        }
        let encoded_doc = decode_varint(&self.list.doc_bytes, &mut self.doc_offset);
        let doc = if self.within == 0 {
            encoded_doc
        } else {
            self.previous_doc + encoded_doc
        };
        let tf = decode_varint(&self.list.tf_bytes, &mut self.tf_offset);
        self.previous_doc = doc;
        self.within += 1;
        self.remaining -= 1;
        Some((doc, tf))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.remaining, Some(self.remaining))
    }
}

impl ExactSizeIterator for PostingIter<'_> {}

#[derive(Default)]
pub struct TextIndex {
    /// Dicionario de termos: a `String` existe uma vez; os restantes caminhos
    /// trabalham com `TermId` denso e postings contiguos.
    terms: HashMap<String, TermId>,
    postings: Vec<PostingList>,
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

/// Acumulador de scores BM25 denso da implementação anterior. Mantido apenas
/// como oráculo dos testes de equivalência do caminho WAND.
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
#[cfg(test)]
#[derive(Debug, Default)]
struct AcumuladorBm25 {
    scores: Vec<f32>,
    marcas: Vec<u32>,
    tocados: Vec<u32>,
    epoca: u32,
}

#[cfg(test)]
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

#[derive(Debug, Clone, Copy)]
struct RankedDoc {
    doc: u32,
    lsn: Lsn,
    score: f32,
}

impl PartialEq for RankedDoc {
    fn eq(&self, other: &Self) -> bool {
        self.doc == other.doc && self.score.to_bits() == other.score.to_bits()
    }
}

impl Eq for RankedDoc {}

/// O maior elemento do heap é o PIOR resultado: menor score; em empate, maior
/// LSN. Assim `peek()` é o limiar atual em O(1).
impl Ord for RankedDoc {
    fn cmp(&self, other: &Self) -> Ordering {
        other
            .score
            .total_cmp(&self.score)
            .then_with(|| self.lsn.cmp(&other.lsn))
            .then_with(|| self.doc.cmp(&other.doc))
    }
}

impl PartialOrd for RankedDoc {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[derive(Debug, Default, Clone, Copy)]
struct WandStats {
    postings_scored: usize,
    postings_skipped: usize,
    documents_scored: usize,
    blocks_skipped: usize,
}

struct WandCursor<'a> {
    list: &'a PostingList,
    idf: f32,
    block: usize,
    within: u16,
    doc_offset: usize,
    tf_offset: usize,
    current_doc: Option<u32>,
    current_tf: u32,
}

impl<'a> WandCursor<'a> {
    fn new(list: &'a PostingList, idf: f32) -> Option<Self> {
        if list.is_empty() {
            return None;
        }
        let first = list.blocks[0];
        let mut out = Self {
            list,
            idf,
            block: 0,
            within: 0,
            doc_offset: first.start_doc_byte,
            tf_offset: first.start_tf_byte,
            current_doc: None,
            current_tf: 0,
        };
        // `debug_assert!` NAO avalia a expressao em release. Estando a chamada
        // aqui dentro, `load_first_in_block` simplesmente desaparecia da build
        // de producao: todos os cursores nasciam com `current_doc = None` e a
        // pesquisa WAND devolvia resultados errados — enquanto os testes, que
        // correm em debug, passavam todos. O oraculo de equivalencia existia e
        // estava certo; nunca tinha corrido em release.
        //
        // A carga faz parte da construcao, nao e uma verificacao: se o primeiro
        // bloco nao carrega, nao ha cursor.
        if !out.load_first_in_block() {
            return None;
        }
        Some(out)
    }

    fn load_first_in_block(&mut self) -> bool {
        let Some(block) = self.list.blocks.get(self.block).copied() else {
            return false;
        };
        self.doc_offset = block.start_doc_byte;
        self.tf_offset = block.start_tf_byte;
        self.current_doc = Some(decode_varint(&self.list.doc_bytes, &mut self.doc_offset));
        self.current_tf = decode_varint(&self.list.tf_bytes, &mut self.tf_offset);
        self.within = 1;
        true
    }

    fn current_doc(&self) -> Option<u32> {
        self.current_doc
    }

    fn current_tf(&self) -> u32 {
        self.current_tf
    }

    fn current_block(&self) -> PostingBlock {
        self.list.blocks[self.block]
    }

    fn global_upper(&self, avgdl: f32) -> f64 {
        bm25_upper(self.idf, self.list.max_tf, self.list.min_doc_len, avgdl)
    }

    fn block_upper(&self, avgdl: f32) -> f64 {
        let block = self.current_block();
        bm25_upper(self.idf, block.max_tf, block.min_doc_len, avgdl)
    }

    fn advance_one(&mut self) {
        let Some(previous_doc) = self.current_doc else {
            return;
        };
        let block = self.current_block();
        if self.within < block.count {
            let delta = decode_varint(&self.list.doc_bytes, &mut self.doc_offset);
            self.current_doc = Some(previous_doc + delta);
            self.current_tf = decode_varint(&self.list.tf_bytes, &mut self.tf_offset);
            self.within += 1;
        } else {
            self.block += 1;
            if !self.load_first_in_block() {
                self.current_doc = None;
            }
        }
    }

    fn advance_to(&mut self, target: u32, stats: &mut WandStats) {
        // Metadata de bloco permite saltar bytes sem procurar offsets por
        // posting. Conta-se inclusive o posting corrente, pois end_doc < target.
        while self.current_doc.is_some() && self.current_block().end_doc < target {
            let remaining = usize::from(self.current_block().count - self.within + 1);
            stats.postings_skipped += remaining;
            self.block += 1;
            if !self.load_first_in_block() {
                self.current_doc = None;
                return;
            }
        }
        while self.current_doc.is_some_and(|doc| doc < target) {
            stats.postings_skipped += 1;
            self.advance_one();
        }
    }

    fn exhaust(&mut self, stats: &mut WandStats) {
        if self.current_doc.is_none() {
            return;
        }
        let current_remaining = usize::from(self.current_block().count - self.within + 1);
        let later: usize = self.list.blocks[self.block + 1..]
            .iter()
            .map(|block| usize::from(block.count))
            .sum();
        stats.postings_skipped += current_remaining + later;
        self.block = self.list.blocks.len();
        self.current_doc = None;
    }
}

#[inline]
fn bm25_score(idf: f32, tf: u32, doc_len: u32, avgdl: f32) -> f32 {
    let tf = tf as f32;
    let dl = doc_len as f32;
    idf * (tf * (K1 + 1.0)) / (tf + K1 * (1.0 - B + B * dl / avgdl))
}

/// Limite superior conservador. O cálculo em f64 e a margem final impedem que
/// arredondamento faça o WAND eliminar um documento cujo score f32 seria válido.
#[inline]
fn bm25_upper(idf: f32, max_tf: u32, min_doc_len: u32, avgdl: f32) -> f64 {
    let tf = max_tf as f64;
    let dl = min_doc_len as f64;
    let avgdl = avgdl as f64;
    let exact = idf as f64 * (tf * (K1 as f64 + 1.0))
        / (tf + K1 as f64 * (1.0 - B as f64 + B as f64 * dl / avgdl));
    exact * (1.0 + 1e-6) + 1e-6
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
        self.search_wand(query, k).0
    }

    /// Block-Max WAND exato. Os limites superiores só decidem que documentos
    /// NÃO precisam ser pontuados; todo documento que entra no Top-K recebe o
    /// BM25 canónico e o desempate por LSN continua idêntico ao caminho exaustivo.
    fn search_wand(&self, query: &str, k: usize) -> (Vec<TextHit>, WandStats) {
        let mut stats = WandStats::default();
        let n = self.ids.len() as f32;
        if n == 0.0 || k == 0 {
            return (Vec::new(), stats);
        }
        let avgdl = (self.total_len as f32 / n).max(1.0);
        let mut cursors: Vec<WandCursor<'_>> = tokenize(query)
            .into_iter()
            .filter_map(|term| {
                let term_id = *self.terms.get(&term)? as usize;
                let list = self.postings.get(term_id)?;
                if list.is_empty() {
                    return None;
                }
                let df = list.len as f32;
                let idf = ((n - df + 0.5) / (df + 0.5) + 1.0).ln();
                WandCursor::new(list, idf)
            })
            .collect();
        if cursors.is_empty() {
            return (Vec::new(), stats);
        }

        let mut heap: BinaryHeap<RankedDoc> = BinaryHeap::with_capacity(k + 1);
        let mut order: Vec<usize> = Vec::with_capacity(cursors.len());

        loop {
            order.clear();
            order.extend((0..cursors.len()).filter(|i| cursors[*i].current_doc().is_some()));
            if order.is_empty() {
                break;
            }

            let threshold = heap.peek().map_or(0.0, |hit| hit.score) as f64;

            // Block-Max: enquanto todos os cursores permanecerem nos blocos
            // correntes, a soma destes limites vale para qualquer documento até
            // `safe_end`. Se nem ela alcança o limiar, salta o intervalo inteiro.
            if heap.len() == k {
                let block_upper: f64 = order.iter().map(|i| cursors[*i].block_upper(avgdl)).sum();
                if block_upper < threshold {
                    let safe_end = order
                        .iter()
                        .map(|i| cursors[*i].current_block().end_doc)
                        .min()
                        .unwrap_or(u32::MAX);
                    let target = safe_end.saturating_add(1);
                    for &i in &order {
                        if cursors[i].current_doc().is_some_and(|doc| doc <= safe_end) {
                            if safe_end == u32::MAX {
                                cursors[i].exhaust(&mut stats);
                            } else {
                                cursors[i].advance_to(target, &mut stats);
                            }
                        }
                    }
                    stats.blocks_skipped += 1;
                    continue;
                }
            }

            order.sort_unstable_by_key(|i| cursors[*i].current_doc().unwrap_or(u32::MAX));
            let first_doc = cursors[order[0]].current_doc().expect("cursor ativo");

            // WAND: acha o primeiro pivot cuja soma dos limites globais pode
            // alcançar o limiar corrente.
            let mut upper = 0.0f64;
            let mut pivot_doc = None;
            for &i in &order {
                upper += cursors[i].global_upper(avgdl);
                if heap.len() < k || upper >= threshold {
                    pivot_doc = cursors[i].current_doc();
                    break;
                }
            }
            let Some(pivot_doc) = pivot_doc else {
                break;
            };

            if first_doc != pivot_doc {
                for &i in &order {
                    match cursors[i].current_doc() {
                        Some(doc) if doc < pivot_doc => {
                            cursors[i].advance_to(pivot_doc, &mut stats);
                        }
                        _ => break,
                    }
                }
                continue;
            }

            // A ordem dos cursores é a ordem dos termos da consulta. Somar nessa
            // ordem preserva inclusive o arredondamento f32 do caminho anterior.
            let mut score = 0.0f32;
            for cursor in &cursors {
                if cursor.current_doc() == Some(first_doc) {
                    stats.postings_scored += 1;
                    score += bm25_score(
                        cursor.idf,
                        cursor.current_tf(),
                        self.doc_len[first_doc as usize],
                        avgdl,
                    );
                }
            }
            stats.documents_scored += 1;
            let candidate = RankedDoc {
                doc: first_doc,
                lsn: self.lsns[first_doc as usize],
                score,
            };
            if heap.len() < k {
                heap.push(candidate);
            } else if heap.peek().is_some_and(|worst| {
                candidate.score > worst.score
                    || (candidate.score.to_bits() == worst.score.to_bits()
                        && (candidate.lsn, candidate.doc) < (worst.lsn, worst.doc))
            }) {
                heap.pop();
                heap.push(candidate);
            }
            for cursor in &mut cursors {
                if cursor.current_doc() == Some(first_doc) {
                    cursor.advance_one();
                }
            }
        }

        let mut hits: Vec<TextHit> = heap
            .into_iter()
            .map(|hit| TextHit {
                id: self.ids[hit.doc as usize],
                lsn: hit.lsn,
                score: hit.score,
            })
            .collect();
        hits.sort_by(|a, b| b.score.total_cmp(&a.score).then_with(|| a.lsn.cmp(&b.lsn)));
        (hits, stats)
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
        // O formato persistido permanece compatível com o snapshot anterior.
        // TermId e blocos são estado derivado e barato de reconstruir; não há
        // motivo para invalidar checkpoints por uma optimização residente.
        let postings: HashMap<String, Vec<(u32, u32)>> = self
            .terms
            .iter()
            .filter_map(|(term, id)| {
                self.postings
                    .get(*id as usize)
                    .map(|list| (term.clone(), list.pairs()))
            })
            .collect();
        heraclitus_views::ckpt::save(
            dir,
            "text",
            &TextSnapshot {
                postings,
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
        let TextSnapshot {
            postings,
            doc_len,
            ids,
            lsns,
            total_len,
            watermark,
        } = snap;
        // COERÊNCIA antes de adoptar o checkpoint. Um checkpoint que descodifica
        // mas é inconsistente — um `doc_id` numa posting além do número de
        // documentos, ou os arrays por-documento com tamanhos diferentes — não
        // falhava aqui: falhava DEPOIS, num índice fora de limites durante a
        // pesquisa, que entra em pânico e ENVENENA o RwLock do índice (todas as
        // pesquisas seguintes abortam). O contrato do checkpoint é degradar para
        // rebuild quando é inutilizável; validar aqui honra-o.
        let n_docs = ids.len();
        if doc_len.len() != n_docs || lsns.len() != n_docs {
            return Ok(false);
        }
        if postings
            .values()
            .flatten()
            .any(|(doc_id, _tf)| *doc_id as usize >= n_docs)
        {
            return Ok(false);
        }
        self.by_event = ids
            .iter()
            .enumerate()
            .map(|(i, id)| (*id, i as u32))
            .collect();
        self.terms.clear();
        self.postings.clear();
        let mut ordered: Vec<(String, Vec<(u32, u32)>)> = postings.into_iter().collect();
        ordered.sort_unstable_by(|a, b| a.0.cmp(&b.0));
        for (term, pairs) in ordered {
            let id = self.postings.len() as TermId;
            self.terms.insert(term, id);
            self.postings.push(PostingList::from_pairs(pairs, &doc_len));
        }
        self.doc_len = doc_len;
        self.ids = ids;
        self.lsns = lsns;
        self.total_len = total_len;
        self.watermark = watermark;
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
        let document_len = tokens.len() as u32;
        let doc = self.ids.len() as u32;
        self.by_event.insert(event.id, doc);
        self.ids.push(event.id);
        self.lsns.push(lsn);
        self.doc_len.push(document_len);
        self.total_len += document_len as u64;

        let mut tf: HashMap<String, u32> = HashMap::new();
        for t in tokens {
            *tf.entry(t).or_default() += 1;
        }
        // HashMap não tem ordem determinística. Ordenar apenas os termos únicos
        // deste documento torna a atribuição de TermIds determinística em todo
        // replay. O restore também é determinístico, embora IDs internos não
        // façam parte do contrato e possam ser renumerados lexicalmente.
        let mut tf: Vec<(String, u32)> = tf.into_iter().collect();
        tf.sort_unstable_by(|a, b| a.0.cmp(&b.0));
        for (term, count) in tf {
            let term_id = match self.terms.get(&term).copied() {
                Some(id) => id,
                None => {
                    let id = self.postings.len() as TermId;
                    self.terms.insert(term, id);
                    self.postings.push(PostingList::default());
                    id
                }
            };
            self.postings[term_id as usize].push(doc, count, document_len);
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

    /// Um checkpoint decodável mas INCOERENTE — um `doc_id` numa posting além
    /// do número de documentos — não falhava no restore: falhava depois, num
    /// índice fora de limites durante a pesquisa, que entra em pânico e envenena
    /// o RwLock do índice. Agora o restore valida a coerência e degrada para
    /// rebuild (`Ok(false)`).
    #[test]
    fn checkpoint_incoerente_degrada_em_vez_de_panicar() {
        let dir = tempfile::tempdir().unwrap();
        let mut idx = TextIndex::new();
        for (i, d) in ["gato preto", "gato branco"].iter().enumerate() {
            let e = Episode::new("a", EventKind::Observation, d.as_bytes().to_vec());
            idx.apply(i as u64, &e);
        }
        idx.checkpoint(dir.path()).unwrap();

        // Escrever um checkpoint INCOERENTE à mão: dois documentos, mas uma
        // posting que aponta para o documento 99 (fora de `ids.len()`).
        let mut postings: HashMap<String, Vec<(u32, u32)>> = HashMap::new();
        postings.insert("gato".into(), vec![(0, 1), (1, 1)]);
        postings.insert("fantasma".into(), vec![(99, 1)]);
        heraclitus_views::ckpt::save(
            dir.path(),
            "text",
            &TextSnapshot {
                postings,
                doc_len: vec![2, 2],
                ids: vec![EventId::new(), EventId::new()],
                lsns: vec![0, 1],
                total_len: 4,
                watermark: 1,
            },
        )
        .unwrap();

        let mut fresco = TextIndex::new();
        assert!(
            !fresco.restore(dir.path()).unwrap(),
            "checkpoint com doc_id fora de intervalo degrada para rebuild"
        );
        // E uma pesquisa no índice fresco não panica (ficou vazio, a reconstruir).
        let _ = fresco.search("gato", 3);
    }
}

#[cfg(test)]
mod testes_acumulador {
    use super::*;
    use heraclitus_core::EventKind;
    use std::collections::HashMap;
    use std::mem::size_of;

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
            let Some(term_id) = idx.terms.get(&term).copied() else {
                continue;
            };
            let Some(plist) = idx.postings.get(term_id as usize) else {
                continue;
            };
            let df = plist.len as f32;
            let idf = ((n - df + 0.5) / (df + 0.5) + 1.0).ln();
            for (doc, tf) in plist.iter() {
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
            "rio", "fogo", "mudanca", "mesmo", "duas", "vezes", "agua", "pedra", "tempo", "medida",
            "alma", "logos",
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
            for consulta in [
                "rio",
                "fogo mudanca",
                "mesmo rio duas vezes",
                "logos",
                "inexistente",
            ] {
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
        assert_eq!(
            a.tocados,
            vec![3],
            "tocado uma so vez apesar de somado duas"
        );
        a.preparar(8);
        a.somar(3, 1.0);
        assert_eq!(a.scores[3], 1.0);
    }

    /// Distribuição adversarial para a busca exaustiva: um termo ubíquo com
    /// milhares de postings e um termo muito forte apenas no início. Depois de
    /// encher o heap, Block-Max deve provar que a cauda inteira não compete.
    #[test]
    fn block_max_salta_a_cauda_sem_mudar_o_top_k() {
        let mut idx = TextIndex::new();
        for i in 0..10_000usize {
            let text = if i < 12 {
                "comum raro raro raro raro raro raro raro raro"
            } else {
                "comum"
            };
            let e = Episode::new("a", EventKind::Observation, text.as_bytes().to_vec());
            idx.apply(i as u64, &e);
        }

        let (novo, stats) = idx.search_wand("comum raro", 5);
        let referencia = search_referencia(&idx, "comum raro", 5);
        assert_eq!(novo.len(), referencia.len());
        for (a, b) in novo.iter().zip(&referencia) {
            assert_eq!(a.id, b.id);
            assert_eq!(a.score.to_bits(), b.score.to_bits());
        }
        assert!(
            stats.blocks_skipped > 0,
            "nenhum bloco foi podado: {stats:?}"
        );
        assert!(
            stats.documents_scored < 100,
            "pontuou quase o corpus inteiro em vez de podar a cauda: {stats:?}"
        );
        assert!(stats.postings_scored < 100);
        assert!(stats.postings_skipped > 9_000);
    }

    /// O layout residente mudou, mas o snapshot em disco deliberadamente não.
    /// Um round-trip prova que TermIds e estatísticas de bloco são reconstruídos.
    #[test]
    fn checkpoint_antigo_reconstroi_dicionario_e_blocos() {
        let idx = corpus(500, 123);
        let esperado = idx.search("rio fogo mudanca", 25);
        let dir = tempfile::tempdir().unwrap();
        idx.checkpoint(dir.path()).unwrap();

        let mut restaurado = TextIndex::new();
        assert!(restaurado.restore(dir.path()).unwrap());
        let obtido = restaurado.search("rio fogo mudanca", 25);
        assert_eq!(esperado.len(), obtido.len());
        for (a, b) in esperado.iter().zip(&obtido) {
            assert_eq!(
                (a.id, a.lsn, a.score.to_bits()),
                (b.id, b.lsn, b.score.to_bits())
            );
        }
        assert!(restaurado.postings.iter().all(|p| !p.blocks.is_empty()));
    }

    #[test]
    fn delta_varint_faz_roundtrip_inclusive_nas_fronteiras_de_bloco() {
        let mut list = PostingList::default();
        let mut esperado = Vec::new();
        let mut doc = 0u32;
        for index in 0..(POSTING_BLOCK_SIZE * 3 + 17) {
            // Alterna deltas de uma e várias bytes; o primeiro posting de cada
            // bloco é absoluto e os demais são relativos.
            doc = doc
                .checked_add(if index % 31 == 0 { 20_000 } else { 1 })
                .unwrap();
            let tf = if index == POSTING_BLOCK_SIZE {
                u32::MAX
            } else {
                (index % 300 + 1) as u32
            };
            list.push(doc, tf, 10 + (index % 50) as u32);
            esperado.push((doc, tf));
        }
        assert_eq!(list.pairs(), esperado);
        assert_eq!(list.len, POSTING_BLOCK_SIZE * 3 + 17);
        assert_eq!(list.blocks.len(), 4);
        assert_eq!(list.blocks[0].count as usize, POSTING_BLOCK_SIZE);
        assert_eq!(list.blocks[3].count, 17);
        assert_eq!(list.blocks[3].end_doc, esperado.last().unwrap().0);
    }

    #[test]
    fn delta_varint_reduz_o_payload_residente_no_caso_comum() {
        let mut list = PostingList::default();
        for doc in 0..100_000u32 {
            list.push(doc, 1, 12);
        }
        let plain_bytes = list.len * (size_of::<u32>() + size_of::<u32>());
        let compressed_bytes =
            list.encoded_payload_bytes() + list.blocks.len() * size_of::<PostingBlock>();
        assert!(
            compressed_bytes < plain_bytes / 3,
            "delta-varint+blocos={compressed_bytes} bytes, SoA u32={plain_bytes} bytes"
        );
        assert_eq!(list.iter().count(), 100_000);
    }

    /// A/B manual: custo de percorrer o codec contra dois `u32` residentes.
    /// A memória é gate no teste acima; temporização é apenas evidência, não
    /// assert de CI sujeito a ruído de scheduler.
    #[test]
    #[ignore = "microbenchmark manual do decode delta-varint"]
    fn mede_decode_delta_varint_contra_u32_plain() {
        use std::hint::black_box;
        use std::time::Instant;

        let plain: Vec<(u32, u32)> = (0..1_000_000u32)
            .map(|doc| (doc.saturating_mul(3), doc % 7 + 1))
            .collect();
        let list = PostingList::from_pairs(plain.clone(), &vec![12; plain.len()]);

        let inicio = Instant::now();
        let mut compressed_sink = 0u64;
        for _ in 0..10 {
            for (doc, tf) in list.iter() {
                compressed_sink = compressed_sink.wrapping_add(u64::from(doc ^ tf));
            }
        }
        let compressed_time = inicio.elapsed();

        let inicio = Instant::now();
        let mut plain_sink = 0u64;
        for _ in 0..10 {
            for &(doc, tf) in &plain {
                plain_sink = plain_sink.wrapping_add(u64::from(doc ^ tf));
            }
        }
        let plain_time = inicio.elapsed();
        assert_eq!(black_box(compressed_sink), black_box(plain_sink));

        let plain_bytes = plain.len() * size_of::<(u32, u32)>();
        let compressed_bytes =
            list.encoded_payload_bytes() + list.blocks.len() * size_of::<PostingBlock>();
        eprintln!(
            "postings={} compressed={compressed_bytes}B plain={plain_bytes}B ratio={:.3} decode={compressed_time:?} plain-scan={plain_time:?}",
            plain.len(),
            compressed_bytes as f64 / plain_bytes as f64
        );
    }

    /// `cargo test -p heraclitus-index-text --lib mede_block_max -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn mede_block_max_contra_varrimento_exaustivo() {
        use std::time::Instant;

        let mut idx = TextIndex::new();
        for i in 0..100_000usize {
            let text = if i < 32 {
                "comum raro raro raro raro raro raro raro raro"
            } else {
                "comum"
            };
            let e = Episode::new("a", EventKind::Observation, text.as_bytes().to_vec());
            idx.apply(i as u64, &e);
        }
        let query = "comum raro";
        let esperado = search_referencia(&idx, query, 10);
        let (obtido, stats) = idx.search_wand(query, 10);
        assert_eq!(
            esperado.iter().map(|h| h.id).collect::<Vec<_>>(),
            obtido.iter().map(|h| h.id).collect::<Vec<_>>()
        );

        let t0 = Instant::now();
        for _ in 0..50 {
            std::hint::black_box(idx.search_wand(query, 10));
        }
        let wand = t0.elapsed();
        let t1 = Instant::now();
        for _ in 0..50 {
            std::hint::black_box(search_referencia(&idx, query, 10));
        }
        let exaustivo = t1.elapsed();
        println!(
            "docs=100000 consultas=50 WAND={wand:.3?} exaustivo={exaustivo:.3?} ganho={:.1}x stats={stats:?}",
            exaustivo.as_secs_f64() / wand.as_secs_f64().max(1e-9)
        );
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
        const PALAVRAS: [&str; 8] = [
            "rio", "fogo", "mudanca", "agua", "pedra", "tempo", "alma", "logos",
        ];
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
