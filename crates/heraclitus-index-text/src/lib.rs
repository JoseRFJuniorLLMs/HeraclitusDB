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
        let mut scores: HashMap<u32, f32> = HashMap::new();
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
                *scores.entry(doc).or_default() += s;
            }
        }
        let mut hits: Vec<TextHit> = scores
            .into_iter()
            .map(|(doc, score)| TextHit {
                id: self.ids[doc as usize],
                lsn: self.lsns[doc as usize],
                score,
            })
            .collect();
        // Desempate por LSN: os scores saem de um HashMap (ordem de iteração
        // aleatória por seed) — sem isto, docs com score igual entravam/saíam
        // do top-k de forma não-determinística entre execuções.
        hits.sort_by(|a, b| b.score.total_cmp(&a.score).then_with(|| a.lsn.cmp(&b.lsn)));
        hits.truncate(k);
        hits
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
