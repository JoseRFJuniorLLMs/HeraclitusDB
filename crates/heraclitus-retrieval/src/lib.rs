//! heraclitus-retrieval — two stages (§3.8).
//!
//! 1. **Recall**: ANN top-N ∥ BM25 top-N ∥ activation top-N, fused with RRF.
//! 2. **Rerank**: pluggable [`Reranker`]; default is a calibrated linear
//!    blend. Feedback is persisted as ordinary log events
//!    (`kind = RetrievalFeedback`) so rerankers can be retrained offline
//!    from the log itself.

use heraclitus_core::{Episode, EventId, EventKind, HeraclitusError, Lsn};
use heraclitus_log::EpisodeLog;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

pub const RRF_K: f64 = 60.0;
pub const RECALL_N: usize = 200;

/// One fused candidate after recall.
#[derive(Debug, Clone)]
pub struct Candidate {
    pub id: EventId,
    pub lsn: Lsn,
    pub rrf: f64,
    /// Raw per-channel signals for the reranker.
    pub vec_dist: Option<f32>,
    pub bm25: Option<f32>,
    pub activation: Option<f32>,
}

/// Reciprocal Rank Fusion over ranked id lists (k = 60).
pub fn rrf_fuse(lists: &[Vec<EventId>]) -> Vec<(EventId, f64)> {
    let mut scores: HashMap<EventId, f64> = HashMap::new();
    for list in lists {
        // Cada lista é um RANKING: `RRF(d) = Σ_L 1/(k + rank_L(d))` pressupõe
        // que dentro de uma lista cada documento tem UMA posição. Somar duas
        // ocorrências do mesmo id na mesma lista inflava-o sem acordo entre
        // canais nenhum — e é o acordo entre canais que o RRF existe para
        // premiar (auditoria 2026-09-05, A10). Fica-se com o MELHOR rank, que
        // é o primeiro visto. Endurecer aqui torna a definição imune a um
        // caller descuidado, mesmo depois de o caller ter sido corrigido.
        let mut vistos: std::collections::HashSet<EventId> = std::collections::HashSet::new();
        for (rank, id) in list.iter().enumerate() {
            if vistos.insert(*id) {
                *scores.entry(*id).or_default() += 1.0 / (RRF_K + rank as f64 + 1.0);
            }
        }
    }
    let mut out: Vec<(EventId, f64)> = scores.into_iter().collect();
    // Desempate determinístico por EventId: os candidatos vêm de um HashMap, e
    // empates de RRF (comuns) ficariam em ordem de iteração não-determinística
    // (seed do SipHash) ⇒ o corte RECALL_N e o top-k variavam entre execuções.
    out.sort_by(|a, b| b.1.total_cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    out
}

/// Stage-2 scorer. Implementations must be deterministic given the same
/// model state.
pub trait Reranker: Send + Sync {
    fn score(&self, query: &str, candidate: &Candidate) -> f32;
    /// Feedback hook; implementations may buffer for offline retraining.
    fn observe(&mut self, _query_id: &str, _chosen: &EventId, _outcome: f32) {}
}

/// Default: calibrated linear blend of (manifold distance, BM25, activation,
/// recency-by-lsn). Weights are deliberately boring and inspectable.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinearReranker {
    pub w_vec: f32,
    pub w_bm25: f32,
    pub w_act: f32,
    pub w_recency: f32,
    pub head_lsn: Lsn,
}

impl Default for LinearReranker {
    fn default() -> Self {
        Self {
            w_vec: 1.0,
            w_bm25: 0.5,
            w_act: 0.3,
            w_recency: 0.1,
            head_lsn: 0,
        }
    }
}

impl Reranker for LinearReranker {
    fn score(&self, _query: &str, c: &Candidate) -> f32 {
        let vec_sim = c.vec_dist.map(|d| 1.0 / (1.0 + d)).unwrap_or(0.0);
        // Auditoria 2026-09-05 (A09): o BM25 que chega aqui não tem tecto — é a
        // soma sobre os termos de idf*(K1+1) (heraclitus-index-text), e o
        // memtable injecta no mesmo canal `tf` em bruto. `tanh(b)` já vale
        // EXACTAMENTE 1.0f32 para b >= ~9.1 (e partilha bit-pattern desde ~8.5),
        // ou seja acima do joelho o sinal textual virava uma constante e a ordem
        // final passava a ser decidida só pela recência (w_recency = 0.1 chega
        // para inverter dois documentos com 3x de diferença em BM25).
        // `b/(1+b)` fica no mesmo contradomínio [0,1) mas mantém-se
        // estritamente monótono em toda a gama alcançável (derivada 2.3e-3 em
        // b=20, cinco ordens de grandeza acima de tanh). As duas guardas são
        // necessárias porque o canal vem de fora: `max(0.0)` afasta o pólo em
        // b = -1 e neutraliza o NaN (f32::max devolve o operando não-NaN —
        // `clamp` NÃO serve, propaga NaN), e o `is_finite` tapa o +inf, que com
        // `tanh` dava 1.0 e aqui daria inf/inf = NaN; 1.0 é o supremo de
        // b/(1+b), portanto a monotonia mantém-se no limite.
        let b = c.bm25.unwrap_or(0.0).max(0.0);
        let bm25 = if b.is_finite() { b / (1.0 + b) } else { 1.0 };
        let act = c.activation.map(|a| a.max(-5.0) / 5.0).unwrap_or(0.0);
        let recency = if self.head_lsn > 0 {
            (c.lsn as f32) / (self.head_lsn as f32)
        } else {
            0.0
        };
        self.w_vec * vec_sim + self.w_bm25 * bm25 + self.w_act * act + self.w_recency * recency
    }
}

/// Feedback payload persisted to the log (kind = RetrievalFeedback).
#[derive(Debug, Serialize, Deserialize)]
pub struct RetrievalFeedback {
    pub query_id: String,
    pub chosen: EventId,
    pub outcome: f32,
}

/// Append a feedback event to the log so rerankers can be retrained offline.
pub fn log_feedback<L: EpisodeLog + ?Sized>(
    log: &L,
    agent_id: &str,
    fb: &RetrievalFeedback,
) -> Result<Lsn, HeraclitusError> {
    let payload =
        serde_json::to_vec(fb).map_err(|e| HeraclitusError::Serialization(e.to_string()))?;
    log.append(Episode::new(
        agent_id,
        EventKind::RetrievalFeedback,
        payload,
    ))
}

/// Inputs to the recall stage: pre-ranked channel results.
///
/// Cada campo é um RANKING INDEPENDENTE. Juntar dois deles numa lista só (era
/// o que o Engine fazia com a memtable e o BM25) destrói a semântica do RRF: a
/// segunda lista passa a começar na posição em que a primeira acabou, como se
/// o seu MELHOR documento fosse pior do que o pior da outra — e com mais de
/// `RECALL_N` correspondências o melhor documento de um canal é cortado antes
/// de o reranker o ver (auditoria 2026-09-05, A10).
pub struct RecallInputs {
    pub vector: Vec<(EventId, Lsn, f32)>, // (id, lsn, dist)
    pub text: Vec<(EventId, Lsn, f32)>,   // (id, lsn, bm25)
    /// Cauda quente por contagem crua de ocorrências (`Memtable::text_search`).
    /// Canal PRÓPRIO e não a cauda de `text`: a escala é incomparável com a do
    /// BM25, e o RRF funde rankings sem precisar de escalas comuns. Para o
    /// RERANKER, que só tem um campo `bm25`, o `retrieve` calibra estes valores
    /// contra o pior BM25 medido do lote (auditoria 2026-09-05, vaga 2, R71).
    pub memtable_text: Vec<(EventId, Lsn, f32)>,
    pub activation: Vec<(EventId, f32)>, // (id, score)
}

/// Full two-stage retrieval over pre-fetched channel results.
pub fn retrieve(
    query: &str,
    inputs: RecallInputs,
    reranker: &dyn Reranker,
    k: usize,
) -> Vec<(Candidate, f32)> {
    let lists: Vec<Vec<EventId>> = vec![
        inputs.vector.iter().map(|(id, _, _)| *id).collect(),
        inputs.text.iter().map(|(id, _, _)| *id).collect(),
        inputs.memtable_text.iter().map(|(id, _, _)| *id).collect(),
        inputs.activation.iter().map(|(id, _)| *id).collect(),
    ];
    let fused = rrf_fuse(&lists);

    let vec_by: HashMap<EventId, (Lsn, f32)> = inputs
        .vector
        .into_iter()
        .map(|(i, l, d)| (i, (l, d)))
        .collect();
    // Auditoria 2026-09-05, vaga 2 (R71): CALIBRAR o canal quente antes de o
    // deixar entrar no campo `bm25` do reranker.
    //
    // A fusão já está certa (A10: a memtable é canal próprio e o RRF, sendo
    // baseado em POSIÇÃO, é imune à escala), mas o SINAL não estava: o mesmo
    // `Candidate::bm25` recebia BM25 medido (Σ idf*(K1+1), normalizado por
    // comprimento, sobre TOKENS) e a contagem crua de SUBSTRINGS da memtable
    // (`Memtable::text_search`: tf, sem idf, sem normalização, sem fronteiras
    // de token). O esmagamento `b/(1+b)` do reranker não distingue as duas
    // unidades — tf=3 e BM25=3.0 dão literalmente o mesmo 0.75 — logo um falso
    // positivo por substring com tf=10 (0.909) batia o melhor documento real
    // do corpus com BM25=3.0 (0.75). Isto só toca em candidatos EXCLUSIVOS da
    // memtable, que existem por duas razões concretas: (a) a memtable casa por
    // substring ("ana" dentro de "banana") e o índice só casa tokens exactos;
    // (b) um documento cujo rank BM25 real cai fora do top-`RECALL_N` mas que
    // está no top-N da memtable.
    //
    // A cura é por LOTE e cabe aqui: `retrieve` tem as DUAS listas em mãos, ao
    // contrário de `Reranker::score`, que vê um candidato de cada vez — nenhuma
    // assinatura pública muda. Um candidato que NÃO aparece no top-`RECALL_N`
    // do BM25 não tem BM25 medido, e o único limite superior honesto que se lhe
    // pode atribuir é o do documento mais fraco que FOI medido neste lote (o
    // `piso`). Daí `piso * tf / (tf_max + 1.0)`: fica ESTRITAMENTE abaixo do
    // piso (o `+1.0` evita o empate exacto com um BM25 real) e mantém-se
    // estritamente monótono em `tf`, preservando a ordem interna do canal
    // quente. Sem canal BM25 no lote não há segunda escala com que ser
    // incoerente, e o tf fica como está — a sua ordem é a única informação
    // disponível. O `piso` tem de ser positivo: com piso <= 0 o produto
    // inverteria (ou achataria) essa ordem, e um BM25 não-positivo é lixo do
    // canal, não uma medição.
    let piso = inputs
        .text
        .iter()
        .map(|(_, _, s)| *s)
        .filter(|s| s.is_finite())
        .fold(f32::INFINITY, f32::min);
    // O canal vem de fora: um `+inf` no lote colapsaria todos os outros tf a ~0
    // e um NaN contaminaria o `tf_max`. Saneia-se ANTES de medir o máximo; o
    // `max(0.0)`/`is_finite` do esmagamento fica como segunda linha de defesa,
    // não como única.
    fn tf_saneado(tf: f32) -> f32 {
        if tf.is_finite() {
            tf.max(0.0)
        } else {
            0.0
        }
    }
    let tf_max = inputs
        .memtable_text
        .iter()
        .map(|(_, _, tf)| tf_saneado(*tf))
        .fold(0.0f32, f32::max);
    let calibrar = piso.is_finite() && piso > 0.0 && tf_max > 0.0;
    // Precedência inalterada: a memtable (calibrada) primeiro e o BM25 da view
    // a sobrepor-se (é `collect` num HashMap, logo a última entrada de cada id
    // vence). Quem está nos dois canais continua a levar o BM25 verdadeiro.
    let txt_by: HashMap<EventId, (Lsn, f32)> = inputs
        .memtable_text
        .into_iter()
        .map(|(i, l, tf)| {
            let tf = tf_saneado(tf);
            let sinal = if calibrar {
                piso * tf / (tf_max + 1.0)
            } else {
                tf
            };
            (i, l, sinal)
        })
        .chain(inputs.text)
        .map(|(i, l, s)| (i, (l, s)))
        .collect();
    let act_by: HashMap<EventId, f32> = inputs.activation.into_iter().collect();

    let mut out: Vec<(Candidate, f32)> = fused
        .into_iter()
        .take(RECALL_N)
        .map(|(id, rrf)| {
            let lsn = vec_by
                .get(&id)
                .map(|(l, _)| *l)
                .or_else(|| txt_by.get(&id).map(|(l, _)| *l))
                .unwrap_or(0);
            let c = Candidate {
                id,
                lsn,
                rrf,
                vec_dist: vec_by.get(&id).map(|(_, d)| *d),
                bm25: txt_by.get(&id).map(|(_, s)| *s),
                activation: act_by.get(&id).copied(),
            };
            let s = reranker.score(query, &c);
            (c, s)
        })
        .collect();
    out.sort_by(|a, b| b.1.total_cmp(&a.1));
    out.truncate(k);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A DEFINIÇÃO do RRF: cada lista é um RANKING — uma permutação em que
    /// cada documento aparece no máximo uma vez e a posição codifica
    /// relevância. Somar duas posições do mesmo id DENTRO da mesma lista
    /// inflava-o sem acordo entre canais nenhum, que é exactamente o que o RRF
    /// existe para premiar (auditoria 2026-09-05, A10).
    #[test]
    fn o_rrf_conta_cada_id_uma_so_vez_por_lista() {
        let d = EventId::new();
        let fundido = rrf_fuse(&[vec![d, d]]);
        assert_eq!(fundido.len(), 1);
        assert!(
            (fundido[0].1 - 1.0 / 61.0).abs() < 1e-12,
            "contou duas vezes (1/61 + 1/62 em vez do melhor rank): {}",
            fundido[0].1
        );
    }

    #[test]
    fn rrf_rewards_cross_channel_agreement() {
        let a = EventId::new();
        let b = EventId::new();
        let c = EventId::new();
        // `a` appears in two channels at modest rank; `b` tops one channel only.
        let fused = rrf_fuse(&[vec![b, a], vec![a, c]]);
        assert_eq!(fused[0].0, a);
    }

    #[test]
    fn two_stage_end_to_end() {
        let target = EventId::new();
        let noise = EventId::new();
        let inputs = RecallInputs {
            vector: vec![(target, 5, 0.1), (noise, 3, 2.0)],
            text: vec![(target, 5, 7.0)],
            memtable_text: Vec::new(),
            activation: vec![(noise, 0.2), (target, 1.5)],
        };
        let reranker = LinearReranker {
            head_lsn: 10,
            ..Default::default()
        };
        let out = retrieve("river", inputs, &reranker, 2);
        assert_eq!(out[0].0.id, target);
        assert!(out[0].1 > out[1].1);
    }

    #[test]
    fn feedback_is_a_log_event() {
        let dir = tempfile::tempdir().unwrap();
        let log =
            heraclitus_log::Log::open(dir.path(), 1 << 20, heraclitus_core::FsyncPolicy::Always)
                .unwrap();
        let fb = RetrievalFeedback {
            query_id: "q1".into(),
            chosen: EventId::new(),
            outcome: 1.0,
        };
        let lsn = log_feedback(&log, "agent-1", &fb).unwrap();
        let (_, ep) = log.read(lsn).unwrap().unwrap();
        assert_eq!(ep.kind, EventKind::RetrievalFeedback);
    }

    /// Constrói um candidato só com sinal textual (os outros canais a zero),
    /// para isolar o esmagamento do BM25 no score final.
    fn candidato_so_texto(lsn: Lsn, bm25: f32) -> Candidate {
        Candidate {
            id: EventId::new(),
            lsn,
            rrf: 0.0,
            vec_dist: None,
            bm25: Some(bm25),
            activation: None,
        }
    }

    #[test]
    fn bm25_forte_nao_perde_para_recencia_por_saturacao() {
        // Auditoria 2026-09-05 (A09): com `tanh` cru, BM25 18.0 e 9.6 dão ambos
        // exactamente 1.0f32 e a ordem passa a ser decidida só pela recência.
        let r = LinearReranker {
            head_lsn: 1_000_000,
            ..Default::default()
        };
        let forte = candidato_so_texto(1, 18.0);
        let fraco = candidato_so_texto(1_000, 9.6);
        let (s_forte, s_fraco) = (r.score("q", &forte), r.score("q", &fraco));
        assert!(
            s_forte > s_fraco,
            "BM25 18.0 (lsn=1) tem de bater BM25 9.6 (lsn=1000): {s_forte} vs {s_fraco}"
        );
    }

    #[test]
    fn esmagamento_do_bm25_e_estritamente_monotono_ate_30() {
        // head_lsn = 0 zera a recência, logo o score é só w_bm25 * esmagamento(b).
        let r = LinearReranker {
            head_lsn: 0,
            ..Default::default()
        };
        let mut anterior = f32::NEG_INFINITY;
        for passo in 0..=60 {
            let b = passo as f32 * 0.5; // 0.0 .. 30.0 — a gama alcançável com n=10k
            let s = r.score("q", &candidato_so_texto(0, b));
            assert!(
                s > anterior,
                "o sinal textual estagnou em b={b}: {s} <= {anterior}"
            );
            anterior = s;
        }
    }

    #[test]
    fn bm25_negativo_ou_nan_nao_envenena_o_score() {
        // b/(1+b) explode em b = -1 e propaga NaN; o canal de texto recebe
        // valores de fora (índice e memtable), por isso o esmagamento tem de os
        // sanear antes da divisão.
        let r = LinearReranker::default();
        for b in [-1.0f32, -2.0, f32::NAN, f32::NEG_INFINITY, f32::INFINITY] {
            let s = r.score("q", &candidato_so_texto(0, b));
            assert!(s.is_finite(), "score não-finito para bm25={b}: {s}");
            assert!(s >= 0.0, "score negativo para bm25={b}: {s}");
        }
    }

    /// Constrói o lote de recall com um só canal de texto medido e um só canal
    /// quente, com LSN IGUAL em todos os hits para anular a recência.
    fn lote_texto(texto: Vec<(EventId, f32)>, memtable: Vec<(EventId, f32)>) -> RecallInputs {
        const LSN: Lsn = 7;
        RecallInputs {
            vector: Vec::new(),
            text: texto.into_iter().map(|(i, s)| (i, LSN, s)).collect(),
            memtable_text: memtable.into_iter().map(|(i, s)| (i, LSN, s)).collect(),
            activation: Vec::new(),
        }
    }

    fn reranker_de_texto() -> LinearReranker {
        LinearReranker {
            head_lsn: 1_000,
            ..Default::default()
        }
    }

    /// Score final de um id no resultado reordenado.
    ///
    /// As asserções destes testes comparam SCORES e não posições de propósito:
    /// `sort_by` é estável, logo um empate preserva a ordem do RRF e um teste
    /// posicional deixaria passar exactamente as mutações que achatam a escala
    /// do canal quente (auditoria 2026-09-05, vaga 2, R71).
    fn score_de(saida: &[(Candidate, f32)], id: EventId) -> f32 {
        saida
            .iter()
            .find(|(c, _)| c.id == id)
            .map(|(_, s)| *s)
            .expect("candidato ausente do top-k")
    }

    /// Auditoria 2026-09-05, vaga 2 (R71) — a PROVA do defeito.
    ///
    /// O canal quente da memtable pontua por contagem crua de SUBSTRINGS
    /// (`Memtable::text_search`: tf, sem idf, sem normalização de comprimento e
    /// sem fronteiras de token) e entrava no reranker pelo MESMO campo `bm25`
    /// do canal medido. Com os pesos por omissão: tf=10 ⇒ 10/11 = 0.909 ⇒
    /// 0.4545, contra o melhor documento real do corpus com BM25=3.0 ⇒ 0.75 ⇒
    /// 0.375. O falso positivo por substring ("ana" dentro de "banana") ganhava
    /// ao topo textual verdadeiro só por as duas escalas serem incomparáveis.
    #[test]
    fn um_hit_so_da_memtable_nao_bate_o_topo_do_bm25() {
        let a = EventId::new();
        let b = EventId::new();
        let saida = retrieve(
            "q",
            lote_texto(vec![(a, 3.0)], vec![(b, 10.0)]),
            &reranker_de_texto(),
            2,
        );
        // ESTRITAMENTE maior, não apenas à frente: um `piso * tf / tf_max`
        // (sem o +1.0) daria exactamente o mesmo score que o topo do BM25 e a
        // ordem passaria a depender só da estabilidade do sort.
        assert!(
            score_de(&saida, a) > score_de(&saida, b),
            "o tf cru da memtable (10) não ficou abaixo do BM25 medido (3.0): {:?}",
            saida.iter().map(|(c, s)| (c.bm25, *s)).collect::<Vec<_>>()
        );
        assert_eq!(saida[0].0.id, a, "o topo do BM25 não saiu em primeiro");
    }

    /// A calibração é uma MUDANÇA DE ESCALA, não um achatamento: dentro do
    /// canal quente a ordem por tf tem de sobreviver. Mata a mutação preguiçosa
    /// de dar a todos os hits da memtable o mesmo valor (o piso, ou 0.0), que
    /// passaria no teste acima (auditoria 2026-09-05, vaga 2, R71).
    #[test]
    fn a_calibracao_preserva_a_ordem_dentro_do_canal_quente() {
        let medido = EventId::new();
        let quente_forte = EventId::new();
        let quente_fraco = EventId::new();
        let saida = retrieve(
            "q",
            lote_texto(
                vec![(medido, 3.0)],
                vec![(quente_forte, 10.0), (quente_fraco, 2.0)],
            ),
            &reranker_de_texto(),
            3,
        );
        assert!(
            score_de(&saida, quente_forte) > score_de(&saida, quente_fraco),
            "tf=10 não ficou acima de tf=2 depois da calibração: {:?}",
            saida.iter().map(|(c, s)| (c.bm25, *s)).collect::<Vec<_>>()
        );
        // E continua a ser um canal SUBORDINADO ao medido.
        assert!(
            score_de(&saida, medido) > score_de(&saida, quente_forte),
            "o canal quente calibrado ultrapassou o BM25 medido"
        );
    }

    /// Sem canal BM25 não há piso medido, logo não há segunda escala com que
    /// ser incoerente: o tf fica como está e continua a ordenar. Mata a mutação
    /// de zerar (ou descartar) o canal quente quando `text` vem vazio
    /// (auditoria 2026-09-05, vaga 2, R71).
    #[test]
    fn sem_canal_bm25_o_tf_da_memtable_ordena_na_mesma() {
        let forte = EventId::new();
        let fraco = EventId::new();
        let saida = retrieve(
            "q",
            lote_texto(Vec::new(), vec![(forte, 5.0), (fraco, 1.0)]),
            &reranker_de_texto(),
            2,
        );
        assert!(
            score_de(&saida, forte) > score_de(&saida, fraco),
            "tf=5 não ficou acima de tf=1 sem canal medido: {:?}",
            saida.iter().map(|(c, s)| (c.bm25, *s)).collect::<Vec<_>>()
        );
        assert!(
            score_de(&saida, fraco) > 0.0,
            "o canal quente foi zerado por não haver piso medido"
        );
    }

    /// A precedência do `chain` não muda: quem está nos DOIS canais leva o BM25
    /// medido, não o tf calibrado. Trava a regressão de inverter a ordem do
    /// `chain` ao mexer no bloco (auditoria 2026-09-05, vaga 2, R71).
    #[test]
    fn candidato_presente_nos_dois_canais_continua_a_levar_o_bm25_medido() {
        let x = EventId::new();
        let saida = retrieve(
            "q",
            lote_texto(vec![(x, 3.0)], vec![(x, 10.0)]),
            &reranker_de_texto(),
            1,
        );
        assert_eq!(
            saida[0].0.bm25,
            Some(3.0),
            "o candidato presente nos dois canais deixou de levar o BM25 medido"
        );
    }

    /// O canal quente vem de fora; um único valor não-finito no lote envenenaria
    /// o `tf_max` (um `+inf` colapsaria todos os outros a ~0) e, sem saneamento,
    /// chegaria ao esmagamento como 1.0 — o máximo do sinal textual — pondo lixo
    /// à frente do topo medido (auditoria 2026-09-05, vaga 2, R71).
    #[test]
    fn tf_nao_finito_ou_negativo_nao_envenena_a_calibracao() {
        let medido = EventId::new();
        let nan = EventId::new();
        let inf = EventId::new();
        let negativo = EventId::new();
        let limpo = EventId::new();
        let saida = retrieve(
            "q",
            lote_texto(
                vec![(medido, 3.0)],
                vec![
                    (nan, f32::NAN),
                    (inf, f32::INFINITY),
                    (negativo, -1.0),
                    (limpo, 10.0),
                ],
            ),
            &reranker_de_texto(),
            5,
        );
        for (c, s) in &saida {
            assert!(s.is_finite(), "score não-finito para {:?}: {s}", c.bm25);
        }
        let s_medido = score_de(&saida, medido);
        for (rotulo, sujo) in [("NaN", nan), ("+inf", inf), ("negativo", negativo)] {
            assert!(
                s_medido > score_de(&saida, sujo),
                "o tf {rotulo} passou à frente do topo do BM25: {:?}",
                saida.iter().map(|(c, s)| (c.bm25, *s)).collect::<Vec<_>>()
            );
        }
        // O lote sujo não pode alterar a calibração do hit legítimo: continua
        // abaixo do piso medido e acima dos que foram saneados para 0.
        assert!(
            s_medido > score_de(&saida, limpo) && score_de(&saida, limpo) > score_de(&saida, nan),
            "a calibração do tf=10 legítimo foi contaminada pelo lote sujo: {:?}",
            saida.iter().map(|(c, s)| (c.bm25, *s)).collect::<Vec<_>>()
        );
    }

    /// Auditoria 2026-09-05, vaga 2 (R71) — a guarda `piso > 0.0`.
    ///
    /// A calibração MULTIPLICA o tf pelo piso, logo um piso não-positivo
    /// destruiria exactamente a informação que ela existe para preservar: com
    /// piso = 0.0 todos os hits quentes colapsam em 0.0, e com piso < 0.0 saem
    /// negativos e são todos achatados pelo `max(0.0)` do esmagamento — em
    /// qualquer dos casos a ordem interna do canal quente morre e o `tf` deixa
    /// de significar seja o que for. Um BM25 não-positivo é lixo do canal e não
    /// uma medição (o índice usa o idf suavizado `ln((n-df+0.5)/(df+0.5) + 1)`,
    /// estritamente positivo), pelo que a resposta certa é NÃO calibrar contra
    /// ele e manter o tf cru — o mesmo que se faz quando não há canal medido de
    /// todo. `retrieve` é API pública e sanea os dois canais precisamente por
    /// eles virem de fora; esta guarda é a metade dessa defesa que faltava
    /// provar.
    #[test]
    fn piso_nao_positivo_nao_achata_o_canal_quente() {
        for piso_lixo in [0.0_f32, -2.0] {
            let medido = EventId::new();
            let forte = EventId::new();
            let fraco = EventId::new();
            let saida = retrieve(
                "q",
                lote_texto(vec![(medido, piso_lixo)], vec![(forte, 5.0), (fraco, 1.0)]),
                &reranker_de_texto(),
                3,
            );
            assert!(
                score_de(&saida, forte) > score_de(&saida, fraco),
                "piso={piso_lixo} achatou a ordem do canal quente (tf=5 vs tf=1): {:?}",
                saida.iter().map(|(c, s)| (c.bm25, *s)).collect::<Vec<_>>()
            );
            for (c, s) in &saida {
                assert!(
                    s.is_finite(),
                    "score não-finito com piso={piso_lixo} para {:?}: {s}",
                    c.bm25
                );
            }
        }
    }
}
