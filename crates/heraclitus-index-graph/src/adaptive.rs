//! adaptive.rs — M17: the graph learns its own rules.
//!
//! Feedback is data, and data lives in the log. When an analyst reviews a flag,
//! they append a feedback event: the signal value the flag fired on plus a
//! verdict (confirmed / rejected). The adaptive worker is then a **pure,
//! deterministic** function of those labeled examples — it tunes the decision
//! threshold to maximize F1, and the improvement over the default is measurable
//! in precision/recall. No daemon mutates anything; the new rule is just the
//! best threshold derivable from the feedback so far, recomputed by replay.

/// One labeled example: the signal the flag fired on, and whether the human
/// confirmed it.
#[derive(Debug, Clone, Copy)]
pub struct LabeledFlag {
    pub score: f32,
    pub confirmed: bool,
}

/// How a threshold scores against the labeled set (a node is predicted positive
/// iff `score >= threshold`).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PolicyEval {
    pub threshold: f32,
    pub precision: f32,
    pub recall: f32,
    pub f1: f32,
}

/// Evaluate a threshold against the labeled examples (precision/recall/F1).
pub fn evaluate_threshold(samples: &[LabeledFlag], threshold: f32) -> PolicyEval {
    let predicted = samples.iter().filter(|s| s.score >= threshold);
    let mut tp = 0.0f32;
    let mut predicted_n = 0.0f32;
    for s in predicted {
        predicted_n += 1.0;
        if s.confirmed {
            tp += 1.0;
        }
    }
    let total_pos = samples.iter().filter(|s| s.confirmed).count() as f32;
    let precision = if predicted_n > 0.0 {
        tp / predicted_n
    } else {
        0.0
    };
    let recall = if total_pos > 0.0 { tp / total_pos } else { 0.0 };
    let f1 = if precision + recall > 0.0 {
        2.0 * precision * recall / (precision + recall)
    } else {
        0.0
    };
    PolicyEval {
        threshold,
        precision,
        recall,
        f1,
    }
}

/// Learn the threshold that maximizes F1 over the labeled examples (M17).
/// Candidates are the distinct observed scores; ties resolve to the lowest
/// threshold (more recall). Deterministic. Falls back to `default` with no data.
///
/// # Porque isto e um sweep e nao um ciclo sobre `evaluate_threshold`
///
/// A versao anterior ordenava os candidatos e chamava `evaluate_threshold` para
/// cada um. Essa funcao percorre as amostras **duas vezes** — uma para contar
/// os previstos e os verdadeiros positivos, outra para o total de positivos —
/// portanto o custo era `2n` por candidato e ate `n` candidatos distintos:
/// **O(n²)**, com o pior caso a acontecer exactamente quando todos os scores
/// sao distintos, que e o caso normal com scores em vírgula flutuante.
///
/// O sweep faz uma unica passagem descendente. Ao descer o threshold, o
/// conjunto previsto so CRESCE, portanto `previstos` e `tp` acumulam e nunca
/// precisam de ser recontados. O `total_pos` sai da mesma passagem.
///
/// Custo: `O(n log n)` pela ordenacao e `O(n)` pelo sweep.
///
/// # O que NAO muda
///
/// O resultado. O desempate continua a ser pelo threshold MAIS BAIXO — mais
/// recall — e por isso os candidatos sao percorridos por ordem crescente no
/// fim, com a mesma regra de melhoria estrita (`> best + 1e-9`) que a versao
/// anterior usava. Ha um teste que confronta as duas implementacoes sobre
/// milhares de amostras geradas: se divergirem, falha.
pub fn learn_threshold(samples: &[LabeledFlag], default: f32) -> f32 {
    if samples.is_empty() {
        return default;
    }

    // Ordem DECRESCENTE de score: ao descer o threshold, o conjunto previsto
    // cresce monotonicamente, que e o que torna o sweep possivel.
    let mut ordenadas: Vec<(f32, bool)> = samples.iter().map(|s| (s.score, s.confirmed)).collect();
    ordenadas.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal));

    let total_pos = ordenadas.iter().filter(|(_, c)| *c).count() as f32;

    // Um par (threshold, f1) por score DISTINTO, em ordem decrescente de
    // threshold. Reserva-se o pior caso — todos distintos — para nao realocar.
    let mut por_threshold: Vec<(f32, f32)> = Vec::with_capacity(ordenadas.len());

    let mut previstos = 0.0f32;
    let mut tp = 0.0f32;
    let mut i = 0usize;
    while i < ordenadas.len() {
        let t = ordenadas[i].0;
        // Consome TODAS as amostras com este score antes de avaliar: o
        // threshold e `>=`, portanto os empates entram todos de uma vez.
        while i < ordenadas.len() && ordenadas[i].0 == t {
            previstos += 1.0;
            if ordenadas[i].1 {
                tp += 1.0;
            }
            i += 1;
        }
        let precision = if previstos > 0.0 { tp / previstos } else { 0.0 };
        let recall = if total_pos > 0.0 { tp / total_pos } else { 0.0 };
        let f1 = if precision + recall > 0.0 {
            2.0 * precision * recall / (precision + recall)
        } else {
            0.0
        };
        por_threshold.push((t, f1));
    }

    // Por ordem CRESCENTE de threshold, com melhoria estrita: o mais baixo
    // ganha o empate, como antes.
    let mut best_t = por_threshold
        .last()
        .map(|(t, _)| *t)
        .unwrap_or(default);
    let mut best_f1 = -1.0f32;
    for &(t, f1) in por_threshold.iter().rev() {
        if f1 > best_f1 + 1e-9 {
            best_f1 = f1;
            best_t = t;
        }
    }
    best_t
}

/// A implementacao O(n²) anterior, mantida SO como referencia de teste.
///
/// Um sweep que devolvesse outra coisa nao seria uma optimizacao, seria uma
/// mudanca de comportamento disfarcada de optimizacao. Esta funcao existe para
/// que a diferenca seja verificavel em vez de afirmada.
#[cfg(test)]
pub(crate) fn learn_threshold_referencia(samples: &[LabeledFlag], default: f32) -> f32 {
    if samples.is_empty() {
        return default;
    }
    let mut candidates: Vec<f32> = samples.iter().map(|s| s.score).collect();
    candidates.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    candidates.dedup();

    let mut best_t = candidates[0];
    let mut best_f1 = -1.0f32;
    for &t in &candidates {
        let f1 = evaluate_threshold(samples, t).f1;
        // Strict improvement only ⇒ first (lowest) threshold wins a tie.
        if f1 > best_f1 + 1e-9 {
            best_f1 = f1;
            best_t = t;
        }
    }
    best_t
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(score: f32, confirmed: bool) -> LabeledFlag {
        LabeledFlag { score, confirmed }
    }

    #[test]
    fn learns_threshold_that_beats_default() {
        // Confirms at 3.0/2.5/2.0, rejects at 1.6/1.0. Default 1.5 wrongly flags
        // the 1.6 reject; the learned threshold excludes it.
        let samples = [
            s(3.0, true),
            s(2.5, true),
            s(2.0, true),
            s(1.6, false),
            s(1.0, false),
        ];
        let default = evaluate_threshold(&samples, 1.5);
        let learned_t = learn_threshold(&samples, 1.5);
        let learned = evaluate_threshold(&samples, learned_t);

        assert!(learned.f1 > default.f1, "learning must improve F1");
        assert!(
            (learned.precision - 1.0).abs() < 1e-6,
            "learned precision is perfect"
        );
        assert!(
            learned_t > 1.6 && learned_t <= 2.0,
            "threshold lands above the reject: {learned_t}"
        );
        // The reject below default (1.0) was never flagged — default precision < 1.
        assert!(default.precision < 1.0);
    }

    #[test]
    fn deterministic_and_handles_empty() {
        let samples = [s(2.0, true), s(1.0, false)];
        assert_eq!(
            learn_threshold(&samples, 1.5),
            learn_threshold(&samples, 1.5)
        );
        assert_eq!(learn_threshold(&[], 1.5), 1.5, "no data ⇒ keep the default");
    }
}

#[cfg(test)]
mod testes_sweep {
    use super::*;

    /// Gerador determinista: um teste de equivalencia que muda a cada corrida
    /// nao e uma prova, e uma loteria.
    struct Rng(u64);
    impl Rng {
        fn proximo(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }
        fn f32_em(&mut self, casas: u32) -> f32 {
            // Poucas casas decimais de proposito: e assim que se geram EMPATES,
            // e o empate e onde a regra de desempate se pode partir sem que
            // ninguem de por isso.
            let m = 10u64.pow(casas);
            (self.proximo() % m) as f32 / m as f32 * 10.0
        }
    }

    /// A prova de que o sweep nao mudou a resposta.
    ///
    /// Confronta a implementacao nova com a O(n²) anterior sobre milhares de
    /// amostras, incluindo casos com muitos empates e casos degenerados (tudo
    /// positivo, tudo negativo, um so elemento).
    #[test]
    fn o_sweep_concorda_com_a_implementacao_quadratica() {
        let mut rng = Rng(0x5eed_1234_9abc_def0);
        for caso in 0..400u32 {
            let n = 1 + (rng.proximo() % 60) as usize;
            // Alterna a granularidade dos scores: com 1 casa decimal ha muitos
            // empates; com 4 quase nenhum.
            let casas = if caso.is_multiple_of(3) { 1 } else { 4 };
            let samples: Vec<LabeledFlag> = (0..n)
                .map(|_| LabeledFlag {
                    score: rng.f32_em(casas),
                    confirmed: rng.proximo().is_multiple_of(2),
                })
                .collect();
            let novo = learn_threshold(&samples, 1.5);
            let referencia = learn_threshold_referencia(&samples, 1.5);
            assert_eq!(
                novo, referencia,
                "caso {caso} (n={n}, casas={casas}) divergiu: sweep={novo} vs quadratica={referencia}\n{samples:?}"
            );
        }
    }

    /// Os degenerados a parte, porque o gerador pode nunca os produzir.
    #[test]
    fn os_casos_degenerados_tambem_concordam() {
        let casos: Vec<Vec<LabeledFlag>> = vec![
            vec![],
            vec![LabeledFlag { score: 1.0, confirmed: true }],
            vec![LabeledFlag { score: 1.0, confirmed: false }],
            // Todos o mesmo score: um unico candidato.
            (0..10u32)
                .map(|i| LabeledFlag { score: 2.0, confirmed: i.is_multiple_of(2) })
                .collect(),
            // Nenhum positivo: F1 e zero em todo o lado, ganha o mais baixo.
            (0..10)
                .map(|i| LabeledFlag { score: i as f32, confirmed: false })
                .collect(),
            // Todos positivos: F1 maximo no threshold mais baixo.
            (0..10)
                .map(|i| LabeledFlag { score: i as f32, confirmed: true })
                .collect(),
        ];
        for (i, samples) in casos.iter().enumerate() {
            assert_eq!(
                learn_threshold(samples, 1.5),
                learn_threshold_referencia(samples, 1.5),
                "caso degenerado {i} divergiu"
            );
        }
    }

    /// O que a optimizacao existe para dar: um `n` que a versao quadratica nao
    /// atravessaria em tempo util atravessa-se agora sem esforco.
    ///
    /// Nao mede tempo (um teste que afirma um numero de milissegundos falha na
    /// maquina de outra pessoa); prova que o caso grande TERMINA e da uma
    /// resposta coerente.
    #[test]
    fn dez_mil_amostras_distintas_sao_tratadas() {
        let mut rng = Rng(0xabcd_0001);
        let samples: Vec<LabeledFlag> = (0..10_000)
            .map(|i| LabeledFlag {
                // Todos distintos: o pior caso da versao quadratica.
                score: i as f32 + rng.f32_em(4) * 0.0001,
                confirmed: rng.proximo().is_multiple_of(3),
            })
            .collect();
        let t = learn_threshold(&samples, 1.5);
        let aval = evaluate_threshold(&samples, t);
        assert!(aval.f1 > 0.0, "o threshold aprendido tem de ter F1 positivo");
        assert!(t.is_finite());
    }
}

#[cfg(test)]
mod medicao {
    use super::*;
    use std::time::Instant;

    /// Mede o sweep contra a versao quadratica. `#[ignore]`: um numero de
    /// milissegundos nao e uma assercao, e uma observacao — falharia na maquina
    /// de outra pessoa.
    ///
    /// Correr com:
    ///   cargo test -p heraclitus-index-graph --lib medicao -- --ignored --nocapture
    #[test]
    #[ignore]
    fn quanto_e_que_o_sweep_poupa() {
        for n in [1_000usize, 4_000, 16_000] {
            let samples: Vec<LabeledFlag> = (0..n)
                .map(|i| LabeledFlag {
                    score: i as f32 * 0.001,
                    confirmed: i.is_multiple_of(3),
                })
                .collect();

            let t0 = Instant::now();
            let a = learn_threshold(&samples, 1.5);
            let sweep = t0.elapsed();

            let t1 = Instant::now();
            let b = learn_threshold_referencia(&samples, 1.5);
            let quad = t1.elapsed();

            assert_eq!(a, b, "as duas implementacoes tem de concordar");
            println!(
                "n={n:>6}  sweep={:>10.3?}  quadratica={:>10.3?}  ganho={:.1}x",
                sweep,
                quad,
                quad.as_secs_f64() / sweep.as_secs_f64().max(1e-9)
            );
        }
    }
}
