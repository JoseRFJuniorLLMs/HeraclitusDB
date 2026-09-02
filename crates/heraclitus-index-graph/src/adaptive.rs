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
/// O sweep faz uma unica passagem ascendente. No menor threshold todos os
/// scores ordenaveis estao previstos; ao subir o threshold, o grupo anterior
/// sai e `previstos`/`tp` sao atualizados em O(1) por amostra.
///
/// Custo: `O(n log n)` pela ordenacao e `O(n)` pelo sweep.
///
/// # O que NAO muda
///
/// O resultado. O desempate continua a ser pelo threshold MAIS BAIXO — mais
/// recall — com a mesma regra de melhoria estrita (`> best + 1e-9`) que a
/// versao anterior usava. `NaN` nunca satisfaz `score >= threshold`; portanto
/// nao e candidato, mas um `NaN` confirmado continua no denominador do recall,
/// exactamente como em [`evaluate_threshold`]. Se todos os scores forem NaN,
/// conserva-se `default`. Ha testes contra a referencia quadratica.
pub fn learn_threshold(samples: &[LabeledFlag], default: f32) -> f32 {
    learn_threshold_impl(samples, default).0
}

#[derive(Debug, Clone, Copy, Default)]
#[cfg_attr(not(test), allow(dead_code))]
struct LearnWork {
    input_samples: usize,
    sortable_samples: usize,
    sort_comparisons: usize,
    sweep_updates: usize,
    threshold_evaluations: usize,
}

fn learn_threshold_impl(samples: &[LabeledFlag], default: f32) -> (f32, LearnWork) {
    let mut work = LearnWork {
        input_samples: samples.len(),
        ..LearnWork::default()
    };
    if samples.is_empty() {
        return (default, work);
    }

    // NaN nao e ordenavel e, pela propria semantica de `evaluate_threshold`,
    // nunca e previsto por threshold algum. Mantemo-lo apenas em `total_pos`.
    let mut ordered: Vec<(f32, bool)> = samples
        .iter()
        .filter(|sample| !sample.score.is_nan())
        .map(|sample| (sample.score, sample.confirmed))
        .collect();
    work.sortable_samples = ordered.len();
    if ordered.is_empty() {
        return (default, work);
    }
    ordered.sort_by(|left, right| {
        #[cfg(test)]
        {
            work.sort_comparisons += 1;
        }
        left.0
            .partial_cmp(&right.0)
            .expect("NaN scores were removed before sorting")
    });

    let total_pos = samples.iter().filter(|sample| sample.confirmed).count() as f32;
    let mut tp = 0.0f32;
    let mut fp = 0.0f32;
    for (_, confirmed) in &ordered {
        if *confirmed {
            tp += 1.0;
        } else {
            fp += 1.0;
        }
    }
    // Confirmed NaNs start (and remain) as false negatives because no ordered
    // threshold can predict them.
    let mut false_negatives = total_pos - tp;

    let mut best_threshold = ordered[0].0;
    let mut best_f1 = -1.0f32;
    let mut i = 0usize;
    while i < ordered.len() {
        let threshold = ordered[i].0;
        let precision = if tp + fp > 0.0 { tp / (tp + fp) } else { 0.0 };
        let recall = if tp + false_negatives > 0.0 {
            tp / (tp + false_negatives)
        } else {
            0.0
        };
        let f1 = if precision + recall > 0.0 {
            2.0 * precision * recall / (precision + recall)
        } else {
            0.0
        };
        work.threshold_evaluations += 1;
        if f1 > best_f1 + 1e-9 {
            best_f1 = f1;
            best_threshold = threshold;
        }

        // `score >= threshold`: so depois de avaliar este threshold o grupo
        // empatado deixa o conjunto previsto para o proximo candidato.
        while i < ordered.len() && ordered[i].0 == threshold {
            if ordered[i].1 {
                tp -= 1.0;
                false_negatives += 1.0;
            } else {
                fp -= 1.0;
            }
            work.sweep_updates += 1;
            i += 1;
        }
    }
    (best_threshold, work)
}

#[cfg(test)]
fn learn_threshold_with_work(samples: &[LabeledFlag], default: f32) -> (f32, LearnWork) {
    learn_threshold_impl(samples, default)
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
    let mut candidates: Vec<f32> = samples
        .iter()
        .map(|sample| sample.score)
        .filter(|score| !score.is_nan())
        .collect();
    if candidates.is_empty() {
        return default;
    }
    candidates.sort_by(|left, right| {
        left.partial_cmp(right)
            .expect("NaN scores were removed before sorting")
    });
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
                .map(|index| LabeledFlag {
                    // NaN e aceite pelo parser f32 do chamador vivo. Ele nao
                    // pode entrar na ordenacao nem virar um threshold.
                    score: if caso.is_multiple_of(11) && index.is_multiple_of(13) {
                        f32::NAN
                    } else {
                        rng.f32_em(casas)
                    },
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
            vec![LabeledFlag {
                score: 1.0,
                confirmed: true,
            }],
            vec![LabeledFlag {
                score: 1.0,
                confirmed: false,
            }],
            // Todos o mesmo score: um unico candidato.
            (0..10u32)
                .map(|i| LabeledFlag {
                    score: 2.0,
                    confirmed: i.is_multiple_of(2),
                })
                .collect(),
            // Nenhum positivo: F1 e zero em todo o lado, ganha o mais baixo.
            (0..10)
                .map(|i| LabeledFlag {
                    score: i as f32,
                    confirmed: false,
                })
                .collect(),
            // Todos positivos: F1 maximo no threshold mais baixo.
            (0..10)
                .map(|i| LabeledFlag {
                    score: i as f32,
                    confirmed: true,
                })
                .collect(),
            // NaNs nunca sao previstos; confirmados ainda contam no recall.
            vec![
                LabeledFlag {
                    score: f32::NAN,
                    confirmed: true,
                },
                LabeledFlag {
                    score: 2.0,
                    confirmed: true,
                },
                LabeledFlag {
                    score: 1.0,
                    confirmed: false,
                },
            ],
            // Sem candidato ordenavel, conserva o default.
            vec![
                LabeledFlag {
                    score: f32::NAN,
                    confirmed: true,
                },
                LabeledFlag {
                    score: f32::NAN,
                    confirmed: false,
                },
            ],
            // Infinidades continuam scores ordenaveis e candidatos legitimos.
            vec![
                LabeledFlag {
                    score: f32::NEG_INFINITY,
                    confirmed: false,
                },
                LabeledFlag {
                    score: 0.0,
                    confirmed: true,
                },
                LabeledFlag {
                    score: f32::INFINITY,
                    confirmed: true,
                },
            ],
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
        assert!(
            aval.f1 > 0.0,
            "o threshold aprendido tem de ter F1 positivo"
        );
        assert!(t.is_finite());
    }

    #[test]
    fn empates_preservam_o_menor_threshold_e_o_bit_de_zero() {
        let negatives = [
            LabeledFlag {
                score: 3.0,
                confirmed: false,
            },
            LabeledFlag {
                score: -0.0,
                confirmed: false,
            },
            LabeledFlag {
                score: 2.0,
                confirmed: false,
            },
            LabeledFlag {
                score: 0.0,
                confirmed: false,
            },
        ];
        let learned = learn_threshold(&negatives, 1.5);
        let reference = learn_threshold_referencia(&negatives, 1.5);
        assert_eq!(learned.to_bits(), reference.to_bits());
        assert_eq!(learned.to_bits(), (-0.0f32).to_bits());
    }

    #[test]
    fn contador_prova_um_unico_sweep_depois_da_ordenacao() {
        fn measure(n: usize) -> LearnWork {
            let samples: Vec<_> = (0..n)
                .map(|index| LabeledFlag {
                    score: index as f32,
                    confirmed: index.is_multiple_of(3),
                })
                .collect();
            let (_, work) = learn_threshold_with_work(&samples, 1.5);
            work
        }

        let small = measure(1_024);
        let large = measure(2_048);
        assert_eq!(small.input_samples, 1_024);
        assert_eq!(small.sortable_samples, 1_024);
        assert_eq!(small.sweep_updates, 1_024);
        assert_eq!(small.threshold_evaluations, 1_024);
        assert_eq!(large.sweep_updates, small.sweep_updates * 2);
        assert_eq!(large.threshold_evaluations, small.threshold_evaluations * 2);
        // A ordenacao da stdlib deve permanecer muito abaixo de n².
        assert!(small.sort_comparisons < 1_024 * 32);
        assert!(large.sort_comparisons < 2_048 * 32);
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
