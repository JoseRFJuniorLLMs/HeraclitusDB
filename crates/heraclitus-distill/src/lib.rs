//! heraclitus-distill — consolidation as compaction (§3.9).
//!
//! Clusters episodic embeddings in the manifold and, for each stable
//! cluster, emits a `Fact` **as a new log event** (`kind = FactDerived`)
//! with `provenance = [episode ids]`. The log stays the single source of
//! truth even for derived knowledge. Policy-triggered, never concurrent
//! with itself, rate-limited by `max_facts_per_run`.

use heraclitus_core::{Episode, EventId, EventKind, Fact, HeraclitusError, Lsn, ProductPoint};
use heraclitus_log::Log;
use heraclitus_manifold::{dist_hyp, estimate, HypCentroidAccumulator, ProductMetric};

mod centroid_index;

#[derive(Debug, Clone)]
pub struct DistillConfig {
    /// Minimum cluster size to emit a fact.
    pub min_cluster: usize,
    /// Maximum manifold distance from a cluster centroid for membership.
    pub threshold: f64,
    /// Rate limit per run (CPU budget stand-in, §3.9).
    pub max_facts_per_run: usize,
}

impl Default for DistillConfig {
    fn default() -> Self {
        Self {
            min_cluster: 3,
            threshold: 0.8,
            max_facts_per_run: 64,
        }
    }
}

pub struct Distiller {
    pub metric: ProductMetric,
    pub config: DistillConfig,
}

struct Cluster {
    // Embeddings do not need to be retained: the Einstein centroid is fully
    // described by `sum(gamma*x)` and `sum(gamma)` in `centroid_hyp`.
    members: Vec<(EventId, String)>,
    centroid_hyp: HypCentroidAccumulator,
}

impl Distiller {
    pub fn new(metric: ProductMetric, config: DistillConfig) -> Self {
        Self { metric, config }
    }

    /// Greedy agglomerative clustering in the manifold (v0: density-style
    /// threshold assignment; HDBSCAN is a planned upgrade).
    fn cluster(&self, episodes: &[(Lsn, Episode)]) -> Vec<Cluster> {
        self.cluster_com(episodes, true).0
    }

    /// O mesmo agrupamento, com o atalho pelo índice de centróides ligado ou
    /// desligado.
    ///
    /// # Porque é que a versão exaustiva fica no código
    ///
    /// O índice (VP-tree com sobreposição *dirty*) promete devolver
    /// EXACTAMENTE o mesmo agrupamento que a varredura completa, incluindo o
    /// desempate. Uma promessa dessas verifica-se contra um oráculo, e o
    /// oráculo tem de continuar a existir para o teste de equivalência poder
    /// correr — não basta tê-lo lido uma vez.
    ///
    /// `usar_indice = false` é a referência. Não é código morto: é o que
    /// decide se o atalho está certo.
    fn cluster_com(
        &self,
        episodes: &[(Lsn, Episode)],
        usar_indice: bool,
    ) -> (Vec<Cluster>, centroid_index::SearchStats) {
        let mut clusters: Vec<Cluster> = Vec::new();
        let mut indice = centroid_index::CentroidIndex::default();
        let mut stats = centroid_index::SearchStats::default();
        for (_, e) in episodes {
            let Some(emb) = &e.embedding else { continue };
            let text = String::from_utf8_lossy(&e.content).into_owned();
            let curvature = -self.metric.sig.k1;
            let hyp_weight = self.metric.sig.weights[0];
            let best = if usar_indice {
                indice.select(
                    &clusters,
                    &emb.hyp,
                    curvature,
                    hyp_weight,
                    self.config.threshold,
                    &mut stats,
                )
            } else {
                clusters
                    .iter()
                    .enumerate()
                    .map(|(index, c)| {
                        // The distiller deliberately clusters only the
                        // hyperbolic component. This is algebraically the same
                        // value produced by ProductMetric for empty
                        // spherical/Euclidean parts, without cloning either the
                        // probe or every centroid.
                        let dh = dist_hyp(c.centroid_hyp.centroid(), &emb.hyp, curvature);
                        stats.brute_force_distances += 1;
                        ((hyp_weight * dh * dh).sqrt(), index)
                    })
                    .filter(|(d, _)| *d < self.config.threshold)
                    .min_by(|a, b| a.0.total_cmp(&b.0))
            };
            match best {
                Some((_, index)) => {
                    let c = &mut clusters[index];
                    c.members.push((e.id, text));
                    c.centroid_hyp.add(&emb.hyp);
                    // O centróide mexeu-se: a cópia que está na árvore ficou
                    // velha e deixa de poder ganhar até à próxima reconstrução.
                    indice.mark_changed(index);
                }
                None => {
                    let mut centroid_hyp = HypCentroidAccumulator::new(emb.hyp.len());
                    centroid_hyp.add(&emb.hyp);
                    clusters.push(Cluster {
                        centroid_hyp,
                        members: vec![(e.id, text)],
                    });
                    // Um agregado NOVO não está na árvore de todo. Sem isto
                    // ficaria invisível até uma reconstrução — e o agrupamento
                    // divergiria do exaustivo em silêncio.
                    indice.mark_changed(clusters.len() - 1);
                }
            }
        }
        (clusters, stats)
    }

    /// Computa os episódios `FactDerived` de um conjunto de episódios já lido —
    /// SEM appendar (caminho unificado §2.6: quem appenda é o HOST, via
    /// `Engine::append`, para os Facts serem indexados ao vivo ≡ boot-replay e
    /// passarem pelo consenso). Só considera Observações com embedding.
    /// `derived_at_head` é o head do log no momento (carimbo aproximado).
    pub fn distill_episodes(
        &self,
        episodes: &[(Lsn, Episode)],
        derived_at_head: Lsn,
    ) -> Result<Vec<Episode>, HeraclitusError> {
        let obs: Vec<(Lsn, Episode)> = episodes
            .iter()
            .filter(|(_, e)| e.kind == EventKind::Observation && e.embedding.is_some())
            .cloned()
            .collect();

        let mut out = Vec::new();
        for cluster in self.cluster(&obs) {
            if cluster.members.len() < self.config.min_cluster {
                continue;
            }
            if out.len() >= self.config.max_facts_per_run {
                break;
            }
            let provenance: Vec<EventId> = cluster.members.iter().map(|(id, _)| *id).collect();
            let samples: Vec<&str> = cluster
                .members
                .iter()
                .map(|(_, t)| t.as_str())
                .take(3)
                .collect();
            let statement = format!(
                "distilled from {} episodes: {}",
                cluster.members.len(),
                samples.join("; ")
            );
            // The geometry does abstraction for free: the Einstein centroid
            // of specifics lands nearer the origin (more abstract).
            let embedding = ProductPoint {
                hyp: cluster.centroid_hyp.into_centroid(),
                sph: vec![],
                euc: vec![],
            };
            let fact = Fact {
                id: EventId::new(),
                statement,
                embedding: Some(embedding.clone()),
                confidence: cluster.members.len() as f32 / (cluster.members.len() as f32 + 2.0),
                provenance: provenance.clone(),
                derived_at_lsn: derived_at_head,
            };
            let payload = serde_json::to_vec(&fact)
                .map_err(|e| HeraclitusError::Serialization(e.to_string()))?;
            let mut ev = Episode::new("distill", EventKind::FactDerived, payload);
            ev.embedding = Some(embedding);
            ev.parents = provenance; // provenance pointers double as graph edges
            out.push(ev);
        }
        Ok(out)
    }

    /// One compaction run over `[from, to)`: emit facts back into the log.
    /// Returns the LSNs of the FactDerived events appended.
    ///
    /// Conveniência standalone (appenda direto ao log). Um host com `Engine`
    /// deve usar [`Self::distill_episodes`] + `Engine::append` (§2.6) e um
    /// scan JANELADO — este método faz `log.scan(from,to)` sem teto, o que
    /// materializa a janela inteira em RAM.
    pub fn run(&self, log: &Log, from: Lsn, to: Lsn) -> Result<Vec<Lsn>, HeraclitusError> {
        let episodes = log.scan(from, to)?;
        let facts = self.distill_episodes(&episodes, log.head())?;
        let mut out = Vec::with_capacity(facts.len());
        for ev in facts {
            out.push(log.append(ev)?);
        }
        Ok(out)
    }

    /// Offline signature re-fit hook (§3.9): sample provenance-pair
    /// distances vs embedding distances and propose a better signature.
    /// A re-fit never mutates anything — the caller versions a new view.
    pub fn refit_signature(
        &self,
        sample: &[estimate::DistortionSample],
    ) -> heraclitus_manifold::Signature {
        estimate::fit_signature(sample)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use heraclitus_core::FsyncPolicy;
    use heraclitus_manifold::hyp_centroid;

    fn ep(text: &str, hyp: Vec<f32>) -> Episode {
        let mut e = Episode::new("agent", EventKind::Observation, text.into());
        e.embedding = Some(ProductPoint {
            hyp,
            sph: vec![],
            euc: vec![],
        });
        e
    }

    /// O índice de centróides promete, no seu próprio cabeçalho, que "o
    /// agregado escolhido é idêntico ao de uma varredura exaustiva, incluindo
    /// depois de os centróides se moverem". Isto verifica a promessa em vez de
    /// acreditar nela.
    ///
    /// Duas armadilhas que este teste evita de propósito:
    ///   - passar por o atalho nunca ter corrido (o índice só liga acima de 32
    ///     agregados) — daí a asserção sobre `indexed_queries`;
    ///   - passar por nunca ter havido reconstrução da árvore, que é onde a
    ///     sobreposição `dirty` se esvazia e as cópias velhas voltam a poder
    ///     ganhar — daí a asserção sobre `rebuilds`.
    #[test]
    fn indice_de_centroides_da_o_mesmo_agrupamento_que_a_varredura() {
        // LCG explícito: um teste de equivalência tem de falhar SEMPRE que a
        // equivalência quebrar, não às vezes.
        let mut semente = 0x2545_F491_4F6C_DD1Du64;
        let mut proximo = move || {
            semente = semente
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            (semente >> 33) as f32 / (1u64 << 31) as f32
        };
        let episodios: Vec<(Lsn, Episode)> = (0..600)
            .map(|i| {
                let hyp: Vec<f32> = (0..4).map(|_| (proximo() - 0.5) * 0.6).collect();
                (i as Lsn, ep(&format!("episodio {i}"), hyp))
            })
            .collect();

        let d = Distiller::new(ProductMetric::default(), DistillConfig::default());
        let (com_indice, stats) = d.cluster_com(&episodios, true);
        let (exaustivo, _) = d.cluster_com(&episodios, false);

        assert!(
            stats.indexed_queries > 0,
            "o caminho indexado nunca correu — o teste não testou nada"
        );
        assert!(
            stats.rebuilds > 0,
            "a árvore nunca foi reconstruída — o caso das cópias velhas ficou por cobrir"
        );
        assert_eq!(
            com_indice.len(),
            exaustivo.len(),
            "número de agregados difere"
        );
        for (i, (a, b)) in com_indice.iter().zip(&exaustivo).enumerate() {
            assert_eq!(
                a.members, b.members,
                "agregado {i}: o atalho pôs membros diferentes"
            );
        }
    }

    #[test]
    fn provenance_round_trip() {
        // M5 acceptance gate: fact -> log -> decode -> provenance intact.
        let dir = tempfile::tempdir().unwrap();
        let log = Log::open(dir.path(), 1 << 20, FsyncPolicy::Always).unwrap();
        // Tight cluster of cat episodes + one far-away outlier.
        let mut ids = Vec::new();
        for i in 0..4 {
            let e = ep(
                &format!("cat episode {i}"),
                vec![0.60 + i as f32 * 0.01, 0.0],
            );
            ids.push(e.id);
            log.append(e).unwrap();
        }
        log.append(ep("unrelated galaxy", vec![-0.7, 0.1])).unwrap();

        let d = Distiller::new(ProductMetric::default(), DistillConfig::default());
        let lsns = d.run(&log, 0, u64::MAX).unwrap();
        assert_eq!(lsns.len(), 1, "exactly one stable cluster");

        let (_, ev) = log.read(lsns[0]).unwrap().unwrap();
        assert_eq!(ev.kind, EventKind::FactDerived);
        let fact: Fact = serde_json::from_slice(&ev.content).unwrap();
        let mut got = fact.provenance.clone();
        got.sort();
        ids.sort();
        assert_eq!(
            got, ids,
            "provenance must point at exactly the source episodes"
        );
        assert_eq!(
            ev.parents, fact.provenance,
            "parents mirror provenance for graph views"
        );

        // Abstraction-by-geometry: centroid is NOT farther out than members.
        let cent: f32 = fact
            .embedding
            .unwrap()
            .hyp
            .iter()
            .map(|x| x * x)
            .sum::<f32>()
            .sqrt();
        assert!(
            cent <= 0.62,
            "centroid norm {cent} should not exceed member norms"
        );
    }

    #[test]
    fn rate_limit_respected() {
        let dir = tempfile::tempdir().unwrap();
        let log = Log::open(dir.path(), 1 << 20, FsyncPolicy::Always).unwrap();
        // Three well-separated clusters of 3.
        for (cx, base) in [(0.2f32, "a"), (0.5, "b"), (0.8, "c")] {
            for i in 0..3 {
                log.append(ep(&format!("{base}{i}"), vec![cx + i as f32 * 0.005, 0.0]))
                    .unwrap();
            }
        }
        let cfg = DistillConfig {
            max_facts_per_run: 2,
            threshold: 0.3,
            min_cluster: 3,
        };
        let d = Distiller::new(ProductMetric::default(), cfg);
        let lsns = d.run(&log, 0, u64::MAX).unwrap();
        assert_eq!(lsns.len(), 2, "rate limit must cap facts per run");
    }

    #[test]
    fn streaming_cluster_centroid_matches_batch_reference_deterministically() {
        let points = vec![
            vec![0.10, -0.20, 0.05],
            vec![0.12, -0.18, 0.04],
            vec![0.15, -0.16, 0.02],
            vec![0.18, -0.14, 0.01],
            vec![0.20, -0.12, -0.01],
        ];
        let episodes: Vec<(Lsn, Episode)> = points
            .iter()
            .enumerate()
            .map(|(lsn, point)| (lsn as Lsn, ep(&format!("point {lsn}"), point.clone())))
            .collect();
        let distiller = Distiller::new(
            ProductMetric::default(),
            DistillConfig {
                min_cluster: 1,
                threshold: 10.0,
                max_facts_per_run: 1,
            },
        );

        let first = distiller.cluster(&episodes);
        let second = distiller.cluster(&episodes);
        assert_eq!(first.len(), 1);
        assert_eq!(second.len(), 1);
        assert_eq!(first[0].members.len(), points.len());

        let expected = hyp_centroid(&points);
        let expected_bits: Vec<u32> = expected.iter().map(|x| x.to_bits()).collect();
        let first_bits: Vec<u32> = first[0]
            .centroid_hyp
            .centroid()
            .iter()
            .map(|x| x.to_bits())
            .collect();
        let second_bits: Vec<u32> = second[0]
            .centroid_hyp
            .centroid()
            .iter()
            .map(|x| x.to_bits())
            .collect();
        assert_eq!(first_bits, expected_bits);
        assert_eq!(second_bits, expected_bits);
    }

    #[test]
    fn indice_de_centroides_e_exercitado_e_equivale_ao_brute_force() {
        let mut episodes = Vec::new();
        let mut lsn = 0;
        // 64 centróides bem separados obrigam a construção da VP-tree e
        // também fazem nascer centróides novos enquanto a árvore já existe.
        for gy in 0..8 {
            for gx in 0..8 {
                let x = (gx as f32 - 3.5) * 0.09;
                let y = (gy as f32 - 3.5) * 0.09;
                episodes.push((lsn, ep(&format!("base {gx}:{gy}"), vec![x, y])));
                lsn += 1;
            }
        }
        // Três passagens atualizam os centróides. Isto exercita tanto a
        // sobreposição dirty como reconstruções sucessivas; cada ponto continua
        // inequivocamente mais perto do seu agregado original.
        for pass in 1..=3 {
            for gy in 0..8 {
                for gx in 0..8 {
                    let jitter = pass as f32 * 0.0005;
                    let x = (gx as f32 - 3.5) * 0.09 + jitter;
                    let y = (gy as f32 - 3.5) * 0.09 - jitter;
                    episodes.push((lsn, ep(&format!("update {pass} {gx}:{gy}"), vec![x, y])));
                    lsn += 1;
                }
            }
        }

        let distiller = Distiller::new(
            ProductMetric::default(),
            DistillConfig {
                min_cluster: 1,
                threshold: 0.04,
                max_facts_per_run: usize::MAX,
            },
        );
        let (indexed, indexed_stats) = distiller.cluster_com(&episodes, true);
        let (reference, reference_stats) = distiller.cluster_com(&episodes, false);

        assert!(
            indexed_stats.indexed_queries > 0,
            "o teste não entrou na VP-tree"
        );
        assert!(indexed_stats.rebuilds > 0, "o índice nunca foi construído");
        assert!(
            indexed_stats.indexed_distances < reference_stats.brute_force_distances,
            "atalho fez {} distâncias contra {} da referência",
            indexed_stats.indexed_distances,
            reference_stats.brute_force_distances
        );
        assert_eq!(indexed.len(), reference.len());
        for (cluster_index, (got, expected)) in indexed.iter().zip(&reference).enumerate() {
            let got_members: Vec<_> = got.members.iter().map(|(id, _)| *id).collect();
            let expected_members: Vec<_> = expected.members.iter().map(|(id, _)| *id).collect();
            assert_eq!(
                got_members, expected_members,
                "membros do cluster {cluster_index}"
            );
            let got_bits: Vec<_> = got
                .centroid_hyp
                .centroid()
                .iter()
                .map(|x| x.to_bits())
                .collect();
            let expected_bits: Vec<_> = expected
                .centroid_hyp
                .centroid()
                .iter()
                .map(|x| x.to_bits())
                .collect();
            assert_eq!(
                got_bits, expected_bits,
                "centróide do cluster {cluster_index}"
            );
        }
    }
}
