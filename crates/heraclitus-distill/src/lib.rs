//! heraclitus-distill — consolidation as compaction (§3.9).
//!
//! Clusters episodic embeddings in the manifold and, for each stable
//! cluster, emits a `Fact` **as a new log event** (`kind = FactDerived`)
//! with `provenance = [episode ids]`. The log stays the single source of
//! truth even for derived knowledge. Policy-triggered, never concurrent
//! with itself, rate-limited by `max_facts_per_run`.

use heraclitus_core::{Episode, EventId, EventKind, Fact, HeraclitusError, Lsn, ProductPoint};
use heraclitus_log::Log;
use heraclitus_manifold::{estimate, hyp_centroid, ProductMetric};

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
    members: Vec<(EventId, ProductPoint, String)>,
    centroid_hyp: Vec<f32>,
}

impl Distiller {
    pub fn new(metric: ProductMetric, config: DistillConfig) -> Self {
        Self { metric, config }
    }

    /// Greedy agglomerative clustering in the manifold (v0: density-style
    /// threshold assignment; HDBSCAN is a planned upgrade).
    fn cluster(&self, episodes: &[(Lsn, Episode)]) -> Vec<Cluster> {
        let mut clusters: Vec<Cluster> = Vec::new();
        for (_, e) in episodes {
            let Some(emb) = &e.embedding else { continue };
            let text = String::from_utf8_lossy(&e.content).into_owned();
            let probe = ProductPoint {
                hyp: emb.hyp.clone(),
                sph: vec![],
                euc: vec![],
            };
            let best = clusters
                .iter_mut()
                .map(|c| {
                    let cent = ProductPoint {
                        hyp: c.centroid_hyp.clone(),
                        sph: vec![],
                        euc: vec![],
                    };
                    (self.metric.dist(&cent, &probe), c)
                })
                .filter(|(d, _)| *d < self.config.threshold)
                .min_by(|a, b| a.0.total_cmp(&b.0));
            match best {
                Some((_, c)) => {
                    c.members.push((e.id, emb.clone(), text));
                    let pts: Vec<Vec<f32>> =
                        c.members.iter().map(|(_, p, _)| p.hyp.clone()).collect();
                    c.centroid_hyp = hyp_centroid(&pts);
                }
                None => clusters.push(Cluster {
                    centroid_hyp: emb.hyp.clone(),
                    members: vec![(e.id, emb.clone(), text)],
                }),
            }
        }
        clusters
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
            let provenance: Vec<EventId> = cluster.members.iter().map(|(id, _, _)| *id).collect();
            let samples: Vec<&str> = cluster
                .members
                .iter()
                .map(|(_, _, t)| t.as_str())
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
                hyp: cluster.centroid_hyp.clone(),
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

    fn ep(text: &str, hyp: Vec<f32>) -> Episode {
        let mut e = Episode::new("agent", EventKind::Observation, text.into());
        e.embedding = Some(ProductPoint {
            hyp,
            sph: vec![],
            euc: vec![],
        });
        e
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
}
