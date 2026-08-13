//! heraclitus-cli — admin & inspection (§3.14) + the M7 QPS×recall harness.

use heraclitus_core::{EventId, FsyncPolicy, ProductPoint};
use heraclitus_index_vector::VectorIndex;
use heraclitus_log::Log;
use heraclitus_manifold::{dist_hyp, project_to_ball, ProductMetric};
use std::time::Instant;

pub fn log_inspect(dir: &std::path::Path) -> Result<String, heraclitus_core::HeraclitusError> {
    let log = Log::open(dir, 256 * 1024 * 1024, FsyncPolicy::Always)?;
    let sealed = log.sealed_segments();
    let mut out = format!(
        "head lsn: {}\nsealed segments: {}\n",
        log.head(),
        sealed.len()
    );
    for s in &sealed {
        out += &format!(
            "  seg {:06}  lsn [{}, {}]  merkle {}\n",
            s.id,
            s.base_lsn,
            s.max_lsn,
            s.blake3_root
                .map(|r| format!("{:02x}{:02x}..", r[0], r[1]))
                .unwrap_or_default()
        );
    }
    Ok(out)
}

pub fn verify(dir: &std::path::Path) -> Result<String, heraclitus_core::HeraclitusError> {
    let log = Log::open(dir, 256 * 1024 * 1024, FsyncPolicy::Always)?;
    // `log.verify()` já devolve `Err(Corruption)` numa raiz Merkle divergente
    // (o `?` propaga) — e `main` agora sai com código 1 em qualquer `Err`.
    let r = log.verify()?;
    Ok(format!(
        "segments: {}  records: {}  merkle ok: {}\nall crc checks passed",
        r.segments, r.records, r.merkle_ok
    ))
}

/// Anchor the current sealed state with a legal timestamp (RFC 3161). With no
/// `--tsa-url`, an in-process dev ACT is used (proves the flow without
/// credentials); with one, a real homologated ACT (e.g. SERPRO) is called.
pub fn anchor(
    log_dir: &std::path::Path,
    receipts_dir: &std::path::Path,
    tsa_url: Option<String>,
    policy: String,
) -> Result<String, String> {
    use heraclitus_compliance::{anchor, current_watermark, HttpTsa, LocalTsa, TsaClient};
    let log =
        Log::open(log_dir, 256 * 1024 * 1024, FsyncPolicy::Always).map_err(|e| e.to_string())?;
    if current_watermark(&log) == 0 {
        return Ok(
            "nada selado para ancorar (sem segmentos selados); apenda mais eventos primeiro".into(),
        );
    }
    let tsa: Box<dyn TsaClient> = match tsa_url {
        Some(u) => Box::new(HttpTsa::new(u, policy)),
        None => Box::new(LocalTsa::generate(policy)),
    };
    let r = anchor(&log, tsa.as_ref(), receipts_dir, None).map_err(|e| e.to_string())?;
    Ok(format!(
        "ancorado: LSN {} · {} segmentos · root {}…\n  imprint SHA-256 {}…\n  carimbo {} (ms epoch) · ACT '{}'\n  recibo: {}",
        r.lsn,
        r.segments,
        &r.root_hex[..r.root_hex.len().min(16)],
        &r.imprint_hex[..r.imprint_hex.len().min(16)],
        r.gen_unix_ms,
        r.policy,
        r.token_file
    ))
}

/// Re-verify every persisted receipt against the live log — the forensic check.
/// A FALHA means the log was altered retroactively below that watermark.
pub fn verify_receipts(
    log_dir: &std::path::Path,
    receipts_dir: &std::path::Path,
) -> Result<String, String> {
    use heraclitus_compliance::{load_manifest, verify_receipt};
    let log =
        Log::open(log_dir, 256 * 1024 * 1024, FsyncPolicy::Always).map_err(|e| e.to_string())?;
    let receipts = load_manifest(receipts_dir).map_err(|e| e.to_string())?;
    if receipts.is_empty() {
        return Ok("nenhum recibo encontrado (manifest.jsonl vazio ou ausente)".into());
    }
    // Forensic step 1: recompute every sealed-segment Merkle root from the
    // actual records (the M0 guarantee). This catches record-level tampering
    // that a stale footer root would otherwise hide.
    // `log.verify()` devolve `Err` numa raiz Merkle divergente (adulteração de
    // registos) — nesse caso os recibos não são confiáveis; falhar o processo.
    let mut out = match log.verify() {
        Ok(r) => format!(
            "integridade do log: OK (segmentos {} · registos {} · merkle recalculado {})\n",
            r.segments, r.records, r.merkle_ok
        ),
        Err(e) => {
            return Err(format!(
                "*** INTEGRIDADE DO LOG FALHOU: {e} — o log foi adulterado; recibos não confiáveis. ***"
            ))
        }
    };
    out += &format!("{} recibo(s) a verificar:\n", receipts.len());
    let mut all_ok = true;
    for r in &receipts {
        match verify_receipt(&log, receipts_dir, r) {
            Ok(v) => {
                out += &format!(
                    "  OK    LSN {:>12}  {} seg  carimbo {} ms  ACT '{}'\n",
                    r.lsn, r.segments, v.gen_unix_ms, r.policy
                );
            }
            Err(e) => {
                all_ok = false;
                out += &format!("  FALHA LSN {:>12}  {}\n", r.lsn, e);
            }
        }
    }
    if all_ok {
        out += "\nTODOS os recibos conferem — log íntegro e não adulterado retroativamente.";
        Ok(out)
    } else {
        out += "\n*** ATENÇÃO: pelo menos um recibo NÃO confere — possível adulteração retroativa do log. ***";
        Err(out)
    }
}

/// Synthetic hierarchical dataset (WordNet-shaped): a b-ary tree embedded by
/// Sarkar-style construction — depth becomes radius, children fan out in
/// angle. Ground truth for recall is exact brute force.
pub fn synth_tree(n: usize, dim: usize, seed: u64) -> Vec<Vec<f32>> {
    let mut pts = Vec::with_capacity(n);
    let mut state = seed.wrapping_add(0x9E3779B97F4A7C15);
    let mut rnd = move || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        (state >> 11) as f32 / (1u64 << 53) as f32
    };
    for i in 0..n {
        // depth in [0,6): log-distributed like a tree's node count per level
        let depth = ((i as f32).log2().max(0.0) / (n as f32).log2() * 6.0).min(5.9);
        let radius = 0.15 + 0.13 * depth; // deeper -> nearer the boundary
        let mut v: Vec<f32> = (0..dim).map(|_| rnd() * 2.0 - 1.0).collect();
        let norm: f32 = v.iter().map(|x| x * x).sum::<f32>().sqrt().max(1e-6);
        for x in v.iter_mut() {
            *x = *x / norm * radius;
        }
        project_to_ball(&mut v);
        pts.push(v);
    }
    pts
}

pub struct BenchReport {
    pub n: usize,
    pub dim: usize,
    pub build_secs: f64,
    /// (ef, qps, recall@10)
    pub curves: Vec<(usize, f64, f64)>,
}

impl BenchReport {
    pub fn to_markdown(&self) -> String {
        let mut s =
            String::from("| N | dim | build | ef | QPS | recall@10 |\n|---|---|---|---|---|---|\n");
        for (ef, qps, recall) in &self.curves {
            s += &format!(
                "| {} | {} | {:.2}s | {} | {:.0} | {:.3} |\n",
                self.n, self.dim, self.build_secs, ef, qps, recall
            );
        }
        s
    }
}

/// The M7 harness core: build the index over a hierarchical dataset, then
/// measure QPS × recall@10 against exact brute-force ground truth.
pub fn bench_recall(n: usize, dim: usize, queries: usize) -> BenchReport {
    // `--n 0` dava resto-por-zero em `(q * 37) % n`; dim=0 daria distâncias
    // triviais. Clamp com o mínimo útil em vez de panicar.
    let n = n.max(1);
    let dim = dim.max(1);
    let pts = synth_tree(n, dim, 42);
    let metric = ProductMetric::default();

    let t0 = Instant::now();
    let mut idx = VectorIndex::new(metric);
    let mut ids = Vec::with_capacity(n);
    for (i, p) in pts.iter().enumerate() {
        let id = EventId(ulid::Ulid::from_parts(i as u64, i as u128));
        ids.push(id);
        idx.insert(
            id,
            i as u64,
            ProductPoint {
                hyp: p.clone(),
                sph: vec![],
                euc: vec![],
            },
        );
    }
    let build_secs = t0.elapsed().as_secs_f64();

    // Query points: perturbed dataset points (realistic near-duplicates).
    let qpts: Vec<Vec<f32>> = (0..queries)
        .map(|q| {
            let mut v = pts[(q * 37) % n].clone();
            for x in v.iter_mut() {
                *x *= 0.98;
            }
            v
        })
        .collect();

    // Exact ground truth (brute force, hyperbolic distance).
    let truth: Vec<Vec<EventId>> = qpts
        .iter()
        .map(|q| {
            let mut d: Vec<(f64, EventId)> = pts
                .iter()
                .zip(&ids)
                .map(|(p, id)| (dist_hyp(q, p, 1.0), *id))
                .collect();
            d.sort_by(|a, b| a.0.total_cmp(&b.0));
            d.iter().take(10).map(|(_, id)| *id).collect()
        })
        .collect();

    let mut curves = Vec::new();
    for ef in [16usize, 32, 64, 128, 256] {
        let t = Instant::now();
        let mut hits_total = 0usize;
        for (q, qv) in qpts.iter().enumerate() {
            let res = idx.search(
                &ProductPoint {
                    hyp: qv.clone(),
                    sph: vec![],
                    euc: vec![],
                },
                10,
                ef,
                None,
            );
            hits_total += res.iter().filter(|h| truth[q].contains(&h.id)).count();
        }
        let secs = t.elapsed().as_secs_f64();
        curves.push((
            ef,
            queries as f64 / secs,
            hits_total as f64 / (queries * 10) as f64,
        ));
    }

    BenchReport {
        n,
        dim,
        build_secs,
        curves,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bench_harness_recall_sane() {
        // Small smoke run: high-ef recall must beat low-ef recall and clear 0.8.
        let r = bench_recall(2000, 16, 30);
        let lo = r.curves.first().unwrap().2;
        let hi = r.curves.last().unwrap().2;
        assert!(hi >= lo, "recall must not degrade with ef ({lo} -> {hi})");
        assert!(hi > 0.8, "recall@10 at ef=256 too low: {hi}");
    }
}
