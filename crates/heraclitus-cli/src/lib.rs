//! heraclitus-cli — admin & inspection (§3.14) + the M7 QPS×recall harness.

use heraclitus_core::{EventId, FsyncPolicy, ProductPoint};
use heraclitus_crypto::KeyStore;
use heraclitus_index_vector::VectorIndex;
use heraclitus_log::Log;
use heraclitus_manifold::{dist_hyp, project_to_ball, ProductMetric};
use std::time::Instant;

/// Cria duas identidades de bootstrap com tokens CSPRNG. Os tokens só são
/// escritos em arquivos `create_new`; stdout contém caminhos, nunca segredos.
/// Em produção, mova `admin.token` para cofre/offline e aplique ACL do SO.
pub fn init_credentials(
    output: &std::path::Path,
) -> Result<String, heraclitus_core::HeraclitusError> {
    use heraclitus_core::HeraclitusError;
    use rand::RngCore;
    use std::io::Write;

    if output.exists() {
        return Err(HeraclitusError::Config(format!(
            "diretório de credenciais já existe: {}",
            output.display()
        )));
    }
    let name = output.file_name().ok_or_else(|| {
        HeraclitusError::Config("diretório de credenciais não pode ser raiz de volume".into())
    })?;
    let parent = output.parent().ok_or_else(|| {
        HeraclitusError::Config("diretório de credenciais precisa de pai explícito".into())
    })?;
    std::fs::create_dir_all(parent)?;
    let output = std::fs::canonicalize(parent)?.join(name);
    std::fs::create_dir(&output)?;

    fn make_token(path: &std::path::Path) -> Result<String, std::io::Error> {
        let mut bytes = [0u8; 48];
        rand::thread_rng().fill_bytes(&mut bytes);
        let token: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        }
        file.write_all(token.as_bytes())?;
        file.sync_all()?;
        Ok(token)
    }

    let writer_path = output.join("writer.token");
    let admin_path = output.join("admin.token");
    let writer = make_token(&writer_path)?;
    let admin = make_token(&admin_path)?;
    let credentials = serde_json::json!([
        {
            "principal": "forge-writer",
            "token_blake3": blake3::hash(writer.as_bytes()).to_hex().to_string(),
            "roles": ["writer"]
        },
        {
            "principal": "security-admin",
            "token_blake3": blake3::hash(admin.as_bytes()).to_hex().to_string(),
            "roles": ["admin", "auditor"]
        }
    ]);
    let credentials_path = output.join("credentials.json");
    let mut credentials_file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&credentials_path)?;
    let encoded = serde_json::to_vec_pretty(&credentials)
        .map_err(|error| HeraclitusError::Serialization(error.to_string()))?;
    credentials_file.write_all(&encoded)?;
    credentials_file.sync_all()?;

    Ok(format!(
        "credenciais criadas sem exibir tokens: credentials={}; writer={}; admin={}",
        credentials_path.display(),
        writer_path.display(),
        admin_path.display()
    ))
}

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

/// Migração offline e não destrutiva para encryption-at-rest.
///
/// A origem e o destino são *data dirs* (cada um contém `log/`). O destino tem
/// de não existir: isto impede sobreposição, mistura de épocas e overwrite
/// acidental. A migração fixa o `head`, verifica a origem, lê em páginas e usa
/// `append_replicated`, preservando LSN/EventId/HLC enquanto a serialização do
/// log cifra content, attrs e embedding com uma chave por `agent_id`.
pub fn migrate_encrypt(
    source: &std::path::Path,
    destination: &std::path::Path,
) -> Result<String, heraclitus_core::HeraclitusError> {
    use heraclitus_core::HeraclitusError;

    let source = std::fs::canonicalize(source)?;
    let source_log = source.join("log");
    if !source_log.is_dir() {
        return Err(HeraclitusError::Config(format!(
            "origem não contém diretório de log: {}",
            source_log.display()
        )));
    }
    if destination.exists() {
        return Err(HeraclitusError::Config(format!(
            "destino já existe; use um diretório novo: {}",
            destination.display()
        )));
    }
    let name = destination
        .file_name()
        .ok_or_else(|| HeraclitusError::Config("destino não pode ser raiz de volume".into()))?;
    let parent = destination.parent().ok_or_else(|| {
        HeraclitusError::Config("destino deve ter um diretório pai explícito".into())
    })?;
    std::fs::create_dir_all(parent)?;
    let destination = std::fs::canonicalize(parent)?.join(name);
    if destination.starts_with(&source) || source.starts_with(&destination) {
        return Err(HeraclitusError::Config(
            "origem e destino não podem conter um ao outro".into(),
        ));
    }

    let source_keys = source.join("keys");
    let source_keystore = source_keys
        .is_dir()
        .then(|| KeyStore::open(&source_keys))
        .transpose()?;
    let source_log = Log::open_with_keystore(
        &source_log,
        256 * 1024 * 1024,
        FsyncPolicy::Always,
        source_keystore,
    )?;
    let source_report = source_log.verify()?;
    let head = source_log.head();

    std::fs::create_dir(&destination)?;
    let destination_keystore = KeyStore::open(destination.join("keys"))?;
    let destination_log = Log::open_with_keystore(
        destination.join("log"),
        256 * 1024 * 1024,
        FsyncPolicy::Always,
        Some(destination_keystore),
    )?;

    let mut cursor = 0u64;
    let mut copied = 0u64;
    while cursor < head {
        let page = source_log.scan_capped(cursor, head, 4096)?;
        if page.is_empty() {
            return Err(HeraclitusError::Corruption {
                context: format!("migração no LSN {cursor}"),
                detail: "origem terminou antes do head fixado".into(),
            });
        }
        for (lsn, episode) in page {
            if lsn != cursor {
                return Err(HeraclitusError::Corruption {
                    context: format!("migração no LSN {cursor}"),
                    detail: format!("histórico não contíguo; próximo LSN é {lsn}"),
                });
            }
            destination_log.append_replicated(lsn, episode)?;
            cursor = cursor.saturating_add(1);
            copied = copied.saturating_add(1);
        }
    }
    destination_log.flush()?;
    let destination_report = destination_log.verify()?;
    if destination_log.head() != head || copied != head {
        return Err(HeraclitusError::Corruption {
            context: "migração cifrada".into(),
            detail: format!(
                "contagem divergente: origem head={head}; destino head={}; copiados={copied}",
                destination_log.head()
            ),
        });
    }

    Ok(format!(
        "migração cifrada concluída: {copied} evento(s); origem {} segmento(s)/{} registro(s); destino {} segmento(s)/{} registro(s); origem preservada em {}; destino {}",
        source_report.segments,
        source_report.records,
        destination_report.segments,
        destination_report.records,
        source.display(),
        destination.display()
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

    #[test]
    fn migrate_encrypt_preserves_identity_and_hides_plaintext() {
        use heraclitus_core::{Episode, EventKind};

        let root = tempfile::tempdir().unwrap();
        let source = root.path().join("source");
        let destination = root.path().join("encrypted");
        let source_log = Log::open(source.join("log"), 1024 * 1024, FsyncPolicy::Always).unwrap();
        let mut episode = Episode::new(
            "titular:hmac-sha256:abc",
            EventKind::Observation,
            b"PII-MIGRATION-UNIQUE-4471".to_vec(),
        );
        episode.session_id = "sessao".into();
        episode
            .attrs
            .insert("matricula".into(), "SERVIDOR-99881".into());
        let (lsn, stamped) = source_log.append_stamped(episode).unwrap();
        source_log.flush().unwrap();
        drop(source_log);

        let report = migrate_encrypt(&source, &destination).unwrap();
        assert!(report.contains("1 evento(s)"));

        let raw: Vec<u8> = std::fs::read_dir(destination.join("log"))
            .unwrap()
            .filter_map(|entry| entry.ok())
            .filter(|entry| entry.path().extension().is_some_and(|x| x == "hrkl"))
            .flat_map(|entry| std::fs::read(entry.path()).unwrap())
            .collect();
        assert!(!raw.windows(25).any(|w| w == b"PII-MIGRATION-UNIQUE-4471"));
        assert!(!raw.windows(14).any(|w| w == b"SERVIDOR-99881"));

        let keys = KeyStore::open(destination.join("keys")).unwrap();
        let encrypted = Log::open_with_keystore(
            destination.join("log"),
            1024 * 1024,
            FsyncPolicy::Always,
            Some(keys),
        )
        .unwrap();
        let (_, restored) = encrypted.read(lsn).unwrap().unwrap();
        assert_eq!(restored.id, stamped.id);
        assert_eq!(restored.ts_hlc, stamped.ts_hlc);
        assert_eq!(restored.content, b"PII-MIGRATION-UNIQUE-4471");
        assert_eq!(restored.attrs["matricula"], "SERVIDOR-99881");
        assert!(encrypted.verify().is_ok());
    }

    #[test]
    fn migrate_encrypt_refuses_existing_destination() {
        let root = tempfile::tempdir().unwrap();
        let source = root.path().join("source");
        std::fs::create_dir_all(source.join("log")).unwrap();
        let destination = root.path().join("existing");
        std::fs::create_dir(&destination).unwrap();
        let error = migrate_encrypt(&source, &destination).unwrap_err();
        assert!(error.to_string().contains("destino já existe"));
    }

    #[test]
    fn init_credentials_hashes_match_tokens_and_refuses_overwrite() {
        let root = tempfile::tempdir().unwrap();
        let output = root.path().join("secrets");
        let message = init_credentials(&output).unwrap();
        let writer = std::fs::read_to_string(output.join("writer.token")).unwrap();
        assert!(!message.contains(&writer));
        let credentials: serde_json::Value =
            serde_json::from_slice(&std::fs::read(output.join("credentials.json")).unwrap())
                .unwrap();
        for (index, name) in [(0, "writer.token"), (1, "admin.token")] {
            let token = std::fs::read_to_string(output.join(name)).unwrap();
            assert_eq!(token.len(), 96);
            assert_eq!(
                credentials[index]["token_blake3"].as_str().unwrap(),
                blake3::hash(token.as_bytes()).to_hex().as_str()
            );
        }
        assert!(init_credentials(&output)
            .unwrap_err()
            .to_string()
            .contains("já existe"));
    }
}
