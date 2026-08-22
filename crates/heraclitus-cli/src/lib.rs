//! heraclitus-cli — admin & inspection (§3.14) + the M7 QPS×recall harness.

use heraclitus_core::{EventId, FsyncPolicy, HeraclitusConfig, ProductPoint};
use heraclitus_crypto::KeyStore;
use heraclitus_index_vector::VectorIndex;
use heraclitus_log::v6::error::HARD_MAX_BLOCK_BYTES;
use heraclitus_log::v6::verify::{
    hex32, inspect as inspect_v6_segment, prove_lsn, verify_segment, IntegrityLevel,
};
use heraclitus_log::Log;
use heraclitus_manifold::{dist_hyp, project_to_ball, ProductMetric};
use std::time::Instant;

/// Tamanho de segmento para os `Log::open` do CLI.
///
/// Vem do default da config em vez de estar cravado: o valor governa o debito
/// de escrita (o indice do segmento ativo e copiado por lote — ver a doc de
/// `HeraclitusConfig::segment_max_bytes`), e o `migrate-encrypt` reescreve o
/// log INTEIRO por esta via. Deixar 256 MiB cravado aqui anulava a mudanca de
/// configuracao precisamente no caminho que mais escreve.
fn segmento() -> u64 {
    HeraclitusConfig::default().segment_max_bytes
}

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
    let log = Log::open(dir, segmento(), FsyncPolicy::Always)?;
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
    let log = Log::open(dir, segmento(), FsyncPolicy::Always)?;
    // `log.verify()` já devolve `Err(Corruption)` numa raiz Merkle divergente
    // (o `?` propaga) — e `main` agora sai com código 1 em qualquer `Err`.
    let r = log.verify()?;
    Ok(format!(
        "segments: {}  records: {}  merkle ok: {}\nall crc checks passed",
        r.segments, r.records, r.merkle_ok
    ))
}

/// Inspeciona um segmento HRKL v6 sem abrir o directório do banco.
///
/// Este comando é deliberadamente de leitura: não repara a cauda nem altera o
/// manifesto. Para um segmento RAW ainda activo, o relatório deixa explícito
/// que não há footer selado e, portanto, não há garantia forense completa.
pub fn inspect_v6(segment: &std::path::Path) -> Result<String, heraclitus_core::HeraclitusError> {
    inspect_v6_segment(segment, HARD_MAX_BLOCK_BYTES)
}

/// Mantém `heraclitus verify <log-dir>` retrocompatível e acrescenta o caminho
/// físico, somente-leitura, para um único segmento HRKL v6.
pub fn verify_target(target: &std::path::Path) -> Result<String, heraclitus_core::HeraclitusError> {
    verify_target_with_level(target, false)
}

/// Variante de [`verify_target`] que habilita a recomputação da raiz canónica
/// para um segmento v6 com `StoragePayload` actual. Um directório legado
/// continua a usar o verificador v1--v5; `--logical` não muda em silêncio a
/// semântica desse caminho.
pub fn verify_target_with_level(
    target: &std::path::Path,
    logical: bool,
) -> Result<String, heraclitus_core::HeraclitusError> {
    if target.is_dir() {
        if logical {
            return Err(heraclitus_core::HeraclitusError::Config(
                "--logical só é suportado para um arquivo HRKL v6; para um diretório legado use `verify <dir>`".into(),
            ));
        }
        return verify(target);
    }
    if target.is_file() {
        return verify_v6(target, logical);
    }
    Err(heraclitus_core::HeraclitusError::Config(format!(
        "alvo de verify não existe ou não é ficheiro/directório: {}",
        target.display()
    )))
}

/// Verifica a integridade física ou lógica de um HRKL v6. O modo lógico usa a
/// mesma ponte `StoragePayload -> (opaque_meta, Episode)` do writer e packer;
/// assim não há um hash de CLI diferente do que foi selado no footer.
fn verify_v6(
    segment: &std::path::Path,
    logical: bool,
) -> Result<String, heraclitus_core::HeraclitusError> {
    let level = if logical {
        IntegrityLevel::Logical
    } else {
        IntegrityLevel::Physical
    };
    let report = verify_segment(
        segment,
        level,
        HARD_MAX_BLOCK_BYTES,
        logical.then_some(&heraclitus_log::canonical_hash_storage_payload_v6),
    )?;
    if !report.is_ok() {
        let detail = if report.notes.is_empty() {
            "falha física sem detalhe adicional".to_owned()
        } else {
            report.notes.join("; ")
        };
        return Err(heraclitus_core::HeraclitusError::Corruption {
            context: format!("verificação HRKL v6: {}", segment.display()),
            detail,
        });
    }

    let scope = if logical { "logical + physical" } else { "physical" };
    let mut out = format!(
        "HRKL v6 {scope} verification passed\nsegment: {}\nlayout: {}\nrecords: {}\nlsn: {}..{}\nblocks: {}\nlogical root (declared): {}\n",
        segment.display(),
        report.layout.as_str(),
        report.record_count,
        report.min_lsn,
        report.max_lsn,
        report.block_count,
        hex32(&report.declared_root),
    );
    if logical {
        out.push_str(&format!(
            "logical root (recomputed): {}\n",
            report.recomputed_root.as_ref().map(hex32).unwrap_or_default()
        ));
    }
    if report.notes.is_empty() {
        out.push_str(&format!("sealed: yes\nscope: {scope} checks"));
    } else {
        out.push_str(&format!("sealed: incomplete\nscope: {scope} checks\nnotes:\n"));
        for note in report.notes {
            out.push_str(&format!("  - {note}\n"));
        }
    }
    Ok(out)
}

/// Emite uma prova de inclusão canónica para um LSN de um arquivo HRKL v6.
/// A operação é intencionalmente explícita: exige segmento selado e verifica a
/// decodificação do payload antes de construir a prova.
pub fn prove_v6_lsn(
    segment: &std::path::Path,
    lsn: u64,
) -> Result<String, heraclitus_core::HeraclitusError> {
    let proof = prove_lsn(
        segment,
        lsn,
        HARD_MAX_BLOCK_BYTES,
        &heraclitus_log::canonical_hash_storage_payload_v6,
    )?
    .ok_or_else(|| {
        heraclitus_core::HeraclitusError::Config(format!(
            "LSN {lsn} não existe no segmento HRKL v6: {}",
            segment.display()
        ))
    })?;
    if !proof.verify() {
        return Err(heraclitus_core::HeraclitusError::Corruption {
            context: format!("prova HRKL v6: {}", segment.display()),
            detail: "a prova construída não fecha contra a raiz declarada".into(),
        });
    }

    let mut out = format!(
        "HRKL v6 inclusion proof\nsegment: {}\nlsn: {}\ncanonical record hash: {}\nlogical root: {}\nleaf: {}/{}\nattestation imprint: {}\npath:\n",
        segment.display(),
        proof.lsn,
        hex32(&proof.canonical_record_hash),
        hex32(&proof.logical_root),
        proof.proof.leaf_index,
        proof.proof.leaf_count,
        hex32(&proof.envelope.imprint()),
    );
    for (index, step) in proof.proof.path.iter().enumerate() {
        let side = if step.sibling_is_left { "left" } else { "right" };
        out.push_str(&format!("  {index}: sibling {side} {}\n", hex32(&step.sibling)));
    }
    out.push_str("proof verifies: true");
    Ok(out)
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
        segmento(),
        FsyncPolicy::Always,
        source_keystore,
    )?;
    let source_report = source_log.verify()?;
    let head = source_log.head();

    std::fs::create_dir(&destination)?;
    let destination_keystore = KeyStore::open(destination.join("keys"))?;
    let destination_log = Log::open_with_keystore(
        destination.join("log"),
        segmento(),
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

/// Anchor the current sealed state as development evidence.
///
/// With no `--tsa-url`, an in-process dev ACT proves the end-to-end flow but
/// has no ICP-Brasil or legal validity. With one, the current client only stores
/// a raw external token over HTTP; HTTPS, CMS/X.509 and ICP-Brasil validation
/// are deliberately not claimed by this build.
pub fn anchor(
    log_dir: &std::path::Path,
    receipts_dir: &std::path::Path,
    tsa_url: Option<String>,
    policy: String,
) -> Result<String, String> {
    use heraclitus_compliance::{anchor, current_watermark, HttpTsa, LocalTsa, TsaClient};
    let log =
        Log::open(log_dir, segmento(), FsyncPolicy::Always).map_err(|e| e.to_string())?;
    if current_watermark(&log) == 0 {
        return Ok(
            "nada selado para ancorar (sem segmentos selados); apenda mais eventos primeiro".into(),
        );
    }
    let external_tsa = tsa_url.is_some();
    let tsa: Box<dyn TsaClient> = match tsa_url {
        Some(u) => Box::new(HttpTsa::new(u, policy)),
        None => Box::new(LocalTsa::generate(policy)),
    };
    let r = anchor(&log, tsa.as_ref(), receipts_dir, None).map_err(|e| e.to_string())?;
    let timestamp_note = if external_tsa {
        "token externo armazenado; cadeia CMS/X.509/ICP-Brasil NÃO validada; hora gravada é local"
    } else {
        "token de desenvolvimento verificado localmente; não é carimbo ICP-Brasil"
    };
    Ok(format!(
        "ancorado: LSN {} · {} segmentos · root {}…\n  imprint SHA-256 {}…\n  registro {} (ms epoch) · origem '{}' · {}\n  recibo: {}",
        r.lsn,
        r.segments,
        &r.root_hex[..r.root_hex.len().min(16)],
        &r.imprint_hex[..r.imprint_hex.len().min(16)],
        r.gen_unix_ms,
        r.policy,
        timestamp_note,
        r.token_file
    ))
}

/// Re-verify every persisted receipt against the live log — the forensic check.
/// A FALHA means the log was altered retroactively below that watermark. An
/// INCONCLUSIVO result means the commitment matches but the timestamp token
/// still has no external trust-chain verifier.
pub fn verify_receipts(
    log_dir: &std::path::Path,
    receipts_dir: &std::path::Path,
) -> Result<String, String> {
    use heraclitus_compliance::{
        load_manifest, verify_receipt, ReceiptVerification, TimestampValidationState,
    };
    let log =
        Log::open(log_dir, segmento(), FsyncPolicy::Always).map_err(|e| e.to_string())?;
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
    let mut integrity_ok = true;
    let mut timestamp_unvalidated = false;
    for r in &receipts {
        match verify_receipt(&log, receipts_dir, r) {
            Ok(ReceiptVerification::DevelopmentOnly(v)) => {
                out += &format!(
                    "  DEV   LSN {:>12}  {} seg  registro {} ms  origem '{}' (não ICP-Brasil)\n",
                    r.lsn, r.segments, v.gen_unix_ms, r.policy
                );
            }
            Ok(ReceiptVerification::CommitmentOnly(state)) => {
                timestamp_unvalidated = true;
                let detail = match state {
                    TimestampValidationState::ExternalTokenUnvalidated => {
                        "token externo sem validação CMS/X.509/ICP-Brasil"
                    }
                    TimestampValidationState::LegacyUnverified => {
                        "manifesto legado sem estado de validação"
                    }
                    TimestampValidationState::DevelopmentOnly => unreachable!(
                        "a verificação de desenvolvimento retorna DevelopmentOnly"
                    ),
                };
                out += &format!(
                    "  INCONCLUSIVO LSN {:>12}  commitment CONFERE · {}\n",
                    r.lsn, detail
                );
            }
            Err(e) => {
                integrity_ok = false;
                out += &format!("  FALHA LSN {:>12}  {}\n", r.lsn, e);
            }
        }
    }
    if !integrity_ok {
        out += "\n*** ATENÇÃO: pelo menos um recibo NÃO confere — possível adulteração retroativa do log. ***";
        Err(out)
    } else if timestamp_unvalidated {
        out += "\nINCONCLUSIVO: os commitments conferem; esta build não valida a cadeia de confiança dos tokens externos. Isto NÃO é uma deteção de fraude e NÃO é validação legal/ICP-Brasil.";
        Err(out)
    } else {
        out += "\nTodos os commitments e tokens de desenvolvimento conferem — nenhuma validação legal/ICP-Brasil foi executada.";
        Ok(out)
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

    struct ExternalTsa;

    impl heraclitus_compliance::TsaClient for ExternalTsa {
        fn policy_name(&self) -> &str {
            "ACT-externa-de-teste"
        }

        fn validation_state(&self) -> heraclitus_compliance::TimestampValidationState {
            heraclitus_compliance::TimestampValidationState::ExternalTokenUnvalidated
        }

        fn stamp(
            &self,
            _imprint: &[u8; 32],
        ) -> Result<Vec<u8>, heraclitus_compliance::CompError> {
            Ok(vec![0x30, 0x00])
        }
    }

    fn v6_hasher(lsn: u64, hlc: u64, payload: &[u8]) -> heraclitus_log::v6::V6Result<[u8; 32]> {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"HERACLITUS:CLI:V6:TEST\\0");
        hasher.update(&lsn.to_le_bytes());
        hasher.update(&hlc.to_le_bytes());
        hasher.update(payload);
        Ok(*hasher.finalize().as_bytes())
    }

    fn write_v6_raw(path: &std::path::Path, records: u64) {
        use heraclitus_log::v6::raw::{RawSegmentWriter, SegmentInit};

        let mut writer = RawSegmentWriter::create(
            path,
            SegmentInit {
                segment_id: 17,
                created_hlc: 10,
                first_lsn: 100,
                writer_epoch: 1,
                storage_namespace_id: [0xA5; 16],
            },
        )
        .unwrap();
        for i in 0..records {
            let payload = format!("cli v6 record {i}").into_bytes();
            let lsn = 100 + i;
            let hlc = 1_000 + i;
            writer
                .append(lsn, hlc, &payload, &v6_hasher(lsn, hlc, &payload).unwrap())
                .unwrap();
        }
        writer.seal().unwrap();
    }

    #[test]
    fn cli_marks_unvalidated_external_token_inconclusive_not_tampered() {
        use heraclitus_compliance::anchor as anchor_receipt;
        use heraclitus_core::{Episode, EventKind};

        let root = tempfile::tempdir().unwrap();
        let log_dir = root.path().join("log");
        let receipts = root.path().join("receipts");
        let log = Log::open(&log_dir, 256, FsyncPolicy::Always).unwrap();
        for i in 0..120 {
            log.append(Episode::new(
                "auditor",
                EventKind::Observation,
                format!("evento {i}").into_bytes(),
            ))
            .unwrap();
        }
        anchor_receipt(&log, &ExternalTsa, &receipts, None).unwrap();
        drop(log);

        let report = verify_receipts(&log_dir, &receipts).unwrap_err();
        assert!(report.contains("INCONCLUSIVO"));
        assert!(report.contains("NÃO é uma deteção de fraude"));
        assert!(!report.contains("possível adulteração retroativa"));
    }

    #[test]
    fn cli_inspect_and_verify_v6_raw_and_packed_segments() {
        use heraclitus_log::v6::packed::PackOptions;
        use heraclitus_log::v6::packer::pack_segment;

        let root = tempfile::tempdir().unwrap();
        let raw = root.path().join("000017.hrkl");
        let packed = root.path().join("000017.g1.hrkl");
        write_v6_raw(&raw, 128);
        pack_segment(&raw, &packed, PackOptions::default(), 0, 1, &v6_hasher).unwrap();

        let raw_inspect = inspect_v6(&raw).unwrap();
        assert!(raw_inspect.contains("Physical Layout      RAW"));
        assert!(verify_target(&raw)
            .unwrap()
            .contains("physical verification passed"));

        let packed_inspect = inspect_v6(&packed).unwrap();
        assert!(packed_inspect.contains("Physical Layout      PACKED"));
        assert!(verify_target(&packed)
            .unwrap()
            .contains("physical verification passed"));
    }

    #[test]
    fn cli_verify_v6_returns_error_for_a_corrupted_packed_block() {
        use heraclitus_log::v6::block::BLOCK_HEADER_LEN;
        use heraclitus_log::v6::header::FILE_HEADER_LEN;
        use heraclitus_log::v6::packed::PackOptions;
        use heraclitus_log::v6::packer::pack_segment;

        let root = tempfile::tempdir().unwrap();
        let raw = root.path().join("000017.hrkl");
        let packed = root.path().join("000017.g1.hrkl");
        write_v6_raw(&raw, 128);
        pack_segment(&raw, &packed, PackOptions::default(), 0, 1, &v6_hasher).unwrap();

        let mut bytes = std::fs::read(&packed).unwrap();
        bytes[FILE_HEADER_LEN + BLOCK_HEADER_LEN + 3] ^= 0xFF;
        std::fs::write(&packed, bytes).unwrap();

        let error = verify_target(&packed).unwrap_err();
        assert!(error.to_string().contains("verificação HRKL v6"));
    }

    #[test]
    fn cli_logical_verify_and_prove_use_the_official_storage_payload_hasher() {
        use heraclitus_core::{Episode, EventKind};
        use heraclitus_log::v6::V6Log;

        let root = tempfile::tempdir().unwrap();
        let v6_root = root.path().join("v6");
        let log = V6Log::open(&v6_root, 1 << 20, FsyncPolicy::Always).unwrap();
        for i in 0..5 {
            log.append(Episode::new(
                "cli-proof",
                EventKind::Observation,
                format!("record-{i}").into_bytes(),
            ))
            .unwrap();
        }
        log.seal_active().unwrap();
        let segment = v6_root
            .join("segments")
            .join("00000000000000000000.g0000.raw.hrkl");

        let verification = verify_target_with_level(&segment, true).unwrap();
        assert!(verification.contains("logical + physical verification passed"));
        assert!(verification.contains("logical root (recomputed)"));

        let proof = prove_v6_lsn(&segment, 3).unwrap();
        assert!(proof.contains("lsn: 3"));
        assert!(proof.contains("proof verifies: true"));
    }

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
