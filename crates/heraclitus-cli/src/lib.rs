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

/// Reconstrói sidecars HRKI pelo caminho vivo do v6 e commita as referências
/// no HRKM. A operação deve ser executada com o writer parado: abrir dois
/// writers sobre a mesma raiz não é uma forma de coordenação entre processos.
pub fn rebuild_index_v6(
    root: &std::path::Path,
    fpr: f64,
    index_agent_id: bool,
    index_session_id: bool,
) -> Result<String, heraclitus_core::HeraclitusError> {
    use heraclitus_log::v6::hrki::{IndexPolicy, IndexPolicySet};
    use heraclitus_log::v6::V6Log;

    if !fpr.is_finite() || !(1e-6..=0.5).contains(&fpr) {
        return Err(heraclitus_core::HeraclitusError::Config(format!(
            "HRKI fpr deve estar em [0.000001, 0.5]; recebido {fpr}"
        )));
    }
    if !root.join("manifests").is_dir() || !root.join("segments").is_dir() {
        return Err(heraclitus_core::HeraclitusError::Config(format!(
            "rebuild-index exige a raiz HRKL v6 com manifests/ e segments/: {}",
            root.display()
        )));
    }
    let mut policy = IndexPolicySet::new();
    if index_agent_id {
        policy = policy.com("agent_id", IndexPolicy::PublicTechnical);
    }
    if index_session_id {
        policy = policy.com("session_id", IndexPolicy::PublicTechnical);
    }
    let log = V6Log::open(root, segmento(), FsyncPolicy::Always)?;
    let outcomes = log.build_pending_hrki(&policy, None, fpr)?;
    let manifest = log.manifest();
    let valid = manifest
        .segments_v2
        .iter()
        .filter(|segment| segment.hrki.is_some())
        .count();
    Ok(format!(
        "HRKI rebuild concluído: {} reconstruído(s); {} sidecar(s) válido(s); manifest generation {}",
        outcomes.len(), valid, manifest.manifest_generation
    ))
}

/// Diagnóstico forense somente-leitura. Findings são devolvidos no texto; uma
/// divergência crítica também resulta em erro/código de saída 1 no binário.
pub fn storage_doctor_v6(
    root: &std::path::Path,
) -> Result<String, heraclitus_core::HeraclitusError> {
    let report = heraclitus_log::v6::doctor_storage(root)?;
    let rendered = report.render();
    if report.has_critical() {
        return Err(heraclitus_core::HeraclitusError::Corruption {
            context: "HRKL v6 storage doctor".into(),
            detail: rendered,
        });
    }
    Ok(rendered)
}

/// SPEC-0050 §120 — `heraclitus manifest show`.
///
/// Rende o HRKM tal como está em disco, incluindo as três filas de trabalho de
/// fundo (§144--§146) e os dois watermarks. É a forma de responder à pergunta
/// operacional que nenhum outro comando responde: *o trabalho derivado está a
/// acompanhar o log, ou está a ficar para trás?*
///
/// Read-only como o resto do grupo de diagnóstico: abre o `ManifestStore` em
/// modo de leitura e nunca o `V6Log`, porque o boot vivo repara a cauda e
/// reconcilia órfãos — diagnosticar alterando o objecto do diagnóstico não é
/// diagnosticar.
pub fn manifest_show_v6(
    root: &std::path::Path,
) -> Result<String, heraclitus_core::HeraclitusError> {
    use heraclitus_log::v6::manifest::ManifestStore;

    let store = ManifestStore::open_read_only(root.join("manifests"))?;
    let loaded = store
        .load()?
        .ok_or_else(|| heraclitus_core::HeraclitusError::Corruption {
            context: "HRKL v6 manifest show".into(),
            detail: format!("nenhuma geração HRKM válida em {}", root.display()),
        })?;
    let m = &loaded.manifest;
    let (canonicos, derivados) = m.storage_bytes();

    let mut out = format!(
        "HRKL v6 manifest
root: {}
namespace: {}
manifest generation: {}
recovered by scan: {}
segments: {}
committed lsn (cumulative watermark): {}
exported through lsn: {}
export lag: {}
canonical bytes: {}
derived bytes: {}
packing queue: {:?}
sidecar queue: {:?}
lakehouse queue: {:?}

",
        root.display(),
        m.storage_namespace_id
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>(),
        loaded.generation,
        loaded.recovered_by_scan,
        m.segments_v2.len(),
        m.cumulative_watermark,
        m.exported_through_lsn,
        m.cumulative_watermark
            .saturating_sub(m.exported_through_lsn),
        canonicos,
        derivados,
        m.packing_queue(),
        m.sidecar_queue(),
        m.lakehouse_queue(),
    );
    for s in &m.segments_v2 {
        let activa = s
            .active()
            .map(|g| format!("g{:04} {:?} {:?}", g.generation, g.layout, g.state))
            .unwrap_or_else(|| "SEM GERAÇÃO ACTIVA".to_string());
        out.push_str(&format!(
            "segment {:>6}  lsn [{}, {}]  records {:>8}  active {}  generations {}  hrki {}  parquet {}
",
            s.segment_id,
            s.first_lsn,
            s.last_lsn,
            s.record_count,
            activa,
            s.generations.len(),
            marca(s.hrki.as_ref().map(|a| a.logical_root), s.logical_root),
            marca(s.parquet.as_ref().map(|a| a.logical_root), s.logical_root),
        ));
    }
    Ok(out)
}

/// SPEC-0050 §129--§133 — `heraclitus migrate-v6`.
///
/// Migra um diretório de log v1--v5 para uma raiz HRKL v6 nova. É a peça que
/// faltava para o v6 ser adoptável: sem ela, tudo o que as Fases 0--6
/// construíram estava inalcançável para quem já tem dados.
///
/// **Não destrói nada.** A origem fica byte a byte intacta (§133), o destino
/// tem de não existir (§83), e cada segmento deixa um recibo verificável em
/// `<destino>/receipts/` com a raiz legada e a raiz lógica v6 lado a lado
/// (§132) — sem as confundir, que é o erro que §131 existe para impedir.
///
/// Depois de correr, o operador aponta a configuração ao destino com
/// `storage_format = "v6"`. A origem só deve ser apagada depois de os recibos
/// terem sido verificados — e essa decisão é dele, nunca deste comando.
pub fn migrate_v6(
    legacy_dir: &std::path::Path,
    destination: &std::path::Path,
    verify: bool,
) -> Result<String, heraclitus_core::HeraclitusError> {
    use heraclitus_log::v6::{migrate_database, MigrateDatabaseOptions};

    let relatorio = migrate_database(
        legacy_dir,
        destination,
        MigrateDatabaseOptions {
            verify,
            created_hlc: 0,
            storage_namespace_id: None,
        },
    )?;

    let mut out = format!(
        "HRKL v6 migrate
origem:  {}
destino: {}
namespace: {}
segmentos: {}
registos: {}
lsn: [{}, {}]
manifest generation: {}
cauda activa legada selada: {}
equivalencia verificada: {}

",
        legacy_dir.display(),
        destination.display(),
        relatorio
            .storage_namespace_id
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>(),
        relatorio.segments.len(),
        relatorio.records,
        relatorio.first_lsn,
        relatorio.last_lsn,
        relatorio.manifest_generation,
        if relatorio.legacy_tail_sealed { "sim" } else { "nao havia" },
        if verify { "sim" } else { "NAO (--no-verify)" },
    );
    for s in &relatorio.segments {
        out.push_str(&format!(
            "segment {:>6}  v{}  lsn [{}, {}]  registos {:>8}  raiz legada {}  recibo {}
",
            s.segment_id,
            s.legacy_format,
            s.first_lsn,
            s.last_lsn,
            s.records,
            match s.legacy_root_ok {
                Some(true) => "confere",
                Some(false) => "DIVERGE",
                None => "cauda (sem rodape)",
            },
            s.receipt_path
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default(),
        ));
    }
    if !relatorio.is_clean() {
        return Err(heraclitus_core::HeraclitusError::Corruption {
            context: "HRKL v6 migrate".into(),
            detail: out,
        });
    }
    out.push_str(
        "
A origem NAO foi alterada. Aponte a configuracao ao destino com
         storage_format = \"v6\" e so apague o legado depois de verificar os recibos.
",
    );
    Ok(out)
}

/// SPEC-0050 §120/§203 — `heraclitus export`.
///
/// Corre uma passagem completa da projecção lakehouse sobre um storage root
/// v6: fila do HRKM -> Parquet -> Iceberg -> Delta -> watermark -> HRKM.
///
/// É o mesmo trabalhador que o servidor corre em background, e não uma segunda
/// implementação. Duas implementações do mesmo export divergiriam, e a que
/// divergisse seria a do caminho menos exercitado — a mesma razão pela qual a
/// verificação do tier frio partilha o `verify_packed_reader` do log.
///
/// Ao contrário do resto do grupo de diagnóstico, este comando **escreve**:
/// materializa objectos no destino e comita uma geração nova do HRKM. Por isso
/// abre o `V6Log` a sério, e não o `ManifestStore` em leitura.
pub fn export_lakehouse_v6(
    root: &std::path::Path,
    destino: &str,
    tabela: &str,
) -> Result<String, heraclitus_core::HeraclitusError> {
    use heraclitus_log::v6::V6Log;
    use std::sync::Arc;

    if !destino.contains("://") {
        std::fs::create_dir_all(destino)?;
    }
    let log = Arc::new(V6Log::open(root, segmento(), FsyncPolicy::Always)?);
    let worker = heraclitus_tier::LakehouseWorker::open_location(
        destino,
        tabela.to_string(),
        log.manifest().storage_namespace_id,
    )?;

    // Runtime de uma só thread: o CLI é um processo de uma tarefa, e o
    // `object_store` precisa de um executor. Um runtime multi-thread aqui
    // custaria threads para nada.
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| {
            heraclitus_core::HeraclitusError::StorageEngine(format!("runtime do export: {e}"))
        })?;
    let saidas = rt.block_on(worker.export_pending(&log))?;

    if saidas.is_empty() {
        return Ok(format!(
            "HRKL v6 export
tabela: {tabela}
destino: {destino}
nada por exportar; a projecção está em dia (exported_through_lsn = {})
",
            log.manifest().exported_through_lsn
        ));
    }
    let mut out = format!(
        "HRKL v6 export
tabela: {tabela}
destino: {destino}
segmentos exportados: {}
",
        saidas.len()
    );
    for s in &saidas {
        out.push_str(&format!(
            "segment {:>6} g{:04}  lsn [{}, {}]  rows {:>8}  bytes {:>10}  delta v{}  {}  {}
",
            s.segment_id,
            s.generation,
            s.first_lsn,
            s.last_lsn,
            s.rows,
            s.size,
            s.delta_version
                .map(|v| v.to_string())
                .unwrap_or_else(|| "-".into()),
            if s.attached {
                "ligado ao HRKM"
            } else {
                "ÓRFÃO (a geração mudou durante o export; reexportável)"
            },
            s.path,
        ));
    }
    let m = log.manifest();
    out.push_str(&format!(
        "exported through lsn: {}
export lag: {}
",
        m.exported_through_lsn,
        m.cumulative_watermark
            .saturating_sub(m.exported_through_lsn)
    ));
    Ok(out)
}

/// `-` = ausente, `ok` = em dia, `obsoleto` = existe mas descreve outra raiz.
fn marca(artefacto: Option<[u8; 32]>, raiz: [u8; 32]) -> &'static str {
    match artefacto {
        None => "-",
        Some(r) if r == raiz => "ok",
        Some(_) => "obsoleto",
    }
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
    trust_store_dir: Option<&std::path::Path>,
) -> Result<String, String> {
    use heraclitus_compliance::icp::TimestampValidationPolicy;
    use heraclitus_compliance::secure_tsa::{SecureTsaClient, TlsPolicy};
    use heraclitus_compliance::trust_store::TrustStore;
    use heraclitus_compliance::{anchor, current_watermark, HttpTsa, LocalTsa, TsaClient};
    let log =
        Log::open(log_dir, segmento(), FsyncPolicy::Always).map_err(|e| e.to_string())?;
    if current_watermark(&log) == 0 {
        return Ok(
            "nada selado para ancorar (sem segmentos selados); apenda mais eventos primeiro".into(),
        );
    }
    // A MESMA armadilha que estava no servidor: um URL `https://` entregue ao
    // `HttpTsa` só falha na primeira tentativa de carimbo, com um erro sobre o
    // esquema que não aponta para a causa. O esquema decide o cliente.
    let external_tsa = tsa_url.is_some();
    let tsa: Box<dyn TsaClient> = match tsa_url {
        Some(u) if u.starts_with("https://") => {
            let dir = trust_store_dir.ok_or_else(|| {
                format!(
                    "`{u}` é https:// e exige --trust-store com as âncoras do órgão (§11): \
                     sem âncoras não há como autenticar a ACT, e um carimbo que ninguém \
                     autenticou não é evidência"
                )
            })?;
            let (store, relatorio) = TrustStore::load_dir(dir)
                .map_err(|e| format!("trust store `{}`: {e}", dir.display()))?;
            if store.is_empty() {
                return Err(format!(
                    "trust store `{}` sem âncoras utilizáveis ({} ficheiro(s) vistos)",
                    dir.display(),
                    relatorio.files_seen
                ));
            }
            Box::new(
                SecureTsaClient::new(
                    u,
                    policy,
                    store,
                    TlsPolicy::default(),
                    std::time::Duration::from_secs(15),
                )
                .map_err(|e| e.to_string())?
                .with_verifier(TimestampValidationPolicy::default()),
            )
        }
        Some(u) => Box::new(HttpTsa::new(u, policy)),
        None => Box::new(LocalTsa::generate(policy)),
    };
    let verificado = tsa.validation_state()
        == heraclitus_compliance::TimestampValidationState::ExternalTokenVerified;
    let r = anchor(&log, tsa.as_ref(), receipts_dir, None).map_err(|e| e.to_string())?;
    let timestamp_note = if verificado {
        "token externo VERIFICADO contra as âncoras instaladas; hora é a da autoridade · \
         revogação não consultada por esta via"
    } else if external_tsa {
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
    trust_store_dir: Option<&std::path::Path>,
    crl_dir: Option<&std::path::Path>,
) -> Result<String, String> {
    use heraclitus_compliance::icp::{IcpBrasilTimestampVerifier, TimestampValidationPolicy};
    use heraclitus_compliance::trust_store::TrustStore;
    use heraclitus_compliance::{
        load_manifest, verify_receipt, verify_receipt_with_verifier, ReceiptVerification,
        TimestampValidationState,
    };
    let log =
        Log::open(log_dir, segmento(), FsyncPolicy::Always).map_err(|e| e.to_string())?;
    let receipts = load_manifest(receipts_dir).map_err(|e| e.to_string())?;
    if receipts.is_empty() {
        return Ok("nenhum recibo encontrado (manifest.jsonl vazio ou ausente)".into());
    }
    // §11 — as âncoras vêm de uma pasta que o OPERADOR indica. Uma falha a
    // carregá-las é fatal e não silenciosa: continuar sem verificador daria um
    // relatório "INCONCLUSIVO" que se leria como "não há verificador nesta
    // build", quando na verdade o operador PEDIU um e ele não abriu.
    let verificador = match trust_store_dir {
        Some(d) => {
            let (store, relatorio) = TrustStore::load_dir(d).map_err(|e| {
                format!("trust store `{}` não carrega: {e}", d.display())
            })?;
            if store.is_empty() {
                return Err(format!(
                    "trust store `{}` não tem âncoras utilizáveis ({} ficheiro(s) vistos):                      sem âncoras não há cadeia contra que validar",
                    d.display(),
                    relatorio.files_seen
                ));
            }
            let mut v = IcpBrasilTimestampVerifier::new(
                store,
                TimestampValidationPolicy::default(),
            );
            if let Some(cd) = crl_dir {
                let (crls, rel) = heraclitus_compliance::crl::CrlStore::load_dir(cd)
                    .map_err(|e| format!("CRLs `{}`: {e}", cd.display()))?;
                if crls.is_empty() {
                    return Err(format!(
                        "pasta de CRLs `{}` sem CRLs utilizáveis ({} ficheiro(s) vistos)",
                        cd.display(),
                        rel.files_seen
                    ));
                }
                v = v.with_crls(crls, heraclitus_compliance::crl::CrlPolicy::default());
            }
            Some(v)
        }
        None => {
            if crl_dir.is_some() {
                // Sem âncoras não há cadeia, e sem cadeia não há certificado
                // cuja revogação consultar. Aceitar em silêncio daria um
                // relatório sem revogação a quem a pediu.
                return Err(
                    "--crl-dir exige --trust-store: a revogação consulta-se sobre os                      certificados de uma cadeia, e sem âncoras não há cadeia"
                        .into(),
                );
            }
            None
        }
    };
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
    let mut autoridade_confirmada = 0usize;
    for r in &receipts {
        let resultado = match &verificador {
            Some(v) => verify_receipt_with_verifier(&log, receipts_dir, r, v),
            None => verify_receipt(&log, receipts_dir, r),
        };
        match resultado {
            Ok(ReceiptVerification::AuthorityVerified(v)) => {
                autoridade_confirmada += 1;
                out += &format!(
                    "  OK    LSN {:>12}  {} seg  autoridade {} ms  âncora {}  cadeia {}  '{}'{}\n",
                    r.lsn,
                    r.segments,
                    v.gen_unix_ms,
                    &v.anchor_fingerprint_hex[..v.anchor_fingerprint_hex.len().min(16)],
                    v.chain_len,
                    v.signer_subject,
                    if v.revocation_checked {
                        ""
                    } else {
                        " · revogação NÃO consultada"
                    }
                );
            }
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
                    // Só chega aqui sem verificador instalado: com um, este
                    // estado teria seguido por `AuthorityVerified` ou falhado.
                    TimestampValidationState::ExternalTokenVerified => {
                        "recibo declara-se verificado · nenhum trust store passado a esta                          verificação, portanto a alegação NÃO foi reconfirmada"
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
        out += if verificador.is_some() {
            "\nINCONCLUSIVO: os commitments conferem, mas pelo menos um recibo não tinha cadeia \
             para validar (token de desenvolvimento ou externo não validado na origem). Isto NÃO \
             é uma deteção de fraude."
        } else {
            "\nINCONCLUSIVO: os commitments conferem; nenhuma cadeia de confiança foi validada \
             porque não foi passado um trust store (--trust-store). Isto NÃO é uma deteção de \
             fraude e NÃO é validação legal/ICP-Brasil."
        };
        Err(out)
    } else if autoridade_confirmada > 0 {
        out += &format!(
            "\n{autoridade_confirmada} recibo(s) com cadeia validada até uma âncora instalada. \
             Ressalva que NÃO se pode omitir: a revogação dos certificados não é consultada, \
             portanto um certificado revogado dentro da validade passaria."
        );
        Ok(out)
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


/// SPEC-0050 §90–§97 — mostra o plano de GC, ou executa-o.
///
/// O `--dry-run` é o default de facto do fluxo do operador: o `plan_gc` já
/// explica cada bloqueio, e ver a lista de bloqueados com a razão é a maior
/// parte do valor. Um GC que não sabe dizer o que **não** apagou não é
/// auditável.
pub fn gc_v6(
    root: &std::path::Path,
    dry_run: bool,
    keep_manifests: usize,
    collect_quarantined: bool,
) -> Result<String, heraclitus_core::HeraclitusError> {
    use heraclitus_core::config::FsyncPolicy;
    use heraclitus_log::v6::{GcRunOptions, V6Log};

    if collect_quarantined && dry_run {
        // Não é um erro, mas vale dizer: a combinação existe para se ver o que
        // um pedido explícito removeria antes de o fazer.
    }
    let log = V6Log::open(root, 1 << 30, FsyncPolicy::Always)?;
    let opts = GcRunOptions {
        keep_manifests,
        collect_quarantined,
    };
    let plano = log.gc_plan(opts)?;

    let mut out = String::new();
    out.push_str(&format!("HRKL v6 GC — {}\n\n", root.display()));

    if plano.generations.is_empty() {
        out.push_str("candidatos: nenhum\n");
    } else {
        out.push_str(&format!(
            "candidatos: {} ({} recuperáveis)\n",
            plano.generations.len(),
            bytes_legiveis(plano.reclaimable_bytes())
        ));
        for c in &plano.generations {
            out.push_str(&format!(
                "  segmento {:>6} geração {:>3}  {:>12}  {}\n",
                c.segment_id,
                c.generation,
                bytes_legiveis(c.physical_size),
                c.location
            ));
        }
    }

    if !plano.blocked.is_empty() {
        out.push_str(&format!("\nbloqueados: {}\n", plano.blocked.len()));
        for b in &plano.blocked {
            out.push_str(&format!(
                "  segmento {:>6} geração {:>3}  {}\n",
                b.segment_id,
                b.generation,
                razao(&b.reason)
            ));
        }
    }

    if !plano.stale_artifacts.is_empty() {
        out.push_str(&format!(
            "\nderivados obsoletos: {}\n",
            plano.stale_artifacts.len()
        ));
    }

    if dry_run {
        out.push_str("\n(dry-run: nada foi removido)\n");
        return Ok(out);
    }

    let execucao = log.collect_garbage(opts)?;
    out.push_str(&format!(
        "\nexecutado: HRKM geração {}\n  removidos: {}\n  órfãos: {}\n",
        execucao.manifest_generation,
        execucao.removed.len(),
        execucao.orphaned.len()
    ));
    // §176/§82 — o que este GC desligou mas não pode apagar. Contá-los como
    // removidos seria dizer que espaço foi libertado quando não foi.
    for location in &execucao.cold_detached {
        out.push_str(&format!(
            "  geração fria desligada (bytes ficam no object store): {location}\n"
        ));
    }
    for location in &execucao.lakehouse_detached {
        out.push_str(&format!(
            "  projecção lakehouse desligada (remoção é do lakehouse, §176): {location}\n"
        ));
    }
    Ok(out)
}

fn razao(r: &heraclitus_log::v6::GcBlockReason) -> String {
    use heraclitus_log::v6::GcBlockReason as R;
    match r {
        R::NotSuperseded => "em uso (activa ou ainda não substituída)".into(),
        R::LegalHold => "§94 legal hold".into(),
        R::LastCanonicalAuthority => "§91 é a última autoridade canónica".into(),
        R::ReaderPinned { pins } => format!("§92 {pins} leitor(es) pinado(s)"),
        R::GracePeriod { remaining_seconds } => {
            format!("§93 grace period: faltam {remaining_seconds}s")
        }
        R::InsufficientVerifiedCopies { have, need } => {
            format!("§184 cópias verificadas {have}/{need}")
        }
        R::Quarantined => "§127 em quarentena (exige pedido explícito)".into(),
        R::LegacyOriginalPreserved => "§133 original legado preservado".into(),
    }
}

fn bytes_legiveis(bytes: u64) -> String {
    const UNIDADES: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut valor = bytes as f64;
    let mut i = 0;
    while valor >= 1024.0 && i + 1 < UNIDADES.len() {
        valor /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{bytes} B")
    } else {
        format!("{valor:.2} {}", UNIDADES[i])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// SPEC-0050 §129--§133 — o ciclo do operador, do princípio ao fim.
    ///
    /// O que se prova aqui é a **sequência que uma instalação real vive**, e
    /// não a migração em si (essa tem o seu teste de integração no
    /// heraclitus-log): migrar -> inspeccionar o manifesto -> diagnosticar ->
    /// abrir e usar. Se qualquer um destes passos falhasse depois de a
    /// migração dizer "sucesso", o comando estaria a mentir.
    #[test]
    fn migrate_v6_produz_um_banco_que_o_resto_das_ferramentas_aceita() {
        use heraclitus_core::{Episode, EventKind};
        use heraclitus_log::v6::V6Log;
        use heraclitus_log::Log;

        let dir = tempfile::tempdir().unwrap();
        let legado = dir.path().join("legacy");
        let destino = dir.path().join("v6");

        let esperado = {
            let log = Log::open(&legado, 8 * 1024, FsyncPolicy::Always).unwrap();
            for i in 0..150 {
                log.append(Episode::new(
                    "operador",
                    EventKind::Observation,
                    format!("evento-{i}-{}", "k".repeat(48)).into_bytes(),
                ))
                .unwrap();
            }
            log.flush().unwrap();
            log.scan(0, log.head()).unwrap()
        };

        let saida = migrate_v6(&legado, &destino, true).unwrap();
        assert!(saida.contains("equivalencia verificada: sim"), "{saida}");
        assert!(saida.contains("cauda activa legada selada: sim"), "{saida}");
        assert!(saida.contains("NAO foi alterada"), "{saida}");

        // O manifesto do banco novo descreve o que foi migrado.
        let manifesto = manifest_show_v6(&destino).unwrap();
        assert!(manifesto.contains("HRKL v6 manifest"), "{manifesto}");
        // Nota: em v6 o `cumulative_watermark` do HRKM é o ÚLTIMO LSN, ao
        // passo que o manifesto legado guarda o `head` (último + 1). A
        // diferença é pré-existente e não é desta migração; aqui usa-se a
        // semântica do formato que estamos a inspeccionar.
        assert!(
            manifesto.contains(&format!(
                "committed lsn (cumulative watermark): {}",
                esperado.last().unwrap().0
            )),
            "{manifesto}"
        );

        // O diagnóstico aceita-o sem queixas.
        let doctor = storage_doctor_v6(&destino).unwrap();
        assert!(doctor.contains("status: CLEAN"), "{doctor}");

        // E o motor v6 abre-o e devolve a história intacta.
        let novo = V6Log::open(&destino, 1 << 20, FsyncPolicy::Always).unwrap();
        let lido = novo.scan(0, novo.head()).unwrap();
        assert_eq!(lido.len(), esperado.len());
        assert_eq!(lido.first().unwrap().1.id, esperado.first().unwrap().1.id);
        assert_eq!(lido.last().unwrap().1.content, esperado.last().unwrap().1.content);

        // Migrar duas vezes para o mesmo destino e um destino inexistente
        // comportam-se como devem.
        assert!(migrate_v6(&legado, &destino, true).is_err());
        assert!(migrate_v6(&dir.path().join("nao-existe"), &dir.path().join("x"), true).is_err());
    }

    /// SPEC-0050 §120/§210 — os dois comandos operacionais da Fase 6 sobre um
    /// banco v6 real.
    ///
    /// O que se prova aqui não é o formato dos ficheiros (isso tem testes
    /// próprios no tier), mas a **sequência que um operador vive**: antes de
    /// exportar, `manifest show` mostra a fila cheia e um atraso positivo;
    /// depois, a fila está vazia, o atraso é zero e cada segmento aparece com
    /// a projecção `ok`. Se o `export` corresse e o `manifest show` não
    /// mudasse, um dos dois estaria a mentir.
    #[test]
    fn export_e_manifest_show_percorrem_o_ciclo_da_fase_6() {
        use heraclitus_core::{Episode, EventKind};
        use heraclitus_log::v6::{PackingProfile, V6Log};

        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("v6");
        {
            let log = V6Log::open(&root, 4_096, FsyncPolicy::Always).unwrap();
            for i in 0..120 {
                log.append(Episode::new(
                    "cli",
                    EventKind::Observation,
                    format!("evento-{i}-{}", "z".repeat(64)).into_bytes(),
                ))
                .unwrap();
            }
            log.seal_active().unwrap();
            log.pack_pending(PackingProfile::Balanced).unwrap();
        }

        let antes = manifest_show_v6(&root).unwrap();
        assert!(antes.contains("exported through lsn: 0"), "{antes}");
        assert!(
            !antes.contains("lakehouse queue: []"),
            "a fila do lakehouse devia ter segmentos:
{antes}"
        );
        assert!(antes.contains("parquet -"), "{antes}");

        let destino = dir.path().join("lakehouse");
        let saida =
            export_lakehouse_v6(&root, &destino.to_string_lossy(), "episodios").unwrap();
        assert!(saida.contains("ligado ao HRKM"), "{saida}");
        assert!(saida.contains("export lag: 0"), "{saida}");

        let depois = manifest_show_v6(&root).unwrap();
        assert!(depois.contains("lakehouse queue: []"), "{depois}");
        assert!(depois.contains("parquet ok"), "{depois}");
        assert!(
            !depois.contains("exported through lsn: 0"),
            "o watermark não avançou:
{depois}"
        );

        // Correr de novo é um no-op: a fila vive no manifesto, portanto a
        // idempotência não depende de este processo se lembrar de nada.
        let repetido =
            export_lakehouse_v6(&root, &destino.to_string_lossy(), "episodios").unwrap();
        assert!(repetido.contains("nada por exportar"), "{repetido}");
        assert_eq!(manifest_show_v6(&root).unwrap(), depois);

        // E o diagnóstico continua limpo depois de tudo.
        let doctor = storage_doctor_v6(&root).unwrap();
        assert!(doctor.contains("status: CLEAN"), "{doctor}");
        assert!(doctor.contains("projections: "), "{doctor}");
    }

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

        let report = verify_receipts(&log_dir, &receipts, None, None).unwrap_err();
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
    fn cli_storage_doctor_and_rebuild_index_are_operational_and_idempotent() {
        use heraclitus_core::{Episode, EventKind};
        use heraclitus_log::v6::hrki::{caminho_sidecar, IndexPolicy, IndexPolicySet};
        use heraclitus_log::v6::{PackingProfile, V6Log};

        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("v6");
        let log = V6Log::open(&root, 2_048, FsyncPolicy::Always).unwrap();
        for i in 0..20 {
            let mut episode = Episode::new(
                if i < 10 { "alice" } else { "bob" },
                EventKind::Observation,
                vec![b'x'; 256],
            );
            episode.session_id = format!("session-{i}");
            log.append(episode).unwrap();
        }
        log.seal_active().unwrap();
        log.pack_pending(PackingProfile::Balanced).unwrap();
        log.build_pending_hrki(
            &IndexPolicySet::new()
                .com("agent_id", IndexPolicy::PublicTechnical)
                .com("session_id", IndexPolicy::PublicTechnical),
            None,
            0.01,
        )
        .unwrap();
        let packed = root.join(
            &log.manifest().segments_v2[0]
                .active()
                .unwrap()
                .location,
        );
        drop(log);

        assert!(storage_doctor_v6(&root).unwrap().contains("status: CLEAN"));
        std::fs::write(caminho_sidecar(&packed), b"bad hrki").unwrap();
        let warning = storage_doctor_v6(&root).unwrap();
        assert!(warning.contains("INVALID_HRKI"), "{warning}");

        let rebuilt = rebuild_index_v6(&root, 0.01, true, true).unwrap();
        assert!(rebuilt.contains("1 reconstruído(s)"), "{rebuilt}");
        assert!(storage_doctor_v6(&root).unwrap().contains("status: CLEAN"));
        let retry = rebuild_index_v6(&root, 0.01, true, true).unwrap();
        assert!(retry.contains("0 reconstruído(s)"), "{retry}");
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

/// Lista as âncoras instaladas com as impressões digitais, para o operador as
/// conferir com as publicadas pelo ITI **fora de banda** (SPEC-0046 §11).
///
/// Sem isto não havia forma nenhuma de ver o que estava instalado. O trust
/// store é o ponto onde toda a confiança do sistema assenta, e a única maneira
/// de saber se lá estava a raiz certa era ler ficheiros DER à mão. Um operador
/// que não consegue inspeccionar a raiz de confiança não consegue afirmar que
/// ela está certa — e é essa afirmação que a conformidade exige dele.
///
/// Os ficheiros RECUSADOS aparecem com o motivo. O motivo já era calculado e
/// não era mostrado a ninguém: quem pusesse um certificado intermédio na pasta
/// via-o desaparecer sem explicação.
pub fn trust_store_listar(dir: &std::path::Path) -> Result<String, String> {
    use heraclitus_compliance::trust_store::TrustStore;
    let (store, relatorio) =
        TrustStore::load_dir(dir).map_err(|e| format!("trust store `{}`: {e}", dir.display()))?;

    let mut out = format!(
        "trust store: {}\n  {} ficheiro(s) vistos · {} âncora(s) carregada(s) · {} recusado(s)\n\n",
        dir.display(),
        relatorio.files_seen,
        relatorio.anchors_loaded,
        relatorio.rejected.len()
    );
    if store.is_empty() {
        out += "NENHUMA ÂNCORA UTILIZÁVEL. Nada será validado contra autoridade nenhuma.\n";
    }
    for a in store.anchors() {
        out += &format!(
            "  SHA-256 {}\n    sujeito: {}\n",
            a.fingerprint_hex(),
            a.subject_display()
        );
    }
    if !relatorio.rejected.is_empty() {
        out += "\nRECUSADOS:\n";
        for (ficheiro, motivo) in &relatorio.rejected {
            out += &format!("  {ficheiro}\n    {motivo}\n");
        }
    }
    out += "\nConfira cada impressão digital com a publicada pelo ITI por um canal \
            independente desta máquina. Uma âncora instalada é uma afirmação de confiança \
            que só o órgão pode fazer.\n";
    Ok(out)
}

/// Verifica um `.tst` avulso — tipicamente um emitido por uma ACT credenciada —
/// contra as âncoras instaladas, e relata o que encontrou.
///
/// É o caminho que faltava para provar interoperabilidade. Até aqui, a única
/// forma de saber se este verificador aceita um token real era pôr o sistema a
/// ancorar contra a ACT em produção — o que ninguém faz para testar.
///
/// `imprint_hex` é o que se espera ter sido carimbado. Sem ele, o token é
/// verificado em tudo o resto e o relatório **di-lo** em vez de calar: um
/// carimbo válido sobre um conteúdo desconhecido não prova nada sobre nenhum
/// documento em particular, e um relatório que o omitisse seria pior do que
/// nenhum.
pub fn verify_token(
    token_path: &std::path::Path,
    trust_store_dir: &std::path::Path,
    crl_dir: Option<&std::path::Path>,
    imprint_hex: Option<&str>,
) -> Result<String, String> {
    use heraclitus_compliance::icp::{IcpBrasilTimestampVerifier, TimestampValidationPolicy};
    use heraclitus_compliance::trust_store::TrustStore;

    let token = std::fs::read(token_path)
        .map_err(|e| format!("token `{}`: {e}", token_path.display()))?;
    let (store, relatorio) = TrustStore::load_dir(trust_store_dir)
        .map_err(|e| format!("trust store `{}`: {e}", trust_store_dir.display()))?;
    if store.is_empty() {
        return Err(format!(
            "trust store `{}` sem âncoras utilizáveis ({} ficheiro(s) vistos): sem âncoras não \
             há nada contra que validar",
            trust_store_dir.display(),
            relatorio.files_seen
        ));
    }
    let mut v = IcpBrasilTimestampVerifier::new(store, TimestampValidationPolicy::default());
    let mut revogacao_pedida = false;
    if let Some(cd) = crl_dir {
        let (crls, rel) = heraclitus_compliance::crl::CrlStore::load_dir(cd)
            .map_err(|e| format!("CRLs `{}`: {e}", cd.display()))?;
        if crls.is_empty() {
            return Err(format!(
                "pasta de CRLs `{}` sem CRLs utilizáveis ({} ficheiro(s) vistos)",
                cd.display(),
                rel.files_seen
            ));
        }
        revogacao_pedida = true;
        v = v.with_crls(crls, heraclitus_compliance::crl::CrlPolicy::default());
    }

    let agora = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);

    let (verificado, imprint_no_token) = match imprint_hex {
        Some(hex) => {
            let bytes = hex_para_bytes(hex)
                .ok_or_else(|| format!("--imprint `{hex}` não é hexadecimal de 32 bytes"))?;
            let arr: [u8; 32] = bytes
                .as_slice()
                .try_into()
                .map_err(|_| format!("--imprint tem {} bytes, esperados 32", bytes.len()))?;
            let r = v
                .verify(&token, &arr, None, agora)
                .map_err(|e| format!("RECUSADO: {e}"))?;
            (r, bytes)
        }
        None => v
            .inspect(&token, agora)
            .map_err(|e| format!("RECUSADO: {e}"))?,
    };

    let mut out = format!("ACEITE: {}\n", token_path.display());
    out += &format!("  autoridade   : {}\n", verificado.signer_subject);
    out += &format!("  genTime      : {} ms (época Unix)\n", verificado.gen_unix_ms);
    out += &format!("  política     : {}\n", verificado.policy_oid);
    out += &format!("  série        : {}\n", verificado.serial_hex);
    out += &format!(
        "  âncora       : {} (cadeia de {} certificado(s) até ela)\n",
        verificado.anchor_fingerprint_hex, verificado.chain_len
    );
    if let Some(a) = verificado.accuracy_secs {
        out += &format!("  precisão     : ±{a} s\n");
    }
    out += &format!("  imprint      : {}\n", bytes_para_hex(&imprint_no_token));

    out += "\nO QUE ESTE RESULTADO NÃO DIZ:\n";
    if imprint_hex.is_none() {
        out += "  · Não foi passado --imprint: o carimbo NÃO foi ligado a nenhum conteúdo. \
                Prova que a cadeia e a assinatura conferem, e mais nada.\n";
    }
    if !revogacao_pedida {
        out += "  · Revogação NÃO consultada (sem --crl-dir): um certificado revogado dentro \
                da validade passaria.\n";
    } else if !verificado.revocation_checked {
        out += "  · Revogação declarada como não consultada pelo verificador.\n";
    } else {
        out += &format!(
            "  · Revogação consultada; a informação é boa até {} ms.\n",
            verificado
                .revocation_valid_until_ms
                .map(|v| v.to_string())
                .unwrap_or_else(|| "(sem nextUpdate)".into())
        );
    }
    Ok(out)
}

fn hex_para_bytes(s: &str) -> Option<Vec<u8>> {
    let s = s.trim();
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

fn bytes_para_hex(b: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        let _ = write!(s, "{x:02x}");
    }
    s
}

#[cfg(test)]
mod testes_operador {
    use super::*;

    /// Um ficheiro que nao e um certificado tem de aparecer no relatorio COM o
    /// motivo. O motivo ja era calculado e nao era mostrado a ninguem: quem
    /// pusesse um intermedio na pasta via-o desaparecer sem explicacao.
    #[test]
    fn o_relatorio_do_trust_store_mostra_o_motivo_de_cada_recusa() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("lixo.pem"), b"nao sou um certificado").unwrap();
        let out = trust_store_listar(dir.path()).unwrap();
        assert!(out.contains("1 ficheiro(s) vistos"), "{out}");
        assert!(out.contains("RECUSADOS"), "{out}");
        assert!(out.contains("lixo.pem"), "{out}");
        assert!(out.contains("NENHUMA ÂNCORA UTILIZÁVEL"), "{out}");
    }

    /// Uma pasta vazia nao e um erro — e um estado, e tem de se ver que o e.
    #[test]
    fn uma_pasta_vazia_diz_que_nada_sera_validado() {
        let dir = tempfile::tempdir().unwrap();
        let out = trust_store_listar(dir.path()).unwrap();
        assert!(out.contains("0 âncora(s)"), "{out}");
        assert!(out.contains("Nada será validado"), "{out}");
    }

    /// Verificar um token contra um trust store vazio nao pode devolver "ok".
    #[test]
    fn verificar_um_token_sem_ancoras_e_recusado_antes_de_o_ler() {
        let dir = tempfile::tempdir().unwrap();
        let tok = dir.path().join("t.tst");
        std::fs::write(&tok, b"qualquer coisa").unwrap();
        let vazio = tempfile::tempdir().unwrap();
        let erro = verify_token(&tok, vazio.path(), None, None).unwrap_err();
        assert!(erro.contains("sem âncoras utilizáveis"), "{erro}");
    }

    /// Um `--imprint` malformado e apanhado antes de qualquer criptografia.
    #[test]
    fn um_imprint_malformado_e_recusado_com_a_razao() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("r.pem"), b"-----BEGIN CERTIFICATE-----").unwrap();
        let tok = dir.path().join("t.tst");
        std::fs::write(&tok, b"x").unwrap();
        let erro = verify_token(&tok, dir.path(), None, Some("zz")).unwrap_err();
        assert!(erro.contains("âncoras"), "{erro}");
    }
}
