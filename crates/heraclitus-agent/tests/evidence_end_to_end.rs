//! SPEC-0074 §25 (Integration) e §33 — a cadeia inteira, sobre um HRKL v6 real.
//!
//! ```text
//! sample agent
//!  -> model span
//!  -> tool call
//!  -> result
//!  -> export
//!  -> tamper copy
//!  -> verify original PASS
//!  -> verify tampered FAIL
//! ```
//!
//! Estes testes não usam mocks do log: abrem um `AnyLog` v6 em disco, selam o
//! segmento e pedem provas pelo mesmo `prove_lsn` que a perícia usaria. Um
//! teste que substituísse o motor por um duplo provaria apenas que o duplo
//! funciona.

use heraclitus_agent::bundle::{BundleSelectionV1, ExportOptions};
use heraclitus_agent::evidence::CaptureModeV1;
use heraclitus_agent::store::{AnyLogEvidenceStore, EvidenceLog, ProofAvailability};
use heraclitus_agent::verifier::{verify_bundle_bytes, VerifyExit};
use heraclitus_agent::{bundle, demo, projection};
use heraclitus_core::{FsyncPolicy, StorageFormat};
use heraclitus_log::AnyLog;
use std::sync::Arc;

const BASE_NANOS: u64 = 1_700_000_000_000_000_000;

struct Fixture {
    _dir: tempfile::TempDir,
    store: AnyLogEvidenceStore,
    log: Arc<AnyLog>,
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().expect("tempdir");
    let log = Arc::new(
        AnyLog::open(
            StorageFormat::V6,
            dir.path().join("log"),
            // Segmentos pequenos para que a selagem aconteça dentro do teste, e
            // não só em produção: sem segmento selado não há prova para
            // verificar, e o teste passaria sem testar nada.
            64 * 1024,
            FsyncPolicy::Always,
        )
        .expect("abrir log v6"),
    );
    Fixture {
        _dir: dir,
        store: AnyLogEvidenceStore::new(log.clone()),
        log,
    }
}

fn popular(f: &Fixture, run_id: &str) -> usize {
    let run = demo::build_demo_run(BASE_NANOS, run_id);
    let n = run.evidences.len();
    for e in &run.evidences {
        f.store.append_evidence(e).expect("append");
    }
    f.store.flush().expect("flush");
    n
}

/// Sela o segmento activo para que `prove_lsn` tenha contra o que fechar.
fn selar(f: &Fixture) {
    if let Some(v6) = f.log.v6_arc() {
        v6.seal_active().expect("selar segmento");
    }
}

fn exportar(f: &Fixture, run_id: &str, destino: &std::path::Path) -> bundle::BundleOutcome {
    bundle::build_bundle(
        &f.store,
        destino,
        &ExportOptions {
            tenant_id: demo::DEMO_TENANT.to_string(),
            selection: BundleSelectionV1::Run {
                run_id: run_id.to_string(),
            },
            privacy_profile: "default".to_string(),
            capture_mode: CaptureModeV1::MetadataOnly,
            max_records: 10_000,
            created_at_unix_nanos: BASE_NANOS,
        },
    )
    .expect("exportar bundle")
}

#[test]
fn a_evidencia_sobrevive_ao_log_e_volta_igual() {
    let f = fixture();
    let n = popular(&f, "01RUNIDA");
    let rows = f.store.scan_evidence(0, f.store.head()).expect("scan");
    assert_eq!(rows.len(), n);
    let original = demo::build_demo_run(BASE_NANOS, "01RUNIDA");
    for (row, esperado) in rows.iter().zip(original.evidences.iter()) {
        assert_eq!(&row.evidence, esperado);
    }
}

#[test]
fn a_timeline_reconstroi_se_a_partir_do_log() {
    let f = fixture();
    popular(&f, "01RUNTL");
    let rows = f.store.scan_evidence(0, f.store.head()).unwrap();
    let runs = projection::project_runs(&rows);
    assert_eq!(runs.len(), 1);
    assert_eq!(runs[0].run_id, "01RUNTL");
    assert_eq!(runs[0].tool_calls, 2);
    assert_eq!(runs[0].approvals, 1);
    let tl = projection::project_timeline(&rows, "01RUNTL");
    assert_eq!(tl.len(), rows.len());
    assert!(tl
        .windows(2)
        .all(|w| w[0].at_unix_nanos <= w[1].at_unix_nanos));
}

#[test]
fn um_segmento_selado_da_prova_que_fecha() {
    let f = fixture();
    popular(&f, "01RUNPROVA");
    selar(&f);
    let rows = f.store.scan_evidence(0, f.store.head()).unwrap();
    let mut provadas = 0;
    for row in &rows {
        if let ProofAvailability::Available(p) = f.store.prove(row.lsn).expect("prove") {
            assert!(p.verified, "a prova de LSN {} não fecha", row.lsn);
            assert!(heraclitus_agent::store::proof_closes(&p));
            assert_eq!(p.canonical_evidence_hash, row.record_hash());
            provadas += 1;
        }
    }
    assert!(
        provadas > 0,
        "nenhum registo ficou provável — o segmento não selou"
    );
}

#[test]
fn evidencia_por_selar_nao_e_dada_como_verificada() {
    // §8 da 0076: "não verificado" nunca vira "válido".
    let f = fixture();
    popular(&f, "01RUNFRESCO");
    let rows = f.store.scan_evidence(0, f.store.head()).unwrap();
    let estado = f.store.prove(rows[0].lsn).unwrap();
    assert!(
        matches!(estado, ProofAvailability::PendingSeal),
        "{estado:?}"
    );
    let mut resumo = projection::EvidenceIntegritySummary::default();
    resumo.observe(&estado);
    assert_eq!(resumo.state(), projection::IntegrityState::Unverified);
}

#[test]
fn exportar_e_verificar_fecha_o_ciclo() {
    let f = fixture();
    popular(&f, "01RUNBUNDLE");
    selar(&f);
    let destino = f._dir.path().join("evidence.zip");
    let outcome = exportar(&f, "01RUNBUNDLE", &destino);
    assert!(destino.exists());
    assert!(outcome.record_count > 0);
    assert!(
        outcome.proofs_present > 0,
        "sem provas o bundle não prova nada"
    );

    let bytes = std::fs::read(&destino).unwrap();
    let report = verify_bundle_bytes(&bytes);
    assert_eq!(
        report.exit,
        VerifyExit::Verified,
        "verdicto {} — {:?}",
        report.verdict,
        report.problems
    );
    assert_eq!(report.missing_records, 0);
    assert_eq!(report.broken_parents, 0);
    assert!(report.approvals_valid >= 1);
    assert!(report.to_human().contains("VERDICT: VERIFIED"));
}

#[test]
fn alterar_um_byte_faz_a_verificacao_falhar() {
    // A demo de dois minutos (0076 §49), passos 9 e 10.
    let f = fixture();
    popular(&f, "01RUNTAMPER");
    selar(&f);
    let destino = f._dir.path().join("evidence.zip");
    exportar(&f, "01RUNTAMPER", &destino);
    let original = std::fs::read(&destino).unwrap();
    assert_eq!(verify_bundle_bytes(&original).exit, VerifyExit::Verified);

    // Trocar o nome do aprovador dentro da timeline.
    let alvo = demo::DEMO_APPROVER.as_bytes();
    let pos = original
        .windows(alvo.len())
        .position(|w| w == alvo)
        .expect("o aprovador está no bundle");
    let mut adulterado = original.clone();
    adulterado[pos] = b'X';

    let report = verify_bundle_bytes(&adulterado);
    assert_ne!(report.exit, VerifyExit::Verified, "{}", report.to_human());
    assert!(!report.problems.is_empty());
}

#[test]
fn um_adulterador_cuidadoso_tambem_e_apanhado() {
    // O teste anterior muda bytes crus, e o CRC do próprio ZIP apanha-o antes
    // de qualquer digest nosso correr. Isso é honesto mas fraco: prova o ZIP,
    // não a evidência.
    //
    // Aqui o adulterador é competente — reescreve o arquivo inteiro, com CRCs
    // correctos, e só NÃO mexe no manifesto. É o que sobra depois de o
    // contentor deixar de ajudar, e tem de continuar a falhar.
    let f = fixture();
    popular(&f, "01RUNCUIDADO");
    selar(&f);
    let destino = f._dir.path().join("evidence.zip");
    exportar(&f, "01RUNCUIDADO", &destino);
    let original = std::fs::read(&destino).unwrap();
    assert_eq!(verify_bundle_bytes(&original).exit, VerifyExit::Verified);

    let mut entradas = heraclitus_agent::zip::read_all(&original).unwrap();
    let timeline = entradas.get(bundle::FILE_TIMELINE).unwrap().clone();
    let alvo = demo::DEMO_APPROVER.as_bytes();
    let pos = timeline
        .windows(alvo.len())
        .position(|w| w == alvo)
        .unwrap();
    let mut nova = timeline.clone();
    nova[pos] = b'X';
    entradas.insert(bundle::FILE_TIMELINE.to_string(), nova);

    let mut w = heraclitus_agent::zip::ZipWriter::new(Vec::new());
    for (nome, dados) in &entradas {
        w.add(nome, dados).unwrap();
    }
    let refeito = w.finish().unwrap();
    // O ZIP agora está perfeitamente bem formado, com CRCs certos.
    assert!(heraclitus_agent::zip::read_all(&refeito).is_ok());

    let report = verify_bundle_bytes(&refeito);
    assert_eq!(
        report.exit,
        VerifyExit::DigestMismatch,
        "{}",
        report.to_human()
    );
    assert!(
        report
            .problems
            .iter()
            .any(|p| p.contains("digest não bate")),
        "{:?}",
        report.problems
    );
}

#[test]
fn alterar_um_hash_de_prova_e_apanhado() {
    let f = fixture();
    popular(&f, "01RUNPROOF");
    selar(&f);
    let destino = f._dir.path().join("evidence.zip");
    exportar(&f, "01RUNPROOF", &destino);
    let original = std::fs::read(&destino).unwrap();

    // Um `0` para `1` num campo hexadecimal de uma prova.
    let mut adulterado = original.clone();
    let marcador = b"\"logical_root\": \"";
    let pos = adulterado
        .windows(marcador.len())
        .position(|w| w == marcador)
        .expect("roots.json e as provas trazem logical_root");
    let alvo = pos + marcador.len();
    adulterado[alvo] = if adulterado[alvo] == b'a' { b'b' } else { b'a' };

    let report = verify_bundle_bytes(&adulterado);
    assert_ne!(report.exit, VerifyExit::Verified, "{}", report.to_human());
}

#[test]
fn acrescentar_um_ficheiro_ao_bundle_e_apanhado() {
    let f = fixture();
    popular(&f, "01RUNADD");
    selar(&f);
    let destino = f._dir.path().join("evidence.zip");
    exportar(&f, "01RUNADD", &destino);
    let original = std::fs::read(&destino).unwrap();
    let mut entradas = heraclitus_agent::zip::read_all(&original).unwrap();
    entradas.insert("extra.json".to_string(), b"{}".to_vec());

    let mut w = heraclitus_agent::zip::ZipWriter::new(Vec::new());
    for (nome, dados) in &entradas {
        w.add(nome, dados).unwrap();
    }
    let refeito = w.finish().unwrap();
    let report = verify_bundle_bytes(&refeito);
    assert_eq!(
        report.exit,
        VerifyExit::DigestMismatch,
        "{}",
        report.to_human()
    );
}

#[test]
fn remover_um_registo_da_timeline_e_apanhado() {
    let f = fixture();
    popular(&f, "01RUNDEL");
    selar(&f);
    let destino = f._dir.path().join("evidence.zip");
    exportar(&f, "01RUNDEL", &destino);
    let original = std::fs::read(&destino).unwrap();
    let mut entradas = heraclitus_agent::zip::read_all(&original).unwrap();

    // Apagar a última linha da timeline e refazer os digests, como faria quem
    // tentasse esconder um passo: o manifesto continua a declarar o número
    // original de registos.
    let timeline = entradas.get(bundle::FILE_TIMELINE).unwrap().clone();
    let mut linhas: Vec<&[u8]> = timeline
        .split(|b| *b == b'\n')
        .filter(|l| !l.is_empty())
        .collect();
    linhas.pop();
    let mut nova = Vec::new();
    for l in linhas {
        nova.extend_from_slice(l);
        nova.push(b'\n');
    }
    entradas.insert(bundle::FILE_TIMELINE.to_string(), nova.clone());

    // Reescrever manifesto e SHA256SUMS de forma coerente com os novos bytes —
    // ou seja, o atacante mais cuidadoso possível, que só não mexe no
    // `record_count`.
    let mut manifesto: serde_json::Value =
        serde_json::from_slice(entradas.get(bundle::FILE_MANIFEST).unwrap()).unwrap();
    let novo_sha = bundle::sha256_hex(&nova);
    for ficheiro in manifesto["files"].as_array_mut().unwrap() {
        if ficheiro["path"] == bundle::FILE_TIMELINE {
            ficheiro["sha256"] = serde_json::Value::String(novo_sha.clone());
            ficheiro["bytes"] = serde_json::Value::from(nova.len() as u64);
        }
    }
    let sums: String = manifesto["files"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| {
            format!(
                "{}  {}\n",
                f["sha256"].as_str().unwrap(),
                f["path"].as_str().unwrap()
            )
        })
        .collect();
    entradas.insert(
        bundle::FILE_MANIFEST.to_string(),
        serde_json::to_vec_pretty(&manifesto).unwrap(),
    );
    entradas.insert(bundle::FILE_SUMS.to_string(), sums.into_bytes());

    let mut w = heraclitus_agent::zip::ZipWriter::new(Vec::new());
    for (nome, dados) in &entradas {
        w.add(nome, dados).unwrap();
    }
    let refeito = w.finish().unwrap();
    let report = verify_bundle_bytes(&refeito);
    assert_ne!(report.exit, VerifyExit::Verified, "{}", report.to_human());
    assert!(
        report.missing_records > 0
            || report.merkle_proofs != heraclitus_agent::verifier::CheckState::Valid,
        "{}",
        report.to_human()
    );
}

#[test]
fn retransmitir_o_mesmo_lote_nao_duplica_a_historia() {
    // §24 e §33: append, retransmitir, exportar, verificar.
    let f = fixture();
    let n = popular(&f, "01RUNDEDUP");
    let run = demo::build_demo_run(BASE_NANOS, "01RUNDEDUP");
    let mut idx = heraclitus_agent::dedupe::DedupeIndex::new(4096);
    let rows = f.store.scan_evidence(0, f.store.head()).unwrap();
    idx.warm_from(rows.iter().map(|r| &r.evidence));

    let mut novos = 0;
    for e in &run.evidences {
        if idx.admit(e) == heraclitus_agent::dedupe::DedupeVerdict::Novel {
            f.store.append_evidence(e).unwrap();
            novos += 1;
        }
    }
    assert_eq!(novos, 0, "a retransmissão criou evidência nova");
    assert_eq!(f.store.scan_evidence(0, f.store.head()).unwrap().len(), n);
}

#[test]
fn reabrir_o_log_preserva_a_evidencia() {
    // §33: crash/restart. O `drop` do fixture fecha os ficheiros; reabrir tem
    // de reencontrar tudo.
    let dir = tempfile::tempdir().unwrap();
    let caminho = dir.path().join("log");
    let esperado = {
        let log = Arc::new(
            AnyLog::open(StorageFormat::V6, &caminho, 64 * 1024, FsyncPolicy::Always).unwrap(),
        );
        let store = AnyLogEvidenceStore::new(log);
        let run = demo::build_demo_run(BASE_NANOS, "01RUNBOOT");
        for e in &run.evidences {
            store.append_evidence(e).unwrap();
        }
        store.flush().unwrap();
        store.scan_evidence(0, store.head()).unwrap()
    };

    let log = Arc::new(
        AnyLog::open(StorageFormat::V6, &caminho, 64 * 1024, FsyncPolicy::Always).unwrap(),
    );
    let store = AnyLogEvidenceStore::new(log);
    let depois = store.scan_evidence(0, store.head()).unwrap();
    assert_eq!(depois.len(), esperado.len());
    for (a, b) in depois.iter().zip(esperado.iter()) {
        assert_eq!(a.evidence, b.evidence);
        assert_eq!(a.lsn, b.lsn);
    }
}

#[test]
fn o_bundle_nao_contem_segredo_nenhum() {
    let f = fixture();
    popular(&f, "01RUNSEC");
    selar(&f);
    let destino = f._dir.path().join("evidence.zip");
    exportar(&f, "01RUNSEC", &destino);
    let bytes = std::fs::read(&destino).unwrap();
    let texto = String::from_utf8_lossy(&bytes);
    for proibido in ["Bearer ", "sk-", "Set-Cookie", "client_secret"] {
        assert!(!texto.contains(proibido), "{proibido} apareceu no bundle");
    }
}

#[test]
fn seleccao_vazia_e_erro_e_nao_bundle_vazio() {
    let f = fixture();
    popular(&f, "01RUNSEL");
    let destino = f._dir.path().join("vazio.zip");
    let err = bundle::build_bundle(
        &f.store,
        &destino,
        &ExportOptions {
            selection: BundleSelectionV1::Run {
                run_id: "nao-existe".into(),
            },
            ..Default::default()
        },
    );
    assert!(matches!(err, Err(bundle::BundleError::EmptySelection)));
    assert!(
        !destino.exists(),
        "não fica um ficheiro a fingir que é bundle"
    );
}
