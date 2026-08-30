//! SPEC-0050 §90–§97 — o GC ligado ao motor, ponta a ponta.
//!
//! Os testes que já existiam provavam a *política* (`plan_gc` decide bem) e a
//! *transacção* (`commit_gc` é crash-safe). Nenhum provava a única coisa que
//! interessa a quem paga o disco: que uma passagem de GC corrida pelo motor
//! **apaga bytes** e deixa a base a funcionar.
//!
//! Antes de `V6Log::collect_garbage` existir isso não era testável, porque não
//! havia por onde chamar: `plan_gc`/`commit_gc` não tinham um único chamador de
//! produção. O `record_pack` marcava a geração RAW como `Superseded` (§88 passo
//! 13) e ninguém a removia — cada banco guardava RAW **e** PACKED de tudo, para
//! sempre.

use heraclitus_core::config::FsyncPolicy;
use heraclitus_core::runtime::{GenerationState, PhysicalLayout, RetentionPolicy};
use heraclitus_core::{Episode, EventKind};
use heraclitus_log::v6::compress::PackingProfile;
use heraclitus_log::v6::{GcRunOptions, V6Log};
use std::path::{Path, PathBuf};

const N: u64 = 1_500;

fn conteudo(i: u64) -> Vec<u8> {
    format!("evento-{i}-{}", "carga".repeat(8)).into_bytes()
}

/// Escreve, sela e empacota — o estado normal de um segmento depois do worker
/// de packing correr.
fn banco_empacotado(dir: &Path) -> V6Log {
    let log = V6Log::open(dir, 1 << 30, FsyncPolicy::Always).unwrap();
    for i in 0..N {
        log.append(Episode::new("gc", EventKind::Observation, conteudo(i)))
            .unwrap();
    }
    log.seal_active().unwrap();
    log.pack_pending(PackingProfile::Balanced).unwrap();
    log
}

fn ficheiros(dir: &Path) -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = std::fs::read_dir(dir)
        .map(|rd| {
            rd.flatten()
                .map(|e| e.path())
                .filter(|p| p.extension().map(|x| x == "hrkl").unwrap_or(false))
                .collect()
        })
        .unwrap_or_default();
    v.sort();
    v
}

fn bytes_em_disco(dir: &Path) -> u64 {
    ficheiros(dir)
        .iter()
        .filter_map(|p| std::fs::metadata(p).ok())
        .map(|m| m.len())
        .sum()
}

/// Faz o grace period de §93 já ter passado, sem esperar 24 h de relógio.
fn sem_grace(log: &V6Log, segment_id: u64) {
    let atual = log.retention(segment_id).unwrap().unwrap();
    log.set_retention(
        segment_id,
        RetentionPolicy {
            gc_grace_seconds: 0,
            ..atual
        },
    )
    .unwrap();
}

#[test]
fn o_gc_recupera_o_raw_superseded_e_a_base_continua_a_ler() {
    let dir = tempfile::tempdir().unwrap();
    let segments = dir.path().join("segments");
    let log = banco_empacotado(dir.path());

    // Depois do packing: duas gerações do mesmo segmento em disco.
    let antes = ficheiros(&segments);
    assert_eq!(
        antes.len(),
        3,
        "esperado RAW selado + PACKED + o novo activo: {antes:?}"
    );
    let bytes_antes = bytes_em_disco(&segments);

    let desc = log.manifest().segments_v2[0].clone();
    assert_eq!(desc.generations.len(), 2);
    let raw = desc
        .generations
        .iter()
        .find(|g| g.layout == PhysicalLayout::Raw)
        .unwrap();
    assert_eq!(
        raw.state,
        GenerationState::Superseded,
        "§88 passo 13: o packing marca a origem superseded"
    );

    // Dentro do grace period nada é coletado — e o plano diz porquê.
    let plano = log.gc_plan(GcRunOptions::default()).unwrap();
    assert!(plano.generations.is_empty());
    assert!(
        plano
            .blocked
            .iter()
            .any(|b| matches!(b.reason, heraclitus_log::v6::GcBlockReason::GracePeriod { .. })),
        "o bloqueio devia ser o grace period: {:?}",
        plano.blocked
    );

    sem_grace(&log, desc.segment_id);

    let execucao = log.collect_garbage(GcRunOptions::default()).unwrap();
    assert_eq!(execucao.removed.len(), 1, "{:?}", execucao.removed);
    assert!(execucao.orphaned.is_empty());

    // Os bytes desapareceram mesmo — que é a afirmação toda.
    let depois = ficheiros(&segments);
    assert_eq!(depois.len(), 2, "o RAW superseded devia ter saído: {depois:?}");
    let bytes_depois = bytes_em_disco(&segments);
    assert!(
        bytes_depois < bytes_antes,
        "o GC não recuperou espaço ({bytes_antes} → {bytes_depois})"
    );

    // E a base continua a servir o histórico completo pela geração PACKED.
    let linhas = log.scan(0, N).unwrap();
    assert_eq!(linhas.len() as u64, N);
    assert_eq!(linhas[0].1.content, conteudo(0));
    assert_eq!(linhas[(N - 1) as usize].1.content, conteudo(N - 1));

    // Reabrir confirma que o manifesto ficou coerente com o disco.
    drop(log);
    let reaberto = V6Log::open(dir.path(), 1 << 30, FsyncPolicy::Always).unwrap();
    assert_eq!(reaberto.scan(0, N).unwrap().len() as u64, N);
    assert_eq!(reaberto.manifest().segments_v2[0].generations.len(), 1);
}

#[test]
fn o_legal_hold_impede_o_gc_e_o_plano_di_lo() {
    // §94 — não negociável por tempo decorrido nem por número de cópias.
    let dir = tempfile::tempdir().unwrap();
    let log = banco_empacotado(dir.path());
    let segment_id = log.manifest().segments_v2[0].segment_id;
    sem_grace(&log, segment_id);
    log.set_legal_hold(segment_id, true).unwrap();

    let plano = log.gc_plan(GcRunOptions::default()).unwrap();
    assert!(plano.generations.is_empty());
    assert!(plano
        .blocked
        .iter()
        .any(|b| b.reason == heraclitus_log::v6::GcBlockReason::LegalHold));

    let execucao = log.collect_garbage(GcRunOptions::default()).unwrap();
    assert!(execucao.removed.is_empty(), "legal hold foi ignorado");
    assert_eq!(ficheiros(&dir.path().join("segments")).len(), 3);

    // Levantado o hold, o GC volta a poder trabalhar.
    log.set_legal_hold(segment_id, false).unwrap();
    assert_eq!(
        log.collect_garbage(GcRunOptions::default())
            .unwrap()
            .removed
            .len(),
        1
    );
}

#[test]
fn um_leitor_pinado_bloqueia_a_coleta_ate_largar() {
    // §92. O registo existe e é honrado; hoje nenhum leitor interno pina (ver
    // `V6Log::pins`), por isso este teste é o que garante que o caminho
    // funciona para quem o usar.
    let dir = tempfile::tempdir().unwrap();
    let log = banco_empacotado(dir.path());
    let desc = log.manifest().segments_v2[0].clone();
    let raw = desc
        .generations
        .iter()
        .find(|g| g.layout == PhysicalLayout::Raw)
        .unwrap();
    sem_grace(&log, desc.segment_id);

    {
        let _guarda = log.pins().pin(desc.segment_id, raw.generation);
        let execucao = log.collect_garbage(GcRunOptions::default()).unwrap();
        assert!(execucao.removed.is_empty(), "coletou com um leitor pinado");
    }

    // O pin sai no `drop`, e a passagem seguinte coleta.
    assert_eq!(
        log.collect_garbage(GcRunOptions::default())
            .unwrap()
            .removed
            .len(),
        1
    );
}

#[test]
fn uma_passagem_sem_nada_a_fazer_e_barata_e_idempotente() {
    let dir = tempfile::tempdir().unwrap();
    let log = banco_empacotado(dir.path());
    let segment_id = log.manifest().segments_v2[0].segment_id;
    sem_grace(&log, segment_id);

    let primeira = log.collect_garbage(GcRunOptions::default()).unwrap();
    assert_eq!(primeira.removed.len(), 1);

    // A segunda não encontra nada — e não é erro. Uma task de fundo corre isto
    // a cada N segundos e a esmagadora maioria das passagens é esta.
    let segunda = log.collect_garbage(GcRunOptions::default()).unwrap();
    assert!(segunda.removed.is_empty());
    assert!(segunda.orphaned.is_empty());
    assert!(segunda.cold_detached.is_empty());
    assert_eq!(log.scan(0, N).unwrap().len() as u64, N);
}

#[test]
fn a_quarentena_nao_e_coletada_por_uma_passagem_automatica() {
    // §127 — uma geração em quarentena é evidência. Um scrub automático não
    // pode destruir o ficheiro que a perícia quer ver.
    let dir = tempfile::tempdir().unwrap();
    let log = banco_empacotado(dir.path());
    let desc = log.manifest().segments_v2[0].clone();
    let packed = desc
        .generations
        .iter()
        .find(|g| g.layout == PhysicalLayout::Packed)
        .unwrap();
    sem_grace(&log, desc.segment_id);
    log.quarantine_generation(desc.segment_id, packed.generation)
        .unwrap();

    let automatica = log.collect_garbage(GcRunOptions::default()).unwrap();
    assert!(
        !automatica
            .removed
            .iter()
            .any(|p| p.to_string_lossy().contains("packed")),
        "a geração em quarentena não pode sair numa passagem automática: {:?}",
        automatica.removed
    );

    // Só um pedido explícito a coleta.
    let explicita = log
        .collect_garbage(GcRunOptions {
            collect_quarantined: true,
            ..Default::default()
        })
        .unwrap();
    assert!(explicita
        .removed
        .iter()
        .any(|p| p.to_string_lossy().contains("packed")));
}
