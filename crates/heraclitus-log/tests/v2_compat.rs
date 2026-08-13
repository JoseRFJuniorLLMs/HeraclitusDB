//! Compat de formato: segmentos FORMAT v2 (pré-M30, payload = `Episode`
//! serializado direto) têm de continuar legíveis pelo código v3 (payload =
//! `StoragePayload`). Sem o decode versionado, o open/scan de dados antigos
//! rebentava com Utf8Error (o primeiro campo do layout errado vira o início
//! de uma String) — foi o que impediria o deploy do binário novo sobre a
//! memória do Claude gravada em v2.

use heraclitus_core::{Episode, EventKind, FsyncPolicy};
use heraclitus_log::format;
use heraclitus_log::Log;
use std::fs::File;
use std::io::Write;

const BINCODE_CFG: bincode::config::Configuration = bincode::config::standard();

/// Constrói à mão um segmento v2 idêntico ao que o binário pré-M30 escrevia:
/// header v2 + registos `encode_record(v2, lsn, hlc, bincode(Episode))`.
fn write_v2_segment(dir: &std::path::Path, episodes: &[Episode]) {
    let path = dir.join(format!("{:020}.hrkl", 0));
    let mut f = File::create(&path).unwrap();
    let hdr = format::SegmentHeader {
        version: 2,
        segment_id: 0,
        created_hlc: 1,
    };
    f.write_all(&hdr.encode()).unwrap();
    for (i, e) in episodes.iter().enumerate() {
        let payload = bincode::serde::encode_to_vec(e, BINCODE_CFG).unwrap();
        let rec = format::encode_record(2, i as u64, e.ts_hlc, &payload);
        f.write_all(&rec).unwrap();
    }
    f.sync_all().unwrap();
}

#[test]
fn v2_segment_remains_readable_and_appendable() {
    let dir = tempfile::tempdir().unwrap();

    let mut eps = Vec::new();
    for i in 0..3u64 {
        let mut e = Episode::new(
            "v2-writer",
            EventKind::Observation,
            format!("registo {i}").into_bytes(),
        );
        e.ts_hlc = 1_000 + i;
        e.attrs.insert("k".into(), format!("v{i}"));
        eps.push(e);
    }
    let ids: Vec<String> = eps.iter().map(|e| e.id.to_string()).collect();
    write_v2_segment(dir.path(), &eps);

    // Reabre com o código atual: o tail v2 é selado no open e um ativo v3
    // fresco continua o log; os registos v2 são descodificados pela versão
    // do SEGMENTO, não pela corrente.
    let log = Log::open(dir.path(), 1 << 20, FsyncPolicy::Always).unwrap();
    assert_eq!(log.head(), 3, "os 3 registos v2 foram recuperados");

    let all = log.scan(0, 10).unwrap();
    assert_eq!(all.len(), 3);
    assert_eq!(String::from_utf8_lossy(&all[0].1.content), "registo 0");
    assert_eq!(all[2].1.attrs.get("k").map(|s| s.as_str()), Some("v2"));
    // A identidade sobrevive ao round-trip trans-versão.
    assert_eq!(all[1].1.id.to_string(), ids[1]);

    // read() pontual atravessa o segmento v2 selado.
    let (l, e) = log.read(1).unwrap().unwrap();
    assert_eq!(l, 1);
    assert_eq!(String::from_utf8_lossy(&e.content), "registo 1");

    // Appends novos vão para o ativo v3; o scan atravessa as duas versões.
    log.append(Episode::new(
        "v3-writer",
        EventKind::Observation,
        b"novo".to_vec(),
    ))
    .unwrap();
    let all = log.scan(0, 10).unwrap();
    assert_eq!(all.len(), 4);
    assert_eq!(String::from_utf8_lossy(&all[3].1.content), "novo");
    assert!(all[3].1.ts_hlc > 0, "append v3 carimba o HLC");
}

#[test]
fn v3_segment_remains_readable_under_v4() {
    // FORMAT v4 (Valid Time nativo): os segmentos v3 EXISTENTES — como o log
    // ativo da memória local no momento do bump — têm de continuar legíveis.
    use heraclitus_log::StoragePayloadV3;
    let dir = tempfile::tempdir().unwrap();

    let mut eps = Vec::new();
    for i in 0..3u64 {
        let mut e = Episode::new(
            "v3-writer",
            EventKind::Observation,
            format!("v3-{i}").into_bytes(),
        );
        e.ts_hlc = 5_000 + i;
        e.attrs.insert("k".into(), format!("v{i}"));
        eps.push(e);
    }

    // Fabrica um segmento v3 byte-exato: header v3 + StoragePayloadV3.
    let path = dir.path().join(format!("{:020}.hrkl", 0));
    let mut f = File::create(&path).unwrap();
    let hdr = format::SegmentHeader {
        version: 3,
        segment_id: 0,
        created_hlc: 1,
    };
    f.write_all(&hdr.encode()).unwrap();
    for (i, e) in eps.iter().enumerate() {
        let sp = StoragePayloadV3 {
            opaque_meta: e.id.0.to_bytes(),
            id: e.id,
            agent_id: e.agent_id.clone(),
            session_id: e.session_id.clone(),
            ts_hlc: e.ts_hlc,
            kind: e.kind.clone(),
            content: e.content.clone(),
            embedding: e.embedding.clone(),
            attrs: e.attrs.clone(),
            parents: e.parents.clone(),
        };
        let payload = bincode::serde::encode_to_vec(&sp, BINCODE_CFG).unwrap();
        let rec = format::encode_record(3, i as u64, e.ts_hlc, &payload);
        f.write_all(&rec).unwrap();
    }
    f.sync_all().unwrap();
    drop(f);

    // Reabre com o motor v4: o tail v3 sela e um ativo v4 continua; os
    // registos v3 descodificam (valid time = None) e appends novos carregam
    // valid time NATIVO que sobrevive ao round-trip.
    let log = Log::open(dir.path(), 1 << 20, FsyncPolicy::Always).unwrap();
    assert_eq!(log.head(), 3);
    let all = log.scan(0, 10).unwrap();
    assert_eq!(all.len(), 3);
    assert_eq!(String::from_utf8_lossy(&all[0].1.content), "v3-0");
    assert_eq!(all[1].1.valid_from, None, "v3 não tinha valid time");

    let mut novo = Episode::new("v4-writer", EventKind::Observation, b"novo".to_vec());
    novo.valid_from = Some(1_000);
    novo.valid_to = Some(2_000);
    log.append(novo).unwrap();
    let (_, back) = log.read(3).unwrap().unwrap();
    assert_eq!(
        back.valid_from,
        Some(1_000),
        "valid time nativo persiste (v4)"
    );
    assert_eq!(back.valid_to, Some(2_000));
}

#[test]
fn replication_is_idempotent_and_rejects_divergence() {
    // V2.3: re-aplicar a MESMA entrada é no-op OK; entrada DIFERENTE na mesma
    // posição é divergência (falha); gap à frente do head falha (contiguidade).
    let dir = tempfile::tempdir().unwrap();
    let log = Log::open(dir.path(), 1 << 20, FsyncPolicy::Always).unwrap();

    let e0 = Episode::new("leader", EventKind::Observation, b"a".to_vec());
    let e1 = Episode::new("leader", EventKind::Observation, b"b".to_vec());

    assert_eq!(log.append_replicated(0, e0.clone()).unwrap(), 0);
    assert_eq!(log.append_replicated(1, e1.clone()).unwrap(), 1);

    // Reconexão do follower: o líder reenvia o lote — idempotente.
    assert_eq!(log.append_replicated(0, e0.clone()).unwrap(), 0);
    assert_eq!(log.append_replicated(1, e1).unwrap(), 1);
    assert_eq!(log.head(), 2, "re-aplicação não duplica");

    // Evento DIFERENTE na posição 0 = divergência de histórico → falha.
    let intruso = Episode::new("attacker", EventKind::Observation, b"x".to_vec());
    assert!(log.append_replicated(0, intruso.clone()).is_err());

    // Gap (posição 5 com head 2) → falha; o follower pede o backlog.
    assert!(log.append_replicated(5, intruso).is_err());
    assert_eq!(log.head(), 2);
}

#[test]
fn hlc_never_starts_behind_persisted_timestamps() {
    // V2.1(9): um registo replicado com carimbo do "líder" muito à frente do
    // wall clock; após REABRIR, o HLC local tem de continuar acima dele —
    // senão `AS OF TIMESTAMP` perderia a monotonicidade de ts por LSN.
    let dir = tempfile::tempdir().unwrap();
    let far_future: u64 = (u64::MAX / 2) & !0xFFFF; // millis<<16 gigante e estável

    {
        let log = Log::open(dir.path(), 1 << 20, FsyncPolicy::Always).unwrap();
        let mut e = Episode::new("leader", EventKind::Observation, b"do futuro".to_vec());
        e.ts_hlc = far_future;
        // append_replicated PRESERVA o carimbo do líder (não re-carimba).
        log.append_replicated(0, e).unwrap();
        let (_, back) = log.read(0).unwrap().unwrap();
        assert_eq!(back.ts_hlc, far_future, "carimbo do líder preservado");
    }

    // Reabre (HLC nasceria frio) e appenda normalmente: o ts novo tem de ser
    // ESTRITAMENTE maior que o persistido — o open observou o máximo do disco.
    let log = Log::open(dir.path(), 1 << 20, FsyncPolicy::Always).unwrap();
    log.append(Episode::new(
        "local",
        EventKind::Observation,
        b"agora".to_vec(),
    ))
    .unwrap();
    let (_, e1) = log.read(1).unwrap().unwrap();
    assert!(
        e1.ts_hlc > far_future,
        "HLC pós-restart ({}) tem de superar o máximo persistido ({far_future})",
        e1.ts_hlc
    );
}
