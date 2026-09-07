use heraclitus_core::{Episode, EventKind, FsyncPolicy, ProductPoint};
use heraclitus_crypto::{KeyStore, SHREDDED};
use heraclitus_log::Log;

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && haystack.windows(needle.len()).any(|w| w == needle)
}

#[test]
fn encryption_covers_content_attrs_embedding_and_shred_keeps_replay_alive() {
    let dir = tempfile::tempdir().unwrap();
    let log_dir = dir.path().join("log");
    let keys_dir = dir.path().join("keys");
    let keys = KeyStore::open(&keys_dir).unwrap();
    let log = Log::open_with_keystore(&log_dir, 1 << 20, FsyncPolicy::Always, Some(keys.clone()))
        .unwrap();

    let mut episode = Episode::new(
        "titular:hmac-sha256:abc",
        EventKind::Custom("OperationalFact".into()),
        b"Carlos autenticou no servidor pessoal".to_vec(),
    );
    episode
        .attrs
        .insert("actor_name".into(), "Carlos Silva".into());
    episode
        .attrs
        .insert("source_ip".into(), "203.0.113.45".into());
    episode.attrs.insert(
        "__heraclitus_idempotency_key".into(),
        "0123456789abcdef".into(),
    );
    episode.attrs.insert(
        "__heraclitus_idempotency_hash".into(),
        "abcdef0123456789".into(),
    );
    episode.embedding = Some(ProductPoint {
        hyp: vec![0.25, 0.5],
        sph: vec![],
        euc: vec![42.0],
    });

    let lsn = log.append(episode).unwrap();
    let (_, clear) = log.read(lsn).unwrap().unwrap();
    assert_eq!(clear.attrs["actor_name"], "Carlos Silva");
    assert_eq!(clear.content, b"Carlos autenticou no servidor pessoal");
    assert!(clear.embedding.is_some());

    for entry in std::fs::read_dir(&log_dir).unwrap().flatten() {
        if !entry.path().is_file() {
            continue;
        }
        let raw = std::fs::read(entry.path()).unwrap();
        assert!(!contains(&raw, b"Carlos Silva"), "PII vazou no WAL");
        assert!(!contains(&raw, b"203.0.113.45"), "IP vazou no WAL");
        assert!(
            !contains(&raw, b"Carlos autenticou no servidor pessoal"),
            "content vazou no WAL"
        );
    }

    assert!(keys.shred("titular:hmac-sha256:abc").unwrap());
    let (_, shredded) = log.read(lsn).unwrap().unwrap();
    assert_eq!(shredded.content, SHREDDED);
    assert_eq!(
        shredded
            .attrs
            .get("__heraclitus_shredded")
            .map(String::as_str),
        Some("true")
    );
    assert!(!shredded.attrs.contains_key("actor_name"));
    assert!(!shredded.attrs.contains_key("source_ip"));
    assert!(shredded.embedding.is_none());
    assert!(shredded.attrs.contains_key("__heraclitus_idempotency_key"));

    drop(log);
    let reopened = Log::open_with_keystore(
        &log_dir,
        1 << 20,
        FsyncPolicy::Always,
        Some(KeyStore::open(&keys_dir).unwrap()),
    )
    .unwrap();
    let (_, after_restart) = reopened.read(lsn).unwrap().unwrap();
    assert_eq!(after_restart.content, SHREDDED);
    assert_eq!(
        after_restart
            .attrs
            .get("__heraclitus_shredded")
            .map(String::as_str),
        Some("true")
    );
}

/// Varre TODOS os ficheiros de `log_dir` e falha se algum contiver PII em
/// claro. É o mesmo invariante que o teste acima afirma sobre o WAL, aqui
/// extraído para poder ser aplicado também DEPOIS do crypto-shred.
fn varrer_log_dir_sem_pii(log_dir: &std::path::Path) {
    for entry in std::fs::read_dir(log_dir).unwrap().flatten() {
        if !entry.path().is_file() {
            continue;
        }
        let raw = std::fs::read(entry.path()).unwrap();
        let nome = entry.path().display().to_string();
        assert!(!contains(&raw, b"Carlos Silva"), "PII vazou em {nome}");
        assert!(!contains(&raw, b"203.0.113.45"), "IP vazou em {nome}");
        assert!(
            !contains(&raw, b"Carlos autenticou no servidor pessoal"),
            "content vazou em {nome}"
        );
    }
}

/// O sidecar `.zmap` do skip-scan não pode vazar PII de um log cifrado.
///
/// O `SkipScanner` constrói o zone map a partir de `Log::scan`, que já devolve
/// os episódios DECIFRADOS; o `ZoneMap` guarda min/max de `agent_id`,
/// `session_id` e de cada `attrs[k]` como `String` crua, e o sidecar era
/// gravado em bincode puro no MESMO directório do WAL. Resultado: com cifra em
/// repouso ligada, uma única consulta escrevia `Carlos Silva` e `203.0.113.45`
/// em claro ao lado do WAL — e, por o `.zmap` não depender de chave nenhuma,
/// esse PII SOBREVIVIA ao `KeyStore::shred` (o crypto-shredding deixava de
/// apagar o acesso ao dado). Auditoria 2026-09-05, A21.
#[test]
fn o_sidecar_zmap_nao_pode_vazar_pii_de_um_log_cifrado() {
    use heraclitus_log::skip_scan::SkipScanner;
    use std::sync::Arc;

    let dir = tempfile::tempdir().unwrap();
    let log_dir = dir.path().join("log");
    let keys_dir = dir.path().join("keys");
    let keys = KeyStore::open(&keys_dir).unwrap();
    // Segmentos pequenos de propósito: o skip-scan só constrói zone maps para
    // segmentos SELADOS, portanto sem selagem o teste não exercia nada.
    let log = Arc::new(
        Log::open_with_keystore(&log_dir, 2048, FsyncPolicy::Always, Some(keys.clone())).unwrap(),
    );

    for i in 0..80 {
        let mut episode = Episode::new(
            "titular:hmac-sha256:abc",
            EventKind::Custom("OperationalFact".into()),
            format!("Carlos autenticou no servidor pessoal {i:04}").into_bytes(),
        );
        episode
            .attrs
            .insert("actor_name".into(), "Carlos Silva".into());
        episode
            .attrs
            .insert("source_ip".into(), "203.0.113.45".into());
        log.append(episode).unwrap();
    }
    log.flush().unwrap();
    assert!(
        log.sealed_segments().len() >= 2,
        "o teste precisa de segmentos selados para o skip-scan construir zone maps"
    );

    // Uma consulta por `agent_id` basta: o pruning constrói o zone map de cada
    // segmento selado e (era isto o defeito) persistia-o em claro.
    let scanner = SkipScanner::new(log.clone());
    scanner.warm().unwrap();
    let (encontrados, _) = scanner
        .scan_pruned(|z| z.may_contain_agent("titular:hmac-sha256:abc"))
        .unwrap();
    assert!(
        !encontrados.is_empty(),
        "a consulta tinha de encontrar os episódios do titular"
    );

    varrer_log_dir_sem_pii(&log_dir);

    // Crypto-shredding: apagar a chave tem de apagar o ACESSO ao dado. Um
    // sidecar em claro não depende de chave nenhuma, logo sobrevive ao shred.
    assert!(keys.shred("titular:hmac-sha256:abc").unwrap());
    varrer_log_dir_sem_pii(&log_dir);
}

/// Ligar a cifra num data dir que já tem sidecars tem de invalidar esses
/// sidecars.
///
/// Um `.zmap` gravado por uma abertura anterior SEM keystore guarda min/max de
/// `agent_id`/`session_id`/`attrs` em claro e não depende de chave nenhuma:
/// se continuasse a ser lido, sobreviveria ao `KeyStore::shred` e continuaria a
/// servir esses valores ao pruning depois de a chave ter sido destruída. O
/// ficheiro é derivado e descartável, portanto apagá-lo só custa uma
/// reconstrução. Auditoria 2026-09-05, A21.
#[test]
fn um_zmap_residual_de_uma_abertura_sem_cifra_e_apagado_ao_reabrir_cifrado() {
    use heraclitus_log::skip_scan::SkipScanner;
    use std::sync::Arc;

    let dir = tempfile::tempdir().unwrap();
    let log_dir = dir.path().join("log");
    let keys_dir = dir.path().join("keys");

    // 1) Data dir aberto SEM keystore: os sidecars são escritos normalmente.
    let claro = Arc::new(Log::open(&log_dir, 2048, FsyncPolicy::Always).unwrap());
    for i in 0..80 {
        let mut episode = Episode::new(
            "titular:hmac-sha256:abc",
            EventKind::Custom("OperationalFact".into()),
            format!("Carlos autenticou no servidor pessoal {i:04}").into_bytes(),
        );
        episode
            .attrs
            .insert("actor_name".into(), "Carlos Silva".into());
        claro.append(episode).unwrap();
    }
    claro.flush().unwrap();
    let selados = claro.sealed_segments().len();
    assert!(selados >= 2, "o teste precisa de segmentos selados");
    SkipScanner::new(claro.clone()).warm().unwrap();
    assert!(
        contar_zmaps(&log_dir) > 0,
        "sem cifra o sidecar TEM de continuar a ser persistido"
    );
    drop(claro);

    // 2) Mesmo data dir, agora com cifra em repouso: os `.zmap` residuais não
    //    podem ser acreditados nem podem ficar no disco.
    let keys = KeyStore::open(&keys_dir).unwrap();
    let cifrado =
        Arc::new(Log::open_with_keystore(&log_dir, 2048, FsyncPolicy::Always, Some(keys)).unwrap());
    let scanner = SkipScanner::new(cifrado.clone());
    scanner.warm().unwrap();
    let (construidos, carregados) = scanner.build_stats();
    assert_eq!(
        carregados, 0,
        "um sidecar em claro não pode ser lido num log cifrado"
    );
    assert_eq!(construidos, selados, "devia ter reconstruído tudo em RAM");
    assert_eq!(
        contar_zmaps(&log_dir),
        0,
        "os sidecars residuais tinham de ter sido apagados"
    );
}

fn contar_zmaps(log_dir: &std::path::Path) -> usize {
    std::fs::read_dir(log_dir)
        .unwrap()
        .flatten()
        .filter(|e| e.path().extension().map(|x| x == "zmap").unwrap_or(false))
        .count()
}

/// Resíduos `.zmap` órfãos e `.zmap.tmp` de crash também têm de desaparecer
/// num log cifrado.
///
/// O fix A21 apagava o sidecar em claro APENAS do segmento que o
/// `zone_map_for` estava a resolver naquele instante (`remove_file` por id), e
/// tanto o `warm()` como o `scan_pruned` só iteram `sealed_segments()`. Dois
/// resíduos escapavam a essa limpeza e ficavam no disco, ao lado de um WAL
/// cifrado, com min/max de `agent_id`/`session_id`/`attrs` em CLARO e sem
/// dependerem de chave nenhuma — logo sobreviviam ao `KeyStore::shred`, que é
/// exactamente o invariante que A21 diz fechar:
///   (a) `<id>.zmap` de um id que já não consta de `sealed_segments()`
///       (segmento removido pela recuperação de `truncate.intent`, restauro
///       parcial de backup, ou remoção manual);
///   (b) `<id>.zmap.tmp` deixado por um crash entre o `sync_all` e o `rename`
///       do `persist_sidecar` — esse nunca era apagado por caminho nenhum.
/// Auditoria 2026-09-05, vaga 2, R51.
#[test]
fn residuos_zmap_orfao_e_tmp_sao_apagados_num_log_cifrado() {
    use heraclitus_log::skip_scan::SkipScanner;
    use std::sync::Arc;

    let dir = tempfile::tempdir().unwrap();
    let log_dir = dir.path().join("log");
    let keys_dir = dir.path().join("keys");
    let keys = KeyStore::open(&keys_dir).unwrap();
    // Segmentos pequenos: o skip-scan só constrói zone maps para segmentos
    // SELADOS.
    let log = Arc::new(
        Log::open_with_keystore(&log_dir, 2048, FsyncPolicy::Always, Some(keys.clone())).unwrap(),
    );

    for i in 0..80 {
        let mut episode = Episode::new(
            "titular:hmac-sha256:abc",
            EventKind::Custom("OperationalFact".into()),
            format!("Carlos autenticou no servidor pessoal {i:04}").into_bytes(),
        );
        episode
            .attrs
            .insert("actor_name".into(), "Carlos Silva".into());
        episode
            .attrs
            .insert("source_ip".into(), "203.0.113.45".into());
        log.append(episode).unwrap();
    }
    log.flush().unwrap();
    let selados = log.sealed_segments().len();
    assert!(selados >= 2, "o teste precisa de segmentos selados");

    // Injectar os dois resíduos que uma versão pré-fix (ou um período sem
    // keystore, ou um crash a meio do `persist_sidecar`) deixava no disco.
    // Bytes em claro de propósito: é isso que um sidecar bincode é.
    let orfao = log_dir.join("00000000000000000999.zmap");
    let tmp = log_dir.join("00000000000000000000.zmap.tmp");
    let lixo_com_pii = b"ZMAP\x01\x00Carlos Silva ... 203.0.113.45".to_vec();
    std::fs::write(&orfao, &lixo_com_pii).unwrap();
    std::fs::write(&tmp, &lixo_com_pii).unwrap();
    assert!(
        !log.sealed_segments().iter().any(|m| m.id == 999),
        "o resíduo órfão tem de ser de um id que o scanner NUNCA visita"
    );

    let scanner = SkipScanner::new(log.clone());
    scanner.warm().unwrap();
    let (encontrados, _) = scanner
        .scan_pruned(|z| z.may_contain_agent("titular:hmac-sha256:abc"))
        .unwrap();
    assert!(
        !encontrados.is_empty(),
        "a consulta tinha de encontrar os episódios do titular"
    );

    // Crypto-shredding: apagar a chave tem de apagar o ACESSO ao dado. Um
    // resíduo em claro não depende de chave nenhuma, logo sobreviveria.
    assert!(keys.shred("titular:hmac-sha256:abc").unwrap());
    // Os dois resíduos são verificados JUNTOS e nomeados na mensagem: uma
    // limpeza que só apanhe um deles (p.ex. filtrar por `extension() == "zmap"`,
    // que deixa o `.zmap.tmp` para trás) tem de dizer QUAL sobreviveu.
    let sobreviventes: Vec<String> = [&orfao, &tmp]
        .iter()
        .filter(|p| p.exists())
        .map(|p| p.display().to_string())
        .collect();
    assert!(
        sobreviventes.is_empty(),
        "resíduos de sidecar sobreviveram ao shred: {sobreviventes:?}"
    );
    varrer_log_dir_sem_pii(&log_dir);
}
