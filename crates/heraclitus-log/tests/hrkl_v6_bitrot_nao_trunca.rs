//! Auditoria 2026-10-16 — regressões de B1, B2, B5 e B6 no HRKL v6.
//!
//! Cada teste nasceu de uma sonda da auditoria
//! (`docs/auditoria-2026-10-16-sondas/heraclitus-log_tests_sonda_auditoria_v6.rs`)
//! que PASSAVA enquanto o defeito existia; aqui a asserção está invertida. São o
//! equivalente v6 de `bitrot_nao_trunca.rs` e `crc_nao_e_engolido.rs`, que
//! cobriam só o log legado — e o v6 é o formato por omissão.
//!
//! Só usam API pública que já existia antes da correcção, de propósito: o
//! mesmo ficheiro, posto sobre o código antigo, tem de falhar nos quatro.

use heraclitus_core::{Episode, EventKind, FsyncPolicy, HeraclitusError};
use heraclitus_log::v6::hrki::{IndexPolicy, IndexPolicySet};
use heraclitus_log::v6::{FooterV6, PackingProfile, V6Log};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

fn segmentos_com_sufixo(dir: &Path, sufixo: &str) -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = std::fs::read_dir(dir.join("segments"))
        .unwrap()
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.to_string_lossy().ends_with(sufixo))
        .collect();
    v.sort();
    v
}

fn selados(dir: &Path) -> Vec<PathBuf> {
    segmentos_com_sufixo(dir, ".raw.hrkl")
}

fn activo(dir: &Path) -> PathBuf {
    let mut v = segmentos_com_sufixo(dir, ".active.hrkl");
    assert_eq!(v.len(), 1, "esperava exactamente uma cauda activa");
    v.remove(0)
}

/// Os nomes são `{id:020}.…`.
fn id_do_segmento(path: &Path) -> u64 {
    path.file_name().unwrap().to_string_lossy()[..20]
        .parse()
        .unwrap()
}

fn inverter_byte(path: &Path, off: u64) {
    let mut f = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .unwrap();
    let mut b = [0u8; 1];
    f.seek(SeekFrom::Start(off)).unwrap();
    f.read_exact(&mut b).unwrap();
    b[0] ^= 0x01;
    f.seek(SeekFrom::Start(off)).unwrap();
    f.write_all(&b).unwrap();
    f.sync_all().unwrap();
}

fn encher(log: &V6Log, n: usize, enchimento: &str) {
    for i in 0..n {
        log.append(Episode::new(
            "a",
            EventKind::Observation,
            format!("evento {i} {enchimento}").into_bytes(),
        ))
        .unwrap();
    }
}

/// B2 — um bit trocado num RAW selado. `scan(0, 200)` devolvia `Ok` com 187
/// linhas e `read` devolvia `Ok(None)` para 13 LSN confirmados, porque o
/// percurso em streaming parava no CRC falhado como se o segmento tivesse
/// acabado. `catch_up`, `rebuild`, o índice de atributos, o `Subscribe`, o
/// snapshot Raft e o relatório do titular avançam todos por linha: os eventos
/// perdiam-se das views sem erro nenhum.
#[test]
fn bitrot_em_raw_selado_falha_alto_no_scan_e_no_read() {
    let dir = tempfile::tempdir().unwrap();
    let log = V6Log::open(dir.path(), 4096, FsyncPolicy::Always).unwrap();
    encher(&log, 200, &"x".repeat(60));
    let head = log.head();
    assert_eq!(log.scan(0, head).unwrap().len() as u64, head, "setup");
    let segs = selados(dir.path());
    assert!(segs.len() >= 3, "o teste precisa de vários RAW selados");
    let alvo = segs[segs.len() / 2].clone();
    let len = std::fs::metadata(&alvo).unwrap().len();
    inverter_byte(&alvo, len / 2);

    match log.scan(0, head) {
        Ok(v) => panic!("scan devolveu Ok com {} de {head} linhas", v.len()),
        Err(HeraclitusError::Corruption { .. }) => {}
        Err(e) => panic!("esperava Corruption, veio {e}"),
    }

    let mut corrompidos = 0;
    for lsn in 0..head {
        match log.read(lsn) {
            Ok(Some((l, _))) => assert_eq!(l, lsn),
            Ok(None) => panic!("read({lsn}) devolveu Ok(None) com o LSN abaixo do head {head}"),
            Err(HeraclitusError::Corruption { .. }) => corrompidos += 1,
            Err(e) => panic!("read({lsn}): esperava Corruption, veio {e}"),
        }
    }
    assert!(corrompidos > 0, "nenhum read acusou o registo corrompido");

    // O diário administrativo recupera-se por `scan_builtin_eq_capped`, cujo
    // ramo RAW também parava no rasgo e ignorava o `torn_at`.
    assert!(
        log.scan_builtin_eq_capped("agent_id", "a", 0, head, usize::MAX)
            .is_err(),
        "varredura podada devolveu Ok sem os registos depois do corrompido"
    );

    // Uma janela que não toca no segmento estragado continua a responder.
    assert_eq!(log.scan(0, 1).unwrap().len(), 1);
}

/// B1 — um bit trocado a 1/3 da cauda activa, com os 100 registos confirmados
/// com `fsync = Always`. O arranque tratava o CRC falhado como cauda rasgada:
/// `head` passava de 100 para 33, os 67 registos seguintes eram apagados e os
/// LSN 33.. voltavam a ser atribuídos aos próximos appends.
#[test]
fn bitrot_no_meio_da_cauda_activa_nao_trunca_confirmados() {
    let dir = tempfile::tempdir().unwrap();
    let a;
    let alvo;
    {
        let log = V6Log::open(dir.path(), 1 << 20, FsyncPolicy::Always).unwrap();
        encher(&log, 100, &"y".repeat(40));
        assert_eq!(log.head(), 100);
        a = activo(dir.path());
        alvo = std::fs::metadata(&a).unwrap().len() / 3;
        inverter_byte(&a, alvo);
    }
    let antes = std::fs::read(&a).unwrap();

    match V6Log::open(dir.path(), 1 << 20, FsyncPolicy::Always) {
        Ok(log) => panic!(
            "o arranque aceitou a cauda corrompida com head {} (antes 100)",
            log.head()
        ),
        Err(HeraclitusError::Corruption { detail, .. }) => {
            assert!(detail.contains("refusing to truncate"), "{detail}")
        }
        Err(e) => panic!("esperava Corruption, veio {e}"),
    }
    assert_eq!(
        std::fs::read(&a).unwrap(),
        antes,
        "a cauda foi alterada — a evidência tinha de ficar intacta"
    );

    // Nada foi destruído: desfeita a corrupção, os 100 registos voltam todos.
    inverter_byte(&a, alvo);
    let log = V6Log::open(dir.path(), 1 << 20, FsyncPolicy::Always).unwrap();
    assert_eq!(log.head(), 100);
    assert_eq!(log.scan(0, 100).unwrap().len(), 100);
}

/// B2 na cauda: leitura sequencial, pontual e filtrada têm de denunciar um
/// registo confirmado que deixou de ser legível, com o writer ainda aberto.
#[test]
fn bitrot_na_cauda_falha_no_scan_no_read_e_no_scan_filtrado() {
    let dir = tempfile::tempdir().unwrap();
    let log = V6Log::open(dir.path(), 1 << 20, FsyncPolicy::Always).unwrap();
    encher(&log, 100, &"y".repeat(40));
    let path = activo(dir.path());
    let alvo = std::fs::metadata(&path).unwrap().len() / 3;
    inverter_byte(&path, alvo);
    assert!(matches!(
        log.scan(0, 100),
        Err(HeraclitusError::Corruption { .. })
    ));
    let mut erros = 0;
    for lsn in 0..log.head() {
        match log.read(lsn) {
            Ok(Some((encontrado, _))) => assert_eq!(encontrado, lsn),
            Err(HeraclitusError::Corruption { .. }) => erros += 1,
            outro => panic!("read({lsn}) abaixo do head: {outro:?}"),
        }
    }
    assert!(erros > 0);
    assert!(matches!(
        log.scan_builtin_eq_capped("agent_id", "a", 0, 100, usize::MAX),
        Err(HeraclitusError::Corruption { .. })
    ));
    assert!(log.read(100).unwrap().is_none());
    assert!(log.read(u64::MAX).unwrap().is_none());
}

/// B2: a contagem sozinha não prova cobertura. Um frame com CRC íntegro que
/// repete outro LSN deixa um confirmado em falta, inclusive no scan filtrado.
#[test]
fn lsn_duplicado_com_crc_integro_na_cauda_nao_esconde_um_confirmado() {
    use heraclitus_log::v6::header::FILE_HEADER_LEN;
    use heraclitus_log::v6::raw::{encode_raw_record, scan_raw_segment};

    let dir = tempfile::tempdir().unwrap();
    let log = V6Log::open(dir.path(), 1 << 20, FsyncPolicy::Always).unwrap();
    encher(&log, 10, "conteudo");
    let path = activo(dir.path());
    let scan = scan_raw_segment(&path).unwrap();
    let mut bytes = std::fs::read(&path).unwrap()[..FILE_HEADER_LEN].to_vec();
    for r in scan.records {
        bytes.extend(encode_raw_record(
            if r.lsn == 1 { 2 } else { r.lsn },
            r.hlc,
            &r.payload,
        ));
    }
    // Mantém dez frames válidos, mas o LSN 1 não aparece e o 2 se repete.
    let mut file = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
    file.write_all(&bytes).unwrap();
    file.sync_all().unwrap();
    assert_eq!(scan_raw_segment(&path).unwrap().records.len(), 10);
    assert!(matches!(
        log.scan(0, 10),
        Err(HeraclitusError::Corruption { .. })
    ));
    assert!(matches!(
        log.read(1),
        Err(HeraclitusError::Corruption { .. })
    ));
    assert!(matches!(
        log.scan_builtin_eq_capped("agent_id", "a", 0, 10, usize::MAX),
        Err(HeraclitusError::Corruption { .. })
    ));
}

/// B5 — escrita interrompida (SIGKILL a meio de um `write` grande, que o Linux
/// corta em fronteira de página) de um registo cujo payload — conteúdo do
/// cliente — traz uma imagem de footer válida mesmo antes do corte. O CRC do
/// footer não tem chave, e o arranque via um footer depois do rasgo e recusava
/// abrir para sempre ("refusing to truncate a sealed segment").
#[test]
fn cauda_rasgada_com_imagem_de_footer_no_payload_recupera() {
    let (dir, _) = cortar_depois_de_imagem_de_footer(0);
    let log = V6Log::open(dir.path(), 1 << 20, FsyncPolicy::Always)
        .expect("a cauda rasgada tem de ser recuperada, não recusada para sempre");
    assert_eq!(log.head(), 1, "só o registo completo sobrevive ao corte");
    let linhas = log.scan(0, 1).unwrap();
    assert_eq!(linhas[0].1.content, b"primeiro");
    let novo = log
        .append(Episode::new(
            "a",
            EventKind::Observation,
            b"depois".to_vec(),
        ))
        .unwrap();
    assert_eq!(novo, 1, "o LSN do registo cortado é o próximo a atribuir");
    drop(log);
    let log = V6Log::open(dir.path(), 1 << 20, FsyncPolicy::Always).unwrap();
    assert_eq!(log.head(), 2);
}

/// O preço do veto do footer, aceite de propósito: se a imagem forjada no
/// payload DECLARA o LSN do próprio registo cortado, é indistinguível do footer
/// verdadeiro de um segmento selado cujo último `payload_len` se estragou — e
/// aí truncar apagaria um registo confirmado. O arranque recusa, sem tocar em
/// nada (falha fechada); o operador corta a cauda no offset indicado.
#[test]
fn imagem_de_footer_que_declara_o_lsn_cortado_recusa_sem_perda() {
    use heraclitus_log::v6::raw::scan_raw_segment;

    let (dir, a) = cortar_depois_de_imagem_de_footer(2);
    let antes = std::fs::read(&a).unwrap();
    match V6Log::open(dir.path(), 1 << 20, FsyncPolicy::Always) {
        Ok(log) => panic!("truncou com head {}", log.head()),
        Err(HeraclitusError::Corruption { detail, .. }) => {
            assert!(detail.contains("valid footer at EOF"), "{detail}")
        }
        Err(e) => panic!("esperava Corruption, veio {e}"),
    }
    assert_eq!(std::fs::read(&a).unwrap(), antes, "nada pode ser alterado");

    // A intervenção do operador: cortar no rasgo devolve o arranque.
    let rasgo = scan_raw_segment(&a).unwrap().torn_at.expect("rasgo");
    std::fs::OpenOptions::new()
        .write(true)
        .open(&a)
        .unwrap()
        .set_len(rasgo)
        .unwrap();
    let log = V6Log::open(dir.path(), 1 << 20, FsyncPolicy::Always).unwrap();
    assert_eq!(log.head(), 1);
}

/// Dois appends — `"primeiro"` e um payload com a imagem de um footer que
/// declara `record_count` registos — e o corte do 2.º logo a seguir à imagem.
fn cortar_depois_de_imagem_de_footer(record_count: u64) -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let imagem = FooterV6 {
        record_count,
        min_lsn: 0,
        max_lsn: record_count.saturating_sub(1),
        min_hlc: 0,
        max_hlc: 0,
        block_count: 0,
        flags: 0,
        block_directory_offset: 0,
        block_directory_len: 0,
        logical_root: [0u8; 32],
    }
    .encode();
    assert!(FooterV6::decode(&imagem).is_ok(), "setup: footer íntegro");
    {
        let log = V6Log::open(dir.path(), 1 << 20, FsyncPolicy::Always).unwrap();
        log.append(Episode::new(
            "a",
            EventKind::Observation,
            b"primeiro".to_vec(),
        ))
        .unwrap();
        let mut conteudo = vec![b'x'; 300];
        conteudo.extend_from_slice(&imagem);
        conteudo.extend_from_slice(&[b'y'; 5000]);
        log.append(Episode::new("a", EventKind::Observation, conteudo))
            .unwrap();
    }
    let a = activo(dir.path());
    let bytes = std::fs::read(&a).unwrap();
    let pos = bytes
        .windows(imagem.len())
        .position(|w| w == &imagem[..])
        .expect("imagem no ficheiro");
    // O corte do `write` a meio do 2.º registo, logo a seguir à imagem.
    let f = std::fs::OpenOptions::new().write(true).open(&a).unwrap();
    f.set_len((pos + imagem.len()) as u64).unwrap();
    drop(f);
    (dir, a)
}

/// B6 — um único RAW selado corrompido travava o packing de todos os
/// segmentos seguintes (e, por arrasto, HRKI, Parquet e GC), com a mensagem
/// enganosa "refusing to pack an unsealed segment" para um segmento que está
/// selado.
#[test]
fn um_raw_corrompido_nao_trava_a_fila_de_packing() {
    let dir = tempfile::tempdir().unwrap();
    let log = V6Log::open(dir.path(), 4096, FsyncPolicy::Always).unwrap();
    encher(&log, 200, &"x".repeat(60));
    let segs = selados(dir.path());
    assert!(segs.len() >= 3, "o teste precisa de vários RAW selados");
    let alvo = segs[1].clone();
    let id_alvo = id_do_segmento(&alvo);
    let len = std::fs::metadata(&alvo).unwrap().len();
    inverter_byte(&alvo, len / 2);

    for passagem in 0..2 {
        let Err(err) = log.pack_pending(PackingProfile::Balanced) else {
            panic!("passagem {passagem}: o segmento corrompido tem de ser reportado, não engolido");
        };
        let msg = err.to_string();
        assert!(
            matches!(err, HeraclitusError::Corruption { .. }),
            "passagem {passagem}: {msg}"
        );
        assert!(!msg.contains("unsealed"), "passagem {passagem}: {msg}");
        assert!(msg.contains("offset"), "passagem {passagem}: {msg}");
        assert_eq!(
            log.manifest().packing_queue(),
            vec![id_alvo],
            "passagem {passagem}: a fila tem de ficar só com o segmento corrompido ({msg})"
        );
    }
}

/// B6, a outra fila do mesmo padrão: um PACKED ilegível não pode impedir os
/// outros segmentos de ganharem sidecar HRKI.
#[test]
fn um_packed_corrompido_nao_trava_a_fila_de_hrki() {
    let dir = tempfile::tempdir().unwrap();
    let log = V6Log::open(dir.path(), 4096, FsyncPolicy::Always).unwrap();
    encher(&log, 200, &"x".repeat(60));
    let empacotados = log.pack_pending(PackingProfile::Balanced).unwrap();
    assert!(empacotados.len() >= 3, "o teste precisa de vários PACKED");
    let packed = segmentos_com_sufixo(dir.path(), ".packed.hrkl");
    let alvo = packed[1].clone();
    let id_alvo = id_do_segmento(&alvo);
    let len = std::fs::metadata(&alvo).unwrap().len();
    inverter_byte(&alvo, len / 2);

    let policy = IndexPolicySet::new().com("agent_id", IndexPolicy::PublicTechnical);
    assert!(
        log.build_pending_hrki(&policy, None, 0.01).is_err(),
        "o PACKED corrompido tem de ser reportado"
    );
    assert_eq!(
        log.manifest().sidecar_queue(),
        vec![id_alvo],
        "só o segmento corrompido pode ficar sem sidecar"
    );
}
