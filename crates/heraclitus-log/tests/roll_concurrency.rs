//! Concorrência × roll de segmento — leitor endurecido + BUG CONHECIDO do escritor.
use heraclitus_core::{Episode, EventKind, FsyncPolicy};
use heraclitus_log::Log;
use std::sync::Arc;

fn append_concurrently(seg: u64, threads: usize, per: usize) -> Arc<Log> {
    let dir = Box::leak(Box::new(tempfile::tempdir().unwrap()));
    let log = Arc::new(
        Log::open(
            dir.path(),
            seg,
            FsyncPolicy::GroupCommit { interval_ms: 50 },
        )
        .unwrap(),
    );
    let hs: Vec<_> = (0..threads)
        .map(|k| {
            let l = log.clone();
            std::thread::spawn(move || {
                for i in 0..per {
                    l.append(Episode::new(
                        "a",
                        EventKind::Observation,
                        format!("t{k}i{i}-{}", "x".repeat(120)).into_bytes(),
                    ))
                    .unwrap();
                }
            })
        })
        .collect();
    for h in hs {
        h.join().unwrap();
    }
    log
}

/// REGRESSÃO (liveness + correção do leitor): com muitos rolls concorrentes o
/// `scan` entrava em LOOP INFINITO e o `read` posicional devolvia o episódio
/// ERRADO (em release; em debug panicava num `debug_assert_eq!`). Tem de
/// terminar e nunca devolver um LSN por outro.
#[test]
fn scan_terminates_and_read_never_returns_wrong_lsn() {
    let log = append_concurrently(4096, 8, 25);
    let head = log.head();
    let _ = log.scan(0, head); // outrora infinito — basta TERMINAR
    let mut wrong = 0;
    for l in 0..head {
        if let Ok(Some((rl, _))) = log.read(l) {
            if rl != l {
                wrong += 1;
            }
        }
    }
    assert_eq!(
        wrong, 0,
        "read() devolveu {wrong} episódios com o LSN errado"
    );
}

/// Sem rolls, nada se perde (prova que a perda vem do ROLL, não da concorrência).
#[test]
fn no_roll_no_loss() {
    let log = append_concurrently(64 << 20, 8, 100);
    let head = log.head();
    assert_eq!(
        log.scan(0, head).unwrap().len() as u64,
        head,
        "scan perdeu registos sem roll"
    );
}

/// REGRESSÃO (escritor): um roll a meio do lote selava o segmento com um índice
/// INCOMPLETO e colava as entradas já escritas ao segmento NOVO com offsets do
/// ficheiro ANTIGO — perdia-se ~1 registo por roll (42 rolls → 125 perdidos).
/// Nenhum registo aceite pode desaparecer, por muitos rolls que haja.
#[test]
fn roll_must_not_lose_records() {
    let log = append_concurrently(65536, 8, 100);
    let head = log.head();
    let missing = (0..head)
        .filter(|&l| !matches!(log.read(l), Ok(Some(_))))
        .count();
    assert_eq!(missing, 0, "roll perdeu {missing} registos de {head}");
}

/// Stress do roll: 16 escritores, payloads de tamanho VARIÁVEL (fronteiras de
/// roll irregulares), 200+ rolls. Nada se perde, nada troca de LSN, o Merkle
/// confere, e o índice RECONSTRUÍDO do disco ao reabrir vê exatamente o mesmo.
#[test]
fn stress_many_rolls_survives_reopen_and_verify() {
    let dir = tempfile::tempdir().unwrap();
    {
        let log = Arc::new(
            Log::open(
                dir.path(),
                4096,
                FsyncPolicy::GroupCommit { interval_ms: 50 },
            )
            .unwrap(),
        );
        let hs: Vec<_> = (0..16usize)
            .map(|k| {
                let l = log.clone();
                std::thread::spawn(move || {
                    for i in 0..100 {
                        let n = 40 + (i * 7 + k * 13) % 400;
                        l.append(Episode::new(
                            "a",
                            EventKind::Observation,
                            format!("t{k}i{i}-{}", "x".repeat(n)).into_bytes(),
                        ))
                        .unwrap();
                    }
                })
            })
            .collect();
        for h in hs {
            h.join().unwrap();
        }
        let head = log.head();
        assert!(
            log.sealed_segments().len() > 50,
            "o teste tem de provocar muitos rolls"
        );
        assert_eq!(
            log.scan(0, head).unwrap().len() as u64,
            head,
            "scan perdeu registos"
        );
        for l in 0..head {
            match log.read(l) {
                Ok(Some((rl, _))) => assert_eq!(rl, l, "read({l}) devolveu o LSN {rl}"),
                other => panic!("read({l}) não devolveu o registo: {:?}", other.is_err()),
            }
        }
        assert!(
            log.verify().is_ok(),
            "cadeia Merkle inconsistente após os rolls"
        );
    }
    let log2 = Log::open(dir.path(), 4096, FsyncPolicy::Always).unwrap();
    let head2 = log2.head();
    assert_eq!(
        log2.scan(0, head2).unwrap().len() as u64,
        head2,
        "scan incompleto após reabrir"
    );
}

/// REGRESSÃO (invariante I6): quem indexa views TEM de indexar o episódio com o
/// `ts_hlc` que ficou no log. `append` carimba a SUA cópia, por isso indexar o
/// original deixava as views com `ts_hlc = 0` ao vivo e com o valor real quando
/// reconstruídas do LSN 0 — estados diferentes para o mesmo log.
#[test]
fn append_stamped_devolve_o_mesmo_ts_que_ficou_no_log() {
    let dir = tempfile::tempdir().unwrap();
    let log = Log::open(dir.path(), 1 << 20, FsyncPolicy::Always).unwrap();
    let ep = Episode::new("a", EventKind::Observation, b"x".to_vec());
    assert_eq!(ep.ts_hlc, 0, "o episódio nasce sem carimbo");

    let (lsn, stamped) = log.append_stamped(ep).unwrap();
    assert_ne!(stamped.ts_hlc, 0, "o devolvido tem de vir carimbado");

    let (_, no_log) = log.read(lsn).unwrap().unwrap();
    assert_eq!(
        stamped.ts_hlc, no_log.ts_hlc,
        "o episódio indexado diverge do que ficou no log (quebra I6)"
    );
}
