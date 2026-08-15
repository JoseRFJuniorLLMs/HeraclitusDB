use heraclitus_core::{Episode, EventKind, FsyncPolicy};
use heraclitus_log::Log;
use std::sync::Arc;

/// REGRESSÃO: o  TEM de ser monotónico por LSN — é o contrato de que a
/// busca binária de  (AS OF TIMESTAMP) depende. O carimbo era
/// feito no chamador e só depois a mensagem entrava na fila do worker (que é
/// quem atribui o LSN), pelo que appends concorrentes se invertiam: medido 69
/// inversões em 1200 registos (5,75%), com o AS OF a fazer busca binária sobre
/// dados desordenados. Agora o carimbo é feito dentro da secção crítica que
/// enfileira o comando.
#[test]
fn ts_monotonico_por_lsn_sob_concorrencia() {
    for tentativa in 0..5 {
        let dir = tempfile::tempdir().unwrap();
        let log = Arc::new(
            Log::open(
                dir.path(),
                1 << 20,
                FsyncPolicy::GroupCommit { interval_ms: 5 },
            )
            .unwrap(),
        );
        let hs: Vec<_> = (0..8usize)
            .map(|k| {
                let l = log.clone();
                std::thread::spawn(move || {
                    for i in 0..150 {
                        l.append(Episode::new(
                            "a",
                            EventKind::Observation,
                            format!("t{k}i{i}").into_bytes(),
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
        let all = log.scan(0, head).unwrap();
        let mut inversoes = 0;
        let mut prev = 0u64;
        for (lsn, e) in &all {
            if e.ts_hlc < prev {
                inversoes += 1;
                if inversoes <= 3 {
                    eprintln!(
                        "  inversao no LSN {lsn}: ts {} < anterior {}",
                        e.ts_hlc, prev
                    );
                }
            }
            prev = e.ts_hlc;
        }
        eprintln!(
            "tentativa {tentativa}: {} registos, {inversoes} inversoes de ts por LSN",
            all.len()
        );
        assert_eq!(
            inversoes, 0,
            "ts NAO e monotonico por LSN — a busca binaria do AS OF TIMESTAMP e invalida"
        );
    }
}
