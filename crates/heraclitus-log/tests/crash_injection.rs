//! M0 acceptance gate: kill the writer process mid-append N times and assert
//! the log always recovers to a consistent, verifiable state.
//!
//! Iterations default to 25 locally; CI runs with CRASH_ITERS=200..1000.

use heraclitus_core::FsyncPolicy;
use heraclitus_log::Log;
use std::process::{Command, Stdio};
use std::time::Duration;

fn crash_writer_bin() -> std::path::PathBuf {
    // target/debug/examples/crash_writer(.exe)
    let mut p = std::env::current_exe().unwrap();
    p.pop(); // deps/
    p.pop(); // debug/
    p.push("examples");
    p.push(format!("crash_writer{}", std::env::consts::EXE_SUFFIX));
    p
}

/// O binário do exemplo precisa ser construído no mesmo target dir do binário
/// de teste. Assumir o target global do Cargo quebra runners que isolam o
/// build (e pode fazer o teste matar um binário de outra build).
fn test_target_dir() -> std::path::PathBuf {
    let mut p = std::env::current_exe().expect("caminho do binário de teste");
    p.pop(); // deps/
    p.pop(); // debug/ | release/
    p
}

#[test]
fn survives_repeated_mid_append_kills() {
    let iters: u64 = std::env::var("CRASH_ITERS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(25);

    // Build the example binary once.
    let status = Command::new(env!("CARGO"))
        .args(["build", "--example", "crash_writer", "-p", "heraclitus-log"])
        .arg("--target-dir")
        .arg(test_target_dir())
        .status()
        .expect("cargo build crash_writer");
    assert!(status.success());

    let dir = tempfile::tempdir().unwrap();
    let mut last_count = 0u64;

    for i in 0..iters {
        let mut child = Command::new(crash_writer_bin())
            .arg(dir.path())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn crash_writer");

        // Let it write for a random-ish slice, then kill it cold.
        std::thread::sleep(Duration::from_millis(20 + (i * 7) % 80));
        child.kill().expect("kill");
        let _ = child.wait();

        // Recovery: open must succeed, verify must pass, count must not shrink.
        let log = Log::open(dir.path(), 64 * 1024, FsyncPolicy::Always)
            .unwrap_or_else(|e| panic!("recovery failed at iteration {i}: {e}"));
        let report = log
            .verify()
            .unwrap_or_else(|e| panic!("verify failed at {i}: {e}"));
        assert!(
            report.records >= last_count,
            "iteration {i}: record count shrank ({} -> {})",
            last_count,
            report.records
        );
        last_count = report.records;
        drop(log);
    }

    assert!(last_count > 0, "writer never managed to append anything");
}

/// Deterministic regression for the zero-byte segment that slipped between two
/// guards and then poisoned itself.
///
/// A segment file shorter than the header is a crash stub: `create` publishes
/// the directory entry before writing the header, and a kill in that window
/// leaves nothing behind. Its `SegmentScan` reports `valid_len: HEADER_LEN` —
/// a header that is not on disk — and every consumer trusts that number and
/// seeks to it. Re-sealing writes the footer at offset 22; resuming the tail
/// appends from 22. Either way the file ends up with a 22-byte hole of zeros,
/// and the *next* open dies in `SegmentHeader::decode` with "bad magic or short
/// header" — the database stops opening.
///
/// The partial-header case (1..21 bytes) was already handled, because
/// `corruption_detected` is `file_len > 0`. Zero bytes escaped between the two
/// conditions: `corruption_detected` is false and the `valid_len < file_len`
/// guard reads `22 < 0`, also false. The crash loop needed ~740 iterations for
/// the kill to land in that window, so it read as flakiness.
///
/// Two stubs on purpose: the lower id is not the last segment and therefore
/// goes through the re-sealing branch, the higher one is the tail.
#[test]
fn um_segmento_de_zero_bytes_nao_impede_o_arranque() {
    let dir = tempfile::tempdir().unwrap();

    let log = Log::open(dir.path(), 64 * 1024, FsyncPolicy::Always).unwrap();
    for i in 0..8u8 {
        log.append(heraclitus_core::Episode::new(
            "crash-agent",
            heraclitus_core::EventKind::Observation,
            vec![i],
        ))
        .unwrap();
    }
    let esperado = log.verify().unwrap().records;
    drop(log);
    assert!(esperado >= 8);

    for id in [9_000u64, 9_001u64] {
        std::fs::write(dir.path().join(format!("{id:020}.hrkl")), b"").unwrap();
    }

    // Duas aberturas: a primeira é a que reparava mal e envenenava o ficheiro,
    // a segunda é a que morria por causa disso.
    for passagem in 0..2 {
        let log = Log::open(dir.path(), 64 * 1024, FsyncPolicy::Always)
            .unwrap_or_else(|e| panic!("abertura falhou na passagem {passagem}: {e}"));
        let report = log
            .verify()
            .unwrap_or_else(|e| panic!("verify falhou na passagem {passagem}: {e}"));
        assert!(
            report.records >= esperado,
            "passagem {passagem}: registos duraveis desapareceram ({esperado} -> {})",
            report.records
        );
        // O log tem de continuar utilizável, não só legível.
        log.append(heraclitus_core::Episode::new(
            "crash-agent",
            heraclitus_core::EventKind::Observation,
            vec![passagem as u8],
        ))
        .unwrap_or_else(|e| panic!("append falhou na passagem {passagem}: {e}"));
        drop(log);
    }

    // Nenhum segmento pode ficar com bytes suficientes para parecer ter
    // cabeçalho sem o ter.
    for entrada in std::fs::read_dir(dir.path()).unwrap().flatten() {
        let p = entrada.path();
        if p.extension().map(|x| x == "hrkl").unwrap_or(false) {
            let bytes = std::fs::read(&p).unwrap();
            assert!(
                bytes.len() >= 22 && &bytes[..4] == b"HRKL",
                "{} ficou com {} bytes sem cabecalho valido",
                p.display(),
                bytes.len()
            );
        }
    }
}

/// Deterministic regression for the `truncate.intent` replay that used to
/// *extend* a crash stub instead of repairing it.
///
/// `set_len` grows a file as readily as it shrinks it. A segment created and
/// then killed before its header reached the disk is a zero-byte file, and the
/// `valid_len` recorded for a segment holding no records is exactly
/// `HEADER_LEN` — so replaying the intent fabricated 22 zero bytes. On the next
/// open that file was long enough to clear the length guard and died in
/// `SegmentHeader::decode` with "bad magic or short header", leaving the log
/// impossible to open.
///
/// It took two passes to surface, which is why it read as randomness: the loop
/// above only tripped over it around iteration ~887 of 1000, and never at the
/// 25 iterations the suite runs locally. Fabricating the state directly makes
/// the proof independent of how long the sleep happened to be.
#[test]
fn a_truncate_intent_never_extends_a_crash_stub() {
    let dir = tempfile::tempdir().unwrap();

    // A real segment with real records, which must survive untouched.
    let log = Log::open(dir.path(), 64 * 1024, FsyncPolicy::Always).unwrap();
    for i in 0..8u8 {
        log.append(heraclitus_core::Episode::new(
            "crash-agent",
            heraclitus_core::EventKind::Observation,
            vec![i],
        ))
        .unwrap();
    }
    let esperado = log.verify().unwrap().records;
    drop(log);
    assert!(esperado >= 8);

    // The stub: exactly what `create` leaves behind when the process dies
    // before the header is written.
    const HEADER_LEN: u64 = 22;
    let stub_id: u64 = 9_999;
    let stub = dir.path().join(format!("{stub_id:020}.hrkl"));
    std::fs::write(&stub, b"").unwrap();

    // The intent that recovery will replay, naming the stub with the
    // `valid_len` of a segment that holds no records.
    let mut intent = Vec::new();
    intent.extend_from_slice(&stub_id.to_le_bytes());
    intent.extend_from_slice(&HEADER_LEN.to_le_bytes());
    std::fs::write(dir.path().join("truncate.intent"), &intent).unwrap();

    // Before the fix this open failed with "bad magic or short header" on the
    // *second* pass; the first pass is what zero-extended the stub.
    for passagem in 0..2 {
        let log = Log::open(dir.path(), 64 * 1024, FsyncPolicy::Always)
            .unwrap_or_else(|e| panic!("abertura falhou na passagem {passagem}: {e}"));
        let report = log
            .verify()
            .unwrap_or_else(|e| panic!("verify falhou na passagem {passagem}: {e}"));
        assert!(
            report.records >= esperado,
            "passagem {passagem}: registos duraveis desapareceram ({esperado} -> {})",
            report.records
        );
        drop(log);
    }

    // Whatever recovery decided to do with the stub, it must never be a file
    // long enough to be mistaken for a header yet without one.
    if stub.exists() {
        let len = std::fs::metadata(&stub).unwrap().len();
        if len >= HEADER_LEN {
            let bytes = std::fs::read(&stub).unwrap();
            assert_eq!(
                &bytes[..4],
                b"HRKL",
                "o toco foi estendido para {len} bytes sem cabecalho valido"
            );
        }
    }
}
