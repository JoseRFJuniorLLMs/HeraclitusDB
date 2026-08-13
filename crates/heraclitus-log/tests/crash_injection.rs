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

#[test]
fn survives_repeated_mid_append_kills() {
    let iters: u64 = std::env::var("CRASH_ITERS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(25);

    // Build the example binary once.
    let status = Command::new(env!("CARGO"))
        .args(["build", "--example", "crash_writer", "-p", "heraclitus-log"])
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
