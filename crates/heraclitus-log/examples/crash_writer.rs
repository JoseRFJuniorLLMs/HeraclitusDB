//! Child-process harness for the crash-injection test. Appends forever with
//! fsync=always until killed. Usage: crash_writer <data_dir>

use heraclitus_core::{Episode, EventKind, FsyncPolicy};
use heraclitus_log::Log;

fn main() {
    let dir = std::env::args().nth(1).expect("usage: crash_writer <dir>");
    let log = Log::open(&dir, 64 * 1024, FsyncPolicy::Always).expect("open");
    let mut i: u64 = log.head();
    loop {
        let ep = Episode::new(
            "crash-agent",
            EventKind::Observation,
            format!("payload-{i}-{}", "x".repeat((i % 200) as usize)).into_bytes(),
        );
        log.append(ep).expect("append");
        i += 1;
    }
}
