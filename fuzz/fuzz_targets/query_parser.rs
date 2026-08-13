//! M4 gate: fuzz the GQL parser from day one — arbitrary input must never
//! panic, and whatever parses must also survive planning + EXPLAIN.

#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let s = String::from_utf8_lossy(data);
    if let Ok(q) = heraclitus_query::parse(&s) {
        let p = heraclitus_query::plan::plan(&q.stmt);
        let _ = heraclitus_query::plan::render(&p);
    }
});
