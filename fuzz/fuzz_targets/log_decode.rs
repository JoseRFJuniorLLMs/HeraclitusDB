//! Fuzz the record decoder: arbitrary bytes must never panic, only return
//! Record / Footer / Torn.

#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Exercise both the legacy (payload-only CRC) and current (header-covering
    // CRC) decode rules; neither may panic on arbitrary input.
    let _ = heraclitus_log::format::decode_record(1, data);
    let _ = heraclitus_log::format::decode_record(2, data);
    let _ = heraclitus_log::format::SegmentHeader::decode(data);
    let _ = heraclitus_log::format::SegmentFooter::decode(data);
});
