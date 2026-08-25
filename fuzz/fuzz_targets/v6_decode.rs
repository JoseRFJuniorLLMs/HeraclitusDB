//! Todos os parsers expostos a bytes v6 partilham esta propriedade: input
//! arbitrário devolve `Err`/estado truncado, nunca panic nem alocação absurda.

#![no_main]

use heraclitus_log::v6::block::{decode_block_records, BlockHeaderV1};
use heraclitus_log::v6::block_directory::BlockDirectory;
use heraclitus_log::v6::hrki::Hrki;
use heraclitus_log::v6::{
    decode_manifest, FileHeaderV6, FooterV6, MemorySource, PackedSegmentReader,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = FileHeaderV6::decode(data);
    let _ = FooterV6::decode(data);
    let _ = Hrki::decode(data);
    let _ = decode_manifest(data);
    let _ = heraclitus_log::v6::raw::decode_raw_record(data);

    let count = data
        .get(..4)
        .map(|b| u32::from_le_bytes(b.try_into().unwrap()))
        .unwrap_or(0);
    let region_end = data
        .get(4..12)
        .map(|b| u64::from_le_bytes(b.try_into().unwrap()))
        .unwrap_or(0);
    let _ = BlockDirectory::decode(data, count, region_end);

    let split = data.len().min(64);
    if let Ok(header) = BlockHeaderV1::decode(&data[..split], &data[split..]) {
        let _ = decode_block_records(&header, &data[split..]);
    }

    let _ = PackedSegmentReader::open(MemorySource(data.to_vec()), 64 * 1024 * 1024);
});
