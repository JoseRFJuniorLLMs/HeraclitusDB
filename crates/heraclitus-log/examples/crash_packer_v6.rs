//! Helper subprocess for the HRKL v6 packing crash-injection suite.

use std::path::PathBuf;

use heraclitus_log::v6::{
    pack_and_commit_with_observer, ManifestStore, PackOptions, PackingStage,
};

fn main() {
    let mut args = std::env::args_os().skip(1);
    let root = PathBuf::from(args.next().expect("storage root"));
    let requested = args
        .next()
        .and_then(|value| value.into_string().ok())
        .and_then(|value| PackingStage::parse(&value))
        .expect("valid packing stage");
    let store = ManifestStore::open_read_only(root.join("manifests")).expect("manifest store");
    let mut loaded = store.load().expect("load manifest").expect("manifest").manifest;
    let segment = loaded
        .segments_v2
        .first()
        .cloned()
        .expect("sealed segment");
    let source = segment
        .generations
        .iter()
        .find(|generation| generation.layout == heraclitus_core::runtime::PhysicalLayout::Raw)
        .cloned()
        .expect("RAW source");
    let target_generation = segment.next_generation_number();
    let source_path = root.join(&source.location);
    let target_path = root.join("segments").join(format!(
        "{:020}.g{:04}.packed.hrkl",
        segment.segment_id, target_generation
    ));
    let mut observer = |stage: PackingStage| {
        if stage == requested {
            // `exit`, não panic: nenhum Drop/cleanup de Rust corre depois da
            // fronteira, aproximando a morte abrupta do processo sem abrir o
            // crash reporter do Windows no CI.
            std::process::exit(86);
        }
        Ok(())
    };
    pack_and_commit_with_observer(
        &store,
        &mut loaded,
        &source_path,
        &target_path,
        PackOptions::default(),
        source.generation,
        target_generation,
        1,
        &heraclitus_log::canonical_hash_storage_payload_v6,
        &mut observer,
    )
    .expect("packing transaction");
}
