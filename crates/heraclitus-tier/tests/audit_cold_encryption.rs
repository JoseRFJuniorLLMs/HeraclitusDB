use heraclitus_core::{Episode, EventKind, FsyncPolicy, ProductPoint};
use heraclitus_crypto::KeyStore;
use heraclitus_log::{
    v6::{PackingProfile, V6Log},
    Log,
};
use heraclitus_tier::{ColdTier, ColdTierV6};

fn event() -> Episode {
    let mut ep = Episode::new("ana", EventKind::Observation, b"private content".to_vec());
    ep.attrs.insert("private_name".into(), "Ana".into());
    ep.embedding = Some(ProductPoint {
        hyp: vec![0.1, 0.2],
        sph: vec![],
        euc: vec![],
    });
    ep
}

fn assert_plain(ep: &Episode) {
    assert_eq!(ep.content, b"private content");
    assert_eq!(
        ep.attrs.get("private_name").map(String::as_str),
        Some("Ana")
    );
    assert_eq!(ep.embedding.as_ref().unwrap().hyp, [0.1, 0.2]);
}

#[tokio::test]
async fn encrypted_v1_recall_decrypts_fields_and_obeys_shred() {
    let dir = tempfile::tempdir().unwrap();
    let keys = KeyStore::open(dir.path().join("keys")).unwrap();
    let log = Log::open_with_keystore(
        dir.path().join("log"),
        1024,
        FsyncPolicy::Always,
        Some(keys.clone()),
    )
    .unwrap();
    for _ in 0..12 {
        log.append(event()).unwrap();
    }
    let segment = log.sealed_segments().first().unwrap().id;
    let bucket = dir.path().join("cold");
    let tier = ColdTier::open_local(&bucket)
        .unwrap()
        .with_keystore(Some(keys.clone()));
    let receipt = tier.demote_prepared(&log, segment).await.unwrap();
    let rows = tier.fetch_cold(&receipt).await.unwrap();
    assert!(!rows.is_empty());
    for (_, ep) in &rows {
        assert_plain(ep);
    }
    assert!(ColdTier::open_local(&bucket)
        .unwrap()
        .fetch_cold(&receipt)
        .await
        .is_err());
    keys.shred("ana").unwrap();
    for (_, ep) in tier.fetch_cold(&receipt).await.unwrap() {
        assert_eq!(ep.content, heraclitus_crypto::SHREDDED);
        assert!(ep.embedding.is_none());
        assert!(!ep.attrs.contains_key("private_name"));
    }
}

#[tokio::test]
async fn encrypted_v6_recall_checks_receipt_and_decrypts_the_verified_image() {
    let dir = tempfile::tempdir().unwrap();
    let keys = KeyStore::open(dir.path().join("keys")).unwrap();
    let log = V6Log::open_with_keystore(
        dir.path().join("log"),
        1 << 20,
        FsyncPolicy::Always,
        Some(keys.clone()),
    )
    .unwrap();
    for _ in 0..5 {
        log.append(event()).unwrap();
    }
    log.seal_active().unwrap();
    log.pack_pending(PackingProfile::Balanced).unwrap();
    let source = log.active_packed_generation(0).unwrap().unwrap();
    let tier = ColdTierV6::open_local(dir.path().join("cold"))
        .unwrap()
        .with_keystore(Some(keys.clone()));
    let receipt = tier
        .publish_generation(&source.path, source.generation, source.source_generation, 1)
        .await
        .unwrap();
    let (rows, stats) = tier.recall_receipt(&receipt).await.unwrap();
    assert_eq!(stats.requests, 1);
    assert_eq!(rows.len(), 5);
    for (_, ep) in &rows {
        assert_plain(ep);
    }
    for field in ["count", "size", "range", "digest", "namespace"] {
        let mut bad = receipt.clone();
        match field {
            "count" => bad.record_count += 1,
            "size" => bad.physical_size += 1,
            "range" => bad.first_lsn += 1,
            "digest" => bad.physical_digest = "00".repeat(32),
            _ => bad.storage_namespace_id = "00".repeat(16),
        }
        assert!(tier.recall_receipt(&bad).await.is_err(), "{field}");
    }
    keys.shred("ana").unwrap();
    for (_, ep) in tier.recall_receipt(&receipt).await.unwrap().0 {
        assert_eq!(ep.content, heraclitus_crypto::SHREDDED);
        assert!(ep.embedding.is_none());
    }
}
