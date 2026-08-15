use heraclitus_core::{Episode, EventKind, FsyncPolicy, ProductPoint};
use heraclitus_crypto::{KeyStore, SHREDDED};
use heraclitus_log::Log;

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && haystack.windows(needle.len()).any(|w| w == needle)
}

#[test]
fn encryption_covers_content_attrs_embedding_and_shred_keeps_replay_alive() {
    let dir = tempfile::tempdir().unwrap();
    let log_dir = dir.path().join("log");
    let keys_dir = dir.path().join("keys");
    let keys = KeyStore::open(&keys_dir).unwrap();
    let log = Log::open_with_keystore(&log_dir, 1 << 20, FsyncPolicy::Always, Some(keys.clone()))
        .unwrap();

    let mut episode = Episode::new(
        "titular:hmac-sha256:abc",
        EventKind::Custom("OperationalFact".into()),
        b"Carlos autenticou no servidor pessoal".to_vec(),
    );
    episode
        .attrs
        .insert("actor_name".into(), "Carlos Silva".into());
    episode
        .attrs
        .insert("source_ip".into(), "203.0.113.45".into());
    episode.attrs.insert(
        "__heraclitus_idempotency_key".into(),
        "0123456789abcdef".into(),
    );
    episode.attrs.insert(
        "__heraclitus_idempotency_hash".into(),
        "abcdef0123456789".into(),
    );
    episode.embedding = Some(ProductPoint {
        hyp: vec![0.25, 0.5],
        sph: vec![],
        euc: vec![42.0],
    });

    let lsn = log.append(episode).unwrap();
    let (_, clear) = log.read(lsn).unwrap().unwrap();
    assert_eq!(clear.attrs["actor_name"], "Carlos Silva");
    assert_eq!(clear.content, b"Carlos autenticou no servidor pessoal");
    assert!(clear.embedding.is_some());

    for entry in std::fs::read_dir(&log_dir).unwrap().flatten() {
        if !entry.path().is_file() {
            continue;
        }
        let raw = std::fs::read(entry.path()).unwrap();
        assert!(!contains(&raw, b"Carlos Silva"), "PII vazou no WAL");
        assert!(!contains(&raw, b"203.0.113.45"), "IP vazou no WAL");
        assert!(
            !contains(&raw, b"Carlos autenticou no servidor pessoal"),
            "content vazou no WAL"
        );
    }

    assert!(keys.shred("titular:hmac-sha256:abc").unwrap());
    let (_, shredded) = log.read(lsn).unwrap().unwrap();
    assert_eq!(shredded.content, SHREDDED);
    assert_eq!(
        shredded
            .attrs
            .get("__heraclitus_shredded")
            .map(String::as_str),
        Some("true")
    );
    assert!(!shredded.attrs.contains_key("actor_name"));
    assert!(!shredded.attrs.contains_key("source_ip"));
    assert!(shredded.embedding.is_none());
    assert!(shredded.attrs.contains_key("__heraclitus_idempotency_key"));

    drop(log);
    let reopened = Log::open_with_keystore(
        &log_dir,
        1 << 20,
        FsyncPolicy::Always,
        Some(KeyStore::open(&keys_dir).unwrap()),
    )
    .unwrap();
    let (_, after_restart) = reopened.read(lsn).unwrap().unwrap();
    assert_eq!(after_restart.content, SHREDDED);
    assert_eq!(
        after_restart
            .attrs
            .get("__heraclitus_shredded")
            .map(String::as_str),
        Some("true")
    );
}
