//! M6 acceptance gate (turmoil): a follower partitioned from the leader
//! converges to every leader-acked event after the partition heals —
//! zero acked writes lost.
//!
//! Scope honesty (RFC-003): this proves catch-up replication under
//! partition, the v0 guarantee. Leader-election failover is the openraft
//! upgrade and is not claimed here.

use heraclitus_core::{Episode, EventKind, FsyncPolicy, StorageFormat};
use heraclitus_log::AnyLog;
use heraclitus_raft::logs_equivalent;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const TOTAL: u64 = 120;
const BINCODE_CFG: bincode::config::Configuration = bincode::config::standard();

#[test]
fn partition_heals_with_zero_acked_loss() {
    let leader_dir = tempfile::tempdir().unwrap();
    let follower_dir = tempfile::tempdir().unwrap();
    let leader_log = Arc::new(
        AnyLog::open(
            StorageFormat::V6,
            leader_dir.path(),
            1 << 20,
            FsyncPolicy::Always,
        )
        .unwrap(),
    );
    let follower_log = Arc::new(
        AnyLog::open(
            StorageFormat::V6,
            follower_dir.path(),
            1 << 20,
            FsyncPolicy::Always,
        )
        .unwrap(),
    );

    let mut sim = turmoil::Builder::new()
        .simulation_duration(std::time::Duration::from_secs(300))
        .build();

    // ── Leader host: keeps appending (acking) and serves fetch requests ──
    let llog = leader_log.clone();
    sim.host("leader", move || {
        let log = llog.clone();
        async move {
            // Writer: one acked append every 10ms until TOTAL.
            let wlog = log.clone();
            tokio::spawn(async move {
                for i in 0..TOTAL {
                    wlog.append(Episode::new(
                        "leader",
                        EventKind::Observation,
                        format!("acked-{i}").into_bytes(),
                    ))
                    .unwrap();
                    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                }
            });

            // Fetch server: req = from_lsn u64; resp = count u32 + records.
            let listener = turmoil::net::TcpListener::bind("0.0.0.0:9000").await?;
            loop {
                let (mut sock, _) = listener.accept().await?;
                let log = log.clone();
                tokio::spawn(async move {
                    let mut buf = [0u8; 8];
                    if sock.read_exact(&mut buf).await.is_err() {
                        return;
                    }
                    let from = u64::from_le_bytes(buf);
                    let batch = log.scan(from, from + 64).unwrap_or_default();
                    let mut out = (batch.len() as u32).to_le_bytes().to_vec();
                    for (lsn, ep) in &batch {
                        let payload = bincode::serde::encode_to_vec(ep, BINCODE_CFG).unwrap();
                        out.extend_from_slice(&lsn.to_le_bytes());
                        out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
                        out.extend_from_slice(&payload);
                    }
                    let _ = sock.write_all(&out).await;
                });
            }
        }
    });

    // ── Follower client: pull loop, resilient to partition errors ──
    let flog = follower_log.clone();
    sim.client("follower", async move {
        loop {
            let from = flog.head();
            if from >= TOTAL {
                return Ok(());
            }
            // During a partition turmoil drops packets silently: without a
            // timeout the connect hangs forever. The timeout IS the lesson.
            match tokio::time::timeout(
                std::time::Duration::from_millis(500),
                fetch_once(&flog, from),
            )
            .await
            {
                Ok(Ok(_)) => {}
                _ => {
                    // Partitioned or timed out — back off and retry.
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                }
            }
        }
    });

    // Let replication start…
    for _ in 0..30 {
        sim.step().unwrap();
    }
    // …then cut the network while the leader keeps acking writes…
    sim.partition("leader", "follower");
    for _ in 0..300 {
        sim.step().unwrap();
    }
    // …and heal. The follower must converge to ALL acked events.
    sim.repair("leader", "follower");
    sim.run().unwrap();

    assert_eq!(leader_log.head(), TOTAL, "leader acked all writes");
    assert_eq!(follower_log.head(), TOTAL, "follower converged after heal");
    assert!(
        logs_equivalent(&leader_log, &follower_log).unwrap(),
        "zero acked events lost: logs must be equivalent"
    );
}

async fn fetch_once(flog: &AnyLog, from: u64) -> turmoil::Result {
    let mut sock = turmoil::net::TcpStream::connect("leader:9000").await?;
    sock.write_all(&from.to_le_bytes()).await?;
    let mut cnt = [0u8; 4];
    sock.read_exact(&mut cnt).await?;
    let count = u32::from_le_bytes(cnt);
    for _ in 0..count {
        let mut l8 = [0u8; 8];
        sock.read_exact(&mut l8).await?;
        let lsn = u64::from_le_bytes(l8);
        let mut l4 = [0u8; 4];
        sock.read_exact(&mut l4).await?;
        let len = u32::from_le_bytes(l4) as usize;
        let mut payload = vec![0u8; len];
        sock.read_exact(&mut payload).await?;
        let (ep, _): (Episode, usize) = bincode::serde::decode_from_slice(&payload, BINCODE_CFG)
            .map_err(std::io::Error::other)?;
        if lsn >= flog.head() {
            flog.append_replicated(lsn, ep)
                .map_err(std::io::Error::other)?;
        }
    }
    Ok(())
}
