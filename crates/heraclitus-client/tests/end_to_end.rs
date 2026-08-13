//! M6 end-to-end: real server on an ephemeral port, real client.

use heraclitus_client::{AppendOptions, Client};
use heraclitus_core::HeraclitusConfig;

#[tokio::test]
async fn grpc_roundtrip() {
    let dir = tempfile::tempdir().unwrap();
    // Pick free ports by binding momentarily.
    let grpc_port = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    };
    let rest_port = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    };
    let config = HeraclitusConfig {
        data_dir: dir.path().to_path_buf(),
        grpc_addr: format!("127.0.0.1:{grpc_port}"),
        rest_addr: format!("127.0.0.1:{rest_port}"),
        ..Default::default()
    };

    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
    let server = tokio::spawn(heraclitus_server::serve(config, async {
        let _ = stop_rx.await;
    }));

    // Connect with retry while the server boots.
    let addr = format!("http://127.0.0.1:{grpc_port}");
    let mut client = loop {
        match Client::connect(addr.clone()).await {
            Ok(c) => break c,
            Err(_) => tokio::time::sleep(std::time::Duration::from_millis(50)).await,
        }
    };

    // Append three episodes, one with an embedding.
    for i in 0..3 {
        let lsn = client
            .append(
                "e2e-agent",
                format!("the river flows {i}").as_bytes(),
                AppendOptions {
                    hyp: if i == 0 { vec![0.3, 0.1] } else { vec![] },
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert_eq!(lsn, i);
    }

    // Read-your-own-writes through the network: query immediately.
    let rows = client
        .query("MATCH (n) WHERE n.agent_id = \"e2e-agent\" RETURN n")
        .await
        .unwrap();
    assert_eq!(rows.as_array().unwrap().len(), 3);

    // EXPLAIN over the wire.
    let plan = client
        .query("EXPLAIN MATCH (n) RETURN n LIMIT 1")
        .await
        .unwrap();
    assert!(plan.as_str().unwrap().contains("ScanFilter"));

    // Two-stage recall.
    let hits = client.recall("river", 2).await.unwrap();
    assert!(!hits.as_array().unwrap().is_empty());

    // NEAREST hits the HNSW + memtable merge path.
    let nn = client.query("NEAREST ([0.3, 0.1], 1)").await.unwrap();
    assert_eq!(nn.as_array().unwrap().len(), 1);

    // Snapshot + admin stats/verify.
    assert_eq!(client.snapshot().await.unwrap(), 3);
    let (ok, msg) = client.admin("stats", "").await.unwrap();
    assert!(ok, "{msg}");
    let (ok, msg) = client.admin("verify", "").await.unwrap();
    assert!(ok, "{msg}");

    let _ = stop_tx.send(());
    let _ = server.await;
}
