//! SPEC-016 — o protocolo Arrow Flight REAL, testado ponta-a-ponta:
//! servidor gRPC in-process + FlightClient oficial a fazer DoGet.
#![cfg(feature = "analytics")]

use arrow_flight::{FlightClient, Ticket};
use futures::TryStreamExt;
use heraclitus_core::{Episode, EventKind, FsyncPolicy};
use heraclitus_log::Log;
use heraclitus_server::flight_grpc::serve_flight;
use std::sync::Arc;

#[tokio::test]
async fn flight_client_does_doget_over_real_grpc() {
    // Log com 2500 episódios.
    let dir = tempfile::tempdir().unwrap();
    let log = Arc::new(Log::open(dir.path(), 1 << 20, FsyncPolicy::Always).unwrap());
    for i in 0..2500u32 {
        log.append(Episode::new(
            if i % 2 == 0 { "alice" } else { "bob" },
            EventKind::Observation,
            format!("e{i}").into_bytes(),
        ))
        .unwrap();
    }

    // Servidor Flight em porta efémera.
    let (addr, _handle) = serve_flight(log, "127.0.0.1:0").await.unwrap();

    // Cliente Flight OFICIAL (arrow-flight) sobre um canal tonic real.
    let channel = tonic_flight::transport::Endpoint::from_shared(format!("http://{addr}"))
        .unwrap()
        .connect()
        .await
        .expect("conectar ao servidor Flight");
    let mut client = FlightClient::new(channel);

    // DoGet("events") → stream de RecordBatches descodificado pelo cliente.
    let stream = client
        .do_get(Ticket::new("events"))
        .await
        .expect("do_get aceito");
    let batches: Vec<_> = stream.try_collect().await.expect("stream decodifica");
    let rows: usize = batches.iter().map(|b| b.num_rows()).sum();
    assert_eq!(rows, 2500, "todas as linhas atravessam o protocolo");
    assert!(batches.iter().all(|b| b.num_rows() <= 1024), "lotes de ≤1024");
    assert_eq!(batches[0].schema().field(1).name(), "agent_id");

    // AS OF respeitado pelo protocolo.
    let stream = client
        .do_get(Ticket::new("events?as_of=100"))
        .await
        .unwrap();
    let batches: Vec<_> = stream.try_collect().await.unwrap();
    let rows: usize = batches.iter().map(|b| b.num_rows()).sum();
    assert_eq!(rows, 100);

    // Ticket desconhecido → erro gRPC limpo, não crash.
    assert!(client.do_get(Ticket::new("hack")).await.is_err());
}
