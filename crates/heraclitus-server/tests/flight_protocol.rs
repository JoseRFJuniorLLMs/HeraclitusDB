//! SPEC-016 — o protocolo Arrow Flight REAL, testado ponta-a-ponta:
//! servidor gRPC in-process + FlightClient oficial a fazer DoGet.
#![cfg(feature = "analytics")]

use arrow_flight::{FlightClient, Ticket};
use futures::TryStreamExt;
use heraclitus_core::{Episode, EventKind, FsyncPolicy};
use heraclitus_log::Log;
use heraclitus_server::flight_grpc::{serve_flight, FlightGuard};
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
    let (addr, _handle) = serve_flight(log, "127.0.0.1:0", aberto()).await.unwrap();

    // Cliente Flight OFICIAL (arrow-flight) sobre um canal tonic real.
    let channel = tonic::transport::Endpoint::from_shared(format!("http://{addr}"))
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
    assert!(
        batches.iter().all(|b| b.num_rows() <= 1024),
        "lotes de ≤1024"
    );
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

#[tokio::test]
async fn unauthenticated_flight_cannot_bind_public_interface() {
    let dir = tempfile::tempdir().unwrap();
    let log = Arc::new(Log::open(dir.path(), 1 << 20, FsyncPolicy::Always).unwrap());
    assert!(serve_flight(log, "0.0.0.0:0", aberto())
        .await
        .unwrap_err()
        .contains("loopback"));
}

#[tokio::test]
async fn flight_exports_large_content_metadata_without_json_expansion() {
    let dir = tempfile::tempdir().unwrap();
    let log = Arc::new(Log::open(dir.path(), 16 << 20, FsyncPolicy::Always).unwrap());
    log.append(Episode::new(
        "large",
        EventKind::Observation,
        vec![255; 6 << 20],
    ))
    .unwrap();
    let (addr, handle) = serve_flight(log, "127.0.0.1:0", aberto()).await.unwrap();
    let channel = tonic::transport::Endpoint::from_shared(format!("http://{addr}"))
        .unwrap()
        .connect()
        .await
        .unwrap();
    let mut client = FlightClient::new(channel);
    let batches: Vec<_> = client
        .do_get(Ticket::new("events"))
        .await
        .unwrap()
        .try_collect()
        .await
        .unwrap();
    assert_eq!(
        batches.iter().map(|batch| batch.num_rows()).sum::<usize>(),
        1
    );
    let lengths = batches[0]
        .column(4)
        .as_any()
        .downcast_ref::<heraclitus_analytics::datafusion::arrow::array::UInt64Array>()
        .unwrap();
    assert_eq!(lengths.value(0), 6 << 20);
    handle.abort();
}

/// Sem credenciais configuradas: o mesmo comportamento aberto do gRPC
/// (loopback-only).
fn aberto() -> FlightGuard {
    FlightGuard::from_config(&heraclitus_core::HeraclitusConfig::default()).unwrap()
}

fn com_credencial(token: &str, papel: heraclitus_core::AccessRole) -> FlightGuard {
    let cfg = heraclitus_core::HeraclitusConfig {
        access_credentials: vec![heraclitus_core::AccessCredential {
            principal: "leitora".into(),
            token_blake3: blake3::hash(token.as_bytes()).to_hex().to_string(),
            roles: vec![papel],
        }],
        ..heraclitus_core::HeraclitusConfig::default()
    };
    FlightGuard::from_config(&cfg).unwrap()
}

async fn cliente(addr: std::net::SocketAddr, token: Option<&str>) -> FlightClient {
    let channel = tonic::transport::Endpoint::from_shared(format!("http://{addr}"))
        .unwrap()
        .connect()
        .await
        .unwrap();
    let mut client = FlightClient::new(channel);
    if let Some(token) = token {
        client
            .add_header("authorization", &format!("Bearer {token}"))
            .unwrap();
    }
    client
}

/// Conferência de 2026-10-02 (F10 residual): com `access_credentials`
/// configuradas o DoGet entregava o log inteiro sem token — o único caminho
/// não autenticado até aos dados. Agora usa o MESMO Bearer do gRPC.
#[tokio::test]
async fn flight_exige_o_bearer_do_grpc_quando_ha_credenciais() {
    let dir = tempfile::tempdir().unwrap();
    let log = Arc::new(Log::open(dir.path(), 1 << 20, FsyncPolicy::Always).unwrap());
    for i in 0..10u32 {
        log.append(Episode::new(
            "alice",
            EventKind::Observation,
            format!("e{i}").into_bytes(),
        ))
        .unwrap();
    }
    let token = "token-de-teste-com-pelo-menos-32-bytes!!";
    let auditados = Arc::new(std::sync::Mutex::new(Vec::<(String, String, bool)>::new()));
    let registo = auditados.clone();
    let guard = com_credencial(token, heraclitus_core::AccessRole::Reader).with_audit(Arc::new(
        move |principal: &str, ticket: &str, ok: bool| {
            registo
                .lock()
                .unwrap()
                .push((principal.to_owned(), ticket.to_owned(), ok));
        },
    ));
    let (addr, handle) = serve_flight(log, "127.0.0.1:0", guard).await.unwrap();

    // Sem token: recusado, sem dados.
    let mut anonimo = cliente(addr, None).await;
    let erro = anonimo.do_get(Ticket::new("events")).await.unwrap_err();
    assert!(
        format!("{erro:?}").contains("Unauthenticated"),
        "DoGet sem token tem de ser Unauthenticated: {erro:?}"
    );
    // Token errado: recusado.
    let mut intruso = cliente(addr, Some("token-errado-mas-igualmente-comprido!!")).await;
    assert!(intruso.do_get(Ticket::new("events")).await.is_err());
    assert!(auditados.lock().unwrap().is_empty(), "recusa antes de ler");

    // Token certo: lê, e fica rasto com a identidade autenticada.
    let mut leitora = cliente(addr, Some(token)).await;
    let batches: Vec<_> = leitora
        .do_get(Ticket::new("events"))
        .await
        .unwrap()
        .try_collect()
        .await
        .unwrap();
    assert_eq!(batches.iter().map(|b| b.num_rows()).sum::<usize>(), 10);
    let registo = auditados.lock().unwrap().clone();
    assert_eq!(
        registo,
        vec![("leitora".to_owned(), "FLIGHT DoGet events".to_owned(), true)]
    );
    handle.abort();
}

/// O loopback é verificado ANTES do bind: um nome que resolve para fora do
/// loopback nunca chega a abrir porta.
#[tokio::test]
async fn flight_recusa_endereco_publico_antes_do_bind() {
    let dir = tempfile::tempdir().unwrap();
    let log = Arc::new(Log::open(dir.path(), 1 << 20, FsyncPolicy::Always).unwrap());
    let erro = serve_flight(log, "0.0.0.0:0", aberto()).await.unwrap_err();
    assert!(erro.contains("loopback"), "{erro}");
    assert!(
        !erro.contains("bind"),
        "a recusa tem de acontecer antes do bind: {erro}"
    );
}

/// Um evento cujo conteúdo excede 16 MiB não pode partir a exportação: a
/// linha Arrow só leva metadados (content_len), não o conteúdo.
#[tokio::test]
async fn flight_nao_aborta_com_evento_maior_que_16_mib() {
    let dir = tempfile::tempdir().unwrap();
    let log = Arc::new(Log::open(dir.path(), 64 << 20, FsyncPolicy::Always).unwrap());
    log.append(Episode::new("a", EventKind::Observation, b"antes".to_vec()))
        .unwrap();
    log.append(Episode::new(
        "grande",
        EventKind::Observation,
        vec![7; 20 << 20],
    ))
    .unwrap();
    log.append(Episode::new(
        "a",
        EventKind::Observation,
        b"depois".to_vec(),
    ))
    .unwrap();
    let (addr, handle) = serve_flight(log, "127.0.0.1:0", aberto()).await.unwrap();
    let mut client = cliente(addr, None).await;
    let batches: Vec<_> = client
        .do_get(Ticket::new("events"))
        .await
        .unwrap()
        .try_collect()
        .await
        .unwrap();
    assert_eq!(batches.iter().map(|b| b.num_rows()).sum::<usize>(), 3);
    handle.abort();
}
