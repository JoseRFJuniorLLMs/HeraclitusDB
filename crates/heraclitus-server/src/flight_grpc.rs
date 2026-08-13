//! SPEC-016 — o protocolo Arrow Flight REAL (`arrow.flight.protocol`) via gRPC.
//!
//! Serve `DoGet(ticket)` sobre o log: `"events[?as_of=N]"` → stream de
//! `FlightData` (batches de 1024 codificados pelo encoder oficial). Qualquer
//! cliente Flight (pyarrow.flight, Polars, ADBC) conecta e lê direto.
//!
//! Corre num listener próprio (`flight_addr`): o arrow-flight 58 usa tonic
//! 0.14 e o gRPC principal do server usa 0.12 — as duas versões coexistem,
//! cada uma no seu porto. Métodos além de DoGet/GetSchema respondem
//! `Unimplemented` honestamente (DoPut de ingestão já existe no data plane
//! IPC do analytics; a variante gRPC é acréscimo natural).

use arrow_flight::encode::FlightDataEncoderBuilder;
use arrow_flight::flight_service_server::{FlightService, FlightServiceServer};
use arrow_flight::{
    Action, ActionType, Criteria, Empty, FlightData, FlightDescriptor, FlightInfo,
    HandshakeRequest, HandshakeResponse, PollInfo, PutResult, SchemaResult, Ticket,
};
use futures::stream::BoxStream;
use futures::{StreamExt, TryStreamExt};
use heraclitus_analytics::vectorized::{episodes_to_batches_sized, BATCH_ROWS};
use heraclitus_log::Log;
use std::sync::Arc;
use tonic_flight::{Request, Response, Status, Streaming};

pub struct HeraclitusFlight {
    log: Arc<Log>,
}

impl HeraclitusFlight {
    pub fn new(log: Arc<Log>) -> Self {
        Self { log }
    }

    fn parse_ticket(t: &Ticket) -> Result<Option<u64>, Status> {
        let s = std::str::from_utf8(&t.ticket)
            .map_err(|_| Status::invalid_argument("ticket não-UTF8"))?;
        if s == "events" {
            return Ok(None);
        }
        if let Some(rest) = s.strip_prefix("events?as_of=") {
            return rest
                .parse::<u64>()
                .map(Some)
                .map_err(|_| Status::invalid_argument(format!("as_of inválido: {rest}")));
        }
        Err(Status::not_found(format!("ticket desconhecido: {s}")))
    }
}

type S<T> = BoxStream<'static, Result<T, Status>>;

#[tonic_flight::async_trait]
impl FlightService for HeraclitusFlight {
    type HandshakeStream = S<HandshakeResponse>;
    type ListFlightsStream = S<FlightInfo>;
    type DoGetStream = S<FlightData>;
    type DoPutStream = S<PutResult>;
    type DoActionStream = S<arrow_flight::Result>;
    type ListActionsStream = S<ActionType>;
    type DoExchangeStream = S<FlightData>;

    async fn do_get(&self, req: Request<Ticket>) -> Result<Response<Self::DoGetStream>, Status> {
        let as_of = Self::parse_ticket(req.get_ref())?;
        let log = self.log.clone();
        // Materialização fora do executor async (o scan lê disco).
        let batches = tokio::task::spawn_blocking(move || {
            let to = as_of.unwrap_or(u64::MAX).min(log.head());
            let events = log.scan(0, to).map_err(|e| e.to_string())?;
            // Streaming Flight: lotes fixos de BATCH_ROWS (contrato do fio).
            episodes_to_batches_sized(&events, BATCH_ROWS).map_err(|e| e.to_string())
        })
        .await
        .map_err(|e| Status::internal(format!("join: {e}")))?
        .map_err(Status::internal)?;

        // O encoder OFICIAL do protocolo: RecordBatches → FlightData frames.
        let stream = FlightDataEncoderBuilder::new()
            .build(futures::stream::iter(batches.into_iter().map(Ok)))
            .map_err(|e| Status::internal(e.to_string()))
            .boxed();
        Ok(Response::new(stream))
    }

    async fn get_schema(
        &self,
        _req: Request<FlightDescriptor>,
    ) -> Result<Response<SchemaResult>, Status> {
        // Schema da tabela `events` (o mesmo dos batches do DoGet).
        let schema = heraclitus_analytics::vectorized::batch_schema();
        let opts = Default::default();
        let ipc = arrow_flight::SchemaAsIpc::new(&schema, &opts);
        let res: SchemaResult = ipc
            .try_into()
            .map_err(|e| Status::internal(format!("schema ipc: {e}")))?;
        Ok(Response::new(res))
    }

    // ── restantes métodos: honestamente Unimplemented ──────────────────────
    async fn handshake(
        &self,
        _req: Request<Streaming<HandshakeRequest>>,
    ) -> Result<Response<Self::HandshakeStream>, Status> {
        Err(Status::unimplemented("handshake"))
    }
    async fn list_flights(
        &self,
        _req: Request<Criteria>,
    ) -> Result<Response<Self::ListFlightsStream>, Status> {
        Err(Status::unimplemented("list_flights"))
    }
    async fn get_flight_info(
        &self,
        _req: Request<FlightDescriptor>,
    ) -> Result<Response<FlightInfo>, Status> {
        Err(Status::unimplemented("get_flight_info"))
    }
    async fn poll_flight_info(
        &self,
        _req: Request<FlightDescriptor>,
    ) -> Result<Response<PollInfo>, Status> {
        Err(Status::unimplemented("poll_flight_info"))
    }
    async fn do_put(
        &self,
        _req: Request<Streaming<FlightData>>,
    ) -> Result<Response<Self::DoPutStream>, Status> {
        Err(Status::unimplemented("do_put (usar o data plane IPC do analytics)"))
    }
    async fn do_action(
        &self,
        _req: Request<Action>,
    ) -> Result<Response<Self::DoActionStream>, Status> {
        Err(Status::unimplemented("do_action"))
    }
    async fn list_actions(
        &self,
        _req: Request<Empty>,
    ) -> Result<Response<Self::ListActionsStream>, Status> {
        Err(Status::unimplemented("list_actions"))
    }
    async fn do_exchange(
        &self,
        _req: Request<Streaming<FlightData>>,
    ) -> Result<Response<Self::DoExchangeStream>, Status> {
        Err(Status::unimplemented("do_exchange"))
    }
}

/// Arranca o servidor Flight num listener próprio. Devolve a porta real.
pub async fn serve_flight(
    log: Arc<Log>,
    addr: &str,
) -> Result<(std::net::SocketAddr, tokio::task::JoinHandle<()>), String> {
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .map_err(|e| format!("flight bind {addr}: {e}"))?;
    let local = listener.local_addr().map_err(|e| e.to_string())?;
    let svc = FlightServiceServer::new(HeraclitusFlight::new(log));
    let handle = tokio::spawn(async move {
        let incoming = tonic_flight::transport::server::TcpIncoming::from(listener);
        let _ = tonic_flight::transport::Server::builder()
            .add_service(svc)
            .serve_with_incoming(incoming)
            .await;
    });
    Ok((local, handle))
}
