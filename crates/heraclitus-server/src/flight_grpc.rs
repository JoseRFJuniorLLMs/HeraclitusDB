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
use heraclitus_log::EpisodeLog;
use std::sync::Arc;
use tonic::{Request, Response, Status, Streaming};

pub struct HeraclitusFlight {
    log: Arc<dyn EpisodeLog>,
}

impl HeraclitusFlight {
    pub fn new<L: EpisodeLog + 'static>(log: Arc<L>) -> Self {
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

#[tonic::async_trait]
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
        static ADMISSION: std::sync::OnceLock<Arc<tokio::sync::Semaphore>> =
            std::sync::OnceLock::new();
        let permit = ADMISSION
            .get_or_init(|| Arc::new(tokio::sync::Semaphore::new(2)))
            .clone()
            .try_acquire_owned()
            .map_err(|_| Status::resource_exhausted("Flight busy"))?;
        let (tx, rx) = tokio::sync::mpsc::channel(2);
        tokio::task::spawn_blocking(move || {
            let produce = || -> Result<(), arrow_flight::error::FlightError> {
                let to = as_of.unwrap_or(u64::MAX).min(log.head());
                let mut cursor = 0;
                let mut pending = Vec::new();
                let mut bytes = 0;
                while cursor < to && !tx.is_closed() {
                    let rows = log.scan_capped(cursor, to, 16).map_err(|e| {
                        arrow_flight::error::FlightError::ExternalError(Box::new(e))
                    })?;
                    if rows.is_empty() {
                        break;
                    }
                    for row in rows {
                        cursor = row.0.saturating_add(1);
                        let size = row.1.resident_bytes();
                        if size > 16 << 20 {
                            return Err(arrow_flight::error::FlightError::ProtocolError(
                                "Flight row exceeds 16MiB".into(),
                            ));
                        }
                        if !pending.is_empty()
                            && (pending.len() == BATCH_ROWS || bytes + size > 16 << 20)
                        {
                            for batch in
                                episodes_to_batches_sized(&pending, BATCH_ROWS).map_err(|e| {
                                    arrow_flight::error::FlightError::ExternalError(Box::new(e))
                                })?
                            {
                                if tx.blocking_send(Ok(batch)).is_err() {
                                    return Ok(());
                                }
                            }
                            pending.clear();
                            bytes = 0;
                        }
                        bytes += size;
                        pending.push(row);
                    }
                }
                if !pending.is_empty() && !tx.is_closed() {
                    for batch in episodes_to_batches_sized(&pending, BATCH_ROWS)
                        .map_err(|e| arrow_flight::error::FlightError::ExternalError(Box::new(e)))?
                    {
                        if tx.blocking_send(Ok(batch)).is_err() {
                            break;
                        }
                    }
                }
                Ok(())
            };
            if let Err(error) = produce() {
                let _ = tx.blocking_send(Err(error));
            }
        });
        // Admission covers the stream lifetime, including buffered batches.
        // Dropping a cancelled stream releases the permit and closes the queue.
        let batches = futures::stream::unfold((rx, permit), |(mut rx, permit)| async move {
            rx.recv().await.map(|batch| (batch, (rx, permit)))
        });
        let stream = FlightDataEncoderBuilder::new()
            .with_schema(heraclitus_analytics::vectorized::batch_schema())
            .build(batches)
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
        Err(Status::unimplemented(
            "do_put (usar o data plane IPC do analytics)",
        ))
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
pub async fn serve_flight<L: EpisodeLog + 'static>(
    log: Arc<L>,
    addr: &str,
) -> Result<(std::net::SocketAddr, tokio::task::JoinHandle<()>), String> {
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .map_err(|e| format!("flight bind {addr}: {e}"))?;
    let local = listener.local_addr().map_err(|e| e.to_string())?;
    if !local.ip().is_loopback() {
        return Err(
            "Flight has no authenticated transport; only loopback listeners are supported".into(),
        );
    }
    let svc = FlightServiceServer::new(HeraclitusFlight::new(log));
    let handle = tokio::spawn(async move {
        let incoming = tonic::transport::server::TcpIncoming::from(listener);
        let _ = tonic::transport::Server::builder()
            .add_service(svc)
            .serve_with_incoming(incoming)
            .await;
    });
    Ok((local, handle))
}
