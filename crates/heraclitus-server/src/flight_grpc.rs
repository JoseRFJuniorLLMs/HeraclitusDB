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
use arrow_flight::error::FlightError;
use arrow_flight::flight_service_server::{FlightService, FlightServiceServer};
use arrow_flight::{
    Action, ActionType, Criteria, Empty, FlightData, FlightDescriptor, FlightInfo,
    HandshakeRequest, HandshakeResponse, PollInfo, PutResult, SchemaResult, Ticket,
};
use futures::stream::BoxStream;
use futures::{StreamExt, TryStreamExt};
use heraclitus_analytics::datafusion::arrow::record_batch::RecordBatch;
use heraclitus_analytics::vectorized::{episodes_to_batches_sized, BATCH_ROWS};
use heraclitus_core::Episode;
use heraclitus_log::EpisodeLog;
use std::sync::Arc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status, Streaming};

struct HeraclitusFlight {
    log: Arc<dyn EpisodeLog>,
}

impl HeraclitusFlight {
    fn new<L: EpisodeLog + 'static>(log: Arc<L>) -> Self {
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

fn episode_resident_bytes(episode: &Episode) -> usize {
    let kind_bytes = match &episode.kind {
        heraclitus_core::EventKind::Custom(value) => value.len(),
        _ => 24,
    };
    let embedding_bytes = episode
        .embedding
        .as_ref()
        .map(|point| {
            point
                .hyp
                .len()
                .saturating_add(point.sph.len())
                .saturating_add(point.euc.len())
                .saturating_mul(std::mem::size_of::<f32>())
        })
        .unwrap_or(0);
    let attrs_bytes = episode
        .attrs
        .iter()
        .map(|(key, value)| key.len().saturating_add(value.len()))
        .sum::<usize>();
    let parents_bytes = episode
        .parents
        .len()
        .saturating_mul(std::mem::size_of::<heraclitus_core::EventId>());

    episode
        .content
        .len()
        .saturating_add(episode.agent_id.len())
        .saturating_add(episode.session_id.len())
        .saturating_add(kind_bytes)
        .saturating_add(embedding_bytes)
        .saturating_add(attrs_bytes)
        .saturating_add(parents_bytes)
        .saturating_add(96)
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

        // Backpressure e admission control globais. O permit vive dentro do
        // produtor e só é libertado quando o stream termina ou o cliente cai.
        const FLIGHT_BUFFERED_BATCHES: usize = 4;
        const FLIGHT_MAX_CONCURRENT: usize = 4;
        const FLIGHT_PAGE_BYTES: usize = 8 * 1024 * 1024;
        static FLIGHT_GATE: std::sync::OnceLock<std::sync::Arc<tokio::sync::Semaphore>> =
            std::sync::OnceLock::new();
        let permit = FLIGHT_GATE
            .get_or_init(|| {
                std::sync::Arc::new(tokio::sync::Semaphore::new(FLIGHT_MAX_CONCURRENT))
            })
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| Status::unavailable("admission control Flight encerrado"))?;

        let (tx, rx) = tokio::sync::mpsc::channel::<Result<RecordBatch, FlightError>>(
            FLIGHT_BUFFERED_BATCHES,
        );

        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let to = as_of.unwrap_or(u64::MAX).min(log.head());
            let mut cur = 0u64;

            while cur < to {
                // Página limitada por LINHAS e por BYTES residentes. Point
                // reads evitam que um scan já tenha alocado milhares de
                // episódios antes de conseguirmos aplicar o budget.
                let mut events = Vec::with_capacity(BATCH_ROWS);
                let mut page_bytes = 0usize;

                while cur < to && events.len() < BATCH_ROWS {
                    let read = match log.read(cur) {
                        Ok(read) => read,
                        Err(error) => {
                            let _ = tx.blocking_send(Err(FlightError::protocol(format!(
                                "leitura do log falhou no LSN {cur}: {error}"
                            ))));
                            return;
                        }
                    };
                    cur = cur.saturating_add(1);

                    let Some((lsn, episode)) = read else {
                        continue;
                    };
                    let row_bytes = episode_resident_bytes(&episode);
                    if row_bytes > FLIGHT_PAGE_BYTES {
                        let _ = tx.blocking_send(Err(FlightError::protocol(format!(
                            "evento LSN {lsn} excede budget Flight de {FLIGHT_PAGE_BYTES} bytes"
                        ))));
                        return;
                    }
                    if !events.is_empty()
                        && page_bytes.saturating_add(row_bytes) > FLIGHT_PAGE_BYTES
                    {
                        // Reprocessar este LSN na página seguinte.
                        cur = lsn;
                        break;
                    }

                    page_bytes = page_bytes.saturating_add(row_bytes);
                    events.push((lsn, episode));
                }

                if events.is_empty() {
                    continue;
                }

                let batches = match episodes_to_batches_sized(&events, BATCH_ROWS) {
                    Ok(batches) => batches,
                    Err(error) => {
                        let _ = tx.blocking_send(Err(FlightError::protocol(format!(
                            "conversão Arrow falhou: {error}"
                        ))));
                        return;
                    }
                };

                for batch in batches {
                    // Receiver fechado = cancelamento cooperativo imediato no
                    // próximo envio, sem continuar a percorrer o log.
                    if tx.blocking_send(Ok(batch)).is_err() {
                        return;
                    }
                }
            }
        });

        let stream = FlightDataEncoderBuilder::new()
            .with_schema(heraclitus_analytics::vectorized::batch_schema())
            .build(ReceiverStream::new(rx))
            .map_err(Status::from)
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
    // A API pública também impõe a mesma fronteira do boot principal. Assim um
    // integrador não consegue expor Flight sem autenticação em 0.0.0.0 apenas
    // por chamar `serve_flight` diretamente.
    if !local.ip().is_loopback() {
        return Err(format!(
            "Flight sem autenticação só pode escutar em loopback; endereço resolvido: {local}"
        ));
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
