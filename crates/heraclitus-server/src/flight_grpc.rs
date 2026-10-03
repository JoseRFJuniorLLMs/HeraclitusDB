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
use heraclitus_core::{AccessRole, HeraclitusConfig, HeraclitusError};
use heraclitus_log::EpisodeLog;
use std::sync::Arc;
use tonic::{Request, Response, Status, Streaming};

/// Gancho de meta-auditoria do Flight: `(principal, ticket, ok)`.
///
/// O servidor liga-o a `Engine::audit_query`; fica como closure para o
/// serviço não depender do `Engine` (o Flight só precisa do log).
pub type FlightAudit = Arc<dyn Fn(&str, &str, bool) + Send + Sync>;

/// Política de acesso do Flight: a MESMA autenticação Bearer do gRPC
/// principal e, opcionalmente, a meta-auditoria.
///
/// Auditoria 2026-10-01 (F10) e conferência de 2026-10-02: o DoGet entregava
/// o log inteiro (todos os agentes, incluindo o diário administrativo) a
/// qualquer processo local, sem token, sem RBAC e sem rasto — com
/// `access_credentials` configuradas era o único caminho não autenticado até
/// aos dados. O loopback limita QUEM chega à porta, não QUEM pode ler.
#[derive(Clone)]
pub struct FlightGuard {
    auth: crate::auth::Authenticator,
    audit: Option<FlightAudit>,
}

impl FlightGuard {
    /// Credenciais tiradas da configuração, exactamente como o gRPC: sem
    /// credenciais configuradas o acesso continua aberto (loopback-only).
    pub fn from_config(config: &HeraclitusConfig) -> Result<Self, HeraclitusError> {
        Ok(Self {
            auth: crate::auth::Authenticator::from_config(config)?,
            audit: None,
        })
    }

    pub fn with_audit(mut self, audit: FlightAudit) -> Self {
        self.audit = Some(audit);
        self
    }
}

pub struct HeraclitusFlight {
    log: Arc<dyn EpisodeLog>,
    audit: Option<FlightAudit>,
}

impl HeraclitusFlight {
    /// O serviço sozinho NÃO autentica: a identidade chega pela extensão
    /// `Principal` que o interceptor de [`FlightGuard`] instala. Por isso o
    /// construtor não é público — servir `HeraclitusFlight` sem o interceptor
    /// faria cada pedido falhar com `principal ausente` (fail-closed), mas a
    /// única via suportada é [`serve_flight`].
    fn new<L: EpisodeLog + 'static>(log: Arc<L>, audit: Option<FlightAudit>) -> Self {
        Self { log, audit }
    }

    /// A auditoria é um append ao log (com fsync em `Always`): bloqueante,
    /// portanto vai para a pool bloqueante em vez de parar um worker do
    /// reactor. É aguardada para o registo preceder a resposta.
    async fn audit(&self, principal: &str, ticket: &str, ok: bool) {
        if let Some(audit) = self.audit.clone() {
            let (principal, ticket) = (principal.to_owned(), ticket.to_owned());
            let _ = tokio::task::spawn_blocking(move || audit(&principal, &ticket, ok)).await;
        }
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
        let principal = crate::auth::require(&req, AccessRole::Reader)?;
        let ticket = String::from_utf8_lossy(&req.get_ref().ticket)
            .chars()
            .take(200)
            .collect::<String>();
        let as_of = match Self::parse_ticket(req.get_ref()) {
            Ok(as_of) => as_of,
            Err(status) => {
                self.audit(&principal.name, &format!("FLIGHT DoGet {ticket}"), false)
                    .await;
                return Err(status);
            }
        };
        let log = self.log.clone();
        static ADMISSION: std::sync::OnceLock<Arc<tokio::sync::Semaphore>> =
            std::sync::OnceLock::new();
        let permit = ADMISSION
            .get_or_init(|| Arc::new(tokio::sync::Semaphore::new(2)))
            .clone()
            .try_acquire_owned()
            .map_err(|_| Status::resource_exhausted("Flight busy"))?;
        // Auditado DEPOIS da admissão (revisão de 2026-10-03): antes, um
        // pedido recusado com "Flight busy" ficava registado como leitura
        // bem-sucedida do log inteiro, e cada recusa custava um append com
        // fsync que o tecto de admissão não limitava.
        self.audit(&principal.name, &format!("FLIGHT DoGet {ticket}"), true)
            .await;
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
                        // `size` mede a RAM retida em `pending` (o Episode
                        // inteiro, com conteúdo), não a linha Arrow: o schema
                        // só exporta lsn/agent_id/kind/ts/content_len. Um
                        // evento grande sai sozinho no seu lote. Antes havia
                        // aqui um aborto acima de 16 MiB — um único append
                        // grande partia para sempre a exportação de qualquer
                        // intervalo que o incluísse, por uma linha de ~100 B.
                        let size = row.1.resident_bytes();
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
        req: Request<FlightDescriptor>,
    ) -> Result<Response<SchemaResult>, Status> {
        crate::auth::require(&req, AccessRole::Reader)?;
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
    guard: FlightGuard,
) -> Result<(std::net::SocketAddr, tokio::task::JoinHandle<()>), String> {
    // Loopback verificado ANTES do bind: verificar só depois deixava a porta
    // pública aberta (e a aceitar ligações no backlog do SO) entre o bind e o
    // erro. Sem TLS no Flight, o Bearer viajaria em claro numa interface
    // pública — o loopback continua obrigatório mesmo com autenticação.
    let resolvidos: Vec<std::net::SocketAddr> = tokio::net::lookup_host(addr)
        .await
        .map_err(|e| format!("flight addr {addr}: {e}"))?
        .collect();
    if resolvidos.is_empty() || resolvidos.iter().any(|a| !a.ip().is_loopback()) {
        return Err("Flight has no TLS transport; only loopback listeners are supported (refused before bind)".into());
    }
    let listener = tokio::net::TcpListener::bind(resolvidos.as_slice())
        .await
        .map_err(|e| format!("flight bind {addr}: {e}"))?;
    let local = listener.local_addr().map_err(|e| e.to_string())?;
    if !local.ip().is_loopback() {
        return Err("Flight has no TLS transport; only loopback listeners are supported".into());
    }
    let FlightGuard { auth, audit } = guard;
    let svc =
        FlightServiceServer::with_interceptor(HeraclitusFlight::new(log, audit), move |req| {
            auth.authenticate(req)
        });
    let handle = tokio::spawn(async move {
        let incoming = tonic::transport::server::TcpIncoming::from(listener);
        let _ = tonic::transport::Server::builder()
            .add_service(svc)
            .serve_with_incoming(incoming)
            .await;
    });
    Ok((local, handle))
}
