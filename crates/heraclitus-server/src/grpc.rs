//! The gRPC service over the engine.

use crate::engine::Engine;
use heraclitus_core::{Episode, EventKind, ProductPoint};
use heraclitus_proto::v1 as pb;
use std::sync::Arc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status};

pub struct Service {
    engine: Arc<Engine>,
}

impl Service {
    pub fn new(engine: Arc<Engine>) -> Self {
        Self { engine }
    }
}

fn internal(e: impl std::fmt::Display) -> Status {
    Status::internal(e.to_string())
}

fn episode_json(lsn: u64, e: &Episode) -> String {
    serde_json::json!({
        "lsn": lsn,
        "id": e.id.to_string(),
        "agent_id": e.agent_id,
        "kind": format!("{:?}", e.kind),
        "content": crate::rest::bytes_str(&e.content),
        "attrs": e.attrs,
        "ts_hlc": e.ts_hlc,
    })
    .to_string()
}

#[tonic::async_trait]
impl pb::heraclitus_server::Heraclitus for Service {
    async fn append(
        &self,
        req: Request<pb::AppendRequest>,
    ) -> Result<Response<pb::AppendResponse>, Status> {
        let r = req.into_inner();
        let kind = match r.kind.as_str() {
            "" | "Observation" => EventKind::Observation,
            "Action" => EventKind::Action,
            "Message" => EventKind::Message,
            "RetrievalFeedback" => EventKind::RetrievalFeedback,
            other => EventKind::Custom(other.to_string()),
        };
        let mut e = Episode::new(r.agent_id, kind, r.content);
        e.session_id = r.session_id;
        if !(r.hyp.is_empty() && r.sph.is_empty() && r.euc.is_empty()) {
            let mut hyp = r.hyp;
            heraclitus_manifold::project_to_ball(&mut hyp);
            e.embedding = Some(ProductPoint {
                hyp,
                sph: r.sph,
                euc: r.euc,
            });
        }
        e.attrs = r.attrs.into_iter().collect();
        for p in r.parents {
            e.parents.push(
                p.parse()
                    .map_err(|_| Status::invalid_argument("bad parent ULID"))?,
            );
        }
        // `append` BLOQUEIA (fsync do log e, com replicação, o commit por quórum
        // do raft). Correr isso num worker assíncrono estagnaria o reactor sob
        // escrita concorrente — daí `spawn_blocking`, o padrão correto para uma
        // operação bloqueante dentro de um handler async.
        let engine = self.engine.clone();
        let lsn = tokio::task::spawn_blocking(move || engine.append(e))
            .await
            .map_err(internal)?
            .map_err(internal)?;
        Ok(Response::new(pb::AppendResponse { lsn }))
    }

    async fn query(
        &self,
        req: Request<pb::QueryRequest>,
    ) -> Result<Response<pb::QueryResponse>, Status> {
        let gql = req.into_inner().gql;
        // GQL pode ESCREVER (`CREATE` → append; `DECIDE` → append por ação) e a
        // meta-auditoria também appenda — todos bloqueiam no quórum quando a
        // replicação está ativa. Corre o bloco inteiro em `spawn_blocking` para
        // não estagnar o reactor (mesmo motivo do `append`).
        let engine = self.engine.clone();
        let result = tokio::task::spawn_blocking(move || {
            let result = heraclitus_query::execute(&gql, engine.as_ref());
            // Meta-auditoria (quando ligada por config): a execução — com sucesso
            // OU falha — vira um evento AuditQuery no log, antes de responder.
            engine.audit_query(&gql, result.is_ok());
            result
        })
        .await
        .map_err(internal)?;
        let v = result.map_err(|e| Status::invalid_argument(e.to_string()))?;
        Ok(Response::new(pb::QueryResponse {
            json: v.to_string(),
        }))
    }

    async fn recall(
        &self,
        req: Request<pb::RecallRequest>,
    ) -> Result<Response<pb::QueryResponse>, Status> {
        let r = req.into_inner();
        // R11: hidratação lê do disco (log.read por hit) — fora do reactor.
        let engine = self.engine.clone();
        let v = tokio::task::spawn_blocking(move || engine.recall(&r.text, r.k.max(1) as usize))
            .await
            .map_err(internal)?
            .map_err(internal)?;
        Ok(Response::new(pb::QueryResponse {
            json: v.to_string(),
        }))
    }

    type SubscribeStream = ReceiverStream<Result<pb::EventMessage, Status>>;

    async fn subscribe(
        &self,
        req: Request<pb::SubscribeRequest>,
    ) -> Result<Response<Self::SubscribeStream>, Status> {
        let from = req.into_inner().from_lsn;
        let (tx, rx) = tokio::sync::mpsc::channel(256);
        let engine = self.engine.clone();
        let mut live = engine.log.tail_subscribe();
        tokio::spawn(async move {
            // History first, then bridge the live tail. Audit #6: when the
            // broadcast lags (slow consumer during a burst), we fall back to
            // re-reading history by LSN — gap-free, never silent drops.
            let mut next = from;
            'catchup: loop {
                loop {
                    // `log.scan` é BLOQUEANTE (abre e lê ficheiros de segmento).
                    // Chamá-lo direto aqui estagnava um worker do reactor durante
                    // todo o catch-up de histórico de um subscritor (milhares de
                    // leituras em disco num log grande) — mesma classe já corrigida
                    // em rest.rs. Fora para a pool bloqueante; `saturating_add`
                    // impede overflow de um `from_lsn` absurdo (u64::MAX).
                    let engine_scan = engine.clone();
                    let start = next;
                    let batch = match tokio::task::spawn_blocking(move || {
                        engine_scan.log.scan(start, start.saturating_add(256))
                    })
                    .await
                    {
                        Ok(Ok(b)) => b,
                        // Erro de scan: encerra a subscrição enviando o erro ao consumidor.
                        // O comportamento anterior abandonava o histórico silenciosamente.
                        Ok(Err(e)) => {
                            let _ = tx.send(Err(Status::internal(e.to_string()))).await;
                            return;
                        }
                        // Task bloqueante abortada (shutdown): encerra o stream.
                        Err(_) => return,
                    };
                    if batch.is_empty() {
                        break;
                    }
                    for (lsn, e) in &batch {
                        next = lsn + 1;
                        let msg = pb::EventMessage {
                            lsn: *lsn,
                            episode_json: episode_json(*lsn, e),
                        };
                        if tx.send(Ok(msg)).await.is_err() {
                            return;
                        }
                    }
                }
                loop {
                    match live.recv().await {
                        Ok((lsn, e)) => {
                            if lsn < next {
                                continue;
                            }
                            if lsn > next {
                                // missed events: re-read from the log
                                continue 'catchup;
                            }
                            next = lsn + 1;
                            let msg = pb::EventMessage {
                                lsn,
                                episode_json: episode_json(lsn, &e),
                            };
                            if tx.send(Ok(msg)).await.is_err() {
                                return;
                            }
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                            continue 'catchup;
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Closed) => return,
                    }
                }
            }
        });
        Ok(Response::new(ReceiverStream::new(rx)))
    }

    async fn snapshot(
        &self,
        _req: Request<pb::SnapshotRequest>,
    ) -> Result<Response<pb::SnapshotResponse>, Status> {
        Ok(Response::new(pb::SnapshotResponse {
            lsn: self.engine.snapshot(),
        }))
    }

    async fn admin(
        &self,
        req: Request<pb::AdminRequest>,
    ) -> Result<Response<pb::AdminResponse>, Status> {
        let r = req.into_inner();
        // R11: `verify` re-varre o log inteiro e `rebuild` replaya-o — minutos
        // em logs grandes. Correr isso no worker async estagnava o reactor do
        // tokio (o mesmo padrão já corrigido no `append`/`query`).
        let engine = self.engine.clone();
        let (ok, message) = tokio::task::spawn_blocking(move || {
            match r.op.as_str() {
                "stats" => (true, engine.stats().to_string()),
                "verify" => match engine.verify() {
                    Ok(v) => (true, v.to_string()),
                    Err(e) => (false, e.to_string()),
                },
                "rebuild" => {
                    let view = if r.arg.is_empty() {
                        None
                    } else {
                        Some(r.arg.as_str())
                    };
                    match engine.rebuild(view) {
                        Ok(()) => (true, "rebuilt".to_string()),
                        Err(e) => (false, e.to_string()),
                    }
                }
                op if op.starts_with("shred:") => {
                    let agent = op.strip_prefix("shred:").unwrap_or("");
                    match engine.shred(agent) {
                        Ok(true) => (
                            true,
                            format!("crypto-shred: key destroyed for agent '{agent}'"),
                        ),
                        Ok(false) => (true, format!("crypto-shred: no key for agent '{agent}'")),
                        Err(e) => (false, e.to_string()),
                    }
                }
                other => (false, format!("unknown admin op: {other}")),
            }
        })
        .await
        .map_err(internal)?;
        Ok(Response::new(pb::AdminResponse { ok, message }))
    }
}
