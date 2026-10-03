//! The gRPC service over the engine.

use crate::engine::Engine;
use heraclitus_core::{AccessRole, Episode, EventKind, ProductPoint};
use heraclitus_log::EpisodeLog;
use heraclitus_proto::v1 as pb;
use std::sync::Arc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status};

pub struct Service {
    engine: Arc<Engine>,
    sentinel: Option<Arc<heraclitus_sentinel::SentinelRuntime>>,
}

impl Service {
    pub fn new(engine: Arc<Engine>) -> Self {
        Self {
            engine,
            sentinel: None,
        }
    }

    pub fn new_with_sentinel(
        engine: Arc<Engine>,
        sentinel: Option<Arc<heraclitus_sentinel::SentinelRuntime>>,
    ) -> Self {
        Self { engine, sentinel }
    }
}

fn internal(e: impl std::fmt::Display) -> Status {
    Status::internal(e.to_string())
}

/// Erro do `append_idempotent` -> estado gRPC (o mesmo para `Append` e
/// `AppendBatch`).
fn status_do_append(e: heraclitus_core::HeraclitusError) -> Status {
    match e {
        heraclitus_core::HeraclitusError::IdempotencyConflict { .. } => {
            Status::already_exists(e.to_string())
        }
        heraclitus_core::HeraclitusError::Query(_) => Status::invalid_argument(e.to_string()),
        _ => internal(e),
    }
}

/// Itens por `AppendBatch` (o lote inteiro continua sob `MAX_REQUEST_BYTES`).
pub const MAX_BATCH_ITEMS: usize = 1000;

/// Tecto de um PEDIDO gRPC (descodificação). Ver o comentário em
/// `lib.rs::serve`.
pub const MAX_REQUEST_BYTES: usize = 64 * 1024 * 1024;
/// Tectos por campo, verificados antes de qualquer trabalho caro.
///
/// Um único tecto de mensagem para todos os métodos tratava igual um `append`
/// com um documento e um texto de GQL ou um `arg` administrativo — campos que
/// nunca precisam de megabytes e que alimentam um parser, um digest e o log
/// de auditoria (que trunca a 500 caracteres, mas só depois de tudo o resto).
pub const MAX_GQL_BYTES: usize = 1024 * 1024;
pub const MAX_ADMIN_ARG_BYTES: usize = 1024 * 1024;
pub const MAX_ATTRS: usize = 1024;
pub const MAX_ATTRS_BYTES: usize = 1024 * 1024;

#[allow(clippy::result_large_err)]
fn limitar(campo: &str, tamanho: usize, tecto: usize) -> Result<(), Status> {
    if tamanho > tecto {
        return Err(Status::invalid_argument(format!(
            "{campo} com {tamanho} bytes excede o tecto de {tecto} bytes"
        )));
    }
    Ok(())
}

fn episode_json(lsn: u64, e: &Episode) -> String {
    let kind = match &e.kind {
        EventKind::Custom(value) => value.clone(),
        other => format!("{other:?}"),
    };
    serde_json::json!({
        "lsn": lsn,
        "id": e.id.to_string(),
        "agent_id": e.agent_id,
        "kind": kind,
        "content": crate::rest::bytes_str(&e.content),
        "attrs": e.attrs,
        "ts_hlc": e.ts_hlc,
    })
    .to_string()
}

impl Service {
    /// Valida um `AppendRequest` e constrói o `Episode` — a MESMA regra para
    /// o `Append` e para cada item do `AppendBatch`, para as duas portas nunca
    /// divergirem no que aceitam.
    #[allow(clippy::result_large_err)]
    fn episodio_do_pedido(
        &self,
        r: pb::AppendRequest,
        principal: &str,
    ) -> Result<(Episode, String), Status> {
        let idempotency_key = r.idempotency_key.clone();
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
            // Auditoria 2026-09-05, vaga 2 (R60): incomparável = recusado à
            // entrada. Este é o ÚNICO sítio de produção onde se constrói um
            // `ProductPoint`, logo o único ingresso a defender. A métrica já
            // põe o par a `f64::INFINITY` (c260497), mas isso só impede o
            // envenenamento: até aqui o episódio ficava gravado no log
            // IMUTÁVEL, ocupava um nó do HNSW que nunca casa nada, e ainda
            // voltava ao cliente como hit-de-enchimento com `dist` não-finito
            // — que `serde_json` serializa como `null`. O escritor tem de
            // saber, e este é o último instante em que ainda se pode dizer
            // "não".
            //
            // A referência é a dimensão EM VIGOR no índice, NUNCA a assinatura
            // da `ProductMetric` (default 32⊗8⊗8): essa é decorativa e
            // rejeitaria todos os clientes reais. Índice vazio aceita e fixa a
            // dimensão — não há referência contra a qual decidir. Nada disto
            // toca no replay nem em `Engine::append`, por isso o histórico
            // continua a poder arrancar.
            let novo = (r.hyp.len(), r.sph.len(), r.euc.len());
            if let Some(vigor) = self.engine.embedding_layout() {
                if novo != vigor {
                    return Err(Status::invalid_argument(format!(
                        "embedding H{}⊗S{}⊗E{} é incomparável com a dimensão em vigor H{}⊗S{}⊗E{}",
                        novo.0, novo.1, novo.2, vigor.0, vigor.1, vigor.2
                    )));
                }
            }
            let mut hyp = r.hyp;
            heraclitus_manifold::project_to_ball(&mut hyp);
            e.embedding = Some(ProductPoint {
                hyp,
                sph: r.sph,
                euc: r.euc,
            });
        }
        if r.attrs.len() > MAX_ATTRS {
            return Err(Status::invalid_argument(format!(
                "{} atributos excedem o tecto de {MAX_ATTRS}",
                r.attrs.len()
            )));
        }
        limitar(
            "attrs",
            r.attrs.iter().map(|(k, v)| k.len() + v.len()).sum(),
            MAX_ATTRS_BYTES,
        )?;
        if r.attrs.keys().any(|key| key.starts_with("__heraclitus_")) {
            return Err(Status::invalid_argument(
                "atributos com prefixo __heraclitus_ são reservados",
            ));
        }
        e.attrs = r.attrs.into_iter().collect();
        e.attrs.insert(
            "__heraclitus_authenticated_principal".into(),
            principal.to_owned(),
        );
        for p in r.parents {
            e.parents.push(
                p.parse()
                    .map_err(|_| Status::invalid_argument("bad parent ULID"))?,
            );
        }
        Ok((e, idempotency_key))
    }
}

#[tonic::async_trait]
impl pb::heraclitus_server::Heraclitus for Service {
    async fn append(
        &self,
        req: Request<pb::AppendRequest>,
    ) -> Result<Response<pb::AppendResponse>, Status> {
        let principal = crate::auth::require(&req, AccessRole::Writer)?;
        let (e, idempotency_key) = self.episodio_do_pedido(req.into_inner(), &principal.name)?;
        // `append` BLOQUEIA (fsync do log e, com replicação, o commit por quórum
        // do raft). Correr isso num worker assíncrono estagnaria o reactor sob
        // escrita concorrente — daí `spawn_blocking`, o padrão correto para uma
        // operação bloqueante dentro de um handler async.
        let engine = self.engine.clone();
        let result =
            tokio::task::spawn_blocking(move || engine.append_idempotent(e, &idempotency_key))
                .await
                .map_err(internal)?
                .map_err(status_do_append)?;
        Ok(Response::new(pb::AppendResponse {
            lsn: result.0,
            deduplicated: result.1,
            event_id: result.2,
        }))
    }

    /// Vários appends numa só ida e volta (otimizacao-20m §3.6, conferido em
    /// 2026-10-02): o RPC era só unário, com um `spawn_blocking` por evento,
    /// e um produtor com milhares de eventos pagava uma ida e volta de rede e
    /// uma tarefa por cada um.
    ///
    /// TODOS os itens são validados antes de se escrever o primeiro (um item
    /// inválido não deixa metade do lote gravado). A escrita não é atómica:
    /// por ordem, e a primeira falha pára o lote com o número de itens já
    /// gravados na mensagem — com `idempotency_key` por item, repetir o lote
    /// inteiro é seguro.
    async fn append_batch(
        &self,
        req: Request<pb::AppendBatchRequest>,
    ) -> Result<Response<pb::AppendBatchResponse>, Status> {
        let principal = crate::auth::require(&req, AccessRole::Writer)?;
        let items = req.into_inner().items;
        if items.len() > MAX_BATCH_ITEMS {
            return Err(Status::invalid_argument(format!(
                "lote com {} itens excede o tecto de {MAX_BATCH_ITEMS}",
                items.len()
            )));
        }
        let mut episodios = Vec::with_capacity(items.len());
        for (i, item) in items.into_iter().enumerate() {
            episodios.push(
                self.episodio_do_pedido(item, &principal.name)
                    .map_err(|s| Status::new(s.code(), format!("item {i}: {}", s.message())))?,
            );
        }
        let engine = self.engine.clone();
        let resultado = tokio::task::spawn_blocking(move || {
            let mut out = Vec::with_capacity(episodios.len());
            for (i, (e, key)) in episodios.into_iter().enumerate() {
                match engine.append_idempotent(e, &key) {
                    Ok((lsn, deduplicated, event_id)) => out.push(pb::AppendResponse {
                        lsn,
                        deduplicated,
                        event_id,
                    }),
                    Err(err) => return Err((i, out.len(), err)),
                }
            }
            Ok(out)
        })
        .await
        .map_err(internal)?;
        match resultado {
            Ok(results) => Ok(Response::new(pb::AppendBatchResponse { results })),
            Err((i, gravados, err)) => {
                let s = status_do_append(err);
                Err(Status::new(
                    s.code(),
                    format!(
                        "item {i} falhou depois de {gravados} itens gravados: {}",
                        s.message()
                    ),
                ))
            }
        }
    }

    async fn query(
        &self,
        req: Request<pb::QueryRequest>,
    ) -> Result<Response<pb::QueryResponse>, Status> {
        limitar("gql", req.get_ref().gql.len(), MAX_GQL_BYTES)?;
        let required = match heraclitus_query::required_access(&req.get_ref().gql)
            .map_err(|e| Status::invalid_argument(e.to_string()))?
        {
            heraclitus_query::QueryAccess::Read => AccessRole::Reader,
            heraclitus_query::QueryAccess::Write => AccessRole::Writer,
        };
        let principal = crate::auth::require(&req, required)?;
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
            engine.audit_query(&gql, result.is_ok(), &principal.name);
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
        crate::auth::require(&req, AccessRole::Reader)?;
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
        crate::auth::require(&req, AccessRole::Reader)?;
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
                        // Task bloqueante cancelada (shutdown do runtime):
                        // encerra o stream. Pânico no scan é OUTRA coisa: um
                        // EOF limpo dizia ao consumidor que o histórico tinha
                        // acabado, quando ficou por entregar — tem de chegar
                        // como erro, como o `Ok(Err(_))` acima.
                        Err(e) if e.is_cancelled() => return,
                        Err(e) => {
                            let _ = tx
                                .send(Err(Status::internal(format!("scan do catch-up: {e}"))))
                                .await;
                            return;
                        }
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
        req: Request<pb::SnapshotRequest>,
    ) -> Result<Response<pb::SnapshotResponse>, Status> {
        crate::auth::require(&req, AccessRole::Reader)?;
        Ok(Response::new(pb::SnapshotResponse {
            lsn: self.engine.snapshot(),
        }))
    }

    async fn admin(
        &self,
        req: Request<pb::AdminRequest>,
    ) -> Result<Response<pb::AdminResponse>, Status> {
        limitar("admin arg", req.get_ref().arg.len(), MAX_ADMIN_ARG_BYTES)?;
        limitar("admin op", req.get_ref().op.len(), 256)?;
        let required = match req.get_ref().op.as_str() {
            // `legal-holds` e leitura: saber quem esta retido nao muda nada.
            // Colocar e levantar um hold ficam no ramo Admin abaixo.
            "stats"
            | "verify"
            | "sentinel-status"
            | "sentinel-incidents"
            | "sentinel-actions"
            | "legal-holds"
            | "regulatory-policies"
            | "regulatory-decisions"
            | "privacy-state"
            | "deferred-anchor-prepare"
            | "deferred-anchors"
            | "model-bundles" => AccessRole::Auditor,
            _ => AccessRole::Admin,
        };
        let principal = crate::auth::require(&req, required)?;
        let r = req.into_inner();
        // R11: `verify` re-varre o log inteiro e `rebuild` replaya-o — minutos
        // em logs grandes. Correr isso no worker async estagnava o reactor do
        // tokio (o mesmo padrão já corrigido no `append`/`query`).
        let engine = self.engine.clone();
        let sentinel = self.sentinel.clone();
        let operation = r.op.clone();
        let audit_principal = principal.name.clone();
        let admin_ctx = crate::trusted_admin::AdminContext::new(
            principal.name.clone(),
            "local",
            principal
                .roles
                .iter()
                .map(|role| format!("{role:?}").to_lowercase())
                .collect(),
        );
        let (ok, message) = tokio::task::spawn_blocking(move || {
            let dispatch = |token: Option<&crate::trusted_admin::AdminExecutionToken>| {
                match r.op.as_str() {
                    "admin-operation-state" => {
                        let key = serde_json::from_str::<serde_json::Value>(&r.arg).ok()
                            .and_then(|value| value.get("idempotency_key").and_then(|key| key.as_str()).map(str::to_owned));
                        match key {
                            Some(key) => (true, serde_json::json!({ "idempotency_key": key, "state": engine.trusted_admin.operation_state(&admin_ctx, &key) }).to_string()),
                            None => (false, "idempotency_key required".into()),
                        }
                    }
                    "stats" => (true, engine.stats().to_string()),
                    // SPEC-0046 §94 / invariante C10 — a porta de entrada do legal
                    // hold. O circuito já existia inteiro e era inalcançável:
                    // `place_legal_hold` persiste o evento e chama
                    // `set_legal_hold_range` no HRKM, o `plan_gc` respeita-o e o
                    // `ensure_crypto_shred_allowed` do `crypto_shred` bloqueia — mas
                    // nada em produção podia CRIAR um hold, portanto §94 era uma
                    // garantia que só os testes conseguiam exercer.
                    op @ ("legal-hold-place" | "legal-hold-release" | "legal-holds") => {
                        crate::grpc::legal_hold_op(&engine, op, &r.arg)
                    }
                    op @ ("regulatory-policy-activate"
                    | "regulatory-evaluate"
                    | "regulatory-policies"
                    | "regulatory-decisions") => {
                        crate::grpc::regulatory_policy_op(&engine, op, &r.arg)
                    }
                    op @ ("privacy-assessment" | "privacy-deadline" | "privacy-package"
                    | "privacy-state") => crate::grpc::privacy_incident_op(&engine, op, &r.arg),
                    op @ ("deferred-anchor-prepare"
                    | "deferred-anchor-import"
                    | "deferred-anchors") => crate::grpc::deferred_anchor_op(&engine, op, &r.arg),
                    op @ ("model-bundle-activate" | "model-bundles") => {
                        crate::grpc::model_bundle_op(&engine, op, &r.arg)
                    }
                    // SPEC-0089 §9 — resolver uma operação UNKNOWN depois de
                    // verificar o efeito real. Admin (cai no ramo por omissão
                    // do mapa de papéis) e corre dentro do `execute_admin`,
                    // portanto a própria reconciliação fica no diário.
                    "admin-reconcile" => admin_reconcile_op(&engine, &admin_ctx, &r.arg),
                    "verify" => match engine.verify() {
                        Ok(v) => (true, v.to_string()),
                        Err(e) => (false, e.to_string()),
                    },
                    "sentinel-status" => match sentinel.as_ref() {
                        Some(runtime) => (
                            true,
                            serde_json::to_string(&runtime.status()).unwrap_or_default(),
                        ),
                        None => (false, "sentinel desabilitado".into()),
                    },
                    "sentinel-incidents" => match sentinel.as_ref() {
                        Some(runtime) => match runtime
                            .query_incidents(heraclitus_sentinel::IncidentFilter::default())
                        {
                            Ok(incidents) => {
                                (true, serde_json::to_string(&incidents).unwrap_or_default())
                            }
                            Err(error) => (false, error.to_string()),
                        },
                        None => (false, "sentinel desabilitado".into()),
                    },
                    "sentinel-actions" => match sentinel.as_ref() {
                        Some(runtime) => match runtime.l4_events(None, None, None, 10_000) {
                            Ok(rows) => {
                                let values: Vec<_> = rows
                                    .into_iter()
                                    .map(|(lsn, episode)| {
                                        serde_json::json!({
                                            "lsn": lsn,
                                            "kind": episode.kind.label(),
                                            "attrs": episode.attrs,
                                            "content": crate::rest::bytes_str(&episode.content),
                                        })
                                    })
                                    .collect();
                                (true, serde_json::to_string(&values).unwrap_or_default())
                            }
                            Err(error) => (false, error.to_string()),
                        },
                        None => (false, "sentinel desabilitado".into()),
                    },
                    "sentinel-checkpoint" => match sentinel.as_ref() {
                        Some(runtime) => match runtime.checkpoint() {
                            Ok(lsn) => (true, format!("checkpoint_lsn={lsn}")),
                            Err(error) => (false, error.to_string()),
                        },
                        None => (false, "sentinel desabilitado".into()),
                    },
                    "sentinel-approve" | "sentinel-deny" => match sentinel.as_ref() {
                        Some(runtime) => {
                            let body = serde_json::from_str::<serde_json::Value>(&r.arg);
                            let result = body
                                .ok()
                                .and_then(|body| {
                                    Some((
                                        body.get("incident_id")?.as_str()?.to_owned(),
                                        body.get("proposal_id")?.as_str()?.to_owned(),
                                        body.get("approval_id")?.as_str()?.to_owned(),
                                        body.get("approver")
                                            .and_then(serde_json::Value::as_str)
                                            .map(str::to_owned),
                                        body.get("reason")
                                            .and_then(serde_json::Value::as_str)
                                            .unwrap_or("")
                                            .to_owned(),
                                    ))
                                })
                                .ok_or_else(|| {
                                    "arg deve conter incident_id, proposal_id e approval_id"
                                        .to_string()
                                })
                                .and_then(
                                    |(incident_id, proposal_id, approval_id, approver, reason)| {
                                        // O `approver` vinha do CORPO do pedido: quem
                                        // alcancasse esta chamada registava uma
                                        // aprovacao humana em nome de qualquer pessoa,
                                        // e um registo de aprovacao existe precisamente
                                        // para atribuir responsabilidade. Passa a ser
                                        // sempre a identidade AUTENTICADA (a mesma que
                                        // ja vai para `audit_admin` na linha de baixo —
                                        // nao fazia sentido a auditoria saber quem era
                                        // e o registo de aprovacao nao saber).
                                        //
                                        // Se o corpo indicar um aprovador, tem de
                                        // coincidir: 403 em vez de correccao silenciosa,
                                        // para que a tentativa fique visivel.
                                        let approver = crate::auth::vincular_aprovador(
                                            approver.as_deref(),
                                            &audit_principal,
                                        )?;
                                        runtime
                                            .persist_human_approval_for(
                                                &incident_id,
                                                &proposal_id,
                                                &approval_id,
                                                approver,
                                                operation == "sentinel-approve",
                                                &reason,
                                            )
                                            .map(|lsn| format!("approval_lsn={lsn}"))
                                            .map_err(|error| error.to_string())
                                    },
                                );
                            match result {
                                Ok(message) => (true, message),
                                Err(error) => (false, error),
                            }
                        }
                        None => (false, "sentinel desabilitado".into()),
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
                        match token
                            .ok_or_else(|| {
                                heraclitus_core::HeraclitusError::Config(
                                    "durable admin token required".into(),
                                )
                            })
                            .and_then(|t| engine.shred_effect(agent, t))
                        {
                            Ok(true) => (
                                true,
                                format!("crypto-shred: key destroyed for agent '{agent}'"),
                            ),
                            Ok(false) => {
                                (true, format!("crypto-shred: no key for agent '{agent}'"))
                            }
                            Err(e) => (false, e.to_string()),
                        }
                    }
                    other => (false, format!("unknown admin op: {other}")),
                }
            };
            let read_only = !admin_ctx.roles.iter().any(|role| role == "admin")
                || matches!(
                    r.op.as_str(),
                    "stats"
                        | "admin-operation-state"
                        | "verify"
                        | "sentinel-status"
                        | "sentinel-incidents"
                        | "sentinel-actions"
                        | "legal-holds"
                        | "regulatory-policies"
                        | "regulatory-decisions"
                        | "privacy-state"
                        | "deferred-anchor-prepare"
                        | "deferred-anchors"
                        | "model-bundles"
                );
            let result = if read_only {
                dispatch(None)
            } else {
                let corpo = serde_json::from_str::<serde_json::Value>(&r.arg).ok();
                let campo = |nome: &str| {
                    corpo
                        .as_ref()
                        .and_then(|v| v.get(nome))
                        .and_then(|k| k.as_str())
                        .map(str::to_owned)
                };
                let supplied = campo("idempotency_key");
                // No `admin-reconcile` a `idempotency_key` do `arg` é a da
                // operação-ALVO. Usá-la também como chave da PRÓPRIA
                // reconciliação (revisão de 2026-10-03) fazia duas coisas
                // erradas: com o mesmo principal, o `execute` via o alvo e
                // recusava por conflito de digest — quem pediu nunca conseguia
                // reconciliar; com um alvo inexistente, a reconciliação
                // encontrava a sua própria reserva e gravava dois resultados
                // para a mesma chave. A chave própria deriva do alvo (um retry
                // do MESMO pedido continua idempotente) e nunca coincide com
                // ele.
                let key = if r.op == "admin-reconcile" {
                    supplied
                        .map(|alvo| {
                            format!(
                                "admin-reconcile:{}:{}:{alvo}",
                                campo("tenant").unwrap_or_else(|| admin_ctx.tenant.clone()),
                                campo("principal")
                                    .unwrap_or_else(|| admin_ctx.principal.clone()),
                            )
                        })
                        .unwrap_or_else(|| admin_ctx.request_id.clone())
                } else {
                    supplied.unwrap_or_else(|| admin_ctx.request_id.clone())
                };
                let mut op = crate::trusted_admin::AdminOperation::new(
                    key.clone(),
                    key,
                    crate::trusted_admin::AdminOperationKind::Custom {
                        name: r.op.clone(),
                        details: r.arg.clone(),
                    },
                    "authenticated Admin RPC",
                );
                op.parameters_digest = blake3::hash(r.arg.as_bytes()).to_hex().to_string();
                match engine.execute_admin(&admin_ctx, &op, |token| {
                    let result = dispatch(Some(token));
                    if result.0 {
                        Ok(result)
                    } else {
                        Err(heraclitus_core::HeraclitusError::Config(result.1))
                    }
                }) {
                    Ok(result) => result,
                    Err(error) => (false, error.to_string()),
                }
            };
            engine.audit_admin(&operation, result.0, &audit_principal);
            result
        })
        .await
        .map_err(internal)?;
        Ok(Response::new(pb::AdminResponse { ok, message }))
    }
}

/// `Admin op="admin-reconcile"`: `arg = {"idempotency_key", "outcome":
/// "succeeded"|"failed", "evidence", "principal"?, "tenant"?}`. `principal`
/// e `tenant` identificam QUEM pediu a operação original (a chave do diário é
/// por tenant+principal+chave); por omissão, quem reconcilia.
pub(crate) fn admin_reconcile_op(
    engine: &std::sync::Arc<crate::engine::Engine>,
    reconciler: &crate::trusted_admin::AdminContext,
    arg: &str,
) -> (bool, String) {
    let body = match serde_json::from_str::<serde_json::Value>(arg) {
        Ok(value) => value,
        Err(error) => return (false, format!("corpo inválido: {error}")),
    };
    let campo = |nome: &str| body.get(nome).and_then(|v| v.as_str());
    let Some(key) = campo("idempotency_key") else {
        return (false, "idempotency_key obrigatório".into());
    };
    let outcome = match campo("outcome") {
        Some("succeeded") => crate::trusted_admin::ReconciledOutcome::Succeeded,
        Some("failed") => crate::trusted_admin::ReconciledOutcome::Failed,
        _ => {
            return (
                false,
                "outcome tem de ser \"succeeded\" ou \"failed\"".into(),
            )
        }
    };
    let evidence = campo("evidence").unwrap_or("");
    let principal = campo("principal").unwrap_or(&reconciler.principal);
    let tenant = campo("tenant").unwrap_or(&reconciler.tenant);
    match engine.reconcile_admin(reconciler, tenant, principal, key, outcome, evidence) {
        Ok(state) => (
            true,
            serde_json::json!({ "idempotency_key": key, "state": state }).to_string(),
        ),
        Err(error) => (false, error.to_string()),
    }
}

/// SPEC-0046 §94 / invariante C10 — as três operações de legal hold do RPC
/// `admin`.
///
/// Vive fora do despachante por duas razões, e a segunda é a que importa: o
/// braço do `match` seria testável apenas montando um `Request` com
/// autenticação, e o que precisa de teste é o **efeito** — colocar um hold
/// bloqueia mesmo o crypto-shred e o GC, levantá-lo desbloqueia, e a listagem
/// diz a verdade.
///
/// Devolve `(ok, mensagem)` como o resto do `admin`.
pub(crate) fn legal_hold_op(
    engine: &std::sync::Arc<crate::engine::Engine>,
    op: &str,
    arg: &str,
) -> (bool, String) {
    if engine.is_replicated() && op != "legal-holds" {
        return (
            false,
            "operação regulatória direta recusada em nó replicado; o append ainda não passa pelo consenso"
                .into(),
        );
    }
    let body = match serde_json::from_str::<serde_json::Value>(arg) {
        Ok(value) => value,
        // A listagem não precisa de corpo; as outras duas precisam.
        Err(_) if op == "legal-holds" => serde_json::Value::Null,
        Err(error) => return (false, format!("corpo inválido: {error}")),
    };
    let campo = |nome: &str| {
        body.get(nome)
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_owned()
    };

    match op {
        "legal-hold-place" => {
            let head = engine.log.head();
            let hold = heraclitus_compliance::LegalHold {
                hold_id: campo("hold_id"),
                scope: heraclitus_compliance::EvidenceSelector {
                    lsn_start: body.get("lsn_start").and_then(|v| v.as_u64()).unwrap_or(0),
                    // Omitir `lsn_end` retém tudo o que existe AGORA, e não
                    // "para sempre": um hold de fim aberto reteria eventos
                    // futuros que nenhuma autoridade avaliou.
                    lsn_end: body
                        .get("lsn_end")
                        .and_then(|v| v.as_u64())
                        .unwrap_or_else(|| head.saturating_sub(1)),
                },
                authority: campo("authority"),
                reason: campo("reason"),
                // Carimbado pelo servidor, não pelo pedido: um cliente que
                // escolhesse o LSN podia datar o hold antes de uma destruição
                // já ocorrida e fazer o registo mentir sobre a ordem.
                created_at_lsn: head,
            };
            match heraclitus_compliance::RegulatoryPolicyEngine::new(engine.log.clone())
                .with_sink(engine.clone())
                .with_cache(engine.regulatory_cache.clone())
                .place_legal_hold(hold)
            {
                Ok(lsn) => (true, format!("legal_hold_lsn={lsn}")),
                Err(error) => (false, error.to_string()),
            }
        }
        "legal-hold-release" => {
            let release = heraclitus_compliance::LegalHoldRelease {
                hold_id: campo("hold_id"),
                authority: campo("authority"),
                reason: campo("reason"),
                released_at_lsn: engine.log.head(),
            };
            match heraclitus_compliance::RegulatoryPolicyEngine::new(engine.log.clone())
                .with_sink(engine.clone())
                .with_cache(engine.regulatory_cache.clone())
                .release_legal_hold(release)
            {
                Ok(lsn) => (true, format!("legal_hold_release_lsn={lsn}")),
                Err(error) => (false, error.to_string()),
            }
        }
        "legal-holds" => {
            let head = engine.log.head();
            match heraclitus_compliance::RegulatoryState::replay(engine.log.as_ref(), head) {
                Ok(state) => {
                    let holds: Vec<_> = state
                        .active_holds()
                        .map(|record| {
                            serde_json::json!({
                                "hold_id": record.hold.hold_id,
                                "authority": record.hold.authority,
                                "reason": record.hold.reason,
                                "lsn_start": record.hold.scope.lsn_start,
                                "lsn_end": record.hold.scope.lsn_end,
                                "placed_at_lsn": record.lsn,
                            })
                        })
                        .collect();
                    (true, serde_json::to_string(&holds).unwrap_or_default())
                }
                Err(error) => (false, error.to_string()),
            }
        }
        outra => (false, format!("operação desconhecida: {outra}")),
    }
}

/// SPEC-0046 — superfície operacional do motor regulatório versionado.
///
/// Ativações e decisões são eventos imutáveis no mesmo log da base. As duas
/// listagens expõem o estado reconstruído por replay; não mantêm um segundo
/// banco oportunista que pudesse divergir da evidência.
pub(crate) fn regulatory_policy_op(
    engine: &std::sync::Arc<crate::engine::Engine>,
    op: &str,
    arg: &str,
) -> (bool, String) {
    if engine.is_replicated() && matches!(op, "regulatory-policy-activate" | "regulatory-evaluate")
    {
        return (
            false,
            "operação regulatória direta recusada em nó replicado; o append ainda não passa pelo consenso"
                .into(),
        );
    }

    let regulatory = heraclitus_compliance::RegulatoryPolicyEngine::new(engine.log.clone())
        .with_sink(engine.clone())
        .with_cache(engine.regulatory_cache.clone());
    match op {
        "regulatory-policy-activate" => {
            let activation =
                match serde_json::from_str::<heraclitus_compliance::PolicyActivation>(arg) {
                    Ok(activation) => activation,
                    Err(error) => {
                        return (false, format!("ativação de política inválida: {error}"))
                    }
                };
            match regulatory.activate_policy(activation) {
                Ok(lsn) => (true, format!("policy_activation_lsn={lsn}")),
                Err(error) => (false, error.to_string()),
            }
        }
        "regulatory-evaluate" => {
            #[derive(serde::Deserialize)]
            struct RequestBody {
                policy_id: String,
                context: heraclitus_compliance::ComplianceContext,
            }
            let request = match serde_json::from_str::<RequestBody>(arg) {
                Ok(request) => request,
                Err(error) => return (false, format!("avaliação regulatória inválida: {error}")),
            };
            match regulatory.evaluate_and_persist(&request.policy_id, request.context) {
                Ok((lsn, decision)) => (
                    true,
                    serde_json::json!({ "lsn": lsn, "decision": decision }).to_string(),
                ),
                Err(error) => (false, error.to_string()),
            }
        }
        "regulatory-policies" => match regulatory.state() {
            Ok(state) => {
                let policies: Vec<_> = state
                    .policy_activations
                    .into_iter()
                    .map(|record| {
                        serde_json::json!({
                            "lsn": record.lsn,
                            "activation": record.activation,
                        })
                    })
                    .collect();
                (true, serde_json::Value::Array(policies).to_string())
            }
            Err(error) => (false, error.to_string()),
        },
        "regulatory-decisions" => match regulatory.state() {
            Ok(state) => {
                let decisions: Vec<_> = state
                    .decisions
                    .into_iter()
                    .map(|record| {
                        serde_json::json!({
                            "lsn": record.lsn,
                            "decision": record.decision,
                        })
                    })
                    .collect();
                (true, serde_json::Value::Array(decisions).to_string())
            }
            Err(error) => (false, error.to_string()),
        },
        other => (false, format!("operação desconhecida: {other}")),
    }
}

/// SPEC-0046 — avaliação de incidente LGPD, prazo versionado e geração do
/// rascunho ANPD. Não existe operação de "submit": o pacote termina
/// explicitamente em `awaiting_human_authorization`.
pub(crate) fn privacy_incident_op(
    engine: &std::sync::Arc<crate::engine::Engine>,
    op: &str,
    arg: &str,
) -> (bool, String) {
    if engine.is_replicated()
        && matches!(
            op,
            "privacy-assessment" | "privacy-deadline" | "privacy-package"
        )
    {
        return (
            false,
            "operação de privacidade direta recusada em nó replicado; o append ainda não passa pelo consenso"
                .into(),
        );
    }
    let privacy = heraclitus_compliance::PrivacyIncidentEngine::new(engine.log.clone())
        .with_sink(engine.clone());
    match op {
        "privacy-assessment" => {
            let assessment =
                match serde_json::from_str::<heraclitus_compliance::PrivacyIncidentAssessment>(arg)
                {
                    Ok(assessment) => assessment,
                    Err(error) => {
                        return (false, format!("avaliação de privacidade inválida: {error}"))
                    }
                };
            match privacy.persist_assessment(assessment) {
                Ok(lsn) => (true, format!("privacy_assessment_lsn={lsn}")),
                Err(error) => (false, error.to_string()),
            }
        }
        "privacy-deadline" => {
            #[derive(serde::Deserialize)]
            struct RequestBody {
                incident_id: String,
                triggered_at: u64,
                policy: heraclitus_compliance::DeadlinePolicy,
            }
            let request = match serde_json::from_str::<RequestBody>(arg) {
                Ok(request) => request,
                Err(error) => return (false, format!("pedido de prazo inválido: {error}")),
            };
            match privacy.calculate_and_persist_deadline(
                request.incident_id,
                request.triggered_at,
                &request.policy,
            ) {
                Ok((lsn, deadline)) => (
                    true,
                    serde_json::json!({ "lsn": lsn, "deadline": deadline }).to_string(),
                ),
                Err(error) => (false, error.to_string()),
            }
        }
        "privacy-package" => {
            #[derive(serde::Deserialize)]
            struct RequestBody {
                assessment_id: String,
                deadline_id: String,
                export_id: String,
                data: heraclitus_compliance::IncidentPackageData,
                export_policy: heraclitus_compliance::PrivacyExportPolicy,
            }
            let request = match serde_json::from_str::<RequestBody>(arg) {
                Ok(request) => request,
                Err(error) => return (false, format!("pedido de pacote ANPD inválido: {error}")),
            };
            let state = match privacy.state() {
                Ok(state) => state,
                Err(error) => return (false, error.to_string()),
            };
            let assessment = match state
                .assessments
                .iter()
                .find(|(_, value)| value.assessment_id == request.assessment_id)
                .map(|(_, value)| value)
            {
                Some(value) => value,
                None => return (false, "assessment_id não persistido".into()),
            };
            let deadline = match state
                .deadlines
                .iter()
                .find(|(_, value)| value.deadline_id == request.deadline_id)
                .map(|(_, value)| value)
            {
                Some(value) => value,
                None => return (false, "deadline_id não persistido".into()),
            };
            let output = match engine.compliance_export_dir("anpd", &request.export_id) {
                Ok(output) => output,
                Err(error) => return (false, error.to_string()),
            };
            match privacy.generate_package(
                assessment,
                deadline,
                &request.data,
                &request.export_policy,
                &output,
            ) {
                Ok((lsn, receipt)) => (
                    true,
                    serde_json::json!({ "lsn": lsn, "receipt": receipt }).to_string(),
                ),
                Err(error) => (false, error.to_string()),
            }
        }
        "privacy-state" => match privacy.state() {
            Ok(state) => (
                true,
                serde_json::json!({
                    "assessments": state.assessments,
                    "deadlines": state.deadlines,
                    "exports": state.exports,
                })
                .to_string(),
            ),
            Err(error) => (false, error.to_string()),
        },
        other => (false, format!("operação desconhecida: {other}")),
    }
}

/// SPEC-0046 — fronteira air-gap. `prepare` devolve somente um compromisso
/// criptográfico (nunca episódios); a assinatura institucional pode ocorrer
/// fora do processo. `import` verifica as duas assinaturas, o binding exato da
/// resposta e persiste a âncora encadeada.
pub(crate) fn deferred_anchor_op(
    engine: &std::sync::Arc<crate::engine::Engine>,
    op: &str,
    arg: &str,
) -> (bool, String) {
    if engine.is_replicated() && op == "deferred-anchor-import" {
        return (
            false,
            "importação de âncora direta recusada em nó replicado; o append ainda não passa pelo consenso"
                .into(),
        );
    }
    let registry = heraclitus_compliance::DeferredAnchorRegistry::new(engine.log.clone())
        .with_sink(engine.clone());
    match op {
        "deferred-anchor-prepare" => {
            #[derive(serde::Deserialize)]
            struct RequestBody {
                lsn_start: u64,
                lsn_end: u64,
                created_at_hlc: u64,
            }
            let request = match serde_json::from_str::<RequestBody>(arg) {
                Ok(request) => request,
                Err(error) => return (false, format!("pedido de commitment inválido: {error}")),
            };
            let commitment = match heraclitus_compliance::EvidenceCommitment::from_log(
                engine.log.as_ref(),
                request.lsn_start,
                request.lsn_end,
                request.created_at_hlc,
            ) {
                Ok(commitment) => commitment,
                Err(error) => return (false, error.to_string()),
            };
            let previous = match registry.state() {
                Ok(state) => state.latest_digest(),
                Err(error) => return (false, error.to_string()),
            };
            match heraclitus_compliance::DeferredAnchorRequest::new(commitment, previous) {
                Ok(request) => (true, serde_json::to_string(&request).unwrap_or_default()),
                Err(error) => (false, error.to_string()),
            }
        }
        "deferred-anchor-import" => {
            #[derive(serde::Deserialize)]
            struct RequestBody {
                signed_request: heraclitus_compliance::SignedDeferredAnchorRequest,
                signed_response: heraclitus_compliance::SignedDeferredAnchorResponse,
                policy: heraclitus_compliance::DeferredTransferPolicy,
            }
            let request = match serde_json::from_str::<RequestBody>(arg) {
                Ok(request) => request,
                Err(error) => return (false, format!("importação de âncora inválida: {error}")),
            };
            let anchor = match heraclitus_compliance::import_deferred_response(
                &request.signed_request,
                &request.signed_response,
                &request.policy,
            ) {
                Ok(anchor) => anchor,
                Err(error) => return (false, error.to_string()),
            };
            match registry.persist(anchor.clone()) {
                Ok(lsn) => (
                    true,
                    serde_json::json!({ "lsn": lsn, "anchor": anchor }).to_string(),
                ),
                Err(error) => (false, error.to_string()),
            }
        }
        "deferred-anchors" => match registry.state() {
            // Auditoria 2026-09-05, vaga 2 (R31): depois de A06 o replay passou
            // a TOLERAR bifurcações — a âncora que não encadeia vai para
            // `state.forks` em vez de abortar o replay com um erro ruidoso.
            // Listar só `anchors` escondia por completo o ramo descartado: o
            // auditor deixou de receber o erro e passou a ver uma cadeia
            // aparentemente imaculada. O par (LSN, EvidenceAnchor) tem de sair
            // AQUI — o contador `deferred_anchor_forks` do dashboard não diz
            // QUAL âncora nem em que LSN, e nem sequer existe na superfície
            // gRPC, que é a que o cliente de auditoria da SPEC-0046 fala.
            // Forma de objecto pelo precedente do `privacy-state` acima.
            Ok(state) => (
                true,
                serde_json::json!({ "anchors": state.anchors, "forks": state.forks }).to_string(),
            ),
            Err(error) => (false, error.to_string()),
        },
        other => (false, format!("operação desconhecida: {other}")),
    }
}

/// SPEC-0046 — valida e ativa bundles offline já colocados sob a raiz de dados
/// controlada pelo servidor. O pedido escolhe um `bundle_id`, nunca um caminho
/// arbitrário do host.
pub(crate) fn model_bundle_op(
    engine: &std::sync::Arc<crate::engine::Engine>,
    op: &str,
    arg: &str,
) -> (bool, String) {
    if engine.is_replicated() && op == "model-bundle-activate" {
        return (
            false,
            "ativação de bundle direta recusada em nó replicado; o append ainda não passa pelo consenso"
                .into(),
        );
    }
    match op {
        "model-bundle-activate" => {
            #[derive(serde::Deserialize)]
            struct RequestBody {
                bundle_id: String,
                policy: heraclitus_compliance::ModelBundlePolicy,
            }
            let request = match serde_json::from_str::<RequestBody>(arg) {
                Ok(request) => request,
                Err(error) => return (false, format!("pedido de bundle inválido: {error}")),
            };
            let root = match engine.compliance_export_dir("model-bundles", &request.bundle_id) {
                Ok(root) => root,
                Err(error) => return (false, error.to_string()),
            };
            let signed = match heraclitus_compliance::SignedModelBundle::load(&root) {
                Ok(signed) => signed,
                Err(error) => return (false, error.to_string()),
            };
            let verified =
                match heraclitus_compliance::verify_model_bundle(&root, &signed, &request.policy) {
                    Ok(verified) => verified,
                    Err(error) => return (false, error.to_string()),
                };
            match heraclitus_compliance::ModelBundleRegistry::new(engine.log.clone())
                .with_sink(engine.clone())
                .activate(verified.clone())
            {
                Ok(lsn) => (
                    true,
                    serde_json::json!({ "lsn": lsn, "bundle": verified }).to_string(),
                ),
                Err(error) => (false, error.to_string()),
            }
        }
        "model-bundles" => {
            let rows = match engine.log.scan(0, engine.log.head()) {
                Ok(rows) => rows,
                Err(error) => return (false, error.to_string()),
            };
            let bundles: Vec<_> = rows
                .into_iter()
                .filter(|(_, episode)| episode.kind.label() == "SecurityModelActivation")
                .filter_map(|(lsn, episode)| {
                    serde_json::from_slice::<heraclitus_compliance::VerifiedModelBundle>(
                        &episode.content,
                    )
                    .ok()
                    .map(|bundle| serde_json::json!({ "lsn": lsn, "bundle": bundle }))
                })
                .collect();
            (true, serde_json::Value::Array(bundles).to_string())
        }
        other => (false, format!("operação desconhecida: {other}")),
    }
}

#[cfg(test)]
mod testes_dimensao_do_embedding {
    use super::*;
    use crate::auth::Principal;
    use heraclitus_core::HeraclitusConfig;
    use pb::heraclitus_server::Heraclitus;

    fn motor(dir: &std::path::Path) -> Arc<Engine> {
        let cfg = HeraclitusConfig {
            data_dir: dir.to_path_buf(),
            ..HeraclitusConfig::default()
        };
        Arc::new(Engine::open(&cfg).unwrap())
    }

    /// Um Append autenticado como Writer — o principal vive nas extensões do
    /// pedido porque é lá que o interceptor o põe e é lá que `auth::require` o
    /// procura.
    fn pedido(hyp: Vec<f32>, sph: Vec<f32>, euc: Vec<f32>) -> Request<pb::AppendRequest> {
        let mut req = Request::new(pb::AppendRequest {
            agent_id: "cliente".into(),
            kind: "Observation".into(),
            content: b"episodio".to_vec(),
            hyp,
            sph,
            euc,
            ..Default::default()
        });
        req.extensions_mut().insert(Principal {
            name: "escritor".into(),
            roles: Arc::new(vec![AccessRole::Writer]),
        });
        req
    }

    fn lote(itens: Vec<pb::AppendRequest>) -> Request<pb::AppendBatchRequest> {
        let mut req = Request::new(pb::AppendBatchRequest { items: itens });
        req.extensions_mut().insert(Principal {
            name: "escritor".into(),
            roles: Arc::new(vec![AccessRole::Writer]),
        });
        req
    }

    fn item(conteudo: &str, chave: &str) -> pb::AppendRequest {
        pb::AppendRequest {
            agent_id: "cliente".into(),
            content: conteudo.as_bytes().to_vec(),
            idempotency_key: chave.into(),
            ..Default::default()
        }
    }

    fn pedido_admin(op: &str, arg: serde_json::Value) -> Request<pb::AdminRequest> {
        let mut req = Request::new(pb::AdminRequest {
            op: op.into(),
            arg: arg.to_string(),
        });
        req.extensions_mut().insert(Principal {
            name: "chefe".into(),
            roles: Arc::new(vec![AccessRole::Admin]),
        });
        req
    }

    /// Deixa uma operação UNKNOWN do principal `chefe`: a intenção chega ao
    /// log, o resultado não (falha injectada na segunda escrita).
    fn deixar_unknown(engine: &Engine, chave: &str) {
        use crate::trusted_admin::{AdminContext, AdminOperation, AdminOperationKind};
        let ctx = AdminContext::new("chefe", "local", vec!["admin".into()]);
        let op = AdminOperation::new(
            chave,
            chave,
            AdminOperationKind::Custom {
                name: "operacao-de-teste".into(),
                details: String::new(),
            },
            "teste",
        );
        let escritas = std::cell::Cell::new(0);
        let resultado: Result<bool, _> = engine.trusted_admin().execute(
            &ctx,
            &op,
            |ep| {
                escritas.set(escritas.get() + 1);
                if escritas.get() == 2 {
                    return Err(heraclitus_core::HeraclitusError::Config(
                        "falha injectada ao gravar o resultado".into(),
                    ));
                }
                let lsn = engine.log.append(ep)?;
                engine.log.flush()?;
                Ok(lsn)
            },
            |_| Ok(true),
        );
        assert!(resultado.is_err());
    }

    /// Revisão de 2026-10-03 (achado 13): o próprio requerente não conseguia
    /// reconciliar a sua operação UNKNOWN — a chave do alvo era reutilizada
    /// como chave da reconciliação e o `execute` recusava por conflito.
    #[tokio::test]
    async fn quem_pediu_a_operacao_consegue_reconcilia_la_e_o_servidor_volta_a_arrancar() {
        let dir = tempfile::tempdir().unwrap();
        {
            let engine = motor(dir.path());
            deixar_unknown(&engine, "K-1");
            let svc = Service::new(engine.clone());
            let r = svc
                .admin(pedido_admin(
                    "admin-reconcile",
                    serde_json::json!({
                        "idempotency_key": "K-1",
                        "outcome": "succeeded",
                        "evidence": "efeito confirmado fora do sistema",
                    }),
                ))
                .await
                .unwrap()
                .into_inner();
            assert!(r.ok, "{}", r.message);
        }
        // O diário tem de continuar válido: o arranque seguinte não pode recusar.
        let engine = motor(dir.path());
        let ctx = crate::trusted_admin::AdminContext::new("chefe", "local", vec!["admin".into()]);
        assert_eq!(
            engine.trusted_admin().operation_state(&ctx, "K-1"),
            Some(crate::trusted_admin::AdminState::Reconciled)
        );
    }

    /// Revisão de 2026-10-03 (achado 11, crítico): reconciliar uma chave que
    /// NÃO existe fazia a reconciliação encontrar a sua própria reserva e
    /// gravar dois resultados para a mesma chave — o arranque seguinte
    /// recusava o diário e o servidor deixava de arrancar.
    #[tokio::test]
    async fn reconciliar_uma_chave_inexistente_falha_sem_partir_o_arranque() {
        let dir = tempfile::tempdir().unwrap();
        {
            let engine = motor(dir.path());
            let svc = Service::new(engine.clone());
            let r = svc
                .admin(pedido_admin(
                    "admin-reconcile",
                    serde_json::json!({
                        "idempotency_key": "nunca-existiu",
                        "outcome": "succeeded",
                        "evidence": "x",
                    }),
                ))
                .await
                .unwrap()
                .into_inner();
            assert!(
                !r.ok,
                "reconciliar o inexistente tem de falhar: {}",
                r.message
            );
        }
        let _engine = motor(dir.path());
    }

    /// `AppendBatch` (otimizacao-20m §3.6): grava por ordem numa só ida e
    /// volta; um item inválido recusa o lote ANTES de escrever; e, com chaves
    /// por item, repetir o lote é idempotente.
    #[tokio::test]
    async fn append_batch_grava_valida_antes_e_repete_sem_duplicar() {
        let dir = tempfile::tempdir().unwrap();
        let engine = motor(dir.path());
        let svc = Service::new(engine.clone());
        let itens = || {
            (0..5)
                .map(|i| item(&format!("e{i}"), &format!("k-{i}")))
                .collect()
        };

        let r = svc.append_batch(lote(itens())).await.unwrap().into_inner();
        assert_eq!(r.results.len(), 5);
        let lsns: Vec<u64> = r.results.iter().map(|x| x.lsn).collect();
        assert!(lsns.windows(2).all(|p| p[0] < p[1]), "por ordem: {lsns:?}");
        assert!(r.results.iter().all(|x| !x.deduplicated));
        let head = engine.head();

        // Repetir o lote inteiro: mesmos LSN, nada novo no log.
        let de_novo = svc.append_batch(lote(itens())).await.unwrap().into_inner();
        assert_eq!(
            de_novo.results.iter().map(|x| x.lsn).collect::<Vec<_>>(),
            lsns
        );
        assert!(de_novo.results.iter().all(|x| x.deduplicated));
        assert_eq!(engine.head(), head);

        // Um item inválido (atributo reservado) recusa o lote sem gravar nada.
        let mut mau = itens();
        mau[3].attrs.insert("__heraclitus_x".into(), "y".into());
        mau[0] = item("novo", "k-novo");
        let erro = svc.append_batch(lote(mau)).await.unwrap_err();
        assert_eq!(erro.code(), tonic::Code::InvalidArgument);
        assert!(erro.message().contains("item 3"), "{}", erro.message());
        assert_eq!(engine.head(), head, "validação antes de escrever");

        // Tecto de itens.
        let demais = (0..=MAX_BATCH_ITEMS)
            .map(|i| item("x", &format!("t-{i}")))
            .collect();
        assert!(svc.append_batch(lote(demais)).await.is_err());
        assert_eq!(engine.head(), head);
    }

    /// Auditoria 2026-09-05, vaga 2 (R60): o caminho de ingestão do gRPC — o
    /// ÚNICO sítio de produção onde se constrói um `ProductPoint` — aceitava
    /// qualquer dimensão. O commit c260497 pôs o par incomparável a
    /// `f64::INFINITY` na métrica, o que fecha o envenenamento (o nó deixa de
    /// dominar as buscas) mas não fecha a fuga: o episódio fica gravado no log
    /// IMUTÁVEL, ocupa um nó permanente do HNSW que nunca casa nada, e o
    /// escritor recebe OK. Este é o último instante em que ainda se pode dizer
    /// "não".
    #[tokio::test]
    async fn append_recusa_embedding_incomparavel_com_a_dimensao_em_vigor() {
        let dir = tempfile::tempdir().unwrap();
        let svc = Service::new(motor(dir.path()));

        // O primeiro embedding FIXA a dimensão do corpus: H3.
        svc.append(pedido(vec![0.1, 0.2, 0.3], vec![], vec![]))
            .await
            .unwrap();
        svc.append(pedido(vec![0.4, 0.5, 0.6], vec![], vec![]))
            .await
            .unwrap();

        let erro = svc
            .append(pedido(vec![0.1; 5], vec![], vec![]))
            .await
            .unwrap_err();
        assert_eq!(erro.code(), tonic::Code::InvalidArgument, "{erro}");
        assert!(
            erro.message().contains("H5") && erro.message().contains("H3"),
            "a mensagem tem de nomear as DUAS dimensões: {}",
            erro.message()
        );

        // A componente esférica conta tanto como a hiperbólica: com a consulta
        // a trazer `sph` vazio, `dist_sph_prepared` devolve 0.0 e a métrica NEM
        // SEQUER vê a incompatibilidade — só a guarda de ingestão a apanha.
        let erro = svc
            .append(pedido(vec![0.1, 0.2, 0.3], vec![0.5], vec![]))
            .await
            .unwrap_err();
        assert_eq!(erro.code(), tonic::Code::InvalidArgument, "{erro}");

        // Controlo positivo: a guarda não pode fechar o caminho legítimo.
        svc.append(pedido(vec![0.7, 0.8, 0.9], vec![], vec![]))
            .await
            .unwrap();
        // Nem o episódio sem embedding nenhum, que não entra no índice.
        svc.append(pedido(vec![], vec![], vec![])).await.unwrap();
    }

    /// Auditoria 2026-09-05, vaga 2 (R60): o efeito observável a jusante. Em
    /// `search_layer` o ramo `results.len() < ef || d < worst` admite o
    /// candidato infinito enquanto ainda faltam resultados — logo, com menos de
    /// `ef` nós comparáveis, o nó de dimensão errada ENTRA nos resultados.
    /// `search` faz `(dist.max(0.0)).sqrt() as f32` -> `f32::INFINITY`,
    /// `Engine::nearest` propaga-o, e `plan.rs` faz `j["dist"] = json!(dist)`:
    /// serde_json converte não-finito em `Value::Null`. O cliente recebia o
    /// episódio incomparável como hit-de-enchimento com `"dist": null`. A
    /// guarda de ingestão é a única coisa que impede essa linha de existir.
    #[tokio::test]
    async fn nenhum_hit_de_nearest_sai_com_dist_nula() {
        let dir = tempfile::tempdir().unwrap();
        let engine = motor(dir.path());
        let svc = Service::new(engine.clone());

        svc.append(pedido(vec![0.1, 0.2, 0.3], vec![], vec![]))
            .await
            .unwrap();
        svc.append(pedido(vec![0.4, 0.5, 0.6], vec![], vec![]))
            .await
            .unwrap();
        // Antes da correcção isto era aceite e ficava no índice para sempre.
        let _ = svc.append(pedido(vec![0.9; 5], vec![], vec![])).await;

        let json = heraclitus_query::execute("NEAREST ([0.1, 0.2, 0.3], 5)", engine.as_ref())
            .unwrap()
            .to_string();
        let linhas: Vec<serde_json::Value> = serde_json::from_str(&json).unwrap();
        assert!(
            !linhas.is_empty(),
            "o corpus comparável tem de continuar a responder: {json}"
        );
        for linha in &linhas {
            assert!(
                !linha["dist"].is_null(),
                "um hit saiu com dist não-finita (incomparável): {json}"
            );
        }
    }
}
