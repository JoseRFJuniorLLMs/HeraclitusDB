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

#[tonic::async_trait]
impl pb::heraclitus_server::Heraclitus for Service {
    async fn append(
        &self,
        req: Request<pb::AppendRequest>,
    ) -> Result<Response<pb::AppendResponse>, Status> {
        let principal = crate::auth::require(&req, AccessRole::Writer)?;
        let r = req.into_inner();
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
            let mut hyp = r.hyp;
            heraclitus_manifold::project_to_ball(&mut hyp);
            e.embedding = Some(ProductPoint {
                hyp,
                sph: r.sph,
                euc: r.euc,
            });
        }
        if r.attrs.keys().any(|key| key.starts_with("__heraclitus_")) {
            return Err(Status::invalid_argument(
                "atributos com prefixo __heraclitus_ são reservados",
            ));
        }
        e.attrs = r.attrs.into_iter().collect();
        e.attrs.insert(
            "__heraclitus_authenticated_principal".into(),
            principal.name,
        );
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
        let result =
            tokio::task::spawn_blocking(move || engine.append_idempotent(e, &idempotency_key))
                .await
                .map_err(internal)?
                .map_err(|e| match e {
                    heraclitus_core::HeraclitusError::IdempotencyConflict { .. } => {
                        Status::already_exists(e.to_string())
                    }
                    heraclitus_core::HeraclitusError::Query(_) => {
                        Status::invalid_argument(e.to_string())
                    }
                    _ => internal(e),
                })?;
        Ok(Response::new(pb::AppendResponse {
            lsn: result.0,
            deduplicated: result.1,
            event_id: result.2,
        }))
    }

    async fn query(
        &self,
        req: Request<pb::QueryRequest>,
    ) -> Result<Response<pb::QueryResponse>, Status> {
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
        let (ok, message) = tokio::task::spawn_blocking(move || {
            let result = match r.op.as_str() {
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
                | "regulatory-decisions") => crate::grpc::regulatory_policy_op(&engine, op, &r.arg),
                op @ ("privacy-assessment" | "privacy-deadline" | "privacy-package"
                | "privacy-state") => crate::grpc::privacy_incident_op(&engine, op, &r.arg),
                op
                @ ("deferred-anchor-prepare" | "deferred-anchor-import" | "deferred-anchors") => {
                    crate::grpc::deferred_anchor_op(&engine, op, &r.arg)
                }
                op @ ("model-bundle-activate" | "model-bundles") => {
                    crate::grpc::model_bundle_op(&engine, op, &r.arg)
                }
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
                                "arg deve conter incident_id, proposal_id e approval_id".to_string()
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
            };
            engine.audit_admin(&operation, result.0, &audit_principal);
            result
        })
        .await
        .map_err(internal)?;
        Ok(Response::new(pb::AdminResponse { ok, message }))
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
    let privacy = heraclitus_compliance::PrivacyIncidentEngine::new(engine.log.clone());
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
    let registry = heraclitus_compliance::DeferredAnchorRegistry::new(engine.log.clone());
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
            Ok(state) => (
                true,
                serde_json::to_string(&state.anchors).unwrap_or_default(),
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
