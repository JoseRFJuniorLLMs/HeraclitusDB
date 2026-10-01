use heraclitus_core::{Episode, EventKind, FsyncPolicy, HeraclitusConfig};
use heraclitus_server::engine::Engine;
use heraclitus_server::trusted_admin::{
    AdminContext, AdminIntent, AdminOperation, AdminOperationKind, AdminState,
};

#[test]
fn durable_intent_without_result_reopens_as_unknown() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = HeraclitusConfig {
        data_dir: dir.path().to_path_buf(),
        fsync: FsyncPolicy::Always,
        ..HeraclitusConfig::default()
    };

    let ctx = AdminContext::new("alice", "tenant", vec!["admin".into()]);
    let mut op = AdminOperation::new(
        "op-crash-window",
        "idem-crash-window",
        AdminOperationKind::Custom {
            name: "crash-probe".into(),
            details: "intent persisted, result absent".into(),
        },
        "restart recovery test",
    );
    op.parameters_digest = "params".into();
    let intent = AdminIntent {
        operation_id: op.operation_id.clone(),
        idempotency_key: op.idempotency_key.clone(),
        intent_digest: op.compute_intent_digest(&ctx),
        principal: ctx.principal.clone(),
        tenant: ctx.tenant.clone(),
        kind: op.kind.clone(),
        target_digest: op.target_digest.clone(),
        parameters_digest: op.parameters_digest.clone(),
        reason: op.reason.clone(),
        approval_policy: op.approval_policy.clone(),
        requested_at_secs: ctx.requested_at_secs,
        approver_count: 0,
    };

    {
        let engine = Engine::open(&cfg).unwrap();
        let mut episode = Episode::new(
            "heraclitus-trusted-admin",
            EventKind::Custom("TrustedAdminIntent".into()),
            serde_json::to_vec(&intent).unwrap(),
        );
        episode.attrs.insert("audit".into(), "trusted-admin".into());
        episode.attrs.insert("protocol".into(), "SPEC-0089".into());

        // Simula o estado em disco depois de Durable Intent + crash antes do
        // Result. Vai direto ao backend deliberadamente: o Engine público deve
        // rejeitar exatamente este namespace.
        heraclitus_log::EpisodeLog::append(engine.log.as_ref(), episode).unwrap();
        heraclitus_log::EpisodeLog::flush(engine.log.as_ref()).unwrap();
    }

    let reopened = Engine::open(&cfg).unwrap();
    assert_eq!(
        reopened
            .trusted_admin()
            .get_operation_state("idem-crash-window"),
        Some(AdminState::Unknown)
    );
    let (_, intent_lsn, result_lsn, _) = reopened
        .trusted_admin()
        .query_idempotency("idem-crash-window")
        .expect("intent must be reconstructed");
    assert_eq!(intent_lsn, 0);
    assert!(result_lsn.is_none());
}


#[test]
fn public_append_rejects_forged_trusted_admin_records() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = HeraclitusConfig {
        data_dir: dir.path().to_path_buf(),
        fsync: FsyncPolicy::Always,
        ..HeraclitusConfig::default()
    };
    let engine = Engine::open(&cfg).unwrap();

    let mut forged = Episode::new(
        "writer",
        EventKind::Custom("TrustedAdminIntent".into()),
        b"{}".to_vec(),
    );
    forged.attrs.insert("audit".into(), "trusted-admin".into());
    forged.attrs.insert("protocol".into(), "SPEC-0089".into());

    let error = engine.append(forged).unwrap_err();
    assert!(
        error.to_string().contains("TrustedAdmin"),
        "append externo deve explicar o namespace reservado: {error}"
    );
}
