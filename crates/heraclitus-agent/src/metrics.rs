//! SPEC-0074 §21 e SPEC-0075 §30 — os nomes das métricas, definidos uma vez.
//!
//! # Porque constantes e não literais espalhados
//!
//! Pelo mesmo motivo que [`heraclitus_core::EventKind::label`] existe: a partir
//! do momento em que um dashboard consulta `agent_ingest_events_total` e o
//! código emite `agent_ingest_event_total`, o painel mostra zero sobre um
//! sistema que está a trabalhar — e ninguém vê o erro, porque "zero" é um valor
//! plausível.
//!
//! # A regra de segurança das etiquetas
//!
//! Nenhuma etiqueta de métrica leva segredo, argumento de ferramenta, prompt ou
//! identificador de pessoa (SPEC-0075 §32: "nenhum segredo aparece em ... metrics
//! labels"). As dimensões permitidas são as de [`SAFE_LABELS`] — e são todas de
//! cardinalidade limitada, que é a outra razão para as restringir: uma etiqueta
//! com `tool_call_id` faria a série temporal crescer sem tecto.

/// Contadores de ingestão.
pub const INGEST_EVENTS_TOTAL: &str = "agent_ingest_events_total";
pub const INGEST_REJECTED_TOTAL: &str = "agent_ingest_rejected_total";
pub const INGEST_DUPLICATES_TOTAL: &str = "agent_ingest_duplicates_total";
pub const INGEST_CONFLICTS_TOTAL: &str = "agent_ingest_conflicts_total";
pub const INGEST_IGNORED_TOTAL: &str = "agent_ingest_ignored_total";
pub const INGEST_QUEUE_DEPTH: &str = "agent_ingest_queue_depth";
pub const INGEST_LAG_SECONDS: &str = "agent_ingest_lag_seconds";
pub const REDACTIONS_TOTAL: &str = "agent_redactions_total";

/// Contadores de produto.
pub const RUNS_TOTAL: &str = "agent_runs_total";
pub const TOOL_CALLS_TOTAL: &str = "agent_tool_calls_total";
pub const BUNDLE_EXPORTS_TOTAL: &str = "agent_bundle_exports_total";
pub const BUNDLE_VERIFY_FAILURES_TOTAL: &str = "agent_bundle_verify_failures_total";

/// Histogramas.
pub const INGEST_LATENCY_SECONDS: &str = "agent_ingest_latency_seconds";
pub const BUNDLE_BUILD_SECONDS: &str = "agent_bundle_build_seconds";
pub const PROOF_BUILD_SECONDS: &str = "agent_proof_build_seconds";

/// Gateway (SPEC-0075 §30).
pub const GATEWAY_REQUESTS_TOTAL: &str = "agent_gateway_requests_total";
pub const GATEWAY_ALLOW_TOTAL: &str = "agent_gateway_allow_total";
pub const GATEWAY_DENY_TOTAL: &str = "agent_gateway_deny_total";
pub const GATEWAY_REQUIRE_APPROVAL_TOTAL: &str = "agent_gateway_require_approval_total";
pub const GATEWAY_SHADOW_DENY_TOTAL: &str = "agent_gateway_shadow_deny_total";
pub const GATEWAY_APPROVAL_PENDING: &str = "agent_gateway_approval_pending";
pub const GATEWAY_APPROVAL_EXPIRED_TOTAL: &str = "agent_gateway_approval_expired_total";
pub const GATEWAY_APPROVAL_REPLAY_REJECTED_TOTAL: &str =
    "agent_gateway_approval_replay_rejected_total";
pub const GATEWAY_POLICY_ERRORS_TOTAL: &str = "agent_gateway_policy_errors_total";
pub const GATEWAY_UPSTREAM_ERRORS_TOTAL: &str = "agent_gateway_upstream_errors_total";

/// Latências do gateway.
pub const POLICY_EVALUATION_SECONDS: &str = "agent_gateway_policy_evaluation_seconds";
pub const APPROVAL_WAIT_SECONDS: &str = "agent_gateway_approval_wait_seconds";
pub const GATEWAY_ADDED_LATENCY_SECONDS: &str = "agent_gateway_added_latency_seconds";
pub const UPSTREAM_TOOL_LATENCY_SECONDS: &str = "agent_gateway_upstream_tool_latency_seconds";

/// As únicas dimensões que podem virar etiqueta.
pub const SAFE_LABELS: &[&str] = &[
    "tenant",
    "source_kind",
    "decision",
    "mode",
    "kind",
    "server",
    "tool",
    "outcome",
];

/// Recusa etiquetas fora da allowlist. Devolve `None` quando a etiqueta não é
/// segura, para que quem chama tenha de decidir conscientemente o que fazer em
/// vez de a emitir por omissão.
pub fn safe_label(name: &str) -> Option<&'static str> {
    SAFE_LABELS.iter().copied().find(|l| *l == name)
}

/// Contadores acumulados por um ingestor, para expor sem depender de um
/// registo global de métricas.
#[derive(Debug, Default, Clone, Copy, serde::Serialize, serde::Deserialize)]
pub struct IngestCounters {
    pub events: u64,
    pub rejected: u64,
    pub duplicates: u64,
    pub conflicts: u64,
    pub ignored: u64,
    pub redactions: u64,
    pub batches: u64,
    pub bytes: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn os_nomes_seguem_o_prefixo_do_produto() {
        for n in [
            INGEST_EVENTS_TOTAL,
            RUNS_TOTAL,
            GATEWAY_DENY_TOTAL,
            BUNDLE_BUILD_SECONDS,
        ] {
            assert!(n.starts_with("agent_"), "{n}");
        }
    }

    #[test]
    fn etiquetas_perigosas_sao_recusadas() {
        assert!(safe_label("tool").is_some());
        assert!(safe_label("human_subject").is_none());
        assert!(safe_label("tool_call_id").is_none());
        assert!(safe_label("prompt").is_none());
        assert!(safe_label("authorization").is_none());
    }
}
