//! Versioned authorization of an external, idempotent consumer transaction.
//! The AdminIntent/Result here records authorization, never claims the external
//! effect happened. Only an explicit consumer result closes the external state.
use crate::{
    trusted_admin::{AdminContext, AdminOperation, AdminOperationKind},
    Engine,
};
use heraclitus_core::HeraclitusError;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Intent {
    pub version: u32,
    pub operation_id: String,
    pub consumer: String,
    pub source_sequence: u64,
    pub payload_digest: String,
    pub expires_ms: u64,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Receipt {
    pub intent: Intent,
    pub principal: String,
    pub tenant: String,
    pub intent_lsn: u64,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Completion {
    pub receipt: Receipt,
    pub applied: bool,
    pub local_sequence: u64,
    pub result_digest: String,
}
fn error(message: &str) -> HeraclitusError {
    HeraclitusError::Config(message.into())
}
fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}
fn operation(
    phase: &str,
    id: &str,
    value: &impl Serialize,
) -> Result<AdminOperation, HeraclitusError> {
    let details = serde_json::to_string(value).map_err(|e| error(&e.to_string()))?;
    let key = format!("external-v1/{phase}/{id}");
    let mut op = AdminOperation::new(
        key.clone(),
        key,
        AdminOperationKind::Custom {
            name: format!("external-{phase}-v1"),
            details: details.clone(),
        },
        "authenticated external consumer transaction",
    );
    op.parameters_digest = blake3::hash(details.as_bytes()).to_hex().to_string();
    Ok(op)
}
impl Engine {
    pub(crate) fn external_intent(
        &self,
        ctx: &AdminContext,
        intent: Intent,
    ) -> Result<Receipt, HeraclitusError> {
        if intent.version != 1
            || intent.consumer != "MachiavelliDB"
            || intent.operation_id.is_empty()
            || intent.operation_id.len() > 128
            || intent
                .operation_id
                .bytes()
                .any(|b| !b.is_ascii_alphanumeric() && b != b'-')
            || intent.payload_digest.len() != 64
            || !intent.payload_digest.bytes().all(|b| b.is_ascii_hexdigit())
        {
            return Err(error("invalid external intent v1"));
        }
        let op = operation("intent", &intent.operation_id, &intent)?;
        // A retry may recover an old receipt after expiry. Consumers must check
        // expiry immediately before committing; status/results remain available.
        if self
            .trusted_admin
            .external_value(ctx, &op.idempotency_key)?
            .is_none()
            && (intent.expires_ms <= now_ms()
                || intent.expires_ms.saturating_sub(now_ms()) > 300_000)
        {
            return Err(error("external intent expiry must be within 5 minutes"));
        }
        self.execute_admin(ctx, &op, |token| {
            Ok(Receipt {
                intent,
                principal: ctx.principal.clone(),
                tenant: ctx.tenant.clone(),
                intent_lsn: token.intent_lsn(),
            })
        })
    }
    pub(crate) fn external_status(
        &self,
        ctx: &AdminContext,
        id: &str,
    ) -> Result<serde_json::Value, HeraclitusError> {
        let receipt = self
            .trusted_admin
            .external_value(ctx, &format!("external-v1/intent/{id}"))?;
        let result = self
            .trusted_admin
            .external_value(ctx, &format!("external-v1/result/{id}"))?;
        Ok(
            serde_json::json!({"version":1,"receipt":receipt,"result":result,
            "state":if result.is_some(){"completed"}else if receipt.is_some(){"authorized"}else{"absent"}}),
        )
    }
    pub(crate) fn external_result(
        &self,
        ctx: &AdminContext,
        result: Completion,
    ) -> Result<Completion, HeraclitusError> {
        let saved = self
            .trusted_admin
            .external_value(
                ctx,
                &format!("external-v1/intent/{}", result.receipt.intent.operation_id),
            )?
            .ok_or_else(|| error("external intent absent"))?;
        let expected = serde_json::to_value(&result.receipt).map_err(|e| error(&e.to_string()))?;
        if saved != expected
            || result.result_digest.len() != 64
            || !result.result_digest.bytes().all(|b| b.is_ascii_hexdigit())
            || result.local_sequence <= result.receipt.intent.source_sequence
        {
            return Err(error(
                "external result does not bind the durable authorization",
            ));
        }
        let op = operation("result", &result.receipt.intent.operation_id, &result)?;
        self.execute_admin(ctx, &op, |_| Ok(result))
    }
    pub(crate) fn external_rpc(
        &self,
        ctx: &AdminContext,
        phase: &str,
        arg: &str,
    ) -> Result<String, HeraclitusError> {
        if ctx.principal == "local-loopback" {
            return Err(error(
                "external authorization requires configured authenticated credentials",
            ));
        }
        let parse = |e: serde_json::Error| error(&e.to_string());
        let value = match phase {
            "external-intent-v1" => serde_json::to_value(
                self.external_intent(ctx, serde_json::from_str(arg).map_err(parse)?)?,
            )
            .map_err(parse)?,
            "external-result-v1" => serde_json::to_value(
                self.external_result(ctx, serde_json::from_str(arg).map_err(parse)?)?,
            )
            .map_err(parse)?,
            "external-status-v1" => {
                #[derive(Deserialize)]
                #[serde(deny_unknown_fields)]
                struct Status {
                    operation_id: String,
                }
                let status: Status = serde_json::from_str(arg).map_err(parse)?;
                self.external_status(ctx, &status.operation_id)?
            }
            _ => return Err(error("unknown external protocol operation")),
        };
        serde_json::to_string(&value).map_err(parse)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn context(name: &str) -> AdminContext {
        AdminContext::new(name, "local", vec!["admin".into()])
    }
    #[test]
    fn authorization_and_consumer_result_survive_restart_are_scoped_and_conflict_safe() {
        let dir = tempfile::tempdir().unwrap();
        let config = heraclitus_core::HeraclitusConfig {
            data_dir: dir.path().to_path_buf(),
            ..Default::default()
        };
        let intent = Intent {
            version: 1,
            operation_id: "transaction-1".into(),
            consumer: "MachiavelliDB".into(),
            source_sequence: 7,
            payload_digest: blake3::hash(b"bound transaction").to_hex().to_string(),
            expires_ms: now_ms() + 60_000,
        };
        let engine = Engine::open(&config).unwrap();
        let receipt = engine
            .external_intent(&context("consumer"), intent.clone())
            .unwrap();
        // Heraclitus LSNs are zero-based.
        assert_eq!(receipt.intent_lsn, 0);
        assert_eq!(
            engine
                .external_intent(&context("consumer"), intent.clone())
                .unwrap(),
            receipt
        );
        assert_eq!(
            engine
                .external_status(&context("other"), &intent.operation_id)
                .unwrap()["state"],
            "absent"
        );
        let mut changed = intent.clone();
        changed.payload_digest = blake3::hash(b"other").to_hex().to_string();
        assert!(engine
            .external_intent(&context("consumer"), changed)
            .is_err());
        let mut reader = context("consumer");
        reader.roles = vec!["reader".into()];
        assert!(engine.external_intent(&reader, intent.clone()).is_err());
        drop(engine);
        let engine = Engine::open(&config).unwrap();
        assert_eq!(
            engine
                .external_status(&context("consumer"), &intent.operation_id)
                .unwrap()["state"],
            "authorized"
        );
        let completion = Completion {
            receipt,
            applied: true,
            local_sequence: 9,
            result_digest: intent.payload_digest.clone(),
        };
        engine
            .external_result(&context("consumer"), completion.clone())
            .unwrap();
        engine
            .external_result(&context("consumer"), completion.clone())
            .unwrap();
        let mut conflict = completion;
        conflict.applied = false;
        assert!(engine
            .external_result(&context("consumer"), conflict)
            .is_err());
        drop(engine);
        let engine = Engine::open(&config).unwrap();
        assert_eq!(
            engine
                .external_status(&context("consumer"), &intent.operation_id)
                .unwrap()["result"]["applied"],
            true
        );
    }
}
