use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

/// Modos de retenção suportados.
#[derive(Debug, Clone, PartialEq)]
pub enum RetentionMode {
    LocalOnly,
    RemoteVersioned,
    WormGovernance,
    WormCompliance,
    OfflineArchive,
}

/// Política de retenção aplicada a um objeto.
#[derive(Debug, Clone, PartialEq)]
pub struct RetentionPolicy {
    pub mode: RetentionMode,
    pub retain_until_secs: u64,
    pub legal_hold: bool,
    pub reason: String,
}

/// Status de retenção de um objeto.
#[derive(Debug, Clone, PartialEq)]
pub enum RetentionStatus {
    ActiveUntil(u64),
    IndefiniteLegalHold,
    Expired,
    Unprotected,
}

/// Metadados de um objeto imutável.
#[derive(Debug, Clone, PartialEq)]
pub struct ImmutableMetadata {
    pub object_id: String,
    pub size_bytes: u64,
    pub physical_digest: String,
    pub retention_status: RetentionStatus,
    pub created_at_secs: u64,
}

/// Recibo gerado ao armazenar um objeto.
#[derive(Debug, Clone, PartialEq)]
pub struct ImmutableReceipt {
    pub object_id: String,
    pub logical_root: String,
    pub physical_digest: String,
    pub backend_id: String,
    pub retention_mode: RetentionMode,
    pub retain_until_secs: u64,
    pub request_digest: String,
    pub response_digest: String,
    pub trusted_time_secs: u64,
}

/// Interface para armazenamento de objetos imutáveis com políticas de retenção.
pub trait ImmutableStore: Send + Sync {
    fn put_immutable(&self, object_id: &str, data: &[u8], retention: &RetentionPolicy) -> Result<ImmutableReceipt, String>;
    fn head(&self, object_id: &str) -> Result<ImmutableMetadata, String>;
    fn verify_retention(&self, object_id: &str) -> Result<RetentionStatus, String>;
    fn set_legal_hold(&self, object_id: &str, hold: bool, reason: &str) -> Result<ImmutableReceipt, String>;
}

#[derive(Clone)]
struct Record {
    data: Vec<u8>,
    metadata: ImmutableMetadata,
    policy: RetentionPolicy,
    receipt: ImmutableReceipt,
}

/// Implementação local em memória com rastreamento de imutabilidade e retenção.
pub struct LocalWormBackend {
    store: Arc<RwLock<HashMap<String, Record>>>,
}

impl LocalWormBackend {
    pub fn new() -> Self {
        Self {
            store: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    fn current_time_secs() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }
    
    fn compute_digest(data: &[u8]) -> String {
        blake3::hash(data).to_hex().to_string()
    }

    /// Recupera os dados binários do objeto armazenado.
    pub fn get_data(&self, object_id: &str) -> Result<Vec<u8>, String> {
        let store = self.store.read().map_err(|_| "Falha ao adquirir o lock".to_string())?;
        if let Some(record) = store.get(object_id) {
            Ok(record.data.clone())
        } else {
            Err("Objeto não encontrado".to_string())
        }
    }

    fn eval_retention(policy: &RetentionPolicy, now_secs: u64) -> RetentionStatus {
        if policy.legal_hold {
            RetentionStatus::IndefiniteLegalHold
        } else if policy.retain_until_secs > now_secs {
            RetentionStatus::ActiveUntil(policy.retain_until_secs)
        } else if policy.retain_until_secs > 0 {
            RetentionStatus::Expired
        } else {
            RetentionStatus::Unprotected
        }
    }
}

impl Default for LocalWormBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl ImmutableStore for LocalWormBackend {
    fn put_immutable(
        &self,
        object_id: &str,
        data: &[u8],
        retention: &RetentionPolicy,
    ) -> Result<ImmutableReceipt, String> {
        let mut store = self.store.write().map_err(|_| "Falha ao adquirir o lock".to_string())?;

        // WORM: não permite sobrescrever um objeto que já existe
        if store.contains_key(object_id) {
            return Err("WORM object cannot be overwritten".to_string());
        }

        let time_secs = Self::current_time_secs();
        let digest = Self::compute_digest(data);

        let status = Self::eval_retention(retention, time_secs);

        let metadata = ImmutableMetadata {
            object_id: object_id.to_string(),
            size_bytes: data.len() as u64,
            physical_digest: digest.clone(),
            retention_status: status.clone(),
            created_at_secs: time_secs,
        };

        let receipt = ImmutableReceipt {
            object_id: object_id.to_string(),
            logical_root: "local_root".to_string(),
            physical_digest: digest.clone(),
            backend_id: "local_worm_1".to_string(),
            retention_mode: retention.mode.clone(),
            retain_until_secs: retention.retain_until_secs,
            request_digest: "req_digest".to_string(),
            response_digest: "res_digest".to_string(),
            trusted_time_secs: time_secs,
        };

        let record = Record {
            data: data.to_vec(),
            metadata,
            policy: retention.clone(),
            receipt: receipt.clone(),
        };

        store.insert(object_id.to_string(), record);

        Ok(receipt)
    }

    fn head(&self, object_id: &str) -> Result<ImmutableMetadata, String> {
        let store = self.store.read().map_err(|_| "Falha ao adquirir o lock".to_string())?;
        if let Some(record) = store.get(object_id) {
            let mut meta = record.metadata.clone();
            meta.retention_status = Self::eval_retention(&record.policy, Self::current_time_secs());
            Ok(meta)
        } else {
            Err("Objeto não encontrado".to_string())
        }
    }

    fn verify_retention(&self, object_id: &str) -> Result<RetentionStatus, String> {
        let store = self.store.read().map_err(|_| "Falha ao adquirir o lock".to_string())?;
        if let Some(record) = store.get(object_id) {
            Ok(Self::eval_retention(&record.policy, Self::current_time_secs()))
        } else {
            Err("Objeto não encontrado".to_string())
        }
    }

    fn set_legal_hold(
        &self,
        object_id: &str,
        hold: bool,
        reason: &str,
    ) -> Result<ImmutableReceipt, String> {
        let mut store = self.store.write().map_err(|_| "Falha ao adquirir o lock".to_string())?;
        if let Some(record) = store.get_mut(object_id) {
            record.policy.legal_hold = hold;
            if hold {
                record.policy.reason = reason.to_string();
            } else {
                record.policy.reason.clear();
            }
            record.metadata.retention_status = Self::eval_retention(&record.policy, Self::current_time_secs());
            
            let mut receipt = record.receipt.clone();
            receipt.trusted_time_secs = Self::current_time_secs();
            record.receipt = receipt.clone();

            Ok(receipt)
        } else {
            Err("Objeto não encontrado".to_string())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_put_immutable_and_verify() {
        let store = LocalWormBackend::new();
        let policy = RetentionPolicy {
            mode: RetentionMode::WormCompliance,
            retain_until_secs: LocalWormBackend::current_time_secs() + 10,
            legal_hold: false,
            reason: String::new(),
        };

        let data = b"dados importantes";
        let obj_id = "doc1";

        let receipt = store.put_immutable(obj_id, data, &policy).unwrap();
        assert_eq!(receipt.object_id, obj_id);

        let status = store.verify_retention(obj_id).unwrap();
        match status {
            RetentionStatus::ActiveUntil(_) => {}
            _ => panic!("O status de retenção deveria estar ativo"),
        }
    }

    #[test]
    fn test_overwrite_worm_object_error() {
        let store = LocalWormBackend::new();
        let policy = RetentionPolicy {
            mode: RetentionMode::WormGovernance,
            retain_until_secs: LocalWormBackend::current_time_secs() + 10,
            legal_hold: false,
            reason: String::new(),
        };

        let data = b"dados originais";
        let obj_id = "doc2";

        store.put_immutable(obj_id, data, &policy).unwrap();

        // Tenta sobrescrever o objeto (deve falhar)
        let result = store.put_immutable(obj_id, b"dados alterados", &policy);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "WORM object cannot be overwritten");
    }

    #[test]
    fn test_legal_hold_on_off() {
        let store = LocalWormBackend::new();
        let policy = RetentionPolicy {
            mode: RetentionMode::WormCompliance,
            retain_until_secs: 0, // Sem retenção temporal
            legal_hold: false,
            reason: String::new(),
        };

        let obj_id = "doc3";
        store.put_immutable(obj_id, b"legal hold test", &policy).unwrap();

        // Ativa o legal hold
        store.set_legal_hold(obj_id, true, "investigação").unwrap();
        
        let status_on = store.verify_retention(obj_id).unwrap();
        assert_eq!(status_on, RetentionStatus::IndefiniteLegalHold);

        // Desativa o legal hold
        store.set_legal_hold(obj_id, false, "").unwrap();
        
        let status_off = store.verify_retention(obj_id).unwrap();
        assert_eq!(status_off, RetentionStatus::Unprotected);
    }
}
