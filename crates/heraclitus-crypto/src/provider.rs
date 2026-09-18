use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use rand::RngCore;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

/// Identificador de Tenant validado (SPEC-0086 §10).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TenantId(String);

impl TenantId {
    /// Cria um novo TenantId
    pub fn new(id: String) -> Result<Self, String> {
        if id.trim().is_empty() {
            Err("Tenant ID não pode ser vazio".into())
        } else {
            Ok(Self(id))
        }
    }

    /// Retorna como string
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Referência a uma chave do provedor (SPEC-0086 §3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyRef {
    pub tenant: TenantId,
    pub key_id: String,
    pub epoch: u64,
}

/// Capacidades do provedor de chaves (SPEC-0086 §3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyCapabilities {
    pub hardware_backed: bool,
    pub non_exportable: bool,
    pub supported_algorithms: Vec<String>,
    pub fips_mode: bool,
}

/// Saúde do provedor (SPEC-0086 §3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyProviderHealth {
    Ready,
    Degraded(String),
    Locked,
    TokenAbsent,
    Unavailable(String),
}

/// Chave de dados encapsulada (SPEC-0086 §3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WrappedDataKey {
    pub key_ref: KeyRef,
    pub wrapped_ciphertext: Vec<u8>,
    pub wrapping_algorithm: String,
    pub created_at_secs: u64,
}

/// Recibo de destruição de chave (SPEC-0086 §3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DestroyReceipt {
    pub key_ref: KeyRef,
    pub destroyed_at_secs: u64,
    pub provider_signature: Option<String>,
    pub proof_digest: String,
}

/// Envelope de encriptação versão 2 (SPEC-0086 §6).
///
/// Carrega metadados estruturais explícitos de tenant, chave e epoch,
/// sem depender de heurística de magic prefix.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptionEnvelopeV2 {
    pub version: u16,
    pub tenant: TenantId,
    pub key_id: String,
    pub key_epoch: u64,
    pub algorithm: String,
    pub nonce: [u8; 12],
    pub aad_digest: [u8; 32],
    pub ciphertext: Vec<u8>,
}

impl EncryptionEnvelopeV2 {
    /// Sela dados e cria o envelope binário V2.
    pub fn seal(
        key: &[u8; 32],
        plaintext: &[u8],
        aad: &[u8],
        tenant: TenantId,
        key_id: String,
        epoch: u64,
    ) -> Vec<u8> {
        let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
        let mut nonce = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce);

        let aad_digest = *blake3::hash(aad).as_bytes();

        let ct = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .expect("chacha20poly1305 encrypt nunca falha para chave/nonce validos");

        let mut result = Vec::new();
        // version = 2 (u16)
        result.extend_from_slice(&2u16.to_be_bytes());

        // tenant (tamanho + bytes)
        let tenant_bytes = tenant.as_str().as_bytes();
        result.extend_from_slice(&(tenant_bytes.len() as u16).to_be_bytes());
        result.extend_from_slice(tenant_bytes);

        // key_id
        let key_id_bytes = key_id.as_bytes();
        result.extend_from_slice(&(key_id_bytes.len() as u16).to_be_bytes());
        result.extend_from_slice(key_id_bytes);

        // key_epoch
        result.extend_from_slice(&epoch.to_be_bytes());

        // algorithm
        let algo = "ChaCha20-Poly1305";
        let algo_bytes = algo.as_bytes();
        result.extend_from_slice(&(algo_bytes.len() as u16).to_be_bytes());
        result.extend_from_slice(algo_bytes);

        // nonce
        result.extend_from_slice(&nonce);

        // aad_digest
        result.extend_from_slice(&aad_digest);

        // ciphertext
        result.extend_from_slice(&ct);

        result
    }

    /// Abre o envelope binário V2 e retorna os dados em texto plano.
    pub fn open(key: &[u8; 32], envelope_bytes: &[u8], expected_aad: &[u8]) -> Option<Vec<u8>> {
        if envelope_bytes.len() < 2 {
            return None;
        }

        let mut offset = 0;
        let version = u16::from_be_bytes(envelope_bytes[offset..offset + 2].try_into().ok()?);
        offset += 2;
        if version != 2 {
            return None;
        }

        // tenant
        if envelope_bytes.len() < offset + 2 {
            return None;
        }
        let tenant_len = u16::from_be_bytes(envelope_bytes[offset..offset + 2].try_into().ok()?) as usize;
        offset += 2;
        if envelope_bytes.len() < offset + tenant_len {
            return None;
        }
        let _tenant_str = std::str::from_utf8(&envelope_bytes[offset..offset + tenant_len]).ok()?;
        offset += tenant_len;

        // key_id
        if envelope_bytes.len() < offset + 2 {
            return None;
        }
        let key_id_len = u16::from_be_bytes(envelope_bytes[offset..offset + 2].try_into().ok()?) as usize;
        offset += 2;
        if envelope_bytes.len() < offset + key_id_len {
            return None;
        }
        let _key_id_str = std::str::from_utf8(&envelope_bytes[offset..offset + key_id_len]).ok()?;
        offset += key_id_len;

        // key_epoch
        if envelope_bytes.len() < offset + 8 {
            return None;
        }
        let _epoch = u64::from_be_bytes(envelope_bytes[offset..offset + 8].try_into().ok()?);
        offset += 8;

        // algorithm
        if envelope_bytes.len() < offset + 2 {
            return None;
        }
        let algo_len = u16::from_be_bytes(envelope_bytes[offset..offset + 2].try_into().ok()?) as usize;
        offset += 2;
        if envelope_bytes.len() < offset + algo_len {
            return None;
        }
        let _algo_str = std::str::from_utf8(&envelope_bytes[offset..offset + algo_len]).ok()?;
        offset += algo_len;

        // nonce (12 bytes)
        if envelope_bytes.len() < offset + 12 {
            return None;
        }
        let nonce = &envelope_bytes[offset..offset + 12];
        offset += 12;

        // aad_digest (32 bytes)
        if envelope_bytes.len() < offset + 32 {
            return None;
        }
        let aad_digest = &envelope_bytes[offset..offset + 32];
        offset += 32;

        // Verificar aad_digest com BLAKE3
        let expected_digest = *blake3::hash(expected_aad).as_bytes();
        if aad_digest != expected_digest {
            return None;
        }

        let ct = &envelope_bytes[offset..];
        let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
        cipher
            .decrypt(
                Nonce::from_slice(nonce),
                Payload {
                    msg: ct,
                    aad: expected_aad,
                },
            )
            .ok()
    }
}

/// Traço para provedores de chaves
pub trait KeyProvider: Send + Sync {
    fn provider_id(&self) -> &str;
    fn capabilities(&self) -> KeyCapabilities;
    fn generate_data_key(&self, tenant: &TenantId) -> Result<(KeyRef, [u8; 32]), String>;
    fn unwrap_data_key(&self, key: &WrappedDataKey) -> Result<[u8; 32], String>;
    fn rotate(&self, tenant: &TenantId) -> Result<KeyRef, String>;
    fn destroy(&self, key: &KeyRef) -> Result<DestroyReceipt, String>;
    fn health(&self) -> KeyProviderHealth;
}

/// Provedor de chaves baseado em software para testes e dev
pub struct SoftwareKeyProvider {
    master_keys: Arc<Mutex<HashMap<TenantId, [u8; 32]>>>,
    epochs: Arc<Mutex<HashMap<TenantId, u64>>>,
}

impl SoftwareKeyProvider {
    /// Cria uma nova instância de SoftwareKeyProvider
    pub fn new() -> Self {
        Self {
            master_keys: Arc::new(Mutex::new(HashMap::new())),
            epochs: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    #[allow(dead_code)]
    fn get_or_create_master_key(&self, tenant: &TenantId) -> [u8; 32] {
        let mut keys = self.master_keys.lock().unwrap();
        if let Some(k) = keys.get(tenant) {
            *k
        } else {
            let mut new_key = [0u8; 32];
            rand::thread_rng().fill_bytes(&mut new_key);
            keys.insert(tenant.clone(), new_key);
            new_key
        }
    }
    
    fn get_epoch(&self, tenant: &TenantId) -> u64 {
        let mut epochs = self.epochs.lock().unwrap();
        *epochs.entry(tenant.clone()).or_insert(1)
    }
    
    fn increment_epoch(&self, tenant: &TenantId) -> u64 {
        let mut epochs = self.epochs.lock().unwrap();
        let e = epochs.entry(tenant.clone()).or_insert(1);
        *e += 1;
        *e
    }
}

impl Default for SoftwareKeyProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl KeyProvider for SoftwareKeyProvider {
    fn provider_id(&self) -> &str {
        "software-v1"
    }

    fn capabilities(&self) -> KeyCapabilities {
        KeyCapabilities {
            hardware_backed: false,
            non_exportable: false,
            supported_algorithms: vec!["ChaCha20-Poly1305".to_string()],
            fips_mode: false,
        }
    }

    fn generate_data_key(&self, tenant: &TenantId) -> Result<(KeyRef, [u8; 32]), String> {
        let mut data_key = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut data_key);
        
        let epoch = self.get_epoch(tenant);
        
        let key_ref = KeyRef {
            tenant: tenant.clone(),
            key_id: format!("{}-key-{}", tenant.as_str(), epoch),
            epoch,
        };
        
        Ok((key_ref, data_key))
    }

    fn unwrap_data_key(&self, _key: &WrappedDataKey) -> Result<[u8; 32], String> {
        Err("Não implementado para SoftwareKeyProvider na versão base".into())
    }

    fn rotate(&self, tenant: &TenantId) -> Result<KeyRef, String> {
        let epoch = self.increment_epoch(tenant);
        
        let mut keys = self.master_keys.lock().unwrap();
        let mut new_key = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut new_key);
        keys.insert(tenant.clone(), new_key);
        
        Ok(KeyRef {
            tenant: tenant.clone(),
            key_id: format!("{}-key-{}", tenant.as_str(), epoch),
            epoch,
        })
    }

    fn destroy(&self, key: &KeyRef) -> Result<DestroyReceipt, String> {
        Ok(DestroyReceipt {
            key_ref: key.clone(),
            destroyed_at_secs: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
            provider_signature: None,
            proof_digest: "dummy-proof".into(),
        })
    }

    fn health(&self) -> KeyProviderHealth {
        KeyProviderHealth::Ready
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_software_key_provider() {
        let provider = SoftwareKeyProvider::new();
        let tenant = TenantId::new("tenant-1".to_string()).unwrap();
        
        assert_eq!(provider.provider_id(), "software-v1");
        assert_eq!(provider.health(), KeyProviderHealth::Ready);
        
        let (key_ref, _data_key) = provider.generate_data_key(&tenant).unwrap();
        assert_eq!(key_ref.tenant, tenant);
        assert_eq!(key_ref.epoch, 1);
        
        let rotated_ref = provider.rotate(&tenant).unwrap();
        assert_eq!(rotated_ref.epoch, 2);
        
        let receipt = provider.destroy(&rotated_ref).unwrap();
        assert_eq!(receipt.key_ref.epoch, 2);
    }
    
    #[test]
    fn test_encryption_envelope_v2() {
        let tenant = TenantId::new("tenant-abc".to_string()).unwrap();
        let key_id = "key-123".to_string();
        let epoch = 1;
        
        let mut key = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut key);
        
        let plaintext = b"Mensagem ultra secreta!";
        let aad = b"Contexto de autenticacao";
        
        let envelope_bytes = EncryptionEnvelopeV2::seal(
            &key,
            plaintext,
            aad,
            tenant,
            key_id,
            epoch
        );
        
        let opened = EncryptionEnvelopeV2::open(&key, &envelope_bytes, aad).expect("Falha ao abrir o envelope");
        assert_eq!(opened, plaintext);
        
        // AAD errado deve falhar
        let wrong_aad = b"Contexto alterado";
        let opened_wrong = EncryptionEnvelopeV2::open(&key, &envelope_bytes, wrong_aad);
        assert!(opened_wrong.is_none());
    }
}
