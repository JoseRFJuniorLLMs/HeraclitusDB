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

/// API histórica do envelope estruturado (SPEC-0086 §6).
///
/// O formato autenticado atual é **versão 3**. A versão 2 anterior deixava o
/// cabeçalho fora do AAD e, portanto, não pode ser reinterpretada como segura.
/// `open` só aceita v3; compatibilidade v2 exige a função explicitamente
/// nomeada `open_legacy_v2_untrusted_metadata`.
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

/// Cabeçalho estrutural do envelope V2 (legível sem a chave de decifra).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvelopeHeader {
    pub version: u16,
    pub tenant: TenantId,
    pub key_id: String,
    pub key_epoch: u64,
    pub algorithm: String,
    pub nonce: [u8; 12],
    pub aad_digest: [u8; 32],
    pub ciphertext_offset: usize,
}

impl EncryptionEnvelopeV2 {
    const LEGACY_VERSION: u16 = 2;
    const AUTHENTICATED_VERSION: u16 = 3;
    const ALGORITHM: &'static str = "ChaCha20-Poly1305";

    /// Inspeciona e valida o cabeçalho do envelope sem necessidade da chave criptográfica.
    /// Permite descobrir `tenant`, `key_id` e `key_epoch` para requisição ao KMS / KeyProvider.
    pub fn peek_header(envelope_bytes: &[u8]) -> Option<EnvelopeHeader> {
        if envelope_bytes.len() < 2 {
            return None;
        }

        let mut offset = 0;
        let version = u16::from_be_bytes(envelope_bytes[offset..offset + 2].try_into().ok()?);
        offset += 2;
        if !matches!(version, Self::LEGACY_VERSION | Self::AUTHENTICATED_VERSION) {
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
        let tenant_str = std::str::from_utf8(&envelope_bytes[offset..offset + tenant_len]).ok()?;
        let tenant = TenantId::new(tenant_str.to_string()).ok()?;
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
        let key_id = std::str::from_utf8(&envelope_bytes[offset..offset + key_id_len]).ok()?.to_string();
        offset += key_id_len;

        // key_epoch
        if envelope_bytes.len() < offset + 8 {
            return None;
        }
        let key_epoch = u64::from_be_bytes(envelope_bytes[offset..offset + 8].try_into().ok()?);
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
        let algorithm = std::str::from_utf8(&envelope_bytes[offset..offset + algo_len]).ok()?.to_string();
        offset += algo_len;

        // nonce (12 bytes)
        if envelope_bytes.len() < offset + 12 {
            return None;
        }
        let nonce: [u8; 12] = envelope_bytes[offset..offset + 12].try_into().ok()?;
        offset += 12;

        // aad_digest (32 bytes)
        if envelope_bytes.len() < offset + 32 {
            return None;
        }
        let aad_digest: [u8; 32] = envelope_bytes[offset..offset + 32].try_into().ok()?;
        offset += 32;

        Some(EnvelopeHeader {
            version,
            tenant,
            key_id,
            key_epoch,
            algorithm,
            nonce,
            aad_digest,
            ciphertext_offset: offset,
        })
    }

    /// Constrói o AAD canônico interno. O cabeçalho faz parte do compromisso
    /// criptográfico; alterar tenant/key/epoch/algoritmo/nonce invalida a tag.
    fn authenticated_aad(
        version: u16,
        tenant: &TenantId,
        key_id: &str,
        epoch: u64,
        algorithm: &str,
        nonce: &[u8; 12],
        caller_aad: &[u8],
    ) -> Vec<u8> {
        fn push_len_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
            let len = u32::try_from(bytes.len()).expect("campo de AAD excede u32::MAX");
            out.extend_from_slice(&len.to_be_bytes());
            out.extend_from_slice(bytes);
        }

        let mut out = Vec::with_capacity(
            32 + tenant.as_str().len() + key_id.len() + algorithm.len() + caller_aad.len(),
        );
        out.extend_from_slice(b"HeraclitusDB/Envelope/HeaderAAD/v1");
        out.extend_from_slice(&version.to_be_bytes());
        push_len_bytes(&mut out, tenant.as_str().as_bytes());
        push_len_bytes(&mut out, key_id.as_bytes());
        out.extend_from_slice(&epoch.to_be_bytes());
        push_len_bytes(&mut out, algorithm.as_bytes());
        out.extend_from_slice(nonce);
        push_len_bytes(&mut out, caller_aad);
        out
    }

    /// Sela dados no formato autenticado atual (v3).
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
        let bound_aad = Self::authenticated_aad(
            Self::AUTHENTICATED_VERSION,
            &tenant,
            &key_id,
            epoch,
            Self::ALGORITHM,
            &nonce,
            aad,
        );

        let ct = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: plaintext,
                    aad: &bound_aad,
                },
            )
            .expect("chacha20poly1305 encrypt nunca falha para chave/nonce validos");

        let mut result = Vec::new();
        result.extend_from_slice(&Self::AUTHENTICATED_VERSION.to_be_bytes());

        let tenant_bytes = tenant.as_str().as_bytes();
        let tenant_len: u16 = tenant_bytes.len().try_into().expect("tenant id excede u16::MAX");
        result.extend_from_slice(&tenant_len.to_be_bytes());
        result.extend_from_slice(tenant_bytes);

        let key_id_bytes = key_id.as_bytes();
        let key_id_len: u16 = key_id_bytes.len().try_into().expect("key_id excede u16::MAX");
        result.extend_from_slice(&key_id_len.to_be_bytes());
        result.extend_from_slice(key_id_bytes);

        result.extend_from_slice(&epoch.to_be_bytes());

        let algo_bytes = Self::ALGORITHM.as_bytes();
        let algo_len: u16 = algo_bytes.len().try_into().expect("algorithm excede u16::MAX");
        result.extend_from_slice(&algo_len.to_be_bytes());
        result.extend_from_slice(algo_bytes);

        result.extend_from_slice(&nonce);
        result.extend_from_slice(&aad_digest);
        result.extend_from_slice(&ct);
        result
    }

    /// Abre apenas o formato autenticado atual (v3).
    ///
    /// Um envelope v2 nunca é promovido silenciosamente a "seguro": callers que
    /// precisam de migração devem optar explicitamente pela API legacy abaixo.
    pub fn open(key: &[u8; 32], envelope_bytes: &[u8], expected_aad: &[u8]) -> Option<Vec<u8>> {
        let header = Self::peek_header(envelope_bytes)?;
        if header.version != Self::AUTHENTICATED_VERSION || header.algorithm != Self::ALGORITHM {
            return None;
        }

        let expected_digest = *blake3::hash(expected_aad).as_bytes();
        if header.aad_digest != expected_digest {
            return None;
        }

        let bound_aad = Self::authenticated_aad(
            header.version,
            &header.tenant,
            &header.key_id,
            header.key_epoch,
            &header.algorithm,
            &header.nonce,
            expected_aad,
        );

        let ct = &envelope_bytes[header.ciphertext_offset..];
        let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
        cipher
            .decrypt(
                Nonce::from_slice(&header.nonce),
                Payload {
                    msg: ct,
                    aad: &bound_aad,
                },
            )
            .ok()
    }

    /// Compatibilidade explícita com envelopes v2 históricos.
    ///
    /// **Atenção:** v2 autentica apenas o AAD fornecido pelo chamador. Tenant,
    /// key_id, epoch e algorithm do cabeçalho NÃO ficam criptograficamente
    /// vinculados. Use somente para migração/leitura de legado e re-selar como
    /// v3 antes de tratar os metadados como confiáveis.
    pub fn open_legacy_v2_untrusted_metadata(
        key: &[u8; 32],
        envelope_bytes: &[u8],
        expected_aad: &[u8],
    ) -> Option<Vec<u8>> {
        let header = Self::peek_header(envelope_bytes)?;
        if header.version != Self::LEGACY_VERSION || header.algorithm != Self::ALGORITHM {
            return None;
        }
        let expected_digest = *blake3::hash(expected_aad).as_bytes();
        if header.aad_digest != expected_digest {
            return None;
        }

        let ct = &envelope_bytes[header.ciphertext_offset..];
        let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
        cipher
            .decrypt(
                Nonce::from_slice(&header.nonce),
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
    fn wrap_data_key(&self, tenant: &TenantId, data_key: &[u8; 32]) -> Result<WrappedDataKey, String>;
    fn unwrap_data_key(&self, key: &WrappedDataKey) -> Result<[u8; 32], String>;
    fn rotate(&self, tenant: &TenantId) -> Result<KeyRef, String>;
    fn destroy(&self, key: &KeyRef) -> Result<DestroyReceipt, String>;
    fn health(&self) -> KeyProviderHealth;
}

/// Provedor de chaves baseado em software para testes e dev.
///
/// Mantém material de wrapping por época. Rotacionar cria uma nova época sem
/// destruir as anteriores; destruir exige a KeyRef exata.
pub struct SoftwareKeyProvider {
    state: Arc<Mutex<SoftwareKeyState>>,
}

#[derive(Default)]
struct SoftwareKeyState {
    epochs: HashMap<TenantId, u64>,
    master_keys: HashMap<(TenantId, u64), [u8; 32]>,
}

impl SoftwareKeyProvider {
    /// Cria uma nova instância de SoftwareKeyProvider
    pub fn new() -> Self {
        Self {
            state: Arc::new(Mutex::new(SoftwareKeyState::default())),
        }
    }

    fn key_id(tenant: &TenantId, epoch: u64) -> String {
        format!("{}-key-{}", tenant.as_str(), epoch)
    }

    fn current_epoch(state: &mut SoftwareKeyState, tenant: &TenantId) -> u64 {
        *state.epochs.entry(tenant.clone()).or_insert(1)
    }

    fn current_master_key(&self, tenant: &TenantId) -> (KeyRef, [u8; 32]) {
        let mut state = self.state.lock().unwrap();
        let epoch = Self::current_epoch(&mut state, tenant);
        let master = *state
            .master_keys
            .entry((tenant.clone(), epoch))
            .or_insert_with(|| {
                let mut key = [0u8; 32];
                rand::thread_rng().fill_bytes(&mut key);
                key
            });
        (
            KeyRef {
                tenant: tenant.clone(),
                key_id: Self::key_id(tenant, epoch),
                epoch,
            },
            master,
        )
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
        let (key_ref, _) = self.current_master_key(tenant);
        let mut data_key = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut data_key);
        Ok((key_ref, data_key))
    }

    fn wrap_data_key(
        &self,
        tenant: &TenantId,
        data_key: &[u8; 32],
    ) -> Result<WrappedDataKey, String> {
        let (key_ref, master) = self.current_master_key(tenant);
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&master));
        let mut nonce = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce);

        let mut wrap_aad = Vec::new();
        wrap_aad.extend_from_slice(b"HeraclitusDB/SoftwareKeyProvider/wrap/v1");
        wrap_aad.extend_from_slice(key_ref.tenant.as_str().as_bytes());
        wrap_aad.push(0);
        wrap_aad.extend_from_slice(key_ref.key_id.as_bytes());
        wrap_aad.extend_from_slice(&key_ref.epoch.to_be_bytes());

        let ct = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: data_key,
                    aad: &wrap_aad,
                },
            )
            .map_err(|e| format!("wrap error: {e}"))?;
        let mut wrapped = Vec::with_capacity(12 + ct.len());
        wrapped.extend_from_slice(&nonce);
        wrapped.extend_from_slice(&ct);

        Ok(WrappedDataKey {
            key_ref,
            wrapped_ciphertext: wrapped,
            wrapping_algorithm: "ChaCha20-Poly1305".into(),
            created_at_secs: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        })
    }

    fn unwrap_data_key(&self, key: &WrappedDataKey) -> Result<[u8; 32], String> {
        if key.key_ref.key_id != Self::key_id(&key.key_ref.tenant, key.key_ref.epoch) {
            return Err("KeyRef inconsistente: key_id não corresponde ao tenant/epoch".into());
        }
        if key.wrapping_algorithm != "ChaCha20-Poly1305" {
            return Err(format!(
                "algoritmo de wrapping não suportado: {}",
                key.wrapping_algorithm
            ));
        }

        let master = {
            let state = self.state.lock().unwrap();
            state
                .master_keys
                .get(&(key.key_ref.tenant.clone(), key.key_ref.epoch))
                .copied()
                .ok_or_else(|| {
                    format!(
                        "Chave mestre {} época {} não encontrada (destruída ou inexistente)",
                        key.key_ref.key_id, key.key_ref.epoch
                    )
                })?
        };

        if key.wrapped_ciphertext.len() < 12 {
            return Err("ciphertext encapsulado inválido (menor que nonce)".into());
        }
        let nonce = &key.wrapped_ciphertext[..12];
        let ct = &key.wrapped_ciphertext[12..];

        let mut wrap_aad = Vec::new();
        wrap_aad.extend_from_slice(b"HeraclitusDB/SoftwareKeyProvider/wrap/v1");
        wrap_aad.extend_from_slice(key.key_ref.tenant.as_str().as_bytes());
        wrap_aad.push(0);
        wrap_aad.extend_from_slice(key.key_ref.key_id.as_bytes());
        wrap_aad.extend_from_slice(&key.key_ref.epoch.to_be_bytes());

        let cipher = ChaCha20Poly1305::new(Key::from_slice(&master));
        let pt = cipher
            .decrypt(
                Nonce::from_slice(nonce),
                Payload {
                    msg: ct,
                    aad: &wrap_aad,
                },
            )
            .map_err(|e| format!("desencapsulamento falhou: {e}"))?;
        pt.try_into()
            .map_err(|_| "tamanho de chave desencapsulada incorreto".into())
    }

    fn rotate(&self, tenant: &TenantId) -> Result<KeyRef, String> {
        let mut state = self.state.lock().unwrap();
        let current = Self::current_epoch(&mut state, tenant);
        let epoch = current
            .checked_add(1)
            .ok_or_else(|| "epoch de chave excedeu u64::MAX".to_string())?;
        state.epochs.insert(tenant.clone(), epoch);

        let mut new_key = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut new_key);
        state.master_keys.insert((tenant.clone(), epoch), new_key);

        Ok(KeyRef {
            tenant: tenant.clone(),
            key_id: Self::key_id(tenant, epoch),
            epoch,
        })
    }

    fn destroy(&self, key: &KeyRef) -> Result<DestroyReceipt, String> {
        if key.key_id != Self::key_id(&key.tenant, key.epoch) {
            return Err("KeyRef inconsistente: recusa destruir chave diferente da referência".into());
        }

        let existed = self
            .state
            .lock()
            .unwrap()
            .master_keys
            .remove(&(key.tenant.clone(), key.epoch))
            .is_some();
        let destroyed_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let mut hasher = blake3::Hasher::new();
        hasher.update(b"HeraclitusDB/SoftwareKeyProvider/destroy-receipt/v1");
        hasher.update(key.tenant.as_str().as_bytes());
        hasher.update(key.key_id.as_bytes());
        hasher.update(&key.epoch.to_be_bytes());
        hasher.update(&destroyed_at.to_be_bytes());
        hasher.update(if existed { b"destroyed" } else { b"not_found" });
        let proof_digest = hasher.finalize().to_hex().to_string();

        Ok(DestroyReceipt {
            key_ref: key.clone(),
            destroyed_at_secs: destroyed_at,
            // Marcador de desenvolvimento; não é assinatura criptográfica institucional.
            provider_signature: Some(format!("sig-software-{}", proof_digest)),
            proof_digest,
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

        // Inspecionar cabeçalho sem possuir a chave
        let header = EncryptionEnvelopeV2::peek_header(&envelope_bytes).expect("Falha ao ler header");
        assert_eq!(header.version, EncryptionEnvelopeV2::AUTHENTICATED_VERSION);
        assert_eq!(header.tenant.as_str(), "tenant-abc");
        assert_eq!(header.key_id, "key-123");
        assert_eq!(header.key_epoch, 1);
    }

    #[test]
    fn test_wrap_unwrap_and_crypto_shred() {
        let provider = SoftwareKeyProvider::new();
        let tenant = TenantId::new("tenant-shred".to_string()).unwrap();

        let (_kref, data_key) = provider.generate_data_key(&tenant).unwrap();

        // Encapsula chave de dados
        let wrapped = provider.wrap_data_key(&tenant, &data_key).expect("wrap falhou");

        // Desencapsula com sucesso
        let unwrapped = provider.unwrap_data_key(&wrapped).expect("unwrap falhou");
        assert_eq!(unwrapped, data_key);

        // Executa crypto-shred da chave mestre do tenant
        let receipt = provider.destroy(&wrapped.key_ref).expect("destroy falhou");
        assert!(!receipt.proof_digest.is_empty());
        assert!(receipt.provider_signature.is_some());

        // Nova tentativa de unwrap deve falhar (chave destruída)
        let unwrap_after_shred = provider.unwrap_data_key(&wrapped);
        assert!(unwrap_after_shred.is_err(), "unwrap deveria falhar após crypto-shred");
    }

    #[test]
    fn rotation_preserves_historical_wrapped_keys() {
        let provider = SoftwareKeyProvider::new();
        let tenant = TenantId::new("tenant-rotation".to_string()).unwrap();
        let (_, data_key) = provider.generate_data_key(&tenant).unwrap();
        let old = provider.wrap_data_key(&tenant, &data_key).unwrap();

        let rotated = provider.rotate(&tenant).unwrap();
        assert_eq!(rotated.epoch, old.key_ref.epoch + 1);

        let recovered = provider.unwrap_data_key(&old).unwrap();
        assert_eq!(recovered, data_key);
    }

    #[test]
    fn destroying_stale_epoch_does_not_destroy_current_epoch() {
        let provider = SoftwareKeyProvider::new();
        let tenant = TenantId::new("tenant-stale".to_string()).unwrap();

        let (_, old_data_key) = provider.generate_data_key(&tenant).unwrap();
        let old = provider.wrap_data_key(&tenant, &old_data_key).unwrap();
        provider.rotate(&tenant).unwrap();

        let (_, current_data_key) = provider.generate_data_key(&tenant).unwrap();
        let current = provider.wrap_data_key(&tenant, &current_data_key).unwrap();

        provider.destroy(&old.key_ref).unwrap();

        assert!(provider.unwrap_data_key(&old).is_err());
        assert_eq!(provider.unwrap_data_key(&current).unwrap(), current_data_key);
    }

    #[test]
    fn envelope_header_is_authenticated() {
        let tenant = TenantId::new("tenant-auth-header".to_string()).unwrap();
        let mut key = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut key);
        let aad = b"aad";
        let plaintext = b"payload";
        let original = EncryptionEnvelopeV2::seal(
            &key,
            plaintext,
            aad,
            tenant,
            "key-1".into(),
            1,
        );

        let header = EncryptionEnvelopeV2::peek_header(&original).unwrap();

        // Troca um byte do key_id sem mudar comprimentos nem ciphertext.
        let mut tampered = original.clone();
        let key_pos = 2 + 2 + header.tenant.as_str().len() + 2;
        tampered[key_pos] ^= 0x01;
        assert!(EncryptionEnvelopeV2::open(&key, &tampered, aad).is_none());

        // Troca o epoch no cabeçalho.
        let mut tampered_epoch = original.clone();
        let epoch_pos = key_pos + header.key_id.len();
        tampered_epoch[epoch_pos + 7] ^= 0x01;
        assert!(EncryptionEnvelopeV2::open(&key, &tampered_epoch, aad).is_none());
    }


    #[test]
    fn secure_open_rejects_legacy_version_instead_of_reinterpreting_it() {
        let tenant = TenantId::new("tenant-version".to_string()).unwrap();
        let mut key = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut key);
        let mut envelope = EncryptionEnvelopeV2::seal(
            &key,
            b"payload",
            b"aad",
            tenant,
            "key-1".into(),
            1,
        );

        envelope[..2].copy_from_slice(&EncryptionEnvelopeV2::LEGACY_VERSION.to_be_bytes());
        assert!(EncryptionEnvelopeV2::open(&key, &envelope, b"aad").is_none());
    }

}
