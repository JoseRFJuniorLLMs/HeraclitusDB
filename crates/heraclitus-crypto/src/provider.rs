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
    /// Inspeciona e valida o cabeçalho do envelope sem necessidade da chave criptográfica.
    /// Permite descobrir `tenant`, `key_id` e `key_epoch` para requisição ao KMS / KeyProvider.
    pub fn peek_header(envelope_bytes: &[u8]) -> Option<EnvelopeHeader> {
        if envelope_bytes.len() < 2 {
            return None;
        }

        let mut offset = 0;
        let version = u16::from_be_bytes(envelope_bytes[offset..offset + 2].try_into().ok()?);
        offset += 2;
        if version != 2 && version != 3 {
            return None;
        }

        // tenant
        if envelope_bytes.len() < offset + 2 {
            return None;
        }
        let tenant_len =
            u16::from_be_bytes(envelope_bytes[offset..offset + 2].try_into().ok()?) as usize;
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
        let key_id_len =
            u16::from_be_bytes(envelope_bytes[offset..offset + 2].try_into().ok()?) as usize;
        offset += 2;
        if envelope_bytes.len() < offset + key_id_len {
            return None;
        }
        let key_id = std::str::from_utf8(&envelope_bytes[offset..offset + key_id_len])
            .ok()?
            .to_string();
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
        let algo_len =
            u16::from_be_bytes(envelope_bytes[offset..offset + 2].try_into().ok()?) as usize;
        offset += 2;
        if envelope_bytes.len() < offset + algo_len {
            return None;
        }
        let algorithm = std::str::from_utf8(&envelope_bytes[offset..offset + algo_len])
            .ok()?
            .to_string();
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

        let mut result = Vec::new();
        // version = 2 (u16)
        result.extend_from_slice(&3u16.to_be_bytes());

        // tenant (tamanho + bytes)
        let tenant_bytes = tenant.as_str().as_bytes();
        let tenant_len: u16 = tenant_bytes
            .len()
            .try_into()
            .expect("tenant id excede u16::MAX");
        result.extend_from_slice(&tenant_len.to_be_bytes());
        result.extend_from_slice(tenant_bytes);

        // key_id
        let key_id_bytes = key_id.as_bytes();
        let key_id_len: u16 = key_id_bytes
            .len()
            .try_into()
            .expect("key_id excede u16::MAX");
        result.extend_from_slice(&key_id_len.to_be_bytes());
        result.extend_from_slice(key_id_bytes);

        // key_epoch
        result.extend_from_slice(&epoch.to_be_bytes());

        // algorithm
        let algo = "ChaCha20-Poly1305";
        let algo_bytes = algo.as_bytes();
        let algo_len: u16 = algo_bytes
            .len()
            .try_into()
            .expect("algorithm excede u16::MAX");
        result.extend_from_slice(&algo_len.to_be_bytes());
        result.extend_from_slice(algo_bytes);

        // nonce
        result.extend_from_slice(&nonce);

        // aad_digest
        result.extend_from_slice(&aad_digest);

        // Version 3 binds the complete encoded header and caller context.
        let mut authenticated = b"heraclitus-envelope-v3\0".to_vec();
        authenticated.extend_from_slice(&result);
        authenticated.extend_from_slice(aad);
        let ct = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: plaintext,
                    aad: &authenticated,
                },
            )
            .expect("chacha20poly1305 encrypt nunca falha para chave/nonce validos");

        result.extend_from_slice(&ct);

        result
    }

    /// Abre o envelope autenticado V3 e retorna os dados em texto plano.
    pub fn open(key: &[u8; 32], envelope_bytes: &[u8], expected_aad: &[u8]) -> Option<Vec<u8>> {
        let header = Self::peek_header(envelope_bytes)?;
        // Legacy V2 did not authenticate its routing metadata. Never silently
        // downgrade: migration must explicitly use open_legacy_v2.
        if header.version != 3 || header.algorithm != "ChaCha20-Poly1305" {
            return None;
        }
        let mut authenticated = b"heraclitus-envelope-v3\0".to_vec();
        authenticated.extend_from_slice(&envelope_bytes[..header.ciphertext_offset]);
        authenticated.extend_from_slice(expected_aad);

        // Verificar aad_digest com BLAKE3
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
                    aad: &authenticated,
                },
            )
            .ok()
    }
    /// Explicit migration-only decoder for unauthenticated V2 routing metadata.
    /// Callers must supply trusted expected routing information independently.
    pub fn open_legacy_v2(
        key: &[u8; 32],
        bytes: &[u8],
        aad: &[u8],
        expected: &KeyRef,
    ) -> Option<Vec<u8>> {
        let h = Self::peek_header(bytes)?;
        if h.version != 2
            || h.algorithm != "ChaCha20-Poly1305"
            || h.tenant != expected.tenant
            || h.key_id != expected.key_id
            || h.key_epoch != expected.epoch
            || h.aad_digest != *blake3::hash(aad).as_bytes()
        {
            return None;
        }
        ChaCha20Poly1305::new(Key::from_slice(key))
            .decrypt(
                Nonce::from_slice(&h.nonce),
                Payload {
                    msg: &bytes[h.ciphertext_offset..],
                    aad,
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
    fn wrap_data_key(
        &self,
        tenant: &TenantId,
        data_key: &[u8; 32],
    ) -> Result<WrappedDataKey, String>;
    fn unwrap_data_key(&self, key: &WrappedDataKey) -> Result<[u8; 32], String>;
    fn rotate(&self, tenant: &TenantId) -> Result<KeyRef, String>;
    fn destroy(&self, key: &KeyRef) -> Result<DestroyReceipt, String>;
    fn health(&self) -> KeyProviderHealth;
}

/// Provedor de chaves baseado em software para testes e dev
pub struct SoftwareKeyProvider {
    state: Arc<Mutex<HashMap<TenantId, TenantKeys>>>,
}

struct TenantKeys {
    epoch: u64,
    keys: HashMap<u64, Option<[u8; 32]>>,
}

fn key_reference(tenant: &TenantId, epoch: u64) -> KeyRef {
    KeyRef {
        tenant: tenant.clone(),
        key_id: format!("{}-key-{}", tenant.as_str(), epoch),
        epoch,
    }
}

fn reference_aad(key: &KeyRef) -> Vec<u8> {
    let mut bytes = b"heraclitus-key-wrap-v2\0".to_vec();
    for part in [key.tenant.as_str().as_bytes(), key.key_id.as_bytes()] {
        bytes.extend_from_slice(&(part.len() as u64).to_be_bytes());
        bytes.extend_from_slice(part);
    }
    bytes.extend_from_slice(&key.epoch.to_be_bytes());
    bytes
}

impl SoftwareKeyProvider {
    pub fn new() -> Self {
        Self {
            state: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    fn current(&self, tenant: &TenantId) -> Result<(KeyRef, [u8; 32]), String> {
        let mut state = self.state.lock().map_err(|_| "key provider poisoned")?;
        let keys = state.entry(tenant.clone()).or_insert_with(|| {
            let mut key = [0; 32];
            rand::thread_rng().fill_bytes(&mut key);
            TenantKeys {
                epoch: 1,
                keys: HashMap::from([(1, Some(key))]),
            }
        });
        let key = keys
            .keys
            .get(&keys.epoch)
            .copied()
            .flatten()
            .ok_or("current epoch destroyed; rotate before creating new wrapped keys")?;
        Ok((key_reference(tenant, keys.epoch), key))
    }
}

impl Default for SoftwareKeyProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for TenantKeys {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        for key in self.keys.values_mut().flatten() {
            key.zeroize();
        }
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

        let (key_ref, _) = self.current(tenant)?;
        Ok((key_ref, data_key))
    }

    fn wrap_data_key(
        &self,
        tenant: &TenantId,
        data_key: &[u8; 32],
    ) -> Result<WrappedDataKey, String> {
        let (key_ref, master) = self.current(tenant)?;
        let master = zeroize::Zeroizing::new(master);
        let aad = reference_aad(&key_ref);
        let cipher = ChaCha20Poly1305::new(Key::from_slice(master.as_ref()));
        let mut nonce = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce);
        let ct = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: data_key,
                    aad: &aad,
                },
            )
            .map_err(|e| format!("wrap error: {e}"))?;
        let mut wrapped = Vec::with_capacity(12 + ct.len());
        wrapped.extend_from_slice(&nonce);
        wrapped.extend_from_slice(&ct);

        Ok(WrappedDataKey {
            key_ref,
            wrapped_ciphertext: wrapped,
            wrapping_algorithm: "ChaCha20-Poly1305/keyref-v2".into(),
            created_at_secs: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        })
    }

    fn unwrap_data_key(&self, key: &WrappedDataKey) -> Result<[u8; 32], String> {
        if key.wrapping_algorithm != "ChaCha20-Poly1305/keyref-v2"
            || key.key_ref != key_reference(&key.key_ref.tenant, key.key_ref.epoch)
        {
            return Err("invalid key reference or wrapping algorithm".into());
        }
        let master = self
            .state
            .lock()
            .map_err(|_| "key provider poisoned")?
            .get(&key.key_ref.tenant)
            .and_then(|k| k.keys.get(&key.key_ref.epoch))
            .copied()
            .flatten()
            .ok_or("key epoch destroyed or unknown")?;
        let master = zeroize::Zeroizing::new(master);
        let aad = reference_aad(&key.key_ref);
        if key.wrapped_ciphertext.len() < 12 {
            return Err("ciphertext encapsulado inválido (menor que nonce)".into());
        }
        let nonce = &key.wrapped_ciphertext[..12];
        let ct = &key.wrapped_ciphertext[12..];
        let cipher = ChaCha20Poly1305::new(Key::from_slice(master.as_ref()));
        let pt = zeroize::Zeroizing::new(
            cipher
                .decrypt(Nonce::from_slice(nonce), Payload { msg: ct, aad: &aad })
                .map_err(|e| format!("desencapsulamento falhou: {e}"))?,
        );
        pt.as_slice()
            .try_into()
            .map_err(|_| "tamanho de chave desencapsulada incorreto".into())
    }

    fn rotate(&self, tenant: &TenantId) -> Result<KeyRef, String> {
        // Initialize before advancing, including rotate on a new tenant.
        let _ = self.current(tenant);
        let mut state = self.state.lock().map_err(|_| "key provider poisoned")?;
        let keys = state.get_mut(tenant).ok_or("tenant unavailable")?;
        let epoch = keys.epoch.checked_add(1).ok_or("key epoch overflow")?;
        let mut key = [0; 32];
        rand::thread_rng().fill_bytes(&mut key);
        keys.keys.insert(epoch, Some(key));
        {
            use zeroize::Zeroize;
            key.zeroize();
        }
        keys.epoch = epoch;
        Ok(key_reference(tenant, epoch))
    }

    fn destroy(&self, key: &KeyRef) -> Result<DestroyReceipt, String> {
        if *key != key_reference(&key.tenant, key.epoch) {
            return Err("invalid key reference".into());
        }
        let mut state = self.state.lock().map_err(|_| "key provider poisoned")?;
        let slot = state
            .get_mut(&key.tenant)
            .and_then(|k| k.keys.get_mut(&key.epoch))
            .ok_or("unknown key reference")?;
        let existed = slot.is_some();
        if let Some(key_bytes) = slot.as_mut() {
            use zeroize::Zeroize;
            key_bytes.zeroize();
        }
        *slot = None;
        let destroyed_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let mut hasher = blake3::Hasher::new();
        hasher.update(key.tenant.as_str().as_bytes());
        hasher.update(key.key_id.as_bytes());
        hasher.update(&key.epoch.to_be_bytes());
        hasher.update(&destroyed_at.to_be_bytes());
        hasher.update(if existed { b"destroyed" } else { b"not_found" });
        let proof_digest = hasher.finalize().to_hex().to_string();

        Ok(DestroyReceipt {
            key_ref: key.clone(),
            destroyed_at_secs: destroyed_at,
            provider_signature: None, // Software receipts are checksums, not signatures.
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
    fn rotation_preserves_history_and_stale_destroy_is_exact() {
        let p = SoftwareKeyProvider::new();
        let t = TenantId::new("tenant".into()).unwrap();
        let old = p.wrap_data_key(&t, &[9; 32]).unwrap();
        p.rotate(&t).unwrap();
        let new = p.wrap_data_key(&t, &[8; 32]).unwrap();
        assert_eq!(p.unwrap_data_key(&old).unwrap(), [9; 32]);
        p.destroy(&old.key_ref).unwrap();
        assert!(p.unwrap_data_key(&old).is_err());
        assert_eq!(p.unwrap_data_key(&new).unwrap(), [8; 32]);
        let mut forged = new.clone();
        forged.key_ref.key_id.push('x');
        assert!(p.destroy(&forged.key_ref).is_err());
        assert!(p.unwrap_data_key(&forged).is_err());
        assert_eq!(p.unwrap_data_key(&new).unwrap(), [8; 32]);
    }

    #[test]
    fn header_mutation_is_authenticated_and_legacy_downgrade_is_rejected() {
        let key = [7; 32];
        let bytes = EncryptionEnvelopeV2::seal(
            &key,
            b"secret",
            b"ctx",
            TenantId::new("t1".into()).unwrap(),
            "key-1".into(),
            1,
        );
        let header = EncryptionEnvelopeV2::peek_header(&bytes).unwrap();
        for i in 0..header.ciphertext_offset {
            let mut mutated = bytes.clone();
            mutated[i] ^= 1;
            assert!(
                EncryptionEnvelopeV2::open(&key, &mutated, b"ctx").is_none(),
                "accepted byte {i}"
            );
        }
        assert_eq!(
            EncryptionEnvelopeV2::open(&key, &bytes, b"ctx").unwrap(),
            b"secret"
        );
    }
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

        let envelope_bytes =
            EncryptionEnvelopeV2::seal(&key, plaintext, aad, tenant, key_id, epoch);

        let opened = EncryptionEnvelopeV2::open(&key, &envelope_bytes, aad)
            .expect("Falha ao abrir o envelope");
        assert_eq!(opened, plaintext);

        // AAD errado deve falhar
        let wrong_aad = b"Contexto alterado";
        let opened_wrong = EncryptionEnvelopeV2::open(&key, &envelope_bytes, wrong_aad);
        assert!(opened_wrong.is_none());

        // Inspecionar cabeçalho sem possuir a chave
        let header =
            EncryptionEnvelopeV2::peek_header(&envelope_bytes).expect("Falha ao ler header");
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
        let wrapped = provider
            .wrap_data_key(&tenant, &data_key)
            .expect("wrap falhou");

        // Desencapsula com sucesso
        let unwrapped = provider.unwrap_data_key(&wrapped).expect("unwrap falhou");
        assert_eq!(unwrapped, data_key);

        // Executa crypto-shred da chave mestre do tenant
        let receipt = provider.destroy(&wrapped.key_ref).expect("destroy falhou");
        assert!(!receipt.proof_digest.is_empty());
        assert!(receipt.provider_signature.is_none());

        // Nova tentativa de unwrap deve falhar (chave destruída)
        let unwrap_after_shred = provider.unwrap_data_key(&wrapped);
        assert!(
            unwrap_after_shred.is_err(),
            "unwrap deveria falhar após crypto-shred"
        );
    }
}
