//! Signed offline model bundles for sovereign environments.

use crate::signer::{HybridSigner, MlDsaSigner};
use crate::{CompError, InstitutionalSigner};
use heraclitus_core::{Episode, EventKind, Lsn};
use heraclitus_log::{AnyLog, EpisodeLog};
use p256::ecdsa::signature::Verifier as _;
use p256::ecdsa::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path};
use std::sync::Arc;
use thiserror::Error;

const ACTIVATION_EVENT: &str = "SecurityModelActivation";
const MAX_FILE_BYTES: u64 = 16 * 1024 * 1024 * 1024;
const MAX_BUNDLE_FILES: usize = 100_000;

#[derive(Debug, Error)]
pub enum ModelBundleError {
    #[error("bundle de modelo inválido: {0}")]
    Invalid(String),
    #[error("assinatura do bundle inválida: {0}")]
    Signature(String),
    #[error("E/S do bundle: {0}")]
    Io(#[from] std::io::Error),
    #[error("serialização do bundle: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("assinador institucional: {0}")]
    Signer(#[from] CompError),
    #[error("log de ativação: {0}")]
    Storage(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelManifest {
    pub model_id: String,
    pub version: String,
    pub artifact_digest: [u8; 32],
    pub tokenizer_digest: [u8; 32],
    pub runtime_id: String,
    pub runtime_version: String,
    pub quantization: Option<String>,
    pub approved_by: String,
}

impl ModelManifest {
    fn validate(&self) -> Result<(), ModelBundleError> {
        for (name, value) in [
            ("model_id", self.model_id.as_str()),
            ("version", self.version.as_str()),
            ("runtime_id", self.runtime_id.as_str()),
            ("runtime_version", self.runtime_version.as_str()),
            ("approved_by", self.approved_by.as_str()),
        ] {
            if value.trim().is_empty() || value.len() > 4096 {
                return Err(ModelBundleError::Invalid(format!("{name} inválido")));
            }
        }
        if self
            .quantization
            .as_ref()
            .is_some_and(|value| value.trim().is_empty() || value.len() > 128)
        {
            return Err(ModelBundleError::Invalid("quantization inválida".into()));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BundleSignatureScheme {
    P256Development,
    MlDsa44,
    HybridP256MlDsa44,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BundleSignature {
    pub scheme: BundleSignatureScheme,
    pub subject: String,
    pub signature: Vec<u8>,
    pub public_key: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelBundleBody {
    pub schema_version: u16,
    pub model: ModelManifest,
    /// Relative paths under `model/`, `tokenizer/` or `sbom/`.
    pub files: BTreeMap<String, [u8; 32]>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedModelBundle {
    pub body: ModelBundleBody,
    pub signature: BundleSignature,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelBundlePolicy {
    pub policy_id: String,
    pub version: String,
    pub allowed_models: BTreeSet<String>,
    /// runtime_id -> approved versions
    pub approved_runtimes: BTreeMap<String, BTreeSet<String>>,
    pub approved_signer_key_digests: BTreeSet<[u8; 32]>,
    pub allowed_signature_schemes: BTreeSet<BundleSignatureScheme>,
}

impl ModelBundlePolicy {
    fn validate(&self) -> Result<(), ModelBundleError> {
        if self.policy_id.trim().is_empty() || self.version.trim().is_empty() {
            return Err(ModelBundleError::Invalid(
                "política do bundle sem identidade/versionamento".into(),
            ));
        }
        if self.allowed_models.is_empty()
            || self.approved_runtimes.is_empty()
            || self.approved_signer_key_digests.is_empty()
            || self.allowed_signature_schemes.is_empty()
        {
            return Err(ModelBundleError::Invalid(
                "política do bundle possui allowlist vazia".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifiedModelBundle {
    pub model: ModelManifest,
    pub bundle_digest: [u8; 32],
    pub signer_subject: String,
    pub signer_key_digest: [u8; 32],
    pub signature_scheme: BundleSignatureScheme,
    pub policy_id: String,
    pub policy_version: String,
}

impl VerifiedModelBundle {
    fn to_episode(&self) -> Result<Episode, ModelBundleError> {
        let mut episode = Episode::new(
            "gov-compliance",
            EventKind::Custom(ACTIVATION_EVENT.into()),
            serde_json::to_vec(self)?,
        );
        episode
            .attrs
            .insert("compliance.generated".into(), "true".into());
        episode
            .attrs
            .insert("sentinel.model_id".into(), self.model.model_id.clone());
        episode
            .attrs
            .insert("sentinel.model_version".into(), self.model.version.clone());
        episode.attrs.insert(
            "compliance.bundle_digest".into(),
            hex_digest(&self.bundle_digest),
        );
        Ok(episode)
    }
}

pub fn build_signed_model_bundle(
    root: impl AsRef<Path>,
    mut model: ModelManifest,
    signer: &dyn InstitutionalSigner,
    scheme: BundleSignatureScheme,
) -> Result<SignedModelBundle, ModelBundleError> {
    let root = root.as_ref();
    let files = collect_payload_files(root)?;
    model.artifact_digest = tree_digest(&files, "model/")?;
    model.tokenizer_digest = tree_digest(&files, "tokenizer/")?;
    model.validate()?;
    let body = ModelBundleBody {
        schema_version: 1,
        model,
        files,
    };
    let body_bytes = canonical_body_bytes(&body)?;
    let signed = signer.sign_snapshot(&body_bytes)?;
    Ok(SignedModelBundle {
        body,
        signature: BundleSignature {
            scheme,
            subject: signed.subject,
            signature: signed.signature,
            public_key: signed.public_key_sec1,
        },
    })
}

impl SignedModelBundle {
    pub fn write_metadata(&self, root: impl AsRef<Path>) -> Result<(), ModelBundleError> {
        let root = root.as_ref();
        std::fs::create_dir_all(root.join("signatures"))?;
        let mut manifest = serde_json::to_vec_pretty(self)?;
        manifest.push(b'\n');
        std::fs::write(root.join("manifest.json"), manifest)?;
        std::fs::write(
            root.join("signatures").join("bundle.sig"),
            &self.signature.signature,
        )?;
        std::fs::write(
            root.join("signatures").join("signer.pub"),
            &self.signature.public_key,
        )?;
        Ok(())
    }

    pub fn load(root: impl AsRef<Path>) -> Result<Self, ModelBundleError> {
        let bytes = std::fs::read(root.as_ref().join("manifest.json"))?;
        Ok(serde_json::from_slice(&bytes)?)
    }
}

pub fn verify_model_bundle(
    root: impl AsRef<Path>,
    signed: &SignedModelBundle,
    policy: &ModelBundlePolicy,
) -> Result<VerifiedModelBundle, ModelBundleError> {
    policy.validate()?;
    signed.body.model.validate()?;
    if signed.body.schema_version != 1 {
        return Err(ModelBundleError::Invalid(
            "schema_version de bundle não suportada".into(),
        ));
    }
    if !policy.allowed_models.contains(&signed.body.model.model_id) {
        return Err(ModelBundleError::Invalid(format!(
            "model_id não allowlisted: {}",
            signed.body.model.model_id
        )));
    }
    let runtime_versions = policy
        .approved_runtimes
        .get(&signed.body.model.runtime_id)
        .ok_or_else(|| ModelBundleError::Invalid("runtime_id não aprovado".into()))?;
    if !runtime_versions.contains(&signed.body.model.runtime_version) {
        return Err(ModelBundleError::Invalid(
            "runtime_version não aprovada".into(),
        ));
    }
    if !policy
        .allowed_signature_schemes
        .contains(&signed.signature.scheme)
    {
        return Err(ModelBundleError::Signature(
            "esquema de assinatura não permitido".into(),
        ));
    }
    let signer_key_digest = *blake3::hash(&signed.signature.public_key).as_bytes();
    if !policy
        .approved_signer_key_digests
        .contains(&signer_key_digest)
    {
        return Err(ModelBundleError::Signature(
            "chave do assinador não allowlisted".into(),
        ));
    }

    let actual_files = collect_payload_files(root.as_ref())?;
    if actual_files != signed.body.files {
        return Err(ModelBundleError::Invalid(
            "conteúdo do bundle diverge do manifesto assinado".into(),
        ));
    }
    if tree_digest(&actual_files, "model/")? != signed.body.model.artifact_digest
        || tree_digest(&actual_files, "tokenizer/")? != signed.body.model.tokenizer_digest
    {
        return Err(ModelBundleError::Invalid(
            "digest agregado de model/tokenizer diverge".into(),
        ));
    }

    let body_bytes = canonical_body_bytes(&signed.body)?;
    verify_bundle_signature(&body_bytes, &signed.signature)?;
    let bundle_digest = *blake3::hash(&serde_json::to_vec(signed)?).as_bytes();
    Ok(VerifiedModelBundle {
        model: signed.body.model.clone(),
        bundle_digest,
        signer_subject: signed.signature.subject.clone(),
        signer_key_digest,
        signature_scheme: signed.signature.scheme,
        policy_id: policy.policy_id.clone(),
        policy_version: policy.version.clone(),
    })
}

fn verify_bundle_signature(
    body: &[u8],
    signature: &BundleSignature,
) -> Result<(), ModelBundleError> {
    let valid = match signature.scheme {
        BundleSignatureScheme::P256Development => {
            let key = VerifyingKey::from_sec1_bytes(&signature.public_key)
                .map_err(|error| ModelBundleError::Signature(format!("chave P-256: {error}")))?;
            let value = Signature::from_slice(&signature.signature).map_err(|error| {
                ModelBundleError::Signature(format!("assinatura P-256: {error}"))
            })?;
            key.verify(body, &value).is_ok()
        }
        BundleSignatureScheme::MlDsa44 => {
            MlDsaSigner::verify(&signature.public_key, body, &signature.signature)
        }
        BundleSignatureScheme::HybridP256MlDsa44 => {
            HybridSigner::verify(&signature.public_key, body, &signature.signature)
        }
    };
    if valid {
        Ok(())
    } else {
        Err(ModelBundleError::Signature(
            "assinatura criptográfica não verifica".into(),
        ))
    }
}

fn canonical_body_bytes(body: &ModelBundleBody) -> Result<Vec<u8>, ModelBundleError> {
    Ok(serde_json::to_vec(body)?)
}

fn collect_payload_files(root: &Path) -> Result<BTreeMap<String, [u8; 32]>, ModelBundleError> {
    let mut files = BTreeMap::new();
    for directory in ["model", "tokenizer", "sbom"] {
        let base = root.join(directory);
        if !base.is_dir() {
            return Err(ModelBundleError::Invalid(format!(
                "diretório obrigatório ausente: {directory}/"
            )));
        }
        collect_directory(root, &base, &mut files)?;
    }
    if !files.keys().any(|path| path.starts_with("model/"))
        || !files.keys().any(|path| path.starts_with("tokenizer/"))
        || !files.keys().any(|path| path.starts_with("sbom/"))
    {
        return Err(ModelBundleError::Invalid(
            "model, tokenizer e sbom devem conter arquivos".into(),
        ));
    }
    if files.len() > MAX_BUNDLE_FILES {
        return Err(ModelBundleError::Invalid(
            "bundle possui arquivos demais".into(),
        ));
    }
    Ok(files)
}

fn collect_directory(
    root: &Path,
    directory: &Path,
    files: &mut BTreeMap<String, [u8; 32]>,
) -> Result<(), ModelBundleError> {
    let mut entries: Vec<_> = std::fs::read_dir(directory)?.collect::<Result<_, _>>()?;
    entries.sort_by_key(std::fs::DirEntry::file_name);
    for entry in entries {
        let path = entry.path();
        let metadata = std::fs::symlink_metadata(&path)?;
        if metadata.file_type().is_symlink() {
            return Err(ModelBundleError::Invalid(format!(
                "symlink proibido no bundle: {}",
                path.display()
            )));
        }
        if metadata.is_dir() {
            collect_directory(root, &path, files)?;
            continue;
        }
        if !metadata.is_file() || metadata.len() > MAX_FILE_BYTES {
            return Err(ModelBundleError::Invalid(format!(
                "arquivo inválido ou grande demais: {}",
                path.display()
            )));
        }
        let relative = path
            .strip_prefix(root)
            .map_err(|_| ModelBundleError::Invalid("arquivo escapou da raiz do bundle".into()))?;
        if relative.components().any(|component| {
            matches!(
                component,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        }) {
            return Err(ModelBundleError::Invalid(
                "caminho não-canônico no bundle".into(),
            ));
        }
        let name = relative.to_string_lossy().replace('\\', "/");
        files.insert(name, *blake3::hash(&std::fs::read(path)?).as_bytes());
    }
    Ok(())
}

fn tree_digest(
    files: &BTreeMap<String, [u8; 32]>,
    prefix: &str,
) -> Result<[u8; 32], ModelBundleError> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"heraclitus/model-tree/v1\0");
    let mut count = 0usize;
    for (name, digest) in files.iter().filter(|(name, _)| name.starts_with(prefix)) {
        count += 1;
        hasher.update(&(name.len() as u64).to_le_bytes());
        hasher.update(name.as_bytes());
        hasher.update(digest);
    }
    if count == 0 {
        return Err(ModelBundleError::Invalid(format!(
            "nenhum arquivo sob {prefix}"
        )));
    }
    Ok(*hasher.finalize().as_bytes())
}

fn hex_digest(digest: &[u8; 32]) -> String {
    let mut output = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(&mut output, "{byte:02x}");
    }
    output
}

#[derive(Clone)]
pub struct ModelBundleRegistry {
    log: Arc<AnyLog>,
}

impl ModelBundleRegistry {
    pub fn new(log: Arc<AnyLog>) -> Self {
        Self { log }
    }

    pub fn activate(&self, verified: VerifiedModelBundle) -> Result<Lsn, ModelBundleError> {
        let existing = self
            .log
            .scan(0, self.log.head())
            .map_err(|error| ModelBundleError::Storage(error.to_string()))?
            .into_iter()
            .find_map(|(lsn, episode)| {
                (episode.kind.label() == ACTIVATION_EVENT)
                    .then(|| serde_json::from_slice::<VerifiedModelBundle>(&episode.content).ok())
                    .flatten()
                    .filter(|value| value.bundle_digest == verified.bundle_digest)
                    .map(|_| lsn)
            });
        if let Some(lsn) = existing {
            return Ok(lsn);
        }
        self.log
            .append(verified.to_episode()?)
            .map_err(|error| ModelBundleError::Storage(error.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signer::MlDsaSigner;
    use heraclitus_core::{FsyncPolicy, StorageFormat};

    fn bundle_tree() -> tempfile::TempDir {
        let temp = tempfile::tempdir().unwrap();
        for directory in ["model", "tokenizer", "sbom"] {
            std::fs::create_dir_all(temp.path().join(directory)).unwrap();
        }
        std::fs::write(temp.path().join("model").join("weights.bin"), b"weights-v1").unwrap();
        std::fs::write(
            temp.path().join("tokenizer").join("vocab.json"),
            b"{\"a\":1}",
        )
        .unwrap();
        std::fs::write(
            temp.path().join("sbom").join("sbom.json"),
            b"{\"spdx\":true}",
        )
        .unwrap();
        temp
    }

    fn manifest() -> ModelManifest {
        ModelManifest {
            model_id: "sentinel-investigator".into(),
            version: "v1".into(),
            artifact_digest: [0; 32],
            tokenizer_digest: [0; 32],
            runtime_id: "local-runtime".into(),
            runtime_version: "1.2.0".into(),
            quantization: None,
            approved_by: "security-board".into(),
        }
    }

    fn policy(signed: &SignedModelBundle) -> ModelBundlePolicy {
        ModelBundlePolicy {
            policy_id: "airgap-model-policy".into(),
            version: "v1".into(),
            allowed_models: [signed.body.model.model_id.clone()].into_iter().collect(),
            approved_runtimes: [(
                signed.body.model.runtime_id.clone(),
                [signed.body.model.runtime_version.clone()]
                    .into_iter()
                    .collect(),
            )]
            .into_iter()
            .collect(),
            approved_signer_key_digests: [*blake3::hash(&signed.signature.public_key).as_bytes()]
                .into_iter()
                .collect(),
            allowed_signature_schemes: [BundleSignatureScheme::MlDsa44].into_iter().collect(),
        }
    }

    #[test]
    fn signed_offline_bundle_verifies_and_activates_idempotently() {
        let tree = bundle_tree();
        let signer = MlDsaSigner::generate("institutional-model-signer").unwrap();
        let signed = build_signed_model_bundle(
            tree.path(),
            manifest(),
            &signer,
            BundleSignatureScheme::MlDsa44,
        )
        .unwrap();
        signed.write_metadata(tree.path()).unwrap();
        let loaded = SignedModelBundle::load(tree.path()).unwrap();
        let verified = verify_model_bundle(tree.path(), &loaded, &policy(&loaded)).unwrap();
        assert_eq!(verified.model.model_id, "sentinel-investigator");

        let log_dir = tempfile::tempdir().unwrap();
        let log = Arc::new(
            AnyLog::open(StorageFormat::V6, log_dir.path(), 4096, FsyncPolicy::Always).unwrap(),
        );
        let registry = ModelBundleRegistry::new(log.clone());
        let lsn = registry.activate(verified.clone()).unwrap();
        assert_eq!(registry.activate(verified).unwrap(), lsn);
        assert_eq!(
            log.scan(0, log.head())
                .unwrap()
                .iter()
                .filter(|(_, episode)| episode.kind.label() == ACTIVATION_EVENT)
                .count(),
            1
        );
    }

    #[test]
    fn tamper_unknown_signer_and_runtime_are_rejected() {
        let tree = bundle_tree();
        let signer = MlDsaSigner::generate("institutional-model-signer").unwrap();
        let signed = build_signed_model_bundle(
            tree.path(),
            manifest(),
            &signer,
            BundleSignatureScheme::MlDsa44,
        )
        .unwrap();
        let valid_policy = policy(&signed);
        std::fs::write(tree.path().join("model").join("weights.bin"), b"tampered").unwrap();
        assert!(verify_model_bundle(tree.path(), &signed, &valid_policy).is_err());

        let tree = bundle_tree();
        let mut wrong_signer = valid_policy.clone();
        wrong_signer.approved_signer_key_digests = [[9; 32]].into_iter().collect();
        assert!(verify_model_bundle(tree.path(), &signed, &wrong_signer).is_err());

        let mut wrong_runtime = valid_policy;
        wrong_runtime.approved_runtimes.clear();
        assert!(verify_model_bundle(tree.path(), &signed, &wrong_runtime).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn symlink_is_rejected_before_hashing() {
        use std::os::unix::fs::symlink;
        let tree = bundle_tree();
        symlink(
            tree.path().join("sbom").join("sbom.json"),
            tree.path().join("model").join("link"),
        )
        .unwrap();
        let signer = MlDsaSigner::generate("signer").unwrap();
        assert!(build_signed_model_bundle(
            tree.path(),
            manifest(),
            &signer,
            BundleSignatureScheme::MlDsa44
        )
        .is_err());
    }
}
