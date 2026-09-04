//! heraclitus-compliance — a camada jurídica para cenário de governo.
//!
//! O motor garante a **integridade matemática** (log imutável + raiz de Merkle
//! blake3). Este crate acrescenta uma camada de **evidência de desenvolvimento**
//! sem tocar nesse core. Validade jurídica para um token RFC 3161 externo
//! depende do verificador CMS/X.509, do trust store e da política escolhidos
//! pelo operador; esses componentes existem, mas âncoras e evidência de uma ACT
//! real nunca são inventadas pelo software:
//!
//! 1. [`commit`] — funde os roots dos segmentos selados num único commitment
//!    reproduzível até uma watermark LSN, e deriva o imprint SHA-256.
//! 2. [`rfc3161`] — o pedido RFC 3161 que pode ser enviado a uma ACT externa.
//! 3. [`tsa`] — a ACT: [`tsa::LocalTsa`] (dev) e [`tsa::HttpTsa`] (HTTP sem
//!    validação, não produção); [`secure_tsa`] é o cliente HTTPS de produção.
//! 4. [`verify`] confere tokens de desenvolvimento; [`icp`] valida CMS, cadeia,
//!    política e revogação contra material instalado pelo órgão.
//! 5. [`signer`] — assinatura institucional (CAdES) soft (dev) / HSM (produção).
//! 6. [`receipt`] — o recibo jurídico persistido (token + manifesto auditável).
//!
//! ## Arquitetura: carimbagem assíncrona por linha d'água
//!
//! Nunca se assina cada `append` (a chamada de rede a uma ACT custa 50–200 ms e
//! mataria o QPS). Em vez disso, um worker assíncrono ancora o **estado
//! consolidado** a cada marco (N LSNs / T minutos): captura a raiz de Merkle
//! daquele instante, carimba o imprint SHA-256, e persiste o recibo. O que isto
//! prova localmente é preciso: o commitment é reproduzível até aquele watermark.
//! A afirmação de que existia antes de um instante oficial exige validar o token
//! externo contra uma cadeia de confiança, e não pode ser feita por este crate
//! ainda.

pub mod algoritmos;
pub mod classification;
pub mod commit;
pub mod constraints;
pub mod crl;
pub mod dashboard;
pub mod deferred;
pub mod icp;
pub mod model_bundle;
pub mod privacy;
pub mod receipt;
pub mod regulatory;
pub mod rfc3161;
pub mod secure_tsa;
pub mod signer;
pub mod sovereignty;
pub mod trust_store;
pub mod tsa;
pub(crate) mod varrimento;

#[cfg(test)]
pub(crate) mod test_pki;
pub mod verify;
pub mod worker;

pub use classification::{
    classify_derived_episode, ClassificationControls, ClassificationDecision,
    ClassificationDowngradeAuthorization, ClassificationError, ClassificationPolicy,
    SourceClassification,
};
pub use commit::{commit_at, commit_now, current_watermark, Commitment};
pub use dashboard::{
    AnchorHealthSnapshot, ComplianceDashboardError, ComplianceDashboardSnapshot,
    ComplianceOverallStatus, DeadlineHealthSnapshot, LegalHoldSnapshot, SovereigntyHealthSnapshot,
};
pub use deferred::{
    import_deferred_response, stamp_deferred_request, DeferredAnchorError, DeferredAnchorRegistry,
    DeferredAnchorRequest, DeferredAnchorResponse, DeferredAnchorState, DeferredSignature,
    DeferredTransferPolicy, EvidenceAnchor, EvidenceCommitment, SignedDeferredAnchorRequest,
    SignedDeferredAnchorResponse,
};
pub use model_bundle::{
    build_signed_model_bundle, verify_model_bundle, BundleSignature, BundleSignatureScheme,
    ModelBundleBody, ModelBundleError, ModelBundlePolicy, ModelBundleRegistry, ModelManifest,
    SignedModelBundle, VerifiedModelBundle,
};
pub use privacy::{
    AnpdCommunicationPackage, AnpdPackageReceipt, BusinessCalendar, ComplianceEvidenceRef,
    DeadlinePolicy, DeadlineState, DeadlineUrgency, IncidentPackageData, PackageManifest,
    PrivacyError, PrivacyExportPolicy, PrivacyIncidentAssessment, PrivacyIncidentEngine,
    PrivacySanitizationReport, PrivacyState, RegulatoryDeadline, RipdEvidenceAppendix, RiskLevel,
    SubmissionState,
};
pub use receipt::{load_manifest, read_token, LegalReceipt, TimestampValidationState};
pub use regulatory::{
    ComplianceContext, CompliancePredicate, ComplianceRequirement, ConfiguredRegulatoryPolicy,
    EvidenceSelector, LegalHold, LegalHoldRecord, LegalHoldRelease, PolicyActivation,
    PolicyActivationRecord, PolicyIdentity, RegulatoryDecision, RegulatoryDecisionRecord,
    RegulatoryError, RegulatoryPolicy, RegulatoryPolicyEngine, RegulatoryRule, RegulatoryState,
    RegulatoryStateCache, RequirementEffect, RetentionClass,
};
pub use signer::{InstitutionalSignature, InstitutionalSigner, Pkcs11Signer, SoftKeySigner};
pub use sovereignty::{
    EgressDecision, EgressEndpoint, EgressPermit, EgressPurpose, GuardedModelBackend,
    GuardedTsaClient, ModelDecision, ModelSovereignty, SovereignModelBackend,
    SovereigntyAuditState, SovereigntyError, SovereigntyMode, SovereigntyPolicy,
    SovereigntyRuntime, SovereigntyVerdict,
};
pub use tsa::{HttpTsa, LocalTsa, TsaClient};
pub use verify::{is_dev_token, verify_dev_token, VerifiedTime};
pub use worker::{run_worker, tick};

use heraclitus_core::Lsn;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Configuration for the watermark-timestamping daemon ([`worker::run_worker`]).
#[derive(Debug, Clone)]
pub struct WorkerConfig {
    /// How often the daemon checks the watermark.
    pub interval: Duration,
    /// Minimum LSN advance since the last anchor before a new one is issued.
    pub min_lsn_step: Lsn,
    /// Where receipts (`<lsn>.tst` + `manifest.jsonl`) are written.
    pub receipts_dir: PathBuf,
}

impl WorkerConfig {
    pub fn new(interval: Duration, min_lsn_step: Lsn, receipts_dir: impl Into<PathBuf>) -> Self {
        Self {
            interval,
            min_lsn_step,
            receipts_dir: receipts_dir.into(),
        }
    }
}

/// Daemon progress: the last watermark anchored (so an advance can be detected).
#[derive(Debug, Clone, Copy, Default)]
pub struct WorkerState {
    pub last_lsn: Lsn,
}

/// Milliseconds since the Unix epoch (wall clock).
pub fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Errors from the compliance layer.
#[derive(Debug, thiserror::Error)]
pub enum CompError {
    #[error("ASN.1/DER: {0}")]
    Der(#[from] der::Error),
    #[error("E/S: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("ACT: {0}")]
    Tsa(String),
    #[error("verificação: {0}")]
    Verify(String),
    #[error("não suportado: {0}")]
    Unsupported(String),
}

/// What a receipt verification established.
///
/// `CommitmentOnly` is intentionally not an error: the log can be intact even
/// while the timestamp token lacks a verifier. It must not be presented as an
/// ICP-Brasil or other legal timestamp validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReceiptVerification {
    /// A development token was internally verified. It is not legal evidence.
    DevelopmentOnly(VerifiedTime),
    /// The commitment matches, but no authority-token trust validation exists.
    CommitmentOnly(TimestampValidationState),
    /// O compromisso bate **e** o `TimeStampToken` foi reverificado agora
    /// contra as âncoras instaladas — não é a alegação que o recibo trazia.
    AuthorityVerified(Box<crate::icp::VerifiedTimestamp>),
}

/// Anchor the log at `watermark` (or the current watermark when `None`):
/// compute the commitment, timestamp its SHA-256 imprint via `tsa`, and persist
/// an evidence receipt under `receipts_dir`. Returns the receipt.
///
/// This is the per-marco operation a background worker calls — it never blocks
/// or touches the append path.
pub fn anchor<L: heraclitus_log::EpisodeLog + ?Sized>(
    log: &L,
    tsa: &dyn TsaClient,
    receipts_dir: impl AsRef<Path>,
    watermark: Option<Lsn>,
) -> Result<LegalReceipt, CompError> {
    let wm = watermark.unwrap_or_else(|| current_watermark(log));
    let commitment = commit_at(log, wm);
    let imprint = commitment.message_imprint_sha256();
    let token = tsa.stamp(&imprint)?;
    // A caller cannot elevate its own output by naming a policy or URL. Only
    // LocalTsa's self-contained development token is decodable here; any other
    // backend records local creation time and persists an explicit unvalidated
    // state until a real external-token verifier exists.
    let validation_state = tsa.validation_state();
    let authority_gen_unix_ms = match validation_state {
        TimestampValidationState::DevelopmentOnly => Some(
            verify_dev_token(&token, &imprint)
                .map_err(|e| CompError::Verify(format!("token de desenvolvimento inválido: {e}")))?
                .gen_unix_ms,
        ),
        // Um cliente que declara ter verificado TEM de saber dizer a hora que
        // verificou. Se não sabe, as duas afirmações contradizem-se, e a
        // contradição não se resolve escrevendo o recibo à mesma: isso deixaria
        // em disco um estado `verificado` com hora de autoridade ausente — a
        // combinação que um auditor lê como prova e que não prova nada.
        TimestampValidationState::ExternalTokenVerified => Some(
            tsa.verified_gen_unix_ms(&token, &imprint).ok_or_else(|| {
                CompError::Verify(
                    "cliente declara token verificado mas não devolve genTime verificado: recibo não escrito"
                        .into(),
                )
            })?,
        ),
        TimestampValidationState::ExternalTokenUnvalidated
        | TimestampValidationState::LegacyUnverified => None,
    };
    let gen_ms = authority_gen_unix_ms.unwrap_or_else(now_unix_ms);
    // Mesma regra que já vale para o `genTime`: um cliente que declara ter
    // verificado TEM de saber dizer a política que o `TSTInfo` assinou. O campo
    // é obrigatório na RFC 3161 §2.4.2, portanto uma verificação bem-sucedida
    // sempre o tem — e um cliente que o cale está a contradizer-se.
    //
    // A contradição não se resolve escrevendo o recibo à mesma: ficaria em
    // disco um estado `verificado` sem a política assinada, que é a combinação
    // que um auditor lê como prova de conformidade com uma política e que não
    // prova política nenhuma.
    let tsa_policy_oid = if validation_state == TimestampValidationState::ExternalTokenVerified {
        Some(tsa.verified_policy_oid(&token, &imprint).ok_or_else(|| {
            CompError::Verify(
                "cliente declara token verificado mas não devolve a política assinada do TSTInfo: recibo não escrito"
                    .into(),
            )
        })?)
    } else {
        None
    };
    receipt::persist(
        receipts_dir,
        &commitment,
        &imprint,
        tsa.policy_name(),
        receipt::TimestampEvidence {
            recorded_unix_ms: gen_ms,
            authority_gen_unix_ms,
            validation_state,
            tsa_policy_oid,
        },
        &token,
    )
}

/// Re-verify a previously issued receipt against the live log: recompute the
/// commitment at the receipt's watermark, confirm the imprint matches what was
/// timestamped, and (only for dev tokens) verify the authority signature.
///
/// A mismatch means the log was altered retroactively below `receipt.lsn` — the
/// exact fraud this layer is built to expose.
pub fn verify_receipt<L: heraclitus_log::EpisodeLog + ?Sized>(
    log: &L,
    receipts_dir: impl AsRef<Path>,
    receipt: &LegalReceipt,
) -> Result<ReceiptVerification, CompError> {
    let commitment = commit_at(log, receipt.lsn);
    let imprint = commitment.message_imprint_sha256();
    if receipt::to_hex(&imprint) != receipt.imprint_hex {
        return Err(CompError::Verify(format!(
            "commitment recalculado não bate com o recibo no LSN {} — log alterado retroativamente?",
            receipt.lsn
        )));
    }
    let token = receipt::read_token(receipts_dir, receipt)?;
    match receipt.validation_state {
        TimestampValidationState::DevelopmentOnly => {
            verify_dev_token(&token, &imprint).map(ReceiptVerification::DevelopmentOnly)
        }
        TimestampValidationState::ExternalTokenUnvalidated
        | TimestampValidationState::LegacyUnverified
        // Um recibo que se declara verificado NÃO é reverificado aqui, e o
        // resultado diz `CommitmentOnly` para o dizer. A alternativa —
        // devolver `AuthorityVerified` com base no campo do próprio recibo —
        // faria o verificador repetir a alegação que devia estar a testar.
        // Quem quer a reverificação chama `verify_receipt_with_verifier`.
        | TimestampValidationState::ExternalTokenVerified => {
            // The commitment is already confirmed above. Do not conflate an
            // absent authority-token verifier with evidence of fraud.
            Ok(ReceiptVerification::CommitmentOnly(
                receipt.validation_state,
            ))
        }
    }
}

/// Como [`verify_receipt`], mas reverifica também o `TimeStampToken` contra as
/// âncoras instaladas.
///
/// É esta a função que separa "o log não foi alterado" de "uma autoridade
/// credenciada afirmou esta hora". Um recibo que se declarava verificado e que
/// agora não confirma devolve `Err`: ou as âncoras mudaram, ou o token foi
/// substituído — e nenhuma das duas pode passar em silêncio.
pub fn verify_receipt_with_verifier<L: heraclitus_log::EpisodeLog + ?Sized>(
    log: &L,
    receipts_dir: impl AsRef<Path>,
    receipt: &LegalReceipt,
    verifier: &crate::icp::IcpBrasilTimestampVerifier,
) -> Result<ReceiptVerification, CompError> {
    let base = verify_receipt(log, &receipts_dir, receipt)?;
    // Um token de desenvolvimento não encadeia até âncora nenhuma, por
    // construção. Passá-lo ao verificador ICP daria um erro que se leria como
    // fraude, quando é só um token de outro formato.
    if receipt.validation_state == TimestampValidationState::DevelopmentOnly {
        return Ok(base);
    }
    let commitment = commit_at(log, receipt.lsn);
    let imprint = commitment.message_imprint_sha256();
    let token = receipt::read_token(&receipts_dir, receipt)?;

    // Um recibo LEGADO foi escrito antes de o estado ser persistido, e pode
    // conter qualquer um dos dois formatos. Distinguir antes de decidir é o que
    // separa um relatório útil de um alarme falso: dizer "possível fraude"
    // sobre um recibo de desenvolvimento de 2024 destrói a credibilidade da
    // ferramenta precisamente no momento em que ela precisa de ser acreditada.
    if receipt.validation_state == TimestampValidationState::LegacyUnverified
        && verify_dev_token(&token, &imprint).is_ok()
    {
        return Ok(base);
    }

    let verificado = verifier.verify(&token, &imprint, None, now_unix_ms())?;
    if let Some(declarada) = receipt.tsa_policy_oid.as_deref() {
        let observada = verificado.policy_oid.to_string();
        if declarada != observada {
            return Err(CompError::Verify(format!(
                "política do token mudou: recibo declara `{declarada}` e a reverificação encontrou `{observada}`"
            )));
        }
    }
    Ok(ReceiptVerification::AuthorityVerified(Box::new(verificado)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use heraclitus_core::{Episode, EventKind, FsyncPolicy};
    use heraclitus_log::Log;

    fn append_n(log: &Log, n: usize) {
        for i in 0..n {
            let ep = Episode::new(
                "auditor",
                EventKind::Observation,
                format!("evento de auditoria #{i}").into_bytes(),
            );
            log.append(ep).unwrap();
        }
    }

    #[test]
    fn anchor_and_verify_end_to_end() {
        let dir = tempfile::tempdir().unwrap();
        let receipts = tempfile::tempdir().unwrap();
        // tiny segments so several seal and the watermark advances
        let log = Log::open(dir.path(), 256, FsyncPolicy::Always).unwrap();
        append_n(&log, 200);

        let wm = current_watermark(&log);
        assert!(wm > 0, "esperava segmentos selados para ancorar");

        let tsa = LocalTsa::generate("ACT-dev/Observatorio-simulado");
        let receipt = anchor(&log, &tsa, receipts.path(), None).unwrap();
        assert_eq!(receipt.lsn, wm);
        assert!(receipt.segments >= 1);

        // A fresh development receipt is explicitly not promoted to legal
        // evidence, even though its self-contained token verifies.
        assert!(matches!(
            verify_receipt(&log, receipts.path(), &receipt).unwrap(),
            ReceiptVerification::DevelopmentOnly(_)
        ));
        assert_eq!(
            receipt.validation_state,
            TimestampValidationState::DevelopmentOnly
        );
        assert_eq!(receipt.authority_gen_unix_ms, Some(receipt.gen_unix_ms));

        // the commitment is reproducible: same watermark → same imprint
        let again = commit_at(&log, wm).message_imprint_sha256();
        assert_eq!(receipt::to_hex(&again), receipt.imprint_hex);

        // manifest persisted exactly one entry
        assert_eq!(load_manifest(receipts.path()).unwrap().len(), 1);
    }

    #[test]
    fn tampered_commitment_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let receipts = tempfile::tempdir().unwrap();
        let log = Log::open(dir.path(), 256, FsyncPolicy::Always).unwrap();
        append_n(&log, 120);

        let tsa = LocalTsa::generate("ACT-dev");
        let mut receipt = anchor(&log, &tsa, receipts.path(), None).unwrap();

        // forge the recorded imprint → verification must fail
        receipt.imprint_hex = receipt::to_hex(&[0u8; 32]);
        assert!(verify_receipt(&log, receipts.path(), &receipt).is_err());
    }

    struct ExternalTsa;

    impl TsaClient for ExternalTsa {
        fn policy_name(&self) -> &str {
            "ACT-externa-de-teste"
        }

        fn validation_state(&self) -> TimestampValidationState {
            TimestampValidationState::ExternalTokenUnvalidated
        }

        fn stamp(&self, _imprint: &[u8; 32]) -> Result<Vec<u8>, CompError> {
            // Deliberately not a DevToken: the current build cannot validate
            // an external RFC 3161/CMS token and must report that honestly.
            Ok(vec![0x30, 0x00])
        }
    }

    #[test]
    fn external_token_is_commitment_only_not_fraud_or_legal_validation() {
        let dir = tempfile::tempdir().unwrap();
        let receipts = tempfile::tempdir().unwrap();
        let log = Log::open(dir.path(), 256, FsyncPolicy::Always).unwrap();
        append_n(&log, 120);

        let receipt = anchor(&log, &ExternalTsa, receipts.path(), None).unwrap();
        assert_eq!(
            receipt.validation_state,
            TimestampValidationState::ExternalTokenUnvalidated
        );
        assert_eq!(receipt.authority_gen_unix_ms, None);

        assert_eq!(
            verify_receipt(&log, receipts.path(), &receipt).unwrap(),
            ReceiptVerification::CommitmentOnly(TimestampValidationState::ExternalTokenUnvalidated)
        );
    }
}

#[cfg(test)]
mod testes_politica_ponta_a_ponta {
    use super::*;
    use crate::icp::{IcpBrasilTimestampVerifier, TimestampValidationPolicy};
    use crate::receipt::TimestampValidationState;
    use crate::trust_store::TrustStore;
    use crate::tsa::TsaClient;

    const AGORA_S: u64 = 1_760_000_000;

    /// Uma ACT sintética que devolve um token REAL (da PKI de teste) e verifica-o
    /// com um verificador REAL, sem rede.
    ///
    /// Existe porque o `SecureTsaClient` precisa de um socket, e o elo que
    /// faltava provar — o OID chegar ao RECIBO — está no `anchor()`, não no
    /// cliente. Sem isto, `anchor()` podia deitar o OID fora e nenhum teste
    /// dava por isso.
    struct ActSintetica {
        token: Vec<u8>,
        verificador: IcpBrasilTimestampVerifier,
        /// Simula um cliente que se declara verificado mas não sabe dizer a
        /// política — a contradição que o `anchor()` tem de recusar.
        cala_a_politica: bool,
    }

    impl ActSintetica {
        fn nova(cala_a_politica: bool) -> (Self, [u8; 32]) {
            let chain = crate::test_pki::chain_de_teste();
            // O imprint tem de ser o do commitment que o teste vai ancorar;
            // preenche-se depois, em `para_imprint`.
            let imp = [0u8; 32];
            let token = crate::test_pki::token_de_teste(
                &chain,
                &imp,
                AGORA_S - 60,
                None,
                crate::test_pki::OpcoesToken::default(),
            );
            let mut store = TrustStore::new();
            store.add_pem_or_der("raiz", &chain.root_der).unwrap();
            (
                Self {
                    token,
                    verificador: IcpBrasilTimestampVerifier::new(
                        store,
                        TimestampValidationPolicy::default(),
                    ),
                    cala_a_politica,
                },
                imp,
            )
        }

        /// Reemite o token sobre um imprint concreto.
        fn para_imprint(&mut self, imprint: &[u8; 32], chain: &crate::test_pki::Chain) {
            self.token = crate::test_pki::token_de_teste(
                chain,
                imprint,
                AGORA_S - 60,
                None,
                crate::test_pki::OpcoesToken::default(),
            );
        }
    }

    impl TsaClient for ActSintetica {
        fn policy_name(&self) -> &str {
            // Deliberadamente um ROTULO HUMANO, e não um OID: é assim que se
            // apanha o erro de gravar o rótulo onde devia ir a política
            // assinada.
            "ACT de Teste do Órgão"
        }
        fn validation_state(&self) -> TimestampValidationState {
            TimestampValidationState::ExternalTokenVerified
        }
        fn stamp(&self, _imprint: &[u8; 32]) -> Result<Vec<u8>, CompError> {
            Ok(self.token.clone())
        }
        fn verified_gen_unix_ms(&self, token: &[u8], imprint: &[u8; 32]) -> Option<u64> {
            self.verificador
                .verify(token, imprint, None, AGORA_S * 1_000)
                .ok()
                .map(|v| v.gen_unix_ms)
        }
        fn verified_policy_oid(&self, token: &[u8], imprint: &[u8; 32]) -> Option<String> {
            if self.cala_a_politica {
                return None;
            }
            self.verificador
                .verify(token, imprint, None, AGORA_S * 1_000)
                .ok()
                .map(|v| v.policy_oid.to_string())
        }
    }

    fn log_com_eventos() -> (tempfile::TempDir, heraclitus_log::Log) {
        use heraclitus_core::{Episode, EventKind, FsyncPolicy};
        let dir = tempfile::tempdir().unwrap();
        let log = heraclitus_log::Log::open(dir.path(), 256, FsyncPolicy::Always).unwrap();
        for i in 0..200 {
            log.append(Episode::new(
                "auditor",
                EventKind::Observation,
                format!("evento {i}").into_bytes(),
            ))
            .unwrap();
        }
        (dir, log)
    }

    /// O elo que faltava: o OID **assinado pela ACT** tem de chegar ao recibo, e
    /// não o rótulo humano que o operador escolheu.
    #[test]
    fn o_oid_assinado_chega_ao_recibo_e_nao_o_rotulo_humano() {
        let (_d, log) = log_com_eventos();
        let recibos = tempfile::tempdir().unwrap();
        let chain = crate::test_pki::chain_de_teste();

        // O imprint depende do commitment, portanto calcula-se primeiro.
        let wm = current_watermark(&log);
        let imprint = commit_at(&log, wm).message_imprint_sha256();

        let (mut act, _) = ActSintetica::nova(false);
        act.para_imprint(&imprint, &chain);

        let r = anchor(&log, &act, recibos.path(), Some(wm)).expect("ancoragem");
        assert_eq!(
            r.validation_state,
            TimestampValidationState::ExternalTokenVerified
        );
        assert_eq!(
            r.tsa_policy_oid.as_deref(),
            Some(crate::test_pki::OID_POLITICA_TESTE.to_string().as_str()),
            "o recibo tem de trazer a política ASSINADA no TSTInfo"
        );
        assert_ne!(
            r.tsa_policy_oid.as_deref(),
            Some("ACT de Teste do Órgão"),
            "o rótulo humano não é uma política RFC 3161"
        );
        assert_eq!(
            r.policy, "ACT de Teste do Órgão",
            "o rótulo fica no seu campo"
        );
    }

    /// Um cliente que se declara verificado e não sabe dizer a política
    /// contradiz-se. A contradição não se resolve escrevendo o recibo à mesma:
    /// ficaria em disco um estado "verificado" sem a política assinada, que é a
    /// combinação que um auditor lê como prova e que não prova a política.
    #[test]
    fn um_cliente_verificado_que_cala_a_politica_nao_escreve_recibo() {
        let (_d, log) = log_com_eventos();
        let recibos = tempfile::tempdir().unwrap();
        let chain = crate::test_pki::chain_de_teste();
        let wm = current_watermark(&log);
        let imprint = commit_at(&log, wm).message_imprint_sha256();

        let (mut act, _) = ActSintetica::nova(true);
        act.para_imprint(&imprint, &chain);

        let erro = anchor(&log, &act, recibos.path(), Some(wm)).unwrap_err();
        assert!(
            erro.to_string().contains("política"),
            "a contradição tem de ser fatal: {erro}"
        );
    }
}
