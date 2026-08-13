//! heraclitus-compliance — a camada jurídica para cenário de governo.
//!
//! O motor garante a **integridade matemática** (log imutável + raiz de Merkle
//! blake3). Este crate acrescenta a **validade jurídica** sem tocar nesse core:
//!
//! 1. [`commit`] — funde os roots dos segmentos selados num único commitment
//!    reproduzível até uma watermark LSN, e deriva o imprint SHA-256.
//! 2. [`rfc3161`] — o pedido RFC 3161 que vai para uma ACT homologada (SERPRO /
//!    Observatório Nacional).
//! 3. [`tsa`] — a ACT: [`tsa::LocalTsa`] (dev, ponta-a-ponta sem credencial) e
//!    [`tsa::HttpTsa`] (produção).
//! 4. [`verify`] — confere imprint + assinatura + extrai a hora.
//! 5. [`signer`] — assinatura institucional (CAdES) soft (dev) / HSM (produção).
//! 6. [`receipt`] — o recibo jurídico persistido (token + manifesto auditável).
//!
//! ## Arquitetura: carimbagem assíncrona por linha d'água
//!
//! Nunca se assina cada `append` (a chamada de rede a uma ACT custa 50–200 ms e
//! mataria o QPS). Em vez disso, um worker assíncrono ancora o **estado
//! consolidado** a cada marco (N LSNs / T minutos): captura a raiz de Merkle
//! daquele instante, carimba o imprint SHA-256, e persiste o recibo. O que isto
//! prova juridicamente é preciso: *aquele estado existia ANTES do instante
//! oficial T* — combinado com a ordem causal interna (log + HLC), fecha a prova
//! forense.

pub mod commit;
pub mod receipt;
pub mod rfc3161;
pub mod signer;
pub mod tsa;
pub mod verify;
pub mod worker;

pub use commit::{commit_at, commit_now, current_watermark, Commitment};
pub use receipt::{load_manifest, read_token, LegalReceipt};
pub use signer::{InstitutionalSignature, InstitutionalSigner, Pkcs11Signer, SoftKeySigner};
pub use tsa::{HttpTsa, LocalTsa, TsaClient};
pub use verify::{is_dev_token, verify_dev_token, VerifiedTime};
pub use worker::{run_worker, tick};

use heraclitus_core::Lsn;
use heraclitus_log::Log;
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

/// Anchor the log at `watermark` (or the current watermark when `None`):
/// compute the commitment, timestamp its SHA-256 imprint via `tsa`, and persist
/// a legal receipt under `receipts_dir`. Returns the receipt.
///
/// This is the per-marco operation a background worker calls — it never blocks
/// or touches the append path.
pub fn anchor(
    log: &Log,
    tsa: &dyn TsaClient,
    receipts_dir: impl AsRef<Path>,
    watermark: Option<Lsn>,
) -> Result<LegalReceipt, CompError> {
    let wm = watermark.unwrap_or_else(|| current_watermark(log));
    let commitment = commit_at(log, wm);
    let imprint = commitment.message_imprint_sha256();
    let token = tsa.stamp(&imprint)?;
    // Prefer the authority's own time when we can read it offline (dev token);
    // otherwise record our wall clock (real RFC token time is validated by the
    // production verifier against ICP-Brasil roots).
    let gen_ms = verify_dev_token(&token, &imprint)
        .map(|v| v.gen_unix_ms)
        .unwrap_or_else(|_| now_unix_ms());
    receipt::persist(
        receipts_dir,
        &commitment,
        &imprint,
        tsa.policy_name(),
        gen_ms,
        &token,
    )
}

/// Re-verify a previously issued receipt against the live log: recompute the
/// commitment at the receipt's watermark, confirm the imprint matches what was
/// timestamped, and (for dev tokens) verify the authority signature.
///
/// A mismatch means the log was altered retroactively below `receipt.lsn` — the
/// exact fraud this layer is built to expose.
pub fn verify_receipt(
    log: &Log,
    receipts_dir: impl AsRef<Path>,
    receipt: &LegalReceipt,
) -> Result<VerifiedTime, CompError> {
    let commitment = commit_at(log, receipt.lsn);
    let imprint = commitment.message_imprint_sha256();
    if receipt::to_hex(&imprint) != receipt.imprint_hex {
        return Err(CompError::Verify(format!(
            "commitment recalculado não bate com o recibo no LSN {} — log alterado retroativamente?",
            receipt.lsn
        )));
    }
    let token = receipt::read_token(receipts_dir, receipt)?;
    // Distinguir "não consigo validar" de "fraude". `verify_dev_token` só sabe
    // ler o token da autoridade de DESENVOLVIMENTO; um `.tst` RFC 3161 real
    // (modo HttpTsa, produção) nunca descodifica como DevToken, e antes isso
    // devolvia o mesmo erro de uma assinatura adulterada — ou seja, TODOS os
    // recibos legítimos de produção eram reportados como fraude. O commitment
    // (que é o que prova que o log não mudou) JÁ foi verificado acima.
    match verify_dev_token(&token, &imprint) {
        Ok(v) => Ok(v),
        Err(e) if !verify::is_dev_token(&token) => Err(CompError::Verify(format!(
            "commitment CONFERE (o log não foi alterado no LSN {}), mas o token é um \
             RFC 3161 real e a validação da cadeia de confiança (ICP-Brasil) ainda não \
             está implementada — isto NÃO é uma deteção de fraude. Detalhe: {e}",
            receipt.lsn
        ))),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use heraclitus_core::{Episode, EventKind, FsyncPolicy};

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

        // a fresh verification of an untouched log passes
        verify_receipt(&log, receipts.path(), &receipt).unwrap();

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
}
