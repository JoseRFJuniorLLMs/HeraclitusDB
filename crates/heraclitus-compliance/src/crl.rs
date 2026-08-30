//! SPEC-0046 §9 — revogação de certificados por CRL, offline.
//!
//! Até aqui, [`crate::icp::VerifiedTimestamp::revocation_checked`] era sempre
//! `false` e um certificado **revogado mas dentro da validade passava**. É o
//! caso que interessa a quem quer forjar evidência: uma chave comprometida é
//! revogada e continua, para um verificador que não consulta revogação, tão boa
//! como no primeiro dia.
//!
//! # Porque CRL de ficheiro e não OCSP
//!
//! OCSP é uma ligação de rede por verificação. Isso trá-lo-ia para dentro do
//! caminho de verificação de evidência — que é justamente o caminho que tem de
//! continuar a funcionar num órgão em air-gap, anos depois, quando o
//! respondedor da AC já não existir. Uma CRL é um ficheiro assinado: copia-se,
//! arquiva-se com a evidência, e verifica-se sem rede nenhuma.
//!
//! A consequência assumida é a frescura: uma CRL diz o que era verdade quando
//! foi emitida. Por isso a validade da própria CRL é imposta
//! ([`CrlPolicy::max_staleness`]), e o resultado diz até quando a informação é
//! boa em vez de deixar o leitor supor que é de agora.
//!
//! # Como uma revogação se relaciona com um carimbo já emitido
//!
//! Não é a mesma pergunta que "este certificado serve hoje". Um carimbo emitido
//! enquanto o certificado valia continua a provar a hora depois de ele ser
//! revogado — é a razão de existir de um carimbo. O que o invalida é:
//!
//! 1. ter sido **revogado antes** de carimbar (`revocationDate <= genTime`): a
//!    autoridade já tinha dito que aquela chave não valia; ou
//! 2. ter sido revogado por **compromisso de chave** (`keyCompromise`,
//!    `cACompromise`), em qualquer data. A data de revogação é quando a AC
//!    soube, não quando a chave foi comprometida — quem tem a chave pode
//!    carimbar com qualquer `genTime` que queira, incluindo um anterior.
//!
//! O caso 2 é o que impede este módulo de ser uma comparação de datas. Tratar
//! um `keyCompromise` como "revogado depois, portanto o carimbo vale" é
//! exactamente o erro que um atacante com a chave explora.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use der::{Decode, Encode};
use x509_cert::crl::CertificateList;

use crate::CompError;

/// Tecto por ficheiro. Uma CRL de uma AC grande chega a alguns MB; acima disto
/// é quase certo ser outra coisa.
const MAX_CRL_BYTES: u64 = 16 * 1024 * 1024;
/// Tecto de ficheiros, para uma pasta apontada por engano.
const MAX_CRLS: usize = 256;

/// Verificador de assinatura injectado pelo [`crate::icp`]: o mesmo que valida
/// a emissão dos certificados valida a assinatura da CRL. Passá-lo em vez de o
/// duplicar aqui garante que os dois caminhos aceitam exactamente os mesmos
/// algoritmos — se divergissem, uma CRL assinada com um esquema que a cadeia
/// recusa passaria a ser aceite sem que ninguém desse por isso.
pub type VerificadorAssinatura<'a> = &'a dyn Fn(
    &x509_cert::Certificate,
    &der::asn1::ObjectIdentifier,
    &[u8],
    &[u8],
) -> Result<(), CompError>;

/// Conversor de `Time` X.509 para ms Unix, também injectado para partilhar o
/// tratamento de `UTCTime` vs `GeneralizedTime` com o resto do verificador.
pub type ConversorTempo<'a> = &'a dyn Fn(&x509_cert::time::Time) -> Result<u64, CompError>;

/// Regra de frescura. Sem isto, uma CRL de 2019 responderia "não revogado" com
/// a mesma confiança de uma de hoje.
#[derive(Debug, Clone, Copy)]
pub struct CrlPolicy {
    /// Quanto tempo depois de `nextUpdate` uma CRL ainda é aceite.
    ///
    /// O default é zero: uma CRL expirada não é consultada. Um órgão em
    /// air-gap que só recebe CRLs por mala diplomática alarga isto — e ao
    /// alargá-lo está a declarar quanto risco aceita, que é melhor do que o
    /// sistema decidir por ele em silêncio.
    pub max_staleness: std::time::Duration,
}

impl Default for CrlPolicy {
    fn default() -> Self {
        Self {
            max_staleness: std::time::Duration::ZERO,
        }
    }
}

/// CRLs indexadas pelo DER do nome do emissor.
#[derive(Debug, Clone, Default)]
pub struct CrlStore {
    por_emissor: BTreeMap<Vec<u8>, Vec<CertificateList>>,
    loaded_from: Option<PathBuf>,
    total: usize,
}

/// O que aconteceu ao carregar uma pasta — para um operador saber qual ficheiro
/// falhou, em vez de descobrir que "a revogação não funciona".
#[derive(Debug, Clone, Default)]
pub struct CrlLoadReport {
    pub files_seen: usize,
    pub crls_loaded: usize,
    pub rejected: Vec<(String, String)>,
}

impl CrlStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn is_empty(&self) -> bool {
        self.total == 0
    }

    pub fn len(&self) -> usize {
        self.total
    }

    pub fn loaded_from(&self) -> Option<&Path> {
        self.loaded_from.as_deref()
    }

    /// As CRLs emitidas por este nome.
    pub fn for_issuer(&self, issuer_der: &[u8]) -> &[CertificateList] {
        self.por_emissor
            .get(issuer_der)
            .map(Vec::as_slice)
            .unwrap_or(&[])
    }

    /// Carrega `.crl`, `.pem` e `.der` de uma pasta, por ordem de nome.
    ///
    /// Uma pasta que não existe devolve um store vazio em vez de erro: é o
    /// mesmo que não ter configurado revogação, e o verificador já sabe
    /// distinguir "não consultei" de "consultei e está limpo".
    pub fn load_dir(dir: &Path) -> Result<(Self, CrlLoadReport), CompError> {
        let mut store = Self {
            loaded_from: Some(dir.to_path_buf()),
            ..Default::default()
        };
        let mut report = CrlLoadReport::default();

        let mut files: Vec<PathBuf> = match std::fs::read_dir(dir) {
            Ok(entries) => entries
                .flatten()
                .map(|e| e.path())
                .filter(|p| {
                    p.extension()
                        .and_then(|e| e.to_str())
                        .is_some_and(|e| matches!(e, "crl" | "pem" | "der"))
                })
                .collect(),
            Err(_) => return Ok((store, report)),
        };
        files.sort();

        for path in files {
            report.files_seen += 1;
            let nome = path.display().to_string();
            if store.total >= MAX_CRLS {
                report
                    .rejected
                    .push((nome, format!("limite de {MAX_CRLS} CRLs atingido")));
                continue;
            }
            match std::fs::metadata(&path) {
                Ok(meta) if meta.len() > MAX_CRL_BYTES => {
                    report.rejected.push((
                        nome,
                        format!("{} bytes acima do limite de {MAX_CRL_BYTES}", meta.len()),
                    ));
                    continue;
                }
                Err(error) => {
                    report.rejected.push((nome, error.to_string()));
                    continue;
                }
                _ => {}
            }
            let bytes = match std::fs::read(&path) {
                Ok(b) => b,
                Err(error) => {
                    report.rejected.push((nome, error.to_string()));
                    continue;
                }
            };
            match store.add_pem_or_der(&bytes) {
                Ok(()) => report.crls_loaded += 1,
                Err(error) => report.rejected.push((nome, error.to_string())),
            }
        }
        Ok((store, report))
    }

    /// Acrescenta uma CRL a partir de bytes DER ou PEM.
    pub fn add_pem_or_der(&mut self, bytes: &[u8]) -> Result<(), CompError> {
        let crl = if bytes.starts_with(b"-----BEGIN") {
            // `CertificateList` não satisfaz o bound de `DecodePem`;
            // descodifica-se o envelope PEM à mão e entra-se pelo mesmo
            // caminho DER que os ficheiros binários.
            let (_rotulo, der_bytes) = der::pem::decode_vec(bytes)
                .map_err(|e| CompError::Verify(format!("CRL em PEM inválida: {e}")))?;
            CertificateList::from_der(&der_bytes)
                .map_err(|e| CompError::Verify(format!("CRL não é um CertificateList: {e}")))?
        } else {
            CertificateList::from_der(bytes)
                .map_err(|e| CompError::Verify(format!("CRL não é um CertificateList: {e}")))?
        };
        let issuer = crl
            .tbs_cert_list
            .issuer
            .to_der()
            .map_err(|e| CompError::Verify(format!("emissor da CRL não codifica: {e}")))?;
        self.por_emissor.entry(issuer).or_default().push(crl);
        self.total += 1;
        Ok(())
    }
}

/// Motivo da revogação (RFC 5280 §5.3.1), nos valores que mudam a decisão.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevocationReason {
    KeyCompromise,
    CaCompromise,
    /// Qualquer outro motivo, ou nenhum declarado.
    Outro(u8),
}

impl RevocationReason {
    const fn from_u8(v: u8) -> Self {
        match v {
            1 => Self::KeyCompromise,
            2 => Self::CaCompromise,
            outro => Self::Outro(outro),
        }
    }

    /// Se este motivo invalida o carimbo **independentemente** da data.
    pub const fn invalida_retroativamente(self) -> bool {
        matches!(self, Self::KeyCompromise | Self::CaCompromise)
    }

    pub const fn label(self) -> &'static str {
        match self {
            Self::KeyCompromise => "keyCompromise",
            Self::CaCompromise => "cACompromise",
            Self::Outro(_) => "outro",
        }
    }
}

/// O que se soube sobre um certificado da cadeia.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EstadoRevogacao {
    /// Assunto do certificado consultado.
    pub subject: String,
    /// `nextUpdate` da CRL usada, em ms — até quando a informação é boa.
    pub crl_next_update_ms: Option<u64>,
    /// `thisUpdate` da CRL usada, em ms.
    pub crl_this_update_ms: u64,
}

/// Uma CRL que serve para este emissor: assinatura confere e está dentro da
/// janela permitida.
fn crl_utilizavel<'a>(
    crls: &'a [CertificateList],
    emissor: &x509_cert::Certificate,
    now_unix_ms: u64,
    policy: &CrlPolicy,
    verificar_assinatura: VerificadorAssinatura<'_>,
    tempo_ms: ConversorTempo<'_>,
) -> Result<(&'a CertificateList, u64, Option<u64>), CompError> {
    let mut ultimo_erro = String::from("nenhuma CRL para este emissor");
    for crl in crls {
        let tbs = match crl.tbs_cert_list.to_der() {
            Ok(t) => t,
            Err(e) => {
                ultimo_erro = format!("tbsCertList não codifica: {e}");
                continue;
            }
        };
        let Some(assinatura) = crl.signature.as_bytes() else {
            ultimo_erro = "assinatura da CRL não alinhada em bytes".into();
            continue;
        };
        // A CRL é uma afirmação da AC. Sem verificar a assinatura, qualquer um
        // que escreva na pasta pode declarar um certificado como não revogado —
        // e é essa a resposta que passa despercebida.
        if let Err(e) = verificar_assinatura(
            emissor,
            &crl.signature_algorithm.oid,
            &tbs,
            assinatura,
        ) {
            ultimo_erro = format!("assinatura da CRL não confere: {e}");
            continue;
        }
        let this_update = match tempo_ms(&crl.tbs_cert_list.this_update) {
            Ok(t) => t,
            Err(e) => {
                ultimo_erro = e.to_string();
                continue;
            }
        };
        if this_update > now_unix_ms {
            ultimo_erro = "CRL com thisUpdate no futuro".into();
            continue;
        }
        let next_update = match crl.tbs_cert_list.next_update.as_ref() {
            Some(t) => match tempo_ms(t) {
                Ok(v) => Some(v),
                Err(e) => {
                    ultimo_erro = e.to_string();
                    continue;
                }
            },
            None => None,
        };
        if let Some(fim) = next_update {
            let limite = fim.saturating_add(policy.max_staleness.as_millis() as u64);
            if now_unix_ms > limite {
                ultimo_erro = format!(
                    "CRL expirou em {fim} ms e a tolerância configurada é de {} s",
                    policy.max_staleness.as_secs()
                );
                continue;
            }
        }
        return Ok((crl, this_update, next_update));
    }
    Err(CompError::Verify(format!(
        "nenhuma CRL utilizável: {ultimo_erro}"
    )))
}

/// Consulta a revogação de `cert`, emitido por `emissor`, para um carimbo
/// emitido em `gen_unix_ms`.
///
/// `Err` significa **recusar o carimbo**: ou o certificado estava revogado de
/// forma que o invalida, ou não há informação de revogação utilizável. A
/// segunda também é um `Err` de propósito — quem pediu consulta de revogação e
/// recebe "não consegui consultar" não pode ficar com um resultado que se lê
/// como "limpo".
#[allow(clippy::too_many_arguments)]
pub fn consultar(
    store: &CrlStore,
    cert: &x509_cert::Certificate,
    emissor: &x509_cert::Certificate,
    gen_unix_ms: u64,
    now_unix_ms: u64,
    policy: &CrlPolicy,
    verificar_assinatura: VerificadorAssinatura<'_>,
    tempo_ms: ConversorTempo<'_>,
) -> Result<EstadoRevogacao, CompError> {
    let issuer_der = cert
        .tbs_certificate
        .issuer
        .to_der()
        .map_err(|e| CompError::Verify(format!("emissor não codifica: {e}")))?;
    let crls = store.for_issuer(&issuer_der);
    if crls.is_empty() {
        return Err(CompError::Verify(format!(
            "revogação pedida mas não há CRL do emissor `{}` para `{}`",
            cert.tbs_certificate.issuer, cert.tbs_certificate.subject
        )));
    }
    let (crl, this_update, next_update) = crl_utilizavel(
        crls,
        emissor,
        now_unix_ms,
        policy,
        verificar_assinatura,
        tempo_ms,
    )
    .map_err(|e| {
        CompError::Verify(format!(
            "emissor `{}`: {e}",
            cert.tbs_certificate.issuer
        ))
    })?;

    if let Some(revogados) = crl.tbs_cert_list.revoked_certificates.as_ref() {
        for entrada in revogados {
            if entrada.serial_number != cert.tbs_certificate.serial_number {
                continue;
            }
            let quando = tempo_ms(&entrada.revocation_date)?;
            let motivo = motivo_de(entrada);
            if motivo.invalida_retroativamente() {
                return Err(CompError::Verify(format!(
                    "certificado `{}` revogado por {} em {} ms: um compromisso de chave \
                     invalida o carimbo em qualquer data, porque quem tem a chave pode \
                     carimbar com o genTime que quiser",
                    cert.tbs_certificate.subject,
                    motivo.label(),
                    quando
                )));
            }
            if quando <= gen_unix_ms {
                return Err(CompError::Verify(format!(
                    "certificado `{}` já estava revogado ({} ms) quando carimbou ({} ms)",
                    cert.tbs_certificate.subject, quando, gen_unix_ms
                )));
            }
            // Revogado DEPOIS de carimbar e sem compromisso: o carimbo
            // continua a provar a hora. É a razão de um carimbo existir.
        }
    }

    Ok(EstadoRevogacao {
        subject: cert.tbs_certificate.subject.to_string(),
        crl_next_update_ms: next_update,
        crl_this_update_ms: this_update,
    })
}

fn motivo_de(entrada: &x509_cert::crl::RevokedCert) -> RevocationReason {
    const OID_CRL_REASON: der::asn1::ObjectIdentifier =
        der::asn1::ObjectIdentifier::new_unwrap("2.5.29.21");
    let Some(exts) = entrada.crl_entry_extensions.as_ref() else {
        return RevocationReason::Outro(0);
    };
    let Some(ext) = exts.iter().find(|e| e.extn_id == OID_CRL_REASON) else {
        return RevocationReason::Outro(0);
    };
    // ENUMERATED de um octeto na esmagadora maioria dos casos. Um valor que
    // não se consegue ler é tratado como "outro" e NÃO como compromisso: se
    // fosse ao contrário, uma CRL malformada recusaria carimbos válidos.
    match der::asn1::Any::from_der(ext.extn_value.as_bytes()) {
        Ok(any) => {
            let bytes = any.value();
            bytes
                .last()
                .map(|v| RevocationReason::from_u8(*v))
                .unwrap_or(RevocationReason::Outro(0))
        }
        Err(_) => RevocationReason::Outro(0),
    }
}
