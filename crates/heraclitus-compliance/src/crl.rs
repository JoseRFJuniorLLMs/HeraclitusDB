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

use der::{Decode, Encode, Tagged};
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
    &x509_cert::spki::AlgorithmIdentifierOwned,
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
    /// Exigir que a CRL declare `nextUpdate`.
    ///
    /// `true` por defeito. Sem `nextUpdate` nao ha frescura nenhuma a impor e a
    /// CRL escapa por completo a `max_staleness`: uma CRL de 2019 responderia
    /// "nao revogado" com a mesma autoridade de uma de hoje. A RFC 5280 diz que
    /// as ACs conformes DEVEM emitir `nextUpdate`, portanto exigi-lo nao recusa
    /// nada de legitimo.
    pub exigir_next_update: bool,
}

impl Default for CrlPolicy {
    fn default() -> Self {
        Self {
            max_staleness: std::time::Duration::ZERO,
            exigir_next_update: true,
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

    /// Acrescenta uma CRL ja descodificada — usada para as que viajam dentro
    /// do proprio token.
    pub fn acrescentar(&mut self, crl: CertificateList) {
        let Ok(issuer) = crl.tbs_cert_list.issuer.to_der() else {
            return;
        };
        self.por_emissor.entry(issuer).or_default().push(crl);
        self.total += 1;
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

/// Extensões de CRL que este validador processa. Uma extensão CRÍTICA fora
/// desta lista faz recusar a CRL (RFC 5280 §5.2 + §6.3.3).
const OID_DELTA_CRL_INDICATOR: der::asn1::ObjectIdentifier =
    der::asn1::ObjectIdentifier::new_unwrap("2.5.29.27");
const OID_ISSUING_DISTRIBUTION_POINT: der::asn1::ObjectIdentifier =
    der::asn1::ObjectIdentifier::new_unwrap("2.5.29.28");
const OID_CRL_NUMBER: der::asn1::ObjectIdentifier =
    der::asn1::ObjectIdentifier::new_unwrap("2.5.29.20");
const OID_AUTHORITY_KEY_ID: der::asn1::ObjectIdentifier =
    der::asn1::ObjectIdentifier::new_unwrap("2.5.29.35");

/// §5.2 — o âmbito da CRL. Uma CRL parcial usada como se fosse completa
/// responde "não revogado" sobre certificados que ela nunca teve de cobrir.
/// As seis perguntas do `issuingDistributionPoint` (§5.2.5), separadas de
/// [`verificar_ambito`] para poderem ser verificadas sem construir uma CRL DER
/// inteira — é aqui que se decide se uma CRL responde sequer à pergunta que lhe
/// estamos a fazer, e essa decisão merece testes directos.
///
/// A regra em todas elas é a mesma: se a CRL declara um âmbito que este
/// validador não sabe casar com o certificado em mãos, recusa-se. Aceitar
/// significaria responder "não revogado" a partir de uma lista que nunca teve
/// de conter aquele serial.
fn verificar_idp(
    idp: &x509_cert::ext::pkix::IssuingDistributionPoint,
    e_ca: bool,
) -> Result<(), CompError> {
    // §5.2.5 — uma CRL com `distributionPoint` cobre SO os
    // certificados cujo `cRLDistributionPoints` aponta para ali.
    // Tratar uma particao como se fosse a lista completa do emissor
    // e responder "nao revogado" sobre seriais que ela nunca teve de
    // listar — exactamente a falha que o cabecalho desta funcao
    // descreve, e que faltava implementar.
    //
    // Saber se ESTE certificado pertence a esta particao exige
    // comparar `GeneralNames` com o CDP do proprio certificado.
    // Enquanto isso nao existir, a resposta honesta e recusar: o
    // resto da funcao ja segue esta regra para tudo o que nao sabe
    // interpretar.
    if idp.distribution_point.is_some() {
        return Err(CompError::Verify(
            "CRL de uma PARTICAO: o issuingDistributionPoint traz distributionPoint, logo ela cobre so os certificados que apontam para esse ponto. Usa-la como completa daria 'nao revogado' a quem esta revogado noutra particao. Instale a CRL completa do emissor"
                .into(),
        ));
    }
    // Uma CRL so de certificados de atributo nao diz nada sobre
    // certificados de chave publica, que sao os unicos que este
    // validador verifica.
    if idp.only_contains_attribute_certs {
        return Err(CompError::Verify(
            "CRL so de certificados de atributo (onlyContainsAttributeCerts) consultada para um certificado de chave publica"
                .into(),
        ));
    }
    if idp.only_some_reasons.is_some() {
        return Err(CompError::Verify(
            "CRL limitada a alguns motivos de revogação (onlySomeReasons): não \
             cobre todos os casos e usá-la como completa esconderia os restantes"
                .into(),
        ));
    }
    if idp.indirect_crl {
        return Err(CompError::Verify(
            "CRL indirecta (indirectCRL): as entradas podem pertencer a outros \
             emissores via certificateIssuer, que este validador não interpreta"
                .into(),
        ));
    }
    // Uma CRL só de utilizadores não diz nada sobre uma AC, e
    // vice-versa. Responder com ela é responder à pergunta errada.
    if idp.only_contains_ca_certs && !e_ca {
        return Err(CompError::Verify(
            "CRL só de certificados de AC consultada para um certificado de fim de \
             entidade"
                .into(),
        ));
    }
    if idp.only_contains_user_certs && e_ca {
        return Err(CompError::Verify(
            "CRL só de certificados de utilizador consultada para uma AC".into(),
        ));
    }
    Ok(())
}

fn verificar_ambito(crl: &CertificateList, e_ca: bool) -> Result<(), CompError> {
    let Some(exts) = crl.tbs_cert_list.crl_extensions.as_ref() else {
        return Ok(());
    };
    for ext in exts.iter() {
        match ext.extn_id {
            // §5.2.4 — uma delta CRL lista só o que MUDOU desde uma CRL base.
            // Tratá-la como completa é responder "não revogado" sobre tudo o
            // que foi revogado antes dela. É sempre crítica, por esta razão.
            OID_DELTA_CRL_INDICATOR => {
                return Err(CompError::Verify(
                    "esta é uma delta CRL: lista só as alterações desde uma CRL base e usá-la \
                     como completa daria 'não revogado' a tudo o que foi revogado antes. \
                     Instale a CRL completa"
                        .into(),
                ))
            }
            OID_ISSUING_DISTRIBUTION_POINT => {
                let idp = x509_cert::ext::pkix::IssuingDistributionPoint::from_der(
                    ext.extn_value.as_bytes(),
                )
                .map_err(|e| {
                    CompError::Verify(format!("issuingDistributionPoint inválido: {e}"))
                })?;
                verificar_idp(&idp, e_ca)?;
            }
            // Conhecidas e sem efeito na decisão.
            OID_CRL_NUMBER | OID_AUTHORITY_KEY_ID => {}
            outro if ext.critical => {
                return Err(CompError::Verify(format!(
                    "CRL com a extensão crítica {outro} que este validador não processa: §5.2 \
                     manda recusar, porque crítica significa que ignorá-la muda a resposta"
                )))
            }
            _ => {}
        }
    }
    Ok(())
}

/// Todas as CRLs deste emissor que servem: assinatura confere, âmbito
/// compatível e dentro da janela permitida.
///
/// Devolve **todas** e não a primeira. Consultar só a primeira era um buraco
/// real: um emissor com CRLs particionadas (ou simplesmente com duas versões na
/// pasta) tem o serial revogado numa e ausente noutra, e a primeira que
/// aparecesse decidia. O ficheiro que o `read_dir` devolvesse primeiro passava
/// a ser a política de revogação do órgão.
#[allow(clippy::type_complexity)]
fn crls_utilizaveis<'a>(
    crls: &'a [CertificateList],
    emissor: &x509_cert::Certificate,
    e_ca: bool,
    now_unix_ms: u64,
    policy: &CrlPolicy,
    verificar_assinatura: VerificadorAssinatura<'_>,
    tempo_ms: ConversorTempo<'_>,
) -> Result<Vec<(&'a CertificateList, u64, Option<u64>)>, CompError> {
    // §6.3.3 — quem assina uma CRL tem de o poder fazer. `keyCertSign` não
    // basta: são bits diferentes e a AC pode delegar um sem o outro.
    crate::constraints::exigir_key_usage(
        emissor,
        x509_cert::ext::pkix::KeyUsages::CRLSign,
        "assinar CRLs (cRLSign)",
    )?;

    let mut boas = Vec::new();
    let mut motivos: Vec<String> = Vec::new();
    for crl in crls {
        let tbs = match crl.tbs_cert_list.to_der() {
            Ok(t) => t,
            Err(e) => {
                motivos.push(format!("tbsCertList não codifica: {e}"));
                continue;
            }
        };
        let Some(assinatura) = crl.signature.as_bytes() else {
            motivos.push("assinatura da CRL não alinhada em bytes".into());
            continue;
        };
        // A CRL é uma afirmação da AC. Sem verificar a assinatura, qualquer um
        // que escreva na pasta pode declarar um certificado como não revogado —
        // e é essa a resposta que passa despercebida.
        if let Err(e) = verificar_assinatura(emissor, &crl.signature_algorithm, &tbs, assinatura) {
            // Distinguir "não sei verificar" de "não confere": a segunda
            // lê-se como CRL adulterada e a primeira é uma lacuna nossa.
            motivos.push(if e.to_string().contains("não suportado") {
                format!("algoritmo da CRL não suportado: {e}")
            } else {
                format!("assinatura da CRL não confere: {e}")
            });
            continue;
        }
        if let Err(e) = verificar_ambito(crl, e_ca) {
            motivos.push(e.to_string());
            continue;
        }
        let this_update = match tempo_ms(&crl.tbs_cert_list.this_update) {
            Ok(t) => t,
            Err(e) => {
                motivos.push(e.to_string());
                continue;
            }
        };
        if this_update > now_unix_ms {
            motivos.push("CRL com thisUpdate no futuro".into());
            continue;
        }
        let next_update = match crl.tbs_cert_list.next_update.as_ref() {
            Some(t) => match tempo_ms(t) {
                Ok(v) => Some(v),
                Err(e) => {
                    motivos.push(e.to_string());
                    continue;
                }
            },
            None => None,
        };
        match next_update {
            Some(fim) => {
                let limite = fim.saturating_add(policy.max_staleness.as_millis() as u64);
                if now_unix_ms > limite {
                    motivos.push(format!(
                        "CRL expirou em {fim} ms e a tolerância configurada é de {} s",
                        policy.max_staleness.as_secs()
                    ));
                    continue;
                }
            }
            None if policy.exigir_next_update => {
                // Sem `nextUpdate` não há frescura nenhuma a impor: a CRL
                // escapava por completo à política. Uma CRL de 2019 respondia
                // "não revogado" com a mesma autoridade de uma de hoje.
                motivos.push(
                    "CRL sem nextUpdate: não declara até quando é válida, e a política de \
                     frescura não teria nada contra que a medir"
                        .into(),
                );
                continue;
            }
            None => {}
        }
        boas.push((crl, this_update, next_update));
    }
    if boas.is_empty() {
        return Err(CompError::Verify(format!(
            "nenhuma CRL utilizável: {}",
            if motivos.is_empty() {
                "nenhuma CRL para este emissor".to_string()
            } else {
                motivos.join(" · ")
            }
        )));
    }
    Ok(boas)
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
    e_ca: bool,
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
    let boas = crls_utilizaveis(
        crls,
        emissor,
        e_ca,
        now_unix_ms,
        policy,
        verificar_assinatura,
        tempo_ms,
    )
    .map_err(|e| CompError::Verify(format!("emissor `{}`: {e}", cert.tbs_certificate.issuer)))?;

    // A janela de confiança do conjunto é a MAIS CURTA: a informação só é boa
    // enquanto TODAS as CRLs que se consultaram continuarem válidas.
    let mut next_update_min: Option<u64> = None;
    let mut this_update_max = 0u64;

    for (crl, this_update, next_update) in &boas {
        this_update_max = this_update_max.max(*this_update);
        next_update_min = match (next_update_min, next_update) {
            (Some(a), Some(b)) => Some(a.min(*b)),
            (None, Some(b)) => Some(*b),
            (a, None) => a,
        };
        let Some(revogados) = crl.tbs_cert_list.revoked_certificates.as_ref() else {
            continue;
        };
        for entrada in revogados {
            if entrada.serial_number != cert.tbs_certificate.serial_number {
                continue;
            }
            let quando = tempo_ms(&entrada.revocation_date)?;
            let motivo = motivo_de(entrada)?;
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
        crl_next_update_ms: next_update_min,
        crl_this_update_ms: this_update_max,
    })
}

/// Lê o `reasonCode` (2.5.29.21) de uma entrada.
///
/// A etiqueta é verificada. Ler o último octeto de um valor cuja etiqueta
/// ninguém confirmou aceitaria, por exemplo, um OCTET STRING cujo último byte
/// calhasse ser 1 — e trataria como `keyCompromise` uma entrada que não o é.
/// No sentido inverso, um `reasonCode` que não se consegue ler é um erro e não
/// um "outro": tratar o ilegível como benigno é a leitura que deixa passar
/// exactamente o que interessa apanhar.
fn motivo_de(entrada: &x509_cert::crl::RevokedCert) -> Result<RevocationReason, CompError> {
    const OID_CRL_REASON: der::asn1::ObjectIdentifier =
        der::asn1::ObjectIdentifier::new_unwrap("2.5.29.21");
    let Some(exts) = entrada.crl_entry_extensions.as_ref() else {
        return Ok(RevocationReason::Outro(0));
    };
    let Some(ext) = exts.iter().find(|e| e.extn_id == OID_CRL_REASON) else {
        return Ok(RevocationReason::Outro(0));
    };
    let any = der::asn1::Any::from_der(ext.extn_value.as_bytes()).map_err(|e| {
        CompError::Verify(format!(
            "reasonCode não é DER válido: {e} — uma entrada de CRL ilegível não pode ser \
             tratada como revogação benigna"
        ))
    })?;
    if any.tag() != der::Tag::Enumerated {
        return Err(CompError::Verify(format!(
            "reasonCode com etiqueta {} em vez de ENUMERATED: recusado em vez de interpretado",
            any.tag()
        )));
    }
    let bytes = any.value();
    let v = bytes
        .last()
        .copied()
        .ok_or_else(|| CompError::Verify("reasonCode ENUMERATED vazio".into()))?;
    Ok(RevocationReason::from_u8(v))
}

#[cfg(test)]
mod testes_ambito {
    use super::*;
    use x509_cert::ext::pkix::{
        name::{DistributionPointName, GeneralName, GeneralNames},
        IssuingDistributionPoint,
    };

    fn idp() -> IssuingDistributionPoint {
        IssuingDistributionPoint {
            distribution_point: None,
            only_contains_user_certs: false,
            only_contains_ca_certs: false,
            only_some_reasons: None,
            indirect_crl: false,
            only_contains_attribute_certs: false,
        }
    }

    /// Uma CRL sem âmbito declarado cobre o emissor inteiro: é a única que
    /// responde à pergunta que lhe fazemos.
    #[test]
    fn sem_ambito_declarado_serve() {
        assert!(verificar_idp(&idp(), false).is_ok());
        assert!(verificar_idp(&idp(), true).is_ok());
    }

    /// O buraco que isto fecha: uma CRL de UMA partição era aceite como se
    /// listasse tudo o que o emissor revogou. Um serial revogado noutra
    /// partição respondia "não revogado" — a pior resposta possível de um
    /// verificador de revogação, porque é silenciosa e parece um sucesso.
    #[test]
    fn uma_particao_nao_passa_por_lista_completa() {
        let mut p = idp();
        p.distribution_point = Some(DistributionPointName::FullName(GeneralNames::from(vec![
            GeneralName::UniformResourceIdentifier(
                "http://ac.example/actcrl-1.crl"
                    .to_owned()
                    .try_into()
                    .unwrap(),
            ),
        ])));
        let erro = verificar_idp(&p, false).unwrap_err().to_string();
        assert!(erro.contains("PARTICAO"), "{erro}");
    }

    /// Certificados de atributo são outra coisa; esta CRL não diz nada sobre
    /// os certificados de chave pública que este validador verifica.
    #[test]
    fn crl_so_de_certificados_de_atributo_nao_serve() {
        let mut p = idp();
        p.only_contains_attribute_certs = true;
        assert!(verificar_idp(&p, false).is_err());
    }

    /// Os âmbitos que já eram recusados continuam a sê-lo — a extracção não
    /// pode ter perdido nenhum pelo caminho.
    #[test]
    fn os_ambitos_ja_cobertos_continuam_recusados() {
        let mut indirecta = idp();
        indirecta.indirect_crl = true;
        assert!(verificar_idp(&indirecta, false).is_err());

        // Só de AC, perguntada sobre uma entidade final: pergunta errada.
        let mut so_ac = idp();
        so_ac.only_contains_ca_certs = true;
        assert!(verificar_idp(&so_ac, false).is_err());
        assert!(verificar_idp(&so_ac, true).is_ok(), "sobre uma AC serve");

        // E o simétrico.
        let mut so_utilizador = idp();
        so_utilizador.only_contains_user_certs = true;
        assert!(verificar_idp(&so_utilizador, true).is_err());
        assert!(verificar_idp(&so_utilizador, false).is_ok());
    }
}
