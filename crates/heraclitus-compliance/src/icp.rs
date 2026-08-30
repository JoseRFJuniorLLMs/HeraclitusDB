//! SPEC-0046 §9 — `IcpBrasilTimestampVerifier`: verificação de produção de um
//! `TimeStampToken` RFC 3161.
//!
//! # O que muda face ao que havia
//!
//! O verificador anterior ([`crate::verify::verify_dev_token`]) tira a chave
//! **de dentro do próprio token**. Isso deteta corrupção e nada mais: quem
//! forjar um par de chaves produz um recibo que passa. O doc-comment dele
//! diz-lo, e essa honestidade é o que impedia o sistema de afirmar conformidade
//! que não tinha (C4/C5).
//!
//! Este módulo fecha o buraco: a chave que valida a assinatura vem de um
//! certificado que tem de encadear até uma âncora que o **operador** instalou
//! (§11), e não do documento que se está a verificar. É a diferença entre
//! "estes bytes não foram alterados" e "uma autoridade credenciada afirmou
//! esta hora".
//!
//! # A ordem das verificações não é arbitrária
//!
//! Cada passo assume o anterior, e trocá-los cria buracos concretos:
//!
//! 1. **Tamanho**, antes de qualquer parsing — um token de 200 MB não pode
//!    fazer o verificador alocar antes de ser recusado.
//! 2. **Estrutura CMS**, e `eContentType == id-ct-TSTInfo`. Um `SignedData`
//!    que encapsula outra coisa não é um carimbo, por muito válida que seja a
//!    assinatura.
//! 3. **Cadeia até uma âncora**, ANTES de verificar a assinatura. Verificar
//!    primeiro a assinatura e só depois a cadeia gasta CPU a validar
//!    assinaturas de emissores desconhecidos — e, pior, convida ao erro de
//!    reportar "assinatura válida" para um token que ninguém devia aceitar.
//! 4. **Assinatura sobre os `signedAttrs`**, com a chave do certificado já
//!    ancorado.
//! 5. **`messageDigest`** dos atributos contra o digest do `eContent`. Sem
//!    isto, a assinatura cobre os atributos e o conteúdo podia ser outro —
//!    é a ligação entre o que foi assinado e o que se está a ler.
//! 6. **`TSTInfo`**: imprint, algoritmo, nonce, política, `genTime`.
//!
//! # O que este módulo NÃO faz, e é preciso dizer
//!
//! **Revogação.** A §9 lista `revocation information` "conforme aplicável".
//! Não há aqui consulta de CRL nem de OCSP: um certificado revogado **passa**
//! esta verificação se ainda estiver dentro da validade. Isso é uma lacuna
//! real e está declarada em [`VerifiedTimestamp::revocation_checked`], que é
//! sempre `false`. Fingir que se verificou seria o modo de falha que a C5
//! existe para impedir.
//!
//! **Cross-certificação e políticas de nome.** A construção da cadeia é por
//! correspondência exacta de `issuer`/`subject` em DER, com verificação de
//! `basicConstraints`. Não implementa `nameConstraints` nem `policyMapping` do
//! RFC 5280. Para a topologia da ICP-Brasil — raiz → AC intermédia → ACT — é
//! suficiente; para uma malha com cross-certificados não é, e recusa em vez de
//! adivinhar.

use std::time::Duration;

use const_oid::ObjectIdentifier;
use der::asn1::{GeneralizedTime, Int, OctetString, SetOfVec};
use der::{Any, Decode, Encode, Sequence};
use x509_cert::ext::pkix::{BasicConstraints, ExtendedKeyUsage};
use x509_cert::time::Time;
use x509_cert::Certificate;

use crate::trust_store::{sha256, TrustStore};
use crate::CompError;

// ---------------------------------------------------------------------------
// OIDs
// ---------------------------------------------------------------------------
// Declarados aqui, com a referência ao lado, em vez de vindos de um `db`: num
// crate de compliance, o OID e a norma que o define têm de ser legíveis juntos.

/// RFC 5652 §5 — `id-signedData`.
const OID_SIGNED_DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.2");
/// RFC 3161 §2.4.2 — `id-ct-TSTInfo`.
const OID_CT_TST_INFO: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.1.4");
/// RFC 5652 §11.1 — `id-contentType`.
const OID_ATTR_CONTENT_TYPE: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.3");
/// RFC 5652 §11.2 — `id-messageDigest`.
const OID_ATTR_MESSAGE_DIGEST: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.4");
/// RFC 5280 — `id-kp-timeStamping`.
const OID_KP_TIME_STAMPING: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.8");
/// NIST — `id-sha256`.
const OID_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1");
/// PKCS#1 — `sha256WithRSAEncryption`.
const OID_SHA256_RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");
/// PKCS#1 — `rsaEncryption` (o algoritmo da chave pública).
const OID_RSA_ENCRYPTION: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");
/// ANSI X9.62 — `ecdsa-with-SHA256`.
const OID_ECDSA_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");
/// ANSI X9.62 — `id-ecPublicKey`.
const OID_EC_PUBLIC_KEY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
/// SECG — `prime256v1` / NIST P-256.
const OID_PRIME256V1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");

// ---------------------------------------------------------------------------
// TSTInfo (RFC 3161 §2.4.2)
// ---------------------------------------------------------------------------

/// `MessageImprint ::= SEQUENCE { hashAlgorithm AlgorithmIdentifier, hashedMessage OCTET STRING }`
#[derive(Debug, Clone, Sequence)]
pub struct MessageImprint {
    pub hash_algorithm: x509_cert::spki::AlgorithmIdentifierOwned,
    pub hashed_message: OctetString,
}

/// `Accuracy ::= SEQUENCE { seconds INTEGER OPTIONAL, millis [0] ..., micros [1] ... }`
#[derive(Debug, Clone, Sequence)]
pub struct Accuracy {
    #[asn1(optional = "true")]
    pub seconds: Option<u64>,
    #[asn1(context_specific = "0", tag_mode = "IMPLICIT", optional = "true")]
    pub millis: Option<u16>,
    #[asn1(context_specific = "1", tag_mode = "IMPLICIT", optional = "true")]
    pub micros: Option<u16>,
}

/// `TSTInfo` de RFC 3161 §2.4.2.
///
/// Os campos opcionais que este verificador não usa continuam declarados: um
/// `TSTInfo` real traz `tsa` e extensões, e um parser que os não conhecesse
/// falharia a descodificar tokens legítimos.
#[derive(Debug, Clone, Sequence)]
pub struct TstInfo {
    pub version: u8,
    pub policy: ObjectIdentifier,
    pub message_imprint: MessageImprint,
    pub serial_number: Int,
    pub gen_time: GeneralizedTime,
    #[asn1(optional = "true")]
    pub accuracy: Option<Accuracy>,
    #[asn1(default = "Default::default")]
    pub ordering: bool,
    #[asn1(optional = "true")]
    pub nonce: Option<Int>,
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT", optional = "true")]
    pub tsa: Option<Any>,
    #[asn1(context_specific = "1", tag_mode = "IMPLICIT", optional = "true")]
    pub extensions: Option<Any>,
}

// ---------------------------------------------------------------------------
// Política e resultado
// ---------------------------------------------------------------------------

/// SPEC-0046 §9.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimestampValidationPolicy {
    /// Quando `Some`, o `TSTInfo.policy` tem de ser exactamente este. É como
    /// um órgão exige que o carimbo tenha sido emitido sob a política de
    /// carimbo credenciada, e não sob uma política de teste da mesma ACT.
    pub required_policy_oid: Option<ObjectIdentifier>,
    /// Tolerância entre o `genTime` e o relógio local. Um carimbo do futuro
    /// além desta margem é recusado: ou o relógio local está atrasado, ou o
    /// token foi fabricado.
    pub max_clock_skew: Duration,
    /// Profundidade máxima da cadeia. Limita o esforço e uma cadeia
    /// artificialmente longa.
    pub max_chain_depth: usize,
    /// Tecto do token, aplicado antes de qualquer parsing.
    pub max_token_bytes: usize,
}

impl Default for TimestampValidationPolicy {
    fn default() -> Self {
        Self {
            // Sem OID exigido por omissão: fixá-lo aqui seria hardcodar
            // política de uma jurisdição no core, que é o que §11 proíbe para
            // os nomes das ACTs e vale igualmente para as políticas.
            required_policy_oid: None,
            max_clock_skew: Duration::from_secs(300),
            max_chain_depth: 8,
            max_token_bytes: 512 * 1024,
        }
    }
}

/// O que uma verificação bem-sucedida apurou.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedTimestamp {
    /// Hora afirmada pela autoridade, em ms desde a época.
    pub gen_unix_ms: u64,
    /// A política sob a qual a ACT emitiu.
    pub policy_oid: ObjectIdentifier,
    /// Número de série do carimbo, em hex — é por ele que se pede à ACT que
    /// confirme uma emissão.
    pub serial_hex: String,
    /// Subject do certificado que assinou.
    pub signer_subject: String,
    /// Âncora a que a cadeia chegou. Diz ao operador **qual** das raízes que
    /// instalou é que sustenta este carimbo.
    pub anchor_fingerprint_hex: String,
    /// Nº de certificados entre o signatário e a âncora, inclusive.
    pub chain_len: usize,
    /// Precisão declarada, em segundos, quando a ACT a declara.
    pub accuracy_secs: Option<u64>,
    /// `true` só quando o pedido trazia nonce **e** o token o devolveu igual.
    pub nonce_matched: bool,
    /// **Sempre `false`.** Este verificador não consulta CRL nem OCSP; um
    /// certificado revogado mas dentro da validade passa. Está no resultado, e
    /// não só na documentação, para que quem construa um relatório a partir
    /// disto não possa afirmar mais do que foi feito.
    pub revocation_checked: bool,
}

/// SPEC-0046 §9.
#[derive(Debug, Clone)]
pub struct IcpBrasilTimestampVerifier {
    /// CRLs e regra de frescura, quando o operador as instalou.
    crls: Option<(crate::crl::CrlStore, crate::crl::CrlPolicy)>,
    trust_store: TrustStore,
    policy: TimestampValidationPolicy,
}

impl IcpBrasilTimestampVerifier {
    /// Instala a consulta de revogação por CRL.
    ///
    /// Sem isto, `revocation_checked` é `false` e um certificado revogado
    /// dentro da validade passa — o que está declarado no resultado, mas
    /// continua a ser a lacuna. Com isto, cada certificado da cadeia tem de ter
    /// uma CRL assinada pelo seu emissor e dentro da janela, ou a verificação
    /// FALHA: "pedi consulta de revogação e não a consegui fazer" não pode
    /// devolver um resultado que se leia como limpo.
    pub fn with_crls(mut self, store: crate::crl::CrlStore, policy: crate::crl::CrlPolicy) -> Self {
        self.crls = Some((store, policy));
        self
    }

    pub fn new(trust_store: TrustStore, policy: TimestampValidationPolicy) -> Self {
        Self {
            crls: None,
            trust_store,
            policy,
        }
    }

    pub fn trust_store(&self) -> &TrustStore {
        &self.trust_store
    }

    pub fn policy(&self) -> &TimestampValidationPolicy {
        &self.policy
    }

    /// Verifica um `TimeStampToken` contra o imprint esperado.
    ///
    /// `expected_nonce` é o nonce que o pedido levou, quando levou. Passar
    /// `None` **não** desactiva verificação nenhuma: significa que o pedido não
    /// tinha nonce, e nesse caso o token também não devia ter um.
    ///
    /// `now_unix_ms` é injectado em vez de lido do relógio para que a
    /// verificação seja reproduzível — o mesmo token verificado no mesmo
    /// instante lógico dá sempre o mesmo resultado.
    pub fn verify(
        &self,
        token_der: &[u8],
        expected_imprint: &[u8; 32],
        expected_nonce: Option<&[u8]>,
        now_unix_ms: u64,
    ) -> Result<VerifiedTimestamp, CompError> {
        // 1 — tecto antes de tocar no conteúdo.
        if token_der.len() > self.policy.max_token_bytes {
            return Err(verify_err(format!(
                "token de {} bytes acima do tecto de {}",
                token_der.len(),
                self.policy.max_token_bytes
            )));
        }
        if self.trust_store.is_empty() {
            // §11 — sem âncoras não há nada a validar contra, e devolver "ok"
            // seria a pior resposta possível.
            return Err(verify_err(
                "trust store vazio: nenhuma ACT credenciada configurada (§11)".into(),
            ));
        }

        // 2 — estrutura CMS.
        let content = cms::content_info::ContentInfo::from_der(token_der)
            .map_err(|e| verify_err(format!("ContentInfo inválido: {e}")))?;
        if content.content_type != OID_SIGNED_DATA {
            return Err(verify_err(format!(
                "contentType {} não é id-signedData",
                content.content_type
            )));
        }
        let signed = content
            .content
            .decode_as::<cms::signed_data::SignedData>()
            .map_err(|e| verify_err(format!("SignedData inválido: {e}")))?;

        if signed.encap_content_info.econtent_type != OID_CT_TST_INFO {
            return Err(verify_err(format!(
                "eContentType {} não é id-ct-TSTInfo: isto não é um carimbo",
                signed.encap_content_info.econtent_type
            )));
        }
        let econtent = signed
            .encap_content_info
            .econtent
            .as_ref()
            .ok_or_else(|| verify_err("SignedData sem eContent".into()))?;
        // O `eContent` é um OCTET STRING que embrulha o DER do TSTInfo.
        let tst_der = econtent
            .decode_as::<OctetString>()
            .map_err(|e| verify_err(format!("eContent não é OCTET STRING: {e}")))?;
        let tst_bytes = tst_der.as_bytes();

        // Um token com mais de um signatário é ambíguo: qual das assinaturas
        // é que sustenta a hora? Recusar é mais honesto do que escolher uma.
        let signers: Vec<_> = signed.signer_infos.0.iter().collect();
        let signer = match signers.as_slice() {
            [único] => *único,
            [] => return Err(verify_err("SignedData sem SignerInfo".into())),
            outros => {
                return Err(verify_err(format!(
                    "{} signatários no carimbo; qual sustenta a hora é ambíguo",
                    outros.len()
                )))
            }
        };

        // 3 — cadeia até uma âncora, ANTES de gastar CPU em assinaturas.
        let certificados = certificados_de(&signed)?;
        let signer_cert = encontrar_signatario(&certificados, &signer.sid)?;
        let cadeia = self.construir_cadeia(signer_cert, &certificados)?;
        let ancora = cadeia.anchor;

        // 4 — assinatura sobre os signedAttrs.
        let attrs = signer
            .signed_attrs
            .as_ref()
            .ok_or_else(|| verify_err(
                // RFC 5652 §5.3: quando há signedAttrs a assinatura é sobre
                // eles; sem eles seria sobre o conteúdo. Aceitar as duas
                // formas duplica a superfície de verificação sem ganho — um
                // TimeStampToken traz sempre signedAttrs.
                "SignerInfo sem signedAttrs: forma não suportada".into(),
            ))?;
        let attrs_der = reencode_signed_attrs(attrs)?;
        verificar_assinatura(
            signer_cert,
            &signer.signature_algorithm.oid,
            &attrs_der,
            signer.signature.as_bytes(),
        )?;

        // 5 — os atributos assinados descrevem ESTE conteúdo.
        verificar_atributos(attrs, tst_bytes)?;

        // 6 — o TSTInfo.
        let tst = TstInfo::from_der(tst_bytes)
            .map_err(|e| verify_err(format!("TSTInfo inválido: {e}")))?;
        if tst.version != 1 {
            return Err(verify_err(format!(
                "TSTInfo versão {} não suportada",
                tst.version
            )));
        }
        if let Some(exigida) = self.policy.required_policy_oid {
            if tst.policy != exigida {
                return Err(verify_err(format!(
                    "política do carimbo {} não é a exigida {exigida}",
                    tst.policy
                )));
            }
        }
        if tst.message_imprint.hash_algorithm.oid != OID_SHA256 {
            return Err(verify_err(format!(
                "messageImprint em {} — só SHA-256 é aceite",
                tst.message_imprint.hash_algorithm.oid
            )));
        }
        if tst.message_imprint.hashed_message.as_bytes() != expected_imprint.as_slice() {
            return Err(verify_err(
                "o carimbo é sobre outro conteúdo (messageImprint não confere)".into(),
            ));
        }

        let nonce_matched = match (expected_nonce, tst.nonce.as_ref()) {
            (Some(esperado), Some(recebido)) => {
                if recebido.as_bytes() != esperado {
                    return Err(verify_err(
                        "nonce do carimbo não é o do pedido: possível repetição".into(),
                    ));
                }
                true
            }
            (Some(_), None) => {
                return Err(verify_err(
                    "pedido levou nonce e o carimbo não o devolveu".into(),
                ))
            }
            // Um nonce que ninguém pediu não é um erro do carimbo; é um campo
            // a mais que simplesmente não prova frescura.
            (None, _) => false,
        };

        let gen_unix_ms = generalized_para_unix_ms(&tst.gen_time)?;
        let skew = self.policy.max_clock_skew.as_millis() as u64;
        if gen_unix_ms > now_unix_ms.saturating_add(skew) {
            return Err(verify_err(format!(
                "carimbo do futuro: genTime {gen_unix_ms} ms além da tolerância de {skew} ms"
            )));
        }

        // A validade de cada certificado é aferida no instante do CARIMBO, não
        // no de hoje: um carimbo emitido enquanto o certificado era válido
        // continua a provar a hora depois de ele expirar — é essa a razão de
        // existir de um carimbo do tempo.
        for cert in &cadeia.certs {
            validade_em(cert, gen_unix_ms)?;
        }
        verificar_eku_timestamping(signer_cert)?;

        // §9 — revogação. Só depois de a cadeia estar validada: consultar uma
        // CRL para um certificado que nem encadeia seria trabalho sobre uma
        // premissa falsa, e um erro de revogação aqui leria-se como se o
        // problema fosse a revogação quando é a cadeia.
        let revocation_checked = self.verificar_revogacao(&cadeia, gen_unix_ms, now_unix_ms)?;

        Ok(VerifiedTimestamp {
            gen_unix_ms,
            policy_oid: tst.policy,
            serial_hex: hex(tst.serial_number.as_bytes()),
            signer_subject: signer_cert.tbs_certificate.subject.to_string(),
            anchor_fingerprint_hex: hex(&ancora),
            chain_len: cadeia.certs.len(),
            accuracy_secs: tst.accuracy.as_ref().and_then(|a| a.seconds),
            nonce_matched,
            revocation_checked,
        })
    }

    /// Consulta a revogação de cada certificado da cadeia. Devolve `true` se a
    /// consulta foi feita, `false` se não há CRLs instaladas, e `Err` se foi
    /// pedida e não pôde ser concluída.
    ///
    /// A âncora NÃO é consultada: uma raiz auto-emitida não é revogada por uma
    /// CRL sua — retirá-la da confiança é remover o ficheiro da pasta, que é o
    /// mecanismo que o operador tem e vê.
    fn verificar_revogacao(
        &self,
        cadeia: &Cadeia,
        gen_unix_ms: u64,
        now_unix_ms: u64,
    ) -> Result<bool, CompError> {
        let Some((store, politica)) = self.crls.as_ref() else {
            return Ok(false);
        };
        let assinatura = |emissor: &Certificate,
                          oid: &ObjectIdentifier,
                          msg: &[u8],
                          sig: &[u8]| verificar_assinatura(emissor, oid, msg, sig);
        let tempo = |t: &x509_cert::time::Time| tempo_para_unix_ms(t);

        for (i, cert) in cadeia.certs.iter().enumerate() {
            // O emissor é o elo seguinte da cadeia; para o último, é a âncora.
            let emissor = cadeia.certs.get(i + 1).unwrap_or(&cadeia.anchor_cert);
            crate::crl::consultar(
                store,
                cert,
                emissor,
                gen_unix_ms,
                now_unix_ms,
                politica,
                &assinatura,
                &tempo,
            )?;
        }
        Ok(true)
    }

    /// Constrói a cadeia do signatário até uma âncora do trust store.
    fn construir_cadeia(
        &self,
        signer: &Certificate,
        pool: &[Certificate],
    ) -> Result<Cadeia, CompError> {
        let mut certs: Vec<Certificate> = vec![signer.clone()];
        let mut atual = signer.clone();

        for _ in 0..self.policy.max_chain_depth {
            let issuer_der = atual
                .tbs_certificate
                .issuer
                .to_der()
                .map_err(|e| verify_err(format!("issuer não codifica: {e}")))?;

            // Uma âncora fecha a cadeia. Procura-se primeiro no trust store:
            // se o emissor é confiável, não interessa que o token traga uma
            // cópia dele.
            for anchor in self.trust_store.anchors_for_issuer(&issuer_der) {
                if verificar_emissao(&atual, &anchor.certificate).is_ok() {
                    return Ok(Cadeia {
                        certs,
                        anchor: anchor.fingerprint,
                        anchor_cert: anchor.certificate.clone(),
                    });
                }
            }

            // Senão, um intermédio do próprio token.
            let intermedio = pool.iter().find(|c| {
                c.tbs_certificate
                    .subject
                    .to_der()
                    .map(|s| s == issuer_der)
                    .unwrap_or(false)
                    && !mesmo_certificado(c, &atual)
            });
            let Some(intermedio) = intermedio else {
                return Err(verify_err(format!(
                    "cadeia não chega a nenhuma âncora configurada (emissor `{}` desconhecido)",
                    atual.tbs_certificate.issuer
                )));
            };
            // Um intermédio TEM de ser CA. Sem esta verificação, uma folha
            // qualquer emitida pela mesma AC podia assinar outra folha e a
            // cadeia fechava.
            verificar_ca(intermedio)?;
            verificar_emissao(&atual, intermedio)?;
            certs.push(intermedio.clone());
            atual = intermedio.clone();
        }
        Err(verify_err(format!(
            "cadeia excede a profundidade máxima de {}",
            self.policy.max_chain_depth
        )))
    }
}

struct Cadeia {
    certs: Vec<Certificate>,
    anchor: [u8; 32],
    /// O certificado da âncora. A impressão digital chega para identificar,
    /// mas não para verificar a assinatura da CRL que a âncora emite.
    anchor_cert: Certificate,
}

// ---------------------------------------------------------------------------
// Auxiliares
// ---------------------------------------------------------------------------

fn verify_err(detalhe: String) -> CompError {
    CompError::Verify(detalhe)
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(out, "{b:02x}");
    }
    out
}

fn mesmo_certificado(a: &Certificate, b: &Certificate) -> bool {
    match (a.to_der(), b.to_der()) {
        (Ok(x), Ok(y)) => x == y,
        _ => false,
    }
}

fn certificados_de(signed: &cms::signed_data::SignedData) -> Result<Vec<Certificate>, CompError> {
    let set = signed
        .certificates
        .as_ref()
        .ok_or_else(|| verify_err("SignedData sem certificados: nada para ancorar".into()))?;
    let mut out = Vec::new();
    for escolha in set.0.iter() {
        if let cms::cert::CertificateChoices::Certificate(cert) = escolha {
            out.push(cert.clone());
        }
        // `other`/attribute certificates não são um certificado X.509 de
        // signatário; ignorá-los é correcto, e não silencioso: se nenhum
        // X.509 sobrar, o passo seguinte falha a dizer que não encontrou o
        // signatário.
    }
    Ok(out)
}

fn encontrar_signatario<'a>(
    pool: &'a [Certificate],
    sid: &cms::signed_data::SignerIdentifier,
) -> Result<&'a Certificate, CompError> {
    match sid {
        cms::signed_data::SignerIdentifier::IssuerAndSerialNumber(ias) => {
            let alvo_issuer = ias
                .issuer
                .to_der()
                .map_err(|e| verify_err(format!("issuer do SID não codifica: {e}")))?;
            pool.iter()
                .find(|c| {
                    c.tbs_certificate
                        .issuer
                        .to_der()
                        .map(|i| i == alvo_issuer)
                        .unwrap_or(false)
                        && c.tbs_certificate.serial_number == ias.serial_number
                })
                .ok_or_else(|| {
                    verify_err("certificado do signatário não vem no token".into())
                })
        }
        cms::signed_data::SignerIdentifier::SubjectKeyIdentifier(skid) => {
            let alvo = skid.0.as_bytes();
            pool.iter()
                .find(|c| ski_de(c).as_deref() == Some(alvo))
                .ok_or_else(|| {
                    verify_err(
                        "certificado do signatário (por subjectKeyIdentifier) não vem no token"
                            .into(),
                    )
                })
        }
    }
}

fn ski_de(cert: &Certificate) -> Option<Vec<u8>> {
    const OID_SKI: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.14");
    let exts = cert.tbs_certificate.extensions.as_ref()?;
    let ext = exts.iter().find(|e| e.extn_id == OID_SKI)?;
    let os = OctetString::from_der(ext.extn_value.as_bytes()).ok()?;
    Some(os.as_bytes().to_vec())
}

/// RFC 5652 §5.4 — a assinatura é sobre o DER de um `SET OF Attribute`, e o
/// campo no `SignerInfo` vem com uma etiqueta `[0] IMPLICIT`. Reconstituir o
/// `SET OF` explícito é obrigatório: assinar sobre os bytes tal como aparecem
/// no token daria uma verificação que falha sempre.
fn reencode_signed_attrs(attrs: &cms::signed_data::SignedAttributes) -> Result<Vec<u8>, CompError> {
    let mut set: SetOfVec<x509_cert::attr::Attribute> = SetOfVec::new();
    for attr in attrs.iter() {
        set.insert(attr.clone())
            .map_err(|e| verify_err(format!("signedAttrs duplicados: {e}")))?;
    }
    set.to_der()
        .map_err(|e| verify_err(format!("signedAttrs não recodificam: {e}")))
}

fn verificar_atributos(
    attrs: &cms::signed_data::SignedAttributes,
    tst_bytes: &[u8],
) -> Result<(), CompError> {
    let mut viu_content_type = false;
    let mut viu_message_digest = false;
    for attr in attrs.iter() {
        if attr.oid == OID_ATTR_CONTENT_TYPE {
            let valor = attr
                .values
                .get(0)
                .ok_or_else(|| verify_err("contentType sem valor".into()))?;
            let oid = valor
                .decode_as::<ObjectIdentifier>()
                .map_err(|e| verify_err(format!("contentType inválido: {e}")))?;
            if oid != OID_CT_TST_INFO {
                return Err(verify_err(format!(
                    "contentType assinado é {oid}, não id-ct-TSTInfo"
                )));
            }
            viu_content_type = true;
        } else if attr.oid == OID_ATTR_MESSAGE_DIGEST {
            let valor = attr
                .values
                .get(0)
                .ok_or_else(|| verify_err("messageDigest sem valor".into()))?;
            let digest = valor
                .decode_as::<OctetString>()
                .map_err(|e| verify_err(format!("messageDigest inválido: {e}")))?;
            if digest.as_bytes() != sha256(tst_bytes) {
                // Este é o elo que liga a assinatura ao conteúdo. Sem ele, a
                // assinatura cobriria os atributos e o TSTInfo podia ser outro.
                return Err(verify_err(
                    "messageDigest assinado não corresponde ao TSTInfo do token".into(),
                ));
            }
            viu_message_digest = true;
        }
    }
    if !viu_content_type || !viu_message_digest {
        return Err(verify_err(
            "signedAttrs sem contentType ou sem messageDigest (RFC 5652 §11)".into(),
        ));
    }
    Ok(())
}

/// Verifica `assinatura` sobre `mensagem` com a chave pública de `cert`.
///
/// Só ECDSA-P256-SHA256 e RSA-PKCS#1v1.5-SHA256. Qualquer outro algoritmo é
/// **recusado com o OID no erro** em vez de ignorado: um verificador que passe
/// por cima de um algoritmo que não conhece é um verificador que aceita tudo.
fn verificar_assinatura(
    cert: &Certificate,
    algoritmo: &ObjectIdentifier,
    mensagem: &[u8],
    assinatura: &[u8],
) -> Result<(), CompError> {
    let spki = &cert.tbs_certificate.subject_public_key_info;
    match *algoritmo {
        OID_ECDSA_SHA256 => {
            if spki.algorithm.oid != OID_EC_PUBLIC_KEY {
                return Err(verify_err(
                    "assinatura ECDSA com uma chave que não é EC".into(),
                ));
            }
            let curva = spki
                .algorithm
                .parameters
                .as_ref()
                .and_then(|p| p.decode_as::<ObjectIdentifier>().ok());
            if curva != Some(OID_PRIME256V1) {
                return Err(verify_err(
                    "só a curva P-256 é suportada nesta verificação".into(),
                ));
            }
            let pontos = spki
                .subject_public_key
                .as_bytes()
                .ok_or_else(|| verify_err("chave pública EC não alinhada em bytes".into()))?;
            let vk = p256::ecdsa::VerifyingKey::from_sec1_bytes(pontos)
                .map_err(|e| verify_err(format!("chave pública EC inválida: {e}")))?;
            // O CMS traz a assinatura ECDSA em DER (SEQUENCE de r,s).
            let sig = p256::ecdsa::DerSignature::from_bytes(assinatura)
                .map_err(|e| verify_err(format!("assinatura ECDSA malformada: {e}")))?;
            use p256::ecdsa::signature::Verifier;
            vk.verify(mensagem, &sig)
                .map_err(|_| verify_err("assinatura do carimbo não confere".into()))
        }
        OID_SHA256_RSA => {
            if spki.algorithm.oid != OID_RSA_ENCRYPTION {
                return Err(verify_err(
                    "assinatura RSA com uma chave que não é RSA".into(),
                ));
            }
            let der = spki
                .subject_public_key
                .as_bytes()
                .ok_or_else(|| verify_err("chave pública RSA não alinhada em bytes".into()))?;
            let chave = <rsa::RsaPublicKey as rsa::pkcs1::DecodeRsaPublicKey>::from_pkcs1_der(der)
                .map_err(|e| verify_err(format!("chave pública RSA inválida: {e}")))?;
            use sha2::{Digest, Sha256};
            let digest = Sha256::digest(mensagem);
            let esquema = rsa::Pkcs1v15Sign::new::<Sha256>();
            chave
                .verify(esquema, &digest, assinatura)
                .map_err(|_| verify_err("assinatura do carimbo não confere".into()))
        }
        outro => Err(verify_err(format!(
            "algoritmo de assinatura {outro} não suportado; a verificação recusa em vez de o ignorar"
        ))),
    }
}

fn verificar_emissao(filho: &Certificate, emissor: &Certificate) -> Result<(), CompError> {
    let tbs = filho
        .tbs_certificate
        .to_der()
        .map_err(|e| verify_err(format!("tbsCertificate não codifica: {e}")))?;
    let assinatura = filho
        .signature
        .as_bytes()
        .ok_or_else(|| verify_err("assinatura do certificado não alinhada em bytes".into()))?;
    verificar_assinatura(emissor, &filho.signature_algorithm.oid, &tbs, assinatura)
}

fn verificar_ca(cert: &Certificate) -> Result<(), CompError> {
    const OID_BASIC_CONSTRAINTS: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.19");
    let exts = cert
        .tbs_certificate
        .extensions
        .as_ref()
        .ok_or_else(|| verify_err("certificado intermédio sem extensões: não é CA".into()))?;
    let ext = exts
        .iter()
        .find(|e| e.extn_id == OID_BASIC_CONSTRAINTS)
        .ok_or_else(|| verify_err("certificado intermédio sem basicConstraints".into()))?;
    let bc = BasicConstraints::from_der(ext.extn_value.as_bytes())
        .map_err(|e| verify_err(format!("basicConstraints inválido: {e}")))?;
    if !bc.ca {
        return Err(verify_err(
            "certificado intermédio com CA=false: uma folha não pode emitir".into(),
        ));
    }
    Ok(())
}

fn verificar_eku_timestamping(cert: &Certificate) -> Result<(), CompError> {
    const OID_EKU: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.37");
    let exts = cert
        .tbs_certificate
        .extensions
        .as_ref()
        .ok_or_else(|| verify_err("certificado da ACT sem extensões".into()))?;
    let ext = exts.iter().find(|e| e.extn_id == OID_EKU).ok_or_else(|| {
        verify_err(
            "certificado da ACT sem extendedKeyUsage: o propósito de carimbo não está declarado"
                .into(),
        )
    })?;
    let eku = ExtendedKeyUsage::from_der(ext.extn_value.as_bytes())
        .map_err(|e| verify_err(format!("extendedKeyUsage inválido: {e}")))?;
    if !eku.0.contains(&OID_KP_TIME_STAMPING) {
        return Err(verify_err(
            "certificado sem id-kp-timeStamping: não está autorizado a carimbar".into(),
        ));
    }
    Ok(())
}

fn validade_em(cert: &Certificate, instante_ms: u64) -> Result<(), CompError> {
    let inicio = tempo_para_unix_ms(&cert.tbs_certificate.validity.not_before)?;
    let fim = tempo_para_unix_ms(&cert.tbs_certificate.validity.not_after)?;
    if instante_ms < inicio || instante_ms > fim {
        return Err(verify_err(format!(
            "certificado `{}` fora da validade no instante do carimbo",
            cert.tbs_certificate.subject
        )));
    }
    Ok(())
}

fn tempo_para_unix_ms(t: &Time) -> Result<u64, CompError> {
    let segundos = match t {
        Time::UtcTime(u) => u.to_unix_duration().as_secs(),
        Time::GeneralTime(g) => g.to_unix_duration().as_secs(),
    };
    segundos
        .checked_mul(1_000)
        .ok_or_else(|| verify_err("tempo do certificado transborda em ms".into()))
}

fn generalized_para_unix_ms(t: &GeneralizedTime) -> Result<u64, CompError> {
    t.to_unix_duration()
        .as_secs()
        .checked_mul(1_000)
        .ok_or_else(|| verify_err("genTime transborda em ms".into()))
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_pki::{self, OpcoesToken};
    use crate::trust_store::TrustStore;

    const AGORA_S: u64 = 1_760_000_000;
    const AGORA_MS: u64 = AGORA_S * 1_000;

    fn imprint() -> [u8; 32] {
        sha256(b"o conteudo a carimbar")
    }

    fn verificador(chain: &test_pki::Chain) -> IcpBrasilTimestampVerifier {
        let mut store = TrustStore::new();
        store.add_pem_or_der("raiz", &chain.root_der).unwrap();
        IcpBrasilTimestampVerifier::new(store, TimestampValidationPolicy::default())
    }

    /// O caminho feliz, e o que ele prova: a hora vem de um certificado que
    /// encadeia ate uma ancora que o OPERADOR instalou — nao de uma chave que
    /// veio dentro do proprio token.
    #[test]
    fn um_carimbo_bem_formado_verifica_e_diz_a_que_ancora_chegou() {
        let chain = test_pki::chain_de_teste();
        let token = test_pki::token_de_teste(
            &chain,
            &imprint(),
            AGORA_S - 60,
            None,
            OpcoesToken::default(),
        );
        let v = verificador(&chain)
            .verify(&token, &imprint(), None, AGORA_MS)
            .expect("carimbo valido");

        assert_eq!(v.gen_unix_ms, (AGORA_S - 60) * 1_000);
        assert_eq!(v.policy_oid, test_pki::OID_POLITICA_TESTE);
        assert_eq!(v.chain_len, 1, "folha ancorada directamente na raiz");
        assert_eq!(v.accuracy_secs, Some(1));
        assert!(v.signer_subject.contains("ACT de Teste"));
        assert!(!v.anchor_fingerprint_hex.is_empty());
        // §9: a revogacao NAO foi verificada, e o resultado di-lo.
        assert!(!v.revocation_checked);
    }

    /// Sem ancoras nao ha nada contra que validar, e "ok" seria a pior
    /// resposta possivel.
    #[test]
    fn um_trust_store_vazio_recusa_tudo() {
        let chain = test_pki::chain_de_teste();
        let token =
            test_pki::token_de_teste(&chain, &imprint(), AGORA_S, None, OpcoesToken::default());
        let erro = IcpBrasilTimestampVerifier::new(
            TrustStore::new(),
            TimestampValidationPolicy::default(),
        )
        .verify(&token, &imprint(), None, AGORA_MS)
        .unwrap_err();
        assert!(erro.to_string().contains("trust store vazio"), "{erro}");
    }

    /// A diferenca face ao verificador antigo, num teste: uma cadeia que nao
    /// chega a NENHUMA ancora configurada e recusada, por muito valida que a
    /// assinatura seja em si.
    #[test]
    fn uma_cadeia_que_nao_chega_a_uma_ancora_e_recusada() {
        let chain = test_pki::chain_de_teste();
        let token =
            test_pki::token_de_teste(&chain, &imprint(), AGORA_S, None, OpcoesToken::default());
        let mut store = TrustStore::new();
        store
            .add_pem_or_der(
                "outra",
                &test_pki::self_signed_root("Outra Raiz").certificate_der,
            )
            .unwrap();
        let erro = IcpBrasilTimestampVerifier::new(store, TimestampValidationPolicy::default())
            .verify(&token, &imprint(), None, AGORA_MS)
            .unwrap_err();
        assert!(erro.to_string().contains("nenhuma âncora"), "{erro}");
    }

    #[test]
    fn uma_assinatura_de_outra_chave_nao_passa() {
        let chain = test_pki::chain_de_teste();
        let token = test_pki::token_de_teste(
            &chain,
            &imprint(),
            AGORA_S,
            None,
            OpcoesToken {
                assinar_com_chave_errada: true,
                ..Default::default()
            },
        );
        let erro = verificador(&chain)
            .verify(&token, &imprint(), None, AGORA_MS)
            .unwrap_err();
        assert!(erro.to_string().contains("não confere"), "{erro}");
    }

    /// O elo entre a assinatura e o conteudo. Sem ele, a assinatura cobria os
    /// atributos e o TSTInfo podia ser outro.
    #[test]
    fn um_message_digest_que_nao_corresponde_ao_conteudo_e_recusado() {
        let chain = test_pki::chain_de_teste();
        let token = test_pki::token_de_teste(
            &chain,
            &imprint(),
            AGORA_S,
            None,
            OpcoesToken {
                message_digest_errado: true,
                ..Default::default()
            },
        );
        let erro = verificador(&chain)
            .verify(&token, &imprint(), None, AGORA_MS)
            .unwrap_err();
        assert!(erro.to_string().contains("messageDigest"), "{erro}");
    }

    #[test]
    fn signed_attrs_sem_content_type_e_recusado() {
        let chain = test_pki::chain_de_teste();
        let token = test_pki::token_de_teste(
            &chain,
            &imprint(),
            AGORA_S,
            None,
            OpcoesToken {
                sem_content_type: true,
                ..Default::default()
            },
        );
        let erro = verificador(&chain)
            .verify(&token, &imprint(), None, AGORA_MS)
            .unwrap_err();
        assert!(erro.to_string().contains("contentType"), "{erro}");
    }

    #[test]
    fn um_carimbo_sobre_outro_conteudo_e_recusado() {
        let chain = test_pki::chain_de_teste();
        let token =
            test_pki::token_de_teste(&chain, &imprint(), AGORA_S, None, OpcoesToken::default());
        let outro = sha256(b"conteudo diferente");
        let erro = verificador(&chain)
            .verify(&token, &outro, None, AGORA_MS)
            .unwrap_err();
        assert!(erro.to_string().contains("outro conteúdo"), "{erro}");
    }

    #[test]
    fn um_nonce_diferente_do_pedido_e_recusado() {
        let chain = test_pki::chain_de_teste();
        let token = test_pki::token_de_teste(
            &chain,
            &imprint(),
            AGORA_S,
            Some(&[0x01, 0x02, 0x03]),
            OpcoesToken::default(),
        );
        let v = verificador(&chain);
        let ok = v
            .verify(&token, &imprint(), Some(&[0x01, 0x02, 0x03]), AGORA_MS)
            .unwrap();
        assert!(ok.nonce_matched);
        let erro = v
            .verify(&token, &imprint(), Some(&[0x09]), AGORA_MS)
            .unwrap_err();
        assert!(erro.to_string().contains("nonce"), "{erro}");
    }

    #[test]
    fn um_pedido_com_nonce_exige_que_o_carimbo_o_devolva() {
        let chain = test_pki::chain_de_teste();
        let token =
            test_pki::token_de_teste(&chain, &imprint(), AGORA_S, None, OpcoesToken::default());
        let erro = verificador(&chain)
            .verify(&token, &imprint(), Some(&[0x07]), AGORA_MS)
            .unwrap_err();
        assert!(erro.to_string().contains("não o devolveu"), "{erro}");
    }

    #[test]
    fn um_carimbo_do_futuro_alem_da_tolerancia_e_recusado() {
        let chain = test_pki::chain_de_teste();
        let token = test_pki::token_de_teste(
            &chain,
            &imprint(),
            AGORA_S + 3_600,
            None,
            OpcoesToken::default(),
        );
        let erro = verificador(&chain)
            .verify(&token, &imprint(), None, AGORA_MS)
            .unwrap_err();
        assert!(erro.to_string().contains("futuro"), "{erro}");
    }

    /// §9 — o proposito tem de estar declarado. Um certificado que a mesma AC
    /// emitiu para outra coisa nao pode carimbar.
    #[test]
    fn um_certificado_sem_id_kp_time_stamping_nao_carimba() {
        let chain = test_pki::chain_com(false, true);
        let token =
            test_pki::token_de_teste(&chain, &imprint(), AGORA_S, None, OpcoesToken::default());
        let erro = verificador(&chain)
            .verify(&token, &imprint(), None, AGORA_MS)
            .unwrap_err();
        // A folha deste fixture nao traz a extensao de todo, portanto cai no
        // primeiro dos dois ramos. O outro — extensao presente sem o OID de
        // carimbo — e a mesma recusa por outra razao, e esta no corpo de
        // `verificar_eku_timestamping`.
        assert!(
            erro.to_string().contains("extendedKeyUsage"),
            "{erro}"
        );
    }

    /// A validade e aferida no instante do CARIMBO. Uma folha cuja janela ja
    /// fechou antes de carimbar nao pode ter carimbado.
    #[test]
    fn um_certificado_fora_da_validade_no_instante_do_carimbo_e_recusado() {
        let chain = test_pki::chain_com(true, false);
        let token =
            test_pki::token_de_teste(&chain, &imprint(), AGORA_S, None, OpcoesToken::default());
        let erro = verificador(&chain)
            .verify(&token, &imprint(), None, AGORA_MS)
            .unwrap_err();
        assert!(erro.to_string().contains("validade"), "{erro}");
    }

    #[test]
    fn um_signed_data_que_nao_encapsula_um_tstinfo_e_recusado() {
        let chain = test_pki::chain_de_teste();
        let token = test_pki::token_de_teste(
            &chain,
            &imprint(),
            AGORA_S,
            None,
            OpcoesToken {
                econtent_type_errado: true,
                ..Default::default()
            },
        );
        let erro = verificador(&chain)
            .verify(&token, &imprint(), None, AGORA_MS)
            .unwrap_err();
        assert!(erro.to_string().contains("não é um carimbo"), "{erro}");
    }

    #[test]
    fn um_token_sem_o_certificado_do_signatario_e_recusado() {
        let chain = test_pki::chain_de_teste();
        let token = test_pki::token_de_teste(
            &chain,
            &imprint(),
            AGORA_S,
            None,
            OpcoesToken {
                sem_certificado: true,
                ..Default::default()
            },
        );
        let erro = verificador(&chain)
            .verify(&token, &imprint(), None, AGORA_MS)
            .unwrap_err();
        assert!(erro.to_string().contains("sem certificados"), "{erro}");
    }

    /// Dois signatarios tornam ambiguo qual assinatura sustenta a hora.
    /// Escolher uma seria pior do que recusar.
    #[test]
    fn dois_signatarios_sao_recusados_em_vez_de_se_escolher_um() {
        let chain = test_pki::chain_de_teste();
        let token = test_pki::token_de_teste(
            &chain,
            &imprint(),
            AGORA_S,
            None,
            OpcoesToken {
                dois_signatarios: true,
                ..Default::default()
            },
        );
        let erro = verificador(&chain)
            .verify(&token, &imprint(), None, AGORA_MS)
            .unwrap_err();
        assert!(erro.to_string().contains("ambíguo"), "{erro}");
    }

    #[test]
    fn uma_politica_exigida_que_nao_bate_e_recusada() {
        let chain = test_pki::chain_de_teste();
        let token =
            test_pki::token_de_teste(&chain, &imprint(), AGORA_S, None, OpcoesToken::default());
        let mut store = TrustStore::new();
        store.add_pem_or_der("raiz", &chain.root_der).unwrap();
        let politica = TimestampValidationPolicy {
            required_policy_oid: Some(ObjectIdentifier::new_unwrap("1.3.6.1.4.1.1.1.1")),
            ..Default::default()
        };
        let erro = IcpBrasilTimestampVerifier::new(store, politica)
            .verify(&token, &imprint(), None, AGORA_MS)
            .unwrap_err();
        assert!(erro.to_string().contains("política"), "{erro}");
    }

    #[test]
    fn um_token_acima_do_tecto_e_recusado_antes_de_ser_lido() {
        let chain = test_pki::chain_de_teste();
        let mut store = TrustStore::new();
        store.add_pem_or_der("raiz", &chain.root_der).unwrap();
        let politica = TimestampValidationPolicy {
            max_token_bytes: 8,
            ..Default::default()
        };
        let erro = IcpBrasilTimestampVerifier::new(store, politica)
            .verify(&[0u8; 64], &imprint(), None, AGORA_MS)
            .unwrap_err();
        assert!(erro.to_string().contains("acima do tecto"), "{erro}");
    }

    #[test]
    fn lixo_nao_e_um_token() {
        let chain = test_pki::chain_de_teste();
        let erro = verificador(&chain)
            .verify(b"nao sou DER nenhum", &imprint(), None, AGORA_MS)
            .unwrap_err();
        assert!(erro.to_string().contains("ContentInfo"), "{erro}");
    }

    // -----------------------------------------------------------------
    // §9 — revogação. O que estes testes fixam não é "a CRL é lida", é a
    // relação entre uma revogação e um carimbo JÁ EMITIDO, que não é a mesma
    // pergunta que "este certificado serve hoje".
    // -----------------------------------------------------------------

    const CRL_INICIO_S: u64 = AGORA_S - 3_600;
    const CRL_FIM_S: u64 = AGORA_S + 86_400;

    fn verificador_com_crl(
        chain: &test_pki::Chain,
        crl_der: &[u8],
        politica: crate::crl::CrlPolicy,
    ) -> IcpBrasilTimestampVerifier {
        let mut store = TrustStore::new();
        store.add_pem_or_der("raiz", &chain.root_der).unwrap();
        let mut crls = crate::crl::CrlStore::new();
        crls.add_pem_or_der(crl_der).unwrap();
        IcpBrasilTimestampVerifier::new(store, TimestampValidationPolicy::default())
            .with_crls(crls, politica)
    }

    fn crl_da_raiz(chain: &test_pki::Chain, revogados: Vec<test_pki::Revogacao>) -> Vec<u8> {
        test_pki::crl_de_teste(
            &chain.root,
            &chain.root_key,
            CRL_INICIO_S,
            Some(CRL_FIM_S),
            revogados,
        )
    }

    fn token_padrao(chain: &test_pki::Chain) -> Vec<u8> {
        test_pki::token_de_teste(chain, &imprint(), AGORA_S - 60, None, OpcoesToken::default())
    }

    /// Sem CRLs instaladas nada muda — e o resultado continua a dizer que a
    /// revogação NÃO foi consultada, em vez de calar a lacuna.
    #[test]
    fn sem_crls_instaladas_a_revogacao_fica_declaradamente_por_consultar() {
        let chain = test_pki::chain_de_teste();
        let v = verificador(&chain)
            .verify(&token_padrao(&chain), &imprint(), None, AGORA_MS)
            .unwrap();
        assert!(!v.revocation_checked);
    }

    #[test]
    fn uma_crl_limpa_marca_a_revogacao_como_consultada() {
        let chain = test_pki::chain_de_teste();
        let crl = crl_da_raiz(&chain, vec![]);
        let v = verificador_com_crl(&chain, &crl, Default::default())
            .verify(&token_padrao(&chain), &imprint(), None, AGORA_MS)
            .unwrap();
        assert!(
            v.revocation_checked,
            "com CRL válida a consulta aconteceu e o campo tem de o dizer"
        );
    }

    /// O caso que a lacuna deixava passar: a autoridade já tinha dito que
    /// aquela chave não valia, e o carimbo foi emitido à mesma.
    #[test]
    fn um_certificado_revogado_antes_de_carimbar_e_recusado() {
        let chain = test_pki::chain_de_teste();
        let crl = crl_da_raiz(
            &chain,
            vec![test_pki::Revogacao {
                serial: chain.tsa.tbs_certificate.serial_number.clone(),
                quando_s: AGORA_S - 600,
                motivo: None,
            }],
        );
        let erro = verificador_com_crl(&chain, &crl, Default::default())
            .verify(&token_padrao(&chain), &imprint(), None, AGORA_MS)
            .unwrap_err();
        assert!(erro.to_string().contains("já estava revogado"), "{erro}");
    }

    /// A outra metade da regra, e a que é fácil errar por excesso de zelo: um
    /// carimbo emitido enquanto o certificado valia CONTINUA a provar a hora
    /// depois de ele ser revogado. É a razão de existir de um carimbo.
    #[test]
    fn um_certificado_revogado_depois_de_carimbar_continua_a_provar_a_hora() {
        let chain = test_pki::chain_de_teste();
        let crl = crl_da_raiz(
            &chain,
            vec![test_pki::Revogacao {
                serial: chain.tsa.tbs_certificate.serial_number.clone(),
                // 10 s antes de agora, mas 50 s DEPOIS do carimbo.
                quando_s: AGORA_S - 10,
                motivo: Some(4), // superseded
            }],
        );
        let v = verificador_com_crl(&chain, &crl, Default::default())
            .verify(&token_padrao(&chain), &imprint(), None, AGORA_MS)
            .expect("revogação posterior não invalida um carimbo anterior");
        assert!(v.revocation_checked);
    }

    /// O caso que impede isto de ser uma comparação de datas. A data de
    /// revogação é quando a AC SOUBE do compromisso, não quando ele aconteceu:
    /// quem tem a chave carimba com o `genTime` que quiser, incluindo um
    /// anterior à revogação.
    #[test]
    fn key_compromise_invalida_o_carimbo_mesmo_tendo_sido_revogado_depois() {
        let chain = test_pki::chain_de_teste();
        let crl = crl_da_raiz(
            &chain,
            vec![test_pki::Revogacao {
                serial: chain.tsa.tbs_certificate.serial_number.clone(),
                quando_s: AGORA_S - 10,
                motivo: Some(1), // keyCompromise
            }],
        );
        let erro = verificador_com_crl(&chain, &crl, Default::default())
            .verify(&token_padrao(&chain), &imprint(), None, AGORA_MS)
            .unwrap_err();
        assert!(erro.to_string().contains("keyCompromise"), "{erro}");
    }

    /// "Pedi consulta de revogação e não a consegui fazer" não pode devolver um
    /// resultado que se leia como limpo.
    #[test]
    fn sem_crl_do_emissor_a_verificacao_falha_em_vez_de_dizer_limpo() {
        let chain = test_pki::chain_de_teste();
        let outra = test_pki::self_signed_root("Raiz Sem Relacao");
        let crl = test_pki::crl_de_teste(
            &outra.certificate,
            &outra.key,
            CRL_INICIO_S,
            Some(CRL_FIM_S),
            vec![],
        );
        let erro = verificador_com_crl(&chain, &crl, Default::default())
            .verify(&token_padrao(&chain), &imprint(), None, AGORA_MS)
            .unwrap_err();
        assert!(erro.to_string().contains("não há CRL do emissor"), "{erro}");
    }

    /// Uma CRL de 2019 responderia "não revogado" com a mesma confiança de uma
    /// de hoje. A frescura é imposta, e a tolerância é uma decisão explícita do
    /// operador em vez de um default silencioso.
    #[test]
    fn uma_crl_expirada_nao_e_consultada() {
        let chain = test_pki::chain_de_teste();
        let crl = test_pki::crl_de_teste(
            &chain.root,
            &chain.root_key,
            AGORA_S - 7_200,
            Some(AGORA_S - 3_600),
            vec![],
        );
        let erro = verificador_com_crl(&chain, &crl, Default::default())
            .verify(&token_padrao(&chain), &imprint(), None, AGORA_MS)
            .unwrap_err();
        assert!(erro.to_string().contains("expirou"), "{erro}");

        // A mesma CRL passa quando o operador DECLARA que aceita esta idade.
        let tolerante = crate::crl::CrlPolicy {
            max_staleness: std::time::Duration::from_secs(7_200),
        };
        let v = verificador_com_crl(&chain, &crl, tolerante)
            .verify(&token_padrao(&chain), &imprint(), None, AGORA_MS)
            .expect("com tolerância declarada a CRL serve");
        assert!(v.revocation_checked);
    }

    /// Sem verificar a assinatura, qualquer um que escreva na pasta pode
    /// declarar um certificado como não revogado — e é essa a resposta que
    /// passa despercebida.
    #[test]
    fn uma_crl_assinada_por_outra_chave_nao_conta() {
        let chain = test_pki::chain_de_teste();
        let impostor = test_pki::self_signed_root("Impostor");
        // Emitida em NOME da raiz verdadeira, mas assinada pela chave errada.
        let crl = test_pki::crl_de_teste(
            &chain.root,
            &impostor.key,
            CRL_INICIO_S,
            Some(CRL_FIM_S),
            vec![],
        );
        let erro = verificador_com_crl(&chain, &crl, Default::default())
            .verify(&token_padrao(&chain), &imprint(), None, AGORA_MS)
            .unwrap_err();
        assert!(
            erro.to_string().contains("assinatura da CRL não confere"),
            "{erro}"
        );
    }
}
