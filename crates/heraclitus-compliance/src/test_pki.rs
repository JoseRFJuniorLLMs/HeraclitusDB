//! PKI sintética para os testes do Marco 0 da SPEC-0046.
//!
//! A §38 (Marco 0) pede "testes com fixture ICP". Um repositório público não
//! pode embarcar certificados ICP-Brasil reais — nem a chave privada de uma
//! ACT credenciada existe para se gerar um token de teste com ela. O que se
//! pode fazer, e é o que este módulo faz, é gerar uma cadeia com a **mesma
//! estrutura**: raiz auto-assinada → certificado de ACT com
//! `extendedKeyUsage = id-kp-timeStamping`, e com ela produzir tokens CMS
//! válidos e inválidos.
//!
//! O que isto prova e o que não prova, dito à partida: prova que o verificador
//! aceita uma cadeia bem formada e recusa cada uma das formas de a partir.
//! **Não** prova interoperabilidade com uma ACT real — isso exige um `.tst`
//! emitido por uma autoridade credenciada, que é evidência de laboratório e
//! entra pelo caminho da SPEC-0049, não por um teste unitário.
//!
//! Compilado só em testes (`cfg(test)`) e sob a feature `test-pki`, para que
//! nada disto possa ser chamado por engano a partir de produção: uma fábrica
//! de certificados dentro do binário de um servidor de compliance é uma
//! superfície que não tem razão para existir.

use const_oid::db::rfc5280::ID_KP_TIME_STAMPING;
use der::asn1::OctetString;
use der::{Any, Encode};
use p256::ecdsa::{DerSignature, SigningKey};
use x509_cert::spki::SubjectPublicKeyInfoOwned;
use x509_cert::builder::{Builder, CertificateBuilder, Profile};
use x509_cert::ext::pkix::ExtendedKeyUsage;
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::time::Validity;
use x509_cert::Certificate;

/// Uma raiz auto-assinada e a sua chave.
pub struct Root {
    pub key: SigningKey,
    pub certificate: Certificate,
    pub certificate_der: Vec<u8>,
    pub subject_der: Vec<u8>,
}

/// Cadeia completa: raiz + folha de ACT.
pub struct Chain {
    /// Guardada para quem precise de emitir mais certificados sob esta raiz.
    #[allow(dead_code)]
    pub root_key: SigningKey,
    pub root: Certificate,
    pub root_der: Vec<u8>,
    pub root_subject_der: Vec<u8>,
    pub tsa_key: SigningKey,
    pub tsa: Certificate,
    pub tsa_der: Vec<u8>,
}

fn nome(cn: &str) -> Name {
    format!("CN={cn}").parse().expect("DN de teste")
}

fn chave(semente: u8) -> SigningKey {
    // Determinística: dois testes que gerem "a mesma" cadeia têm de obter a
    // mesma, senão um golden vector nunca seria estável.
    let mut bytes = [0u8; 32];
    bytes[31] = semente.max(1);
    SigningKey::from_bytes(&bytes.into()).expect("chave de teste")
}

/// Janela fixa, de 2020 a 2035.
///
/// Deliberadamente NAO e `Validity::from_now`: os testes do verificador fixam
/// o relogio num instante conhecido, e uma validade relativa a hora real
/// fazia-os passar ou falhar consoante o dia em que corressem. Um fixture que
/// depende do relogio de parede nao e um fixture.
fn validade_larga() -> Validity {
    use der::asn1::UtcTime;
    use x509_cert::time::Time;
    let inicio = UtcTime::from_unix_duration(std::time::Duration::from_secs(1_577_836_800))
        .expect("not_before");
    let fim = UtcTime::from_unix_duration(std::time::Duration::from_secs(2_051_222_400))
        .expect("not_after");
    Validity {
        not_before: Time::UtcTime(inicio),
        not_after: Time::UtcTime(fim),
    }
}

/// Raiz auto-assinada com o CN dado.
pub fn self_signed_root(cn: &str) -> Root {
    root_com_semente(cn, cn.bytes().fold(1u8, |a, b| a.wrapping_add(b)))
}

fn root_com_semente(cn: &str, semente: u8) -> Root {
    let key = chave(semente);
    let spki = SubjectPublicKeyInfoOwned::from_key(*key.verifying_key()).expect("spki");
    let builder = CertificateBuilder::new(
        Profile::Root,
        SerialNumber::from(1u32),
        validade_larga(),
        nome(cn),
        spki,
        &key,
    )
    .expect("builder da raiz");
    let certificate: Certificate = builder.build::<DerSignature>().expect("assinar raiz");
    let certificate_der = certificate.to_der().expect("der da raiz");
    let subject_der = certificate
        .tbs_certificate
        .subject
        .to_der()
        .expect("subject der");
    Root {
        key,
        certificate,
        certificate_der,
        subject_der,
    }
}

/// Raiz + certificado de ACT com `id-kp-timeStamping`.
pub fn chain_de_teste() -> Chain {
    chain_com(true, true)
}

/// `eku_timestamping = false` produz uma folha sem o propósito exigido — é a
/// forma de provar que o verificador o exige de facto.
/// `dentro_da_validade = false` produz uma folha já expirada.
pub fn chain_com(eku_timestamping: bool, dentro_da_validade: bool) -> Chain {
    let root = root_com_semente("Raiz de Teste ACT", 7);
    let tsa_key = chave(9);
    let spki = SubjectPublicKeyInfoOwned::from_key(*tsa_key.verifying_key()).expect("spki tsa");

    let validade = if dentro_da_validade {
        validade_larga()
    } else {
        // Uma janela que fechou há muito. `Validity::from_now` não sabe fazer
        // isto, portanto constrói-se à mão.
        use der::asn1::UtcTime;
        use x509_cert::time::Time;
        let inicio = UtcTime::from_unix_duration(std::time::Duration::from_secs(1_000_000_000))
            .expect("not_before");
        let fim = UtcTime::from_unix_duration(std::time::Duration::from_secs(1_100_000_000))
            .expect("not_after");
        Validity {
            not_before: Time::UtcTime(inicio),
            not_after: Time::UtcTime(fim),
        }
    };

    let mut builder = CertificateBuilder::new(
        Profile::Leaf {
            issuer: root.certificate.tbs_certificate.subject.clone(),
            enable_key_agreement: false,
            enable_key_encipherment: false,
        },
        SerialNumber::from(2u32),
        validade,
        nome("ACT de Teste"),
        spki,
        &root.key,
    )
    .expect("builder da ACT");

    if eku_timestamping {
        builder
            .add_extension(&ExtendedKeyUsage(vec![ID_KP_TIME_STAMPING]))
            .expect("eku");
    }

    let tsa: Certificate = builder.build::<DerSignature>().expect("assinar ACT");
    let tsa_der = tsa.to_der().expect("der da ACT");

    Chain {
        root_key: root.key,
        root: root.certificate,
        root_der: root.certificate_der,
        root_subject_der: root.subject_der,
        tsa_key,
        tsa,
        tsa_der,
    }
}


// ---------------------------------------------------------------------------
// Construção de TimeStampTokens para os testes do verificador
// ---------------------------------------------------------------------------

use cms::cert::CertificateChoices;
use cms::content_info::ContentInfo;
use cms::signed_data::{
    CertificateSet, EncapsulatedContentInfo, SignedData, SignerIdentifier, SignerInfo, SignerInfos,
};
use der::asn1::{Int, SetOfVec};
use der::Tag;

const OID_SIGNED_DATA: const_oid::ObjectIdentifier =
    const_oid::ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.2");
const OID_CT_TST_INFO: const_oid::ObjectIdentifier =
    const_oid::ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.1.4");
const OID_ATTR_CONTENT_TYPE: const_oid::ObjectIdentifier =
    const_oid::ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.3");
const OID_ATTR_MESSAGE_DIGEST: const_oid::ObjectIdentifier =
    const_oid::ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.4");
const OID_SHA256: const_oid::ObjectIdentifier =
    const_oid::ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1");
const OID_ECDSA_SHA256: const_oid::ObjectIdentifier =
    const_oid::ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");
/// Política de carimbo fictícia dos testes.
pub const OID_POLITICA_TESTE: const_oid::ObjectIdentifier =
    const_oid::ObjectIdentifier::new_unwrap("1.3.6.1.4.1.99999.1.1");

fn algid(oid: const_oid::ObjectIdentifier) -> x509_cert::spki::AlgorithmIdentifierOwned {
    x509_cert::spki::AlgorithmIdentifierOwned {
        oid,
        parameters: None,
    }
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(bytes);
    let out = h.finalize();
    let mut fixed = [0u8; 32];
    fixed.copy_from_slice(&out);
    fixed
}

/// Como o token deve ser construído — cada variante existe para um teste
/// conseguir provar que a verificação recusa aquela falha em concreto.
#[derive(Debug, Clone, Copy, Default)]
pub struct OpcoesToken {
    /// Assina com uma chave que não é a do certificado incluído.
    pub assinar_com_chave_errada: bool,
    /// Grava um `messageDigest` que não corresponde ao TSTInfo.
    pub message_digest_errado: bool,
    /// Omite o atributo `contentType`.
    pub sem_content_type: bool,
    /// Não inclui o certificado da ACT no token.
    pub sem_certificado: bool,
    /// `eContentType` diferente de `id-ct-TSTInfo`.
    pub econtent_type_errado: bool,
    /// Dois `SignerInfo` em vez de um.
    pub dois_signatarios: bool,
}

/// Constrói um `TimeStampToken` sobre `imprint`.
pub fn token_de_teste(
    chain: &Chain,
    imprint: &[u8; 32],
    gen_unix_secs: u64,
    nonce: Option<&[u8]>,
    opcoes: OpcoesToken,
) -> Vec<u8> {
    use crate::icp::{Accuracy, MessageImprint, TstInfo};
    use der::asn1::GeneralizedTime;

    let tst = TstInfo {
        version: 1,
        policy: OID_POLITICA_TESTE,
        message_imprint: MessageImprint {
            hash_algorithm: algid(OID_SHA256),
            hashed_message: OctetString::new(imprint.to_vec()).expect("imprint"),
        },
        serial_number: Int::new(&[0x2a]).expect("serial"),
        gen_time: GeneralizedTime::from_unix_duration(std::time::Duration::from_secs(
            gen_unix_secs,
        ))
        .expect("genTime"),
        accuracy: Some(Accuracy {
            seconds: Some(1),
            millis: None,
            micros: None,
        }),
        ordering: false,
        nonce: nonce.map(|n| Int::new(n).expect("nonce")),
        tsa: None,
        extensions: None,
    };
    let tst_der = tst.to_der().expect("tstinfo der");

    let digest = if opcoes.message_digest_errado {
        sha256(b"outro conteudo")
    } else {
        sha256(&tst_der)
    };

    let mut atributos: Vec<x509_cert::attr::Attribute> = Vec::new();
    if !opcoes.sem_content_type {
        atributos.push(x509_cert::attr::Attribute {
            oid: OID_ATTR_CONTENT_TYPE,
            values: SetOfVec::try_from(vec![
                Any::new(Tag::ObjectIdentifier, OID_CT_TST_INFO.as_bytes()).expect("any oid"),
            ])
            .expect("set"),
        });
    }
    atributos.push(x509_cert::attr::Attribute {
        oid: OID_ATTR_MESSAGE_DIGEST,
        values: SetOfVec::try_from(vec![Any::new(Tag::OctetString, digest.to_vec())
            .expect("any digest")])
        .expect("set"),
    });

    let set: SetOfVec<x509_cert::attr::Attribute> =
        SetOfVec::try_from(atributos.clone()).expect("signed attrs");
    let assinado = set.to_der().expect("attrs der");

    let chave = if opcoes.assinar_com_chave_errada {
        chave(200)
    } else {
        chain.tsa_key.clone()
    };
    use p256::ecdsa::signature::Signer;
    let assinatura: DerSignature = chave.sign(&assinado);

    let sid = SignerIdentifier::IssuerAndSerialNumber(cms::cert::IssuerAndSerialNumber {
        issuer: chain.tsa.tbs_certificate.issuer.clone(),
        serial_number: chain.tsa.tbs_certificate.serial_number.clone(),
    });
    let signer = SignerInfo {
        version: cms::content_info::CmsVersion::V1,
        sid,
        digest_alg: algid(OID_SHA256),
        signed_attrs: Some(SetOfVec::try_from(atributos).expect("attrs")),
        signature_algorithm: algid(OID_ECDSA_SHA256),
        signature: OctetString::new(assinatura.to_bytes().to_vec()).expect("sig"),
        unsigned_attrs: None,
    };
    let mut infos = vec![signer.clone()];
    if opcoes.dois_signatarios {
        let mut outro = signer.clone();
        outro.digest_alg = algid(OID_SHA256);
        // Basta ser diferente para o SET aceitar os dois.
        outro.signature = OctetString::new(vec![1u8; 70]).expect("sig2");
        infos.push(outro);
    }

    let certificados = if opcoes.sem_certificado {
        None
    } else {
        let escolhas = vec![
            CertificateChoices::Certificate(chain.tsa.clone()),
            CertificateChoices::Certificate(chain.root.clone()),
        ];
        Some(CertificateSet(SetOfVec::try_from(escolhas).expect("certs")))
    };

    let econtent_type = if opcoes.econtent_type_errado {
        OID_SHA256
    } else {
        OID_CT_TST_INFO
    };
    let signed = SignedData {
        version: cms::content_info::CmsVersion::V3,
        digest_algorithms: SetOfVec::try_from(vec![algid(OID_SHA256)]).expect("digest algs"),
        encap_content_info: EncapsulatedContentInfo {
            econtent_type,
            econtent: Some(
                Any::new(Tag::OctetString, tst_der.clone()).expect("econtent"),
            ),
        },
        certificates: certificados,
        crls: None,
        signer_infos: SignerInfos(SetOfVec::try_from(infos).expect("signers")),
    };
    let ci = ContentInfo {
        content_type: OID_SIGNED_DATA,
        content: Any::encode_from(&signed).expect("content"),
    };
    ci.to_der().expect("token der")
}


// ---------------------------------------------------------------------------
// CRLs sinteticas (SPEC-0046 §9). Emitidas pela mesma raiz que emite a folha,
// para que os testes de revogacao usem uma cadeia REAL em vez de fingirem uma.
// ---------------------------------------------------------------------------

use x509_cert::crl::{CertificateList, RevokedCert, TbsCertList};

/// Uma entrada de revogacao a colocar na CRL.
pub struct Revogacao {
    /// Serial do certificado revogado.
    pub serial: SerialNumber,
    /// Instante da revogacao (segundos Unix).
    pub quando_s: u64,
    /// `reasonCode` (RFC 5280 §5.3.1): 1 = keyCompromise, 2 = cACompromise.
    /// `None` nao escreve a extensao.
    pub motivo: Option<u8>,
}

/// Emite uma CRL assinada por `emissor_key` em nome de `emissor`.
///
/// `next_update_s = None` produz uma CRL sem `nextUpdate` — legal em RFC 5280 e
/// util para provar que o verificador nao exige o campo mas tambem nao inventa
/// uma janela.
pub fn crl_de_teste(
    emissor: &Certificate,
    emissor_key: &SigningKey,
    this_update_s: u64,
    next_update_s: Option<u64>,
    revogados: Vec<Revogacao>,
) -> Vec<u8> {
    use der::asn1::BitString;
    use p256::ecdsa::signature::Signer;
    use x509_cert::ext::Extension;
    use x509_cert::time::Time;

    const OID_CRL_REASON: const_oid::ObjectIdentifier =
        const_oid::ObjectIdentifier::new_unwrap("2.5.29.21");

    let entradas: Vec<RevokedCert> = revogados
        .into_iter()
        .map(|r| {
            let extensions = r.motivo.map(|codigo| {
                // ENUMERATED (tag 0x0A), um octeto.
                let valor = der::asn1::Any::new(
                    Tag::Enumerated,
                    OctetString::new(vec![codigo]).expect("octet").as_bytes().to_vec(),
                )
                .expect("enumerated");
                vec![Extension {
                    extn_id: OID_CRL_REASON,
                    critical: false,
                    extn_value: OctetString::new(valor.to_der().expect("der enum"))
                        .expect("octet ext"),
                }]
            });
            RevokedCert {
                serial_number: r.serial,
                revocation_date: Time::try_from(
                    std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(r.quando_s),
                )
                .expect("data de revogacao"),
                crl_entry_extensions: extensions,
            }
        })
        .collect();

    let tbs = TbsCertList {
        version: x509_cert::Version::V2,
        signature: emissor.tbs_certificate.signature.clone(),
        issuer: emissor.tbs_certificate.subject.clone(),
        this_update: Time::try_from(
            std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(this_update_s),
        )
        .expect("thisUpdate"),
        next_update: next_update_s.map(|s| {
            Time::try_from(std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(s))
                .expect("nextUpdate")
        }),
        revoked_certificates: if entradas.is_empty() {
            None
        } else {
            Some(entradas)
        },
        crl_extensions: None,
    };

    let tbs_der = tbs.to_der().expect("tbsCertList em DER");
    let assinatura: DerSignature = emissor_key.sign(&tbs_der);
    let crl = CertificateList {
        tbs_cert_list: tbs,
        signature_algorithm: emissor.signature_algorithm.clone(),
        signature: BitString::from_bytes(assinatura.as_bytes()).expect("bitstring da CRL"),
    };
    crl.to_der().expect("CRL em DER")
}
