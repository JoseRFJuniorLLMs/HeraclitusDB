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
use const_oid::AssociatedOid;
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
    /// Quando a cadeia e RSA, a chave privada da folha. `token_de_teste` assina
    /// com ela em vez da ECDSA, e declara o OID RSA correspondente.
    pub rsa_folha: Option<rsa::RsaPrivateKey>,
    /// O digest com que a cadeia RSA foi assinada.
    pub rsa_digest: Option<DigestRsa>,
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
        rsa_folha: None,
        rsa_digest: None,
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
#[derive(Debug, Clone, Default)]
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
    /// Certificados a juntar ao conjunto do token, alem da folha e do emissor
    /// imediato. E o que permite testar uma cadeia de tres niveis: o intermedio
    /// viaja no token e a ancora fica no trust store.
    pub certs_extra: Vec<Certificate>,
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

    // Numa cadeia RSA o SignerInfo tem de ser assinado com a chave RSA da
    // folha e declarar o OID RSA correspondente. Assinar com ECDSA e declarar
    // RSA daria um token que falha sempre — e que testaria a mensagem de erro
    // em vez do ramo RSA.
    let (assinatura_bytes, oid_assinatura) = match (&chain.rsa_folha, chain.rsa_digest) {
        (Some(priv_rsa), Some(d)) => {
            use rsa::pkcs1v15::SigningKey;
            use rsa::signature::{SignatureEncoding, Signer};
            let chave_rsa = if opcoes.assinar_com_chave_errada {
                rsa::RsaPrivateKey::new(&mut rand::thread_rng(), 2048).expect("outra RSA")
            } else {
                priv_rsa.clone()
            };
            let (sig, oid) = match d {
                DigestRsa::Sha256 => (
                    SigningKey::<sha2::Sha256>::new(chave_rsa).sign(&assinado).to_vec(),
                    const_oid::ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11"),
                ),
                DigestRsa::Sha384 => (
                    SigningKey::<sha2::Sha384>::new(chave_rsa).sign(&assinado).to_vec(),
                    const_oid::ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.12"),
                ),
                DigestRsa::Sha512 => (
                    SigningKey::<sha2::Sha512>::new(chave_rsa).sign(&assinado).to_vec(),
                    const_oid::ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.13"),
                ),
            };
            (sig, oid)
        }
        _ => {
            let chave = if opcoes.assinar_com_chave_errada {
                chave(200)
            } else {
                chain.tsa_key.clone()
            };
            use p256::ecdsa::signature::Signer;
            let assinatura: DerSignature = chave.sign(&assinado);
            (assinatura.to_bytes().to_vec(), OID_ECDSA_SHA256)
        }
    };

    let sid = SignerIdentifier::IssuerAndSerialNumber(cms::cert::IssuerAndSerialNumber {
        issuer: chain.tsa.tbs_certificate.issuer.clone(),
        serial_number: chain.tsa.tbs_certificate.serial_number.clone(),
    });
    let signer = SignerInfo {
        version: cms::content_info::CmsVersion::V1,
        sid,
        digest_alg: algid(OID_SHA256),
        signed_attrs: Some(SetOfVec::try_from(atributos).expect("attrs")),
        signature_algorithm: algid(oid_assinatura),
        signature: OctetString::new(assinatura_bytes.clone()).expect("sig"),
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
        let mut escolhas = vec![
            CertificateChoices::Certificate(chain.tsa.clone()),
            CertificateChoices::Certificate(chain.root.clone()),
        ];
        for extra in &opcoes.certs_extra {
            escolhas.push(CertificateChoices::Certificate(extra.clone()));
        }
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
    /// Escreve o `reasonCode` com uma etiqueta que NAO e ENUMERATED, para
    /// provar que o parser a verifica em vez de ler o ultimo octeto.
    pub motivo_com_etiqueta_errada: bool,
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
    crl_com(emissor, emissor_key, this_update_s, next_update_s, revogados, false)
}

/// Como `crl_de_teste`, mas pode marcar a CRL como DELTA.
pub fn crl_com(
    emissor: &Certificate,
    emissor_key: &SigningKey,
    this_update_s: u64,
    next_update_s: Option<u64>,
    revogados: Vec<Revogacao>,
    delta: bool,
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
            let etiqueta = if r.motivo_com_etiqueta_errada {
                Tag::OctetString
            } else {
                Tag::Enumerated
            };
            let extensions = r.motivo.map(|codigo| {
                // ENUMERATED (tag 0x0A), um octeto.
                let valor = der::asn1::Any::new(
                    etiqueta,
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
        crl_extensions: if delta {
            // 2.5.29.27 deltaCRLIndicator, sempre CRITICA.
            Some(vec![x509_cert::ext::Extension {
                extn_id: const_oid::ObjectIdentifier::new_unwrap("2.5.29.27"),
                critical: true,
                extn_value: OctetString::new(
                    der::asn1::Uint::new(&[1u8]).expect("uint").to_der().expect("der"),
                )
                .expect("octet"),
            }])
        } else {
            None
        },
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

// ---------------------------------------------------------------------------
// Cadeias com RESTRICOES (SPEC-0046 §9 / RFC 5280 §6.1). Sem estas, os testes
// das restricoes teriam de fingir certificados em vez de os emitir — e um
// certificado fingido nao prova que o verificador le a extensao real.
// ---------------------------------------------------------------------------

/// Uma cadeia de tres niveis: raiz -> AC intermedia -> folha de ACT.
pub struct CadeiaTresNiveis {
    pub root: Certificate,
    pub root_der: Vec<u8>,
    /// O certificado do intermedio. Guardado para um teste o poder inspeccionar
    /// sem o extrair do token.
    #[allow(dead_code)]
    pub sub: Certificate,
    /// Pronta a passar a `token_de_teste`: `root` e o INTERMEDIO (o emissor
    /// imediato da folha) e `tsa` e a folha. A raiz verdadeira vai em
    /// `OpcoesToken::certs_extra` e no trust store.
    pub chain: Chain,
}

/// O que se quer restringir na cadeia gerada.
#[derive(Default)]
pub struct OpcoesRestricoes {
    /// `permittedSubtrees` da RAIZ, como DN de base (ex.: "O=ICP-Brasil").
    pub raiz_permite_dn: Option<String>,
    /// `excludedSubtrees` da RAIZ.
    pub raiz_exclui_dn: Option<String>,
    /// `pathLenConstraint` da AC intermedia.
    pub sub_path_len: Option<u8>,
    /// `pathLenConstraint` da raiz.
    pub raiz_path_len: Option<u8>,
    /// DN COMPLETO do intermedio (ex.: "CN=AC Intermedia,O=ICP-Brasil").
    /// Default: "CN=AC Intermedia".
    pub sub_dn: Option<String>,
    /// DN COMPLETO da folha. Default: "CN=ACT de Teste".
    pub folha_dn: Option<String>,
    /// Acrescenta uma extensao CRITICA com um OID que o validador nao processa.
    pub critica_desconhecida_na_folha: bool,
}

/// Emite raiz -> intermedio -> folha com as restricoes pedidas.
pub fn cadeia_tres_niveis(opcoes: OpcoesRestricoes) -> CadeiaTresNiveis {
    use x509_cert::ext::pkix::constraints::name::{GeneralSubtree, NameConstraints};
    use x509_cert::ext::pkix::name::GeneralName;

    let subtree = |dn: &str| GeneralSubtree {
        base: GeneralName::DirectoryName(dn.parse::<Name>().expect("DN da subtree")),
        minimum: 0,
        maximum: None,
    };

    // --- raiz -----------------------------------------------------------
    let root_key = chave(31);
    let root_spki = SubjectPublicKeyInfoOwned::from_key(*root_key.verifying_key()).expect("spki");
    // Quando ha pathLen, a raiz e emitida como SubCA AUTO-EMITIDA: o
    // `Profile::Root` ja escreve um basicConstraints proprio e acrescentar
    // outro produziria um certificado com a extensao DUPLICADA — malformado, e
    // um mau fixture (o verificador leria a primeira e o teste provaria outra
    // coisa).
    let perfil = match opcoes.raiz_path_len {
        Some(pl) => Profile::SubCA {
            issuer: nome("Raiz Restrita"),
            path_len_constraint: Some(pl),
        },
        None => Profile::Root,
    };
    let mut rb = CertificateBuilder::new(
        perfil,
        SerialNumber::from(100u32),
        validade_larga(),
        nome("Raiz Restrita"),
        root_spki,
        &root_key,
    )
    .expect("builder da raiz");
    if opcoes.raiz_permite_dn.is_some() || opcoes.raiz_exclui_dn.is_some() {
        rb.add_extension(&NameConstraints {
            permitted_subtrees: opcoes.raiz_permite_dn.as_deref().map(|d| vec![subtree(d)]),
            excluded_subtrees: opcoes.raiz_exclui_dn.as_deref().map(|d| vec![subtree(d)]),
        })
        .expect("nameConstraints da raiz");
    }

    let root: Certificate = rb.build::<DerSignature>().expect("assinar raiz");
    let root_der = root.to_der().expect("der da raiz");

    // --- intermedio -----------------------------------------------------
    let sub_key = chave(37);
    let sub_spki = SubjectPublicKeyInfoOwned::from_key(*sub_key.verifying_key()).expect("spki sub");
    let sb = CertificateBuilder::new(
        Profile::SubCA {
            issuer: root.tbs_certificate.subject.clone(),
            path_len_constraint: opcoes.sub_path_len,
        },
        SerialNumber::from(101u32),
        validade_larga(),
        opcoes
            .sub_dn
            .as_deref()
            .unwrap_or("CN=AC Intermedia")
            .parse::<Name>()
            .expect("DN do intermedio"),
        sub_spki,
        &root_key,
    )
    .expect("builder do intermedio");
    let sub: Certificate = sb.build::<DerSignature>().expect("assinar intermedio");

    // --- folha ----------------------------------------------------------
    let folha_key = chave(41);
    let folha_spki =
        SubjectPublicKeyInfoOwned::from_key(*folha_key.verifying_key()).expect("spki folha");
    let folha_nome = opcoes
        .folha_dn
        .as_deref()
        .unwrap_or("CN=ACT de Teste")
        .parse::<Name>()
        .expect("DN da folha");
    let mut fb = CertificateBuilder::new(
        Profile::Leaf {
            issuer: sub.tbs_certificate.subject.clone(),
            enable_key_agreement: false,
            enable_key_encipherment: false,
        },
        SerialNumber::from(102u32),
        validade_larga(),
        folha_nome,
        folha_spki,
        &sub_key,
    )
    .expect("builder da folha");
    fb.add_extension(&ExtendedKeyUsage(vec![ID_KP_TIME_STAMPING]))
        .expect("eku");
    if opcoes.critica_desconhecida_na_folha {
        // 1.3.6.1.4.1.99999.1 — nao esta em CRITICAS_PROCESSADAS, de proposito.
        fb.add_extension(&CriticaDesconhecida).expect("extensao critica");
    }
    let folha: Certificate = fb.build::<DerSignature>().expect("assinar folha");
    let folha_der = folha.to_der().expect("der da folha");

    let sub_subject_der = sub.tbs_certificate.subject.to_der().expect("subject der");
    CadeiaTresNiveis {
        root: root.clone(),
        root_der,
        sub: sub.clone(),
        chain: Chain {
            root_key: sub_key.clone(),
            root: sub,
            root_der: Vec::new(),
            root_subject_der: sub_subject_der,
            tsa_key: folha_key,
            tsa: folha,
            tsa_der: folha_der,
            rsa_folha: None,
            rsa_digest: None,
        },
    }
}

/// Uma extensao critica com um OID que o validador nao conhece — o caso que a
/// RFC 5280 §6.1.4(f) manda recusar.
struct CriticaDesconhecida;

impl AssociatedOid for CriticaDesconhecida {
    const OID: const_oid::ObjectIdentifier =
        const_oid::ObjectIdentifier::new_unwrap("1.3.6.1.4.1.99999.1");
}

impl der::Encode for CriticaDesconhecida {
    fn encoded_len(&self) -> der::Result<der::Length> {
        der::asn1::Null.encoded_len()
    }
    fn encode(&self, writer: &mut impl der::Writer) -> der::Result<()> {
        der::asn1::Null.encode(writer)
    }
}

impl x509_cert::ext::AsExtension for CriticaDesconhecida {
    fn critical(&self, _subject: &Name, _extensions: &[x509_cert::ext::Extension]) -> bool {
        true
    }
}

// ---------------------------------------------------------------------------
// Cadeias RSA (SPEC-0046 §9). A auditoria de 2026-08-31 apanhou que o ramo RSA
// — o que uma ACT real usa — nunca era executado por teste nenhum: toda a PKI
// sintetica era ECDSA P-256. Um ramo que so existe e nao corre e indistinguivel
// de um ramo errado.
// ---------------------------------------------------------------------------

use rsa::RsaPrivateKey;
use std::sync::OnceLock;

/// Gerar RSA-2048 custa quase um segundo. Gera-se UMA vez para toda a suite.
fn chave_rsa_2048() -> &'static RsaPrivateKey {
    static K: OnceLock<RsaPrivateKey> = OnceLock::new();
    K.get_or_init(|| {
        RsaPrivateKey::new(&mut rand::thread_rng(), 2048).expect("gerar RSA-2048")
    })
}

/// Uma chave deliberadamente fraca, para provar que o piso de tamanho existe.
fn chave_rsa_1024() -> &'static RsaPrivateKey {
    static K: OnceLock<RsaPrivateKey> = OnceLock::new();
    K.get_or_init(|| {
        RsaPrivateKey::new(&mut rand::thread_rng(), 1024).expect("gerar RSA-1024")
    })
}

/// Segunda chave de 2048, para a folha ser distinta da raiz.
fn chave_rsa_2048_folha() -> &'static RsaPrivateKey {
    static K: OnceLock<RsaPrivateKey> = OnceLock::new();
    K.get_or_init(|| {
        RsaPrivateKey::new(&mut rand::thread_rng(), 2048).expect("gerar RSA-2048 folha")
    })
}

/// Que digest usar na assinatura dos certificados RSA.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DigestRsa {
    Sha256,
    Sha384,
    Sha512,
}

/// Raiz RSA + folha de ACT RSA, ambas assinadas com `digest`.
///
/// `raiz_fraca` usa RSA-1024 na raiz, para provar que o minimo de bits e
/// imposto ao EMISSOR e nao so a folha.
pub fn chain_rsa(digest: DigestRsa, raiz_fraca: bool) -> Chain {
    use rsa::pkcs1v15::SigningKey;
    use rsa::signature::Keypair;

    macro_rules! constroi {
        ($D:ty) => {{
            let raiz_priv = if raiz_fraca {
                chave_rsa_1024().clone()
            } else {
                chave_rsa_2048().clone()
            };
            let raiz_signer = SigningKey::<$D>::new(raiz_priv);
            let raiz_spki = x509_cert::spki::SubjectPublicKeyInfoOwned::from_key(
                raiz_signer.verifying_key().as_ref().clone(),
            )
            .expect("spki da raiz RSA");
            let rb = CertificateBuilder::new(
                Profile::Root,
                SerialNumber::from(200u32),
                validade_larga(),
                nome("Raiz RSA de Teste"),
                raiz_spki,
                &raiz_signer,
            )
            .expect("builder da raiz RSA");
            let root: Certificate = rb
                .build::<rsa::pkcs1v15::Signature>()
                .expect("assinar raiz RSA");

            let folha_priv = chave_rsa_2048_folha().clone();
            let folha_signer = SigningKey::<$D>::new(folha_priv.clone());
            let folha_spki = x509_cert::spki::SubjectPublicKeyInfoOwned::from_key(
                folha_signer.verifying_key().as_ref().clone(),
            )
            .expect("spki da folha RSA");
            let mut fb = CertificateBuilder::new(
                Profile::Leaf {
                    issuer: root.tbs_certificate.subject.clone(),
                    enable_key_agreement: false,
                    enable_key_encipherment: false,
                },
                SerialNumber::from(201u32),
                validade_larga(),
                nome("ACT RSA de Teste"),
                folha_spki,
                &raiz_signer,
            )
            .expect("builder da folha RSA");
            fb.add_extension(&ExtendedKeyUsage(vec![ID_KP_TIME_STAMPING]))
                .expect("eku");
            let tsa: Certificate = fb
                .build::<rsa::pkcs1v15::Signature>()
                .expect("assinar folha RSA");
            (root, tsa, folha_priv)
        }};
    }

    let (root, tsa, folha_priv) = match digest {
        DigestRsa::Sha256 => constroi!(sha2::Sha256),
        DigestRsa::Sha384 => constroi!(sha2::Sha384),
        DigestRsa::Sha512 => constroi!(sha2::Sha512),
    };

    let root_der = root.to_der().expect("der da raiz RSA");
    let root_subject_der = root
        .tbs_certificate
        .subject
        .to_der()
        .expect("subject da raiz RSA");
    let tsa_der = tsa.to_der().expect("der da folha RSA");

    Chain {
        // A `Chain` foi desenhada a volta de ECDSA. Para RSA os campos de chave
        // ficam preenchidos com chaves ECDSA que ninguem usa: quem carimba com
        // uma cadeia RSA usa `token_rsa`, que recebe a chave RSA a parte.
        root_key: chave(1),
        root,
        root_der,
        root_subject_der,
        tsa_key: chave(2),
        tsa,
        tsa_der,
        rsa_folha: Some(folha_priv),
        rsa_digest: Some(digest),
    }
}
