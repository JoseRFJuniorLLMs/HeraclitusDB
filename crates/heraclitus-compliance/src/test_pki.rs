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
#[derive(Clone)]
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
    /// Emite o `contentType` com DOIS valores, o primeiro correcto.
    pub content_type_com_dois_valores: bool,
    /// Assina os signedAttrs sobre SHA-512 (o `messageDigest` passa a ter 64
    /// bytes e o `digestAlgorithm` a declarar SHA-512).
    pub digest_attrs_sha512: bool,
    /// Declara um `digestAlgorithm` que o verificador nao sabe calcular.
    pub digest_attrs_desconhecido: bool,
    /// O envelope declara um digest DIFERENTE do que o SignerInfo usa.
    pub envelope_declara_outro_digest: bool,
    /// CRLs a anexar ao proprio token (DER), como faz uma ACT que serve
    /// clientes em air-gap.
    pub crls_no_token: Vec<Vec<u8>>,
    /// Substitui o `messageImprint` por bytes e algoritmo arbitrarios.
    pub imprint_bruto: Option<(Vec<u8>, const_oid::ObjectIdentifier)>,
    /// Emite o `genTime` com fraccao de segundo, como uma ACT real que declare
    /// precisao de milissegundos (RFC 3161 §2.4.2 permite-o explicitamente).
    pub gen_time_milis: Option<u16>,
    /// Certificados a juntar ao conjunto do token, alem da folha e do emissor
    /// imediato. E o que permite testar uma cadeia de tres niveis: o intermedio
    /// viaja no token e a ancora fica no trust store.
    pub certs_extra: Vec<Certificate>,
}

/// Como `token_de_teste`, mas com um `messageImprint` de tamanho e algoritmo
/// arbitrarios — para exercitar digests que nao sejam SHA-256.
pub fn token_de_teste_com_imprint(
    chain: &Chain,
    imprint: &[u8],
    oid_digest: const_oid::ObjectIdentifier,
    gen_unix_secs: u64,
) -> Vec<u8> {
    let o = OpcoesToken {
        imprint_bruto: Some((imprint.to_vec(), oid_digest)),
        ..Default::default()
    };
    token_de_teste(chain, &[0u8; 32], gen_unix_secs, None, o)
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

    let tst = TstInfo {
        version: 1,
        policy: OID_POLITICA_TESTE,
        message_imprint: match &opcoes.imprint_bruto {
            Some((bytes, oid)) => MessageImprint {
                hash_algorithm: algid(*oid),
                hashed_message: OctetString::new(bytes.clone()).expect("imprint bruto"),
            },
            None => MessageImprint {
                hash_algorithm: algid(OID_SHA256),
                hashed_message: OctetString::new(imprint.to_vec()).expect("imprint"),
            },
        },
        serial_number: Int::new(&[0x2a]).expect("serial"),
        gen_time: crate::icp::GenTime::nova(gen_unix_secs, opcoes.gen_time_milis)
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

    // O digest dos signedAttrs: SHA-256 por omissao, SHA-512 quando a opcao o
    // pede — e o `digestAlgorithm` do SignerInfo tem de o declarar.
    let (digest, oid_digest) = if opcoes.message_digest_errado {
        (sha256(b"outro conteudo").to_vec(), OID_SHA256)
    } else if opcoes.digest_attrs_sha512 {
        use sha2::Digest as _;
        (
            sha2::Sha512::digest(&tst_der).to_vec(),
            const_oid::ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.3"),
        )
    } else if opcoes.digest_attrs_desconhecido {
        (
            sha256(&tst_der).to_vec(),
            // id-md5 — deliberadamente fora do que se sabe calcular.
            const_oid::ObjectIdentifier::new_unwrap("1.2.840.113549.2.5"),
        )
    } else {
        (sha256(&tst_der).to_vec(), OID_SHA256)
    };

    let mut atributos: Vec<x509_cert::attr::Attribute> = Vec::new();
    if !opcoes.sem_content_type {
        atributos.push(x509_cert::attr::Attribute {
            oid: OID_ATTR_CONTENT_TYPE,
            values: SetOfVec::try_from(if opcoes.content_type_com_dois_valores {
                // O primeiro esta CERTO. So o segundo diz outra coisa — e era
                // o primeiro que o verificador examinava.
                vec![
                    Any::new(Tag::ObjectIdentifier, OID_CT_TST_INFO.as_bytes())
                        .expect("any oid"),
                    Any::new(Tag::ObjectIdentifier, OID_SHA256.as_bytes()).expect("any oid 2"),
                ]
            } else {
                vec![Any::new(Tag::ObjectIdentifier, OID_CT_TST_INFO.as_bytes())
                    .expect("any oid")]
            })
            .expect("set"),
        });
    }
    atributos.push(x509_cert::attr::Attribute {
        oid: OID_ATTR_MESSAGE_DIGEST,
        values: SetOfVec::try_from(vec![Any::new(Tag::OctetString, digest.clone())
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
        digest_alg: algid(oid_digest),
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
        // Tem de bater com o `digestAlgorithm` do SignerInfo: o envelope
        // declara os digests que o verificador vai precisar, e um SignerInfo
        // que use outro contradi-lo.
        digest_algorithms: SetOfVec::try_from(vec![algid(if opcoes
            .envelope_declara_outro_digest
        {
            const_oid::ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.3")
        } else {
            oid_digest
        })])
        .expect("digest algs"),
        encap_content_info: EncapsulatedContentInfo {
            econtent_type,
            econtent: Some(
                Any::new(Tag::OctetString, tst_der.clone()).expect("econtent"),
            ),
        },
        certificates: certificados,
        crls: if opcoes.crls_no_token.is_empty() {
            None
        } else {
            use der::Decode;
            let escolhas: Vec<cms::revocation::RevocationInfoChoice> = opcoes
                .crls_no_token
                .iter()
                .map(|d| {
                    cms::revocation::RevocationInfoChoice::Crl(
                        x509_cert::crl::CertificateList::from_der(d).expect("CRL do token"),
                    )
                })
                .collect();
            Some(cms::revocation::RevocationInfoChoices(
                SetOfVec::try_from(escolhas).expect("set de CRLs"),
            ))
        },
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
    /// Emite a folha com um `extendedKeyUsage` que, alem do carimbo, declara
    /// outro proposito — o que a RFC 3161 §2.3 proibe.
    pub folha_eku_com_outro_proposito: bool,
    /// Emite o `extendedKeyUsage` da folha como NAO critico.
    pub folha_eku_nao_critico: bool,
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
    if opcoes.folha_eku_nao_critico {
        fb.add_extension(&EkuNaoCritico(vec![ID_KP_TIME_STAMPING]))
            .expect("eku nao critico");
    } else if opcoes.folha_eku_com_outro_proposito {
        // id-kp-serverAuth a par do carimbo: a chave deixa de estar reservada.
        fb.add_extension(&ExtendedKeyUsage(vec![
            ID_KP_TIME_STAMPING,
            const_oid::ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.1"),
        ]))
        .expect("eku duplo");
    } else {
        fb.add_extension(&ExtendedKeyUsage(vec![ID_KP_TIME_STAMPING]))
            .expect("eku");
    }
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

/// Um SEGUNDO certificado de AC com o MESMO sujeito do intermedio da cadeia
/// mas com outra chave — o que uma PKI real tem durante um rollover de chave.
///
/// Emitido por uma raiz DIFERENTE, de proposito: assim ele nao encadeia ate a
/// ancora instalada, e a unica forma de a cadeia fechar e o verificador tentar
/// tambem o outro candidato. Se escolher so o primeiro, falha.
pub fn sosia_do_intermedio(c: &CadeiaTresNiveis) -> Certificate {
    let outra_raiz = chave(53);
    let raiz_spki = SubjectPublicKeyInfoOwned::from_key(*outra_raiz.verifying_key()).expect("spki");
    let rb = CertificateBuilder::new(
        Profile::Root,
        SerialNumber::from(300u32),
        validade_larga(),
        nome("Raiz Estranha"),
        raiz_spki,
        &outra_raiz,
    )
    .expect("builder raiz estranha");
    let raiz: Certificate = rb.build::<DerSignature>().expect("assinar raiz estranha");

    let sosia_key = chave(59);
    let spki = SubjectPublicKeyInfoOwned::from_key(*sosia_key.verifying_key()).expect("spki sosia");
    let sb = CertificateBuilder::new(
        Profile::SubCA {
            issuer: raiz.tbs_certificate.subject.clone(),
            path_len_constraint: None,
        },
        SerialNumber::from(301u32),
        validade_larga(),
        c.sub.tbs_certificate.subject.clone(),
        spki,
        &outra_raiz,
    )
    .expect("builder sosia");
    sb.build::<DerSignature>().expect("assinar sosia")
}

/// `extendedKeyUsage` forcado a NAO critico. O builder decide a criticidade
/// sozinho (critico quando nao ha `anyExtendedKeyUsage`), portanto a unica
/// forma de produzir o caso nao conforme e envolver o tipo.
struct EkuNaoCritico(Vec<const_oid::ObjectIdentifier>);

impl AssociatedOid for EkuNaoCritico {
    const OID: const_oid::ObjectIdentifier =
        const_oid::ObjectIdentifier::new_unwrap("2.5.29.37");
}

impl der::Encode for EkuNaoCritico {
    fn encoded_len(&self) -> der::Result<der::Length> {
        ExtendedKeyUsage(self.0.clone()).encoded_len()
    }
    fn encode(&self, writer: &mut impl der::Writer) -> der::Result<()> {
        ExtendedKeyUsage(self.0.clone()).encode(writer)
    }
}

impl x509_cert::ext::AsExtension for EkuNaoCritico {
    fn critical(&self, _s: &Name, _e: &[x509_cert::ext::Extension]) -> bool {
        false
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

// Chaves RSA FIXAS, em PKCS#8 DER.
//
// Gera-las a cada corrida custava ~2,5 s de um nucleo — e isso derrubou
// `l2_behavioral_adapter_emits_replayable_signal_after_shadow_promotion` do
// Sentinel, que espera ate 5 s por um worker unico e ficava sem CPU enquanto
// esta suite fazia primalidade. O teste do Sentinel estava certo (espera em
// polling, nao com `sleep` fixo); o problema era esta suite a roubar-lhe o
// processador.
//
// Chaves fixas resolvem as duas coisas: nao ha custo nenhum, e dois testes que
// gerem "a mesma" cadeia obtem mesmo a mesma — que e a regra que o resto deste
// ficheiro ja seguia para as chaves ECDSA.
//
// Sao chaves de TESTE, geradas para este ficheiro e sem valor nenhum fora dele.
const R2048A_PKCS8_HEX: &str = concat!(
    "308204be020100300d06092a864886f70d0101010500048204a8308204a40201000282010100aa1aaa23b7923a9030ca",
    "5e60797284829da5812504c93d98cac8ec1d5fb0fca0b30ebfe4d558e17ce84e6f117ccbe5fce7b885a2781013db9ac9",
    "6dc335994c70e7840af4a907378e4a8df3cd7dc6482eec0891041a58abd16ba3a2edb197ce98eafac0cbb37d6ea86042",
    "4e16ee70dd90690b519b44c6531d93a2a0a16a091d3b7f7e7c71629068c259d02144f26da8426bc7ec21324559d23515",
    "b1b70b6c082973c515f55f3b49d84b15da8b5e93a773ba032808ff3061006d7056da62f04318e9105d5294ed1cffea53",
    "316abb251093b07587d1662a01fd984881844b7afd996196e5642c59c3b877bf04523aba1a436db596159598442a5849",
    "ce2ca058443102030100010282010100a6f9fdc189d554ff6da578f722c0332b342cde94c419f70921261200d38a1cb2",
    "72922bf42929524f168ac7a456e8a01e9e2817a5e04d87f0ae04c466371b005a6428cdc85493ed09144e3be09f722031",
    "4f292990e97bd94d7d67e7eb83c50cdc36ed668b8ee9b5d23a8b5bb44ee323db3a020e5d6829763536531172e16f88ec",
    "e10912b2219d885f3f31c9cc512d36080f205d11d1fc6f7a840efa452748a026db5f0c542d4072d95903ce4e997a76d9",
    "98f0175242e6ee2f285bdef1fc088616985ba54fb7469729159994f110dd2a05d598ab83e1e709c4f24ff9ee99716acb",
    "6f58718bfdff1216e7ba4b4f78e2be43e96b621aeefaa3376a5b7b88650e7e7102818100d29cef2ffc2e5fada209b5aa",
    "c5e1f4f20a1fecbc9ca078d9b17df023e5e42bd00f03fae79887bafefdaf560454ced2904d8f3e719457295f9ee38b97",
    "4e86f3bdac406152be3eb35445f7bb88e2c4d037f339c0c51e1b93123487a3d5f5093a4738c254b201e3622ae02c5007",
    "50778a742d47625aef6f37d1f9b69777e9076f5b02818100cec2f191fd172afb610971d560002be22a22731a9aa6298a",
    "e06ad3f167474d49106e9f6d1d8337642eb5025c71a85eb38355d7e9ecaa932d48b0327697b449de4ece5ebcdb10b99b",
    "edb1b4f7e64b7bcc4af7de8e4a150a5247936bb3b44f348ddb74c9582795c92aedbab5665b1f261b773071c0065be95d",
    "ce93101b4d32dc630281800e82774c0400a1e0d16fffcf0310fd120bb68555bd28a50ac25a9dc7ab57dbd8da9ff8922a",
    "04f7d2076223f7ea6bd13fd5c80f923d98ffa5b1c9955d58309dec2c48c72baf259caf2a9ed591a9a5cb7e7f48344aa0",
    "37601b79f8fa458c3b1583c09a4ac174b5d89681992bee4511e73cf7bd9a3e0f8ec6f6b5506a00fdd1e04f0281800c98",
    "234ed933c81277deb36863e89ec3affd59358da60171cc29b5af46b33929f22e4ad7c2ac737b4ebd07dfc9ac8fd82f6f",
    "d32f14936f539ad1e0c1088c9ad347c99a4bb6ac5622016089bd6ff1b920c09048a6322d05ebed2035b7448c6e8f1587",
    "0f9ca70ca0ac54bec2bdf15efc5b3fef5b7e6ee4ba5a5472f0d038eb983102818100b29588f559fbb9aa455064fc7281",
    "9ba76b36b671e6f26c9c122d96b6d10e690379f77d8e1e66beb0434bbaeb3cd19b5e4b94545c449753786c775c07887a",
    "4a0d30813da589682cafeacf6e217ada1ae6d982fd76ec97014a4db8380f88b3cef01784d8601e098e19b3a7261e6a27",
    "220191be7db7ef8f7df85aac3fe0066c636c",
);

const R2048B_PKCS8_HEX: &str = concat!(
    "308204be020100300d06092a864886f70d0101010500048204a8308204a40201000282010100b9593878b80e0ee53c52",
    "a8be16199594f3b6ccf6171facd3a8766709e120fb26be845acc9a5252a843060439ff367fb48c8ee90f3c0ecd836bc5",
    "f5dbc2c960a0ba303a8ac0d12edcc1e09011a420716ca4164c5be6aa46f933c32ef236a83430e2091e54610b29d4832c",
    "6c31eead1a20106654cf98fe2dad8b5b51b22f9cfd41636d963b4d79da144ea327fec9e3d42ce784bd2aee4a0dfd36a6",
    "26a985d4c71e32695a563391f45af4331d4e69addcdab37d43bac3f6d35a0b0aaaf024bca2ea90ca76945606be9a251f",
    "bb931730696a8030c74914201b9e6ecc7ff93dcaa9af9fb05d00db57bc5c4a1b028d37e71078d2dfcfd9a6e007d36428",
    "e5de7a2ad03f0203010001028201003b5c2caed4db83bfbce30831e0a80ef4e65ccc25a0603f9c85de6dbf873f65d011",
    "c217c661422e40bf3e650a2207553d00ab204f05c003e7ac13795b09762f212aa0198fa89315fc138794fc6161169261",
    "b6d67bb4532269db3f0e80fa2a4294c93f7c5c2fbc408853fe5d245cb9499dad42e8b497de07c905d1984785e234653a",
    "22508fb5cfa3cb6968253b5180ee4fcb126edc7fecbf1a4e68eb15ee001167f39cdeee9340327f5e22336857af923338",
    "a7bfa352210b0b7578804bfb1b0e0674a98b914cc0a890d48b00d71b979bb6a135df824de576bf3e031f85087d516bd6",
    "a26174bfe9e78bd2561fb52dcf373085fd39080e3d03e37e4ba28c4b644d4102818100d5ab30286c9a590944d64d4c5b",
    "b706dd4bbecd8471c12065e02b744be8246234e99c4e38832da673744636a3a12f95f133ae0799748d3017b1435382d8",
    "c55355f4bc39d4f084f6c20f76736499b7904d51626b691f6119b9a1c190f9fc2cfafde26e9bd457dccc8c1da3d1067c",
    "fb478cd1f654d640b71d6ff3d48707eb765f1f02818100de11b1bb083424971ac89d3b38b04f93acacdf54edbb214b04",
    "09b60d0dfc5091107100cdd57c39b62afac00554e15761624e3fdc8c102f0db3e6dc6d89284479a249c793021a5f2a24",
    "cfd1c2c95a2b54855c718f065f987df5bd3baa289ecb1c6fd0f81523cfee5d76af26f2aa860d020a86b8e5930e3d4f07",
    "fbdc16ad560ae102818100a13951d63ed45c38953b8b0a01ee61fc9b49f6b3684e4c8ef28e776b4b5820ce4233d205ec",
    "5d86ca7942fdb98c4766c1a0b8413db6674e91a20ce637c62f66c966289d0ea30a0153beed26f712d222cd648a79f7d1",
    "58a85b9cc57d0a5410f0b69fa3cc6b767cc1cf3c123f07c148addd811479414d859e6dba33744c328c980b0281802c3f",
    "f45d637618706faad801cbfafdf05c311a536f07a1cbb3e3477e7471f98fde69d6122ddf1214e59d8f93c06522a74a12",
    "73913beba1a4a65b7342f458acc45bfd3da26281e4c29e1137280c3d4673121be898ea593426ad47e6d2b2436a0fa18c",
    "4f52cf0f08dd60dfe7efe4e0cf48bfd63693b068def8978bad406b8bc0a1028181008f37838c3a556008ae3bc4378314",
    "570c6ce6e13b6813bf8cea8bdd9a5c0bc2374f0b7bc12c44bc36a6df4f39959dc9008e26d14ac4e7e92688e9be1a4ea0",
    "e93cb8cbfc58c7a193c890ac09204b2be24422655c531fa4677914b93ec0e35a9dc0b24a3b5429ce078ef009928d32c1",
    "cfc297dc2329074198c709341effe9df1815",
);

const R1024_PKCS8_HEX: &str = concat!(
    "30820277020100300d06092a864886f70d0101010500048202613082025d02010002818100db8c3104405cd4bf5b1fb6",
    "e0e562029c1d70d650a06f926388f0a516ab07831aec5ada56cb3baf80652000c07b0753780d652fb5c790f90a3e519e",
    "94773843ba91a9ffc0943b142651d47604118de8904ebfdfbfcf651b0b1149c26fd2b7d07ab10a8d371761a53b98c038",
    "eb6cf3004843fb93587664d49ea722db105115f1a3020301000102818100b8abc59743e451f7dbd86365eccc72518ada",
    "1d0b98c800a4c4cd56b028909b110c7aa769966dd003fa0bdf5608a672e96aab1064a1472a94193362669399ba2d27dd",
    "8dee6fd58376344fc2bfc8dc533d315c3f2a3e1fc87bdda3c29c7bdba3b8b1c40ca6b7162c7c497aed9fa8b137442e91",
    "22392dd0d4fb57e435d7ed13e211024100f35839fa6989f32a1694756eea38a4e8fc1a937401130cc8e8dd8fccafd1f8",
    "60611057103b0f9d26f6bc25034c7a5e6508b5c4deb65a08cdbb15cb9b3accb885024100e6f7249cab7edb707f520fe8",
    "ddd42c285d6c12c8a0cf645489b477119817443d3f0ad0f2bf77e6643d27674a3de8d6b10f3e09cb9f3f31bd605fa87b",
    "95912e070240242d36995abd4e7030612bc02c83f54849ca6da76e4d75b61ca06bb3636414c7c746559b2d1c9a2163c6",
    "febda9cdfb608bd5f209a6146680a7528b2d6da567bd024100c76ab1e0d7adb33821a62ff866b78fdcd634becf1d1193",
    "d5ee03b41eabcbc2ee82a50b1ddcb5606641eae8a2d06b5e1b08470f5c114615e325f7d1d7ca9ecc370240161fae3c81",
    "e2500e7712585c4b8095e5a6b861b0350acafc904cd4b2d64e666efade85e762cba9770916a5fcd55a72cc12eee84806",
    "09cfdfb8f4057fe81edc93",
);

fn de_hex(h: &str) -> Vec<u8> {
    (0..h.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&h[i..i + 2], 16).expect("hex da chave de teste"))
        .collect()
}

fn chave_pkcs8(hex: &str) -> RsaPrivateKey {
    use rsa::pkcs8::DecodePrivateKey;
    RsaPrivateKey::from_pkcs8_der(&de_hex(hex)).expect("chave PKCS#8 de teste")
}

fn chave_rsa_2048() -> &'static RsaPrivateKey {
    static K: OnceLock<RsaPrivateKey> = OnceLock::new();
    K.get_or_init(|| chave_pkcs8(R2048A_PKCS8_HEX))
}

/// Uma chave deliberadamente fraca, para provar que o piso de tamanho existe.
fn chave_rsa_1024() -> &'static RsaPrivateKey {
    static K: OnceLock<RsaPrivateKey> = OnceLock::new();
    K.get_or_init(|| chave_pkcs8(R1024_PKCS8_HEX))
}

/// Segunda chave de 2048, para a folha ser distinta da raiz.
fn chave_rsa_2048_folha() -> &'static RsaPrivateKey {
    static K: OnceLock<RsaPrivateKey> = OnceLock::new();
    K.get_or_init(|| chave_pkcs8(R2048B_PKCS8_HEX))
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


#[cfg(test)]
mod despejo_para_o_harness {
    /// Escreve uma cadeia sintetica completa em disco — ancora, token e CRL —
    /// para o harness de qualificacao poder ser exercitado ponta a ponta sem um
    /// `.tst` real.
    ///
    /// Nao substitui a evidencia de laboratorio: prova que a CANALIZACAO
    /// funciona, nao que interoperamos com uma ACT credenciada. O unico input
    /// que continua a faltar e o token real.
    ///
    /// `#[ignore]` de proposito: corre a mao, com `HERACLITUS_DESPEJO=<pasta>`.
    #[test]
    #[ignore]
    fn escrever() {
        let Ok(dir) = std::env::var("HERACLITUS_DESPEJO") else {
            eprintln!("defina HERACLITUS_DESPEJO=<pasta>");
            return;
        };
        let base = std::path::PathBuf::from(&dir);
        let anc = base.join("ancoras");
        let crls = base.join("crls");
        std::fs::create_dir_all(&anc).unwrap();
        std::fs::create_dir_all(&crls).unwrap();

        let chain = super::chain_de_teste();
        let conteudo = b"conteudo de qualificacao";
        let imprint = crate::trust_store::sha256(conteudo);
        let token = super::token_de_teste(
            &chain,
            &imprint,
            1_760_000_000 - 60,
            None,
            super::OpcoesToken::default(),
        );
        let crl = super::crl_de_teste(
            &chain.root,
            &chain.root_key,
            1_760_000_000 - 3_600,
            Some(1_760_000_000 + 86_400 * 3650),
            vec![],
        );
        std::fs::write(anc.join("raiz.der"), &chain.root_der).unwrap();
        std::fs::write(crls.join("raiz.crl"), &crl).unwrap();
        std::fs::write(base.join("carimbo.tst"), &token).unwrap();
        let hex: String = imprint.iter().map(|b| format!("{b:02x}")).collect();
        std::fs::write(base.join("imprint.txt"), &hex).unwrap();
        std::fs::write(base.join("politica.txt"), super::OID_POLITICA_TESTE.to_string()).unwrap();
        println!("despejado em {dir}");
        println!("imprint  = {hex}");
        println!("politica = {}", super::OID_POLITICA_TESTE);
    }
}
