//! SPEC-0046 §9 — que assinaturas o verificador aceita, e porquê essas.
//!
//! # O que estava errado, e era total
//!
//! O verificador aceitava **um** algoritmo RSA: `sha256WithRSAEncryption`. A
//! DOC-ICP-01.01 impõe à AC Raiz da ICP-Brasil RSA-4096 com **SHA-512**. Ou
//! seja: numa hierarquia real `Raiz → AC → ACT`, o elo `Raiz → AC` está assinado
//! com `sha512WithRSAEncryption` e caía no ramo de recusa.
//!
//! A consequência não era um aviso. Era um carimbo perfeitamente legítimo de uma
//! ACT credenciada a ser recusado — e com a mensagem errada, porque o erro do
//! elo superior é engolido pelo `.is_ok()` da procura de âncora e reaparece como
//! *"cadeia não chega a nenhuma âncora configurada"*. Um operador leria isso
//! como "instalei a âncora errada" e iria mexer na pasta certa pela razão
//! errada.
//!
//! Não havia sequer estrutura para outro digest: `Sha256::digest` e
//! `Pkcs1v15Sign::new::<Sha256>()` estavam escritos no ramo.
//!
//! # O que se aceita agora, e o que continua a ser recusado
//!
//! | esquema | SHA-256 | SHA-384 | SHA-512 |
//! |---|---|---|---|
//! | RSA PKCS#1 v1.5 | sim | sim | sim |
//! | RSASSA-PSS | sim | sim | sim |
//! | ECDSA P-256 | sim | sim | sim |
//!
//! ECDSA em P-384 e P-521 **continua recusado**, e o erro di-lo pelo nome: as
//! caixas `p384`/`p521` não estão na árvore e acrescentá-las a um crate com
//! gates de supply-chain (SPEC-0049) é uma decisão de quem mantém a árvore, não
//! de quem corrige um bug. A ICP-Brasil impõe RSA, portanto isto não bloqueia o
//! uso a que o módulo se destina — mas fica dito em vez de descoberto.
//!
//! SHA-1 e MD5 não têm ramo e nunca terão: um verificador de evidência legal que
//! aceite um digest com colisões conhecidas não está a verificar nada.
//!
//! # Tamanho mínimo de chave
//!
//! A caixa `rsa` impõe um **máximo** (4096) e nenhum mínimo. Um módulo de 512
//! bits era aceite: fatoriza-se num portátil em horas, e quem o fizesse a uma
//! âncora legada emitia folhas que passavam em tudo — cadeia, assinatura,
//! `messageDigest`, EKU, validade — e ainda assinava a CRL que declarava essas
//! folhas como não revogadas. [`PoliticaAlgoritmos::min_rsa_bits`] fecha isso,
//! com o piso da própria ICP-Brasil.

use der::asn1::ObjectIdentifier;
use der::{Decode, Encode};
use x509_cert::spki::AlgorithmIdentifierOwned;
use x509_cert::Certificate;

use crate::CompError;

// --- assinatura --------------------------------------------------------
pub const OID_ECDSA_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");
pub const OID_ECDSA_SHA384: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.3");
pub const OID_ECDSA_SHA512: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.4");
pub const OID_SHA256_RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");
pub const OID_SHA384_RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.12");
pub const OID_SHA512_RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.13");
pub const OID_RSASSA_PSS: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.10");

// --- chave -------------------------------------------------------------
pub const OID_RSA_ENCRYPTION: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");
pub const OID_EC_PUBLIC_KEY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
pub const OID_PRIME256V1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");
pub const OID_SECP384R1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.34");
pub const OID_SECP521R1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.35");

// --- digest ------------------------------------------------------------
pub const OID_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1");
pub const OID_SHA384: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.2");
pub const OID_SHA512: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.3");

/// Os digests que este verificador sabe calcular.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Digest {
    Sha256,
    Sha384,
    Sha512,
}

impl Digest {
    pub fn do_oid(oid: &ObjectIdentifier) -> Option<Self> {
        match *oid {
            OID_SHA256 => Some(Self::Sha256),
            OID_SHA384 => Some(Self::Sha384),
            OID_SHA512 => Some(Self::Sha512),
            _ => None,
        }
    }

    pub const fn oid(self) -> ObjectIdentifier {
        match self {
            Self::Sha256 => OID_SHA256,
            Self::Sha384 => OID_SHA384,
            Self::Sha512 => OID_SHA512,
        }
    }

    pub const fn bytes(self) -> usize {
        match self {
            Self::Sha256 => 32,
            Self::Sha384 => 48,
            Self::Sha512 => 64,
        }
    }

    pub fn digerir(self, m: &[u8]) -> Vec<u8> {
        use sha2::Digest as _;
        match self {
            Self::Sha256 => sha2::Sha256::digest(m).to_vec(),
            Self::Sha384 => sha2::Sha384::digest(m).to_vec(),
            Self::Sha512 => sha2::Sha512::digest(m).to_vec(),
        }
    }

    pub const fn label(self) -> &'static str {
        match self {
            Self::Sha256 => "SHA-256",
            Self::Sha384 => "SHA-384",
            Self::Sha512 => "SHA-512",
        }
    }
}

/// Decisões do operador sobre que criptografia aceitar.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PoliticaAlgoritmos {
    /// Bits mínimos do módulo RSA. Default 2048, que é o piso da ICP-Brasil
    /// para certificados de fim de entidade.
    ///
    /// Baixá-lo é uma decisão explícita, e o erro diz quantos bits o
    /// certificado tem para que ela seja informada.
    pub min_rsa_bits: usize,
}

impl Default for PoliticaAlgoritmos {
    fn default() -> Self {
        Self { min_rsa_bits: 2048 }
    }
}

fn erro(d: String) -> CompError {
    CompError::Verify(d)
}

/// O que um `AlgorithmIdentifier` de assinatura significa.
#[derive(Debug, PartialEq, Eq)]
enum Esquema {
    Ecdsa(Digest),
    RsaPkcs1(Digest),
    RsaPss(Digest),
}

/// Traduz o `AlgorithmIdentifier` da assinatura no esquema a verificar.
///
/// `digest_externo` e o digest declarado FORA do OID da assinatura. Existe por
/// causa do CMS: a RFC 3370 §3.2 diz que, para RSA PKCS#1 v1.5, o
/// `SignerInfo.signatureAlgorithm` e `rsaEncryption` — um OID que NAO carrega
/// digest nenhum — e que o digest e o do `SignerInfo.digestAlgorithm`. E o que
/// o OpenSSL emite (`openssl ts -reply`).
///
/// Sem isto, `rsaEncryption` caia no ramo de recusa e um carimbo perfeitamente
/// valido de uma ACT que assine com OpenSSL era rejeitado como "algoritmo nao
/// suportado".
///
/// A tolerancia e ESTREITA de proposito: so se aplica quando ha um digest
/// externo para usar, e quem verifica certificados X.509 passa `None` — ali o
/// OID combinado e obrigatorio e `rsaEncryption` continua a ser recusado.
fn interpretar(
    alg: &AlgorithmIdentifierOwned,
    digest_externo: Option<Digest>,
) -> Result<Esquema, CompError> {
    if alg.oid == OID_RSA_ENCRYPTION {
        return match digest_externo {
            Some(d) => Ok(Esquema::RsaPkcs1(d)),
            None => Err(erro(
                "assinatura com rsaEncryption sem digest declarado: este OID nao carrega digest \
                 e nao ha digestAlgorithm para o suprir"
                    .into(),
            )),
        };
    }
    match alg.oid {
        OID_ECDSA_SHA256 => Ok(Esquema::Ecdsa(Digest::Sha256)),
        OID_ECDSA_SHA384 => Ok(Esquema::Ecdsa(Digest::Sha384)),
        OID_ECDSA_SHA512 => Ok(Esquema::Ecdsa(Digest::Sha512)),
        OID_SHA256_RSA => Ok(Esquema::RsaPkcs1(Digest::Sha256)),
        OID_SHA384_RSA => Ok(Esquema::RsaPkcs1(Digest::Sha384)),
        OID_SHA512_RSA => Ok(Esquema::RsaPkcs1(Digest::Sha512)),
        OID_RSASSA_PSS => {
            // O digest do PSS vem dos PARÂMETROS, não do OID. Assumir SHA-256
            // aqui seria verificar com o digest errado — e uma verificação com
            // o digest errado falha sempre, o que se leria como assinatura
            // inválida num token perfeitamente bom.
            let params = alg.parameters.as_ref().ok_or_else(|| {
                erro("RSASSA-PSS sem parâmetros: o digest não está declarado".into())
            })?;
            let der = params
                .to_der()
                .map_err(|e| erro(format!("parâmetros PSS não recodificam: {e}")))?;
            let pss = pkcs1::RsaPssParams::from_der(&der)
                .map_err(|e| erro(format!("RSASSA-PSS-params inválidos: {e}")))?;
            let d = Digest::do_oid(&pss.hash.oid).ok_or_else(|| {
                erro(format!(
                    "RSASSA-PSS com digest {} não suportado",
                    pss.hash.oid
                ))
            })?;
            // A MGF tem de usar o mesmo digest. Um PSS com MGF1-SHA1 e
            // hash SHA-256 é legal em ASN.1 e é exactamente o tipo de
            // combinação que não se quer aceitar em evidência legal.
            let mgf_hash = pss.mask_gen.parameters.as_ref().map(|p| p.oid);
            if mgf_hash != Some(d.oid()) {
                return Err(erro(format!(
                    "RSASSA-PSS com MGF1 sobre um digest diferente do da assinatura ({}): \
                     recusado por ser uma combinação que nada legítimo produz",
                    mgf_hash
                        .map(|o| o.to_string())
                        .unwrap_or_else(|| "ausente".into())
                )));
            }
            if usize::from(pss.salt_len) != d.bytes() {
                return Err(erro(format!(
                    "RSASSA-PSS com saltLength {} em vez de {} (tamanho do digest)",
                    pss.salt_len,
                    d.bytes()
                )));
            }
            Ok(Esquema::RsaPss(d))
        }
        // Um OID que não conhecemos é recusado COM o OID. Um verificador que
        // passe por cima de um algoritmo que não conhece é um verificador que
        // aceita tudo.
        outro => Err(erro(format!(
            "algoritmo de assinatura {outro} não suportado; a verificação recusa em vez de o \
             ignorar. Aceites: RSA PKCS#1v1.5 e RSASSA-PSS com SHA-256/384/512, ECDSA P-256 \
             com SHA-256/384/512"
        ))),
    }
}

/// Verifica `assinatura` sobre `mensagem` com a chave pública de `cert`.
pub fn verificar(
    cert: &Certificate,
    alg: &AlgorithmIdentifierOwned,
    mensagem: &[u8],
    assinatura: &[u8],
    politica: &PoliticaAlgoritmos,
) -> Result<(), CompError> {
    verificar_com_digest(cert, alg, None, mensagem, assinatura, politica)
}

/// O mesmo, sabendo o digest que o CMS declara a parte (ver [`interpretar`]).
pub fn verificar_com_digest(
    cert: &Certificate,
    alg: &AlgorithmIdentifierOwned,
    digest_externo: Option<Digest>,
    mensagem: &[u8],
    assinatura: &[u8],
    politica: &PoliticaAlgoritmos,
) -> Result<(), CompError> {
    let spki = &cert.tbs_certificate.subject_public_key_info;
    match interpretar(alg, digest_externo)? {
        Esquema::Ecdsa(d) => {
            if spki.algorithm.oid != OID_EC_PUBLIC_KEY {
                return Err(erro("assinatura ECDSA com uma chave que não é EC".into()));
            }
            let curva = spki
                .algorithm
                .parameters
                .as_ref()
                .and_then(|p| p.decode_as::<ObjectIdentifier>().ok());
            match curva {
                Some(OID_PRIME256V1) => {}
                Some(c) if c == OID_SECP384R1 || c == OID_SECP521R1 => {
                    return Err(erro(format!(
                        "curva {c} reconhecida mas não implementada: as caixas `p384`/`p521` não \
                         estão na árvore. Acrescentá-las é uma decisão de supply-chain \
                         (SPEC-0049), não uma correcção — e a ICP-Brasil impõe RSA"
                    )))
                }
                outra => {
                    return Err(erro(format!(
                        "curva EC {} não suportada",
                        outra
                            .map(|o| o.to_string())
                            .unwrap_or_else(|| "ausente".into())
                    )))
                }
            }
            let pontos = spki
                .subject_public_key
                .as_bytes()
                .ok_or_else(|| erro("chave pública EC não alinhada em bytes".into()))?;
            let vk = p256::ecdsa::VerifyingKey::from_sec1_bytes(pontos)
                .map_err(|e| erro(format!("chave pública EC inválida: {e}")))?;
            // O CMS traz a assinatura ECDSA em DER (SEQUENCE de r,s).
            let sig = p256::ecdsa::Signature::from_der(assinatura)
                .map_err(|e| erro(format!("assinatura ECDSA malformada: {e}")))?;
            // Prehash em vez de `Verifier`: só assim se aceita ECDSA com um
            // digest que não seja o do tamanho do campo. O FIPS 186-4 manda
            // usar os bits mais à esquerda, que é o que `verify_prehash` faz.
            let resumo = d.digerir(mensagem);
            use p256::ecdsa::signature::hazmat::PrehashVerifier;
            vk.verify_prehash(&resumo, &sig)
                .map_err(|_| erro("assinatura não confere".into()))
        }
        Esquema::RsaPkcs1(d) | Esquema::RsaPss(d) => {
            if spki.algorithm.oid != OID_RSA_ENCRYPTION && spki.algorithm.oid != OID_RSASSA_PSS {
                return Err(erro("assinatura RSA com uma chave que não é RSA".into()));
            }
            let der = spki
                .subject_public_key
                .as_bytes()
                .ok_or_else(|| erro("chave pública RSA não alinhada em bytes".into()))?;
            let chave = <rsa::RsaPublicKey as rsa::pkcs1::DecodeRsaPublicKey>::from_pkcs1_der(der)
                .map_err(|e| erro(format!("chave pública RSA inválida: {e}")))?;
            let bits = rsa::traits::PublicKeyParts::n(&chave).bits();
            if bits < politica.min_rsa_bits {
                return Err(erro(format!(
                    "chave RSA de {bits} bits abaixo do mínimo de {} exigido pela política: um \
                     módulo pequeno fatoriza-se, e quem o fizesse emitiria carimbos que passam \
                     em tudo o resto",
                    politica.min_rsa_bits
                )));
            }
            let resumo = d.digerir(mensagem);
            let resultado = match interpretar(alg, digest_externo)? {
                Esquema::RsaPss(_) => {
                    let esquema = match d {
                        Digest::Sha256 => rsa::pss::Pss::new::<sha2::Sha256>(),
                        Digest::Sha384 => rsa::pss::Pss::new::<sha2::Sha384>(),
                        Digest::Sha512 => rsa::pss::Pss::new::<sha2::Sha512>(),
                    };
                    rsa::traits::SignatureScheme::verify(esquema, &chave, &resumo, assinatura)
                }
                _ => {
                    let esquema = match d {
                        Digest::Sha256 => rsa::Pkcs1v15Sign::new::<sha2::Sha256>(),
                        Digest::Sha384 => rsa::Pkcs1v15Sign::new::<sha2::Sha384>(),
                        Digest::Sha512 => rsa::Pkcs1v15Sign::new::<sha2::Sha512>(),
                    };
                    rsa::traits::SignatureScheme::verify(esquema, &chave, &resumo, assinatura)
                }
            };
            resultado.map_err(|_| erro("assinatura não confere".into()))
        }
    }
}

/// RFC 5280 §4.1.1.2 — `signatureAlgorithm` (fora da assinatura) tem de ser
/// **idêntico** a `tbsCertificate.signature` (dentro dela).
///
/// O campo que escolhia o algoritmo era o de fora, que não está coberto por
/// assinatura nenhuma. Comparar os dois é o que impede que alguém troque o
/// algoritmo declarado de um certificado sem invalidar a assinatura — a norma
/// exige a comparação exactamente por isso, e ela não existia.
pub fn coerencia_de_algoritmo(cert: &Certificate) -> Result<(), CompError> {
    let fora = cert
        .signature_algorithm
        .to_der()
        .map_err(|e| erro(format!("signatureAlgorithm não codifica: {e}")))?;
    let dentro = cert
        .tbs_certificate
        .signature
        .to_der()
        .map_err(|e| erro(format!("tbsCertificate.signature não codifica: {e}")))?;
    if fora != dentro {
        return Err(erro(format!(
            "certificado `{}` declara {} fora da assinatura e {} dentro: §4.1.1.2 exige que \
             sejam iguais, e o campo de fora não está protegido por assinatura nenhuma",
            cert.tbs_certificate.subject,
            cert.signature_algorithm.oid,
            cert.tbs_certificate.signature.oid
        )));
    }
    Ok(())
}

#[cfg(test)]
mod testes_interpretar {
    use super::*;

    fn alg(oid: ObjectIdentifier) -> AlgorithmIdentifierOwned {
        AlgorithmIdentifierOwned {
            oid,
            parameters: None,
        }
    }

    /// O cerne da correccao: no CMS (RFC 3370 §3.2) o `signatureAlgorithm` de
    /// RSA PKCS#1 v1.5 e `rsaEncryption` — um OID que NAO carrega digest — e o
    /// digest vem do `digestAlgorithm` a parte. E o que o OpenSSL emite.
    #[test]
    fn rsa_encryption_usa_o_digest_externo() {
        assert_eq!(
            interpretar(&alg(OID_RSA_ENCRYPTION), Some(Digest::Sha256)).unwrap(),
            Esquema::RsaPkcs1(Digest::Sha256)
        );
        assert_eq!(
            interpretar(&alg(OID_RSA_ENCRYPTION), Some(Digest::Sha512)).unwrap(),
            Esquema::RsaPkcs1(Digest::Sha512)
        );
    }

    /// Sem digest a parte, `rsaEncryption` nao diz o suficiente: recusa-se, em
    /// vez de adivinhar SHA-256 (que verificaria com o digest errado e falharia
    /// como se a assinatura fosse invalida).
    #[test]
    fn rsa_encryption_sem_digest_recusa() {
        assert!(interpretar(&alg(OID_RSA_ENCRYPTION), None).is_err());
    }

    /// Um OID COMBINADO continua a valer por si — e ignora o digest externo,
    /// porque ja o carrega. Isto garante que a tolerancia nao afrouxou a
    /// verificacao de certificados X.509, que passam `None`.
    #[test]
    fn oid_combinado_ignora_o_externo_e_vale_sem_ele() {
        assert_eq!(
            interpretar(&alg(OID_SHA256_RSA), None).unwrap(),
            Esquema::RsaPkcs1(Digest::Sha256)
        );
        assert_eq!(
            interpretar(&alg(OID_SHA256_RSA), Some(Digest::Sha512)).unwrap(),
            Esquema::RsaPkcs1(Digest::Sha256)
        );
    }
}
