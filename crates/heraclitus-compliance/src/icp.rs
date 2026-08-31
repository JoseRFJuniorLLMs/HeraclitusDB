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
use der::asn1::{Int, OctetString, SetOfVec};
use der::{Any, Decode, Encode, Sequence};
use x509_cert::ext::pkix::{BasicConstraints, ExtendedKeyUsage};
use x509_cert::time::Time;
use x509_cert::Certificate;

use crate::trust_store::TrustStore;
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
// O OID de SHA-256 vive em `crate::algoritmos`; o imprint deixou de estar
// fixado nele e passou a vir do que o token DECLARA.
// Os OIDs de assinatura e de chave vivem agora em `crate::algoritmos`, que e
// quem despacha a verificacao. Duplica-los aqui deixaria duas listas a
// divergir — e a que ficasse desactualizada seria a que decide.

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

/// `GeneralizedTime` tolerante a fracções de segundo, para o `genTime`.
///
/// A RFC 3161 §2.4.2 permite-as **explicitamente**: *"the ASN.1 GeneralizedTime
/// syntax can include fraction-of-second details"*, e é assim que uma ACT
/// declara precisão de milissegundos. O `GeneralizedTime` da caixa `der` é
/// DER-estrito — o DER proíbe a fracção — e recusa-a.
///
/// O resultado era o pior possível: um token de uma ACT credenciada que
/// declarasse `20260830143012.500Z` **nem chegava a descodificar**, e o erro
/// falava de ASN.1 malformado. O operador procuraria um token corrompido que
/// não existe.
///
/// Guarda-se a fracção em milissegundos porque é ela que o `genTime` significa;
/// descartá-la truncaria a hora que a autoridade afirmou, que é precisamente o
/// facto que o carimbo existe para registar.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GenTime {
    pub unix_ms: u64,
    /// Os octetos originais, para uma recodificação fiel.
    bruto: Vec<u8>,
}

impl GenTime {
    pub const fn unix_ms(&self) -> u64 {
        self.unix_ms
    }

    /// Constrói a partir de segundos Unix, com uma fracção opcional em
    /// milissegundos. `milis = None` emite a forma sem fracção.
    pub fn nova(unix_secs: u64, milis: Option<u16>) -> Result<Self, CompError> {
        let dias = (unix_secs / 86_400) as i64;
        let resto = unix_secs % 86_400;
        // civil_from_days (Howard Hinnant).
        let z = dias + 719_468;
        let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
        let doe = z - era * 146_097;
        let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
        let y = yoe + era * 400;
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
        let mp = (5 * doy + 2) / 153;
        let d = doy - (153 * mp + 2) / 5 + 1;
        let m = if mp < 10 { mp + 3 } else { mp - 9 };
        let ano = if m <= 2 { y + 1 } else { y };
        let texto = match milis {
            Some(f) => format!(
                "{ano:04}{m:02}{d:02}{:02}{:02}{:02}.{f:03}Z",
                resto / 3_600,
                (resto % 3_600) / 60,
                resto % 60
            ),
            None => format!(
                "{ano:04}{m:02}{d:02}{:02}{:02}{:02}Z",
                resto / 3_600,
                (resto % 3_600) / 60,
                resto % 60
            ),
        };
        let unix_ms = analisar_generalized(&texto).ok_or_else(|| {
            verify_err(format!("genTime construído inválido: `{texto}`"))
        })?;
        Ok(Self {
            unix_ms,
            bruto: texto.into_bytes(),
        })
    }
}

impl der::FixedTag for GenTime {
    const TAG: der::Tag = der::Tag::GeneralizedTime;
}

impl<'a> der::DecodeValue<'a> for GenTime {
    fn decode_value<R: der::Reader<'a>>(
        reader: &mut R,
        header: der::Header,
    ) -> der::Result<Self> {
        let bruto = reader.read_vec(header.length)?;
        let texto = std::str::from_utf8(&bruto)
            .map_err(|_| der::Tag::GeneralizedTime.value_error())?;
        let unix_ms = analisar_generalized(texto)
            .ok_or_else(|| der::Tag::GeneralizedTime.value_error())?;
        Ok(Self { unix_ms, bruto })
    }
}

impl der::EncodeValue for GenTime {
    fn value_len(&self) -> der::Result<der::Length> {
        der::Length::try_from(self.bruto.len())
    }
    fn encode_value(&self, writer: &mut impl der::Writer) -> der::Result<()> {
        writer.write(&self.bruto)
    }
}

/// `YYYYMMDDHHMMSS[.fff…]Z` → ms desde a época.
///
/// Só a forma com `Z` é aceite. Uma hora com deslocamento local (`+0300`) é
/// legal em BER e proibida no perfil da RFC 5280 §4.1.2.5.2; aceitá-la
/// obrigaria a confiar num fuso que o emissor escolheu, num campo cujo
/// propósito é fixar um instante absoluto.
fn analisar_generalized(s: &str) -> Option<u64> {
    let s = s.strip_suffix('Z')?;
    let (base, fraccao) = match s.split_once('.') {
        Some((b, f)) => (b, Some(f)),
        None => match s.split_once(',') {
            // A vírgula é o separador decimal alternativo do X.680.
            Some((b, f)) => (b, Some(f)),
            None => (s, None),
        },
    };
    if base.len() != 14 || !base.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let n = |i: usize, j: usize| base[i..j].parse::<i64>().ok();
    let (ano, mes, dia) = (n(0, 4)?, n(4, 6)?, n(6, 8)?);
    let (h, m, seg) = (n(8, 10)?, n(10, 12)?, n(12, 14)?);
    if !(1..=12).contains(&mes) || !(1..=31).contains(&dia) || h > 23 || m > 59 || seg > 60 {
        return None;
    }
    // Dias desde a época pelo algoritmo de Howard Hinnant (civil_from_days
    // invertido). Evita uma dependência de calendário para meia dúzia de linhas.
    let y = if mes <= 2 { ano - 1 } else { ano };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (mes + 9) % 12;
    let doy = (153 * mp + 2) / 5 + dia - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let dias = era * 146_097 + doe - 719_468;

    let segundos = dias.checked_mul(86_400)? + h * 3_600 + m * 60 + seg;
    if segundos < 0 {
        return None;
    }
    let mut ms = (segundos as u64).checked_mul(1_000)?;
    if let Some(f) = fraccao {
        if f.is_empty() || !f.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        // Só os três primeiros dígitos interessam em ms; o resto é precisão
        // que este tipo não representa e que descartar não altera a hora
        // afirmada para lá do milissegundo.
        let mut milis = 0u64;
        for (i, b) in f.bytes().take(3).enumerate() {
            milis += u64::from(b - b'0') * 10u64.pow(2 - i as u32);
        }
        ms = ms.checked_add(milis)?;
    }
    Some(ms)
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
    pub gen_time: GenTime,
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
    /// Tecto de certificados no conjunto do token.
    ///
    /// O tamanho em bytes era o único travão: um token de 512 KB cabe em
    /// milhares de certificados minúsculos, e a construção da cadeia percorre o
    /// conjunto a cada elo. É um travão de esforço, não uma regra da norma —
    /// uma cadeia ICP-Brasil traz três ou quatro.
    pub max_certificados: usize,
    /// Exigir o `extendedKeyUsage` da RFC 3161 §2.3: crítico e com o carimbo
    /// como único propósito. `true` por omissão.
    ///
    /// Desligá-lo aceita uma ACT que não segue a norma, e é uma decisão sobre
    /// quanto se aceita — não uma opção de conveniência.
    pub eku_estrito: bool,
    /// SPEC-0046 §9 — rigidez da validação de cadeia (RFC 5280 §6.1):
    /// `nameConstraints`, `pathLenConstraint`, `keyUsage` e o tratamento de
    /// extensões críticas não reconhecidas.
    pub restricoes: crate::constraints::RestricoesPolicy,
    /// SPEC-0046 §9 — que assinaturas se aceitam e com que tamanho mínimo de
    /// chave. O default cobre a ICP-Brasil real (RSA com SHA-256/384/512).
    pub algoritmos: crate::algoritmos::PoliticaAlgoritmos,
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
            max_certificados: 32,
            eku_estrito: true,
            restricoes: crate::constraints::RestricoesPolicy::default(),
            algoritmos: crate::algoritmos::PoliticaAlgoritmos::default(),
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
    /// Até quando a resposta de revogação é boa: o `nextUpdate` MAIS CURTO de
    /// todas as CRLs consultadas, em ms.
    ///
    /// Era calculado e deitado fora. Sem ele, um relatório construído a partir
    /// deste resultado não distingue uma consulta feita contra CRLs de hoje de
    /// uma feita contra CRLs de 2019 — e `revocation_checked: true` lê-se igual
    /// nos dois casos.
    pub revocation_valid_until_ms: Option<u64>,
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
    /// Verifica **tudo menos** a ligação a um conteúdo: cadeia, assinatura,
    /// `messageDigest`, EKU, validade, restrições e revogação. Devolve também o
    /// `messageImprint` que o token declara.
    ///
    /// Existe para uma coisa só, e é a que faltava: pegar num `.tst` emitido
    /// por uma ACT credenciada e ver se este verificador o aceita, sem ter o
    /// documento original. É como se prova interoperabilidade — e sem isso a
    /// única forma de a testar era pôr o sistema a ancorar em produção.
    ///
    /// **Não** prova que o token carimbou coisa nenhuma em particular. Quem
    /// chama isto tem de o dizer no que reportar; é por isso que o imprint sai
    /// no resultado em vez de ser silenciosamente aceite.
    pub fn inspect(
        &self,
        token_der: &[u8],
        now_unix_ms: u64,
    ) -> Result<(VerifiedTimestamp, Vec<u8>), CompError> {
        let imprint = Self::imprint_declarado(token_der)?;
        let v = self.verify(token_der, &imprint, None, now_unix_ms)?;
        Ok((v, imprint))
    }

    /// O `messageImprint` que o token declara, sem verificar nada.
    fn imprint_declarado(token_der: &[u8]) -> Result<Vec<u8>, CompError> {
        let content = cms::content_info::ContentInfo::from_der(token_der)
            .map_err(|e| verify_err(format!("não é um ContentInfo CMS: {e}")))?;
        let signed = content
            .content
            .decode_as::<cms::signed_data::SignedData>()
            .map_err(|e| verify_err(format!("SignedData inválido: {e}")))?;
        let econtent = signed
            .encap_content_info
            .econtent
            .ok_or_else(|| verify_err("SignedData sem eContent".into()))?;
        let tst_bytes = econtent.value();
        let tst = TstInfo::from_der(tst_bytes)
            .map_err(|e| verify_err(format!("TSTInfo inválido: {e}")))?;
        Ok(tst.message_imprint.hashed_message.as_bytes().to_vec())
    }

    pub fn verify(
        &self,
        token_der: &[u8],
        expected_imprint: &[u8],
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
        let certificados = certificados_de(&signed, self.policy.max_certificados)?;
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
            &signer.signature_algorithm,
            &attrs_der,
            signer.signature.as_bytes(),
            &self.policy.algoritmos,
        )?;

        // 5 — os atributos assinados descrevem ESTE conteúdo.
        // §5.1 — o `digestAlgorithm` do SignerInfo tem de constar dos
        // `digestAlgorithms` do SignedData. O campo existe para que um
        // verificador saiba de antemão que digests vai precisar; um SignerInfo
        // que use outro está a contradizer o envelope que o contém, e a
        // contradição não é decorativa: é a marca de um token remontado.
        if !signed
            .digest_algorithms
            .iter()
            .any(|a| a.oid == signer.digest_alg.oid)
        {
            return Err(verify_err(format!(
                "digestAlgorithm {} do SignerInfo não consta dos digestAlgorithms do SignedData",
                signer.digest_alg.oid
            )));
        }

        // §5.3 — o digest dos signedAttrs é o que o SignerInfo declara.
        let digest_attrs = crate::algoritmos::Digest::do_oid(&signer.digest_alg.oid)
            .ok_or_else(|| {
                verify_err(format!(
                    "digestAlgorithm {} do SignerInfo não suportado",
                    signer.digest_alg.oid
                ))
            })?;
        verificar_atributos(attrs, tst_bytes, digest_attrs)?;

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
        // O imprint pode ser SHA-256, 384 ou 512. Fixá-lo em SHA-256 recusava
        // um carimbo legítimo de uma ACT que trabalhe com outro digest — e
        // impedia que este verificador servisse para inspeccionar um `.tst`
        // de terceiros, que é para o que ele existe fora do caminho vivo.
        let d_imprint = crate::algoritmos::Digest::do_oid(&tst.message_imprint.hash_algorithm.oid);
        if d_imprint.is_none() {
            return Err(verify_err(format!(
                "messageImprint em {} — só SHA-256 é aceite",
                tst.message_imprint.hash_algorithm.oid
            )));
        }
        let d_imprint = d_imprint.expect("verificado acima");
        let recebido = tst.message_imprint.hashed_message.as_bytes();
        if recebido.len() != d_imprint.bytes() {
            return Err(verify_err(format!(
                "messageImprint declara {} e traz {} bytes em vez de {}",
                d_imprint.label(),
                recebido.len(),
                d_imprint.bytes()
            )));
        }
        if recebido != expected_imprint {
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

        let gen_unix_ms = tst.gen_time.unix_ms();
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
        // A âncora também. A RFC 5280 §6.1 trata-a como dado de entrada e não
        // exige validá-la, mas uma raiz cuja janela já tinha fechado quando o
        // carimbo foi emitido não podia estar a certificar coisa nenhuma nesse
        // instante — e o doc deste módulo afirmava que isto era verificado
        // quando não era.
        validade_em(&cadeia.anchor_cert, gen_unix_ms)?;
        verificar_eku_timestamping(signer_cert, self.policy.eku_estrito)?;

        // §2.4.2 — extensões do TSTInfo. São opacas para este verificador; uma
        // marcada CRÍTICA é uma instrução que não sabemos cumprir, e a resposta
        // certa a uma instrução que não se entende num documento de evidência é
        // recusar, não seguir em frente.
        if let Some(exts) = tst.extensions.as_ref() {
            verificar_extensoes_tstinfo(exts)?;
        }

        // §6.1 — as restrições de emissão. Antes da revogação e depois da
        // cadeia: uma cadeia que a política do emissor não autoriza não vale a
        // pena consultar, e o erro tem de dizer que o problema é a autorização,
        // não a revogação.
        self.verificar_restricoes(&cadeia)?;

        // §9 — revogação. Só depois de a cadeia estar validada: consultar uma
        // CRL para um certificado que nem encadeia seria trabalho sobre uma
        // premissa falsa, e um erro de revogação aqui leria-se como se o
        // problema fosse a revogação quando é a cadeia.
        // §5.1 — as CRLs que o proprio token traz. Descarta-las era o que
        // quebrava o caso air-gap: uma ACT que anexa a CRL ao carimbo esta a
        // entregar exactamente a informacao de revogacao que uma maquina sem
        // rede nunca conseguiria ir buscar, e nos deitavamo-la fora para depois
        // falhar por "nao ha CRL do emissor".
        //
        // Usa-las nao e confiar nelas: cada uma e verificada contra o emissor
        // como qualquer outra, e uma CRL forjada dentro do token nao passa a
        // verificacao de assinatura.
        let crls_do_token = crls_embutidas(&signed);
        let (revocation_checked, revocation_valid_until_ms) =
            self.verificar_revogacao(&cadeia, gen_unix_ms, now_unix_ms, &crls_do_token)?;

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
            revocation_valid_until_ms,
        })
    }

    /// Impõe as restrições que cada emissor da cadeia declarou (RFC 5280
    /// §6.1.4): `nameConstraints`, `pathLenConstraint`, `keyUsage` da folha e
    /// extensões críticas não reconhecidas.
    ///
    /// A âncora não é validada como certificado — é um dado de entrada
    /// confiável por instalação, e a RFC 5280 §6.1 trata-a assim. Mas as suas
    /// `nameConstraints` e o seu `pathLenConstraint` **aplicam-se**: são
    /// afirmações sobre o que ela autoriza abaixo de si, e é para isso que
    /// existem.
    fn verificar_restricoes(&self, cadeia: &Cadeia) -> Result<(), CompError> {
        let policy = &self.policy.restricoes;

        // §6.1.4(f) — extensões críticas, em cada certificado do caminho.
        for cert in &cadeia.certs {
            crate::constraints::verificar_criticas(cert, policy)?;
        }

        // §4.2.1.9 — profundidade autorizada.
        crate::constraints::verificar_path_len(&cadeia.certs, &cadeia.anchor_cert)?;

        // §4.2.1.10 — nomes, da âncora para baixo. A ordem importa: cada AC
        // acrescenta as suas restrições ANTES de se verificar o que ela emitiu,
        // e nunca pode alargar o que herdou.
        let mut restricoes = crate::constraints::Restricoes::default();
        restricoes.acumular(&cadeia.anchor_cert)?;
        for cert in cadeia.certs.iter().rev() {
            restricoes.verificar(cert)?;
            restricoes.acumular(cert)?;
        }

        // A folha tem de poder assinar. `id-kp-timeStamping` diz o propósito;
        // `keyUsage` diz se a chave sequer assina.
        if let Some(folha) = cadeia.certs.first() {
            crate::constraints::exigir_assinatura_de_folha(folha)?;
        }
        Ok(())
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
        crls_do_token: &[x509_cert::crl::CertificateList],
    ) -> Result<(bool, Option<u64>), CompError> {
        let Some((store, politica)) = self.crls.as_ref() else {
            return Ok((false, None));
        };
        // As do token juntam-se as instaladas. A ordem nao importa: `consultar`
        // percorre TODAS as utilizaveis de um emissor, e uma revogacao declarada
        // em qualquer uma delas conta.
        let store = if crls_do_token.is_empty() {
            std::borrow::Cow::Borrowed(store)
        } else {
            let mut juntas = store.clone();
            for crl in crls_do_token {
                juntas.acrescentar(crl.clone());
            }
            std::borrow::Cow::Owned(juntas)
        };
        let store = store.as_ref();
        let alg_policy = &self.policy.algoritmos;
        let assinatura = |emissor: &Certificate,
                          alg: &x509_cert::spki::AlgorithmIdentifierOwned,
                          msg: &[u8],
                          sig: &[u8]| verificar_assinatura(emissor, alg, msg, sig, alg_policy);
        let tempo = |t: &x509_cert::time::Time| tempo_para_unix_ms(t);
        let mut validade_ate: Option<u64> = None;

        for (i, cert) in cadeia.certs.iter().enumerate() {
            // O emissor é o elo seguinte da cadeia; para o último, é a âncora.
            let emissor = cadeia.certs.get(i + 1).unwrap_or(&cadeia.anchor_cert);
            // `e_ca` distingue folha de AC: uma CRL com escopo
            // `onlyContainsUserCerts` nao diz nada sobre uma AC, e responder
            // com ela seria responder a pergunta errada.
            let e_ca = i > 0;
            let estado = crate::crl::consultar(
                store,
                cert,
                emissor,
                e_ca,
                gen_unix_ms,
                now_unix_ms,
                politica,
                &assinatura,
                &tempo,
            )?;
            // A janela do conjunto é a mais curta: a informação só vale
            // enquanto TODAS as CRLs consultadas continuarem válidas.
            validade_ate = match (validade_ate, estado.crl_next_update_ms) {
                (Some(a), Some(b)) => Some(a.min(b)),
                (None, b) => b,
                (a, None) => a,
            };
        }
        Ok((true, validade_ate))
    }

    /// Constrói a cadeia do signatário até uma âncora do trust store, com
    /// **backtracking**.
    ///
    /// A versão anterior escolhia o *primeiro* certificado do conjunto cujo
    /// sujeito batesse com o emissor e desistia se ele não servisse. Isso
    /// falhava no caso mais banal de uma PKI real: o **rollover de chave** de
    /// uma AC. Durante a transição, a AC tem dois certificados com o mesmo
    /// sujeito e chaves diferentes, e um carimbo legítimo traz os dois. Se o
    /// primeiro do conjunto fosse o antigo, a cadeia não fechava — e o erro
    /// dizia "emissor desconhecido", que é exactamente a coisa errada a
    /// procurar quando o emissor está ali ao lado.
    ///
    /// Agora tentam-se todos os candidatos. O caminho já percorrido é
    /// verificado a cada passo, o que também fecha ciclos: dois certificados
    /// que se emitam mutuamente não fazem isto correr para sempre.
    fn construir_cadeia(
        &self,
        signer: &Certificate,
        pool: &[Certificate],
    ) -> Result<Cadeia, CompError> {
        let mut caminho: Vec<Certificate> = vec![signer.clone()];
        // A causa mais informativa que se encontrou pelo caminho. Sem isto, um
        // elo recusado por ALGORITMO reaparecia como "emissor desconhecido" —
        // o erro do `.is_ok()` era engolido e o operador procurava a âncora
        // errada.
        let mut porque = String::new();
        match self.procurar_ancora(&mut caminho, pool, &mut porque) {
            Some(c) => Ok(c),
            None => Err(verify_err(if porque.is_empty() {
                format!(
                    "cadeia não chega a nenhuma âncora configurada (emissor `{}` desconhecido)",
                    signer.tbs_certificate.issuer
                )
            } else {
                format!(
                    "cadeia não chega a nenhuma âncora configurada; o elo mais próximo falhou \
                     por: {porque}"
                )
            })),
        }
    }

    fn procurar_ancora(
        &self,
        caminho: &mut Vec<Certificate>,
        pool: &[Certificate],
        porque: &mut String,
    ) -> Option<Cadeia> {
        if caminho.len() > self.policy.max_chain_depth {
            if porque.is_empty() {
                *porque = format!(
                    "profundidade máxima de {} excedida",
                    self.policy.max_chain_depth
                );
            }
            return None;
        }
        let atual = caminho.last().cloned()?;
        let issuer_der = atual.tbs_certificate.issuer.to_der().ok()?;

        // Uma âncora fecha a cadeia. Procura-se primeiro no trust store: se o
        // emissor é confiável, não interessa que o token traga uma cópia dele.
        for anchor in self.trust_store.anchors_for_issuer(&issuer_der) {
            match verificar_emissao(&atual, &anchor.certificate, &self.policy.algoritmos) {
                Ok(()) => {
                    return Some(Cadeia {
                        certs: caminho.clone(),
                        anchor: anchor.fingerprint,
                        anchor_cert: anchor.certificate.clone(),
                    })
                }
                Err(e) => {
                    if porque.is_empty() {
                        *porque = e.to_string();
                    }
                }
            }
        }

        // Senão, cada intermédio do próprio token que se apresente como emissor.
        for candidato in pool.iter().filter(|c| {
            c.tbs_certificate
                .subject
                .to_der()
                .map(|s| s == issuer_der)
                .unwrap_or(false)
        }) {
            // Já está no caminho: seguir seria um ciclo.
            if caminho.iter().any(|x| mesmo_certificado(x, candidato)) {
                continue;
            }
            // Um intermédio TEM de ser CA. Sem esta verificação, uma folha
            // qualquer emitida pela mesma AC podia assinar outra folha e a
            // cadeia fechava.
            if let Err(e) = verificar_ca(candidato) {
                if porque.is_empty() {
                    *porque = e.to_string();
                }
                continue;
            }
            if let Err(e) = verificar_emissao(&atual, candidato, &self.policy.algoritmos) {
                if porque.is_empty() {
                    *porque = e.to_string();
                }
                continue;
            }
            caminho.push(candidato.clone());
            if let Some(c) = self.procurar_ancora(caminho, pool, porque) {
                return Some(c);
            }
            caminho.pop();
        }
        None
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

/// As CRLs anexadas ao `SignedData`. Formatos que nao sejam um
/// `CertificateList` X.509 sao ignorados — nao ha nada de util a fazer com
/// eles, e ignora-los nao e silencioso: se a revogacao nao puder ser
/// concluida, o passo seguinte falha a dizer que nao havia CRL.
/// As extensões do `TSTInfo` chegam como um `Any` opaco. Descodifica-se o
/// suficiente para ver a criticidade de cada uma.
fn verificar_extensoes_tstinfo(exts: &der::Any) -> Result<(), CompError> {
    let der_bytes = exts
        .to_der()
        .map_err(|e| verify_err(format!("extensões do TSTInfo não recodificam: {e}")))?;
    let lista = x509_cert::ext::Extensions::from_der(&der_bytes)
        .map_err(|e| verify_err(format!("extensões do TSTInfo inválidas: {e}")))?;
    for ext in lista.iter() {
        if ext.critical {
            return Err(verify_err(format!(
                "TSTInfo com a extensão crítica {} que este verificador não processa: uma                  instrução crítica que não se sabe cumprir recusa-se, não se ignora",
                ext.extn_id
            )));
        }
    }
    Ok(())
}

fn crls_embutidas(signed: &cms::signed_data::SignedData) -> Vec<x509_cert::crl::CertificateList> {
    let Some(escolhas) = signed.crls.as_ref() else {
        return Vec::new();
    };
    escolhas
        .0
        .iter()
        .filter_map(|e| match e {
            cms::revocation::RevocationInfoChoice::Crl(c) => Some(c.clone()),
            _ => None,
        })
        .collect()
}

fn certificados_de(
    signed: &cms::signed_data::SignedData,
    max: usize,
) -> Result<Vec<Certificate>, CompError> {
    let set = signed
        .certificates
        .as_ref()
        .ok_or_else(|| verify_err("SignedData sem certificados: nada para ancorar".into()))?;
    if set.0.len() > max {
        return Err(verify_err(format!(
            "token com {} certificados acima do tecto de {max}: a construção da cadeia percorre              o conjunto a cada elo, e o tamanho em bytes não é travão suficiente",
            set.0.len()
        )));
    }
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

/// RFC 5652 §5.3 — `contentType` e `messageDigest` têm de ter **exactamente
/// um** valor. Um atributo com dois, em que o primeiro está certo e o segundo
/// não, passava: só o primeiro era examinado.
fn valor_unico<'a>(
    attr: &'a x509_cert::attr::Attribute,
    nome: &str,
) -> Result<&'a der::Any, CompError> {
    if attr.values.len() != 1 {
        return Err(verify_err(format!(
            "atributo assinado `{nome}` com {} valores: a RFC 5652 §5.3 exige exactamente um,              e examinar só o primeiro deixaria o segundo dizer outra coisa",
            attr.values.len()
        )));
    }
    attr.values
        .get(0)
        .ok_or_else(|| verify_err(format!("{nome} sem valor")))
}

fn verificar_atributos(
    attrs: &cms::signed_data::SignedAttributes,
    tst_bytes: &[u8],
    digest: crate::algoritmos::Digest,
) -> Result<(), CompError> {
    let mut viu_content_type = false;
    let mut viu_message_digest = false;
    for attr in attrs.iter() {
        if attr.oid == OID_ATTR_CONTENT_TYPE {
            let valor = valor_unico(attr, "contentType")?;
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
            let valor = valor_unico(attr, "messageDigest")?;
            let declarado = valor
                .decode_as::<OctetString>()
                .map_err(|e| verify_err(format!("messageDigest inválido: {e}")))?;
            // O digest vem do `digestAlgorithm` do SignerInfo, não fixado em
            // SHA-256. Uma ACT que assine os signedAttrs sobre SHA-512 emite um
            // `messageDigest` de 64 bytes, e compará-lo com um SHA-256 falharia
            // sempre — com uma mensagem a culpar o conteúdo do token.
            if declarado.as_bytes() != digest.digerir(tst_bytes) {
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
    alg: &x509_cert::spki::AlgorithmIdentifierOwned,
    mensagem: &[u8],
    assinatura: &[u8],
    politica: &crate::algoritmos::PoliticaAlgoritmos,
) -> Result<(), CompError> {
    crate::algoritmos::verificar(cert, alg, mensagem, assinatura, politica)
}

fn verificar_emissao(
    filho: &Certificate,
    emissor: &Certificate,
    politica: &crate::algoritmos::PoliticaAlgoritmos,
) -> Result<(), CompError> {
    let tbs = filho
        .tbs_certificate
        .to_der()
        .map_err(|e| verify_err(format!("tbsCertificate não codifica: {e}")))?;
    let assinatura = filho
        .signature
        .as_bytes()
        .ok_or_else(|| verify_err("assinatura do certificado não alinhada em bytes".into()))?;
    // §4.1.1.2 — o algoritmo que escolhe o verificador vinha do campo de FORA
    // da assinatura, que ninguém assina. Comparar com o de dentro é o que
    // impede que ele seja trocado sem invalidar nada.
    crate::algoritmos::coerencia_de_algoritmo(filho)?;
    verificar_assinatura(
        emissor,
        &filho.signature_algorithm,
        &tbs,
        assinatura,
        politica,
    )
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
    // §4.2.1.3 — `basicConstraints.cA` diz que o certificado é de uma AC;
    // `keyUsage.keyCertSign` diz que ESTA chave assina certificados. São duas
    // afirmações diferentes e a segunda não era lida.
    crate::constraints::exigir_key_usage(
        cert,
        x509_cert::ext::pkix::KeyUsages::KeyCertSign,
        "emitir certificados (keyCertSign)",
    )?;
    Ok(())
}

/// RFC 3161 §2.3 — o certificado da ACT tem de declarar o carimbo como o
/// **único** propósito, e declará-lo como crítico.
///
/// A norma não deixa margem: *"MUST contain only one instance of the extended
/// key usage field extension ... with KeyPurposeID having value:
/// id-kp-timeStamping. This extension MUST be critical."* É o mecanismo que
/// obriga a ACT a reservar uma chave só para carimbar.
///
/// Aceitar um EKU não crítico e acompanhado de outros propósitos — o que se
/// fazia — desfaz essa reserva: um certificado emitido para TLS que por acaso
/// também liste `id-kp-timeStamping` passava a poder assinar carimbos, e a
/// chave que serve um servidor web passava a servir evidência legal.
fn verificar_eku_timestamping(
    cert: &Certificate,
    estrito: bool,
) -> Result<(), CompError> {
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
    if !estrito {
        return Ok(());
    }
    if !ext.critical {
        return Err(verify_err(
            "extendedKeyUsage não é crítico: a RFC 3161 §2.3 exige que seja, porque é assim que              a restrição vincula quem processa o certificado. Para aceitar uma ACT não conforme,              desligue `eku_estrito` — conscientemente"
                .into(),
        ));
    }
    if eku.0.len() != 1 {
        let outros: Vec<String> = eku
            .0
            .iter()
            .filter(|o| **o != OID_KP_TIME_STAMPING)
            .map(|o| o.to_string())
            .collect();
        return Err(verify_err(format!(
            "extendedKeyUsage declara mais propósitos além do carimbo ({}): a RFC 3161 §2.3              exige uma chave RESERVADA para carimbar, e uma chave que serve para outra coisa              não está reservada",
            outros.join(", ")
        )));
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




#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_pki::{self, OpcoesToken};
    use crate::trust_store::{sha256, TrustStore};

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
                motivo_com_etiqueta_errada: false,
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
                motivo_com_etiqueta_errada: false,
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
                motivo_com_etiqueta_errada: false,
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
            ..Default::default()
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

    // -----------------------------------------------------------------
    // §9 — algoritmos. Antes desta ronda o unico RSA aceite era
    // sha256WithRSAEncryption, e a DOC-ICP-01.01 impoe SHA-512 a AC Raiz: uma
    // hierarquia ICP-Brasil real NAO encadeava. E o ramo RSA nunca era corrido
    // por teste nenhum, porque toda a PKI sintetica era ECDSA.
    // -----------------------------------------------------------------

    fn verificador_rsa(chain: &test_pki::Chain) -> IcpBrasilTimestampVerifier {
        let mut store = TrustStore::new();
        store.add_pem_or_der("raiz", &chain.root_der).unwrap();
        IcpBrasilTimestampVerifier::new(store, TimestampValidationPolicy::default())
    }

    /// O caso que a auditoria apanhou: uma cadeia assinada em SHA-512 — o que a
    /// AC Raiz da ICP-Brasil usa — tem de encadear.
    #[test]
    fn uma_cadeia_rsa_sha512_encadeia() {
        let chain = test_pki::chain_rsa(test_pki::DigestRsa::Sha512, false);
        let token = test_pki::token_de_teste(
            &chain,
            &imprint(),
            AGORA_S - 60,
            None,
            OpcoesToken::default(),
        );
        let v = verificador_rsa(&chain)
            .verify(&token, &imprint(), None, AGORA_MS)
            .expect("SHA-512 e o que a AC Raiz da ICP-Brasil usa");
        assert_eq!(v.gen_unix_ms, (AGORA_S - 60) * 1_000);
        assert!(v.signer_subject.contains("ACT RSA"));
    }

    #[test]
    fn uma_cadeia_rsa_sha384_encadeia() {
        let chain = test_pki::chain_rsa(test_pki::DigestRsa::Sha384, false);
        let token = test_pki::token_de_teste(
            &chain,
            &imprint(),
            AGORA_S - 60,
            None,
            OpcoesToken::default(),
        );
        verificador_rsa(&chain)
            .verify(&token, &imprint(), None, AGORA_MS)
            .expect("SHA-384 tem de encadear");
    }

    #[test]
    fn uma_cadeia_rsa_sha256_encadeia() {
        let chain = test_pki::chain_rsa(test_pki::DigestRsa::Sha256, false);
        let token = test_pki::token_de_teste(
            &chain,
            &imprint(),
            AGORA_S - 60,
            None,
            OpcoesToken::default(),
        );
        verificador_rsa(&chain)
            .verify(&token, &imprint(), None, AGORA_MS)
            .expect("SHA-256 continua a encadear");
    }

    /// A assinatura RSA e mesmo verificada, e nao apenas descodificada.
    #[test]
    fn uma_assinatura_rsa_de_outra_chave_nao_passa() {
        let chain = test_pki::chain_rsa(test_pki::DigestRsa::Sha512, false);
        let token = test_pki::token_de_teste(
            &chain,
            &imprint(),
            AGORA_S - 60,
            None,
            OpcoesToken {
                assinar_com_chave_errada: true,
                ..Default::default()
            },
        );
        let erro = verificador_rsa(&chain)
            .verify(&token, &imprint(), None, AGORA_MS)
            .unwrap_err();
        assert!(erro.to_string().contains("não confere"), "{erro}");
    }

    /// Um modulo de 1024 bits fatoriza-se. A caixa `rsa` so impoe um MAXIMO;
    /// o piso e desta politica, e aplica-se ao EMISSOR, nao so a folha.
    #[test]
    fn uma_raiz_rsa_de_1024_bits_e_recusada_pelo_piso_da_politica() {
        let chain = test_pki::chain_rsa(test_pki::DigestRsa::Sha256, true);
        let token = test_pki::token_de_teste(
            &chain,
            &imprint(),
            AGORA_S - 60,
            None,
            OpcoesToken::default(),
        );
        let erro = verificador_rsa(&chain)
            .verify(&token, &imprint(), None, AGORA_MS)
            .unwrap_err();
        assert!(
            erro.to_string().contains("1024") || erro.to_string().contains("âncora"),
            "{erro}"
        );

        // E passa quando o operador DECLARA que aceita esta fraqueza.
        let mut store = TrustStore::new();
        store.add_pem_or_der("raiz", &chain.root_der).unwrap();
        let politica = TimestampValidationPolicy {
            algoritmos: crate::algoritmos::PoliticaAlgoritmos { min_rsa_bits: 1024 },
            ..Default::default()
        };
        IcpBrasilTimestampVerifier::new(store, politica)
            .verify(&token, &imprint(), None, AGORA_MS)
            .expect("com o piso declarado a 1024 a cadeia fecha");
    }

    /// §4.1.1.2 — o algoritmo que escolhe o verificador vinha do campo de FORA
    /// da assinatura, que ninguem assina.
    #[test]
    fn um_certificado_com_algoritmos_divergentes_dentro_e_fora_e_recusado() {
        use der::{Decode, Encode};
        let chain = test_pki::chain_de_teste();
        // Troca o `signatureAlgorithm` exterior da folha, deixando o
        // `tbsCertificate.signature` intacto. A assinatura continua valida
        // sobre o tbs — e por isso e que so a COMPARACAO apanha isto.
        let mut folha = chain.tsa.clone();
        folha.signature_algorithm.oid =
            der::asn1::ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");
        let der_alterado = folha.to_der().unwrap();
        let relido = x509_cert::Certificate::from_der(&der_alterado).unwrap();
        let erro = crate::algoritmos::coerencia_de_algoritmo(&relido).unwrap_err();
        assert!(erro.to_string().contains("4.1.1.2") || erro.to_string().contains("iguais"),
            "{erro}");
    }

    /// Um algoritmo desconhecido e recusado COM o OID, e nao ignorado.
    #[test]
    fn um_algoritmo_desconhecido_e_recusado_com_o_oid_no_erro() {
        use crate::algoritmos::{verificar, PoliticaAlgoritmos};
        let chain = test_pki::chain_de_teste();
        let alg = x509_cert::spki::AlgorithmIdentifierOwned {
            // md5WithRSAEncryption — precisamente o que nunca deve passar.
            oid: der::asn1::ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.4"),
            parameters: None,
        };
        let erro = verificar(
            &chain.tsa,
            &alg,
            b"mensagem",
            &[0u8; 64],
            &PoliticaAlgoritmos::default(),
        )
        .unwrap_err();
        assert!(erro.to_string().contains("1.2.840.113549.1.1.4"), "{erro}");
        assert!(erro.to_string().contains("não suportado"), "{erro}");
    }

    // -----------------------------------------------------------------
    // §5.2/§6.3 — o que a auditoria de 2026-08-31 apanhou no codigo de CRLs.
    // -----------------------------------------------------------------

    fn verificador_com_crls(
        chain: &test_pki::Chain,
        crls_der: &[Vec<u8>],
        politica: crate::crl::CrlPolicy,
    ) -> IcpBrasilTimestampVerifier {
        let mut store = TrustStore::new();
        store.add_pem_or_der("raiz", &chain.root_der).unwrap();
        let mut crls = crate::crl::CrlStore::new();
        for c in crls_der {
            crls.add_pem_or_der(c).unwrap();
        }
        IcpBrasilTimestampVerifier::new(store, TimestampValidationPolicy::default())
            .with_crls(crls, politica)
    }

    /// O buraco: consultava-se **a primeira** CRL utilizavel do emissor. Com
    /// duas na pasta, o ficheiro que o `read_dir` devolvesse primeiro passava a
    /// ser a politica de revogacao do orgao.
    #[test]
    fn a_revogacao_e_procurada_em_todas_as_crls_do_emissor_nao_so_na_primeira() {
        let chain = test_pki::chain_de_teste();
        let limpa = crl_da_raiz(&chain, vec![]);
        let com_revogacao = crl_da_raiz(
            &chain,
            vec![test_pki::Revogacao {
                serial: chain.tsa.tbs_certificate.serial_number.clone(),
                quando_s: AGORA_S - 600,
                motivo: None,
                motivo_com_etiqueta_errada: false,
            }],
        );
        // A limpa vem primeiro, de proposito.
        let erro = verificador_com_crls(&chain, &[limpa, com_revogacao], Default::default())
            .verify(&token_padrao(&chain), &imprint(), None, AGORA_MS)
            .unwrap_err();
        assert!(
            erro.to_string().contains("já estava revogado"),
            "uma CRL limpa nao pode encobrir a revogacao declarada noutra: {erro}"
        );
    }

    /// §5.2.4 — uma delta CRL lista so o que MUDOU. Usa-la como completa e
    /// responder "nao revogado" a tudo o que foi revogado antes dela.
    #[test]
    fn uma_delta_crl_nao_e_aceite_como_completa() {
        let chain = test_pki::chain_de_teste();
        let delta = test_pki::crl_com(
            &chain.root,
            &chain.root_key,
            CRL_INICIO_S,
            Some(CRL_FIM_S),
            vec![],
            true,
        );
        let erro = verificador_com_crls(&chain, &[delta], Default::default())
            .verify(&token_padrao(&chain), &imprint(), None, AGORA_MS)
            .unwrap_err();
        assert!(erro.to_string().contains("delta"), "{erro}");
    }

    /// Sem `nextUpdate` a CRL escapava por completo a politica de frescura: uma
    /// de 2019 respondia com a mesma autoridade de uma de hoje.
    #[test]
    fn uma_crl_sem_next_update_e_recusada_por_nao_declarar_ate_quando_vale() {
        let chain = test_pki::chain_de_teste();
        let sem_fim = test_pki::crl_de_teste(
            &chain.root,
            &chain.root_key,
            CRL_INICIO_S,
            None,
            vec![],
        );
        let erro = verificador_com_crls(&chain, std::slice::from_ref(&sem_fim), Default::default())
            .verify(&token_padrao(&chain), &imprint(), None, AGORA_MS)
            .unwrap_err();
        assert!(erro.to_string().contains("nextUpdate"), "{erro}");

        // E aceite quando o operador DECLARA que aceita CRLs sem prazo.
        let permissiva = crate::crl::CrlPolicy {
            exigir_next_update: false,
            ..Default::default()
        };
        let v = verificador_com_crls(&chain, &[sem_fim], permissiva)
            .verify(&token_padrao(&chain), &imprint(), None, AGORA_MS)
            .expect("com a exigencia desligada a CRL serve");
        assert!(v.revocation_checked);
    }

    /// Ler o ultimo octeto sem confirmar a etiqueta aceitaria um OCTET STRING
    /// cujo ultimo byte calhasse ser 1 e trata-lo-ia como `keyCompromise`.
    #[test]
    fn um_reason_code_com_etiqueta_errada_e_recusado_em_vez_de_interpretado() {
        let chain = test_pki::chain_de_teste();
        let crl = crl_da_raiz(
            &chain,
            vec![test_pki::Revogacao {
                serial: chain.tsa.tbs_certificate.serial_number.clone(),
                quando_s: AGORA_S - 10,
                motivo: Some(1),
                motivo_com_etiqueta_errada: true,
            }],
        );
        let erro = verificador_com_crls(&chain, &[crl], Default::default())
            .verify(&token_padrao(&chain), &imprint(), None, AGORA_MS)
            .unwrap_err();
        assert!(erro.to_string().contains("ENUMERATED"), "{erro}");
    }

    /// A janela de confianca chega ao resultado: um relatorio construido a
    /// partir disto pode dizer ate quando a resposta de revogacao vale.
    #[test]
    fn a_janela_de_validade_da_crl_chega_ao_resultado() {
        let chain = test_pki::chain_de_teste();
        let crl = crl_da_raiz(&chain, vec![]);
        let v = verificador_com_crls(&chain, &[crl], Default::default())
            .verify(&token_padrao(&chain), &imprint(), None, AGORA_MS)
            .unwrap();
        assert!(v.revocation_checked);
        assert_eq!(
            v.revocation_valid_until_ms,
            Some(CRL_FIM_S * 1_000),
            "sem isto, quem le o resultado nao sabe se a informacao e de hoje ou de 2019"
        );
    }

    // -----------------------------------------------------------------
    // RFC 5280 §6.1.4 — as restricoes que o emissor declara. Ate esta ronda
    // eram lidas por ninguem: um certificado com nameConstraints,
    // pathLenConstraint ou keyUsage era aceite como se elas nao existissem.
    // -----------------------------------------------------------------

    /// Monta o token de uma cadeia de tres niveis: a folha assina, o intermedio
    /// viaja no token e a raiz fica no trust store.
    fn token_e_verificador(
        c: &test_pki::CadeiaTresNiveis,
        policy: TimestampValidationPolicy,
    ) -> (Vec<u8>, IcpBrasilTimestampVerifier) {
        let token = test_pki::token_de_teste(
            &c.chain,
            &imprint(),
            AGORA_S - 60,
            None,
            OpcoesToken {
                certs_extra: vec![c.root.clone()],
                ..Default::default()
            },
        );
        let mut store = TrustStore::new();
        store.add_pem_or_der("raiz", &c.root_der).unwrap();
        (token, IcpBrasilTimestampVerifier::new(store, policy))
    }

    /// A cadeia de tres niveis fecha quando nada a restringe — a base contra a
    /// qual os testes seguintes provam que a restricao e que os recusa.
    #[test]
    fn uma_cadeia_de_tres_niveis_sem_restricoes_fecha() {
        let c = test_pki::cadeia_tres_niveis(Default::default());
        let (token, v) = token_e_verificador(&c, TimestampValidationPolicy::default());
        let r = v
            .verify(&token, &imprint(), None, AGORA_MS)
            .expect("raiz -> AC -> ACT e a topologia da ICP-Brasil");
        assert_eq!(r.chain_len, 2, "folha + intermedio, ancorados na raiz");
    }

    /// §4.2.1.10 — uma AC restringida pela raiz nao pode emitir fora da sua
    /// subarvore. Era o buraco: a restricao existe para limitar o estrago de
    /// uma AC comprometida, e era como se nao estivesse la.
    #[test]
    fn uma_ac_restringida_nao_emite_fora_da_sua_subarvore() {
        let c = test_pki::cadeia_tres_niveis(test_pki::OpcoesRestricoes {
            raiz_permite_dn: Some("O=ICP-Brasil".into()),
            // Nem o intermedio nem a folha caem sob `O=ICP-Brasil`.
            ..Default::default()
        });
        let (token, v) = token_e_verificador(&c, TimestampValidationPolicy::default());
        let erro = v.verify(&token, &imprint(), None, AGORA_MS).unwrap_err();
        assert!(
            erro.to_string().contains("nameConstraints"),
            "a restricao da raiz tem de recusar: {erro}"
        );
    }

    /// A outra metade: um nome DENTRO da subarvore passa. Sem este teste, uma
    /// implementacao que recusasse tudo passaria o teste anterior.
    #[test]
    fn um_nome_dentro_da_subarvore_permitida_passa() {
        let c = test_pki::cadeia_tres_niveis(test_pki::OpcoesRestricoes {
            raiz_permite_dn: Some("O=ICP-Brasil".into()),
            sub_dn: Some("CN=AC Intermedia,O=ICP-Brasil".into()),
            folha_dn: Some("CN=ACT de Teste,O=ICP-Brasil".into()),
            ..Default::default()
        });
        let (token, v) = token_e_verificador(&c, TimestampValidationPolicy::default());
        v.verify(&token, &imprint(), None, AGORA_MS)
            .expect("nomes sob a subarvore permitida tem de passar");
    }

    /// Uma subarvore EXCLUIDA recusa mesmo estando dentro das permitidas.
    #[test]
    fn uma_subarvore_excluida_recusa() {
        let c = test_pki::cadeia_tres_niveis(test_pki::OpcoesRestricoes {
            raiz_exclui_dn: Some("O=Proibido".into()),
            sub_dn: Some("CN=AC Intermedia,O=Proibido".into()),
            folha_dn: Some("CN=ACT,O=Proibido".into()),
            ..Default::default()
        });
        let (token, v) = token_e_verificador(&c, TimestampValidationPolicy::default());
        let erro = v.verify(&token, &imprint(), None, AGORA_MS).unwrap_err();
        assert!(erro.to_string().contains("excludedSubtree"), "{erro}");
    }

    /// §4.2.1.9 — uma raiz com `pathLenConstraint: 0` nao autoriza nenhum
    /// intermedio abaixo de si. O campo era descodificado e deitado fora.
    #[test]
    fn path_len_zero_na_raiz_recusa_um_intermedio() {
        let c = test_pki::cadeia_tres_niveis(test_pki::OpcoesRestricoes {
            raiz_path_len: Some(0),
            ..Default::default()
        });
        let (token, v) = token_e_verificador(&c, TimestampValidationPolicy::default());
        let erro = v.verify(&token, &imprint(), None, AGORA_MS).unwrap_err();
        assert!(erro.to_string().contains("pathLenConstraint"), "{erro}");
    }

    /// E `pathLenConstraint: 1` autoriza exactamente um.
    #[test]
    fn path_len_um_na_raiz_autoriza_um_intermedio() {
        let c = test_pki::cadeia_tres_niveis(test_pki::OpcoesRestricoes {
            raiz_path_len: Some(1),
            ..Default::default()
        });
        let (token, v) = token_e_verificador(&c, TimestampValidationPolicy::default());
        v.verify(&token, &imprint(), None, AGORA_MS)
            .expect("um intermedio cabe em pathLen=1");
    }

    /// §6.1.4(f) — critica significa "se nao percebes isto, nao uses este
    /// certificado". Ignora-la transforma um mecanismo de seguranca no oposto.
    #[test]
    fn uma_extensao_critica_desconhecida_faz_recusar() {
        let c = test_pki::cadeia_tres_niveis(test_pki::OpcoesRestricoes {
            critica_desconhecida_na_folha: true,
            ..Default::default()
        });
        let (token, v) = token_e_verificador(&c, TimestampValidationPolicy::default());
        let erro = v.verify(&token, &imprint(), None, AGORA_MS).unwrap_err();
        assert!(erro.to_string().contains("1.3.6.1.4.1.99999.1"), "{erro}");
        assert!(erro.to_string().contains("crítica"), "{erro}");

        // E passa quando o operador DECLARA que a leu e a tolera. A escotilha e
        // por OID, nao um interruptor geral: tolerar "todas" seria voltar ao
        // comportamento que se corrigiu.
        let mut toleradas = std::collections::BTreeSet::new();
        toleradas.insert(ObjectIdentifier::new_unwrap("1.3.6.1.4.1.99999.1"));
        let politica = TimestampValidationPolicy {
            restricoes: crate::constraints::RestricoesPolicy {
                criticas_toleradas: toleradas,
            },
            ..Default::default()
        };
        let (token2, v2) = token_e_verificador(&c, politica);
        v2.verify(&token2, &imprint(), None, AGORA_MS)
            .expect("com o OID declarado a extensao e tolerada");
    }

    // -----------------------------------------------------------------
    // RFC 3161 §2.4.2 / RFC 5652 §5.3 — o que um token REAL traz e que a PKI
    // sintetica nunca produzia.
    // -----------------------------------------------------------------

    /// A RFC 3161 permite EXPLICITAMENTE fraccao de segundo no `genTime`. O
    /// `GeneralizedTime` do `der` e DER-estrito e recusava-a: um token de uma
    /// ACT que declarasse precisao de milissegundos nem chegava a descodificar,
    /// e o erro falava de ASN.1 malformado.
    #[test]
    fn um_gen_time_com_fraccao_de_segundo_descodifica_e_conta_os_milissegundos() {
        let chain = test_pki::chain_de_teste();
        let token = test_pki::token_de_teste(
            &chain,
            &imprint(),
            AGORA_S - 60,
            None,
            OpcoesToken {
                gen_time_milis: Some(500),
                ..Default::default()
            },
        );
        let v = verificador(&chain)
            .verify(&token, &imprint(), None, AGORA_MS)
            .expect("uma ACT real declara precisao em milissegundos");
        assert_eq!(
            v.gen_unix_ms,
            (AGORA_S - 60) * 1_000 + 500,
            "a fraccao e a hora que a autoridade afirmou; descarta-la trunca o facto"
        );
    }

    /// O `genTime` sem fraccao continua a funcionar — a forma que a PKI
    /// sintetica sempre produziu.
    #[test]
    fn um_gen_time_sem_fraccao_continua_a_funcionar() {
        let chain = test_pki::chain_de_teste();
        let v = verificador(&chain)
            .verify(&token_padrao(&chain), &imprint(), None, AGORA_MS)
            .unwrap();
        assert_eq!(v.gen_unix_ms, (AGORA_S - 60) * 1_000);
    }

    /// A ida e volta do `GenTime` sobre instantes conhecidos, incluindo um ano
    /// bissexto e a fronteira de mes.
    #[test]
    fn o_gen_time_converte_instantes_conhecidos() {
        // 2020-02-29T12:00:00Z = 1582977600
        let t = crate::icp::GenTime::nova(1_582_977_600, None).unwrap();
        assert_eq!(t.unix_ms(), 1_582_977_600_000);
        // 2000-03-01T00:00:00Z = 951868800
        let t2 = crate::icp::GenTime::nova(951_868_800, Some(125)).unwrap();
        assert_eq!(t2.unix_ms(), 951_868_800_125);
        // A epoca.
        assert_eq!(crate::icp::GenTime::nova(0, None).unwrap().unix_ms(), 0);
    }

    /// §5.3 — um atributo com dois valores, o primeiro certo e o segundo nao,
    /// passava: so o primeiro era examinado.
    #[test]
    fn um_atributo_assinado_com_dois_valores_e_recusado() {
        let chain = test_pki::chain_de_teste();
        let token = test_pki::token_de_teste(
            &chain,
            &imprint(),
            AGORA_S - 60,
            None,
            OpcoesToken {
                content_type_com_dois_valores: true,
                ..Default::default()
            },
        );
        let erro = verificador(&chain)
            .verify(&token, &imprint(), None, AGORA_MS)
            .unwrap_err();
        assert!(erro.to_string().contains("2 valores"), "{erro}");
    }

    /// O `messageDigest` e comparado com o digest que o SignerInfo DECLARA, e
    /// nao com SHA-256 fixado no codigo.
    #[test]
    fn o_message_digest_usa_o_digest_declarado_pelo_signer_info() {
        let chain = test_pki::chain_de_teste();
        let token = test_pki::token_de_teste(
            &chain,
            &imprint(),
            AGORA_S - 60,
            None,
            OpcoesToken {
                digest_attrs_sha512: true,
                ..Default::default()
            },
        );
        verificador(&chain)
            .verify(&token, &imprint(), None, AGORA_MS)
            .expect("signedAttrs sobre SHA-512 sao legitimos e tem de passar");
    }

    /// Um `digestAlgorithm` que nao sabemos calcular e recusado com o OID, e
    /// nao ignorado.
    #[test]
    fn um_digest_algorithm_desconhecido_e_recusado_com_o_oid() {
        let chain = test_pki::chain_de_teste();
        let token = test_pki::token_de_teste(
            &chain,
            &imprint(),
            AGORA_S - 60,
            None,
            OpcoesToken {
                digest_attrs_desconhecido: true,
                ..Default::default()
            },
        );
        let erro = verificador(&chain)
            .verify(&token, &imprint(), None, AGORA_MS)
            .unwrap_err();
        assert!(erro.to_string().contains("digestAlgorithm"), "{erro}");
    }

    // -----------------------------------------------------------------
    // RFC 3161 §2.3 — a chave da ACT tem de estar RESERVADA para carimbar.
    // -----------------------------------------------------------------

    /// Um certificado emitido para TLS que por acaso tambem liste
    /// `id-kp-timeStamping` passava a poder assinar carimbos: a chave que serve
    /// um servidor web servia evidencia legal.
    #[test]
    fn um_eku_com_outro_proposito_alem_do_carimbo_e_recusado() {
        let c = test_pki::cadeia_tres_niveis(test_pki::OpcoesRestricoes {
            folha_eku_com_outro_proposito: true,
            ..Default::default()
        });
        let (token, v) = token_e_verificador(&c, TimestampValidationPolicy::default());
        let erro = v.verify(&token, &imprint(), None, AGORA_MS).unwrap_err();
        assert!(erro.to_string().contains("1.3.6.1.5.5.7.3.1"), "{erro}");
        assert!(erro.to_string().contains("RESERVADA"), "{erro}");
    }

    /// A criticidade e o que vincula quem processa o certificado. Sem ela, a
    /// restricao e uma sugestao.
    #[test]
    fn um_eku_nao_critico_e_recusado_e_a_escotilha_e_declarada() {
        let c = test_pki::cadeia_tres_niveis(test_pki::OpcoesRestricoes {
            folha_eku_nao_critico: true,
            ..Default::default()
        });
        let (token, v) = token_e_verificador(&c, TimestampValidationPolicy::default());
        let erro = v.verify(&token, &imprint(), None, AGORA_MS).unwrap_err();
        assert!(erro.to_string().contains("não é crítico"), "{erro}");

        // Uma ACT nao conforme e aceite so quando o operador o DECLARA.
        let politica = TimestampValidationPolicy {
            eku_estrito: false,
            ..Default::default()
        };
        let (token2, v2) = token_e_verificador(&c, politica);
        v2.verify(&token2, &imprint(), None, AGORA_MS)
            .expect("com eku_estrito desligado a ACT nao conforme passa");
    }

    /// O `messageImprint` pode ser SHA-384 ou SHA-512. Fixa-lo em SHA-256
    /// recusava um carimbo legitimo e impedia inspeccionar um `.tst` de
    /// terceiros — que e para o que o `inspect` existe.
    #[test]
    fn um_imprint_sha512_e_aceite_e_confrontado_pelo_tamanho_certo() {
        use crate::algoritmos::Digest;
        let chain = test_pki::chain_de_teste();
        let conteudo = b"o conteudo a carimbar";
        let imp512 = Digest::Sha512.digerir(conteudo);
        let token = test_pki::token_de_teste_com_imprint(
            &chain,
            &imp512,
            crate::algoritmos::OID_SHA512,
            AGORA_S - 60,
        );
        let (v, encontrado) = verificador(&chain)
            .inspect(&token, AGORA_MS)
            .expect("SHA-512 no imprint e legitimo");
        assert_eq!(encontrado, imp512);
        assert_eq!(v.gen_unix_ms, (AGORA_S - 60) * 1_000);
    }

    /// Um imprint cujo tamanho nao bate com o algoritmo declarado e malformado.
    #[test]
    fn um_imprint_com_tamanho_errado_para_o_algoritmo_e_recusado() {
        let chain = test_pki::chain_de_teste();
        let token = test_pki::token_de_teste_com_imprint(
            &chain,
            &[0u8; 20], // 20 bytes declarados como SHA-256
            crate::algoritmos::OID_SHA256,
            AGORA_S - 60,
        );
        let erro = verificador(&chain).inspect(&token, AGORA_MS).unwrap_err();
        assert!(erro.to_string().contains("em vez de 32"), "{erro}");
    }

    /// §5.1 — uma ACT que serve clientes em air-gap anexa a CRL ao proprio
    /// carimbo. Descarta-la era o que quebrava esse caso: a maquina sem rede
    /// tinha a informacao na mao e falhava por "nao ha CRL do emissor".
    #[test]
    fn uma_crl_embutida_no_token_e_usada_e_verificada() {
        let chain = test_pki::chain_de_teste();
        let crl = crl_da_raiz(&chain, vec![]);
        let token = test_pki::token_de_teste(
            &chain,
            &imprint(),
            AGORA_S - 60,
            None,
            OpcoesToken {
                crls_no_token: vec![crl],
                ..Default::default()
            },
        );
        // O trust store tem a ancora, e NENHUMA CRL instalada.
        let mut store = TrustStore::new();
        store.add_pem_or_der("raiz", &chain.root_der).unwrap();
        let v = IcpBrasilTimestampVerifier::new(store, TimestampValidationPolicy::default())
            .with_crls(crate::crl::CrlStore::new(), Default::default());
        let r = v
            .verify(&token, &imprint(), None, AGORA_MS)
            .expect("a CRL veio dentro do token");
        assert!(r.revocation_checked);
    }

    /// Usa-las NAO e confiar nelas: uma CRL forjada dentro do token nao passa a
    /// verificacao de assinatura, e o resultado e o mesmo de nao haver CRL.
    #[test]
    fn uma_crl_forjada_dentro_do_token_nao_conta() {
        let chain = test_pki::chain_de_teste();
        let impostor = test_pki::self_signed_root("Impostor");
        let crl_falsa = test_pki::crl_de_teste(
            &chain.root,
            &impostor.key,
            CRL_INICIO_S,
            Some(CRL_FIM_S),
            vec![],
        );
        let token = test_pki::token_de_teste(
            &chain,
            &imprint(),
            AGORA_S - 60,
            None,
            OpcoesToken {
                crls_no_token: vec![crl_falsa],
                ..Default::default()
            },
        );
        let mut store = TrustStore::new();
        store.add_pem_or_der("raiz", &chain.root_der).unwrap();
        let erro = IcpBrasilTimestampVerifier::new(store, TimestampValidationPolicy::default())
            .with_crls(crate::crl::CrlStore::new(), Default::default())
            .verify(&token, &imprint(), None, AGORA_MS)
            .unwrap_err();
        assert!(
            erro.to_string().contains("assinatura da CRL não confere"),
            "{erro}"
        );
    }

    /// Rollover de chave: durante a transicao a AC tem DOIS certificados com o
    /// mesmo sujeito e chaves diferentes, e um carimbo legitimo traz os dois.
    /// Escolher o primeiro e desistir fazia a cadeia falhar — com a mensagem
    /// "emissor desconhecido", que manda procurar o emissor que esta ali.
    #[test]
    fn dois_certificados_do_mesmo_emissor_nao_fazem_a_cadeia_desistir() {
        let c = test_pki::cadeia_tres_niveis(Default::default());
        let sosia = test_pki::sosia_do_intermedio(&c);
        // O conjunto do token e montado como [folha, chain.root, ...extras].
        // Para o sosia ser o PRIMEIRO candidato — que e o unico cenario em que
        // o backtracking se prova — ele tem de ocupar a posicao do emissor
        // imediato, e o intermedio bom vem nos extras.
        let mut baralhada = c.chain.clone();
        baralhada.root = sosia;
        let token = test_pki::token_de_teste(
            &baralhada,
            &imprint(),
            AGORA_S - 60,
            None,
            OpcoesToken {
                certs_extra: vec![c.sub.clone(), c.root.clone()],
                ..Default::default()
            },
        );
        let mut store = TrustStore::new();
        store.add_pem_or_der("raiz", &c.root_der).unwrap();
        let r = IcpBrasilTimestampVerifier::new(store, TimestampValidationPolicy::default())
            .verify(&token, &imprint(), None, AGORA_MS)
            .expect("com backtracking a cadeia fecha pelo candidato certo");
        assert_eq!(r.chain_len, 2);
    }

    /// A prova do backtracking, com a ORDEM do conjunto fixada: o candidato
    /// errado vem primeiro e a cadeia tem de fechar pelo segundo.
    ///
    /// Tem de ser aqui e nao num token: o `SET OF` do CMS e canonicamente
    /// ordenado, portanto quem monta um token nao escolhe a ordem — e um teste
    /// que nao escolhe a ordem nao prova backtracking nenhum. Escrevi um assim
    /// primeiro: passava, e a mutacao que remove o backtracking nao o derrubava.
    #[test]
    fn a_busca_tenta_o_segundo_candidato_quando_o_primeiro_nao_serve() {
        let c = test_pki::cadeia_tres_niveis(Default::default());
        let sosia = test_pki::sosia_do_intermedio(&c);
        let mut store = TrustStore::new();
        store.add_pem_or_der("raiz", &c.root_der).unwrap();
        let v = IcpBrasilTimestampVerifier::new(store, TimestampValidationPolicy::default());

        // O sosia tem o mesmo sujeito do intermedio bom e NAO encadeia ate a
        // ancora instalada. Vem primeiro, de proposito.
        let pool = vec![c.chain.tsa.clone(), sosia, c.sub.clone(), c.root.clone()];
        let cadeia = v
            .construir_cadeia(&c.chain.tsa, &pool)
            .expect("o segundo candidato serve");
        assert_eq!(cadeia.certs.len(), 2, "folha + intermedio bom");
        assert_eq!(
            cadeia.anchor_cert.tbs_certificate.subject,
            c.root.tbs_certificate.subject
        );
    }

    /// E quando NENHUM candidato serve, o erro diz o que falhou de facto em vez
    /// de "emissor desconhecido" — que era o que aparecia quando um elo era
    /// recusado por algoritmo.
    #[test]
    fn o_erro_da_cadeia_diz_a_causa_mais_proxima() {
        let chain = test_pki::chain_de_teste();
        let token = test_pki::token_de_teste(
            &chain,
            &imprint(),
            AGORA_S - 60,
            None,
            OpcoesToken::default(),
        );
        let mut store = TrustStore::new();
        store
            .add_pem_or_der("outra", &test_pki::self_signed_root("Outra").certificate_der)
            .unwrap();
        let erro = IcpBrasilTimestampVerifier::new(store, TimestampValidationPolicy::default())
            .verify(&token, &imprint(), None, AGORA_MS)
            .unwrap_err();
        assert!(erro.to_string().contains("âncora"), "{erro}");
    }

    /// §5.1 — o `digestAlgorithm` do SignerInfo tem de constar dos
    /// `digestAlgorithms` do envelope. A contradicao entre os dois e a marca de
    /// um token remontado.
    #[test]
    fn um_signer_info_que_contradiz_o_envelope_e_recusado() {
        let chain = test_pki::chain_de_teste();
        let token = test_pki::token_de_teste(
            &chain,
            &imprint(),
            AGORA_S - 60,
            None,
            OpcoesToken {
                envelope_declara_outro_digest: true,
                ..Default::default()
            },
        );
        let erro = verificador(&chain)
            .verify(&token, &imprint(), None, AGORA_MS)
            .unwrap_err();
        assert!(erro.to_string().contains("digestAlgorithms"), "{erro}");
    }
}

#[cfg(test)]
mod testes_inspect {
    use super::*;
    use crate::test_pki::{self, OpcoesToken};
    use crate::trust_store::{sha256, TrustStore};

    const AGORA_S: u64 = 1_760_000_000;

    /// `inspect` existe para pegar num `.tst` de uma ACT real e ver se este
    /// verificador o aceita, sem ter o documento original — e devolve o
    /// imprint para que quem reporte NAO possa calar que nada foi ligado.
    #[test]
    fn inspect_valida_a_cadeia_e_devolve_o_imprint_sem_o_ligar_a_nada() {
        let chain = test_pki::chain_de_teste();
        let esperado = sha256(b"o conteudo a carimbar");
        let token = test_pki::token_de_teste(
            &chain,
            &esperado,
            AGORA_S - 60,
            None,
            OpcoesToken::default(),
        );
        let mut store = TrustStore::new();
        store.add_pem_or_der("raiz", &chain.root_der).unwrap();
        let v = IcpBrasilTimestampVerifier::new(store, TimestampValidationPolicy::default());

        let (r, imprint) = v.inspect(&token, AGORA_S * 1_000).expect("token valido");
        assert_eq!(imprint, esperado.to_vec());
        assert!(r.signer_subject.contains("ACT de Teste"));
        assert_eq!(r.chain_len, 1);
    }

    /// E recusa o que tem de recusar: `inspect` nao e um atalho que salte a
    /// validacao da cadeia.
    #[test]
    fn inspect_recusa_uma_cadeia_que_nao_chega_a_uma_ancora() {
        let chain = test_pki::chain_de_teste();
        let token = test_pki::token_de_teste(
            &chain,
            &sha256(b"x"),
            AGORA_S - 60,
            None,
            OpcoesToken::default(),
        );
        let mut store = TrustStore::new();
        store
            .add_pem_or_der("outra", &test_pki::self_signed_root("Outra").certificate_der)
            .unwrap();
        let erro = IcpBrasilTimestampVerifier::new(store, TimestampValidationPolicy::default())
            .inspect(&token, AGORA_S * 1_000)
            .unwrap_err();
        assert!(erro.to_string().contains("âncora"), "{erro}");
    }
}
