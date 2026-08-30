//! RFC 3161 Time-Stamp Protocol — the *outbound* request structures.
//!
//! These are DER-encoded exactly as a homologated ACT (e.g. SERPRO, synced to
//! the Observatório Nacional atomic clock) expects. The response is a CMS
//! `TimeStampToken`; parsing + chain-validating that real token against
//! ICP-Brasil trust anchors is the production verifier (see `verify`), which
//! needs the órgão's trust roots and is staged after this milestone.

use der::asn1::{Null, ObjectIdentifier, OctetString};
use der::{Decode, Encode, Sequence};

/// SHA-256 (`id-sha256`, 2.16.840.1.101.3.4.2.1) — the digest algorithm we
/// send. blake3 is intentionally *not* used here: ACTs reject unregistered OIDs.
pub const OID_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1");

/// `AlgorithmIdentifier` with NULL parameters (the encoding ACTs expect for
/// SHA-256).
#[derive(Debug, Clone, PartialEq, Eq, Sequence)]
pub struct AlgorithmIdentifier {
    pub algorithm: ObjectIdentifier,
    #[asn1(optional = "true")]
    pub parameters: Option<Null>,
}

impl AlgorithmIdentifier {
    pub fn sha256() -> Self {
        Self {
            algorithm: OID_SHA256,
            parameters: Some(Null),
        }
    }
}

/// `MessageImprint ::= SEQUENCE { hashAlgorithm, hashedMessage OCTET STRING }`.
#[derive(Debug, Clone, PartialEq, Eq, Sequence)]
pub struct MessageImprint {
    pub hash_algorithm: AlgorithmIdentifier,
    pub hashed_message: OctetString,
}

impl MessageImprint {
    /// Build a SHA-256 imprint from a 32-byte digest.
    pub fn sha256(digest: &[u8; 32]) -> Result<Self, der::Error> {
        Ok(Self {
            hash_algorithm: AlgorithmIdentifier::sha256(),
            hashed_message: OctetString::new(digest.as_slice())?,
        })
    }

    /// The raw hashed message bytes.
    pub fn digest_bytes(&self) -> &[u8] {
        self.hashed_message.as_bytes()
    }
}

/// `TimeStampReq` (RFC 3161 §2.4.1). `certReq` is sent TRUE so the ACT returns
/// its signing certificate inside the token (needed for offline verification).
#[derive(Debug, Clone, PartialEq, Eq, Sequence)]
pub struct TimeStampReq {
    pub version: u8,
    pub message_imprint: MessageImprint,
    #[asn1(optional = "true")]
    pub req_policy: Option<ObjectIdentifier>,
    #[asn1(optional = "true")]
    pub nonce: Option<u64>,
    pub cert_req: bool,
}

impl TimeStampReq {
    /// Construct a v1 request for a SHA-256 imprint with the given anti-replay
    /// nonce.
    pub fn new(imprint: &[u8; 32], nonce: u64) -> Result<Self, der::Error> {
        Ok(Self {
            version: 1,
            message_imprint: MessageImprint::sha256(imprint)?,
            req_policy: None,
            nonce: Some(nonce),
            cert_req: true,
        })
    }

    /// DER bytes, ready to POST (`Content-Type: application/timestamp-query`).
    pub fn to_der_bytes(&self) -> Result<Vec<u8>, der::Error> {
        self.to_der()
    }

    /// Parse a DER request (used by an in-process TSA to read the imprint back).
    pub fn from_der_bytes(bytes: &[u8]) -> Result<Self, der::Error> {
        Self::from_der(bytes)
    }
}
// ---------------------------------------------------------------------------
// A RESPOSTA (RFC 3161 §2.4.2). Sem isto, o que ficava guardado como "token"
// era o corpo HTTP inteiro — uma `TimeStampResp`, não um `ContentInfo` — e o
// `PKIStatus` nunca era lido. Uma ACT que RECUSA emite `status=2` e nenhum
// token: essa recusa ficava persistida como se fosse evidência legal.
// ---------------------------------------------------------------------------

/// `PKIStatus` (RFC 3161 §2.4.2 / RFC 2510). Só `granted` e `grantedWithMods`
/// trazem um carimbo utilizável.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PkiStatus {
    Granted,
    GrantedWithMods,
    Rejection,
    Waiting,
    RevocationWarning,
    RevocationNotification,
    Unknown(u32),
}

impl PkiStatus {
    pub const fn from_u32(v: u32) -> Self {
        match v {
            0 => Self::Granted,
            1 => Self::GrantedWithMods,
            2 => Self::Rejection,
            3 => Self::Waiting,
            4 => Self::RevocationWarning,
            5 => Self::RevocationNotification,
            outro => Self::Unknown(outro),
        }
    }

    /// Descrição estável para auditoria.
    pub const fn label(self) -> &'static str {
        match self {
            Self::Granted => "granted",
            Self::GrantedWithMods => "grantedWithMods",
            Self::Rejection => "rejection",
            Self::Waiting => "waiting",
            Self::RevocationWarning => "revocationWarning",
            Self::RevocationNotification => "revocationNotification",
            Self::Unknown(_) => "desconhecido",
        }
    }
}

/// `PKIFreeText ::= SEQUENCE SIZE (1..MAX) OF UTF8String`.
///
/// O conteúdo fica por ler de propósito: é texto de diagnóstico da ACT, não um
/// facto em que se decida, e modelá-lo daria a impressão de que é de confiança.
///
/// O que NÃO pode ficar por fazer é prender o tipo à tag. Enquanto este campo
/// era um `der::asn1::Any`, decodificava-se com **qualquer** tag — e como é
/// opcional e vem antes do `failInfo`, engolia o `BIT STRING` do `failInfo`,
/// que ficava sempre `None`. O efeito era silencioso e do pior tipo: uma recusa
/// da ACT continuava a ser detectada pelo `status`, mas o motivo — o
/// `unacceptedPolicy` que diz ao operador o que corrigir — desaparecia.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PkiFreeText {
    /// Os octetos de valor, verbatim, para que um `to_der()` reproduza o que
    /// veio.
    raw: Vec<u8>,
}

impl der::FixedTag for PkiFreeText {
    const TAG: der::Tag = der::Tag::Sequence;
}

impl<'a> der::DecodeValue<'a> for PkiFreeText {
    fn decode_value<R: der::Reader<'a>>(
        reader: &mut R,
        header: der::Header,
    ) -> der::Result<Self> {
        Ok(Self {
            raw: reader.read_vec(header.length)?,
        })
    }
}

impl der::EncodeValue for PkiFreeText {
    fn value_len(&self) -> der::Result<der::Length> {
        der::Length::try_from(self.raw.len())
    }

    fn encode_value(&self, writer: &mut impl der::Writer) -> der::Result<()> {
        writer.write(&self.raw)
    }
}

/// `PKIStatusInfo ::= SEQUENCE { status PKIStatus, statusString PKIFreeText
/// OPTIONAL, failInfo PKIFailureInfo OPTIONAL }`.
#[derive(Debug, Clone, PartialEq, Eq, Sequence)]
pub struct PkiStatusInfo {
    pub status: u32,
    #[asn1(optional = "true")]
    pub status_string: Option<PkiFreeText>,
    #[asn1(optional = "true")]
    pub fail_info: Option<der::asn1::BitString>,
}

impl PkiStatusInfo {
    pub const fn status(&self) -> PkiStatus {
        PkiStatus::from_u32(self.status)
    }

    /// Os bits de `PKIFailureInfo` que a ACT acendeu, por nome. Entram na
    /// mensagem de erro porque um operador que vê `unacceptedPolicy` sabe
    /// exactamente o que corrigir; um que vê "recusado" não sabe nada.
    pub fn fail_info_labels(&self) -> Vec<&'static str> {
        const BITS: [(usize, &str); 8] = [
            (0, "badAlg"),
            (2, "badRequest"),
            (5, "badDataFormat"),
            (14, "timeNotAvailable"),
            (15, "unacceptedPolicy"),
            (16, "unacceptedExtension"),
            (17, "addInfoNotAvailable"),
            (25, "systemFailure"),
        ];
        let Some(bits) = &self.fail_info else {
            return Vec::new();
        };
        let octetos = bits.raw_bytes();
        BITS.iter()
            .filter(|(i, _)| {
                let byte = i / 8;
                byte < octetos.len() && (octetos[byte] >> (7 - (i % 8))) & 1 == 1
            })
            .map(|(_, nome)| *nome)
            .collect()
    }
}

/// `TimeStampResp ::= SEQUENCE { status PKIStatusInfo, timeStampToken
/// TimeStampToken OPTIONAL }`, onde `TimeStampToken` é um CMS `ContentInfo`.
#[derive(Debug, Clone, PartialEq, Eq, Sequence)]
pub struct TimeStampResp {
    pub status: PkiStatusInfo,
    #[asn1(optional = "true")]
    pub time_stamp_token: Option<der::asn1::Any>,
}

impl TimeStampResp {
    pub fn from_der_bytes(bytes: &[u8]) -> Result<Self, der::Error> {
        Self::from_der(bytes)
    }

    /// Os bytes DER do `TimeStampToken`, e só se a ACT o concedeu.
    ///
    /// Devolve `Err` — nunca `Ok(vazio)` — para qualquer estado que não seja
    /// `granted`/`grantedWithMods`. `revocationWarning` e
    /// `revocationNotification` são recusados apesar de a ACT poder anexar um
    /// token: significam que a chave da própria ACT está a ser revogada, e um
    /// carimbo emitido sob essa condição não é evidência que se queira citar.
    ///
    /// `grantedWithMods` é aceite porque tudo o que a ACT possa ter alterado e
    /// que importe — o imprint, o nonce, a política, o certificado — é
    /// reverificado a seguir pelo [`crate::icp::IcpBrasilTimestampVerifier`],
    /// que recusa se não bater. Aceitar aqui não é confiar na ACT; é adiar a
    /// decisão para quem a pode tomar com prova.
    pub fn granted_token(&self) -> Result<Vec<u8>, TimeStampRespError> {
        let estado = self.status.status();
        match estado {
            PkiStatus::Granted | PkiStatus::GrantedWithMods => {}
            _ => {
                return Err(TimeStampRespError::NaoConcedido {
                    status: estado,
                    motivos: self.status.fail_info_labels(),
                })
            }
        }
        let token = self
            .time_stamp_token
            .as_ref()
            .ok_or(TimeStampRespError::SemToken { status: estado })?;
        token.to_der().map_err(TimeStampRespError::Der)
    }
}

/// Porque é que uma resposta da ACT não produziu um carimbo.
#[derive(Debug)]
pub enum TimeStampRespError {
    /// A ACT respondeu, e recusou.
    NaoConcedido {
        status: PkiStatus,
        motivos: Vec<&'static str>,
    },
    /// Concedeu mas não anexou o token — resposta malformada.
    SemToken { status: PkiStatus },
    Der(der::Error),
}

impl std::fmt::Display for TimeStampRespError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NaoConcedido { status, motivos } => {
                write!(f, "a ACT recusou o carimbo: status={}", status.label())?;
                if let PkiStatus::Unknown(v) = status {
                    write!(f, "({v})")?;
                }
                if !motivos.is_empty() {
                    write!(f, " · failInfo={}", motivos.join(","))?;
                }
                Ok(())
            }
            Self::SemToken { status } => write!(
                f,
                "a ACT respondeu {} mas não anexou TimeStampToken: resposta malformada",
                status.label()
            ),
            Self::Der(e) => write!(f, "TimeStampResp não é DER válido: {e}"),
        }
    }
}

impl std::error::Error for TimeStampRespError {}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_der_roundtrips_and_carries_imprint() {
        let imprint = [0xABu8; 32];
        let req = TimeStampReq::new(&imprint, 0xDEAD_BEEF).unwrap();
        let der = req.to_der_bytes().unwrap();
        let back = TimeStampReq::from_der_bytes(&der).unwrap();
        assert_eq!(back.version, 1);
        assert_eq!(back.nonce, Some(0xDEAD_BEEF));
        assert!(back.cert_req);
        assert_eq!(back.message_imprint.digest_bytes(), &imprint[..]);
        assert_eq!(back.message_imprint.hash_algorithm.algorithm, OID_SHA256);
    }

    // -----------------------------------------------------------------
    // A resposta da ACT (§2.4.2). O que estes testes fixam é que uma RECUSA
    // nunca pode sair daqui como um carimbo — era assim que uma resposta
    // `status=2` acabava persistida no manifesto como evidência legal.
    // -----------------------------------------------------------------

    /// Constrói uma `TimeStampResp` com o estado dado e, opcionalmente, um
    /// token de brincar (um `SEQUENCE` vazio basta: o que se testa aqui é a
    /// decisão sobre o estado, não o conteúdo do token).
    fn resposta(status: u32, com_token: bool, fail_info: Option<&[u8]>) -> Vec<u8> {
        use der::asn1::{Any, BitString};
        use der::{Encode, Tag};

        let info = PkiStatusInfo {
            status,
            status_string: None,
            fail_info: fail_info.map(|b| BitString::from_bytes(b).expect("bitstring")),
        };
        let token = if com_token {
            // `SEQUENCE {}` — DER mínimo, chega para provar que o token é
            // devolvido tal e qual quando o estado o permite.
            Some(Any::new(Tag::Sequence, Vec::<u8>::new()).expect("any"))
        } else {
            None
        };
        TimeStampResp {
            status: info,
            time_stamp_token: token,
        }
        .to_der()
        .expect("resposta em DER")
    }

    #[test]
    fn granted_devolve_o_token_tal_e_qual() {
        let der = resposta(0, true, None);
        let resp = TimeStampResp::from_der_bytes(&der).unwrap();
        assert_eq!(resp.status.status(), PkiStatus::Granted);
        assert_eq!(resp.granted_token().unwrap(), vec![0x30, 0x00]);
    }

    /// O caso que a lacuna deixava passar para dentro do manifesto.
    #[test]
    fn uma_recusa_da_act_nunca_sai_daqui_como_carimbo() {
        let der = resposta(2, false, None);
        let resp = TimeStampResp::from_der_bytes(&der).unwrap();
        let erro = resp.granted_token().unwrap_err().to_string();
        assert!(erro.contains("recusou"), "{erro}");
        assert!(erro.contains("rejection"), "{erro}");
    }

    /// Um operador que vê `unacceptedPolicy` sabe o que corrigir; um que vê só
    /// "recusado" não sabe nada.
    #[test]
    fn os_bits_de_fail_info_saem_por_nome() {
        // bit 15 = unacceptedPolicy → 3.º octeto, bit mais significativo.
        let der = resposta(2, false, Some(&[0x00, 0x01]));
        let resp = TimeStampResp::from_der_bytes(&der).unwrap();
        assert_eq!(resp.status.fail_info_labels(), vec!["unacceptedPolicy"]);
        assert!(resp
            .granted_token()
            .unwrap_err()
            .to_string()
            .contains("unacceptedPolicy"));
    }

    /// A regressão que o `Option<Any>` causava: `statusString` é opcional e vem
    /// ANTES de `failInfo`; como `Any` aceita qualquer tag, engolia o
    /// `BIT STRING` seguinte e o motivo da recusa desaparecia em silêncio.
    #[test]
    fn status_string_presente_nao_engole_o_fail_info() {
        use der::{Encode, Tag};
        // `PKIFreeText` com um UTF8String — o que uma ACT real envia.
        let texto = der::asn1::Utf8StringRef::new("politica nao aceite")
            .unwrap()
            .to_der()
            .unwrap();
        let free_text = der::asn1::Any::new(Tag::Sequence, texto).unwrap();
        let info = PkiStatusInfo {
            status: 2,
            status_string: Some(
                PkiFreeText::from_der(&free_text.to_der().unwrap()).unwrap(),
            ),
            fail_info: Some(der::asn1::BitString::from_bytes(&[0x00, 0x01]).unwrap()),
        };
        let der_bytes = TimeStampResp {
            status: info,
            time_stamp_token: None,
        }
        .to_der()
        .unwrap();

        let resp = TimeStampResp::from_der_bytes(&der_bytes).unwrap();
        assert!(
            resp.status.status_string.is_some(),
            "o statusString tem de continuar a ser lido"
        );
        assert_eq!(
            resp.status.fail_info_labels(),
            vec!["unacceptedPolicy"],
            "o failInfo não pode ser consumido pelo campo anterior"
        );
    }

    /// A ACT a avisar que a SUA PRÓPRIA chave está a ser revogada. Pode até
    /// anexar um token — e um carimbo emitido sob esta condição não é evidência
    /// que se queira citar.
    #[test]
    fn revocation_warning_e_recusado_mesmo_trazendo_token() {
        for status in [4u32, 5] {
            let der = resposta(status, true, None);
            let resp = TimeStampResp::from_der_bytes(&der).unwrap();
            assert!(
                resp.granted_token().is_err(),
                "status {status} traz aviso de revogação da própria ACT e não pode passar"
            );
        }
    }

    /// `grantedWithMods` passa: tudo o que a ACT possa ter alterado e que
    /// importe é reverificado a seguir pelo verificador ICP.
    #[test]
    fn granted_with_mods_passa_e_a_decisao_fica_para_o_verificador() {
        let der = resposta(1, true, None);
        let resp = TimeStampResp::from_der_bytes(&der).unwrap();
        assert!(resp.granted_token().is_ok());
    }

    /// Concedeu e não anexou nada: resposta malformada, e não um carimbo vazio.
    #[test]
    fn granted_sem_token_e_resposta_malformada() {
        let der = resposta(0, false, None);
        let resp = TimeStampResp::from_der_bytes(&der).unwrap();
        assert!(resp
            .granted_token()
            .unwrap_err()
            .to_string()
            .contains("malformada"));
    }
}
