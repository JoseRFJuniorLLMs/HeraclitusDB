//! SPEC-0075 §7–§9 — identidade, validação OIDC/JWT e manuseamento de tokens.
//!
//! # A regra que o resto do produto depende
//!
//! > Heraclitus valida identidades emitidas por sistemas existentes. **Não vira
//! > provedor corporativo de identidade** (§2.5).
//!
//! Portanto não há aqui emissão de tokens, nem base de dados de utilizadores,
//! nem `/login`. Há a validação de um JWT contra um conjunto de chaves
//! públicas, com uma allowlist explícita de emissores e algoritmos.
//!
//! # O que nunca é persistido (§9)
//!
//! ```text
//! Authorization  Cookie  Set-Cookie  access_token  refresh_token
//! client_secret  api_key
//! ```
//!
//! O que sobra de um token validado é [`ValidatedIdentity`]: subject, issuer,
//! audience, papéis e tempos. Nem o token nem a assinatura entram na evidência.
//! O que pode entrar é a **impressão digital** ([`ValidatedIdentity::credential_fingerprint`]),
//! que identifica a credencial sem a reproduzir.
//!
//! # Algoritmos
//!
//! `RS256`, `ES256` e `HS256`. A allowlist é fechada por construção: `alg` vem
//! do cabeçalho do token — que é input do atacante — e um validador que aceite
//! `none` ou que deixe o token escolher entre HMAC e RSA é a vulnerabilidade
//! clássica de JWT (confusão de algoritmo). Aqui o algoritmo aceite é decidido
//! pela **chave configurada**, não pelo token.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

/// Algoritmos aceites.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum JwtAlg {
    RS256,
    ES256,
    HS256,
}

impl JwtAlg {
    fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "RS256" => Self::RS256,
            "ES256" => Self::ES256,
            "HS256" => Self::HS256,
            _ => return None,
        })
    }
    pub fn label(self) -> &'static str {
        match self {
            Self::RS256 => "RS256",
            Self::ES256 => "ES256",
            Self::HS256 => "HS256",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum IdentityError {
    #[error("token mal formado: {0}")]
    Malformed(&'static str),
    #[error("algoritmo `{0}` não é aceite")]
    UnsupportedAlg(String),
    #[error("emissor `{0}` não está na allowlist")]
    IssuerNotAllowed(String),
    #[error("audiência inválida")]
    AudienceMismatch,
    #[error("token expirado")]
    Expired,
    #[error("token ainda não é válido (nbf)")]
    NotYetValid,
    #[error("nenhuma chave corresponde ao kid `{0}`")]
    UnknownKid(String),
    #[error("assinatura inválida")]
    BadSignature,
    #[error("sem `sub`")]
    MissingSubject,
    #[error("identidade obrigatória em produção e o pedido não trouxe nenhuma")]
    MissingIdentity,
}

/// Uma chave pública utilizável para validar.
#[derive(Debug, Clone)]
pub enum VerificationKey {
    /// `n` e `e` em big-endian, tal como vêm do JWK.
    Rsa { n: Vec<u8>, e: Vec<u8> },
    /// Ponto SEC1 não comprimido (`0x04 || x || y`).
    EcP256 { sec1: Vec<u8> },
    /// Segredo partilhado. Só faz sentido quando o Heraclitus e o emissor são
    /// o mesmo operador — um IdP de terceiros nunca partilha um HMAC.
    Hmac { secret: Vec<u8> },
}

impl VerificationKey {
    fn alg(&self) -> JwtAlg {
        match self {
            Self::Rsa { .. } => JwtAlg::RS256,
            Self::EcP256 { .. } => JwtAlg::ES256,
            Self::Hmac { .. } => JwtAlg::HS256,
        }
    }
}

/// Conjunto de chaves, indexado por `kid`.
#[derive(Debug, Clone, Default)]
pub struct KeySet {
    keys: BTreeMap<String, VerificationKey>,
}

impl KeySet {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_key(mut self, kid: impl Into<String>, key: VerificationKey) -> Self {
        self.keys.insert(kid.into(), key);
        self
    }

    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    pub fn len(&self) -> usize {
        self.keys.len()
    }

    /// Lê um JWKS (RFC 7517). Chaves com tipos que não sabemos validar são
    /// ignoradas — não são erro, são simplesmente inutilizáveis por nós.
    pub fn from_jwks(json: &str) -> Result<Self, IdentityError> {
        let v: serde_json::Value =
            serde_json::from_str(json).map_err(|_| IdentityError::Malformed("JWKS não é JSON"))?;
        let arr = v
            .get("keys")
            .and_then(|k| k.as_array())
            .ok_or(IdentityError::Malformed("JWKS sem `keys`"))?;
        let mut out = Self::new();
        for k in arr {
            let kid = k
                .get("kid")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string();
            let kty = k.get("kty").and_then(|x| x.as_str()).unwrap_or("");
            match kty {
                "RSA" => {
                    let (Some(n), Some(e)) = (
                        k.get("n").and_then(|x| x.as_str()).and_then(b64url_decode),
                        k.get("e").and_then(|x| x.as_str()).and_then(b64url_decode),
                    ) else {
                        continue;
                    };
                    out.keys.insert(kid, VerificationKey::Rsa { n, e });
                }
                "EC" => {
                    if k.get("crv").and_then(|x| x.as_str()) != Some("P-256") {
                        continue;
                    }
                    let (Some(x), Some(y)) = (
                        k.get("x").and_then(|v| v.as_str()).and_then(b64url_decode),
                        k.get("y").and_then(|v| v.as_str()).and_then(b64url_decode),
                    ) else {
                        continue;
                    };
                    if x.len() != 32 || y.len() != 32 {
                        continue;
                    }
                    let mut sec1 = Vec::with_capacity(65);
                    sec1.push(0x04);
                    sec1.extend_from_slice(&x);
                    sec1.extend_from_slice(&y);
                    out.keys.insert(kid, VerificationKey::EcP256 { sec1 });
                }
                _ => continue,
            }
        }
        Ok(out)
    }
}

/// A política de validação (§8.2).
#[derive(Debug, Clone)]
pub struct OidcValidator {
    /// Allowlist de emissores. Vazia = recusa tudo (fail closed).
    pub issuers: Vec<String>,
    pub audience: String,
    /// Tolerância de relógio, em segundos.
    pub clock_skew_seconds: u64,
    /// Claim de onde vêm os papéis (`roles`, `groups`, `realm_access.roles`...).
    pub roles_claim: String,
    pub keys: KeySet,
}

impl Default for OidcValidator {
    fn default() -> Self {
        Self {
            issuers: Vec::new(),
            audience: String::new(),
            clock_skew_seconds: 60,
            roles_claim: "roles".to_string(),
            keys: KeySet::new(),
        }
    }
}

/// O que sobra de um token validado. Note-se o que **não** está aqui: o token.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidatedIdentity {
    pub subject: String,
    pub issuer: String,
    pub audience: Option<String>,
    pub roles: Vec<String>,
    pub issued_at: Option<u64>,
    pub expires_at: Option<u64>,
    pub auth_time: Option<u64>,
    pub alg: JwtAlg,
    /// BLAKE3 do token. Identifica a credencial sem a reproduzir — é o que o
    /// `source_credential_fingerprint` da delegação guarda (§7.3).
    pub credential_fingerprint: String,
}

impl OidcValidator {
    /// Valida um `Authorization: Bearer <token>`.
    ///
    /// A ordem das verificações é deliberada: forma, algoritmo, chave,
    /// **assinatura**, e só depois as claims. Ler claims de um token cuja
    /// assinatura ainda não foi verificada é tratar input hostil como facto.
    pub fn validate(
        &self,
        token: &str,
        now_unix_seconds: u64,
    ) -> Result<ValidatedIdentity, IdentityError> {
        let parts: Vec<&str> = token.trim().split('.').collect();
        if parts.len() != 3 {
            return Err(IdentityError::Malformed("um JWT tem três segmentos"));
        }
        let header_raw =
            b64url_decode(parts[0]).ok_or(IdentityError::Malformed("cabeçalho não é base64url"))?;
        let header: serde_json::Value = serde_json::from_slice(&header_raw)
            .map_err(|_| IdentityError::Malformed("cabeçalho não é JSON"))?;
        let alg_str = header
            .get("alg")
            .and_then(|a| a.as_str())
            .ok_or(IdentityError::Malformed("cabeçalho sem `alg`"))?;
        let alg = JwtAlg::parse(alg_str)
            .ok_or_else(|| IdentityError::UnsupportedAlg(alg_str.to_string()))?;
        let kid = header.get("kid").and_then(|k| k.as_str()).unwrap_or("");

        // A chave decide o algoritmo, não o token. Um token que diga `HS256`
        // não pode fazer-se validar contra uma chave pública RSA usando-a como
        // segredo HMAC — a confusão clássica.
        let key = self
            .keys
            .keys
            .get(kid)
            .or_else(|| {
                // Sem `kid`: só é aceitável quando há exactamente uma chave.
                // Com duas, escolher seria adivinhar.
                //
                // A condição `kid.is_empty()` não é decorativa: sem ela, um
                // token que NOMEIE um `kid` desconhecido cairia neste ramo e
                // seria validado contra a única chave configurada — ou seja, o
                // atacante escolheria a chave mentindo sobre o seu nome.
                (kid.is_empty() && self.keys.keys.len() == 1)
                    .then(|| self.keys.keys.values().next().unwrap())
            })
            .ok_or_else(|| IdentityError::UnknownKid(kid.to_string()))?;
        if key.alg() != alg {
            return Err(IdentityError::UnsupportedAlg(format!(
                "{alg_str} não corresponde ao tipo da chave `{kid}`"
            )));
        }

        let signature = b64url_decode(parts[2])
            .ok_or(IdentityError::Malformed("assinatura não é base64url"))?;
        let signing_input = format!("{}.{}", parts[0], parts[1]);
        if !verify_signature(key, alg, signing_input.as_bytes(), &signature) {
            return Err(IdentityError::BadSignature);
        }

        let payload_raw =
            b64url_decode(parts[1]).ok_or(IdentityError::Malformed("payload não é base64url"))?;
        let claims: serde_json::Value = serde_json::from_slice(&payload_raw)
            .map_err(|_| IdentityError::Malformed("payload não é JSON"))?;

        let issuer = claims
            .get("iss")
            .and_then(|i| i.as_str())
            .unwrap_or("")
            .to_string();
        if self.issuers.is_empty() || !self.issuers.iter().any(|i| i == &issuer) {
            return Err(IdentityError::IssuerNotAllowed(issuer));
        }

        let audience = match claims.get("aud") {
            Some(serde_json::Value::String(s)) => Some(s.clone()),
            Some(serde_json::Value::Array(a)) => a
                .iter()
                .filter_map(|x| x.as_str())
                .find(|x| *x == self.audience)
                .map(str::to_string),
            _ => None,
        };
        if !self.audience.is_empty() && audience.as_deref() != Some(self.audience.as_str()) {
            return Err(IdentityError::AudienceMismatch);
        }

        let exp = claims.get("exp").and_then(|x| x.as_u64());
        let nbf = claims.get("nbf").and_then(|x| x.as_u64());
        if let Some(exp) = exp {
            if now_unix_seconds > exp.saturating_add(self.clock_skew_seconds) {
                return Err(IdentityError::Expired);
            }
        }
        if let Some(nbf) = nbf {
            if now_unix_seconds.saturating_add(self.clock_skew_seconds) < nbf {
                return Err(IdentityError::NotYetValid);
            }
        }

        let subject = claims
            .get("sub")
            .and_then(|s| s.as_str())
            .filter(|s| !s.is_empty())
            .ok_or(IdentityError::MissingSubject)?
            .to_string();

        Ok(ValidatedIdentity {
            subject,
            issuer,
            audience,
            roles: extract_roles(&claims, &self.roles_claim),
            issued_at: claims.get("iat").and_then(|x| x.as_u64()),
            expires_at: exp,
            auth_time: claims.get("auth_time").and_then(|x| x.as_u64()),
            alg,
            credential_fingerprint: fingerprint(token),
        })
    }
}

/// Papéis a partir de um claim, que pode ser `roles`, `groups` ou um caminho
/// pontuado (`realm_access.roles`, como o Keycloak faz).
fn extract_roles(claims: &serde_json::Value, path: &str) -> Vec<String> {
    let mut cur = claims;
    for seg in path.split('.') {
        match cur.get(seg) {
            Some(next) => cur = next,
            None => return Vec::new(),
        }
    }
    match cur {
        serde_json::Value::Array(a) => a
            .iter()
            .filter_map(|x| x.as_str())
            .map(str::to_string)
            .collect(),
        serde_json::Value::String(s) => s.split_whitespace().map(str::to_string).collect(),
        _ => Vec::new(),
    }
}

fn verify_signature(key: &VerificationKey, alg: JwtAlg, msg: &[u8], sig: &[u8]) -> bool {
    match (key, alg) {
        (VerificationKey::Rsa { n, e }, JwtAlg::RS256) => {
            let n = rsa::BigUint::from_bytes_be(n);
            let e = rsa::BigUint::from_bytes_be(e);
            let Ok(pk) = rsa::RsaPublicKey::new(n, e) else {
                return false;
            };
            let digest = Sha256::digest(msg);
            rsa::traits::SignatureScheme::verify(
                rsa::Pkcs1v15Sign::new::<Sha256>(),
                &pk,
                &digest,
                sig,
            )
            .is_ok()
        }
        (VerificationKey::EcP256 { sec1 }, JwtAlg::ES256) => {
            use p256::ecdsa::signature::Verifier as _;
            let Ok(vk) = p256::ecdsa::VerifyingKey::from_sec1_bytes(sec1) else {
                return false;
            };
            // JWS usa a forma "raw" r||s de 64 bytes, não DER.
            let Ok(signature) = p256::ecdsa::Signature::from_slice(sig) else {
                return false;
            };
            vk.verify(msg, &signature).is_ok()
        }
        (VerificationKey::Hmac { secret }, JwtAlg::HS256) => {
            use hmac::Mac;
            let Ok(mut mac) = hmac::Hmac::<Sha256>::new_from_slice(secret) else {
                return false;
            };
            mac.update(msg);
            mac.verify_slice(sig).is_ok()
        }
        _ => false,
    }
}

/// Impressão digital de uma credencial. Domínio próprio para que não possa ser
/// confundida com o hash de outra coisa.
pub fn fingerprint(token: &str) -> String {
    crate::canonical::hex32(&crate::canonical::domain_hash(
        b"heraclitus.agent.credential.v1",
        token.as_bytes(),
    ))
}

/// base64url sem padding (RFC 7515). Escrito à mão: é a única codificação de
/// que precisamos e vive no caminho de validação de um token — que é input
/// hostil, e portanto o sítio onde menos se quer uma superfície extra.
pub fn b64url_decode(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(s.len() * 3 / 4 + 3);
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    for b in s.bytes() {
        let v = match b {
            b'A'..=b'Z' => b - b'A',
            b'a'..=b'z' => b - b'a' + 26,
            b'0'..=b'9' => b - b'0' + 52,
            b'-' => 62,
            b'_' => 63,
            // O padding é tolerado no fim; qualquer outro caractere não é.
            b'=' => break,
            _ => return None,
        } as u32;
        acc = (acc << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(((acc >> bits) & 0xff) as u8);
        }
    }
    // Sobras de bits têm de ser zero: de outro modo duas codificações
    // diferentes descodificariam para os mesmos bytes.
    if bits > 0 && (acc & ((1 << bits) - 1)) != 0 {
        return None;
    }
    Some(out)
}

/// base64url sem padding, para construir tokens em testes e exemplos.
pub fn b64url_encode(data: &[u8]) -> String {
    const AB: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        out.push(AB[(n >> 18) as usize & 63] as char);
        out.push(AB[(n >> 12) as usize & 63] as char);
        if chunk.len() > 1 {
            out.push(AB[(n >> 6) as usize & 63] as char);
        }
        if chunk.len() > 2 {
            out.push(AB[n as usize & 63] as char);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use hmac::Mac;

    fn hs256_token(claims: serde_json::Value, secret: &[u8], alg: &str, kid: &str) -> String {
        let header = serde_json::json!({ "alg": alg, "typ": "JWT", "kid": kid });
        let h = b64url_encode(serde_json::to_string(&header).unwrap().as_bytes());
        let p = b64url_encode(serde_json::to_string(&claims).unwrap().as_bytes());
        let signing = format!("{h}.{p}");
        let mut mac = hmac::Hmac::<Sha256>::new_from_slice(secret).unwrap();
        mac.update(signing.as_bytes());
        let sig = b64url_encode(&mac.finalize().into_bytes());
        format!("{signing}.{sig}")
    }

    fn validator() -> OidcValidator {
        OidcValidator {
            issuers: vec!["https://id.example.gov".into()],
            audience: "heraclitus-agent-gateway".into(),
            clock_skew_seconds: 0,
            roles_claim: "roles".into(),
            keys: KeySet::new().with_key(
                "k1",
                VerificationKey::Hmac {
                    secret: b"segredo-partilhado-de-teste".to_vec(),
                },
            ),
        }
    }

    fn claims() -> serde_json::Value {
        serde_json::json!({
            "iss": "https://id.example.gov",
            "aud": "heraclitus-agent-gateway",
            "sub": "jose",
            "exp": 2_000,
            "nbf": 1_000,
            "iat": 1_000,
            "roles": ["cfo", "auditor"]
        })
    }

    #[test]
    fn token_valido_passa() {
        let t = hs256_token(claims(), b"segredo-partilhado-de-teste", "HS256", "k1");
        let id = validator().validate(&t, 1_500).unwrap();
        assert_eq!(id.subject, "jose");
        assert_eq!(id.roles, vec!["cfo".to_string(), "auditor".to_string()]);
        assert_eq!(id.alg, JwtAlg::HS256);
        assert_eq!(id.credential_fingerprint.len(), 64);
    }

    #[test]
    fn o_token_nunca_aparece_na_identidade() {
        let t = hs256_token(claims(), b"segredo-partilhado-de-teste", "HS256", "k1");
        let id = validator().validate(&t, 1_500).unwrap();
        let dump = serde_json::to_string(&id).unwrap();
        assert!(!dump.contains(&t));
        assert!(!dump.contains("segredo-partilhado"));
    }

    #[test]
    fn emissor_errado_e_recusado() {
        let mut c = claims();
        c["iss"] = "https://mau.example".into();
        let t = hs256_token(c, b"segredo-partilhado-de-teste", "HS256", "k1");
        assert!(matches!(
            validator().validate(&t, 1_500),
            Err(IdentityError::IssuerNotAllowed(_))
        ));
    }

    #[test]
    fn audiencia_errada_e_recusada() {
        let mut c = claims();
        c["aud"] = "outro-servico".into();
        let t = hs256_token(c, b"segredo-partilhado-de-teste", "HS256", "k1");
        assert_eq!(
            validator().validate(&t, 1_500),
            Err(IdentityError::AudienceMismatch)
        );
    }

    #[test]
    fn expirado_e_recusado() {
        let t = hs256_token(claims(), b"segredo-partilhado-de-teste", "HS256", "k1");
        assert_eq!(validator().validate(&t, 2_001), Err(IdentityError::Expired));
    }

    #[test]
    fn nbf_no_futuro_e_recusado() {
        let t = hs256_token(claims(), b"segredo-partilhado-de-teste", "HS256", "k1");
        assert_eq!(
            validator().validate(&t, 999),
            Err(IdentityError::NotYetValid)
        );
    }

    #[test]
    fn algoritmo_none_e_recusado() {
        let header = serde_json::json!({ "alg": "none", "typ": "JWT", "kid": "k1" });
        let h = b64url_encode(serde_json::to_string(&header).unwrap().as_bytes());
        let p = b64url_encode(serde_json::to_string(&claims()).unwrap().as_bytes());
        let t = format!("{h}.{p}.");
        assert!(matches!(
            validator().validate(&t, 1_500),
            Err(IdentityError::UnsupportedAlg(_))
        ));
    }

    #[test]
    fn confusao_de_algoritmo_e_recusada() {
        // Um token que se diz RS256 não pode validar contra uma chave HMAC —
        // nem o contrário. É a chave configurada que manda.
        let t = hs256_token(claims(), b"segredo-partilhado-de-teste", "RS256", "k1");
        assert!(matches!(
            validator().validate(&t, 1_500),
            Err(IdentityError::UnsupportedAlg(_))
        ));
    }

    #[test]
    fn assinatura_alterada_e_recusada() {
        let t = hs256_token(claims(), b"outro-segredo-qualquer-aqui", "HS256", "k1");
        assert_eq!(
            validator().validate(&t, 1_500),
            Err(IdentityError::BadSignature)
        );
    }

    #[test]
    fn payload_alterado_invalida_a_assinatura() {
        let t = hs256_token(claims(), b"segredo-partilhado-de-teste", "HS256", "k1");
        let parts: Vec<&str> = t.split('.').collect();
        let mut c = claims();
        c["sub"] = "outro".into();
        let p = b64url_encode(serde_json::to_string(&c).unwrap().as_bytes());
        let forjado = format!("{}.{}.{}", parts[0], p, parts[2]);
        assert_eq!(
            validator().validate(&forjado, 1_500),
            Err(IdentityError::BadSignature)
        );
    }

    #[test]
    fn kid_desconhecido_e_recusado() {
        let t = hs256_token(claims(), b"segredo-partilhado-de-teste", "HS256", "k9");
        assert!(matches!(
            validator().validate(&t, 1_500),
            Err(IdentityError::UnknownKid(_))
        ));
    }

    #[test]
    fn allowlist_vazia_recusa_tudo() {
        let mut v = validator();
        v.issuers.clear();
        let t = hs256_token(claims(), b"segredo-partilhado-de-teste", "HS256", "k1");
        assert!(matches!(
            v.validate(&t, 1_500),
            Err(IdentityError::IssuerNotAllowed(_))
        ));
    }

    #[test]
    fn sem_sub_e_recusado() {
        let mut c = claims();
        c.as_object_mut().unwrap().remove("sub");
        let t = hs256_token(c, b"segredo-partilhado-de-teste", "HS256", "k1");
        assert_eq!(
            validator().validate(&t, 1_500),
            Err(IdentityError::MissingSubject)
        );
    }

    #[test]
    fn papeis_em_caminho_pontuado() {
        let mut v = validator();
        v.roles_claim = "realm_access.roles".into();
        let mut c = claims();
        c["realm_access"] = serde_json::json!({ "roles": ["cfo"] });
        let t = hs256_token(c, b"segredo-partilhado-de-teste", "HS256", "k1");
        assert_eq!(
            v.validate(&t, 1_500).unwrap().roles,
            vec!["cfo".to_string()]
        );
    }

    #[test]
    fn base64url_recusa_lixo_e_fecha_o_ciclo() {
        assert_eq!(b64url_decode("YWJj"), Some(b"abc".to_vec()));
        assert_eq!(b64url_decode("a b"), None);
        assert_eq!(b64url_decode("+/=="), None);
        let data = b"qualquer coisa binaria \x00\xff";
        assert_eq!(
            b64url_decode(&b64url_encode(data)).as_deref(),
            Some(&data[..])
        );
    }

    #[test]
    fn token_malformado_nao_entra_em_panico() {
        let v = validator();
        for t in ["", ".", "a.b", "a.b.c.d", "....", "a.b.c"] {
            let _ = v.validate(t, 1_500);
        }
    }

    #[test]
    fn jwks_ec_e_lido() {
        let x = b64url_encode(&[1u8; 32]);
        let y = b64url_encode(&[2u8; 32]);
        let jwks = format!(
            r#"{{"keys":[{{"kty":"EC","crv":"P-256","kid":"ec1","x":"{x}","y":"{y}"}},
                        {{"kty":"OKP","crv":"Ed25519","kid":"ignorada","x":"AA"}}]}}"#
        );
        let ks = KeySet::from_jwks(&jwks).unwrap();
        assert_eq!(ks.len(), 1);
        assert!(matches!(ks.keys["ec1"], VerificationKey::EcP256 { .. }));
    }

    #[test]
    fn jwks_rsa_e_lido() {
        let n = b64url_encode(&[0xc7u8; 256]);
        let jwks = format!(r#"{{"keys":[{{"kty":"RSA","kid":"r1","n":"{n}","e":"AQAB"}}]}}"#);
        let ks = KeySet::from_jwks(&jwks).unwrap();
        assert!(matches!(ks.keys["r1"], VerificationKey::Rsa { .. }));
    }
}
