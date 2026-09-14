//! SPEC-0074 §11 e §23 — o portão de privacidade.
//!
//! > **Observabilidade não pode virar vazamento de segredo.**
//!
//! # A regra que este módulo torna mecânica
//!
//! Há duas classes de dados aqui, e confundi-las é o defeito que o produto não
//! pode ter:
//!
//! | classe | exemplo | política |
//! |---|---|---|
//! | conteúdo | argumentos da tool, prompt, resultado | tecto + redacção, conforme o modo |
//! | credencial | `Authorization`, `Cookie`, `sk-...`, chave AWS | **NUNCA persistida**, em modo nenhum |
//!
//! A segunda linha não tem excepção: `FULL_EXPLICIT` autoriza guardar o corpo
//! de uma tool call, **não** autoriza guardar o bearer token que a
//! acompanhava. Um administrador pode decidir aceitar o risco do primeiro; o
//! segundo não é um risco que lhe pertença — é a credencial de outra pessoa.
//!
//! # O que este módulo NÃO promete
//!
//! Detectar todo o segredo possível (§23). Os detectores apanham as formas
//! conhecidas e declaram o que apanharam; um segredo com forma inédita passa.
//! Por isso o default é `METADATA_ONLY`: a defesa primária é **não guardar o
//! corpo**, e os detectores são a segunda linha, não a primeira.

use crate::canonical::{content_hash, hex32};
use crate::evidence::{CaptureModeV1, EvidenceContentV1, PrivacyEnvelopeV1};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// Marcador que substitui um valor redigido. Fixo, para que o hash canónico de
/// duas redacções equivalentes seja igual.
pub const REDACTED_MARKER: &str = "[REDACTED]";

/// Cabeçalhos que nunca são persistidos, em modo nenhum (SPEC-0074 §22,
/// SPEC-0075 §9). Comparados em minúsculas.
pub const DENY_HEADERS_DEFAULT: &[&str] = &[
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "x-auth-token",
    "x-amz-security-token",
    "mcp-session-token",
];

/// Nomes de campo que nunca são persistidos em claro, venham de onde vierem.
pub const DENY_FIELDS_DEFAULT: &[&str] = &[
    "password",
    "passwd",
    "secret",
    "client_secret",
    "api_key",
    "apikey",
    "access_token",
    "refresh_token",
    "id_token",
    "private_key",
    "token",
    "credential",
    "credentials",
    "authorization",
    // SPEC-0074 §11: "prompts completos = OFF", "completions completas = OFF".
    // Ficam como qualquer outro campo negado — a CHAVE sobrevive (a auditoria
    // precisa de saber que houve um prompt), o VALOR não.
    "prompt",
    "completion",
    "gen_ai.input.messages",
    "gen_ai.output.messages",
];

/// Perfil de redacção. `profile_id` viaja na evidência para que uma auditoria
/// consiga dizer *sob que regras* o corpo foi cortado.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct RedactionProfile {
    pub profile_id: String,
    pub capture_mode: CaptureModeV1,
    /// Tecto de bytes por corpo persistido. Excedê-lo trunca e contabiliza.
    pub max_body_bytes: usize,
    /// Tecto por valor de campo tipado.
    pub max_field_bytes: usize,
    /// Quantos campos tipados podem sobreviver.
    pub max_fields: usize,
    pub deny_headers: Vec<String>,
    pub deny_fields: Vec<String>,
}

impl Default for RedactionProfile {
    fn default() -> Self {
        Self {
            profile_id: "default".to_string(),
            capture_mode: CaptureModeV1::MetadataOnly,
            max_body_bytes: 8 * 1024,
            max_field_bytes: 1024,
            max_fields: 64,
            deny_headers: DENY_HEADERS_DEFAULT.iter().map(|s| s.to_string()).collect(),
            deny_fields: DENY_FIELDS_DEFAULT.iter().map(|s| s.to_string()).collect(),
        }
    }
}

impl RedactionProfile {
    pub fn with_mode(mut self, mode: CaptureModeV1) -> Self {
        self.capture_mode = mode;
        self
    }

    fn denies_header(&self, name: &str) -> bool {
        let lower = name.to_ascii_lowercase();
        self.deny_headers
            .iter()
            .any(|d| d.eq_ignore_ascii_case(&lower))
    }

    /// Um nome de campo é negado se bater exactamente ou se contiver o termo
    /// negado como sub-palavra (`user_password`, `aws.secret.key`).
    ///
    /// A comparação por substring é deliberadamente grosseira: em caso de
    /// dúvida, redigir. Um campo chamado `tokenizer_name` perder o valor é um
    /// incómodo; um campo chamado `oauth_token` sobreviver é um incidente.
    fn denies_field(&self, name: &str) -> bool {
        let lower = name.to_ascii_lowercase();
        self.deny_fields
            .iter()
            .any(|d| lower == *d || lower.contains(d.as_str()))
    }
}

/// Classes de segredo reconhecidas. O nome da classe entra na evidência; o
/// segredo, nunca.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SecretClass {
    Bearer,
    Basic,
    OpenAiStyleKey,
    AwsAccessKeyId,
    GitHubToken,
    SlackToken,
    PrivateKeyBlock,
    JwtLike,
    CookieHeader,
}

impl SecretClass {
    pub fn label(self) -> &'static str {
        match self {
            Self::Bearer => "bearer",
            Self::Basic => "basic",
            Self::OpenAiStyleKey => "openai_style_key",
            Self::AwsAccessKeyId => "aws_access_key_id",
            Self::GitHubToken => "github_token",
            Self::SlackToken => "slack_token",
            Self::PrivateKeyBlock => "private_key_block",
            Self::JwtLike => "jwt_like",
            Self::CookieHeader => "cookie_header",
        }
    }
}

/// Procura formas conhecidas de segredo. Sem regex: as formas são literais ou
/// prefixos, e um motor de regex sobre input hostil é exactamente o tipo de
/// superfície que a SPEC-0075 §12 manda evitar.
pub fn detect_secrets(text: &str) -> BTreeSet<SecretClass> {
    let mut found = BTreeSet::new();
    let lower = text.to_ascii_lowercase();
    if lower.contains("bearer ") {
        found.insert(SecretClass::Bearer);
    }
    if lower.contains("basic ") {
        found.insert(SecretClass::Basic);
    }
    if lower.contains("cookie:") || lower.contains("set-cookie:") {
        found.insert(SecretClass::CookieHeader);
    }
    if text.contains("-----BEGIN") && text.contains("PRIVATE KEY") {
        found.insert(SecretClass::PrivateKeyBlock);
    }
    for token in split_tokens(text) {
        if token.starts_with("sk-") && token.len() >= 20 {
            found.insert(SecretClass::OpenAiStyleKey);
        }
        if (token.starts_with("AKIA") || token.starts_with("ASIA")) && token.len() == 20 {
            found.insert(SecretClass::AwsAccessKeyId);
        }
        if token.starts_with("ghp_")
            || token.starts_with("gho_")
            || token.starts_with("github_pat_")
        {
            found.insert(SecretClass::GitHubToken);
        }
        if token.starts_with("xoxb-") || token.starts_with("xoxp-") || token.starts_with("xapp-") {
            found.insert(SecretClass::SlackToken);
        }
        if looks_like_jwt(token) {
            found.insert(SecretClass::JwtLike);
        }
    }
    found
}

fn split_tokens(text: &str) -> impl Iterator<Item = &str> {
    text.split(|c: char| c.is_whitespace() || matches!(c, '"' | '\'' | ',' | ';' | '=' | '<' | '>'))
        .filter(|t| !t.is_empty())
}

/// Três segmentos base64url separados por ponto, com cabeçalho plausível.
/// Não descodifica nada: o objectivo é classificar, não validar.
fn looks_like_jwt(token: &str) -> bool {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return false;
    }
    if parts.iter().any(|p| p.len() < 8) {
        return false;
    }
    if !parts.iter().all(|p| {
        p.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    }) {
        return false;
    }
    // O cabeçalho de um JWT começa sempre por `{"` -> `eyJ` em base64url.
    parts[0].starts_with("eyJ")
}

/// O resultado de passar conteúdo pelo portão.
#[derive(Debug, Clone)]
pub struct RedactionOutcome {
    pub content: EvidenceContentV1,
    pub privacy: PrivacyEnvelopeV1,
}

/// Entrada crua a redigir.
#[derive(Debug, Clone, Default)]
pub struct RawContent {
    pub content_type: Option<String>,
    /// Bytes originais, tal como observados. NUNCA são guardados sem passar
    /// por aqui.
    pub body: Option<Vec<u8>>,
    /// Campos tipados (argumentos de tool, atributos GenAI conhecidos).
    pub fields: BTreeMap<String, String>,
    /// Cabeçalhos HTTP observados. Os negados desaparecem; os restantes viram
    /// campos `header.<nome>`.
    pub headers: BTreeMap<String, String>,
}

/// Aplica o portão de privacidade (SPEC-0074 §11).
///
/// Invariantes que esta função faz cumprir, independentemente do modo:
///
/// 1. `canonical_content_hash` é calculado sobre os bytes **originais**, antes
///    de qualquer corte. É o que permite provar, mais tarde, que o argumento
///    aprovado foi o argumento executado.
/// 2. Nenhum cabeçalho da deny-list chega ao resultado.
/// 3. Nenhum campo da deny-list chega ao resultado em claro.
/// 4. O corpo só é persistido se o modo o autorizar E não contiver segredo
///    detectado.
pub fn apply(profile: &RedactionProfile, raw: &RawContent) -> RedactionOutcome {
    let mut content = EvidenceContentV1 {
        content_type: raw.content_type.clone(),
        ..Default::default()
    };
    let mut privacy = PrivacyEnvelopeV1 {
        capture_mode: profile.capture_mode,
        redaction_profile_id: Some(profile.profile_id.clone()),
        ..Default::default()
    };
    let mut classes: BTreeSet<SecretClass> = BTreeSet::new();

    if let Some(body) = &raw.body {
        content.content_length = Some(body.len() as u64);
        content.canonical_content_hash = Some(hex32(&content_hash(body)));
        if let Ok(text) = std::str::from_utf8(body) {
            classes.extend(detect_secrets(text));
        }
    }

    // Cabeçalhos: os negados nunca sobrevivem; os outros entram como campos
    // prefixados para não colidirem com argumentos da ferramenta.
    for (name, value) in &raw.headers {
        if profile.denies_header(name) {
            privacy.redacted_field_count += 1;
            classes.extend(detect_secrets(value));
            continue;
        }
        classes.extend(detect_secrets(value));
        let key = format!("header.{}", name.to_ascii_lowercase());
        let (v, truncated) = truncate(value, profile.max_field_bytes);
        privacy.truncated_bytes += truncated;
        insert_bounded(&mut content.fields, profile.max_fields, key, v);
    }

    for (name, value) in &raw.fields {
        if profile.denies_field(name) {
            privacy.redacted_field_count += 1;
            classes.extend(detect_secrets(value));
            insert_bounded(
                &mut content.fields,
                profile.max_fields,
                name.clone(),
                REDACTED_MARKER.to_string(),
            );
            continue;
        }
        let detected = detect_secrets(value);
        if !detected.is_empty() {
            // O NOME do campo é inócuo, o valor não é. Redigir o valor e
            // declarar a classe dá à auditoria o essencial — "aqui passou um
            // bearer token" — sem o guardar.
            classes.extend(detected);
            privacy.redacted_field_count += 1;
            insert_bounded(
                &mut content.fields,
                profile.max_fields,
                name.clone(),
                REDACTED_MARKER.to_string(),
            );
            continue;
        }
        let (v, truncated) = truncate(value, profile.max_field_bytes);
        privacy.truncated_bytes += truncated;
        insert_bounded(&mut content.fields, profile.max_fields, name.clone(), v);
    }

    if let Some(body) = &raw.body {
        if profile.capture_mode.persists_body() {
            if classes.is_empty() {
                match std::str::from_utf8(body) {
                    Ok(text) => {
                        let (v, truncated) = truncate(text, profile.max_body_bytes);
                        privacy.truncated_bytes += truncated;
                        content.body = Some(v);
                    }
                    Err(_) => {
                        // Binário não é texto para redigir. O hash já está
                        // registado; o corpo fica de fora.
                        privacy.redacted_field_count += 1;
                    }
                }
            } else {
                // Modo autoriza corpo, mas há segredo detectado. A deny-list
                // ganha ao modo — ver o cabeçalho do módulo.
                privacy.redacted_field_count += 1;
            }
        }
    }

    privacy.redaction_applied =
        privacy.redacted_field_count > 0 || privacy.truncated_bytes > 0 || !classes.is_empty();
    privacy.secret_classes_detected = classes.iter().map(|c| c.label().to_string()).collect();
    RedactionOutcome { content, privacy }
}

/// Corta no limite de bytes sem partir um caracter UTF-8 ao meio.
fn truncate(value: &str, max_bytes: usize) -> (String, u64) {
    if value.len() <= max_bytes {
        return (value.to_string(), 0);
    }
    let mut end = max_bytes;
    while end > 0 && !value.is_char_boundary(end) {
        end -= 1;
    }
    let cut = (value.len() - end) as u64;
    (value[..end].to_string(), cut)
}

/// Inserção com tecto de cardinalidade (§12: "sem alocação sem limite").
fn insert_bounded(
    map: &mut BTreeMap<String, String>,
    max: usize,
    key: String,
    value: String,
) -> bool {
    if map.len() >= max && !map.contains_key(&key) {
        return false;
    }
    map.insert(key, value);
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn raw_with_field(k: &str, v: &str) -> RawContent {
        let mut r = RawContent::default();
        r.fields.insert(k.to_string(), v.to_string());
        r
    }

    #[test]
    fn authorization_nunca_e_persistido_nem_em_full_explicit() {
        let profile = RedactionProfile::default().with_mode(CaptureModeV1::FullExplicit);
        let mut raw = RawContent::default();
        raw.headers.insert(
            "Authorization".into(),
            "Bearer sk-abcdefghijklmnopqrstu".into(),
        );
        let out = apply(&profile, &raw);
        let dump = serde_json::to_string(&out.content).unwrap();
        assert!(!dump.contains("sk-abcdefghijklmnopqrstu"), "{dump}");
        assert!(!dump.to_lowercase().contains("bearer"), "{dump}");
        assert!(out.privacy.redacted_field_count >= 1);
    }

    #[test]
    fn cookie_nunca_sobrevive() {
        let profile = RedactionProfile::default().with_mode(CaptureModeV1::FullExplicit);
        let mut raw = RawContent::default();
        raw.headers
            .insert("Cookie".into(), "session=deadbeef".into());
        let out = apply(&profile, &raw);
        let dump = serde_json::to_string(&out.content).unwrap();
        assert!(!dump.contains("deadbeef"), "{dump}");
    }

    #[test]
    fn metadata_only_guarda_hash_mas_nao_o_corpo() {
        let profile = RedactionProfile::default();
        let raw = RawContent {
            body: Some(b"{\"amount\":5000}".to_vec()),
            ..Default::default()
        };
        let out = apply(&profile, &raw);
        assert!(out.content.body.is_none());
        assert!(out.content.canonical_content_hash.is_some());
        assert_eq!(out.content.content_length, Some(15));
    }

    #[test]
    fn redacted_guarda_o_corpo_quando_nao_ha_segredo() {
        let profile = RedactionProfile::default().with_mode(CaptureModeV1::Redacted);
        let raw = RawContent {
            body: Some(b"{\"amount\":5000}".to_vec()),
            ..Default::default()
        };
        let out = apply(&profile, &raw);
        assert_eq!(out.content.body.as_deref(), Some("{\"amount\":5000}"));
    }

    #[test]
    fn corpo_com_segredo_nao_e_guardado_mesmo_em_modo_que_o_permitiria() {
        let profile = RedactionProfile::default().with_mode(CaptureModeV1::FullExplicit);
        let raw = RawContent {
            body: Some(b"Authorization: Bearer abc".to_vec()),
            ..Default::default()
        };
        let out = apply(&profile, &raw);
        assert!(out.content.body.is_none());
        assert!(out
            .privacy
            .secret_classes_detected
            .contains(&"bearer".to_string()));
    }

    #[test]
    fn campo_chamado_password_e_redigido_mas_a_chave_sobrevive() {
        let profile = RedactionProfile::default().with_mode(CaptureModeV1::Redacted);
        let out = apply(&profile, &raw_with_field("user_password", "hunter2"));
        assert_eq!(
            out.content.fields.get("user_password").map(String::as_str),
            Some(REDACTED_MARKER)
        );
    }

    #[test]
    fn chave_aws_e_classificada() {
        let profile = RedactionProfile::default().with_mode(CaptureModeV1::Redacted);
        let out = apply(&profile, &raw_with_field("note", "AKIAIOSFODNN7EXAMPLE"));
        assert!(out
            .privacy
            .secret_classes_detected
            .contains(&"aws_access_key_id".to_string()));
        assert_eq!(
            out.content.fields.get("note").map(String::as_str),
            Some(REDACTED_MARKER)
        );
    }

    #[test]
    fn jwt_e_classificado() {
        let jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let profile = RedactionProfile::default().with_mode(CaptureModeV1::Redacted);
        let out = apply(&profile, &raw_with_field("assertion", jwt));
        assert!(out
            .privacy
            .secret_classes_detected
            .contains(&"jwt_like".to_string()));
    }

    #[test]
    fn truncagem_conta_bytes_e_nao_parte_utf8() {
        let profile = RedactionProfile {
            max_field_bytes: 5,
            capture_mode: CaptureModeV1::Redacted,
            ..Default::default()
        };
        let out = apply(&profile, &raw_with_field("nota", "ação!!"));
        let v = out.content.fields.get("nota").unwrap();
        assert!(v.len() <= 5);
        assert!(std::str::from_utf8(v.as_bytes()).is_ok());
        assert!(out.privacy.truncated_bytes > 0);
    }

    #[test]
    fn tecto_de_cardinalidade_e_respeitado() {
        let profile = RedactionProfile {
            max_fields: 3,
            capture_mode: CaptureModeV1::Redacted,
            ..Default::default()
        };
        let mut raw = RawContent::default();
        for i in 0..50 {
            raw.fields.insert(format!("f{i}"), "v".into());
        }
        let out = apply(&profile, &raw);
        assert_eq!(out.content.fields.len(), 3);
    }

    #[test]
    fn hash_e_dos_bytes_originais_e_nao_dos_truncados() {
        let profile = RedactionProfile {
            max_body_bytes: 4,
            capture_mode: CaptureModeV1::Redacted,
            ..Default::default()
        };
        let body = b"0123456789".to_vec();
        let out = apply(
            &profile,
            &RawContent {
                body: Some(body.clone()),
                ..Default::default()
            },
        );
        assert_eq!(
            out.content.canonical_content_hash,
            Some(hex32(&content_hash(&body)))
        );
    }
}
