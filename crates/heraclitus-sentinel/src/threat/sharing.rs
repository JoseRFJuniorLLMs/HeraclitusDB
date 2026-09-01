//! SPEC-0047 §24–§27 — sharing policy, pseudonymisation, sanitisation and the
//! internal-data leak gate.
//!
//! # T8 is a type, not a procedure
//!
//! > Sanitização ocorre antes da exportação.
//!
//! Written as a rule, that is a thing every exporter must remember.  Written
//! as a type, it is a thing no exporter can forget: [`SanitizedThreatObject`]
//! has a private field, so the only way to obtain one is
//! [`ThreatSanitizer::sanitize`], and any export surface that accepts one is
//! therefore guaranteed to have received sanitised content.
//!
//! # §27, and why the LLM is named in it
//!
//! > Exportação MUST falhar se conteúdo contiver secret / private key /
//! > credential / raw token / classified field / prohibited PII — **mesmo que
//! > o LLM recomende compartilhamento**.
//!
//! The spec is anticipating a specific failure: the L4 investigation
//! summarises an incident, concludes the IOC is worth sharing, and its
//! summary quotes the log line that contained the credential.  The gate here
//! runs on bytes and knows nothing about who proposed them, which is the only
//! arrangement in which "even if the model recommends it" means anything.
//!
//! The detector is deliberately **conservative and dumb**: it looks for
//! high-signal shapes (PEM headers, common token prefixes, long
//! high-entropy strings next to credential-ish keys). It will produce false
//! positives, and a false positive costs one blocked export that a human can
//! review — the other error costs a disclosure.
//!
//! # §25 — pseudonymisation
//!
//! > Não utilizar hash simples para identificadores previsíveis.
//! > Utilizar `HMAC(domain_key, canonical_identifier)`.
//!
//! An unkeyed hash of a username, an internal hostname or an RFC 1918 address
//! is reversible by anybody with a wordlist: the input space is tiny.
//! [`Pseudonymizer`] therefore keys the digest, and keys it *per destination*,
//! so two recipients cannot join their pseudonyms to rebuild our inventory.

use std::collections::BTreeMap;

use serde::Serialize;

use super::ir::{Indicator, ThreatObject};
use super::tlp::TlpLevel;

/// SPEC-0047 §24.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SharingPolicy {
    pub destination: String,
    pub maximum_tlp: TlpLevel,
    pub allow_internal_ips: bool,
    pub allow_user_identity: bool,
    pub allow_asset_names: bool,
    pub allow_raw_evidence: bool,
}

impl SharingPolicy {
    /// Everything denied, ceiling at `TLP:CLEAR`.  A policy someone forgot to
    /// fill in must share nothing, not everything.
    pub fn deny_all(destination: impl Into<String>) -> Self {
        Self {
            destination: destination.into(),
            maximum_tlp: TlpLevel::Clear,
            allow_internal_ips: false,
            allow_user_identity: false,
            allow_asset_names: false,
            allow_raw_evidence: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SanitizationError {
    #[error("{marking} exceeds the {maximum} ceiling of destination `{destination}`")]
    TlpCeiling {
        destination: String,
        marking: &'static str,
        maximum: &'static str,
    },
    #[error("object `{object_id}` would leak {category} to `{destination}` (field `{field}`)")]
    InternalDataLeak {
        object_id: String,
        destination: String,
        category: &'static str,
        field: String,
    },
    #[error(
        "nothing left to share for object `{object_id}`: every indicator was withheld by policy"
    )]
    NothingLeftToShare { object_id: String },
}

/// An object that has passed [`ThreatSanitizer::sanitize`].
///
/// The unit field is private, which is the whole mechanism: outside this
/// module the type cannot be constructed, so no export path can be handed
/// unsanitised content by mistake.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct SanitizedThreatObject {
    pub object_id: String,
    pub object_type: String,
    pub tlp: TlpLevel,
    pub destination: String,
    pub indicators: Vec<String>,
    pub confidence: u8,
    pub valid_from: Option<u64>,
    pub valid_until: Option<u64>,
    /// What policy removed, by category, so the recipient (and an auditor)
    /// can see that redaction happened rather than guessing.
    pub withheld: BTreeMap<String, usize>,
    #[serde(skip)]
    _sealed: Sealed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
struct Sealed;

/// SPEC-0047 §25.
#[derive(Clone)]
pub struct Pseudonymizer {
    key: [u8; 32],
}

impl std::fmt::Debug for Pseudonymizer {
    /// The key never reaches a log line, a panic message or a `{:?}` in an
    /// error.  A pseudonymisation key printed once is a pseudonymisation
    /// scheme broken forever, retroactively.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Pseudonymizer { key: <redacted> }")
    }
}

impl Pseudonymizer {
    /// Derive the per-destination key from a deployment secret.
    ///
    /// Different destinations get different keys so that two recipients who
    /// compare notes cannot correlate `user-a1b2…` across both and rebuild the
    /// identity graph they were never given.
    pub fn for_destination(deployment_secret: &[u8], destination: &str) -> Self {
        let mut h = blake3::Hasher::new_derive_key("HRKL:SPEC-0047:pseudonym-domain-key:v1");
        h.update(deployment_secret);
        h.update(&(destination.len() as u64).to_le_bytes());
        h.update(destination.as_bytes());
        Self {
            key: *h.finalize().as_bytes(),
        }
    }

    /// `HMAC(domain_key, canonical_identifier)`.
    ///
    /// BLAKE3's keyed mode is a PRF over the whole input and is the intended
    /// construction for exactly this — an unkeyed `hash(username)` would be a
    /// dictionary lookup away from plaintext.
    pub fn pseudonym(&self, kind: &str, canonical_identifier: &str) -> String {
        let mut h = blake3::Hasher::new_keyed(&self.key);
        h.update(&(kind.len() as u64).to_le_bytes());
        h.update(kind.as_bytes());
        h.update(canonical_identifier.as_bytes());
        format!("{kind}-{}", &h.finalize().to_hex()[..24])
    }
}

/// SPEC-0047 §26.
pub trait ThreatSanitizer {
    fn sanitize(
        &self,
        object: &ThreatObject,
        policy: &SharingPolicy,
    ) -> Result<SanitizedThreatObject, SanitizationError>;
}

/// The default sanitiser: TLP ceiling, indicator filtering, leak gate.
#[derive(Debug, Clone)]
pub struct PolicySanitizer {
    pseudonymizer: Pseudonymizer,
}

impl PolicySanitizer {
    pub fn new(pseudonymizer: Pseudonymizer) -> Self {
        Self { pseudonymizer }
    }
}

impl ThreatSanitizer for PolicySanitizer {
    fn sanitize(
        &self,
        object: &ThreatObject,
        policy: &SharingPolicy,
    ) -> Result<SanitizedThreatObject, SanitizationError> {
        // §23/T5 first: the ceiling is checked before anything is copied, so a
        // TLP:RED object never gets partially rendered into a buffer that some
        // later error path might log.
        if !object.tlp().may_share_to(policy.maximum_tlp) {
            return Err(SanitizationError::TlpCeiling {
                destination: policy.destination.clone(),
                marking: object.tlp().label(),
                maximum: policy.maximum_tlp.label(),
            });
        }

        let mut withheld: BTreeMap<String, usize> = BTreeMap::new();
        let mut indicators = Vec::with_capacity(object.indicators.len());
        for indicator in &object.indicators {
            // §27 runs on every value, before any policy decision could let it
            // through: a credential in a `Custom` indicator is a leak whatever
            // the flags say.
            if let Some(category) = detect_internal_secret(indicator) {
                return Err(SanitizationError::InternalDataLeak {
                    object_id: object.object_id.clone(),
                    destination: policy.destination.clone(),
                    category,
                    field: indicator.kind_label().to_owned(),
                });
            }
            match indicator {
                Indicator::Ip(cidr) if is_internal(cidr) && !policy.allow_internal_ips => {
                    *withheld.entry("internal_ip".into()).or_default() += 1;
                }
                Indicator::Email(address) if !policy.allow_user_identity => {
                    // Withheld, but not erased from the picture: a pseudonym
                    // lets the recipient correlate two reports about the same
                    // mailbox without learning whose it is.
                    indicators.push(self.pseudonymizer.pseudonym("email", address));
                    *withheld.entry("user_identity".into()).or_default() += 1;
                }
                Indicator::Domain(name)
                    if is_internal_hostname(name) && !policy.allow_asset_names =>
                {
                    indicators.push(self.pseudonymizer.pseudonym("asset", name));
                    *withheld.entry("asset_name".into()).or_default() += 1;
                }
                other => indicators.push(render(other)),
            }
        }

        if indicators.is_empty() {
            return Err(SanitizationError::NothingLeftToShare {
                object_id: object.object_id.clone(),
            });
        }

        Ok(SanitizedThreatObject {
            object_id: object.object_id.clone(),
            object_type: object.object_type.label().to_owned(),
            tlp: object.tlp(),
            destination: policy.destination.clone(),
            indicators,
            confidence: object.confidence(),
            valid_from: object.valid_from,
            valid_until: object.valid_until,
            withheld,
            _sealed: Sealed,
        })
    }
}

fn render(indicator: &Indicator) -> String {
    match indicator {
        Indicator::Ip(cidr) => cidr.to_string(),
        Indicator::Domain(v)
        | Indicator::Url(v)
        | Indicator::Email(v)
        | Indicator::UserAgent(v) => v.clone(),
        Indicator::FileHash { algorithm, value } => {
            format!("{}:{}", algorithm.label(), hex(value))
        }
        Indicator::CertificateFingerprint(value) => hex(value),
        Indicator::Custom { kind, value } => format!("{kind}:{value}"),
    }
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// RFC 1918 / RFC 4193 / loopback / link-local.
fn is_internal(cidr: &super::ir::IpCidr) -> bool {
    use std::net::IpAddr;
    match cidr.addr() {
        IpAddr::V4(v4) => {
            v4.is_private() || v4.is_loopback() || v4.is_link_local() || v4.is_unspecified()
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                // fc00::/7 unique local, fe80::/10 link local.
                || (v6.segments()[0] & 0xfe00) == 0xfc00
                || (v6.segments()[0] & 0xffc0) == 0xfe80
        }
    }
}

/// Hostnames that name our own estate rather than an adversary's.
fn is_internal_hostname(name: &str) -> bool {
    const INTERNAL_SUFFIXES: [&str; 6] = [
        ".local",
        ".internal",
        ".intranet",
        ".lan",
        ".corp",
        ".home.arpa",
    ];
    INTERNAL_SUFFIXES.iter().any(|s| name.ends_with(s)) || !name.contains('.')
}

/// SPEC-0047 §27 — the leak gate.
///
/// Returns the category of the thing that must not leave, or `None`.
/// Deliberately shape-based rather than clever: a regex zoo would find more
/// and would also be the thing that breaks and lets something through.
fn detect_internal_secret(indicator: &Indicator) -> Option<&'static str> {
    let haystack = match indicator {
        Indicator::Url(v) | Indicator::UserAgent(v) => v.clone(),
        Indicator::Custom { kind, value } => format!("{kind}={value}"),
        _ => return None,
    };
    let lower = haystack.to_ascii_lowercase();

    if lower.contains("-----begin") && lower.contains("private key") {
        return Some("private key");
    }
    for prefix in [
        "aws_secret_access_key",
        "aws_access_key_id",
        "ghp_",
        "github_pat_",
        "xoxb-",
        "xoxp-",
        "sk-",
        "bearer ",
        "authorization:",
    ] {
        if lower.contains(prefix) {
            return Some("credential");
        }
    }
    for key in ["password", "passwd", "secret", "api_key", "apikey", "token"] {
        if let Some(pos) = lower.find(key) {
            let tail = &haystack[pos + key.len()..];
            let value = tail
                .trim_start_matches([':', '=', ' ', '"', '\''])
                .split(['&', ' ', '"', '\'', ';'])
                .next()
                .unwrap_or("");
            // A URL parameter literally named `token` with a substantial
            // opaque value is the case §27 is about.  A short value is more
            // likely a word than a secret.
            if value.len() >= 12 && looks_opaque(value) {
                return Some("raw token");
            }
        }
    }
    if lower.contains("classification:") || lower.contains("classified") {
        return Some("classified field");
    }
    None
}

/// Enough character-class variety that the string is unlikely to be prose.
fn looks_opaque(value: &str) -> bool {
    let mut digits = 0usize;
    let mut letters = 0usize;
    for c in value.chars() {
        if c.is_ascii_digit() {
            digits += 1;
        } else if c.is_ascii_alphabetic() {
            letters += 1;
        } else if !matches!(c, '-' | '_' | '.' | '+' | '/' | '=') {
            return false;
        }
    }
    digits > 0 && letters > 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::threat::canonical::canonical_ip;
    use crate::threat::ir::{ThreatObjectType, ThreatProvenance};

    fn sanitizer() -> PolicySanitizer {
        PolicySanitizer::new(Pseudonymizer::for_destination(b"deployment", "partner"))
    }

    fn object(tlp: TlpLevel, indicators: Vec<Indicator>) -> ThreatObject {
        let mut o = ThreatObject::new(
            "obj",
            ThreatObjectType::Indicator,
            ThreatProvenance {
                source_id: "feed".into(),
                collection: "c".into(),
                received_at: 0,
                source_object_id: "o".into(),
                source_digest: [0; 32],
                confidence: 70,
                tlp,
            },
            [0; 32],
        );
        o.indicators = indicators;
        o
    }

    fn open_policy() -> SharingPolicy {
        SharingPolicy {
            destination: "partner".into(),
            maximum_tlp: TlpLevel::Amber,
            allow_internal_ips: false,
            allow_user_identity: false,
            allow_asset_names: false,
            allow_raw_evidence: false,
        }
    }

    #[test]
    fn tlp_red_never_leaves_towards_an_unauthorised_destination() {
        // Gate T5.
        let err = sanitizer()
            .sanitize(
                &object(TlpLevel::Red, vec![Indicator::Domain("evil.com".into())]),
                &open_policy(),
            )
            .unwrap_err();
        assert!(matches!(err, SanitizationError::TlpCeiling { .. }));
    }

    #[test]
    fn a_default_policy_shares_nothing_above_clear() {
        let p = SharingPolicy::deny_all("unknown");
        assert_eq!(p.maximum_tlp, TlpLevel::Clear);
        assert!(sanitizer()
            .sanitize(
                &object(TlpLevel::Green, vec![Indicator::Domain("evil.com".into())]),
                &p
            )
            .is_err());
    }

    #[test]
    fn internal_addresses_are_withheld_and_the_removal_is_declared() {
        let o = object(
            TlpLevel::Green,
            vec![
                canonical_ip("10.1.2.3").unwrap(),
                canonical_ip("203.0.113.9").unwrap(),
            ],
        );
        let out = sanitizer().sanitize(&o, &open_policy()).unwrap();
        assert_eq!(out.indicators, vec!["203.0.113.9/32"]);
        assert_eq!(out.withheld["internal_ip"], 1);
    }

    #[test]
    fn identities_become_stable_pseudonyms_not_deletions() {
        let o = object(
            TlpLevel::Green,
            vec![Indicator::Email("alice@corp.example".into())],
        );
        let a = sanitizer().sanitize(&o, &open_policy()).unwrap();
        let b = sanitizer().sanitize(&o, &open_policy()).unwrap();
        assert_eq!(a.indicators, b.indicators, "pseudonyms must be stable");
        assert!(a.indicators[0].starts_with("email-"));
        assert!(
            !a.indicators[0].contains("alice"),
            "the identity must not survive"
        );
        assert_eq!(a.withheld["user_identity"], 1);
    }

    #[test]
    fn two_destinations_cannot_join_their_pseudonyms() {
        // §25 — different domain keys, so a recipient comparing notes with
        // another recipient learns nothing.
        let a = Pseudonymizer::for_destination(b"deployment", "partner-a");
        let b = Pseudonymizer::for_destination(b"deployment", "partner-b");
        assert_ne!(
            a.pseudonym("email", "alice@corp.example"),
            b.pseudonym("email", "alice@corp.example")
        );
    }

    #[test]
    fn a_pseudonym_is_keyed_not_a_plain_hash() {
        // A plain hash of a predictable identifier is a dictionary lookup.
        let keyed = Pseudonymizer::for_destination(b"deployment", "partner")
            .pseudonym("email", "alice@corp.example");
        let plain = format!(
            "email-{}",
            &blake3::hash(b"alice@corp.example").to_hex()[..24]
        );
        assert_ne!(keyed, plain);
    }

    #[test]
    fn the_key_never_appears_in_debug_output() {
        let p = Pseudonymizer::for_destination(b"deployment", "partner");
        let rendered = format!("{p:?}");
        assert!(rendered.contains("<redacted>"));
        assert!(!rendered.contains("key: ["));
    }

    #[test]
    fn credentials_block_the_export_regardless_of_who_proposed_them() {
        // §27 — "mesmo que o LLM recomende compartilhamento".  The gate reads
        // bytes and has no parameter for provenance of the suggestion.
        for (indicator, expected) in [
            (
                Indicator::Url("https://evil.com/cb?token=A1b2C3d4E5f6G7".into()),
                "raw token",
            ),
            (
                Indicator::Custom {
                    kind: "note".into(),
                    value: "-----BEGIN RSA PRIVATE KEY-----".into(),
                },
                "private key",
            ),
            (
                Indicator::Custom {
                    kind: "header".into(),
                    value: "Authorization: Bearer abc".into(),
                },
                "credential",
            ),
            (
                Indicator::Custom {
                    kind: "meta".into(),
                    value: "classification: RESERVADO".into(),
                },
                "classified field",
            ),
        ] {
            let err = sanitizer()
                .sanitize(&object(TlpLevel::Clear, vec![indicator]), &open_policy())
                .unwrap_err();
            match err {
                SanitizationError::InternalDataLeak { category, .. } => {
                    assert_eq!(category, expected)
                }
                other => panic!("expected a leak refusal, got {other:?}"),
            }
        }
    }

    #[test]
    fn an_ordinary_url_is_not_mistaken_for_a_secret() {
        let out = sanitizer()
            .sanitize(
                &object(
                    TlpLevel::Clear,
                    vec![Indicator::Url("http://evil.com/login?user=bob".into())],
                ),
                &open_policy(),
            )
            .unwrap();
        assert_eq!(out.indicators.len(), 1);
    }

    #[test]
    fn an_object_stripped_to_nothing_is_an_error_not_an_empty_export() {
        // Publishing an object id with no content tells the recipient that
        // something exists and nothing about it — all of the disclosure risk
        // of naming it, none of the value.
        let err = sanitizer()
            .sanitize(
                &object(TlpLevel::Green, vec![canonical_ip("192.168.0.1").unwrap()]),
                &open_policy(),
            )
            .unwrap_err();
        assert!(matches!(err, SanitizationError::NothingLeftToShare { .. }));
    }
}
