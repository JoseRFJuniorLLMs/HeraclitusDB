//! SPEC-0047 §14–§17 — STIX 2.1 import, with the input limits that keep it
//! from being a denial-of-service surface.
//!
//! # §14 first, because it runs first
//!
//! A threat feed is untrusted input that arrives by the megabyte.  §14 asks
//! for a bound on object size, bundle size, indicator count, relationship
//! count, nesting depth and parse time.  The interesting one is **nesting**:
//! a few kilobytes of `[[[[[…]]]]]` is enough to exhaust a recursive parser's
//! stack, and by the time the parser has seen the depth it has already
//! recursed.  So [`ThreatInputLimits::check_shape`] runs a flat byte scan
//! before any parsing at all — no allocation, no recursion, one pass.
//!
//! # §17 — an unknown object is preserved, not dropped
//!
//! > Objeto desconhecido MUST poder ser: preserved / indexed partially /
//! > exported unchanged when policy permits.
//!
//! Dropping is the tempting default and it is wrong in a specific way: STIX
//! profiles are extended constantly, and an importer that discards what it
//! does not recognise turns "we do not model this yet" into "this
//! intelligence never arrived" — silently, with the object still counted in
//! the feed's object count.  Unknown types become
//! [`ThreatObjectType::Unknown`] carrying the original label, and unmodelled
//! fields land in `unknown_fields`.
//!
//! # The pattern subset, and why it is a subset
//!
//! STIX patterning is a language: comparison expressions, observation
//! operators, qualifiers (`WITHIN`, `REPEATS`, `START`/`STOP`), set
//! membership, regex matching.  Implementing a fraction of it and treating
//! unparsed input as "no indicators" would produce an importer that reports
//! success and silently ingests nothing — the same failure the sentinel's
//! Sigma frontend is deliberately restricted to avoid.
//!
//! So this importer accepts a declared subset — equality comparisons over
//! known object paths, combined with `OR`/`AND` — and reports anything else as
//! [`PatternSupport::Unsupported`], which is preserved on the object and
//! counted in the import report.  An operator can see how much of a feed was
//! understood instead of assuming all of it was.

use serde::Deserialize;
use serde_json::Value;

use super::canonical::{
    canonical_domain, canonical_email, canonical_file_hash, canonical_ip, canonical_url,
    CanonicalError,
};
use super::ir::{
    HashAlgorithm, Indicator, IndicatorState, ThreatObject, ThreatObjectType, ThreatProvenance,
    ThreatRelation,
};
use super::tlp::TlpLevel;

/// SPEC-0047 §14.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ThreatInputLimits {
    pub max_bundle_bytes: usize,
    pub max_object_bytes: usize,
    pub max_objects: usize,
    pub max_indicators_per_object: usize,
    pub max_relationships_per_object: usize,
    pub max_nesting_depth: usize,
}

impl Default for ThreatInputLimits {
    /// Sized for a feed, not for a single hand-written bundle: 64 MiB total,
    /// 100 000 objects.  The nesting limit of 32 is far above anything STIX
    /// legitimately produces (a bundle of objects of properties is depth 4)
    /// and far below what breaks a parser.
    fn default() -> Self {
        Self {
            max_bundle_bytes: 64 * 1024 * 1024,
            max_object_bytes: 1024 * 1024,
            max_objects: 100_000,
            max_indicators_per_object: 1_024,
            max_relationships_per_object: 1_024,
            max_nesting_depth: 32,
        }
    }
}

impl ThreatInputLimits {
    /// Structural pre-check over raw bytes: size and nesting depth, before a
    /// parser is allowed near the input.
    ///
    /// Depth is counted outside string literals — a `{` inside a quoted value
    /// is data, and counting it would reject legitimate bundles that happen to
    /// contain JSON in a description field.
    pub fn check_shape(&self, bytes: &[u8]) -> Result<(), ThreatImportError> {
        if bytes.len() > self.max_bundle_bytes {
            return Err(ThreatImportError::BundleTooLarge {
                bytes: bytes.len(),
                limit: self.max_bundle_bytes,
            });
        }
        let mut depth = 0usize;
        let mut max_depth = 0usize;
        let mut in_string = false;
        let mut escaped = false;
        for &b in bytes {
            if in_string {
                if escaped {
                    escaped = false;
                } else if b == b'\\' {
                    escaped = true;
                } else if b == b'"' {
                    in_string = false;
                }
                continue;
            }
            match b {
                b'"' => in_string = true,
                b'{' | b'[' => {
                    depth += 1;
                    max_depth = max_depth.max(depth);
                    if max_depth > self.max_nesting_depth {
                        return Err(ThreatImportError::TooDeep {
                            depth: max_depth,
                            limit: self.max_nesting_depth,
                        });
                    }
                }
                b'}' | b']' => depth = depth.saturating_sub(1),
                _ => {}
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ThreatImportError {
    #[error("bundle is {bytes} bytes, above the {limit} byte limit (§14)")]
    BundleTooLarge { bytes: usize, limit: usize },
    #[error("bundle nests {depth} levels, above the {limit} level limit (§14)")]
    TooDeep { depth: usize, limit: usize },
    #[error("bundle carries {count} objects, above the {limit} object limit (§14)")]
    TooManyObjects { count: usize, limit: usize },
    #[error("object `{id}` is {bytes} bytes, above the {limit} byte limit (§14)")]
    ObjectTooLarge {
        id: String,
        bytes: usize,
        limit: usize,
    },
    #[error("object `{id}` declares {count} {what}, above the {limit} limit (§14)")]
    TooManyParts {
        id: String,
        what: &'static str,
        count: usize,
        limit: usize,
    },
    #[error("input is not JSON: {0}")]
    NotJson(String),
    #[error("input is not a STIX bundle: {0}")]
    NotABundle(String),
}

/// How much of an indicator's pattern this build understood.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PatternSupport {
    /// Every comparison in the pattern was recognised.
    Full,
    /// Some comparisons were recognised and some were not.
    Partial,
    /// Nothing was recognised.  The object is still imported (§17) but
    /// contributes no indicators to the exact index.
    Unsupported,
}

impl PatternSupport {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Full => "full",
            Self::Partial => "partial",
            Self::Unsupported => "unsupported",
        }
    }
}

/// What an import run produced, including what it could not use.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ImportReport {
    pub objects: usize,
    pub indicators: usize,
    /// Objects whose STIX type this build does not model (§17).
    pub unknown_types: usize,
    /// Indicator objects whose pattern was wholly unparsed.
    pub unsupported_patterns: usize,
    /// Indicator objects whose pattern was only partly parsed.
    pub partial_patterns: usize,
    /// Individual comparison terms rejected by canonicalisation (§21).
    pub rejected_values: Vec<String>,
}

/// SPEC-0047 §15.
pub trait ThreatImporter {
    fn import(&self, bytes: &[u8]) -> Result<Vec<ThreatObject>, ThreatImportError>;
}

/// STIX 2.1 bundle importer.
#[derive(Debug, Clone)]
pub struct StixImporter {
    pub limits: ThreatInputLimits,
    source_id: String,
    collection: String,
    /// Ingestion timestamp, injected rather than read from a clock so an
    /// import replays identically.
    received_at: u64,
}

#[derive(Deserialize)]
struct Bundle {
    #[serde(default)]
    r#type: String,
    #[serde(default)]
    objects: Vec<Value>,
}

impl StixImporter {
    pub fn new(
        source_id: impl Into<String>,
        collection: impl Into<String>,
        received_at: u64,
    ) -> Self {
        Self {
            limits: ThreatInputLimits::default(),
            source_id: source_id.into(),
            collection: collection.into(),
            received_at,
        }
    }

    pub fn with_limits(mut self, limits: ThreatInputLimits) -> Self {
        self.limits = limits;
        self
    }

    /// Import and report.  [`ThreatImporter::import`] is the same thing with
    /// the report dropped.
    pub fn import_with_report(
        &self,
        bytes: &[u8],
    ) -> Result<(Vec<ThreatObject>, ImportReport), ThreatImportError> {
        self.limits.check_shape(bytes)?;
        let bundle: Bundle =
            serde_json::from_slice(bytes).map_err(|e| ThreatImportError::NotJson(e.to_string()))?;
        if bundle.r#type != "bundle" {
            return Err(ThreatImportError::NotABundle(format!(
                "top-level `type` is `{}`, expected `bundle`",
                bundle.r#type
            )));
        }
        if bundle.objects.len() > self.limits.max_objects {
            return Err(ThreatImportError::TooManyObjects {
                count: bundle.objects.len(),
                limit: self.limits.max_objects,
            });
        }

        let source_digest = *blake3::hash(bytes).as_bytes();
        let markings = collect_markings(&bundle.objects);

        let mut out = Vec::new();
        let mut report = ImportReport::default();
        for raw in &bundle.objects {
            let stix_type = raw.get("type").and_then(Value::as_str).unwrap_or("");
            // Marking definitions are metadata for the other objects, not
            // intelligence of their own.
            if stix_type == "marking-definition" || stix_type == "bundle" {
                continue;
            }
            let object = self.convert(raw, &markings, source_digest, &mut report)?;
            report.indicators += object.indicators.len();
            out.push(object);
        }
        report.objects = out.len();
        Ok((out, report))
    }

    fn convert(
        &self,
        raw: &Value,
        markings: &MarkingTable,
        source_digest: [u8; 32],
        report: &mut ImportReport,
    ) -> Result<ThreatObject, ThreatImportError> {
        let stix_type = raw.get("type").and_then(Value::as_str).unwrap_or("unknown");
        let id = raw
            .get("id")
            .and_then(Value::as_str)
            .unwrap_or(stix_type)
            .to_owned();

        let serialised = serde_json::to_vec(raw).unwrap_or_default();
        if serialised.len() > self.limits.max_object_bytes {
            return Err(ThreatImportError::ObjectTooLarge {
                id,
                bytes: serialised.len(),
                limit: self.limits.max_object_bytes,
            });
        }

        let object_type = map_type(stix_type);
        if matches!(object_type, ThreatObjectType::Unknown(_)) {
            report.unknown_types += 1;
        }

        // §23 — the marking of the object, or the most restrictive default.
        let tlp = markings.resolve(raw);

        let confidence = raw
            .get("confidence")
            .and_then(Value::as_u64)
            .map(|c| c.min(100) as u8)
            // STIX makes `confidence` optional. Absent is not "certain": it is
            // "unstated", and the neutral value is the middle of the scale, not
            // the top.
            .unwrap_or(50);

        let provenance = ThreatProvenance {
            source_id: self.source_id.clone(),
            collection: self.collection.clone(),
            received_at: self.received_at,
            source_object_id: id.clone(),
            source_digest,
            confidence,
            tlp,
        };

        let mut object = ThreatObject::new(
            id.clone(),
            object_type,
            provenance,
            *blake3::hash(&serialised).as_bytes(),
        );
        object.source_version = raw
            .get("spec_version")
            .and_then(Value::as_str)
            .unwrap_or("2.1")
            .to_owned();
        object.valid_from = raw
            .get("valid_from")
            .and_then(Value::as_str)
            .and_then(parse_rfc3339_millis);
        object.valid_until = raw
            .get("valid_until")
            .and_then(Value::as_str)
            .and_then(parse_rfc3339_millis);
        if raw.get("revoked").and_then(Value::as_bool).unwrap_or(false) {
            object.state = IndicatorState::Revoked;
        }

        if stix_type == "indicator" {
            let pattern = raw.get("pattern").and_then(Value::as_str).unwrap_or("");
            let (indicators, support, rejected) = parse_pattern(pattern);
            match support {
                PatternSupport::Unsupported if !pattern.is_empty() => {
                    report.unsupported_patterns += 1
                }
                PatternSupport::Partial => report.partial_patterns += 1,
                _ => {}
            }
            report.rejected_values.extend(rejected);
            if indicators.len() > self.limits.max_indicators_per_object {
                return Err(ThreatImportError::TooManyParts {
                    id,
                    what: "indicators",
                    count: indicators.len(),
                    limit: self.limits.max_indicators_per_object,
                });
            }
            object.indicators = indicators;
            object.unknown_fields.insert(
                "x_heraclitus_pattern_support".into(),
                Value::String(support.label().into()),
            );
            // §17 — the pattern is kept verbatim so an unsupported one can be
            // re-exported unchanged, and so an operator can see what we could
            // not read.
            object
                .unknown_fields
                .insert("pattern".into(), Value::String(pattern.to_owned()));
        }

        if stix_type == "relationship" {
            let relationship_type = raw
                .get("relationship_type")
                .and_then(Value::as_str)
                .unwrap_or("related-to")
                .to_owned();
            if let Some(target) = raw.get("target_ref").and_then(Value::as_str) {
                object.relationships.push(ThreatRelation {
                    relationship_type,
                    target_object_id: target.to_owned(),
                });
            }
        }
        if object.relationships.len() > self.limits.max_relationships_per_object {
            return Err(ThreatImportError::TooManyParts {
                id,
                what: "relationships",
                count: object.relationships.len(),
                limit: self.limits.max_relationships_per_object,
            });
        }

        // §5/§17 — everything this build does not model is preserved.
        if let Some(map) = raw.as_object() {
            for (key, value) in map {
                if !MODELLED_FIELDS.contains(&key.as_str()) {
                    object.unknown_fields.insert(key.clone(), value.clone());
                }
            }
        }
        Ok(object)
    }
}

impl ThreatImporter for StixImporter {
    fn import(&self, bytes: &[u8]) -> Result<Vec<ThreatObject>, ThreatImportError> {
        self.import_with_report(bytes).map(|(objects, _)| objects)
    }
}

/// Fields the IR models directly; everything else is carried in
/// `unknown_fields` so §17 stays satisfiable.
const MODELLED_FIELDS: [&str; 9] = [
    "type",
    "id",
    "spec_version",
    "confidence",
    "valid_from",
    "valid_until",
    "revoked",
    "relationship_type",
    "target_ref",
];

/// SPEC-0047 §16 — the minimum mapping.  Anything else keeps its label (§5).
fn map_type(stix_type: &str) -> ThreatObjectType {
    match stix_type {
        "indicator" => ThreatObjectType::Indicator,
        "malware" => ThreatObjectType::Malware,
        "tool" => ThreatObjectType::Tool,
        "infrastructure" => ThreatObjectType::Infrastructure,
        "campaign" => ThreatObjectType::Campaign,
        "threat-actor" => ThreatObjectType::ThreatActor,
        "vulnerability" => ThreatObjectType::Vulnerability,
        "attack-pattern" => ThreatObjectType::AttackPattern,
        "incident" => ThreatObjectType::Incident,
        "report" => ThreatObjectType::Report,
        // `relationship` and `sighting` are in §16's list and are carried as
        // themselves rather than being forced into one of the ten: they
        // describe links between objects, not an object.
        other => ThreatObjectType::Unknown(other.to_owned()),
    }
}

/// Resolves `object_marking_refs` to a TLP level.
#[derive(Debug, Default)]
struct MarkingTable {
    by_id: std::collections::BTreeMap<String, TlpLevel>,
}

impl MarkingTable {
    /// §23 — the object's marking is the most restrictive of its references.
    /// An unresolvable reference contributes [`TlpLevel::Red`]: a marking we
    /// cannot read is not a marking we may ignore.
    fn resolve(&self, raw: &Value) -> TlpLevel {
        let Some(refs) = raw.get("object_marking_refs").and_then(Value::as_array) else {
            return TlpLevel::Red;
        };
        if refs.is_empty() {
            return TlpLevel::Red;
        }
        TlpLevel::most_restrictive(refs.iter().map(|r| {
            r.as_str()
                .and_then(|id| self.by_id.get(id).copied())
                .unwrap_or(TlpLevel::Red)
        }))
    }
}

fn collect_markings(objects: &[Value]) -> MarkingTable {
    let mut table = MarkingTable::default();
    for raw in objects {
        if raw.get("type").and_then(Value::as_str) != Some("marking-definition") {
            continue;
        }
        let Some(id) = raw.get("id").and_then(Value::as_str) else {
            continue;
        };
        // TLP 2.0 puts the level in `name`; TLP 1.0 used `definition.tlp`.
        let level = raw
            .get("name")
            .and_then(Value::as_str)
            .and_then(TlpLevel::parse)
            .or_else(|| {
                raw.get("definition")
                    .and_then(|d| d.get("tlp"))
                    .and_then(Value::as_str)
                    .and_then(TlpLevel::parse)
            });
        if let Some(level) = level {
            table.by_id.insert(id.to_owned(), level);
        }
    }
    table
}

/// Parse the declared subset of STIX patterning.
///
/// Accepted: `[path = 'value']`, and several such comparisons joined by `OR`
/// or `AND` inside one observation expression.  Everything else — `LIKE`,
/// `MATCHES`, `IN`, `NOT`, `>`/`<`, qualifiers, multiple observation
/// expressions — is reported, not guessed.
fn parse_pattern(pattern: &str) -> (Vec<Indicator>, PatternSupport, Vec<String>) {
    let mut indicators = Vec::new();
    let mut rejected = Vec::new();
    let mut terms = 0usize;
    let mut recognised = 0usize;

    for segment in pattern.split(['[', ']']) {
        let segment = segment.trim();
        if segment.is_empty() {
            continue;
        }
        for term in split_terms(segment) {
            let term = term.trim();
            if term.is_empty() {
                continue;
            }
            terms += 1;
            match parse_comparison(term) {
                Ok(Some(indicator)) => {
                    recognised += 1;
                    indicators.push(indicator);
                }
                // A recognised path whose value failed canonicalisation: the
                // term was understood, the value was refused (§21).
                Err(reason) => {
                    recognised += 1;
                    rejected.push(reason);
                }
                Ok(None) => {}
            }
        }
    }

    let support = if terms == 0 || recognised == 0 {
        PatternSupport::Unsupported
    } else if recognised == terms {
        PatternSupport::Full
    } else {
        PatternSupport::Partial
    };
    (indicators, support, rejected)
}

fn split_terms(segment: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut rest = segment;
    loop {
        let next = [" OR ", " AND ", " or ", " and "]
            .iter()
            .filter_map(|sep| rest.find(sep).map(|i| (i, sep.len())))
            .min_by_key(|(i, _)| *i);
        match next {
            Some((i, len)) => {
                out.push(&rest[..i]);
                rest = &rest[i + len..];
            }
            None => {
                out.push(rest);
                return out;
            }
        }
    }
}

/// `ipv4-addr:value = '198.51.100.1'` → an indicator.
///
/// `Ok(None)` means the term's shape or path is not in the supported subset.
/// `Err` means the path *was* supported and the value was refused by §21 — a
/// distinction that matters, because the first is our gap and the second is
/// the feed's.
fn parse_comparison(term: &str) -> Result<Option<Indicator>, String> {
    let Some((lhs, rhs)) = term.split_once('=') else {
        return Ok(None);
    };
    // Reject the operators that look like `=` but are not: `!=`, `>=`, `<=`.
    if lhs.ends_with('!') || lhs.ends_with('>') || lhs.ends_with('<') {
        return Ok(None);
    }
    let path = lhs.trim().trim_start_matches('(').trim();
    let value = rhs
        .trim()
        .trim_end_matches(')')
        .trim()
        .trim_matches('\'')
        .trim_matches('"');
    if value.is_empty() {
        return Ok(None);
    }
    let refuse = |e: CanonicalError| format!("{path} = '{value}': {e}");
    match path {
        "ipv4-addr:value" | "ipv6-addr:value" | "network-traffic:dst_ref.value" => {
            canonical_ip(value).map(Some).map_err(refuse)
        }
        "domain-name:value" => canonical_domain(value)
            .map(|d| Some(Indicator::Domain(d)))
            .map_err(refuse),
        "url:value" => canonical_url(value)
            .map(|u| Some(Indicator::Url(u)))
            .map_err(refuse),
        "email-addr:value" => canonical_email(value).map(Some).map_err(refuse),
        "user-agent:value" => Ok(Some(Indicator::UserAgent(value.to_owned()))),
        "x509-certificate:hashes.'SHA-256'" | "x509-certificate:hashes.SHA-256" => Ok(Some(
            Indicator::CertificateFingerprint(value.as_bytes().to_vec()),
        )),
        other => {
            if let Some(algorithm) = file_hash_algorithm(other) {
                canonical_file_hash(algorithm, value)
                    .map(Some)
                    .map_err(refuse)
            } else {
                Ok(None)
            }
        }
    }
}

fn file_hash_algorithm(path: &str) -> Option<HashAlgorithm> {
    let rest = path.strip_prefix("file:hashes.")?;
    let name = rest
        .trim_matches('\'')
        .trim_matches('"')
        .to_ascii_uppercase();
    Some(match name.as_str() {
        "MD5" => HashAlgorithm::Md5,
        "SHA-1" | "SHA1" => HashAlgorithm::Sha1,
        "SHA-256" | "SHA256" => HashAlgorithm::Sha256,
        "SHA-512" | "SHA512" => HashAlgorithm::Sha512,
        "SHA3-256" => HashAlgorithm::Sha3_256,
        "SSDEEP" => HashAlgorithm::Ssdeep,
        "TLSH" => HashAlgorithm::Tlsh,
        other => HashAlgorithm::Custom(other.to_owned()),
    })
}

/// Minimal RFC 3339 → epoch milliseconds, for the `2026-08-29T12:34:56.789Z`
/// shape STIX uses.
///
/// Written here rather than pulled in with a date crate: the sentinel has no
/// time dependency and this is the only place it needs one. Offsets other than
/// `Z` return `None` — STIX 2.1 requires UTC, and quietly treating `+03:00` as
/// UTC would shift an expiry by three hours in the direction that keeps a dead
/// indicator alive.
fn parse_rfc3339_millis(value: &str) -> Option<u64> {
    let value = value.strip_suffix('Z')?;
    let (date, time) = value.split_once('T')?;
    let mut d = date.split('-');
    let year: i64 = d.next()?.parse().ok()?;
    let month: i64 = d.next()?.parse().ok()?;
    let day: i64 = d.next()?.parse().ok()?;
    // Auditoria 2026-09-05 (A11): o ano tem de ser limitado AQUI, antes de
    // `days_from_civil`, porque essa função já transborda sozinha no `y - 1`
    // com um ano perto de `i64::MAX`.  `0..=9999` é exactamente o perfil que o
    // STIX 2.1 permite (`date-fullyear = 4DIGIT`), por isso não recusa nenhum
    // timestamp legítimo — e mantém `days` abaixo de ~2,9 milhões, o que põe a
    // aritmética de baixo fora do alcance do transbordo.
    if d.next().is_some()
        || !(0..=9999).contains(&year)
        || !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
    {
        return None;
    }
    let (hms, frac) = match time.split_once('.') {
        Some((h, f)) => (h, f),
        None => (time, ""),
    };
    let mut t = hms.split(':');
    let hour: i64 = t.next()?.parse().ok()?;
    let minute: i64 = t.next()?.parse().ok()?;
    let second: i64 = t.next()?.parse().ok()?;
    // Auditoria 2026-09-05 (A11): faltava o lado de baixo.  `hour > 23` deixa
    // passar `-9000000000000000`, que transborda em `hour * 3_600`; e um
    // minuto negativo nem chegava a transbordar — devolvia em silêncio um
    // instante anterior ao que a data diz, que é pior do que recusar.
    if t.next().is_some()
        || !(0..=23).contains(&hour)
        || !(0..=59).contains(&minute)
        || !(0..=60).contains(&second)
    {
        return None;
    }
    let millis: i64 = if frac.is_empty() {
        0
    } else {
        let digits: String = frac.chars().take(3).collect();
        // Auditoria 2026-09-05 (A01): `take(3)` limita CARACTERES mas
        // `digits.len()` conta BYTES, e o expoente de `pow` é `u32` — uma
        // fracção com um carácter multi-byte (".ééZ") dava `3 - 4u32`, uma
        // subtracção que transborda. Com `overflow-checks = true` isso é um
        // pânico no meio da importação de um feed de terceiros, que atravessa
        // o `Err` que `ThreatPlane::load` apanha e derruba o arranque.
        // Exigir dígitos ASCII antes de calcular a escala fecha o buraco na
        // raiz (`digits.len() <= 3` passa a ser garantido) e ainda recusa o
        // sinal que o `parse::<i64>` aceitava: ".-12" valia -12 ms e deslocava
        // o instante para trás em silêncio.
        if !digits.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        let scale = 10i64.pow(3 - digits.len() as u32);
        digits.parse::<i64>().ok()? * scale
    };
    let days = days_from_civil(year, month, day);
    // Aritmética verificada como cinto e suspensórios: com os domínios acima
    // nada disto pode transbordar, mas a entrada vem de um feed de terceiros e
    // `overflow-checks = true` transforma qualquer folga futura num pânico —
    // que atravessa o `Err` de `ThreatPlane::load` e derruba o arranque.
    // `None` é o que o chamador (`and_then`, em `convert`) já sabe tratar.
    let total = days
        .checked_mul(86_400)?
        .checked_add(hour * 3_600 + minute * 60 + second)?;
    u64::try_from(total.checked_mul(1_000)?.checked_add(millis)?).ok()
}

/// Howard Hinnant's `days_from_civil`: civil date to days since 1970-01-01.
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

#[cfg(test)]
mod tests {
    use super::*;

    fn importer() -> StixImporter {
        StixImporter::new("oasis-fixture", "collection-1", 1_000)
    }

    fn bundle(objects: &str) -> Vec<u8> {
        format!(r#"{{"type":"bundle","id":"bundle--1","objects":[{objects}]}}"#).into_bytes()
    }

    #[test]
    fn imports_the_indicator_types_of_16() {
        let raw = bundle(
            r#"
            {"type":"indicator","id":"indicator--1","spec_version":"2.1","confidence":90,
             "pattern":"[ipv4-addr:value = '198.51.100.1']","valid_from":"2026-01-01T00:00:00Z"},
            {"type":"indicator","id":"indicator--2","pattern":"[domain-name:value = 'EVIL.com']"},
            {"type":"indicator","id":"indicator--3",
             "pattern":"[file:hashes.'SHA-256' = 'ABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABAB']"},
            {"type":"malware","id":"malware--1","name":"x"},
            {"type":"threat-actor","id":"threat-actor--1"}
            "#,
        );
        let (objects, report) = importer().import_with_report(&raw).unwrap();
        assert_eq!(objects.len(), 5);
        assert_eq!(report.indicators, 3);

        assert_eq!(
            objects[0].indicators[0],
            canonical_ip("198.51.100.1").unwrap()
        );
        assert_eq!(objects[0].confidence(), 90);
        assert_eq!(objects[0].valid_from, Some(1_767_225_600_000));
        assert_eq!(
            objects[1].indicators[0],
            Indicator::Domain("evil.com".into()),
            "§21 canonicalisation happens on the way in"
        );
        assert_eq!(objects[3].object_type, ThreatObjectType::Malware);
        assert_eq!(objects[4].object_type, ThreatObjectType::ThreatActor);
    }

    #[test]
    fn an_unknown_type_is_preserved_rather_than_dropped() {
        // §17.  Dropping would turn "not modelled" into "never arrived".
        let raw = bundle(
            r#"{"type":"x-acme-thing","id":"x-acme-thing--1","x_custom":{"a":1},"name":"n"}"#,
        );
        let (objects, report) = importer().import_with_report(&raw).unwrap();
        assert_eq!(objects.len(), 1);
        assert_eq!(report.unknown_types, 1);
        assert_eq!(
            objects[0].object_type,
            ThreatObjectType::Unknown("x-acme-thing".into())
        );
        assert!(objects[0].unknown_fields.contains_key("x_custom"));
        assert!(objects[0].unknown_fields.contains_key("name"));
    }

    #[test]
    fn an_unsupported_pattern_is_reported_not_silently_empty() {
        // The failure this prevents: an importer that returns success and
        // ingests nothing.
        let raw = bundle(
            r#"{"type":"indicator","id":"indicator--9","pattern":"[file:name MATCHES '^evil.*']"}"#,
        );
        let (objects, report) = importer().import_with_report(&raw).unwrap();
        assert!(objects[0].indicators.is_empty());
        assert_eq!(report.unsupported_patterns, 1);
        assert_eq!(
            objects[0].unknown_fields["x_heraclitus_pattern_support"],
            Value::String("unsupported".into())
        );
        assert!(
            objects[0].unknown_fields.contains_key("pattern"),
            "the original pattern must survive for re-export (§17)"
        );
    }

    #[test]
    fn a_partly_understood_pattern_is_labelled_partial() {
        let raw = bundle(
            r#"{"type":"indicator","id":"indicator--10",
                "pattern":"[ipv4-addr:value = '198.51.100.1' OR file:name MATCHES 'x']"}"#,
        );
        let (objects, report) = importer().import_with_report(&raw).unwrap();
        assert_eq!(objects[0].indicators.len(), 1);
        assert_eq!(report.partial_patterns, 1);
        assert_eq!(
            objects[0].unknown_fields["x_heraclitus_pattern_support"],
            Value::String("partial".into())
        );
    }

    #[test]
    fn a_supported_path_with_a_bad_value_is_reported_as_the_feeds_problem() {
        let raw = bundle(
            r#"{"type":"indicator","id":"indicator--11","pattern":"[ipv4-addr:value = '999.1.1.1']"}"#,
        );
        let (objects, report) = importer().import_with_report(&raw).unwrap();
        assert!(objects[0].indicators.is_empty());
        assert_eq!(report.rejected_values.len(), 1);
        assert!(report.rejected_values[0].contains("999.1.1.1"));
        // Every term was understood, so the pattern itself is not the gap.
        assert_eq!(report.unsupported_patterns, 0);
    }

    #[test]
    fn multiple_comparisons_in_one_observation_are_all_taken() {
        let raw = bundle(
            r#"{"type":"indicator","id":"indicator--12",
                "pattern":"[domain-name:value = 'a.example' OR domain-name:value = 'b.example']"}"#,
        );
        let (objects, _) = importer().import_with_report(&raw).unwrap();
        assert_eq!(objects[0].indicators.len(), 2);
    }

    #[test]
    fn inequality_operators_are_not_mistaken_for_equality() {
        for pattern in [
            "[file:size != '100']",
            "[file:size >= '100']",
            "[file:size <= '100']",
        ] {
            let raw = bundle(&format!(
                r#"{{"type":"indicator","id":"indicator--13","pattern":"{pattern}"}}"#
            ));
            let (objects, _) = importer().import_with_report(&raw).unwrap();
            assert!(
                objects[0].indicators.is_empty(),
                "`{pattern}` must not be read as equality"
            );
        }
    }

    #[test]
    fn tlp_markings_are_resolved_and_the_most_restrictive_wins() {
        let raw = bundle(
            r#"
            {"type":"marking-definition","id":"marking-definition--clear","name":"TLP:CLEAR"},
            {"type":"marking-definition","id":"marking-definition--red","name":"TLP:RED"},
            {"type":"indicator","id":"indicator--20","pattern":"[domain-name:value = 'a.example']",
             "object_marking_refs":["marking-definition--clear"]},
            {"type":"indicator","id":"indicator--21","pattern":"[domain-name:value = 'b.example']",
             "object_marking_refs":["marking-definition--clear","marking-definition--red"]}
            "#,
        );
        let (objects, _) = importer().import_with_report(&raw).unwrap();
        assert_eq!(objects[0].tlp(), TlpLevel::Clear);
        assert_eq!(
            objects[1].tlp(),
            TlpLevel::Red,
            "§23: one restricted parent marking is enough"
        );
    }

    #[test]
    fn an_unmarked_or_unresolvable_object_is_red_not_clear() {
        let raw = bundle(
            r#"
            {"type":"indicator","id":"indicator--30","pattern":"[domain-name:value = 'a.example']"},
            {"type":"indicator","id":"indicator--31","pattern":"[domain-name:value = 'b.example']",
             "object_marking_refs":["marking-definition--not-in-this-bundle"]}
            "#,
        );
        let (objects, _) = importer().import_with_report(&raw).unwrap();
        assert_eq!(objects[0].tlp(), TlpLevel::Red);
        assert_eq!(objects[1].tlp(), TlpLevel::Red);
    }

    #[test]
    fn revoked_objects_arrive_revoked() {
        let raw = bundle(
            r#"{"type":"indicator","id":"indicator--40","revoked":true,
                "pattern":"[domain-name:value = 'a.example']"}"#,
        );
        let (objects, _) = importer().import_with_report(&raw).unwrap();
        assert_eq!(objects[0].state, IndicatorState::Revoked);
    }

    #[test]
    fn absent_confidence_is_neutral_not_certain() {
        let raw = bundle(
            r#"{"type":"indicator","id":"indicator--41","pattern":"[domain-name:value = 'a.example']"}"#,
        );
        let (objects, _) = importer().import_with_report(&raw).unwrap();
        assert_eq!(objects[0].confidence(), 50);
    }

    // ---- §14 limits --------------------------------------------------

    #[test]
    fn a_nesting_bomb_is_refused_before_parsing() {
        // The point of the pre-scan: the depth is known before any recursive
        // descent has happened.
        let bomb = format!("[{}{}", "[".repeat(200), "]".repeat(201));
        let err = importer().import(bomb.as_bytes()).unwrap_err();
        assert!(matches!(err, ThreatImportError::TooDeep { .. }), "{err:?}");
    }

    #[test]
    fn braces_inside_strings_do_not_count_as_nesting() {
        // Otherwise a description containing JSON would be rejected as a bomb.
        let raw = bundle(
            r#"{"type":"report","id":"report--1","description":"payload was {{{{{{{{ nested"}"#,
        );
        let limits = ThreatInputLimits {
            max_nesting_depth: 4,
            ..Default::default()
        };
        assert!(importer().with_limits(limits).import(&raw).is_ok());
    }

    #[test]
    fn oversized_bundles_and_objects_are_refused() {
        let raw = bundle(r#"{"type":"report","id":"report--1"}"#);
        let tiny_bundle = ThreatInputLimits {
            max_bundle_bytes: 10,
            ..Default::default()
        };
        assert!(matches!(
            importer().with_limits(tiny_bundle).import(&raw),
            Err(ThreatImportError::BundleTooLarge { .. })
        ));

        let tiny_object = ThreatInputLimits {
            max_object_bytes: 4,
            ..Default::default()
        };
        assert!(matches!(
            importer().with_limits(tiny_object).import(&raw),
            Err(ThreatImportError::ObjectTooLarge { .. })
        ));
    }

    #[test]
    fn too_many_objects_is_refused() {
        let objects = (0..5)
            .map(|i| format!(r#"{{"type":"report","id":"report--{i}"}}"#))
            .collect::<Vec<_>>()
            .join(",");
        let raw = bundle(&objects);
        let limits = ThreatInputLimits {
            max_objects: 3,
            ..Default::default()
        };
        assert!(matches!(
            importer().with_limits(limits).import(&raw),
            Err(ThreatImportError::TooManyObjects { .. })
        ));
    }

    #[test]
    fn non_bundles_and_non_json_are_refused_clearly() {
        assert!(matches!(
            importer().import(b"not json"),
            Err(ThreatImportError::NotJson(_))
        ));
        assert!(matches!(
            importer().import(br#"{"type":"indicator"}"#),
            Err(ThreatImportError::NotABundle(_))
        ));
    }

    // ---- timestamps --------------------------------------------------

    #[test]
    fn rfc3339_parses_only_utc() {
        assert_eq!(parse_rfc3339_millis("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(
            parse_rfc3339_millis("2026-01-01T00:00:00Z"),
            Some(1_767_225_600_000)
        );
        assert_eq!(
            parse_rfc3339_millis("2026-01-01T00:00:00.250Z"),
            Some(1_767_225_600_250)
        );
        assert_eq!(
            parse_rfc3339_millis("2026-01-01T00:00:00+03:00"),
            None,
            "an offset must not be silently read as UTC: it would move an expiry"
        );
        assert_eq!(parse_rfc3339_millis("2026-13-01T00:00:00Z"), None);
        assert_eq!(parse_rfc3339_millis("garbage"), None);
    }

    #[test]
    fn leap_years_are_not_off_by_a_day() {
        // 2024-03-01 is 19783 days after the epoch.
        assert_eq!(
            parse_rfc3339_millis("2024-03-01T00:00:00Z"),
            Some(19_783 * 86_400 * 1_000)
        );
    }

    #[test]
    fn fraccao_de_segundo_com_bytes_nao_ascii_devolve_none_sem_panico() {
        // Auditoria 2026-09-05 (A01): `take(3)` conta CARACTERES e `len()` conta
        // BYTES. Duas letras acentuadas sao 2 caracteres e 4 bytes, logo o
        // expoente `3 - digits.len() as u32` era uma subtraccao u32 que
        // transbordava — panico, e nao `None`, num feed de terceiros.
        assert_eq!(
            parse_rfc3339_millis("2026-01-01T00:00:00.\u{e9}\u{e9}Z"),
            None
        );
        assert_eq!(
            parse_rfc3339_millis("2026-01-01T00:00:00.1\u{e9}\u{e9}Z"),
            None
        );
        // Um sinal nao e um digito de fraccao: `parse::<i64>` aceitava-o e
        // ".-12" deslocava o instante 12 ms para tras em silencio.
        assert_eq!(parse_rfc3339_millis("2026-01-01T00:00:00.-12Z"), None);
        assert_eq!(parse_rfc3339_millis("2026-01-01T00:00:00.+12Z"), None);
        // As fraccoes legitimas continuam a valer o mesmo.
        assert_eq!(
            parse_rfc3339_millis("2026-01-01T00:00:00.250Z"),
            Some(1_767_225_600_250)
        );
        assert_eq!(
            parse_rfc3339_millis("2026-01-01T00:00:00.2Z"),
            Some(1_767_225_600_200)
        );
    }

    #[test]
    fn bundle_com_fraccao_multibyte_e_importado_sem_derrubar_o_arranque() {
        // O caminho real do achado: ThreatPlane::load promete que um feed
        // malformado vai para `files_failed` e nao impede o arranque, e um
        // panico atravessa esse `Err`.
        let raw = bundle(
            r#"{"type":"indicator","id":"indicator--1","spec_version":"2.1",
                "pattern":"[domain-name:value = 'a.com']",
                "valid_from":"2026-01-01T00:00:00.ééZ"}"#,
        );
        let (objects, _) = importer()
            .import_with_report(&raw)
            .expect("o bundle importa");
        assert_eq!(objects.len(), 1);
        assert_eq!(objects[0].valid_from, None);
    }

    #[test]
    fn ano_sem_tecto_e_campos_negativos_devolvem_none_em_vez_de_panico() {
        // Auditoria 2026-09-05 (A11): o ano era `parse::<i64>()` sem limite e
        // hora/minuto/segundo so eram testados pelo lado de cima. Um ano de 9
        // digitos transborda em `total * 1_000`, i64::MAX transborda mais cedo
        // dentro de `days_from_civil` (`y - 1`), e uma hora negativa transborda
        // em `hour * 3_600`.
        assert_eq!(parse_rfc3339_millis("300000000-01-01T00:00:00Z"), None);
        assert_eq!(
            parse_rfc3339_millis("9223372036854775807-01-01T00:00:00Z"),
            None
        );
        assert_eq!(
            parse_rfc3339_millis("1970-01-01T-9000000000000000:00:00Z"),
            None
        );
        // Um minuto negativo nem sequer entrava em panico: devolvia um instante
        // que nunca existiu (60 s antes da meia-noite de 2026-01-01).
        assert_eq!(parse_rfc3339_millis("2026-01-01T00:-1:00Z"), None);
        assert_eq!(parse_rfc3339_millis("2026-01-01T00:00:-1Z"), None);
        // As fronteiras legitimas do perfil RFC 3339 do STIX continuam a passar.
        assert!(parse_rfc3339_millis("9999-12-31T23:59:60Z").is_some());
        assert_eq!(parse_rfc3339_millis("1970-01-01T00:00:00Z"), Some(0));
    }

    #[test]
    fn bundle_com_valid_until_absurdo_e_importado_sem_panico() {
        // Sem janela de validade e um estado que o registo ja trata; um panico
        // no meio da importacao de um feed de terceiros nao e.
        let raw = bundle(
            r#"{"type":"indicator","id":"indicator--1","spec_version":"2.1",
                "pattern":"[ipv4-addr:value = '1.2.3.4']",
                "valid_until":"300000000-01-01T00:00:00Z"}"#,
        );
        let (objects, _) = importer()
            .import_with_report(&raw)
            .expect("o bundle importa");
        assert_eq!(objects.len(), 1);
        assert_eq!(objects[0].valid_until, None);
    }
}
