//! SPEC-0047 §21 — canonicalisation before indexing.
//!
//! The rule that governs every function here is the second sentence of §21:
//!
//! > Normalização MUST NOT alterar semanticamente indicadores.
//!
//! That cuts both ways, and the second direction is the one that gets
//! implemented wrong.  Under-normalising costs recall: `EVIL.COM` and
//! `evil.com` land in different buckets and neither matches the other.
//! **Over**-normalising costs correctness, silently: strip a trailing slash
//! from `http://host/` and you have changed nothing, but strip a trailing dot
//! from `evil.com.` inside a *URL* and you may have changed which host is
//! resolved.  So the URL rules here are deliberately conservative, and every
//! transformation that could alter meaning is refused instead of guessed.
//!
//! ## Why there is no IDNA implementation here
//!
//! §21 asks for IDNA domain normalisation.  Doing it correctly means UTS-46
//! mapping, bidi checks and a Unicode table — none of which the sentinel crate
//! carries, and all of which are exactly where homograph bugs live.  A
//! half-implementation would map some non-ASCII domains and mangle others, and
//! the mangled ones would be *stored* mangled, never matching the traffic they
//! were meant to catch.
//!
//! So a non-ASCII domain is **rejected** with
//! [`CanonicalError::IdnaUnsupported`] rather than approximated.  A rejected
//! indicator is visible at the gate; a mis-mapped one is invisible until it
//! fails to fire.  Already-encoded punycode (`xn--…`) is ASCII and passes
//! through normally, which covers the feeds that do their own encoding.

use std::net::IpAddr;

use super::ir::{HashAlgorithm, Indicator, IpCidr};

/// Longest legal DNS name, and the longest legal label (RFC 1035 §2.3.4).
const MAX_DOMAIN_LEN: usize = 253;
const MAX_LABEL_LEN: usize = 63;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CanonicalError {
    #[error("empty indicator value")]
    Empty,
    #[error("`{0}` is not an IP address or CIDR block")]
    NotAnIp(String),
    #[error("`{0}` is not a valid domain name")]
    NotADomain(String),
    #[error("non-ASCII domain `{0}`: IDNA normalisation is not implemented in this build, and approximating it would store an indicator that never matches")]
    IdnaUnsupported(String),
    #[error("`{0}` is not an absolute URL with a supported scheme")]
    NotAUrl(String),
    #[error("`{value}` is not lowercase hex of {expected} bytes for {algorithm}")]
    BadDigest {
        value: String,
        algorithm: String,
        expected: usize,
    },
}

/// Canonical IP or CIDR.  Accepts `203.0.113.4`, `203.0.113.0/24`, `2001:db8::/32`.
///
/// A v4-mapped v6 address (`::ffff:203.0.113.4`) is folded to its v4 form here,
/// once, at the gate — rather than at match time, where the coercion would be
/// invisible and would make `IpCidr::contains` cross address families.
pub fn canonical_ip(value: &str) -> Result<Indicator, CanonicalError> {
    let value = value.trim();
    if value.is_empty() {
        return Err(CanonicalError::Empty);
    }
    let (addr_part, prefix_part) = match value.split_once('/') {
        Some((a, p)) => (a, Some(p)),
        None => (value, None),
    };
    let addr: IpAddr = addr_part
        .parse()
        .map_err(|_| CanonicalError::NotAnIp(value.to_owned()))?;
    let addr = fold_v4_mapped(addr);
    let cidr = match prefix_part {
        Some(p) => {
            let len: u8 = p
                .parse()
                .map_err(|_| CanonicalError::NotAnIp(value.to_owned()))?;
            IpCidr::new(addr, len).ok_or_else(|| CanonicalError::NotAnIp(value.to_owned()))?
        }
        None => IpCidr::host(addr),
    };
    Ok(Indicator::Ip(cidr))
}

fn fold_v4_mapped(addr: IpAddr) -> IpAddr {
    match addr {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        },
        other => other,
    }
}

/// Canonical domain: lowercase ASCII, no trailing root dot, validated labels.
///
/// The trailing dot goes because `evil.com` and `evil.com.` name the same node
/// and keeping both would split the index.  Everything else is validation, not
/// transformation.
pub fn canonical_domain(value: &str) -> Result<String, CanonicalError> {
    let value = value.trim().trim_end_matches('.');
    if value.is_empty() {
        return Err(CanonicalError::Empty);
    }
    if !value.is_ascii() {
        return Err(CanonicalError::IdnaUnsupported(value.to_owned()));
    }
    if value.len() > MAX_DOMAIN_LEN {
        return Err(CanonicalError::NotADomain(value.to_owned()));
    }
    let lower = value.to_ascii_lowercase();
    for label in lower.split('.') {
        if label.is_empty() || label.len() > MAX_LABEL_LEN {
            return Err(CanonicalError::NotADomain(value.to_owned()));
        }
        if !label
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return Err(CanonicalError::NotADomain(value.to_owned()));
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err(CanonicalError::NotADomain(value.to_owned()));
        }
    }
    Ok(lower)
}

/// Conservative URL canonicalisation (§21).
///
/// What is normalised: the scheme and host are lowercased, and a default port
/// (`:80` for http, `:443` for https) is dropped.  Both are guaranteed
/// meaning-preserving by the URL and HTTP specifications.
///
/// What is **not** normalised, and why:
///
/// - **Path case.** Paths are case-sensitive on most servers; lowercasing
///   `/Login` would index a resource that does not exist.
/// - **Percent-decoding.** `%2F` and `/` are different characters to a path
///   parser; decoding merges two distinct URLs into one key.
/// - **Trailing slash.** `/a` and `/a/` are different resources.
/// - **Query order and fragments.** Reordering parameters changes the request
///   for any server that reads them positionally, and the fragment is client
///   side but is occasionally the whole payload of a malicious link.
///
/// This is a stricter promise than most URL normalisers make, and it is the
/// one §21 actually asks for.
pub fn canonical_url(value: &str) -> Result<String, CanonicalError> {
    let value = value.trim();
    let (scheme, rest) = value
        .split_once("://")
        .ok_or_else(|| CanonicalError::NotAUrl(value.to_owned()))?;
    let scheme = scheme.to_ascii_lowercase();
    if !matches!(scheme.as_str(), "http" | "https" | "ftp" | "ws" | "wss") {
        return Err(CanonicalError::NotAUrl(value.to_owned()));
    }
    if rest.is_empty() {
        return Err(CanonicalError::NotAUrl(value.to_owned()));
    }
    // Authority ends at the first `/`, `?` or `#`.
    let end = rest
        .find(['/', '?', '#'])
        .unwrap_or(rest.len());
    let (authority, tail) = rest.split_at(end);

    // Userinfo is kept verbatim: credentials in a URL are part of the
    // indicator, and lowercasing a password would change it.
    let (userinfo, hostport) = match authority.rsplit_once('@') {
        Some((u, h)) => (Some(u), h),
        None => (None, authority),
    };

    let (host, port) = split_host_port(hostport)?;
    let host = if host.starts_with('[') {
        // IPv6 literal: lowercase is safe, the address grammar is hex.
        host.to_ascii_lowercase()
    } else if host.parse::<IpAddr>().is_ok() {
        host.to_ascii_lowercase()
    } else {
        canonical_domain(host)?
    };

    let port = match port {
        Some(p) if is_default_port(&scheme, p) => None,
        other => other,
    };

    let mut out = String::with_capacity(value.len());
    out.push_str(&scheme);
    out.push_str("://");
    if let Some(u) = userinfo {
        out.push_str(u);
        out.push('@');
    }
    out.push_str(&host);
    if let Some(p) = port {
        out.push(':');
        out.push_str(&p.to_string());
    }
    out.push_str(tail);
    Ok(out)
}

fn split_host_port(hostport: &str) -> Result<(&str, Option<u16>), CanonicalError> {
    if let Some(rest) = hostport.strip_prefix('[') {
        // `[::1]:8080`
        let close = rest
            .find(']')
            .ok_or_else(|| CanonicalError::NotAUrl(hostport.to_owned()))?;
        let host = &hostport[..close + 2];
        let after = &rest[close + 1..];
        let port = match after.strip_prefix(':') {
            Some(p) => Some(
                p.parse()
                    .map_err(|_| CanonicalError::NotAUrl(hostport.to_owned()))?,
            ),
            None if after.is_empty() => None,
            None => return Err(CanonicalError::NotAUrl(hostport.to_owned())),
        };
        return Ok((host, port));
    }
    match hostport.rsplit_once(':') {
        Some((h, p)) => {
            let port = p
                .parse()
                .map_err(|_| CanonicalError::NotAUrl(hostport.to_owned()))?;
            Ok((h, Some(port)))
        }
        None => Ok((hostport, None)),
    }
}

fn is_default_port(scheme: &str, port: u16) -> bool {
    matches!(
        (scheme, port),
        ("http", 80) | ("https", 443) | ("ftp", 21) | ("ws", 80) | ("wss", 443)
    )
}

/// Canonical file hash: lowercase hex in, raw bytes out, algorithm explicit.
///
/// The length is checked against the algorithm.  A "SHA-256" with 20 hex
/// characters is a mislabelled feed entry, and storing it would create an
/// indicator that can never match anything.
pub fn canonical_file_hash(
    algorithm: HashAlgorithm,
    value: &str,
) -> Result<Indicator, CanonicalError> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(CanonicalError::Empty);
    }
    // Fuzzy hashes are base64-ish, not hex, and have no fixed length.  They are
    // carried verbatim; `HashAlgorithm::is_exact` is what stops them being used
    // as identity.
    if !algorithm.is_exact() {
        return Ok(Indicator::FileHash {
            algorithm,
            value: trimmed.as_bytes().to_vec(),
        });
    }
    let expected = match algorithm {
        HashAlgorithm::Md5 => 16,
        HashAlgorithm::Sha1 => 20,
        HashAlgorithm::Sha256 | HashAlgorithm::Sha3_256 => 32,
        HashAlgorithm::Sha512 => 64,
        _ => 0,
    };
    let bytes = unhex(trimmed).ok_or_else(|| CanonicalError::BadDigest {
        value: trimmed.to_owned(),
        algorithm: algorithm.label().to_owned(),
        expected,
    })?;
    if expected != 0 && bytes.len() != expected {
        return Err(CanonicalError::BadDigest {
            value: trimmed.to_owned(),
            algorithm: algorithm.label().to_owned(),
            expected,
        });
    }
    Ok(Indicator::FileHash {
        algorithm,
        value: bytes,
    })
}

/// Canonical email: the domain is normalised, the local part is not.
///
/// RFC 5321 makes the local part case-**sensitive** and leaves its
/// interpretation to the receiving host.  Most hosts fold case; some do not.
/// Lowercasing it would merge two mailboxes that a strict server keeps apart,
/// which is precisely the semantic change §21 forbids.
pub fn canonical_email(value: &str) -> Result<Indicator, CanonicalError> {
    let value = value.trim();
    let (local, domain) = value
        .rsplit_once('@')
        .ok_or_else(|| CanonicalError::NotADomain(value.to_owned()))?;
    if local.is_empty() {
        return Err(CanonicalError::Empty);
    }
    let domain = canonical_domain(domain)?;
    Ok(Indicator::Email(format!("{local}@{domain}")))
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(s.len() / 2);
    for pair in b.chunks_exact(2) {
        let hi = (pair[0] as char).to_digit(16)?;
        let lo = (pair[1] as char).to_digit(16)?;
        out.push((hi * 16 + lo) as u8);
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ip_forms_collapse_to_one_key() {
        let a = canonical_ip("203.0.113.4").unwrap();
        let b = canonical_ip(" 203.0.113.4 ").unwrap();
        let mapped = canonical_ip("::ffff:203.0.113.4").unwrap();
        assert_eq!(a, b);
        assert_eq!(
            a, mapped,
            "a v4-mapped v6 address is the same address and must share the key"
        );
        assert_eq!(a.index_key(), mapped.index_key());
    }

    #[test]
    fn ipv6_is_canonicalised_by_the_std_parser() {
        let a = canonical_ip("2001:0db8:0000:0000:0000:0000:0000:0001").unwrap();
        let b = canonical_ip("2001:db8::1").unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn bad_ips_are_errors_not_guesses() {
        assert!(canonical_ip("999.1.1.1").is_err());
        assert!(canonical_ip("10.0.0.0/33").is_err());
        assert!(canonical_ip("").is_err());
    }

    #[test]
    fn domain_case_and_root_dot_are_normalised() {
        assert_eq!(canonical_domain("EVIL.Com.").unwrap(), "evil.com");
        assert_eq!(canonical_domain(" sub.EVIL.com ").unwrap(), "sub.evil.com");
    }

    #[test]
    fn non_ascii_domains_are_refused_rather_than_approximated() {
        // The homograph case: a half-done IDNA would store something that
        // never matches the traffic it was meant to catch.
        let err = canonical_domain("café.example").unwrap_err();
        assert!(matches!(err, CanonicalError::IdnaUnsupported(_)));
        // Punycode is ASCII and goes through.
        assert_eq!(
            canonical_domain("XN--CAF-DMA.example").unwrap(),
            "xn--caf-dma.example"
        );
    }

    #[test]
    fn malformed_domains_are_rejected() {
        for bad in ["", ".", "a..b", "-lead.com", "trail-.com", &"a".repeat(64)] {
            assert!(canonical_domain(bad).is_err(), "accepted `{bad}`");
        }
    }

    #[test]
    fn url_normalises_only_what_is_safe() {
        assert_eq!(
            canonical_url("HTTP://EVIL.COM:80/Path?B=2&A=1#frag").unwrap(),
            "http://evil.com/Path?B=2&A=1#frag"
        );
        assert_eq!(
            canonical_url("https://Evil.com:443/x").unwrap(),
            "https://evil.com/x"
        );
        // Non-default port survives.
        assert_eq!(
            canonical_url("http://evil.com:8080/x").unwrap(),
            "http://evil.com:8080/x"
        );
    }

    #[test]
    fn url_does_not_touch_path_case_encoding_or_trailing_slash() {
        // Each of these pairs is two different resources; merging them would
        // be the semantic change §21 forbids.
        assert_ne!(
            canonical_url("http://evil.com/A").unwrap(),
            canonical_url("http://evil.com/a").unwrap()
        );
        assert_ne!(
            canonical_url("http://evil.com/a%2Fb").unwrap(),
            canonical_url("http://evil.com/a/b").unwrap()
        );
        assert_ne!(
            canonical_url("http://evil.com/a").unwrap(),
            canonical_url("http://evil.com/a/").unwrap()
        );
        assert_ne!(
            canonical_url("http://evil.com/x?a=1&b=2").unwrap(),
            canonical_url("http://evil.com/x?b=2&a=1").unwrap()
        );
    }

    #[test]
    fn url_handles_ipv6_literals_and_userinfo() {
        assert_eq!(
            canonical_url("http://[2001:DB8::1]:80/x").unwrap(),
            "http://[2001:db8::1]/x"
        );
        assert_eq!(
            canonical_url("https://User:PaSs@EVIL.com/x").unwrap(),
            "https://User:PaSs@evil.com/x",
            "credentials are part of the indicator and are not case-folded"
        );
    }

    #[test]
    fn relative_and_unknown_scheme_urls_are_rejected() {
        for bad in ["/just/a/path", "evil.com/x", "javascript://evil", "http://"] {
            assert!(canonical_url(bad).is_err(), "accepted `{bad}`");
        }
    }

    #[test]
    fn hash_length_is_checked_against_the_declared_algorithm() {
        let sha = canonical_file_hash(HashAlgorithm::Sha256, &"AB".repeat(32)).unwrap();
        match sha {
            Indicator::FileHash { value, .. } => assert_eq!(value.len(), 32),
            other => panic!("{other:?}"),
        }
        // A "SHA-256" that is 20 bytes is a mislabelled feed entry.
        assert!(canonical_file_hash(HashAlgorithm::Sha256, &"ab".repeat(20)).is_err());
        assert!(canonical_file_hash(HashAlgorithm::Sha256, "nothex").is_err());
    }

    #[test]
    fn hex_case_does_not_split_the_index() {
        let upper = canonical_file_hash(HashAlgorithm::Sha256, &"AB".repeat(32)).unwrap();
        let lower = canonical_file_hash(HashAlgorithm::Sha256, &"ab".repeat(32)).unwrap();
        assert_eq!(upper.index_key(), lower.index_key());
    }

    #[test]
    fn fuzzy_hashes_pass_through_without_a_length_rule() {
        let f = canonical_file_hash(HashAlgorithm::Ssdeep, "3:AXGBicFlgVNhBGcL6wCrFQEv:AXGHsNhxLsr2C");
        assert!(f.is_ok());
    }

    #[test]
    fn email_domain_is_folded_and_local_part_is_not() {
        let e = canonical_email("Admin@EVIL.com").unwrap();
        assert_eq!(e, Indicator::Email("Admin@evil.com".into()));
    }
}
