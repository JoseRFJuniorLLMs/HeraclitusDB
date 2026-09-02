//! Zero-egress gate for air-gapped qualification (SPEC-0049 §97–§98).
//!
//! §97 forbids the installation from attempting DNS, package downloads,
//! licence checks, telemetry, update checks or remote model discovery; §98
//! makes any unauthorised connection an air-gap failure.
//!
//! What this monitor can and cannot prove is worth stating plainly, because an
//! air-gap claim that overstates its evidence is worse than no claim:
//!
//! * it **can** prove egress happened — one sighting of a non-allowlisted
//!   remote endpoint fails the gate and is recorded with its timestamp;
//! * it **cannot** prove egress did not happen. It samples kernel socket
//!   tables, so a connection that opens and closes entirely between two samples
//!   leaves no trace here.
//!
//! Absence therefore remains the job of an external network tap, whose signed
//! report the `zero_egress` gate consumes. This monitor is the second line: it
//! runs on the host itself, needs no lab equipment, and its report uses the
//! same `attempted_egress` field `Invoke-AirgapQualification.ps1` already
//! reads.

use std::collections::BTreeSet;
use std::net::IpAddr;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};
use serde::Serialize;

use crate::evidence::{sha256_file, write_bytes_new, write_json_new};

#[derive(Debug, Clone)]
pub struct EgressConfig {
    /// Command to observe. When absent, `pid` must be supplied.
    pub program: Option<String>,
    pub args: Vec<String>,
    pub pid: Option<u32>,
    pub duration_seconds: u64,
    pub sample_interval_ms: u64,
    /// Remote addresses that are legitimate for this deployment (a replica, a
    /// local time source). Loopback is always allowed and never listed.
    pub allow: Vec<String>,
    pub report: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct Observation {
    pub protocol: &'static str,
    pub remote: String,
    pub first_seen_elapsed_ms: u128,
}

#[derive(Debug, Serialize)]
struct EgressReport {
    schema_version: u32,
    generator: String,
    started_at_unix: u64,
    finished_at_unix: u64,
    subject_command: Option<Vec<String>>,
    subject_pid: Option<u32>,
    subject_exit_code: Option<i32>,
    duration_seconds: f64,
    sample_interval_ms: u64,
    samples_taken: u64,
    samples_failed: u64,
    allowlist: Vec<String>,
    /// The field `Invoke-AirgapQualification.ps1` gates on.
    attempted_egress: u64,
    observations: Vec<Observation>,
    allowed_observations: Vec<Observation>,
    passed: bool,
    method: &'static str,
    limitations: Vec<&'static str>,
}

#[derive(Debug)]
pub struct EgressSummary {
    pub attempted_egress: u64,
    pub samples_taken: u64,
    pub passed: bool,
    pub report: PathBuf,
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Loopback, unspecified and link-local addresses never leave the host, so they
/// are not egress and are excluded before the allowlist is even consulted.
pub fn is_local(address: &IpAddr) -> bool {
    match address {
        IpAddr::V4(v4) => v4.is_loopback() || v4.is_unspecified() || v4.is_link_local(),
        IpAddr::V6(v6) => v6.is_loopback() || v6.is_unspecified(),
    }
}

pub fn is_allowed(address: &IpAddr, allow: &[String]) -> bool {
    is_local(address) || allow.iter().any(|entry| entry == &address.to_string())
}

#[cfg(windows)]
fn connections(pid: u32) -> Result<Vec<(&'static str, IpAddr, u16)>> {
    // `netstat` rather than `Get-NetTCPConnection`, and the reason is the gate's
    // whole point. A PowerShell launch costs about two seconds per sample here,
    // measured — long enough for a package download to open, transfer and close
    // entirely between two samples. `netstat` starts in tens of milliseconds, so
    // the monitor can actually run at the interval the operator asked for.
    //
    // The locale objection against `netstat` applies to its *headers* and the
    // TCP state column, neither of which is parsed: the protocol token and the
    // trailing PID are stable across languages.
    let output = Command::new("netstat")
        .args(["-ano"])
        .output()
        .context("enumerate sockets with netstat")?;
    if !output.status.success() {
        bail!("socket enumeration failed");
    }
    Ok(parse_netstat(&String::from_utf8_lossy(&output.stdout), pid))
}

/// Extract the endpoints owned by `pid` from `netstat -ano` output.
///
/// For TCP the remote address is what matters. For UDP `netstat` reports no
/// peer at all, so the local address is used instead: a UDP socket bound to a
/// non-loopback interface is the signal that a DNS query left the host, which
/// is exactly what §97 forbids.
#[allow(dead_code)]
fn parse_netstat(text: &str, pid: u32) -> Vec<(&'static str, IpAddr, u16)> {
    let mut found = Vec::new();
    for line in text.lines() {
        let fields = line.split_whitespace().collect::<Vec<_>>();
        if fields.len() < 4 {
            continue;
        }
        // The PID is always the last column, whether or not a state is present.
        let Ok(owner) = fields[fields.len() - 1].parse::<u32>() else {
            continue;
        };
        if owner != pid {
            continue;
        }
        let (protocol, endpoint) = match fields[0].to_ascii_uppercase().as_str() {
            "TCP" | "TCPV6" => ("tcp", fields.get(2)),
            "UDP" | "UDPV6" => ("udp", fields.get(1)),
            _ => continue,
        };
        let Some(endpoint) = endpoint else {
            continue;
        };
        if let Some((address, port)) = parse_endpoint(endpoint) {
            found.push((protocol, address, port));
        }
    }
    found
}

/// `1.2.3.4:443`, `[::1]:443`, and the `*:*` wildcard `netstat` prints for an
/// unbound UDP peer. The wildcard is not an address and is dropped rather than
/// guessed at.
#[allow(dead_code)]
fn parse_endpoint(endpoint: &str) -> Option<(IpAddr, u16)> {
    let (address, port) = endpoint.rsplit_once(':')?;
    let port = port.parse::<u16>().ok()?;
    let address = address.trim_start_matches('[').trim_end_matches(']');
    // A scope id (`fe80::1%12`) is a local interface qualifier, not part of the
    // address.
    let address = address.split('%').next()?;
    address.parse::<IpAddr>().ok().map(|ip| (ip, port))
}

#[cfg(target_os = "linux")]
fn connections(pid: u32) -> Result<Vec<(&'static str, IpAddr, u16)>> {
    use std::fs;

    // Only sockets this process actually holds: /proc/net/* is namespace-wide
    // and would attribute the whole host's traffic to the subject.
    let mut inodes = BTreeSet::new();
    for entry in fs::read_dir(format!("/proc/{pid}/fd"))
        .with_context(|| format!("read /proc/{pid}/fd"))?
        .flatten()
    {
        if let Ok(link) = fs::read_link(entry.path()) {
            let text = link.to_string_lossy();
            if let Some(inode) = text
                .strip_prefix("socket:[")
                .and_then(|rest| rest.strip_suffix(']'))
            {
                inodes.insert(inode.to_owned());
            }
        }
    }

    let mut found = Vec::new();
    for (protocol, path, remote_column) in [
        ("tcp", "/proc/net/tcp", 2),
        ("tcp", "/proc/net/tcp6", 2),
        ("udp", "/proc/net/udp", 1),
        ("udp", "/proc/net/udp6", 1),
    ] {
        let Ok(table) = fs::read_to_string(path) else {
            continue;
        };
        for line in table.lines().skip(1) {
            let fields = line.split_whitespace().collect::<Vec<_>>();
            if fields.len() < 10 || !inodes.contains(fields[9]) {
                continue;
            }
            if let Some((address, port)) = parse_proc_endpoint(fields[remote_column]) {
                found.push((protocol, address, port));
            }
        }
    }
    Ok(found)
}

#[cfg(not(any(windows, target_os = "linux")))]
fn connections(_pid: u32) -> Result<Vec<(&'static str, IpAddr, u16)>> {
    bail!("socket enumeration is not implemented on this platform")
}

#[cfg(target_os = "linux")]
fn parse_proc_endpoint(field: &str) -> Option<(IpAddr, u16)> {
    use std::net::{Ipv4Addr, Ipv6Addr};

    let (address, port) = field.split_once(':')?;
    let port = u16::from_str_radix(port, 16).ok()?;
    match address.len() {
        8 => {
            let raw = u32::from_str_radix(address, 16).ok()?;
            Some((IpAddr::V4(Ipv4Addr::from(raw.to_be())), port))
        }
        32 => {
            let mut octets = [0_u8; 16];
            for (index, chunk) in address.as_bytes().chunks(8).enumerate() {
                let word = u32::from_str_radix(std::str::from_utf8(chunk).ok()?, 16).ok()?;
                octets[index * 4..index * 4 + 4].copy_from_slice(&word.to_le_bytes());
            }
            Some((IpAddr::V6(Ipv6Addr::from(octets)), port))
        }
        _ => None,
    }
}

pub fn run(config: EgressConfig) -> Result<EgressSummary> {
    if config.report.exists() {
        bail!(
            "refusing to overwrite egress report {}",
            config.report.display()
        );
    }
    if config.sample_interval_ms == 0 {
        bail!("--sample-interval-ms must be greater than zero");
    }
    for entry in &config.allow {
        entry
            .parse::<IpAddr>()
            .with_context(|| format!("--allow expects a literal IP address, got {entry:?}"))?;
    }
    let started_at_unix = now_unix();
    let mut child = match &config.program {
        Some(program) => Some(
            Command::new(program)
                .args(&config.args)
                .stdin(Stdio::null())
                .spawn()
                .with_context(|| format!("spawn air-gap subject {program}"))?,
        ),
        None => None,
    };
    let pid = match (&child, config.pid) {
        (Some(child), _) => child.id(),
        (None, Some(pid)) => pid,
        (None, None) => bail!("supply either a subject command or --pid"),
    };

    let started = Instant::now();
    let deadline = started + Duration::from_secs(config.duration_seconds.max(1));
    let mut seen = BTreeSet::new();
    let mut observations = Vec::new();
    let mut allowed_observations = Vec::new();
    let mut samples_taken = 0_u64;
    let mut samples_failed = 0_u64;
    let mut exit_code = None;

    while Instant::now() < deadline {
        match connections(pid) {
            Ok(sockets) => {
                samples_taken += 1;
                for (protocol, address, port) in sockets {
                    let key = (protocol, address, port);
                    if !seen.insert(key) {
                        continue;
                    }
                    let observation = Observation {
                        protocol,
                        remote: format!("{address}:{port}"),
                        first_seen_elapsed_ms: started.elapsed().as_millis(),
                    };
                    if is_allowed(&address, &config.allow) {
                        allowed_observations.push(observation);
                    } else {
                        observations.push(observation);
                    }
                }
            }
            Err(_) => samples_failed += 1,
        }
        if let Some(child) = child.as_mut() {
            if let Some(status) = child.try_wait()? {
                exit_code = Some(status.code().unwrap_or(-1));
                break;
            }
        }
        std::thread::sleep(Duration::from_millis(config.sample_interval_ms));
    }
    if let Some(mut child) = child.take() {
        if exit_code.is_none() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }

    observations.sort();
    allowed_observations.sort();
    let attempted_egress = observations.len() as u64;
    // A subject whose sockets were never readable proves nothing; treating that
    // as zero egress would be the exact false pass §98 is written against.
    let observable = samples_taken > 0;
    let passed = observable && attempted_egress == 0 && exit_code.unwrap_or(0) == 0;

    let report = EgressReport {
        schema_version: 1,
        generator: format!("heraclitus-qualifier/{}", env!("CARGO_PKG_VERSION")),
        started_at_unix,
        finished_at_unix: now_unix(),
        subject_command: config.program.as_ref().map(|program| {
            std::iter::once(program.clone())
                .chain(config.args.clone())
                .collect()
        }),
        subject_pid: Some(pid),
        subject_exit_code: exit_code,
        duration_seconds: started.elapsed().as_secs_f64(),
        sample_interval_ms: config.sample_interval_ms,
        samples_taken,
        samples_failed,
        allowlist: config.allow.clone(),
        attempted_egress,
        observations,
        allowed_observations,
        passed,
        method: "kernel socket table sampling of the subject process",
        limitations: vec![
            "sampling cannot observe a connection that opens and closes between two samples; \
             absence of egress is proven by the external network tap, not by this report",
            "only the subject process is watched, not processes it spawns",
        ],
    };
    write_json_new(&config.report, &report)?;
    let digest = sha256_file(&config.report)?;
    write_bytes_new(
        &crate::crash::sidecar_path(&config.report),
        format!(
            "{digest}  {}\n",
            config
                .report
                .file_name()
                .map(|name| name.to_string_lossy())
                .unwrap_or_default()
        )
        .as_bytes(),
    )?;
    Ok(EgressSummary {
        attempted_egress,
        samples_taken,
        passed,
        report: config.report,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loopback_is_not_egress_and_the_internet_is() {
        assert!(is_local(&"127.0.0.1".parse().unwrap()));
        assert!(is_local(&"::1".parse().unwrap()));
        assert!(is_local(&"0.0.0.0".parse().unwrap()));
        assert!(!is_local(&"8.8.8.8".parse().unwrap()));
        assert!(!is_local(&"10.0.0.7".parse().unwrap()));
    }

    #[test]
    fn the_allowlist_admits_only_exact_declared_peers() {
        let allow = vec!["10.0.0.7".to_owned()];
        assert!(is_allowed(&"10.0.0.7".parse().unwrap(), &allow));
        assert!(!is_allowed(&"10.0.0.8".parse().unwrap(), &allow));
        assert!(is_allowed(&"127.0.0.1".parse().unwrap(), &[]));
    }

    #[test]
    fn netstat_rows_are_attributed_to_the_right_process() {
        // Real `netstat -ano` shape: TCP carries a state column, UDP does not,
        // so the PID is read from the end rather than a fixed position.
        let text = "\
Active Connections

  Proto  Local Address          Foreign Address        State           PID
  TCP    127.0.0.1:17474        0.0.0.0:0              LISTENING       30352
  TCP    10.0.0.5:52100         93.184.216.34:443      ESTABLISHED     30352
  TCP    10.0.0.5:52101         1.1.1.1:443            ESTABLISHED     999
  UDP    10.0.0.5:53            *:*                                    30352
  UDP    127.0.0.1:5353         *:*                                    999
";
        let mine = parse_netstat(text, 30352);
        assert_eq!(mine.len(), 3, "{mine:?}");
        // Another process's connection to the internet is not ours to report.
        assert!(!mine.iter().any(|(_, ip, _)| ip.to_string() == "1.1.1.1"));
        // The TCP peer, and the UDP local bind that betrays a DNS query.
        assert!(mine
            .iter()
            .any(|(p, ip, port)| *p == "tcp" && ip.to_string() == "93.184.216.34" && *port == 443));
        assert!(mine
            .iter()
            .any(|(p, ip, _)| *p == "udp" && ip.to_string() == "10.0.0.5"));
        // The listening row's `0.0.0.0:0` is unspecified, so not egress.
        assert!(mine.iter().any(|(_, ip, _)| is_local(ip)));
    }

    #[test]
    fn endpoints_parse_and_wildcards_are_dropped_not_guessed() {
        assert_eq!(
            parse_endpoint("93.184.216.34:443").unwrap().0.to_string(),
            "93.184.216.34"
        );
        assert_eq!(parse_endpoint("[::1]:7474").unwrap().1, 7474);
        // A scope id qualifies the interface, not the address.
        assert_eq!(
            parse_endpoint("[fe80::1%12]:546").unwrap().0.to_string(),
            "fe80::1"
        );
        // `*:*` is netstat saying "no peer", not an address.
        assert!(parse_endpoint("*:*").is_none());
        assert!(parse_endpoint("1.2.3.4:notaport").is_none());
        assert!(parse_endpoint("garbage").is_none());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn proc_endpoints_decode_little_endian_hex() {
        let (address, port) = parse_proc_endpoint("0100007F:1F90").unwrap();
        assert_eq!(address.to_string(), "127.0.0.1");
        assert_eq!(port, 8080);
    }

    #[test]
    fn a_non_ip_allowlist_entry_is_rejected_before_the_subject_starts() {
        let temp = tempfile::tempdir().unwrap();
        let error = run(EgressConfig {
            program: None,
            args: Vec::new(),
            pid: Some(std::process::id()),
            duration_seconds: 1,
            sample_interval_ms: 50,
            allow: vec!["registry.example.invalid".to_owned()],
            report: temp.path().join("egress.json"),
        })
        .unwrap_err();
        assert!(error.to_string().contains("--allow"));
    }
}
