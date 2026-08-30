//! Process resource sampling for the soak and crash trials (SPEC-0049 §19).
//!
//! Every field is an `Option`. A metric this platform cannot produce is
//! recorded as `null`, never as `0`: PQ17 forbids treating an inconclusive
//! measurement as a result, and a zeroed resident-set series would make a leak
//! look like perfect stability.

use std::process::Command;

use serde::Serialize;

#[derive(Debug, Clone, Default, Serialize)]
pub struct ProcessSample {
    pub pid: u32,
    /// Resident set size in bytes.
    pub rss_bytes: Option<u64>,
    pub threads: Option<u64>,
    /// Open file descriptors on Unix, open kernel handles on Windows.
    pub handles: Option<u64>,
}

impl ProcessSample {
    /// True when every §19 growth series is observable on this host. A soak
    /// that cannot see memory or descriptors cannot clear the §20 leak gate.
    pub fn is_complete(&self) -> bool {
        self.rss_bytes.is_some() && self.threads.is_some() && self.handles.is_some()
    }
}

#[cfg(target_os = "linux")]
pub fn sample(pid: u32) -> ProcessSample {
    use std::fs;

    let mut out = ProcessSample {
        pid,
        ..Default::default()
    };
    if let Ok(status) = fs::read_to_string(format!("/proc/{pid}/status")) {
        for line in status.lines() {
            if let Some(value) = line.strip_prefix("VmRSS:") {
                out.rss_bytes = parse_kib(value);
            } else if let Some(value) = line.strip_prefix("Threads:") {
                out.threads = value.trim().parse().ok();
            }
        }
    }
    out.handles = fs::read_dir(format!("/proc/{pid}/fd"))
        .map(|entries| entries.filter(|entry| entry.is_ok()).count() as u64)
        .ok();
    out
}

#[cfg(target_os = "linux")]
fn parse_kib(value: &str) -> Option<u64> {
    let kib: u64 = value.split_whitespace().next()?.parse().ok()?;
    kib.checked_mul(1024)
}

#[cfg(windows)]
pub fn sample(pid: u32) -> ProcessSample {
    // `Get-Process` is the only dependency-free source of all three series on
    // Windows. It costs one process launch per sample, which is irrelevant at
    // the minute-scale cadence a soak uses.
    let script = format!(
        "$ErrorActionPreference='Stop'; $p = Get-Process -Id {pid}; \
         Write-Output ('{{0}} {{1}} {{2}}' -f $p.WorkingSet64, $p.Threads.Count, $p.HandleCount)"
    );
    let mut out = ProcessSample {
        pid,
        ..Default::default()
    };
    let Ok(output) = Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", &script])
        .output()
    else {
        return out;
    };
    if !output.status.success() {
        return out;
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let mut fields = text.split_whitespace();
    out.rss_bytes = fields.next().and_then(|value| value.parse().ok());
    out.threads = fields.next().and_then(|value| value.parse().ok());
    out.handles = fields.next().and_then(|value| value.parse().ok());
    out
}

#[cfg(not(any(target_os = "linux", windows)))]
pub fn sample(pid: u32) -> ProcessSample {
    let _ = Command::new("true");
    ProcessSample {
        pid,
        ..Default::default()
    }
}

/// Ordinary least squares slope of `values` against `seconds`, in units per
/// second. `None` when fewer than two distinct instants were observed, because
/// a single point cannot express a trend.
pub fn slope_per_second(seconds: &[f64], values: &[f64]) -> Option<f64> {
    if seconds.len() != values.len() || seconds.len() < 2 {
        return None;
    }
    let count = seconds.len() as f64;
    let mean_x = seconds.iter().sum::<f64>() / count;
    let mean_y = values.iter().sum::<f64>() / count;
    let mut covariance = 0.0;
    let mut variance = 0.0;
    for (x, y) in seconds.iter().zip(values) {
        let dx = x - mean_x;
        covariance += dx * (y - mean_y);
        variance += dx * dx;
    }
    if variance <= f64::EPSILON {
        return None;
    }
    Some(covariance / variance)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slope_detects_linear_growth_and_refuses_a_single_point() {
        let seconds = [0.0, 10.0, 20.0, 30.0];
        let growing = [100.0, 200.0, 300.0, 400.0];
        let flat = [100.0, 100.0, 100.0, 100.0];
        assert_eq!(slope_per_second(&seconds, &growing), Some(10.0));
        assert_eq!(slope_per_second(&seconds, &flat), Some(0.0));
        assert_eq!(slope_per_second(&[1.0], &[1.0]), None);
        // A vertical series has no defined slope; reporting 0 would hide it.
        assert_eq!(slope_per_second(&[5.0, 5.0], &[1.0, 9.0]), None);
    }

    #[test]
    fn an_unobservable_metric_is_never_a_zero_measurement() {
        let sample = ProcessSample {
            pid: 1,
            rss_bytes: None,
            threads: Some(4),
            handles: Some(9),
        };
        assert!(!sample.is_complete());
        assert!(ProcessSample {
            pid: 1,
            rss_bytes: Some(1),
            threads: Some(1),
            handles: Some(1)
        }
        .is_complete());
    }
}
