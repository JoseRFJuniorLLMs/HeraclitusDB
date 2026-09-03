//! cgroups v2 resource limit detection and enforcement.
//!
//! Under containerized or systemd-managed Linux environments, total physical RAM
//! and CPU count do not reflect the effective constraints imposed on the process.
//! If the server sizes its caches against total host RAM instead of the cgroup limit,
//! it is vulnerable to being terminated by the Linux OOM-killer.

use serde::{Deserialize, Serialize};
use std::path::Path;

/// Effective resource limits computed from host and cgroups v2 boundaries.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EffectiveResourceLimits {
    /// Maximum memory in bytes allowed for this process, or None if unbounded.
    pub memory_limit_bytes: Option<u64>,
    /// Current memory usage in bytes, if available.
    pub memory_current_bytes: Option<u64>,
    /// Effective CPU quota in millicores (e.g., 2000 = 2 cores), or None if unbounded.
    pub cpu_quota_millicores: Option<u32>,
    /// Whether cgroups v2 was detected and active.
    pub cgroups_v2_active: bool,
}

/// Detects cgroups v2 limits from the default path /sys/fs/cgroup.
pub fn detect_cgroup_limits() -> EffectiveResourceLimits {
    detect_cgroup_limits_at(Path::new("/sys/fs/cgroup"))
}

/// Detects cgroups v2 limits at a specific root path (useful for testing).
pub fn detect_cgroup_limits_at(cgroup_root: &Path) -> EffectiveResourceLimits {
    #[cfg(target_os = "linux")]
    {
        if !cgroup_root.exists() {
            return EffectiveResourceLimits::default();
        }

        let memory_max_path = cgroup_root.join("memory.max");
        let memory_current_path = cgroup_root.join("memory.current");
        let cpu_max_path = cgroup_root.join("cpu.max");

        let memory_limit_bytes = if memory_max_path.exists() {
            std::fs::read_to_string(&memory_max_path)
                .ok()
                .and_then(|s| parse_cgroup_val(s.trim()))
        } else {
            None
        };

        let memory_current_bytes = if memory_current_path.exists() {
            std::fs::read_to_string(&memory_current_path)
                .ok()
                .and_then(|s| parse_cgroup_val(s.trim()))
        } else {
            None
        };

        let cpu_quota_millicores = if cpu_max_path.exists() {
            std::fs::read_to_string(&cpu_max_path)
                .ok()
                .and_then(|s| parse_cpu_max(s.trim()))
        } else {
            None
        };

        let cgroups_v2_active = memory_max_path.exists() || cpu_max_path.exists();

        EffectiveResourceLimits {
            memory_limit_bytes,
            memory_current_bytes,
            cpu_quota_millicores,
            cgroups_v2_active,
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = cgroup_root;
        EffectiveResourceLimits::default()
    }
}

/// Parses a cgroup value: an integer or 'max' which becomes None.
pub fn parse_cgroup_val(val: &str) -> Option<u64> {
    if val == "max" || val.is_empty() {
        None
    } else {
        val.parse::<u64>().ok()
    }
}

/// Parses cgroups v2 cpu.max format: [quota] [period].
/// Example: 200000 100000 -> 2.0 cores -> 2000 millicores.
/// Example: max 100000 -> None.
pub fn parse_cpu_max(val: &str) -> Option<u32> {
    let mut parts = val.split_whitespace();
    let quota_str = parts.next()?;
    let period_str = parts.next()?;

    if quota_str == "max" {
        return None;
    }

    let quota: u64 = quota_str.parse().ok()?;
    let period: u64 = period_str.parse().ok()?;

    if period == 0 {
        return None;
    }

    // millicores = (quota * 1000) / period
    let millicores = (quota.saturating_mul(1000)) / period;
    Some(millicores as u32)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_memory_values() {
        assert_eq!(parse_cgroup_val("max"), None);
        assert_eq!(parse_cgroup_val(""), None);
        assert_eq!(parse_cgroup_val("1073741824"), Some(1073741824));
    }

    #[test]
    fn parse_cpu_values() {
        assert_eq!(parse_cpu_max("max 100000"), None);
        assert_eq!(parse_cpu_max("200000 100000"), Some(2000));
        assert_eq!(parse_cpu_max("50000 100000"), Some(500));
        assert_eq!(parse_cpu_max("invalid"), None);
    }
}
