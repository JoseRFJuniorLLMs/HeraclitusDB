//! Hardware and operating system capability detection.
//!
//! Provides dynamic cataloging of kernel version, processor features,
//! NUMA nodes, cgroups constraints, and supported I/O primitives.

use crate::cgroup::{detect_cgroup_limits, EffectiveResourceLimits};
use serde::{Deserialize, Serialize};

/// Catalog of platform and hardware capabilities.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlatformCapabilities {
    pub os: String,
    pub arch: String,
    pub kernel_version: Option<String>,
    pub numa_nodes: usize,
    pub logical_cpus: usize,
    pub io_uring_available: bool,
    pub cgroups_v2_active: bool,
    pub effective_limits: EffectiveResourceLimits,
    pub avx2: bool,
    pub avx512f: bool,
    pub neon: bool,
}

/// Detects capabilities of the current execution environment.
pub fn detect_capabilities() -> PlatformCapabilities {
    let os = std::env::consts::OS.to_string();
    let arch = std::env::consts::ARCH.to_string();
    let logical_cpus = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);

    let effective_limits = detect_cgroup_limits();
    let cgroups_v2_active = effective_limits.cgroups_v2_active;

    #[cfg(target_os = "linux")]
    let (kernel_version, numa_nodes, io_uring_available) = {
        let kernel = std::fs::read_to_string("/proc/sys/kernel/osrelease")
            .ok()
            .map(|s| s.trim().to_string());

        let numa = detect_linux_numa_nodes();
        let uring = check_linux_io_uring();

        (kernel, numa, uring)
    };

    #[cfg(not(target_os = "linux"))]
    let (kernel_version, numa_nodes, io_uring_available) = (None, 1, false);

    #[cfg(target_arch = "x86_64")]
    let (avx2, avx512f) = (
        std::is_x86_feature_detected!("avx2"),
        std::is_x86_feature_detected!("avx512f"),
    );
    #[cfg(not(target_arch = "x86_64"))]
    let (avx2, avx512f) = (false, false);

    #[cfg(target_arch = "aarch64")]
    let neon = std::arch::is_aarch64_feature_detected!("neon");
    #[cfg(not(target_arch = "aarch64"))]
    let neon = false;

    PlatformCapabilities {
        os,
        arch,
        kernel_version,
        numa_nodes,
        logical_cpus,
        io_uring_available,
        cgroups_v2_active,
        effective_limits,
        avx2,
        avx512f,
        neon,
    }
}

#[cfg(target_os = "linux")]
fn detect_linux_numa_nodes() -> usize {
    if let Ok(entries) = std::fs::read_dir("/sys/devices/system/node") {
        let count = entries
            .filter_map(|e| e.ok())
            .filter(|e| {
                e.file_name()
                    .to_str()
                    .map(|s| s.starts_with("node") && s[4..].chars().all(|c| c.is_ascii_digit()))
                    .unwrap_or(false)
            })
            .count();
        if count > 0 {
            return count;
        }
    }
    1
}

#[cfg(target_os = "linux")]
fn check_linux_io_uring() -> bool {
    if let Ok(content) = std::fs::read_to_string("/proc/sys/kernel/io_uring_disabled") {
        if content.trim() == "1" || content.trim() == "2" {
            return false;
        }
    }
    true
}

impl PlatformCapabilities {
    /// Produces a compact 1-line log string suitable for server boot.
    pub fn summary_line(&self) -> String {
        format!(
            "OS: {}/{} | Kernel: {} | CPUs: {} | NUMA: {} | cgroups_v2: {} | io_uring: {}",
            self.os,
            self.arch,
            self.kernel_version.as_deref().unwrap_or("unknown"),
            self.logical_cpus,
            self.numa_nodes,
            if self.cgroups_v2_active { "yes" } else { "no" },
            if self.io_uring_available {
                "available"
            } else {
                "no"
            }
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_basic_capabilities() {
        let caps = detect_capabilities();
        assert!(!caps.os.is_empty());
        assert!(!caps.arch.is_empty());
        assert!(caps.logical_cpus >= 1);
        let summary = caps.summary_line();
        assert!(summary.contains("OS:"));
    }
}
