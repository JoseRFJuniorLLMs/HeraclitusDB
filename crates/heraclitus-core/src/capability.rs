//! SPEC-026 — capability catalog.
//!
//! A single in-memory inventory of the host's real hardware/feature profile,
//! interrogated by the planner before choosing a physical strategy (SIMD vs
//! GPU vs plain imperative). Detection is conservative and honest: features we
//! cannot reliably probe from `std` are reported as `false` rather than
//! optimistically assumed.

#[derive(Debug, Clone, Default, PartialEq)]
pub struct CapabilityCatalog {
    /// CPU exposes wide vector registers (AVX2+ on x86_64).
    pub supports_hardware_vector_simd: bool,
    /// A massive-compute runtime (CUDA/Vulkan) is present. Not probed from std.
    pub supports_gpu_acceleration: bool,
    /// Multi-socket NUMA topology. Not probed from std.
    pub supports_numa: bool,
    pub logical_cpus: usize,
    pub registered_compression_profiles: Vec<String>,
}

#[cfg(target_arch = "x86_64")]
fn detect_simd() -> bool {
    std::arch::is_x86_feature_detected!("avx2")
}
#[cfg(not(target_arch = "x86_64"))]
fn detect_simd() -> bool {
    false
}

impl CapabilityCatalog {
    /// Probe the real host. GPU/NUMA stay `false` (no reliable std probe) — the
    /// planner treats absence as "use the CPU path", which is always correct.
    pub fn detect() -> Self {
        let logical_cpus = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1);
        Self {
            supports_hardware_vector_simd: detect_simd(),
            supports_gpu_acceleration: false,
            supports_numa: false,
            logical_cpus,
            registered_compression_profiles: vec![
                "dictionary".into(),
                "delta".into(),
                "delta-of-delta".into(),
                "frame-of-reference".into(),
            ],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_reports_sane_host() {
        let c = CapabilityCatalog::detect();
        assert!(c.logical_cpus >= 1);
        assert!(c
            .registered_compression_profiles
            .contains(&"delta-of-delta".to_string()));
    }
}
