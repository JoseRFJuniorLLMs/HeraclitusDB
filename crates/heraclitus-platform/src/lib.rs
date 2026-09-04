//! HeraclitusDB Platform Abstraction and Kernel Acceleration Layer.
//!
//! SPEC-0073 — Linux Native Runtime & Kernel Acceleration.
//!
//! Provides an explicit architectural boundary for OS-level interactions,
//! capability detection, cgroups v2 resource accounting, memory advice, and
//! process lifecycle orchestration. Crates above this layer must never
//! invoke arbitrary platform-specific unsafe calls directly.

pub mod capabilities;
pub mod cgroup;
pub mod linux_config;
pub mod memory;
pub mod numa;
pub mod odirect;
pub mod process;
pub mod simd;

pub use capabilities::{detect_capabilities, PlatformCapabilities};
pub use cgroup::{detect_cgroup_limits, EffectiveResourceLimits};
pub use linux_config::{
    resolver as resolver_linux, AffinityPolicy, IoBackendChoice, LinuxConfig, ResolvedLinuxRuntime,
    Tristate,
};
pub use memory::{advise, advise_slice, page_size, MemoryAdvice};
pub use numa::{detect_numa_topology, NumaNode, NumaTopology};
pub use odirect::{abrir_bulk, alinhado, BufferAlinhado, FicheiroBulk, ModoBulk};
pub use process::{notify_extend_timeout, notify_ready, notify_watchdog, wait_for_shutdown_signal};
pub use simd::{dot, dot_scalar, SimdLevel};
