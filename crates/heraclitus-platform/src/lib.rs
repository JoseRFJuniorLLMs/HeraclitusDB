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
pub mod memory;
pub mod process;

pub use capabilities::{detect_capabilities, PlatformCapabilities};
pub use cgroup::{detect_cgroup_limits, EffectiveResourceLimits};
pub use memory::{advise, advise_slice, page_size, MemoryAdvice};
pub use process::{notify_ready, notify_watchdog, wait_for_shutdown_signal};
