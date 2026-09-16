//! HeraclitusDB interactive Operations & Security Cockpit (`heraclitus top`).
//!
//! The implementation is split into focused modules so the terminal remains a
//! consumer of measured telemetry rather than a second source of truth.

mod cockpit;
mod http;
mod render;

pub use cockpit::run_top;
