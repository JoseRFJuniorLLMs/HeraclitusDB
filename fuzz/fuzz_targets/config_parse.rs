//! SPEC-0049 §39 — the configuration parser is an exposed parsing surface.
//!
//! It is exposed in a way that is easy to overlook: an air-gapped installer
//! reads a TOML file an operator typed, and `HeraclitusConfig::apply_env` reads
//! strings from the environment. Neither input is trusted to be well formed.
//!
//! The property under test is that arbitrary bytes produce `Err`, a clamped
//! value, or a default — never a panic, and never a configuration that passes
//! `validate_security` while holding a value the validator is supposed to
//! reject.

#![no_main]

use heraclitus_core::HeraclitusConfig;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };

    // Malformed TOML must be rejected, not panicked on.
    let Ok(config) = toml::from_str::<HeraclitusConfig>(text) else {
        return;
    };

    // A config that parses must survive validation without panicking, whatever
    // the validator decides about it.
    let accepted = config.validate_security().is_ok();

    if accepted {
        // Anything the validator accepted must satisfy the invariants the rest
        // of the engine assumes. A panic here means validate_security let
        // through a value that will fail much later, in a worse place.
        assert!(
            (1e-6..=0.5).contains(&config.v6_hrki_bloom_fpr),
            "accepted an out-of-range bloom FPR: {}",
            config.v6_hrki_bloom_fpr
        );
        assert!(
            !config.rest_cors_origins.iter().any(|origin| origin == "*"),
            "accepted a wildcard CORS origin on a REST surface with write routes"
        );
    }

    // Re-serialising an accepted config and reading it back must be stable:
    // an installer that writes the config it just validated has to get the
    // same configuration back.
    if let Ok(rendered) = toml::to_string(&config) {
        if let Ok(round_tripped) = toml::from_str::<HeraclitusConfig>(&rendered) {
            assert_eq!(
                round_tripped.storage_format, config.storage_format,
                "storage format did not survive a round trip"
            );
            assert_eq!(
                round_tripped.segment_max_bytes, config.segment_max_bytes,
                "segment size did not survive a round trip"
            );
            assert_eq!(
                round_tripped.production_mode, config.production_mode,
                "production_mode did not survive a round trip"
            );
        }
    }
});
