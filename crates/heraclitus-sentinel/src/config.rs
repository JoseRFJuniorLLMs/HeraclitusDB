//! Runtime configuration helpers.  The serializable fields live in core so a
//! host can parse TOML without linking this crate.

use crate::error::SentinelError;
pub use heraclitus_core::{
    SentinelConfig, SentinelL1Config, SentinelL2Config, SentinelL3Config, SentinelMode,
};

pub fn validate(config: &SentinelConfig) -> Result<(), SentinelError> {
    if !config.enabled || config.mode == SentinelMode::Disabled {
        return Ok(());
    }
    if config.mode == SentinelMode::Autonomous {
        return Err(SentinelError::Config(
            "mode=autonomous está bloqueado até existir permit verificado e executor qualificado"
                .into(),
        ));
    }
    if config.queue_capacity == 0 {
        return Err(SentinelError::Config(
            "queue_capacity deve ser maior que zero".into(),
        ));
    }
    if config.worker_threads == 0 {
        return Err(SentinelError::Config(
            "worker_threads deve ser maior que zero".into(),
        ));
    }
    if config.catch_up_batch == 0 {
        return Err(SentinelError::Config(
            "catch_up_batch deve ser maior que zero".into(),
        ));
    }
    if config.pipeline_version == 0 {
        return Err(SentinelError::Config(
            "pipeline_version deve ser maior que zero".into(),
        ));
    }
    if config.l2.enabled && (config.l2.minimum_support == 0 || config.l2.learning_delay_events == 0)
    {
        return Err(SentinelError::Config(
            "l2.minimum_support e l2.learning_delay_events devem ser maiores que zero".into(),
        ));
    }
    if config.l2.suspicious_severity > 10 {
        return Err(SentinelError::Config(
            "l2.suspicious_severity deve estar entre 0 e 10".into(),
        ));
    }
    if config.l3.enabled && !(1..=32).contains(&config.l3.max_graph_hops) {
        return Err(SentinelError::Config(
            "l3.max_graph_hops deve estar entre 1 e 32".into(),
        ));
    }
    Ok(())
}
