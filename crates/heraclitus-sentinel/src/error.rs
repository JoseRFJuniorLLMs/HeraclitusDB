use thiserror::Error;

#[derive(Debug, Error)]
pub enum SentinelError {
    #[error("Sentinel está desabilitado")]
    Disabled,
    #[error("configuração do Sentinel inválida: {0}")]
    Config(String),
    #[error("fila do Sentinel encerrada")]
    QueueClosed,
    #[error("cursor do Sentinel: {0}")]
    Cursor(String),
    #[error("log do Sentinel: {0}")]
    Log(#[from] heraclitus_core::HeraclitusError),
    #[error("I/O do Sentinel: {0}")]
    Io(#[from] std::io::Error),
    #[error("serialização do Sentinel: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("compilação de regra Sigma do Sentinel: {0}")]
    Sigma(String),
    #[error("correlação do Sentinel: {0}")]
    Correlation(#[from] crate::correlation::CorrelationError),
    #[error("comportamento do Sentinel: {0}")]
    Behavior(#[from] crate::behavior::BehaviorError),
    #[error("investigação L4 do Sentinel: {0}")]
    Ai(#[from] crate::ai::AiError),
    #[error("política do Sentinel: {0}")]
    Policy(#[from] crate::policy::PolicyError),
    #[error("governança do Sentinel: {0}")]
    Governance(#[from] crate::governance::GovernanceError),
    #[error("worker do Sentinel: {0}")]
    Worker(String),
}
