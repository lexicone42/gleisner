//! Container error types.

/// Errors that can occur during container configuration or execution.
#[derive(Debug, thiserror::Error)]
pub enum ContainerError {
    /// Sandbox preparation failed.
    #[error("sandbox preparation failed: {0}")]
    Sandbox(#[from] gleisner_polis::error::SandboxError),

    /// Process spawn or wait failed.
    #[error("process error: {0}")]
    Process(#[from] std::io::Error),

    /// Configuration is invalid.
    #[error("invalid configuration: {0}")]
    Config(String),

    /// Command exceeded its configured timeout.
    #[error("command timed out after {0:?}")]
    Timeout(std::time::Duration),

    /// Forge composition parsing failed.
    #[cfg(feature = "forge")]
    #[error("forge composition error: {0}")]
    Forge(String),
}
