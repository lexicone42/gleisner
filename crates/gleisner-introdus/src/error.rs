//! Error types for the attestation subsystem.

/// Errors from the Introdus attestation subsystem.
#[derive(Debug, thiserror::Error)]
pub enum AttestationError {
    /// Failed to serialize the attestation statement.
    #[error("failed to serialize attestation: {0}")]
    SerializeError(#[from] serde_json::Error),

    /// Signing operation failed.
    #[error("signing failed: {0}")]
    SigningFailed(String),

    /// Failed to capture git state.
    #[error("git state capture failed: {0}")]
    GitError(String),

    /// Cryptographic key operation failed (load, generate, or parse).
    #[error("key error: {0}")]
    KeyError(String),

    /// I/O error during attestation operations.
    #[error("attestation I/O error: {0}")]
    IoError(#[from] std::io::Error),
}
