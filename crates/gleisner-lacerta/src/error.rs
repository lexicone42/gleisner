//! Error types for the verification subsystem.

/// Errors from the Lacerta verification subsystem.
#[derive(Debug, thiserror::Error)]
pub enum VerificationError {
    /// Signature verification failed.
    #[error("signature verification failed: {0}")]
    InvalidSignature(String),

    /// Digest mismatch.
    #[error("digest mismatch for `{artifact}`: expected {expected}, got {actual}")]
    DigestMismatch {
        /// The artifact whose digest was checked.
        artifact: String,
        /// Expected hex digest.
        expected: String,
        /// Actual hex digest.
        actual: String,
    },

    /// Policy evaluation failed.
    #[error("policy evaluation error: {0}")]
    PolicyError(String),

    /// I/O error during verification.
    #[error("verification I/O error: {0}")]
    IoError(#[from] std::io::Error),

    /// JSON parsing error.
    #[error("JSON error: {0}")]
    JsonError(#[from] serde_json::Error),

    /// Unsupported verification material type.
    #[error("unsupported verification material: {0}")]
    UnsupportedMaterial(String),

    /// Bundle structure is invalid.
    #[error("invalid bundle: {0}")]
    InvalidBundle(String),
}
