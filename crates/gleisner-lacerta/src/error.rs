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
}
