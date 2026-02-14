//! Error types for the SBOM subsystem.

/// Errors from the Bridger SBOM subsystem.
#[derive(Debug, thiserror::Error)]
pub enum SbomError {
    /// Failed to parse a lockfile.
    #[error("failed to parse lockfile `{path}`: {reason}")]
    ParseError {
        /// Path to the lockfile.
        path: String,
        /// What went wrong.
        reason: String,
    },

    /// I/O error during SBOM operations.
    #[error("SBOM I/O error: {0}")]
    IoError(#[from] std::io::Error),
}
