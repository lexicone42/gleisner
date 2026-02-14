//! Error types for the Polis sandbox subsystem.

/// Errors from the Polis sandbox subsystem.
#[derive(Debug, thiserror::Error)]
pub enum SandboxError {
    /// bubblewrap binary not found on PATH.
    #[error("bwrap not found — install with: sudo apt install bubblewrap")]
    BwrapNotFound,

    /// Profile TOML failed to parse.
    #[error("invalid profile `{path}`: {source}")]
    InvalidProfile {
        /// Path or name that was attempted.
        path: String,
        /// The underlying TOML parse error.
        source: toml::de::Error,
    },

    /// A filesystem path in the profile does not exist.
    #[error("profile references nonexistent path: {0}")]
    PathNotFound(std::path::PathBuf),

    /// The sandboxed process failed to start.
    #[error("failed to spawn sandboxed process: {0}")]
    SpawnFailed(#[from] std::io::Error),

    /// Landlock is not supported on this kernel.
    #[error("landlock requires Linux 5.13+, detected kernel {0}")]
    LandlockUnsupported(String),
}
