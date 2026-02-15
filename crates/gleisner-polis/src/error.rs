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

    /// Landlock ruleset construction or enforcement failed.
    #[error("landlock enforcement failed: {0}")]
    LandlockError(String),

    /// A cgroup operation failed.
    #[error("cgroup operation `{operation}` failed: {source}")]
    CgroupError {
        /// The cgroup operation that failed.
        operation: String,
        /// The underlying I/O error.
        source: std::io::Error,
    },

    /// An event monitor encountered an error.
    #[error("monitor error: {0}")]
    MonitorError(String),

    /// slirp4netns binary not found on PATH.
    #[error("slirp4netns not found — install slirp4netns for selective network filtering")]
    SlirpNotFound,

    /// Network setup (slirp4netns, iptables, or child PID detection) failed.
    #[error("network setup failed: {0}")]
    NetworkSetupFailed(String),

    /// A resource limit could not be applied.
    #[error("failed to set {resource}: {detail}")]
    ResourceLimit {
        /// The resource being limited (e.g. "`RLIMIT_NOFILE`").
        resource: &'static str,
        /// Details about the failure.
        detail: String,
    },
}
