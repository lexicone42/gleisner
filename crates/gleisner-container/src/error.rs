//! Container error types with actionable guidance.

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

impl ContainerError {
    /// Produce an actionable suggestion for resolving this error.
    ///
    /// Returns a human-readable string with specific commands or
    /// configuration changes to fix the issue.
    pub fn suggestion(&self) -> &str {
        match self {
            Self::Sandbox(e) => {
                let msg = e.to_string();
                if msg.contains("not found") {
                    "Run: cargo build -p gleisner-sandbox-init (or add it to PATH)"
                } else if msg.contains("PathNotFound") {
                    "The project directory doesn't exist — check the path"
                } else if msg.contains("Landlock") {
                    "Landlock may not be supported — try .landlock(false) or upgrade your kernel"
                } else {
                    "Check that user namespaces are enabled (sysctl kernel.unprivileged_userns_clone=1)"
                }
            }
            Self::Process(e) => {
                if e.kind() == std::io::ErrorKind::NotFound {
                    "The command binary was not found inside the sandbox — add the package that provides it"
                } else if e.kind() == std::io::ErrorKind::PermissionDenied {
                    "Permission denied — check that the binary is executable and the path is mounted"
                } else {
                    "Check that the sandbox has the required mounts and the command exists"
                }
            }
            Self::Config(_) => "Check your TaskSandbox configuration or minimal.toml for errors",
            Self::Timeout(_) => "Increase the timeout or investigate why the command is slow",
            #[cfg(feature = "forge")]
            Self::Forge(_) => {
                "Check that the forge output is valid JSON from `gleisner forge --dry-run`"
            }
        }
    }
}
