//! Public types for sandbox configuration.

use std::path::PathBuf;

/// Linux namespace types available for isolation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Namespace {
    /// PID namespace — sandboxed process sees itself as PID 1.
    Pid,
    /// Network namespace — isolated network stack.
    Net,
    /// IPC namespace — isolated System V IPC and POSIX message queues.
    Ipc,
    /// UTS namespace — isolated hostname.
    Uts,
    /// Time namespace — isolated monotonic/boottime clocks.
    Time,
    /// Cgroup namespace — isolated cgroup root view.
    Cgroup,
}

/// A filesystem mount to create inside the container.
#[derive(Debug, Clone)]
pub enum Mount {
    /// Bind-mount a host path as read-only inside the container.
    ReadOnly {
        /// Path on the host.
        host: PathBuf,
        /// Path inside the container.
        container: PathBuf,
    },
    /// Bind-mount a host path as read-write inside the container.
    ReadWrite {
        /// Path on the host.
        host: PathBuf,
        /// Path inside the container.
        container: PathBuf,
    },
    /// Mount a tmpfs at the given container path.
    Tmpfs {
        /// Path inside the container.
        container: PathBuf,
    },
}

/// Network isolation mode.
#[derive(Debug, Clone)]
pub enum NetworkMode {
    /// Full host network access (no network namespace).
    Host,
    /// Isolated network via pasta with optional domain allowlist.
    Isolated {
        /// Domains allowed for outbound connections.
        allow_domains: Vec<String>,
        /// Whether DNS resolution is permitted.
        allow_dns: bool,
    },
    /// Completely disconnected — no network access at all.
    None,
}

/// Landlock filesystem access level for a path.
#[derive(Debug, Clone)]
pub struct LandlockAccess {
    /// The filesystem path.
    pub path: PathBuf,
    /// Whether write access is granted (false = read-only).
    pub writable: bool,
}

/// Seccomp-BPF preset for syscall filtering.
#[derive(Debug, Clone, Default)]
pub enum SeccompPreset {
    /// No syscall filtering.
    #[default]
    Disabled,
    /// Allowlist tuned for Node.js / V8 runtimes.
    Nodejs,
    /// Explicit syscall allowlist.
    Custom(Vec<String>),
}
