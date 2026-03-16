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

/// A file to create inside the container before exec.
#[derive(Debug, Clone)]
pub struct ContainerFile {
    /// Path inside the container.
    pub path: PathBuf,
    /// File contents.
    pub contents: String,
}

/// A directory to create inside the container before exec.
#[derive(Debug, Clone)]
pub struct ContainerDir {
    /// Path inside the container.
    pub path: PathBuf,
    /// Unix permission mode (e.g. `0o755`).
    pub mode: u32,
}

/// A symbolic link to create inside the container.
#[derive(Debug, Clone)]
pub struct ContainerSymlink {
    /// The target the symlink points to.
    pub target: PathBuf,
    /// The symlink path inside the container.
    pub link: PathBuf,
}

/// Landlock access rule for fine-grained filesystem control.
#[derive(Debug, Clone)]
pub struct LandlockRule {
    /// The filesystem path to control.
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

/// Standard Linux directories that [`Sandbox::rootfs`] discovers and mounts.
pub(crate) const ROOTFS_READONLY_DIRS: &[&str] = &["/usr", "/lib", "/lib64", "/bin", "/sbin"];

/// Directories from the host root that are mounted read-only for basic operation.
pub(crate) const ROOTFS_ETC_PATHS: &[&str] = &[
    "/etc/alternatives",
    "/etc/ld.so.cache",
    "/etc/ld.so.conf",
    "/etc/ld.so.conf.d",
    "/etc/ssl",
    "/etc/ca-certificates",
    "/etc/pki",
    "/etc/passwd",
    "/etc/group",
    "/etc/nsswitch.conf",
    "/etc/resolv.conf",
    "/etc/hosts",
    "/etc/localtime",
    "/etc/hostname",
];
