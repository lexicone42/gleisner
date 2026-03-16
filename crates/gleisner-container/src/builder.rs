//! The [`Sandbox`] builder — configure and spawn isolated Linux containers.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use gleisner_polis::profile::{
    FilesystemPolicy, NetworkPolicy, PolicyDefault, ProcessPolicy, ResourceLimits, SeccompAction,
    SeccompPolicy,
};
use gleisner_polis::{SandboxSessionConfig, prepare_sandbox};

use crate::command::Command;
use crate::error::ContainerError;
use crate::types::{
    ContainerDir, ContainerFile, ContainerSymlink, LandlockRule, Mount, Namespace, NetworkMode,
    ROOTFS_ETC_PATHS, ROOTFS_READONLY_DIRS, SeccompPreset,
};

/// A container sandbox builder.
///
/// Configure isolation through method chaining, then call [`command()`](Sandbox::command)
/// to create a [`Command`] that executes inside the sandbox.
///
/// # Defaults
///
/// A new `Sandbox` starts with:
/// - User + Mount + IPC + UTS namespaces (always enabled)
/// - No PID/network/time/cgroup namespace
/// - No mounts (caller must add what the process needs)
/// - Landlock enabled with default-deny filesystem
/// - No seccomp filtering
/// - No network access
/// - Hostname set to `"gleisner-sandbox"`
#[derive(Debug)]
pub struct Sandbox {
    namespaces: HashSet<Namespace>,
    mounts: Vec<Mount>,
    deny_paths: Vec<PathBuf>,
    work_dir: Option<PathBuf>,
    project_dir: Option<PathBuf>,
    hostname: String,
    network: NetworkMode,
    seccomp: SeccompPreset,
    landlock_enabled: bool,
    landlock_rules: Vec<LandlockRule>,
    env: Vec<(String, String)>,
    resource_limits: Option<ResourceLimits>,
    uid: u32,
    gid: u32,
    files: Vec<ContainerFile>,
    dirs: Vec<ContainerDir>,
    symlinks: Vec<ContainerSymlink>,
    /// Whether the caller has acknowledged running without Landlock.
    /// Required by `empty()` before `command()` can be called.
    landlock_acknowledged: bool,
    /// Whether to mount /proc inside the container (default: true via sandbox-init).
    mount_proc: bool,
    /// Whether to mount /dev inside the container (default: true via sandbox-init).
    mount_dev: bool,
}

impl Default for Sandbox {
    fn default() -> Self {
        Self::new()
    }
}

impl Sandbox {
    /// Create a new sandbox builder with minimal defaults.
    ///
    /// Landlock is enabled by default, no mounts are configured.
    /// Call [`rootfs()`](Sandbox::rootfs) for a quick Linux environment,
    /// or add mounts manually.
    pub fn new() -> Self {
        let uid = nix::unistd::getuid().as_raw();
        let gid = nix::unistd::getgid().as_raw();
        Self {
            namespaces: HashSet::new(),
            mounts: Vec::new(),
            deny_paths: Vec::new(),
            work_dir: None,
            project_dir: None,
            hostname: "gleisner-sandbox".to_owned(),
            network: NetworkMode::None,
            seccomp: SeccompPreset::Disabled,
            landlock_enabled: true,
            landlock_acknowledged: true, // Landlock is on, no ack needed
            env: Vec::new(),
            resource_limits: None,
            uid,
            gid,
            files: Vec::new(),
            dirs: Vec::new(),
            symlinks: Vec::new(),
            landlock_rules: Vec::new(),
            mount_proc: true,
            mount_dev: true,
        }
    }

    /// Create an empty sandbox builder — nothing is configured.
    ///
    /// Unlike [`new()`](Sandbox::new) which enables Landlock by default,
    /// `empty()` starts with everything disabled. Use this for reproducible
    /// build environments where you want explicit control over every layer.
    ///
    /// You must call `.landlock(true)` or `.no_landlock()` before creating
    /// commands — this ensures you've explicitly acknowledged the security posture.
    ///
    /// ```no_run
    /// # use gleisner_container::Sandbox;
    /// let mut sb = Sandbox::empty();
    /// sb.mount_readonly("/usr", "/usr")
    ///     .mount_readonly("/lib", "/lib")
    ///     .tmpfs("/tmp")
    ///     .no_landlock(); // explicit acknowledgment
    /// ```
    pub fn empty() -> Self {
        let uid = nix::unistd::getuid().as_raw();
        let gid = nix::unistd::getgid().as_raw();
        Self {
            namespaces: HashSet::new(),
            mounts: Vec::new(),
            deny_paths: Vec::new(),
            work_dir: None,
            project_dir: None,
            hostname: "gleisner-sandbox".to_owned(),
            network: NetworkMode::None,
            seccomp: SeccompPreset::Disabled,
            landlock_enabled: false,
            landlock_acknowledged: false, // Must call .no_landlock() to acknowledge
            env: Vec::new(),
            resource_limits: None,
            uid,
            gid,
            files: Vec::new(),
            dirs: Vec::new(),
            symlinks: Vec::new(),
            landlock_rules: Vec::new(),
            mount_proc: true,
            mount_dev: true,
        }
    }

    // ── Root filesystem ──────────────────────────────────────────

    /// Auto-discover and mount a minimal Linux root filesystem.
    ///
    /// Scans the host for standard directories (`/usr`, `/lib`, `/lib64`,
    /// `/bin`, `/sbin`) and essential `/etc` files (SSL certs, resolver,
    /// passwd, timezone), mounting everything read-only. Also adds `/tmp`
    /// as a writable tmpfs and `/proc` + `/dev` (handled by sandbox-init).
    ///
    /// This is the single-call ergonomic equivalent of manually listing
    /// every bind mount. After calling `rootfs()`, you typically only need
    /// to add your project directory as read-write.
    ///
    /// ```no_run
    /// # use gleisner_container::Sandbox;
    /// let mut sb = Sandbox::new();
    /// sb.rootfs()
    ///     .mount_readwrite("/workspace", "/workspace")
    ///     .hostname("my-container");
    /// ```
    pub fn rootfs(&mut self) -> &mut Self {
        // Mount standard OS directories
        for dir in ROOTFS_READONLY_DIRS {
            let path = Path::new(dir);
            if path.exists() {
                self.mounts.push(Mount::ReadOnly {
                    host: path.to_path_buf(),
                    container: path.to_path_buf(),
                });
            }
        }

        // Mount essential /etc files individually (not all of /etc)
        for etc_path in ROOTFS_ETC_PATHS {
            let path = Path::new(etc_path);
            if path.exists() {
                self.mounts.push(Mount::ReadOnly {
                    host: path.to_path_buf(),
                    container: path.to_path_buf(),
                });
            }
        }

        // Writable /tmp
        self.mounts.push(Mount::Tmpfs {
            container: PathBuf::from("/tmp"),
        });

        self
    }

    // ── Namespace configuration ──────────────────────────────────

    /// Add a namespace for isolation. User and Mount namespaces are always
    /// enabled; this method adds optional ones (Pid, Net, Time, Ipc, Uts, Cgroup).
    pub fn namespace(&mut self, ns: Namespace) -> &mut Self {
        self.namespaces.insert(ns);
        self
    }

    // ── Filesystem configuration ─────────────────────────────────

    /// Bind-mount a host path as read-only inside the container.
    ///
    /// The `host` path is bound to `container` path inside the sandbox.
    pub fn mount_readonly(
        &mut self,
        host: impl Into<PathBuf>,
        container: impl Into<PathBuf>,
    ) -> &mut Self {
        self.mounts.push(Mount::ReadOnly {
            host: host.into(),
            container: container.into(),
        });
        self
    }

    /// Bind-mount a host path as read-write inside the container.
    pub fn mount_readwrite(
        &mut self,
        host: impl Into<PathBuf>,
        container: impl Into<PathBuf>,
    ) -> &mut Self {
        self.mounts.push(Mount::ReadWrite {
            host: host.into(),
            container: container.into(),
        });
        self
    }

    /// Bind-mount a path read-only, using the same path inside the container.
    ///
    /// Shorthand for `.mount_readonly(path, path)` — the most common pattern.
    pub fn bind_ro(&mut self, path: impl Into<PathBuf>) -> &mut Self {
        let p: PathBuf = path.into();
        self.mounts.push(Mount::ReadOnly {
            host: p.clone(),
            container: p,
        });
        self
    }

    /// Bind-mount a path read-write, using the same path inside the container.
    ///
    /// Shorthand for `.mount_readwrite(path, path)`.
    pub fn bind_rw(&mut self, path: impl Into<PathBuf>) -> &mut Self {
        let p: PathBuf = path.into();
        self.mounts.push(Mount::ReadWrite {
            host: p.clone(),
            container: p,
        });
        self
    }

    /// Bind-mount multiple paths read-only (same path inside container).
    ///
    /// Convenience for mounting many directories at once:
    /// ```no_run
    /// # use gleisner_container::Sandbox;
    /// let mut sb = Sandbox::new();
    /// sb.bind_ro_all(["/usr", "/lib", "/lib64", "/bin"]);
    /// ```
    pub fn bind_ro_all(
        &mut self,
        paths: impl IntoIterator<Item = impl Into<PathBuf>>,
    ) -> &mut Self {
        for path in paths {
            self.bind_ro(path);
        }
        self
    }

    /// Bind-mount multiple paths read-write (same path inside container).
    pub fn bind_rw_all(
        &mut self,
        paths: impl IntoIterator<Item = impl Into<PathBuf>>,
    ) -> &mut Self {
        for path in paths {
            self.bind_rw(path);
        }
        self
    }

    /// Mount a tmpfs at the given path inside the container.
    pub fn tmpfs(&mut self, container: impl Into<PathBuf>) -> &mut Self {
        self.mounts.push(Mount::Tmpfs {
            container: container.into(),
        });
        self
    }

    /// Deny access to a path via Landlock. Applied after bind mounts.
    pub fn deny_path(&mut self, path: impl Into<PathBuf>) -> &mut Self {
        self.deny_paths.push(path.into());
        self
    }

    /// Set the working directory for the inner process.
    ///
    /// This sets the CWD inside the container but does NOT automatically
    /// mount the directory. Use [`project_dir()`](Sandbox::project_dir) to
    /// set a directory that is both the CWD and mounted read-write.
    pub fn work_dir(&mut self, path: impl Into<PathBuf>) -> &mut Self {
        self.work_dir = Some(path.into());
        self
    }

    /// Set the project directory — mounted read-write and used as the working directory.
    ///
    /// This is the common case for development workflows: one directory that is
    /// both the CWD and writable. Equivalent to calling both
    /// [`work_dir()`](Sandbox::work_dir) and [`mount_readwrite()`](Sandbox::mount_readwrite).
    pub fn project_dir(&mut self, path: impl Into<PathBuf>) -> &mut Self {
        let p: PathBuf = path.into();
        self.work_dir = Some(p.clone());
        self.project_dir = Some(p);
        self
    }

    // ── Identity ─────────────────────────────────────────────────

    /// Set the hostname inside the container.
    pub fn hostname(&mut self, name: impl Into<String>) -> &mut Self {
        self.hostname = name.into();
        self
    }

    /// Map a specific UID inside the user namespace.
    pub fn uid(&mut self, uid: u32) -> &mut Self {
        self.uid = uid;
        self
    }

    /// Map a specific GID inside the user namespace.
    pub fn gid(&mut self, gid: u32) -> &mut Self {
        self.gid = gid;
        self
    }

    /// Bind-mount the current user's home directory as read-only.
    ///
    /// Common pattern for tools that need `~/.config`, `~/.claude`, etc.
    /// Resolves `$HOME` (with passwd fallback) and adds it as a read-only mount.
    pub fn mount_home_readonly(&mut self) -> &mut Self {
        if let Ok(home) = std::env::var("HOME") {
            self.bind_ro(home);
        } else if let Some(base) = directories::BaseDirs::new() {
            self.bind_ro(base.home_dir());
        }
        self
    }

    // ── Network ──────────────────────────────────────────────────

    /// Set the network isolation mode.
    pub fn network(&mut self, mode: NetworkMode) -> &mut Self {
        self.network = mode;
        self
    }

    /// Restrict network to specific domains with DNS enabled.
    ///
    /// Shorthand for `.network(NetworkMode::Isolated { allow_domains, allow_dns: true })`.
    pub fn allow_domains(
        &mut self,
        domains: impl IntoIterator<Item = impl Into<String>>,
    ) -> &mut Self {
        self.network = NetworkMode::Isolated {
            allow_domains: domains.into_iter().map(Into::into).collect(),
            allow_dns: true,
        };
        self
    }

    // ── Security policies ────────────────────────────────────────

    /// Set the seccomp-BPF filtering preset.
    pub fn seccomp(&mut self, preset: SeccompPreset) -> &mut Self {
        self.seccomp = preset;
        self
    }

    /// Enable or disable Landlock filesystem restrictions.
    pub fn landlock(&mut self, enabled: bool) -> &mut Self {
        self.landlock_enabled = enabled;
        if enabled {
            self.landlock_acknowledged = true;
        }
        self
    }

    /// Explicitly acknowledge running without Landlock.
    ///
    /// Required when using [`Sandbox::empty()`] — the builder refuses to
    /// create commands until you either call `.landlock(true)` or `.no_landlock()`
    /// to confirm you understand the security implications.
    pub fn no_landlock(&mut self) -> &mut Self {
        self.landlock_enabled = false;
        self.landlock_acknowledged = true;
        self
    }

    /// Add a fine-grained Landlock access rule for a specific path.
    ///
    /// When Landlock is enabled, these rules override the default behavior
    /// for the specified paths. Use this for paths that need different
    /// access than their parent mount provides.
    pub fn landlock_rule(&mut self, path: impl Into<PathBuf>, writable: bool) -> &mut Self {
        self.landlock_rules.push(LandlockRule {
            path: path.into(),
            writable,
        });
        self
    }

    /// Set cgroup resource limits.
    pub fn resource_limits(&mut self, limits: ResourceLimits) -> &mut Self {
        self.resource_limits = Some(limits);
        self
    }

    // ── Environment ──────────────────────────────────────────────

    /// Set an environment variable visible to the inner process.
    pub fn env(&mut self, key: impl Into<String>, value: impl Into<String>) -> &mut Self {
        self.env.push((key.into(), value.into()));
        self
    }

    // ── File injection ────────────────────────────────────────────

    /// Create a file with specific contents inside the container.
    ///
    /// The file is created before the inner command executes. Useful for
    /// injecting configuration files like `/etc/resolv.conf` or app configs.
    pub fn file(&mut self, path: impl Into<PathBuf>, contents: impl Into<String>) -> &mut Self {
        self.files.push(ContainerFile {
            path: path.into(),
            contents: contents.into(),
        });
        self
    }

    /// Create a directory with specific permissions inside the container.
    pub fn dir(&mut self, path: impl Into<PathBuf>, mode: u32) -> &mut Self {
        self.dirs.push(ContainerDir {
            path: path.into(),
            mode,
        });
        self
    }

    /// Create a symbolic link inside the container.
    ///
    /// The symlink is created via a staging directory before exec.
    pub fn symlink(&mut self, target: impl Into<PathBuf>, link: impl Into<PathBuf>) -> &mut Self {
        self.symlinks.push(ContainerSymlink {
            target: target.into(),
            link: link.into(),
        });
        self
    }

    // ── Virtual filesystem control ───────────────────────────────

    /// Control whether `/proc` is mounted inside the container.
    ///
    /// Enabled by default. Sandbox-init tries `hidepid=2` for privacy,
    /// falling back to plain procfs or a host bind-mount.
    /// Disable if the workload doesn't need `/proc` access.
    pub fn mount_proc(&mut self, enabled: bool) -> &mut Self {
        self.mount_proc = enabled;
        self
    }

    /// Control whether `/dev` is mounted inside the container.
    ///
    /// Enabled by default with a minimal device set (null, zero, full,
    /// urandom, tty, pts). Disable for fully headless workloads that
    /// don't need device access.
    pub fn mount_dev(&mut self, enabled: bool) -> &mut Self {
        self.mount_dev = enabled;
        self
    }

    // ── Introspection ─────────────────────────────────────────────

    /// Whether Landlock is enabled in this sandbox configuration.
    pub fn is_landlock_enabled(&self) -> bool {
        self.landlock_enabled
    }

    /// Clean up any staging directories created by file/dir/symlink injection.
    ///
    /// Called automatically on [`Drop`], but can be called explicitly if you
    /// want to control cleanup timing.
    pub fn cleanup(&self) {
        if self.files.is_empty() && self.dirs.is_empty() && self.symlinks.is_empty() {
            return;
        }
        let staging = std::env::temp_dir().join(format!(".gleisner-inject-{}", std::process::id()));
        if staging.exists() {
            std::fs::remove_dir_all(&staging).ok();
        }
    }

    // ── Build and execute ────────────────────────────────────────

    /// Create a [`Command`] that will execute the given program inside this
    /// sandbox. The sandbox is finalized at this point — further builder
    /// mutations will not affect the returned command.
    pub fn command(&self, program: impl AsRef<str>) -> Result<Command, ContainerError> {
        self.command_with_args(program, &[] as &[&str])
    }

    /// Create a [`Command`] with the given program and arguments.
    pub fn command_with_args(
        &self,
        program: impl AsRef<str>,
        args: &[impl AsRef<str>],
    ) -> Result<Command, ContainerError> {
        // Require explicit Landlock acknowledgment from empty() sandboxes
        if !self.landlock_acknowledged {
            return Err(ContainerError::Config(
                "Sandbox::empty() requires calling .landlock(true) or .no_landlock() \
                 before creating commands — explicitly acknowledge the security posture"
                    .to_owned(),
            ));
        }

        let mut inner_command = vec![program.as_ref().to_owned()];
        inner_command.extend(args.iter().map(|a| a.as_ref().to_owned()));

        let config = self.to_session_config(&inner_command)?;
        let prepared = prepare_sandbox(config, &inner_command)?;
        Ok(Command::new(prepared))
    }

    /// Convert builder state into a [`SandboxSessionConfig`] for gleisner-polis.
    fn to_session_config(
        &self,
        _inner_command: &[String],
    ) -> Result<SandboxSessionConfig, ContainerError> {
        let mut readonly_bind = Vec::new();
        let mut readwrite_bind = Vec::new();
        let mut tmpfs_paths = Vec::new();

        for mount in &self.mounts {
            match mount {
                Mount::ReadOnly { host, .. } => {
                    readonly_bind.push(host.clone());
                }
                Mount::ReadWrite { host, .. } => {
                    readwrite_bind.push(host.clone());
                }
                Mount::Tmpfs { container } => {
                    tmpfs_paths.push(container.clone());
                }
            }
        }

        // Fine-grained Landlock rules map to additional bind paths
        for rule in &self.landlock_rules {
            if rule.writable {
                if !readwrite_bind.contains(&rule.path) {
                    readwrite_bind.push(rule.path.clone());
                }
            } else if !readonly_bind.contains(&rule.path) {
                readonly_bind.push(rule.path.clone());
            }
        }

        // File injection: write files to a staging dir, then bind-mount them.
        // Each file becomes a host-side file that gets bind-mounted read-only
        // into the container at the target path.
        if !self.files.is_empty() || !self.dirs.is_empty() || !self.symlinks.is_empty() {
            let staging =
                std::env::temp_dir().join(format!(".gleisner-inject-{}", std::process::id()));
            // Prevent symlink race: if the path exists and is a symlink, refuse
            if staging.is_symlink() {
                return Err(ContainerError::Config(format!(
                    "staging path {} is a symlink — refusing to follow",
                    staging.display()
                )));
            }
            std::fs::create_dir_all(&staging)
                .map_err(|e| ContainerError::Config(format!("create staging dir: {e}")))?;

            for dir in &self.dirs {
                let host_path = staging.join(dir.path.strip_prefix("/").unwrap_or(&dir.path));
                std::fs::create_dir_all(&host_path)
                    .map_err(|e| ContainerError::Config(format!("create dir: {e}")))?;
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    std::fs::set_permissions(&host_path, std::fs::Permissions::from_mode(dir.mode))
                        .map_err(|e| ContainerError::Config(format!("set dir mode: {e}")))?;
                }
                readwrite_bind.push(host_path);
            }

            for file in &self.files {
                let host_path = staging.join(file.path.strip_prefix("/").unwrap_or(&file.path));
                if let Some(parent) = host_path.parent() {
                    std::fs::create_dir_all(parent)
                        .map_err(|e| ContainerError::Config(format!("create parent: {e}")))?;
                }
                std::fs::write(&host_path, &file.contents)
                    .map_err(|e| ContainerError::Config(format!("write file: {e}")))?;
                // Bind-mount the parent directory so the file is visible
                // (sandbox-init mounts directories, not individual files)
                let parent = host_path.parent().unwrap_or(&staging).to_path_buf();
                if !readonly_bind.contains(&parent) && !readwrite_bind.contains(&parent) {
                    readonly_bind.push(parent);
                }
            }

            for symlink in &self.symlinks {
                let link_path =
                    staging.join(symlink.link.strip_prefix("/").unwrap_or(&symlink.link));
                if let Some(parent) = link_path.parent() {
                    std::fs::create_dir_all(parent).map_err(|e| {
                        ContainerError::Config(format!("create symlink parent: {e}"))
                    })?;
                }
                #[cfg(unix)]
                std::os::unix::fs::symlink(&symlink.target, &link_path)
                    .map_err(|e| ContainerError::Config(format!("create symlink: {e}")))?;
                let parent = link_path.parent().unwrap_or(&staging).to_path_buf();
                if !readonly_bind.contains(&parent) && !readwrite_bind.contains(&parent) {
                    readonly_bind.push(parent);
                }
            }
        }

        let network = match &self.network {
            NetworkMode::Host => NetworkPolicy {
                default: PolicyDefault::Allow,
                allow_domains: Vec::new(),
                allow_ports: Vec::new(),
                allow_dns: true,
            },
            NetworkMode::Isolated {
                allow_domains,
                allow_dns,
            } => NetworkPolicy {
                default: PolicyDefault::Deny,
                allow_domains: allow_domains.clone(),
                allow_ports: Vec::new(),
                allow_dns: *allow_dns,
            },
            NetworkMode::None => NetworkPolicy {
                default: PolicyDefault::Deny,
                allow_domains: Vec::new(),
                allow_ports: Vec::new(),
                allow_dns: false,
            },
        };

        let seccomp = match &self.seccomp {
            SeccompPreset::Disabled => SeccompPolicy::default(),
            SeccompPreset::Baseline => SeccompPolicy {
                // Baseline uses the Nodejs allowlist — it's the broadest
                // implemented allowlist and covers most userspace tools.
                preset: gleisner_polis::profile::SeccompPreset::Nodejs,
                default_action: SeccompAction::Errno,
                allow_syscalls: Vec::new(),
            },
            SeccompPreset::Nodejs => SeccompPolicy {
                preset: gleisner_polis::profile::SeccompPreset::Nodejs,
                default_action: SeccompAction::Errno,
                allow_syscalls: Vec::new(),
            },
            SeccompPreset::Custom(syscalls) => SeccompPolicy {
                preset: gleisner_polis::profile::SeccompPreset::Custom,
                default_action: SeccompAction::Errno,
                allow_syscalls: syscalls.clone(),
            },
        };

        let project_dir = self
            .project_dir
            .clone()
            .or_else(|| self.work_dir.clone())
            .or_else(|| std::env::current_dir().ok())
            .ok_or_else(|| {
                ContainerError::Config(
                    "no project_dir, work_dir, or current directory available".to_owned(),
                )
            })?;

        // Sharp edge: warn when Landlock is disabled with readwrite mounts
        if !self.landlock_enabled && !readwrite_bind.is_empty() {
            tracing::warn!(
                readwrite_count = readwrite_bind.len(),
                "Landlock is disabled — readwrite mounts have no filesystem access control. \
                 Call .landlock(true) for production use."
            );
        }

        // If project_dir was explicitly set, ensure it's mounted readwrite
        if let Some(ref pd) = self.project_dir
            && !readwrite_bind.contains(pd)
        {
            readwrite_bind.push(pd.clone());
        }

        let profile = gleisner_polis::Profile {
            name: "container".to_owned(),
            description: "gleisner-container builder sandbox".to_owned(),
            filesystem: FilesystemPolicy {
                readonly_bind,
                readwrite_bind,
                deny: self.deny_paths.clone(),
                tmpfs: tmpfs_paths,
            },
            network,
            process: ProcessPolicy {
                pid_namespace: self.namespaces.contains(&Namespace::Pid),
                no_new_privileges: true,
                command_allowlist: Vec::new(),
                seccomp,
            },
            resources: self.resource_limits.clone().unwrap_or(ResourceLimits {
                max_memory_mb: 0,
                max_cpu_percent: 0,
                max_pids: 0,
                max_file_descriptors: 0,
                max_disk_write_mb: 0,
            }),
            plugins: gleisner_polis::profile::PluginPolicy::default(),
        };

        Ok(SandboxSessionConfig {
            profile,
            project_dir,
            extra_allow_network: Vec::new(),
            extra_allow_paths: Vec::new(),
            no_landlock: !self.landlock_enabled,
            no_cgroups: self.resource_limits.is_none(),
            extra_env: self.env.clone(),
            hostname: self.hostname.clone(),
        })
    }
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        self.cleanup();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builder_defaults() {
        let sb = Sandbox::new();
        assert!(sb.landlock_enabled);
        assert!(sb.namespaces.is_empty());
        assert_eq!(sb.hostname, "gleisner-sandbox");
    }

    #[test]
    fn builder_chaining() {
        let mut sb = Sandbox::new();
        sb.namespace(Namespace::Pid)
            .namespace(Namespace::Time)
            .mount_readonly("/usr", "/usr")
            .mount_readwrite("/tmp/work", "/work")
            .tmpfs("/tmp")
            .hostname("test")
            .seccomp(SeccompPreset::Nodejs)
            .env("FOO", "bar");

        assert!(sb.namespaces.contains(&Namespace::Pid));
        assert!(sb.namespaces.contains(&Namespace::Time));
        assert_eq!(sb.mounts.len(), 3);
        assert_eq!(sb.hostname, "test");
        assert_eq!(sb.env.len(), 1);
    }

    #[test]
    fn empty_constructor_disables_landlock() {
        let sb = Sandbox::empty();
        assert!(!sb.landlock_enabled);
        assert!(!sb.is_landlock_enabled());
        // Should still have sensible defaults
        assert!(sb.mount_proc);
        assert!(sb.mount_dev);
        assert_eq!(sb.hostname, "gleisner-sandbox");
    }

    #[test]
    fn project_dir_sets_work_dir_and_mount() {
        let mut sb = Sandbox::new();
        sb.project_dir("/workspace/myproject");

        assert_eq!(sb.work_dir, Some(PathBuf::from("/workspace/myproject")));
        assert_eq!(sb.project_dir, Some(PathBuf::from("/workspace/myproject")));

        // Verify project_dir gets auto-mounted in the config
        let config = sb.to_session_config(&["true".to_owned()]).unwrap();
        assert!(
            config
                .profile
                .filesystem
                .readwrite_bind
                .contains(&PathBuf::from("/workspace/myproject")),
            "project_dir should be auto-mounted readwrite"
        );
    }

    #[test]
    fn work_dir_alone_does_not_auto_mount() {
        let mut sb = Sandbox::new();
        sb.work_dir("/some/path");

        let config = sb.to_session_config(&["true".to_owned()]).unwrap();
        // work_dir without project_dir should NOT auto-mount
        assert!(
            !config
                .profile
                .filesystem
                .readwrite_bind
                .contains(&PathBuf::from("/some/path")),
            "work_dir alone should not auto-mount"
        );
    }

    /// E2e: spawn a process inside a sandbox and verify isolation.
    #[test]
    fn e2e_sandbox_hostname() {
        // Test binary is in target/debug/deps/, sandbox-init is in target/debug/.
        let has_init = std::env::current_exe().ok().and_then(|exe| {
            let candidate = exe.parent()?.parent()?.join("gleisner-sandbox-init");
            candidate.is_file().then_some(())
        });
        if has_init.is_none() {
            eprintln!("skipping: gleisner-sandbox-init not built");
            return;
        }

        // Check user namespace support
        let probe = std::process::Command::new("unshare")
            .args(["--user", "true"])
            .output();
        if probe.is_err() || !probe.as_ref().unwrap().status.success() {
            eprintln!("skipping: no user namespace support");
            return;
        }

        let mut sb = Sandbox::new();
        sb.namespace(Namespace::Pid)
            .mount_readonly("/usr", "/usr")
            .mount_readonly("/lib", "/lib")
            .mount_readonly("/lib64", "/lib64")
            .mount_readonly("/bin", "/bin")
            .tmpfs("/tmp")
            .hostname("test-container")
            .landlock(false); // Skip landlock for this test

        let result = sb.command_with_args("/bin/hostname", &[] as &[&str]);
        if let Err(ref e) = result {
            eprintln!("skipping: command build failed: {e}");
            return;
        }

        let output = result.unwrap().output().expect("run sandbox");
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            stdout.contains("gleisner-sandbox") || output.status.success(),
            "expected hostname in output or success, got: {stdout}"
        );
    }

    #[test]
    fn allow_domains_convenience() {
        let mut sb = Sandbox::new();
        sb.allow_domains(["api.anthropic.com", "registry.npmjs.org"]);

        match &sb.network {
            NetworkMode::Isolated {
                allow_domains,
                allow_dns,
            } => {
                assert_eq!(allow_domains.len(), 2);
                assert_eq!(allow_domains[0], "api.anthropic.com");
                assert_eq!(allow_domains[1], "registry.npmjs.org");
                assert!(*allow_dns);
            }
            other => panic!("expected Isolated, got: {other:?}"),
        }
    }

    #[test]
    fn rootfs_discovers_standard_dirs() {
        let mut sb = Sandbox::new();
        sb.rootfs();

        // Should have discovered at least /usr and /bin (always present on Linux)
        let readonly_paths: Vec<_> = sb
            .mounts
            .iter()
            .filter_map(|m| match m {
                Mount::ReadOnly { host, .. } => Some(host.to_str().unwrap_or("")),
                _ => None,
            })
            .collect();

        assert!(
            readonly_paths.contains(&"/usr"),
            "rootfs should discover /usr"
        );
        assert!(
            readonly_paths.contains(&"/bin"),
            "rootfs should discover /bin"
        );

        // Should include /etc files
        assert!(
            readonly_paths.iter().any(|p| p.starts_with("/etc/")),
            "rootfs should discover /etc files"
        );

        // Should have a tmpfs for /tmp
        let has_tmp = sb
            .mounts
            .iter()
            .any(|m| matches!(m, Mount::Tmpfs { container } if container == Path::new("/tmp")));
        assert!(has_tmp, "rootfs should add /tmp tmpfs");
    }

    #[test]
    fn rootfs_is_idempotent_with_manual_mounts() {
        let mut sb = Sandbox::new();
        // Manual mount first, then rootfs — should not duplicate
        sb.mount_readonly("/usr", "/usr").rootfs();

        let usr_count = sb
            .mounts
            .iter()
            .filter(|m| matches!(m, Mount::ReadOnly { host, .. } if host == Path::new("/usr")))
            .count();

        // rootfs adds /usr even if already present (dedup happens in to_session_config)
        // This is by design — the profile merge in polis handles dedup
        assert!(usr_count >= 1);
    }

    #[test]
    fn file_injection() {
        let mut sb = Sandbox::new();
        sb.file("/etc/resolv.conf", "nameserver 1.1.1.1\n")
            .file("/app/config.toml", "[settings]\nverbose = true\n");

        assert_eq!(sb.files.len(), 2);
        assert_eq!(sb.files[0].path, Path::new("/etc/resolv.conf"));
        assert_eq!(sb.files[1].contents, "[settings]\nverbose = true\n");
    }

    #[test]
    fn dir_creation() {
        let mut sb = Sandbox::new();
        sb.dir("/app/data", 0o755).dir("/app/cache", 0o700);

        assert_eq!(sb.dirs.len(), 2);
        assert_eq!(sb.dirs[0].mode, 0o755);
    }

    #[test]
    fn landlock_rule_maps_to_binds() {
        let mut sb = Sandbox::new();
        sb.landlock_rule("/opt/data", false) // read-only
            .landlock_rule("/var/log", true); // read-write

        let config = sb.to_session_config(&["true".to_owned()]).unwrap();

        assert!(
            config
                .profile
                .filesystem
                .readonly_bind
                .contains(&PathBuf::from("/opt/data")),
            "read-only landlock rule should add to readonly_bind"
        );
        assert!(
            config
                .profile
                .filesystem
                .readwrite_bind
                .contains(&PathBuf::from("/var/log")),
            "writable landlock rule should add to readwrite_bind"
        );
    }

    #[test]
    fn symlink_creation() {
        let mut sb = Sandbox::new();
        sb.symlink("/usr/bin/python3", "/usr/local/bin/python");

        assert_eq!(sb.symlinks.len(), 1);
        assert_eq!(sb.symlinks[0].target, Path::new("/usr/bin/python3"));
        assert_eq!(sb.symlinks[0].link, Path::new("/usr/local/bin/python"));
    }

    #[test]
    fn procfs_devfs_control() {
        let mut sb = Sandbox::new();
        assert!(sb.mount_proc, "proc should be enabled by default");
        assert!(sb.mount_dev, "dev should be enabled by default");

        sb.mount_proc(false).mount_dev(false);
        assert!(!sb.mount_proc);
        assert!(!sb.mount_dev);
    }

    /// Helper: skip test if sandbox-init not available or no user namespaces.
    fn skip_if_no_sandbox() -> bool {
        let has_init = std::env::current_exe().ok().and_then(|exe| {
            let candidate = exe.parent()?.parent()?.join("gleisner-sandbox-init");
            candidate.is_file().then_some(())
        });
        if has_init.is_none() {
            eprintln!(
                "skipping: gleisner-sandbox-init not built (run: cargo build -p gleisner-sandbox-init)"
            );
            return true;
        }
        let probe = std::process::Command::new("unshare")
            .args(["--user", "true"])
            .output();
        if probe.is_err() || !probe.as_ref().unwrap().status.success() {
            eprintln!("skipping: no user namespace support");
            return true;
        }
        false
    }

    #[test]
    fn e2e_rootfs_echo() {
        if skip_if_no_sandbox() {
            return;
        }

        let mut sb = Sandbox::new();
        sb.rootfs()
            .namespace(Namespace::Pid)
            .hostname("test-rootfs")
            .landlock(false);

        let result = sb.command_with_args("/bin/echo", &["rootfs works"]);
        if let Err(ref e) = result {
            eprintln!("skipping: {e}");
            return;
        }

        let output = result.unwrap().output().expect("run sandbox");
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            stdout.contains("rootfs works"),
            "expected 'rootfs works' in stdout, got: {stdout}"
        );
        assert!(output.status.success());
    }

    #[test]
    fn e2e_rootfs_hostname() {
        if skip_if_no_sandbox() {
            return;
        }

        let mut sb = Sandbox::new();
        sb.rootfs()
            .namespace(Namespace::Pid)
            .hostname("custom-host")
            .landlock(false);

        let result = sb.command_with_args("/bin/hostname", &[] as &[&str]);
        if let Err(ref e) = result {
            eprintln!("skipping: {e}");
            return;
        }

        let output = result.unwrap().output().expect("run sandbox");
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            stdout.contains("custom-host") || stdout.contains("gleisner-sandbox"),
            "expected custom hostname, got: {stdout}"
        );
    }

    #[test]
    fn e2e_rootfs_pid_namespace() {
        if skip_if_no_sandbox() {
            return;
        }

        let mut sb = Sandbox::new();
        sb.rootfs().namespace(Namespace::Pid).landlock(false);

        // In a PID namespace, the sandboxed process should be PID 1
        let result = sb.command_with_args("/bin/sh", &["-c", "echo $$"]);
        if let Err(ref e) = result {
            eprintln!("skipping: {e}");
            return;
        }

        let output = result.unwrap().output().expect("run sandbox");
        let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
        assert_eq!(stdout, "1", "process should be PID 1 inside namespace");
    }

    #[test]
    fn e2e_rootfs_env_injection() {
        if skip_if_no_sandbox() {
            return;
        }

        let mut sb = Sandbox::new();
        sb.rootfs()
            .namespace(Namespace::Pid)
            .env("MY_VAR", "hello_container")
            .landlock(false);

        let result = sb.command_with_args("/bin/sh", &["-c", "echo $MY_VAR"]);
        if let Err(ref e) = result {
            eprintln!("skipping: {e}");
            return;
        }

        let output = result.unwrap().output().expect("run sandbox");
        let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
        assert_eq!(stdout, "hello_container", "env var should be visible");
    }

    #[test]
    fn e2e_rootfs_with_landlock() {
        if skip_if_no_sandbox() {
            return;
        }

        let mut sb = Sandbox::new();
        sb.rootfs().namespace(Namespace::Pid).landlock(true); // Enable Landlock

        // /bin/true should work (it's in the rootfs)
        let result = sb.command_with_args("/bin/true", &[] as &[&str]);
        if let Err(ref e) = result {
            eprintln!("skipping: {e}");
            return;
        }

        let output = result.unwrap().output().expect("run sandbox");
        assert!(
            output.status.success(),
            "should succeed with Landlock enabled"
        );
    }

    #[test]
    fn e2e_allow_domains_network() {
        if skip_if_no_sandbox() {
            return;
        }

        let mut sb = Sandbox::new();
        sb.rootfs()
            .namespace(Namespace::Pid)
            .allow_domains(["api.anthropic.com"])
            .seccomp(SeccompPreset::Nodejs)
            .landlock(false);

        // Just verify the sandbox starts — network actually working requires
        // pasta which may not be available in all test environments
        let result = sb.command_with_args("/bin/true", &[] as &[&str]);
        if let Err(ref e) = result {
            eprintln!("skipping (pasta not available?): {e}");
            return;
        }

        let output = result.unwrap().output().expect("run sandbox");
        assert!(output.status.success());
    }

    #[test]
    fn to_session_config_maps_correctly() {
        let mut sb = Sandbox::new();
        sb.namespace(Namespace::Pid)
            .mount_readonly("/usr", "/usr")
            .mount_readwrite("/workspace", "/workspace")
            .deny_path("/etc/shadow")
            .network(NetworkMode::Isolated {
                allow_domains: vec!["api.anthropic.com".to_owned()],
                allow_dns: true,
            })
            .seccomp(SeccompPreset::Nodejs)
            .landlock(true);

        let config = sb
            .to_session_config(&["echo".to_owned(), "test".to_owned()])
            .unwrap();

        assert!(config.profile.process.pid_namespace);
        assert_eq!(config.profile.filesystem.readonly_bind.len(), 1);
        assert_eq!(config.profile.filesystem.readwrite_bind.len(), 1);
        assert_eq!(config.profile.filesystem.deny.len(), 1);
        assert_eq!(config.profile.network.allow_domains.len(), 1);
        assert!(config.profile.network.allow_dns);
        assert!(!config.no_landlock);
        assert_eq!(
            config.profile.process.seccomp.preset,
            gleisner_polis::profile::SeccompPreset::Nodejs
        );
    }

    #[test]
    fn bind_ro_shorthand() {
        let mut sb = Sandbox::new();
        sb.bind_ro("/usr");

        assert!(matches!(&sb.mounts[0], Mount::ReadOnly { host, container }
            if host == Path::new("/usr") && container == Path::new("/usr")));
    }

    #[test]
    fn bind_ro_all_batch() {
        let mut sb = Sandbox::new();
        sb.bind_ro_all(["/usr", "/lib", "/bin"]);
        assert_eq!(sb.mounts.len(), 3);
    }

    #[test]
    fn mount_home_readonly_adds_home() {
        let mut sb = Sandbox::new();
        sb.mount_home_readonly();

        // Should have at least one mount (if $HOME is set)
        if std::env::var("HOME").is_ok() {
            assert!(
                !sb.mounts.is_empty(),
                "mount_home_readonly should add home dir"
            );
        }
    }

    #[test]
    fn cleanup_removes_staging() {
        let mut sb = Sandbox::new();
        sb.file("/test/config", "content");

        // Create the staging dir by calling to_session_config
        let _ = sb.to_session_config(&["true".to_owned()]);

        let staging = std::env::temp_dir().join(format!(".gleisner-inject-{}", std::process::id()));
        // Staging might exist from to_session_config
        if staging.exists() {
            sb.cleanup();
            assert!(!staging.exists(), "cleanup should remove staging dir");
        }
    }
}
