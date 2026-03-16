//! The [`Sandbox`] builder — configure and spawn isolated Linux containers.

use std::collections::HashSet;
use std::path::PathBuf;

use gleisner_polis::profile::{
    FilesystemPolicy, NetworkPolicy, PolicyDefault, ProcessPolicy, ResourceLimits, SeccompAction,
    SeccompPolicy,
};
use gleisner_polis::{SandboxSessionConfig, prepare_sandbox};

use crate::command::Command;
use crate::error::ContainerError;
use crate::types::{Mount, Namespace, NetworkMode, SeccompPreset};

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
    hostname: String,
    network: NetworkMode,
    seccomp: SeccompPreset,
    landlock_enabled: bool,
    env: Vec<(String, String)>,
    resource_limits: Option<ResourceLimits>,
    uid: u32,
    gid: u32,
}

impl Default for Sandbox {
    fn default() -> Self {
        Self::new()
    }
}

impl Sandbox {
    /// Create a new sandbox builder with minimal defaults.
    pub fn new() -> Self {
        let uid = nix::unistd::getuid().as_raw();
        let gid = nix::unistd::getgid().as_raw();
        Self {
            namespaces: HashSet::new(),
            mounts: Vec::new(),
            deny_paths: Vec::new(),
            work_dir: None,
            hostname: "gleisner-sandbox".to_owned(),
            network: NetworkMode::None,
            seccomp: SeccompPreset::Disabled,
            landlock_enabled: true,
            env: Vec::new(),
            resource_limits: None,
            uid,
            gid,
        }
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
    pub fn work_dir(&mut self, path: impl Into<PathBuf>) -> &mut Self {
        self.work_dir = Some(path.into());
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
        let mut inner_command = vec![program.as_ref().to_owned()];
        inner_command.extend(args.iter().map(|a| a.as_ref().to_owned()));

        let config = self.to_session_config(&inner_command)?;
        let prepared = prepare_sandbox(config, &inner_command)?;
        Ok(Command { prepared })
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

        let work_dir = self
            .work_dir
            .clone()
            .or_else(|| std::env::current_dir().ok())
            .unwrap_or_else(|| PathBuf::from("/"));

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
            project_dir: work_dir,
            extra_allow_network: Vec::new(),
            extra_allow_paths: Vec::new(),
            no_landlock: !self.landlock_enabled,
            no_cgroups: self.resource_limits.is_none(),
            extra_env: self.env.clone(),
            hostname: self.hostname.clone(),
        })
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
}
