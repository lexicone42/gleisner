//! Direct sandbox backend — replaces bubblewrap with `gleisner-sandbox-init`.
//!
//! Constructs a [`SandboxSpec`] from a [`Profile`] and launches
//! `gleisner-sandbox-init` to create the sandbox via direct syscalls
//! (user namespaces, bind mounts, `pivot_root`, Landlock).
//!
//! The parent process never needs `unsafe` — all namespace and mount
//! manipulation happens inside the `gleisner-sandbox-init` child process.

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::Command;

use tracing::{debug, info};

use crate::error::SandboxError;
use crate::policy::SandboxSpec;
use crate::profile::Profile;
use crate::util::expand_tilde;

/// Constructs and executes a sandboxed process from a [`Profile`].
///
/// Replaces the previous `BwrapSandbox` — instead of shelling out to
/// bubblewrap, it launches `gleisner-sandbox-init` with a JSON
/// [`SandboxSpec`] piped via a tempfile.
pub struct DirectSandbox {
    profile: Profile,
    project_dir: PathBuf,
    /// Additional domains to allow beyond the profile's allowlist.
    extra_allow_domains: Vec<String>,
    /// Additional paths to mount read-write beyond the profile.
    extra_rw_paths: Vec<PathBuf>,
    /// Whether to apply Landlock restrictions inside the sandbox.
    enable_landlock: bool,
    /// Path to the `gleisner-sandbox-init` binary.
    init_bin: PathBuf,
}

impl DirectSandbox {
    /// Create a new sandbox targeting the given project directory.
    ///
    /// # Errors
    ///
    /// Returns [`SandboxError::SandboxInitNotFound`] if `gleisner-sandbox-init`
    /// is not found.
    pub fn new(profile: Profile, project_dir: PathBuf) -> Result<Self, SandboxError> {
        let init_bin = detect_sandbox_init().ok_or(SandboxError::SandboxInitNotFound)?;

        info!(
            profile = %profile.name,
            project_dir = %project_dir.display(),
            init_bin = %init_bin.display(),
            "creating direct sandbox"
        );

        Ok(Self {
            profile,
            project_dir,
            extra_allow_domains: Vec::new(),
            extra_rw_paths: Vec::new(),
            enable_landlock: true,
            init_bin,
        })
    }

    /// Add domains to the network allowlist beyond the profile defaults.
    pub fn allow_domains(&mut self, domains: impl IntoIterator<Item = String>) {
        self.extra_allow_domains.extend(domains);
    }

    /// Add paths to mount read-write beyond the profile defaults.
    pub fn allow_paths(&mut self, paths: impl IntoIterator<Item = PathBuf>) {
        self.extra_rw_paths.extend(paths);
    }

    /// Disable Landlock enforcement inside the sandbox.
    pub const fn disable_landlock(&mut self) {
        self.enable_landlock = false;
    }

    /// Build the sandbox spec and launch command.
    ///
    /// When `use_external_netns` is true, the sandbox will not create its
    /// own network namespace (the caller pre-creates one via
    /// [`NamespaceHandle`] and wraps the command with nsenter).
    ///
    /// Returns `(Command, NamedTempFile)`. The tempfile contains the
    /// serialized `SandboxSpec` JSON — the caller **must** hold it alive
    /// until the child process exits.
    pub fn build_command(
        &self,
        inner_command: &[String],
        use_external_netns: bool,
    ) -> (Command, tempfile::NamedTempFile) {
        let spec = self.build_spec(inner_command, use_external_netns);

        // Write spec to tempfile
        let mut tmpfile =
            tempfile::NamedTempFile::new().expect("failed to create sandbox spec tempfile");
        serde_json::to_writer(&mut tmpfile, &spec)
            .expect("failed to serialize SandboxSpec to JSON");
        tmpfile.flush().expect("failed to flush sandbox spec");

        let spec_path = tmpfile.path().display().to_string();

        let mut cmd = Command::new(&self.init_bin);
        cmd.arg(&spec_path);

        debug!(
            init_bin = %self.init_bin.display(),
            spec = %spec_path,
            "built direct sandbox command"
        );

        (cmd, tmpfile)
    }

    /// Build the `SandboxSpec` for the given inner command.
    fn build_spec(&self, inner_command: &[String], use_external_netns: bool) -> SandboxSpec {
        // Expand tildes in all filesystem policy paths
        let mut fs = self.profile.filesystem.clone();
        fs.readonly_bind = fs.readonly_bind.iter().map(|p| expand_tilde(p)).collect();
        fs.readwrite_bind = fs.readwrite_bind.iter().map(|p| expand_tilde(p)).collect();
        fs.deny = fs.deny.iter().map(|p| expand_tilde(p)).collect();
        fs.tmpfs = fs.tmpfs.iter().map(|p| expand_tilde(p)).collect();

        let extra_rw = self
            .extra_rw_paths
            .iter()
            .map(|p| expand_tilde(p))
            .collect();

        let uid = nix::unistd::getuid().as_raw();
        let gid = nix::unistd::getgid().as_raw();

        SandboxSpec {
            filesystem: fs,
            network: self.profile.network.clone(),
            process: self.profile.process.clone(),
            project_dir: self.project_dir.clone(),
            extra_rw_paths: extra_rw,
            work_dir: self.project_dir.clone(),
            inner_command: inner_command.to_vec(),
            enable_landlock: self.enable_landlock,
            use_external_netns,
            uid,
            gid,
        }
    }

    /// Get the extra domains added via CLI flags.
    ///
    /// Used by callers that need to pass these to [`NetworkFilter::resolve()`]
    /// alongside the profile's built-in domain list.
    #[must_use]
    pub fn extra_allow_domains(&self) -> &[String] {
        &self.extra_allow_domains
    }

    /// Apply resource limits to a running child process via `prlimit(1)`.
    ///
    /// Sets `RLIMIT_NOFILE` (file descriptors), `RLIMIT_AS` (virtual memory),
    /// `RLIMIT_NPROC` (max processes), and `RLIMIT_FSIZE` (max file size).
    pub fn apply_rlimits(&self, pid: nix::unistd::Pid) -> Result<(), SandboxError> {
        let limits = &self.profile.resources;
        let pid_arg = format!("--pid={}", pid.as_raw());

        if limits.max_file_descriptors > 0 {
            let val = limits.max_file_descriptors;
            Self::run_prlimit(&pid_arg, &format!("--nofile={val}:{val}"), "RLIMIT_NOFILE")?;
            debug!(pid = pid.as_raw(), max_fd = val, "applied RLIMIT_NOFILE");
        }

        if limits.max_memory_mb > 0 {
            let bytes = limits.max_memory_mb * 1024 * 1024;
            Self::run_prlimit(&pid_arg, &format!("--as={bytes}:{bytes}"), "RLIMIT_AS")?;
            debug!(
                pid = pid.as_raw(),
                memory_mb = limits.max_memory_mb,
                "applied RLIMIT_AS"
            );
        }

        if limits.max_pids > 0 {
            let val = limits.max_pids;
            Self::run_prlimit(&pid_arg, &format!("--nproc={val}:{val}"), "RLIMIT_NPROC")?;
            debug!(pid = pid.as_raw(), max_pids = val, "applied RLIMIT_NPROC");
        }

        if limits.max_disk_write_mb > 0 {
            let bytes = limits.max_disk_write_mb * 1024 * 1024;
            Self::run_prlimit(
                &pid_arg,
                &format!("--fsize={bytes}:{bytes}"),
                "RLIMIT_FSIZE",
            )?;
            debug!(
                pid = pid.as_raw(),
                max_disk_write_mb = limits.max_disk_write_mb,
                "applied RLIMIT_FSIZE"
            );
        }

        Ok(())
    }

    fn run_prlimit(pid_arg: &str, limit_arg: &str, name: &'static str) -> Result<(), SandboxError> {
        let output = Command::new("prlimit")
            .args([pid_arg, limit_arg])
            .output()
            .map_err(|e| SandboxError::ResourceLimit {
                resource: name,
                detail: format!("failed to run prlimit: {e}"),
            })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(SandboxError::ResourceLimit {
                resource: name,
                detail: format!("prlimit failed: {stderr}"),
            });
        }
        Ok(())
    }

    /// Get a reference to the loaded profile.
    #[must_use]
    pub const fn profile(&self) -> &Profile {
        &self.profile
    }

    /// Get the project directory this sandbox targets.
    #[must_use]
    pub fn project_dir(&self) -> &Path {
        &self.project_dir
    }
}

/// Try to find the `gleisner-sandbox-init` binary.
///
/// Checks alongside the running binary first, then falls back to `PATH`.
pub(crate) fn detect_sandbox_init() -> Option<PathBuf> {
    if let Ok(exe) = std::env::current_exe() {
        let sibling = exe.with_file_name("gleisner-sandbox-init");
        if sibling.is_file() {
            return Some(sibling);
        }
    }
    which::which("gleisner-sandbox-init").ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::{
        FilesystemPolicy, NetworkPolicy, PluginPolicy, PolicyDefault, ProcessPolicy, ResourceLimits,
    };

    fn test_profile(network_default: PolicyDefault) -> Profile {
        Profile {
            name: "test".to_owned(),
            description: "test profile".to_owned(),
            filesystem: FilesystemPolicy {
                readonly_bind: vec![PathBuf::from("/usr"), PathBuf::from("/lib")],
                readwrite_bind: vec![],
                deny: vec![],
                tmpfs: vec![PathBuf::from("/tmp")],
            },
            network: NetworkPolicy {
                default: network_default,
                allow_domains: vec!["api.anthropic.com".to_owned()],
                allow_ports: vec![443],
                allow_dns: true,
            },
            process: ProcessPolicy {
                pid_namespace: true,
                no_new_privileges: true,
                command_allowlist: vec![],
            },
            resources: ResourceLimits {
                max_memory_mb: 4096,
                max_cpu_percent: 100,
                max_pids: 256,
                max_file_descriptors: 1024,
                max_disk_write_mb: 10240,
            },
            plugins: PluginPolicy::default(),
        }
    }

    #[test]
    fn build_spec_has_correct_uid_gid() {
        let profile = test_profile(PolicyDefault::Allow);
        let sandbox = DirectSandbox {
            profile,
            project_dir: PathBuf::from("/tmp/test-project"),
            extra_allow_domains: vec![],
            extra_rw_paths: vec![],
            enable_landlock: true,
            init_bin: PathBuf::from("/usr/bin/gleisner-sandbox-init"),
        };

        let spec = sandbox.build_spec(&["echo".to_owned(), "hello".to_owned()], false);

        assert_eq!(spec.uid, nix::unistd::getuid().as_raw());
        assert_eq!(spec.gid, nix::unistd::getgid().as_raw());
        assert_eq!(spec.inner_command, vec!["echo", "hello"]);
        assert!(!spec.use_external_netns);
        assert!(spec.enable_landlock);
    }

    #[test]
    fn build_spec_expands_tildes() {
        let mut profile = test_profile(PolicyDefault::Allow);
        profile
            .filesystem
            .readonly_bind
            .push(PathBuf::from("~/.config/gh"));
        profile
            .filesystem
            .readwrite_bind
            .push(PathBuf::from("~/.cache"));
        profile.filesystem.deny.push(PathBuf::from("~/.ssh"));

        let sandbox = DirectSandbox {
            profile,
            project_dir: PathBuf::from("/tmp/test-project"),
            extra_allow_domains: vec![],
            extra_rw_paths: vec![PathBuf::from("~/.cargo")],
            enable_landlock: true,
            init_bin: PathBuf::from("/usr/bin/gleisner-sandbox-init"),
        };

        let spec = sandbox.build_spec(&["true".to_owned()], false);

        for path in &spec.filesystem.readonly_bind {
            assert!(
                !path.starts_with("~"),
                "readonly_bind should not contain tilde: {}",
                path.display()
            );
        }
        for path in &spec.filesystem.readwrite_bind {
            assert!(
                !path.starts_with("~"),
                "readwrite_bind should not contain tilde: {}",
                path.display()
            );
        }
        for path in &spec.filesystem.deny {
            assert!(
                !path.starts_with("~"),
                "deny should not contain tilde: {}",
                path.display()
            );
        }
        for path in &spec.extra_rw_paths {
            assert!(
                !path.starts_with("~"),
                "extra_rw_paths should not contain tilde: {}",
                path.display()
            );
        }
    }

    #[test]
    fn build_spec_external_netns_skips_unshare() {
        let profile = test_profile(PolicyDefault::Deny);
        let sandbox = DirectSandbox {
            profile,
            project_dir: PathBuf::from("/tmp/test-project"),
            extra_allow_domains: vec![],
            extra_rw_paths: vec![],
            enable_landlock: true,
            init_bin: PathBuf::from("/usr/bin/gleisner-sandbox-init"),
        };

        let spec = sandbox.build_spec(&["true".to_owned()], true);
        assert!(spec.use_external_netns);
    }

    #[test]
    fn build_spec_landlock_disabled() {
        let profile = test_profile(PolicyDefault::Allow);
        let mut sandbox = DirectSandbox {
            profile,
            project_dir: PathBuf::from("/tmp/test-project"),
            extra_allow_domains: vec![],
            extra_rw_paths: vec![],
            enable_landlock: true,
            init_bin: PathBuf::from("/usr/bin/gleisner-sandbox-init"),
        };

        sandbox.disable_landlock();
        let spec = sandbox.build_spec(&["true".to_owned()], false);
        assert!(!spec.enable_landlock);
    }

    #[test]
    fn spec_json_roundtrip() {
        let spec = SandboxSpec {
            filesystem: FilesystemPolicy {
                readonly_bind: vec![PathBuf::from("/usr")],
                readwrite_bind: vec![],
                deny: vec![],
                tmpfs: vec![PathBuf::from("/tmp")],
            },
            network: NetworkPolicy {
                default: PolicyDefault::Deny,
                allow_domains: vec!["api.anthropic.com".to_owned()],
                allow_ports: vec![443],
                allow_dns: true,
            },
            process: ProcessPolicy {
                pid_namespace: true,
                no_new_privileges: true,
                command_allowlist: vec![],
            },
            project_dir: PathBuf::from("/home/user/project"),
            extra_rw_paths: vec![],
            work_dir: PathBuf::from("/home/user/project"),
            inner_command: vec!["echo".to_owned(), "hello".to_owned()],
            enable_landlock: true,
            use_external_netns: false,
            uid: 1000,
            gid: 1000,
        };

        let json = serde_json::to_string(&spec).expect("serialize");
        let parsed: SandboxSpec = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed.project_dir, PathBuf::from("/home/user/project"));
        assert_eq!(parsed.inner_command, vec!["echo", "hello"]);
        assert_eq!(parsed.uid, 1000);
        assert!(parsed.enable_landlock);
    }

    #[test]
    fn detect_sandbox_init_returns_option() {
        let _result = detect_sandbox_init();
    }
}
