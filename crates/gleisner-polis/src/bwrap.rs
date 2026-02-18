//! Bubblewrap sandbox backend.
//!
//! Constructs and executes bubblewrap (`bwrap`) invocations from
//! sandbox profiles. Bubblewrap uses Linux namespaces to create
//! lightweight, unprivileged sandboxes without requiring root.
//!
//! Argument order matters: later bind mounts shadow earlier ones,
//! and deny paths (tmpfs overlays) must come after readonly binds.

use std::path::{Path, PathBuf};
use std::process::Command;

use tracing::{debug, info};

use crate::error::SandboxError;
use crate::profile::{PolicyDefault, Profile};

/// Constructs and executes a bubblewrap sandbox from a [`Profile`].
///
/// The sandbox wraps an inner command (typically `claude`) with
/// filesystem, network, and process isolation as defined by the profile.
pub struct BwrapSandbox {
    profile: Profile,
    project_dir: PathBuf,
    /// Additional domains to allow beyond the profile's allowlist.
    extra_allow_domains: Vec<String>,
    /// Additional paths to mount read-write beyond the profile.
    extra_rw_paths: Vec<PathBuf>,
    /// Path to the `gleisner-sandbox-init` binary on the host filesystem.
    /// When set, Landlock restrictions are applied inside the sandbox
    /// via a trampoline binary that runs before the inner command.
    landlock_init_bin: Option<PathBuf>,
}

impl BwrapSandbox {
    /// Create a new sandbox targeting the given project directory.
    ///
    /// # Errors
    ///
    /// Returns [`SandboxError::BwrapNotFound`] if `bwrap` is not on PATH.
    pub fn new(profile: Profile, project_dir: PathBuf) -> Result<Self, SandboxError> {
        which::which("bwrap").map_err(|_| SandboxError::BwrapNotFound)?;

        info!(
            profile = %profile.name,
            project_dir = %project_dir.display(),
            "creating bwrap sandbox"
        );

        Ok(Self {
            profile,
            project_dir,
            extra_allow_domains: Vec::new(),
            extra_rw_paths: Vec::new(),
            landlock_init_bin: None,
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

    /// Enable Landlock-inside-bwrap via the sandbox-init trampoline binary.
    ///
    /// When enabled, `build_command()` will:
    /// 1. Serialize the profile's filesystem/network policy to a JSON tempfile
    /// 2. Bind-mount the init binary and policy file into the sandbox
    /// 3. Prepend the inner command with `/.gleisner/sandbox-init /.gleisner/policy.json --`
    ///
    /// The caller must hold the returned tempfile handle alive until the
    /// child process exits (the bwrap bind-mount references the host file).
    pub fn enable_landlock(&mut self, init_bin: PathBuf) {
        info!(init_bin = %init_bin.display(), "enabling landlock inside bwrap");
        self.landlock_init_bin = Some(init_bin);
    }

    /// Build the `bwrap` invocation for the given inner command.
    ///
    /// When `use_external_netns` is true:
    /// - `--unshare-net` is **skipped** (the caller must pre-create a
    ///   namespace via [`NamespaceHandle`] and run bwrap inside it via nsenter)
    /// - Firewall rules must be applied separately via
    ///   [`NetworkFilter::apply_firewall_via_nsenter`] before spawning bwrap
    ///
    /// Returns `(Command, Option<NamedTempFile>)`. When Landlock is enabled,
    /// the tempfile contains the serialized `LandlockPolicy` JSON. The caller
    /// **must** hold this handle alive until after the child process exits —
    /// bwrap bind-mounts the host file into the sandbox.
    pub fn build_command(
        &self,
        inner_command: &[String],
        use_external_netns: bool,
    ) -> (Command, Option<tempfile::NamedTempFile>) {
        let mut cmd = Command::new("bwrap");

        // Order matters: filesystem → process → network → working dir → die-with-parent
        self.apply_filesystem_policy(&mut cmd);
        self.apply_process_policy(&mut cmd);

        // When an external namespace is active, skip --unshare-net — the
        // caller enters a pre-created namespace via nsenter instead
        if !use_external_netns {
            self.apply_network_policy(&mut cmd);
        }

        // Landlock-inside-bwrap: serialize policy, bind-mount init binary + policy file,
        // and prepend the inner command with the sandbox-init trampoline.
        let policy_tempfile = self.apply_landlock_policy(&mut cmd);

        // Working directory inside the sandbox
        cmd.args(["--chdir", &self.project_dir.display().to_string()]);

        // Kill sandbox if parent process dies — prevents orphaned sandboxes
        cmd.arg("--die-with-parent");

        // When Landlock is enabled, the inner command is wrapped:
        //   /.gleisner/sandbox-init /.gleisner/policy.json -- <inner_command>
        if self.landlock_init_bin.is_some() {
            cmd.args(["/.gleisner/sandbox-init", "/.gleisner/policy.json", "--"]);
        }

        cmd.args(inner_command);

        debug!(
            args = ?cmd.get_args().collect::<Vec<_>>(),
            "built bwrap command"
        );

        (cmd, policy_tempfile)
    }

    /// Apply filesystem isolation: readonly binds, readwrite binds,
    /// deny paths (tmpfs overlays), and extra tmpfs mounts.
    fn apply_filesystem_policy(&self, cmd: &mut Command) {
        let fs = &self.profile.filesystem;

        // Provide /proc and /dev inside the sandbox
        cmd.args(["--proc", "/proc"]);
        cmd.args(["--dev", "/dev"]);

        // Read-only bind mounts (system paths like /usr, /lib, /etc)
        for path in &fs.readonly_bind {
            let expanded = expand_tilde(path);
            let p = expanded.display().to_string();
            cmd.args(["--ro-bind", &p, &p]);
        }

        // Read-write bind mounts from profile (expand ~ to $HOME)
        for path in &fs.readwrite_bind {
            let expanded = expand_tilde(path);
            if expanded.exists() {
                let p = expanded.display().to_string();
                cmd.args(["--bind", &p, &p]);
            }
        }

        // Extra read-write paths from CLI flags
        for path in &self.extra_rw_paths {
            let p = path.display().to_string();
            cmd.args(["--bind", &p, &p]);
        }

        // Project directory is always read-write
        let proj = self.project_dir.display().to_string();
        cmd.args(["--bind", &proj, &proj]);

        // Denied paths get replaced with empty tmpfs — must come AFTER
        // readonly binds so the tmpfs shadows the bind mount
        for path in &fs.deny {
            let expanded = expand_tilde(path);
            if expanded.exists() {
                cmd.args(["--tmpfs", &expanded.display().to_string()]);
                debug!(path = %expanded.display(), "denying path with tmpfs overlay");
            }
        }

        // Additional tmpfs mounts
        for path in &fs.tmpfs {
            cmd.args(["--tmpfs", &path.display().to_string()]);
        }
    }

    /// Apply process isolation: PID namespace and privilege escalation prevention.
    ///
    /// Note: `no_new_privileges` is enforced by Landlock's `prctl(PR_SET_NO_NEW_PRIVS)`
    /// inside sandbox-init, NOT by bwrap's `--new-session`. Using `--new-session` would
    /// call `setsid()`, disconnecting from the controlling terminal and breaking
    /// interactive use (no Ctrl+C, no stdin). The `--unshare-user` flag already
    /// prevents setuid privilege escalation.
    fn apply_process_policy(&self, cmd: &mut Command) {
        let proc_policy = &self.profile.process;

        if proc_policy.pid_namespace {
            cmd.arg("--unshare-pid");
        }

        // Explicitly create a user namespace and map to the real UID/GID
        // instead of letting bwrap default to UID 0. Without this, Claude
        // Code detects "root" and refuses --dangerously-skip-permissions.
        // --unshare-user is required for --uid/--gid to work.
        let uid = nix::unistd::getuid();
        let gid = nix::unistd::getgid();
        cmd.args([
            "--unshare-user",
            "--uid",
            &uid.to_string(),
            "--gid",
            &gid.to_string(),
        ]);
    }

    /// Apply network isolation.
    ///
    /// When the profile default is `Deny`, the network namespace is
    /// always unshared. Selective domain filtering (via slirp4netns +
    /// iptables) is applied by the `NetworkFilter` wrapper passed to
    /// `build_command()`.
    fn apply_network_policy(&self, cmd: &mut Command) {
        if matches!(self.profile.network.default, PolicyDefault::Deny) {
            cmd.arg("--unshare-net");
        }
    }

    /// When Landlock is enabled, serialize the policy to a tempfile and add
    /// bind-mounts for the init binary and policy file inside the sandbox.
    ///
    /// Returns `Some(tempfile)` that the caller must keep alive, or `None`
    /// if Landlock is not enabled.
    fn apply_landlock_policy(&self, cmd: &mut Command) -> Option<tempfile::NamedTempFile> {
        let init_bin = self.landlock_init_bin.as_ref()?;

        let policy = crate::landlock::LandlockPolicy {
            filesystem: self.profile.filesystem.clone(),
            network: self.profile.network.clone(),
            project_dir: self.project_dir.clone(),
            extra_rw_paths: self.extra_rw_paths.clone(),
        };

        // Write policy JSON to a tempfile on the host
        let mut tmpfile =
            tempfile::NamedTempFile::new().expect("failed to create Landlock policy tempfile");
        serde_json::to_writer(&mut tmpfile, &policy)
            .expect("failed to serialize LandlockPolicy to JSON");

        let policy_path = tmpfile.path().display().to_string();
        let init_path = init_bin.display().to_string();

        // Bind-mount the init binary (read-only) into /.gleisner/sandbox-init
        cmd.args(["--ro-bind", &init_path, "/.gleisner/sandbox-init"]);

        // Bind-mount the policy file (read-only) into /.gleisner/policy.json
        cmd.args(["--ro-bind", &policy_path, "/.gleisner/policy.json"]);

        debug!(
            init_bin = %init_path,
            policy = %policy_path,
            "added landlock policy bind-mounts"
        );

        Some(tmpfile)
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
    /// and `RLIMIT_NPROC` (max processes). These serve as a fallback when
    /// cgroup-based limits cannot be applied (e.g., without `CAP_SYS_ADMIN`),
    /// and as defense-in-depth when cgroups are active.
    ///
    /// Call this immediately after spawning the command returned by
    /// [`build_command()`].
    ///
    /// # Errors
    ///
    /// Returns [`SandboxError::ResourceLimit`] if the rlimit cannot be applied.
    pub fn apply_rlimits(&self, pid: nix::unistd::Pid) -> Result<(), SandboxError> {
        let limits = &self.profile.resources;
        let pid_arg = format!("--pid={}", pid.as_raw());

        // prlimit on a foreign PID requires same UID or CAP_SYS_RESOURCE.
        // Since we just spawned this child, we own it.

        // RLIMIT_NOFILE: max open file descriptors
        if limits.max_file_descriptors > 0 {
            let val = limits.max_file_descriptors;
            Self::run_prlimit(&pid_arg, &format!("--nofile={val}:{val}"), "RLIMIT_NOFILE")?;
            debug!(pid = pid.as_raw(), max_fd = val, "applied RLIMIT_NOFILE");
        }

        // RLIMIT_AS: max virtual memory (bytes). Provides a per-process
        // memory ceiling that works without cgroup delegation.
        if limits.max_memory_mb > 0 {
            let bytes = limits.max_memory_mb * 1024 * 1024;
            Self::run_prlimit(&pid_arg, &format!("--as={bytes}:{bytes}"), "RLIMIT_AS")?;
            debug!(
                pid = pid.as_raw(),
                memory_mb = limits.max_memory_mb,
                "applied RLIMIT_AS"
            );
        }

        // RLIMIT_NPROC: max processes for this UID. This is per-user, not
        // per-cgroup, so it's coarser than pids.max but still useful.
        if limits.max_pids > 0 {
            let val = limits.max_pids;
            Self::run_prlimit(&pid_arg, &format!("--nproc={val}:{val}"), "RLIMIT_NPROC")?;
            debug!(pid = pid.as_raw(), max_pids = val, "applied RLIMIT_NPROC");
        }

        Ok(())
    }

    /// Run a single `prlimit` invocation.
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

/// Expand `~` to the user's home directory.
///
/// Only expands a leading `~` — embedded tildes are left alone.
/// Tries `$HOME` first, falls back to system passwd lookup via
/// `directories::BaseDirs`. Logs a warning and returns the path
/// unchanged only if both methods fail.
pub fn expand_tilde(path: &Path) -> PathBuf {
    let path_str = path.display().to_string();
    if path_str.starts_with('~') {
        let home = std::env::var_os("HOME")
            .map(PathBuf::from)
            .or_else(|| directories::BaseDirs::new().map(|b| b.home_dir().to_path_buf()));
        let Some(home) = home else {
            tracing::warn!(
                path = %path_str,
                "$HOME is not set and passwd lookup failed — tilde path will not be expanded"
            );
            return path.to_path_buf();
        };
        home.join(path.strip_prefix("~").unwrap_or(path))
    } else {
        path.to_path_buf()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::{
        FilesystemPolicy, NetworkPolicy, PluginPolicy, ProcessPolicy, ResourceLimits,
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
                seccomp_profile: None,
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
    fn expand_tilde_substitutes_home() {
        // This test depends on $HOME being set, which is typical
        if std::env::var_os("HOME").is_some() {
            let expanded = expand_tilde(Path::new("~/.ssh"));
            assert!(!expanded.starts_with("~"), "tilde should be expanded");
            assert!(
                expanded.ends_with(".ssh"),
                "path suffix should be preserved"
            );
        }
    }

    #[test]
    fn expand_tilde_leaves_absolute_paths_alone() {
        let path = Path::new("/usr/bin");
        let expanded = expand_tilde(path);
        assert_eq!(expanded, PathBuf::from("/usr/bin"));
    }

    #[test]
    fn build_command_includes_readonly_binds() {
        // Skip if bwrap not installed
        if which::which("bwrap").is_err() {
            return;
        }

        let profile = test_profile(PolicyDefault::Allow);
        let sandbox = BwrapSandbox::new(profile, PathBuf::from("/tmp/test-project"))
            .expect("bwrap should be found");

        let (cmd, _policy_file) =
            sandbox.build_command(&["echo".to_owned(), "hello".to_owned()], false);
        let args = args_of(&cmd);

        assert!(
            args.iter().any(|a| a == "--ro-bind"),
            "should have --ro-bind for /usr"
        );
        assert!(args.iter().any(|a| a == "/usr"), "should bind /usr");
        assert!(
            args.iter().any(|a| a == "--die-with-parent"),
            "should die with parent"
        );
        assert!(
            args.iter().any(|a| a == "echo"),
            "inner command should be present"
        );
    }

    /// Helper: collect bwrap command args as strings for assertions.
    fn args_of(cmd: &Command) -> Vec<String> {
        cmd.get_args()
            .filter_map(|a| a.to_str())
            .map(str::to_owned)
            .collect()
    }

    #[test]
    fn deny_network_unshares_net() {
        if which::which("bwrap").is_err() {
            return;
        }

        let profile = test_profile(PolicyDefault::Deny);
        let sandbox = BwrapSandbox::new(profile, PathBuf::from("/tmp/test-project"))
            .expect("bwrap should be found");

        let (cmd, _policy_file) = sandbox.build_command(&["true".to_owned()], false);
        let args = args_of(&cmd);

        assert!(
            args.iter().any(|a| a == "--unshare-net"),
            "deny network should unshare net namespace"
        );
    }

    #[test]
    fn allow_network_does_not_unshare() {
        if which::which("bwrap").is_err() {
            return;
        }

        let profile = test_profile(PolicyDefault::Allow);
        let sandbox = BwrapSandbox::new(profile, PathBuf::from("/tmp/test-project"))
            .expect("bwrap should be found");

        let (cmd, _policy_file) = sandbox.build_command(&["true".to_owned()], false);
        let args = args_of(&cmd);

        assert!(
            !args.iter().any(|a| a == "--unshare-net"),
            "allow network should not unshare net"
        );
    }

    #[test]
    fn pid_namespace_adds_unshare_pid() {
        if which::which("bwrap").is_err() {
            return;
        }

        let profile = test_profile(PolicyDefault::Allow);
        let sandbox = BwrapSandbox::new(profile, PathBuf::from("/tmp/test-project"))
            .expect("bwrap should be found");

        let (cmd, _policy_file) = sandbox.build_command(&["true".to_owned()], false);
        let args = args_of(&cmd);

        assert!(
            args.iter().any(|a| a == "--unshare-pid"),
            "should unshare PID namespace"
        );
    }

    #[test]
    fn landlock_enabled_adds_init_bind_mounts() {
        if which::which("bwrap").is_err() {
            return;
        }

        let profile = test_profile(PolicyDefault::Allow);
        let mut sandbox = BwrapSandbox::new(profile, PathBuf::from("/tmp/test-project"))
            .expect("bwrap should be found");

        // Use a fake path — we're only checking args, not executing
        sandbox.enable_landlock(PathBuf::from("/usr/bin/gleisner-sandbox-init"));

        let (cmd, policy_file) =
            sandbox.build_command(&["echo".to_owned(), "hello".to_owned()], false);
        let args = args_of(&cmd);

        // Should have bind-mounts for the init binary and policy file
        assert!(
            args.iter().any(|a| a == "/.gleisner/sandbox-init"),
            "should bind-mount sandbox-init"
        );
        assert!(
            args.iter().any(|a| a == "/.gleisner/policy.json"),
            "should bind-mount policy.json"
        );

        // Inner command should be prefixed with sandbox-init invocation
        let args_str = args.join(" ");
        assert!(
            args_str.contains("/.gleisner/sandbox-init /.gleisner/policy.json -- echo hello"),
            "inner command should be wrapped by sandbox-init: {args_str}"
        );

        // Policy tempfile should be present
        assert!(policy_file.is_some(), "should return policy tempfile");
    }

    #[test]
    fn landlock_disabled_returns_no_tempfile() {
        if which::which("bwrap").is_err() {
            return;
        }

        let profile = test_profile(PolicyDefault::Allow);
        let sandbox = BwrapSandbox::new(profile, PathBuf::from("/tmp/test-project"))
            .expect("bwrap should be found");

        let (cmd, policy_file) = sandbox.build_command(&["echo".to_owned()], false);
        let args = args_of(&cmd);

        // Should NOT have Landlock bind-mounts
        assert!(
            !args.iter().any(|a| a == "/.gleisner/sandbox-init"),
            "should not have sandbox-init without enable_landlock"
        );

        assert!(policy_file.is_none(), "should not return policy tempfile");
    }

    #[test]
    fn landlock_policy_json_roundtrips() {
        use crate::landlock::LandlockPolicy;
        use crate::profile::{FilesystemPolicy, NetworkPolicy};

        let policy = LandlockPolicy {
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
            project_dir: PathBuf::from("/home/user/project"),
            extra_rw_paths: vec![],
        };

        let json = serde_json::to_string(&policy).expect("serialize");
        let parsed: LandlockPolicy = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed.project_dir, PathBuf::from("/home/user/project"));
        assert_eq!(parsed.filesystem.readonly_bind.len(), 1);
        assert_eq!(parsed.network.allow_ports, vec![443]);
    }
}
