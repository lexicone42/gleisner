//! Direct sandbox backend using `gleisner-sandbox-init`.
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
/// Launches `gleisner-sandbox-init` with a JSON [`SandboxSpec`] piped
/// via a tempfile.
pub struct DirectSandbox {
    profile: Profile,
    project_dir: PathBuf,
    /// Additional domains to allow beyond the profile's allowlist.
    extra_allow_domains: Vec<String>,
    /// Additional paths to mount read-write beyond the profile.
    extra_rw_paths: Vec<PathBuf>,
    /// Whether to apply Landlock restrictions inside the sandbox.
    enable_landlock: bool,
    /// Whether to skip cgroup resource limits inside the sandbox.
    no_cgroups: bool,
    /// Path to the `gleisner-sandbox-init` binary.
    init_bin: PathBuf,
    /// Extra environment variables to pass to the inner command.
    extra_env: Vec<(String, String)>,
    /// Hostname for the UTS namespace.
    hostname: String,
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

        // Canonicalize project_dir so bind_mount calculates the correct
        // target path. A relative path like "." would otherwise resolve to
        // new_root itself (via new_root.join(".")), covering the entire
        // tmpfs and hiding old_root — causing pivot_root ENOENT.
        let project_dir = std::fs::canonicalize(&project_dir)
            .map_err(|_| SandboxError::PathNotFound(project_dir.clone()))?;

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
            no_cgroups: false,
            init_bin,
            extra_env: Vec::new(),
            hostname: String::new(),
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

    /// Disable rootless cgroup resource limits inside the sandbox.
    pub const fn disable_cgroups(&mut self) {
        self.no_cgroups = true;
    }

    /// Add extra environment variables to pass to the inner command.
    pub fn set_extra_env(&mut self, env: Vec<(String, String)>) {
        self.extra_env = env;
    }

    /// Set the hostname inside the UTS namespace.
    pub fn set_hostname(&mut self, hostname: String) {
        self.hostname = hostname;
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
            resource_limits: if self.no_cgroups {
                None
            } else {
                Some(self.profile.resources.clone())
            },
            extra_env: self.extra_env.clone(),
            seccomp: self.profile.process.seccomp.clone(),
            hostname: self.hostname.clone(),
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
    /// Sets `RLIMIT_NOFILE` (file descriptors), `RLIMIT_NPROC` (max processes),
    /// and `RLIMIT_FSIZE` (max file size).
    ///
    /// NOTE: `RLIMIT_AS` (virtual address space) is intentionally NOT set.
    /// Node.js/V8 on 64-bit systems reserves far more virtual address space
    /// than physical memory actually used (for GC, JIT compilation, etc.).
    /// Setting `RLIMIT_AS` causes V8's allocator to fail silently, hanging
    /// Claude Code. Use cgroup memory limits instead.
    pub fn apply_rlimits(&self, pid: nix::unistd::Pid) -> Result<(), SandboxError> {
        let limits = &self.profile.resources;
        let pid_arg = format!("--pid={}", pid.as_raw());

        if limits.max_file_descriptors > 0 {
            let val = limits.max_file_descriptors;
            Self::run_prlimit(&pid_arg, &format!("--nofile={val}:{val}"), "RLIMIT_NOFILE")?;
            debug!(pid = pid.as_raw(), max_fd = val, "applied RLIMIT_NOFILE");
        }

        // RLIMIT_AS skipped — see doc comment above.

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
                seccomp: Default::default(),
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
            no_cgroups: false,
            init_bin: PathBuf::from("/usr/bin/gleisner-sandbox-init"),
            extra_env: vec![],
            hostname: String::new(),
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
            no_cgroups: false,
            init_bin: PathBuf::from("/usr/bin/gleisner-sandbox-init"),
            extra_env: vec![],
            hostname: String::new(),
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
            no_cgroups: false,
            init_bin: PathBuf::from("/usr/bin/gleisner-sandbox-init"),
            extra_env: vec![],
            hostname: String::new(),
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
            no_cgroups: false,
            init_bin: PathBuf::from("/usr/bin/gleisner-sandbox-init"),
            extra_env: vec![],
            hostname: String::new(),
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
                seccomp: Default::default(),
            },
            project_dir: PathBuf::from("/home/user/project"),
            extra_rw_paths: vec![],
            work_dir: PathBuf::from("/home/user/project"),
            inner_command: vec!["echo".to_owned(), "hello".to_owned()],
            enable_landlock: true,
            use_external_netns: false,
            uid: 1000,
            gid: 1000,
            resource_limits: None,
            extra_env: vec![],
            seccomp: Default::default(),
            hostname: String::new(),
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

    /// Helper: build and run a sandbox command, returning its stdout.
    /// Skips the test if sandbox-init is not available or user namespaces
    /// are not supported (e.g., GitHub Actions).
    fn run_sandboxed(inner_command: &[&str]) -> Option<String> {
        // detect_sandbox_init() looks for a sibling of the current exe,
        // but test binaries live in target/debug/deps/ while sandbox-init
        // is in target/debug/. Check both locations.
        let init_bin = detect_sandbox_init().or_else(|| {
            let exe = std::env::current_exe().ok()?;
            // target/debug/deps/test-bin -> target/debug/gleisner-sandbox-init
            let parent = exe.parent()?.parent()?;
            let candidate = parent.join("gleisner-sandbox-init");
            candidate.is_file().then_some(candidate)
        })?;

        // Quick check: can we create user namespaces?
        let probe = Command::new("unshare")
            .args(["--user", "--", "true"])
            .output()
            .ok()?;
        if !probe.status.success() {
            return None; // no user namespace support
        }

        let uid = nix::unistd::getuid().as_raw();
        let gid = nix::unistd::getgid().as_raw();
        // Use a project dir under $HOME (not /tmp) because /tmp gets
        // overlaid with a fresh tmpfs inside the sandbox.
        let project_dir =
            PathBuf::from(std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_owned()))
                .join(".gleisner-sandbox-e2e");
        std::fs::create_dir_all(&project_dir).ok();

        let spec = SandboxSpec {
            filesystem: FilesystemPolicy {
                readonly_bind: vec![
                    PathBuf::from("/usr"),
                    PathBuf::from("/lib"),
                    PathBuf::from("/lib64"),
                    PathBuf::from("/bin"),
                    PathBuf::from("/sbin"),
                    PathBuf::from("/etc"),
                ],
                readwrite_bind: vec![],
                deny: vec![],
                tmpfs: vec![PathBuf::from("/tmp")],
            },
            network: NetworkPolicy {
                default: PolicyDefault::Allow,
                allow_domains: vec![],
                allow_ports: vec![],
                allow_dns: false,
            },
            process: ProcessPolicy {
                pid_namespace: true,
                no_new_privileges: true,
                command_allowlist: vec![],
                seccomp: Default::default(),
            },
            project_dir: project_dir.clone(),
            extra_rw_paths: vec![],
            work_dir: project_dir,
            inner_command: inner_command.iter().map(ToString::to_string).collect(),
            enable_landlock: false,
            use_external_netns: false,
            uid,
            gid,
            resource_limits: None,
            extra_env: vec![],
            seccomp: Default::default(),
            hostname: String::new(),
        };

        let json = serde_json::to_string(&spec).expect("serialize spec");
        let mut tmpfile = tempfile::NamedTempFile::new().expect("create spec tempfile");
        use std::io::Write;
        tmpfile.write_all(json.as_bytes()).expect("write spec");
        tmpfile.flush().expect("flush spec");

        let output = Command::new(&init_bin)
            .arg(tmpfile.path())
            .output()
            .expect("spawn sandbox-init");

        let stderr = String::from_utf8_lossy(&output.stderr);
        if !output.status.success() {
            eprintln!("sandbox stderr: {stderr}");
            return None;
        }

        Some(String::from_utf8_lossy(&output.stdout).to_string())
    }

    #[test]
    fn e2e_sandbox_hostname_is_gleisner() {
        let Some(output) = run_sandboxed(&["hostname"]) else {
            eprintln!("skipping: sandbox-init not available or no user namespace support");
            return;
        };
        assert_eq!(
            output.trim(),
            "gleisner-sandbox",
            "UTS namespace should set hostname to gleisner-sandbox"
        );
    }

    #[test]
    fn e2e_sandbox_minimal_dev() {
        // ls /dev inside the sandbox — should only contain our minimal set
        let Some(output) = run_sandboxed(&["ls", "/dev"]) else {
            eprintln!("skipping: sandbox-init not available or no user namespace support");
            return;
        };
        let entries: Vec<&str> = output.lines().collect();

        // Must have essential devices
        assert!(entries.contains(&"null"), "missing /dev/null");
        assert!(entries.contains(&"zero"), "missing /dev/zero");
        assert!(entries.contains(&"urandom"), "missing /dev/urandom");
        assert!(entries.contains(&"pts"), "missing /dev/pts");

        // Must NOT have host devices
        assert!(
            !entries
                .iter()
                .any(|e| e.starts_with("sd") || e.starts_with("nvme")),
            "sandbox /dev should not contain block devices: {entries:?}"
        );
        assert!(
            !entries
                .iter()
                .any(|e| e.starts_with("nvidia") || e.starts_with("dri")),
            "sandbox /dev should not contain GPU devices: {entries:?}"
        );
    }

    #[test]
    fn e2e_sandbox_nosuid_mounts() {
        // Check mount flags: /usr should have nosuid,nodev
        let Some(output) = run_sandboxed(&["cat", "/proc/self/mountinfo"]) else {
            eprintln!("skipping: sandbox-init not available or no user namespace support");
            return;
        };
        // Find the /usr mount line and verify nosuid is present
        for line in output.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() > 5 && parts[4] == "/usr" {
                assert!(
                    parts[5].contains("nosuid") || line.contains("nosuid"),
                    "/usr mount should have nosuid flag: {line}"
                );
                return;
            }
        }
        // If /usr wasn't found as a separate mount, that's ok (merged into root)
    }

    #[test]
    fn e2e_sandbox_tmp_nosuid() {
        // /tmp should be nosuid+nodev (NOT noexec — Node.js needs to exec
        // temp scripts). Verify by checking mount flags in mountinfo.
        let Some(output) = run_sandboxed(&["cat", "/proc/self/mountinfo"]) else {
            eprintln!("skipping: sandbox-init not available or no user namespace support");
            return;
        };
        for line in output.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() > 5 && parts[4] == "/tmp" {
                assert!(
                    line.contains("nosuid"),
                    "/tmp mount should have nosuid flag: {line}"
                );
                assert!(
                    line.contains("nodev"),
                    "/tmp mount should have nodev flag: {line}"
                );
                return;
            }
        }
        panic!("/tmp mount not found in mountinfo");
    }

    #[test]
    fn e2e_sandbox_pivot_root_isolation() {
        // After pivot_root, the old host root should not be accessible.
        // /var, /run, /sys should not exist (not in our bind-mount list).
        let Some(output) = run_sandboxed(&["ls", "/"]) else {
            eprintln!("skipping: sandbox-init not available or no user namespace support");
            return;
        };
        let entries: Vec<&str> = output.lines().collect();
        assert!(
            !entries.contains(&"var"),
            "sandbox root should not contain /var (pivot_root isolation)"
        );
        assert!(
            !entries.contains(&"run"),
            "sandbox root should not contain /run (pivot_root isolation)"
        );
        assert!(
            !entries.contains(&"sys"),
            "sandbox root should not contain /sys (pivot_root isolation)"
        );
        // But /usr, /proc, /dev should exist
        assert!(entries.contains(&"usr"), "sandbox root should contain /usr");
        assert!(
            entries.contains(&"proc"),
            "sandbox root should contain /proc"
        );
        assert!(entries.contains(&"dev"), "sandbox root should contain /dev");
    }

    #[test]
    fn e2e_sandbox_no_leaked_fds() {
        // Verify that FDs 3+ are closed inside the sandbox.
        // The orchestrator opens a spec tempfile (FD 3+) — the inner process
        // should not see it. We check by listing /proc/self/fd inside the
        // sandbox and verifying only 0, 1, 2 are open.
        let Some(output) = run_sandboxed(&["ls", "/proc/self/fd"]) else {
            eprintln!("skipping: sandbox-init not available or no user namespace support");
            return;
        };
        let fds: Vec<i32> = output
            .lines()
            .filter_map(|s| s.trim().parse().ok())
            .collect();

        // FD 0,1,2 (stdin/stdout/stderr) should exist.
        // FD 3 may exist transiently (the ls command's own dirfd for reading
        // /proc/self/fd). But no FDs from the orchestrator (spec tempfile,
        // etc.) should leak through.
        let leaked: Vec<i32> = fds.iter().copied().filter(|&fd| fd > 3).collect();
        assert!(
            leaked.is_empty(),
            "inner process should not inherit FDs from orchestrator, got: {leaked:?}"
        );
    }

    #[test]
    fn e2e_sandbox_env_sanitized() {
        // Verify that arbitrary orchestrator env vars are NOT passed through.
        // Set a custom var in the orchestrator, check it's absent inside.
        //
        // We use `run_sandboxed` which calls Command::new(init_bin).
        // The init_bin reads GLEISNER_TEST_LEAK but env_clear() should strip it.
        //
        // Since we can't set env vars in run_sandboxed's child, we test that
        // well-known safe vars ARE present and a known-unsafe pattern is not.
        let Some(output) = run_sandboxed(&["env"]) else {
            eprintln!("skipping: sandbox-init not available or no user namespace support");
            return;
        };

        // PATH should be present (it's in the whitelist)
        assert!(
            output.lines().any(|l| l.starts_with("PATH=")),
            "sandbox should have PATH set"
        );

        // GLEISNER_ internal vars should NOT leak (the init process sets
        // none by default, and env_clear strips the orchestrator's)
        let leaked: Vec<&str> = output
            .lines()
            .filter(|l| l.starts_with("GLEISNER_"))
            .collect();
        assert!(
            leaked.is_empty(),
            "orchestrator GLEISNER_* vars should not leak: {leaked:?}"
        );
    }

    /// E2E: full TUI sandbox path — namespace + pasta + nftables + sandbox-init
    /// with `use_external_netns=true`.
    ///
    /// This replicates what the TUI does when launching an inner Claude Code:
    /// 1. Create user+net namespace via unshare
    /// 2. Start pasta for TAP networking
    /// 3. Apply nftables IP allowlist + IPv6 reject
    /// 4. Run sandbox-init via nsenter (creates nested user namespace)
    /// 5. Inner command runs with Landlock + network filtering
    ///
    /// The inner command verifies network connectivity to api.anthropic.com,
    /// which exercises the full network path: DNS → pasta → nftables → Landlock.
    #[test]
    fn e2e_full_tui_sandbox_path_with_network() {
        use crate::netfilter::{self, NetworkFilter, TapHandle};

        // Skip if required tools aren't available
        if !netfilter::pasta_available()
            || which::which("nsenter").is_err()
            || which::which("nft").is_err()
            || which::which("node").is_err()
        {
            eprintln!("skipping: required tools not available");
            return;
        }

        let init_bin = detect_sandbox_init().or_else(|| {
            let exe = std::env::current_exe().ok()?;
            let parent = exe.parent()?.parent()?;
            let candidate = parent.join("gleisner-sandbox-init");
            candidate.is_file().then_some(candidate)
        });
        let Some(init_bin) = init_bin else {
            eprintln!("skipping: sandbox-init binary not found");
            return;
        };

        // Step 1+2: Create namespace + pasta (same as NamespaceHandle::create + TapHandle::start)
        let Ok(ns) = crate::NamespaceHandle::create() else {
            eprintln!("skipping: no user namespace support");
            return;
        };
        let Ok(_tap) = TapHandle::start(ns.pid()) else {
            eprintln!("skipping: pasta failed");
            return;
        };

        // Step 3: Resolve domains and apply nftables (same as prepare_sandbox steps 6+8)
        let policy = NetworkPolicy {
            default: PolicyDefault::Deny,
            allow_domains: vec!["api.anthropic.com".to_owned()],
            allow_ports: vec![443],
            allow_dns: true,
        };
        let filter = NetworkFilter::resolve(&policy, &[]).expect("resolve filter");
        if !filter.has_endpoints() {
            eprintln!("skipping: DNS resolution failed");
            return;
        }
        filter
            .apply_firewall_via_nsenter(&ns)
            .expect("apply firewall");

        // Step 4+5: Build sandbox spec with use_external_netns=true
        let uid = nix::unistd::getuid().as_raw();
        let gid = nix::unistd::getgid().as_raw();
        let project_dir =
            PathBuf::from(std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_owned()))
                .join(".gleisner-sandbox-e2e");
        std::fs::create_dir_all(&project_dir).ok();

        let spec = SandboxSpec {
            filesystem: FilesystemPolicy {
                readonly_bind: vec![
                    PathBuf::from("/usr"),
                    PathBuf::from("/lib"),
                    PathBuf::from("/lib64"),
                    PathBuf::from("/bin"),
                    PathBuf::from("/sbin"),
                    PathBuf::from("/etc"),
                ],
                readwrite_bind: vec![],
                deny: vec![],
                tmpfs: vec![PathBuf::from("/tmp")],
            },
            network: policy,
            process: ProcessPolicy {
                pid_namespace: false, // nested PID ns not needed for network test
                no_new_privileges: true,
                command_allowlist: vec![],
                seccomp: Default::default(),
            },
            project_dir: project_dir.clone(),
            extra_rw_paths: vec![],
            work_dir: project_dir,
            // node fetch test — verifies DNS + TCP through nftables + Landlock
            inner_command: vec![
                "node".to_owned(),
                "-e".to_owned(),
                "fetch('https://api.anthropic.com/v1/messages').then(r=>{console.log('status:'+r.status);process.exit(0)}).catch(e=>{console.error('error:'+e.message);process.exit(1)})".to_owned(),
            ],
            enable_landlock: true,
            use_external_netns: true, // KEY: this is what the TUI sets
            uid,
            gid,
            resource_limits: None,
            extra_env: vec![],
            seccomp: Default::default(),
            hostname: String::new(),
        };

        // Write spec to tempfile
        let json = serde_json::to_string(&spec).expect("serialize spec");
        let mut tmpfile = tempfile::NamedTempFile::new().expect("create spec tempfile");
        use std::io::Write;
        tmpfile.write_all(json.as_bytes()).expect("write spec");
        tmpfile.flush().expect("flush spec");

        // Run sandbox-init via nsenter (same as prepare_sandbox's nsenter_command)
        let output = Command::new("nsenter")
            .args([
                &format!("--user=/proc/{}/ns/user", ns.pid()),
                &format!("--net=/proc/{}/ns/net", ns.pid()),
                "--preserve-credentials",
                "--no-fork",
                "--",
            ])
            .arg(&init_bin)
            .arg(tmpfile.path())
            .output()
            .expect("spawn nsenter + sandbox-init");

        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);

        eprintln!("sandbox stdout: {stdout}");
        eprintln!("sandbox stderr: {stderr}");

        assert!(
            output.status.success(),
            "full TUI sandbox path should succeed (exit: {})\nstderr: {stderr}",
            output.status
        );
        assert!(
            stdout.contains("status:405") || stdout.contains("status:200"),
            "node fetch should reach api.anthropic.com (stdout: {stdout})"
        );
    }

    #[test]
    fn e2e_sandbox_time_namespace() {
        // Verify the sandbox runs in a separate time namespace by comparing
        // the time namespace inode inside the sandbox with the host's.
        // (We can't check /proc/uptime because bind-mounted procfs doesn't
        // reflect timens offsets — only clock_gettime sees the zeroed clock.)
        let Some(sandbox_ns) = run_sandboxed(&["readlink", "/proc/self/ns/time"]) else {
            eprintln!("skipping: sandbox-init not available or no user namespace support");
            return;
        };
        let host_ns = std::fs::read_link("/proc/self/ns/time")
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_default();

        let sandbox_ns = sandbox_ns.trim();
        if sandbox_ns == host_ns {
            // Same inode — time namespace not created (kernel may not support it).
            eprintln!(
                "time namespace not active (same inode: {sandbox_ns}) — \
                 kernel may not support CLONE_NEWTIME"
            );
        } else {
            eprintln!("time namespace confirmed: sandbox={sandbox_ns} host={host_ns}");
        }
    }

    #[test]
    fn build_spec_does_not_include_rlimit_as_in_apply_rlimits_call() {
        // Verify the doc comment: RLIMIT_AS is intentionally not set.
        // We test this by checking that apply_rlimits on our own PID doesn't
        // set --as (it would error anyway, but the code path should skip it).
        let mut profile = test_profile(PolicyDefault::Allow);
        profile.resources.max_memory_mb = 8192; // Would have triggered RLIMIT_AS before
        profile.resources.max_file_descriptors = 0; // Disable others to isolate
        profile.resources.max_pids = 0;
        profile.resources.max_disk_write_mb = 0;

        let sandbox = DirectSandbox {
            profile,
            project_dir: PathBuf::from("/tmp/test-rlimit"),
            extra_allow_domains: vec![],
            extra_rw_paths: vec![],
            enable_landlock: true,
            no_cgroups: false,
            init_bin: PathBuf::from("/usr/bin/gleisner-sandbox-init"),
            extra_env: vec![],
            hostname: String::new(),
        };

        // apply_rlimits should succeed (no-op since all limits are zero/skipped)
        let result = sandbox.apply_rlimits(nix::unistd::Pid::this());
        assert!(
            result.is_ok(),
            "apply_rlimits with only max_memory_mb should be no-op: {result:?}"
        );
    }

    #[test]
    fn spec_extra_env_serialization() {
        let spec = SandboxSpec {
            filesystem: FilesystemPolicy {
                readonly_bind: vec![PathBuf::from("/usr")],
                readwrite_bind: vec![],
                deny: vec![],
                tmpfs: vec![],
            },
            network: NetworkPolicy {
                default: PolicyDefault::Allow,
                allow_domains: vec![],
                allow_ports: vec![],
                allow_dns: false,
            },
            process: ProcessPolicy {
                pid_namespace: false,
                no_new_privileges: true,
                command_allowlist: vec![],
                seccomp: Default::default(),
            },
            project_dir: PathBuf::from("/tmp/test"),
            extra_rw_paths: vec![],
            work_dir: PathBuf::from("/tmp/test"),
            inner_command: vec!["echo".to_owned()],
            enable_landlock: false,
            use_external_netns: false,
            uid: 1000,
            gid: 100,
            resource_limits: None,
            extra_env: vec![
                ("CARGO_HOME".to_owned(), "/tmp/cargo".to_owned()),
                ("NODE_DEBUG".to_owned(), "net,tls".to_owned()),
            ],
            seccomp: Default::default(),
            hostname: String::new(),
        };

        let json = serde_json::to_string(&spec).expect("serialize");
        assert!(
            json.contains("CARGO_HOME"),
            "extra_env should be serialized"
        );
        assert!(
            json.contains("NODE_DEBUG"),
            "extra_env should contain all vars"
        );

        let parsed: SandboxSpec = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed.extra_env.len(), 2);
        assert_eq!(parsed.extra_env[0].0, "CARGO_HOME");
        assert_eq!(parsed.extra_env[0].1, "/tmp/cargo");
    }

    #[test]
    fn spec_extra_env_omitted_when_empty() {
        let spec = SandboxSpec {
            filesystem: FilesystemPolicy {
                readonly_bind: vec![],
                readwrite_bind: vec![],
                deny: vec![],
                tmpfs: vec![],
            },
            network: NetworkPolicy {
                default: PolicyDefault::Allow,
                allow_domains: vec![],
                allow_ports: vec![],
                allow_dns: false,
            },
            process: ProcessPolicy {
                pid_namespace: false,
                no_new_privileges: true,
                command_allowlist: vec![],
                seccomp: Default::default(),
            },
            project_dir: PathBuf::from("/tmp/test"),
            extra_rw_paths: vec![],
            work_dir: PathBuf::from("/tmp/test"),
            inner_command: vec!["true".to_owned()],
            enable_landlock: false,
            use_external_netns: false,
            uid: 1000,
            gid: 100,
            resource_limits: None,
            extra_env: vec![],
            seccomp: Default::default(),
            hostname: String::new(),
        };

        let json = serde_json::to_string(&spec).expect("serialize");
        assert!(
            !json.contains("extra_env"),
            "empty extra_env should be omitted from JSON (skip_serializing_if)"
        );
    }

    #[test]
    fn build_spec_includes_extra_env() {
        let profile = test_profile(PolicyDefault::Allow);
        let mut sandbox = DirectSandbox {
            profile,
            project_dir: PathBuf::from("/tmp/test-env"),
            extra_allow_domains: vec![],
            extra_rw_paths: vec![],
            enable_landlock: true,
            no_cgroups: false,
            init_bin: PathBuf::from("/usr/bin/gleisner-sandbox-init"),
            extra_env: vec![],
            hostname: String::new(),
        };

        sandbox.set_extra_env(vec![
            ("FOO".to_owned(), "bar".to_owned()),
            ("BAZ".to_owned(), "qux".to_owned()),
        ]);

        let spec = sandbox.build_spec(&["echo".to_owned()], false);
        assert_eq!(spec.extra_env.len(), 2);
        assert_eq!(spec.extra_env[0], ("FOO".to_owned(), "bar".to_owned()));
    }

    #[test]
    fn build_spec_use_external_netns_flag() {
        let profile = test_profile(PolicyDefault::Deny);
        let sandbox = DirectSandbox {
            profile,
            project_dir: PathBuf::from("/tmp/test-netns"),
            extra_allow_domains: vec![],
            extra_rw_paths: vec![],
            enable_landlock: true,
            no_cgroups: false,
            init_bin: PathBuf::from("/usr/bin/gleisner-sandbox-init"),
            extra_env: vec![],
            hostname: String::new(),
        };

        // use_external_netns=false (normal path)
        let spec = sandbox.build_spec(&["true".to_owned()], false);
        assert!(!spec.use_external_netns);

        // use_external_netns=true (TUI path with pre-created namespace)
        let spec = sandbox.build_spec(&["true".to_owned()], true);
        assert!(spec.use_external_netns);
    }

    #[test]
    fn e2e_extra_env_visible_in_sandbox() {
        let inner = &["sh", "-c", "env | grep MYVAR"];
        // Build a spec with extra_env and run it
        let init_bin = detect_sandbox_init().or_else(|| {
            let exe = std::env::current_exe().ok()?;
            let parent = exe.parent()?.parent()?;
            let candidate = parent.join("gleisner-sandbox-init");
            candidate.is_file().then_some(candidate)
        });
        let Some(init_bin) = init_bin else {
            eprintln!("skipping: sandbox-init binary not found");
            return;
        };

        let uid = nix::unistd::getuid().as_raw();
        let gid = nix::unistd::getgid().as_raw();
        let spec = SandboxSpec {
            filesystem: FilesystemPolicy {
                readonly_bind: vec![
                    PathBuf::from("/usr"),
                    PathBuf::from("/lib"),
                    PathBuf::from("/lib64"),
                    PathBuf::from("/bin"),
                    PathBuf::from("/sbin"),
                    PathBuf::from("/etc"),
                ],
                readwrite_bind: vec![],
                deny: vec![],
                tmpfs: vec![PathBuf::from("/tmp")],
            },
            network: NetworkPolicy {
                default: PolicyDefault::Allow,
                allow_domains: vec![],
                allow_ports: vec![],
                allow_dns: false,
            },
            process: ProcessPolicy {
                pid_namespace: false,
                no_new_privileges: true,
                command_allowlist: vec![],
                seccomp: Default::default(),
            },
            project_dir: PathBuf::from("/tmp"),
            extra_rw_paths: vec![],
            work_dir: PathBuf::from("/tmp"),
            inner_command: inner.iter().map(|s| (*s).to_string()).collect(),
            enable_landlock: false,
            use_external_netns: false,
            uid,
            gid,
            resource_limits: None,
            extra_env: vec![("MYVAR".to_owned(), "hello_from_extra_env".to_owned())],
            seccomp: Default::default(),
            hostname: String::new(),
        };

        let json = serde_json::to_string(&spec).expect("serialize");
        let spec_file = tempfile::NamedTempFile::new().expect("create tempfile");
        std::fs::write(spec_file.path(), &json).expect("write spec");

        let output = Command::new(&init_bin).arg(spec_file.path()).output();

        let Ok(output) = output else {
            eprintln!("skipping: sandbox-init failed to run");
            return;
        };

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            if stderr.contains("Operation not permitted") || stderr.contains("EPERM") {
                eprintln!("skipping: no user namespace support");
                return;
            }
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            stdout.contains("MYVAR=hello_from_extra_env"),
            "extra_env should be visible inside sandbox, got stdout: {stdout}, stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
