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
use crate::netfilter::NetworkFilter;
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

    /// Build the `bwrap` invocation for the given inner command.
    ///
    /// When a [`NetworkFilter`] is provided:
    /// - `--unshare-net` is **skipped** (the caller must pre-create a
    ///   namespace via [`NamespaceHandle`] and run bwrap inside it via nsenter)
    /// - The inner command is wrapped in a shell script that applies
    ///   iptables rules before exec-ing the actual command
    ///
    /// The resulting [`Command`] is ready to spawn (or to have its args
    /// appended to an nsenter command).
    #[must_use]
    pub fn build_command(
        &self,
        inner_command: &[String],
        filter: Option<&NetworkFilter>,
    ) -> Command {
        let mut cmd = Command::new("bwrap");

        // Order matters: filesystem → process → network → working dir → die-with-parent
        self.apply_filesystem_policy(&mut cmd);
        self.apply_process_policy(&mut cmd);

        // When a filter is active, skip --unshare-net — the caller enters
        // a pre-created namespace via nsenter instead
        if filter.is_some() {
            // iptables needs /run/xtables.lock — provide a writable /run
            cmd.args(["--tmpfs", "/run"]);
        } else {
            self.apply_network_policy(&mut cmd);
        }

        // Working directory inside the sandbox
        cmd.args(["--chdir", &self.project_dir.display().to_string()]);

        // Kill sandbox if parent process dies — prevents orphaned sandboxes
        cmd.arg("--die-with-parent");

        // The actual command to run inside the sandbox — optionally wrapped
        // with iptables setup when selective network filtering is active
        if let Some(f) = filter {
            let wrapped = f.wrap_command(inner_command);
            cmd.args(wrapped);
        } else {
            cmd.args(inner_command);
        }

        debug!(
            args = ?cmd.get_args().collect::<Vec<_>>(),
            "built bwrap command"
        );

        cmd
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
            let p = path.display().to_string();
            cmd.args(["--ro-bind", &p, &p]);
        }

        // Read-write bind mounts from profile
        for path in &fs.readwrite_bind {
            let p = path.display().to_string();
            cmd.args(["--bind", &p, &p]);
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
    fn apply_process_policy(&self, cmd: &mut Command) {
        let proc_policy = &self.profile.process;

        if proc_policy.pid_namespace {
            cmd.arg("--unshare-pid");
        }

        if proc_policy.no_new_privileges {
            cmd.arg("--new-session");
        }
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

    /// Get the extra domains added via CLI flags.
    ///
    /// Used by callers that need to pass these to [`NetworkFilter::resolve()`]
    /// alongside the profile's built-in domain list.
    #[must_use]
    pub fn extra_allow_domains(&self) -> &[String] {
        &self.extra_allow_domains
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
/// Returns the path unchanged if `$HOME` is not set.
fn expand_tilde(path: &Path) -> PathBuf {
    let path_str = path.display().to_string();
    if path_str.starts_with('~') {
        let Some(home) = std::env::var_os("HOME") else {
            return path.to_path_buf();
        };
        PathBuf::from(home).join(path.strip_prefix("~").unwrap_or(path))
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

        let cmd = sandbox.build_command(&["echo".to_owned(), "hello".to_owned()], None);
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

        let cmd = sandbox.build_command(&["true".to_owned()], None);
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

        let cmd = sandbox.build_command(&["true".to_owned()], None);
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

        let cmd = sandbox.build_command(&["true".to_owned()], None);
        let args = args_of(&cmd);

        assert!(
            args.iter().any(|a| a == "--unshare-pid"),
            "should unshare PID namespace"
        );
    }
}
