//! Shared sandbox session setup.
//!
//! Provides the unified pipeline for creating a sandboxed Claude Code
//! session, used by `gleisner wrap`, `gleisner record`, and the TUI.
//! Each entry point builds its own inner command and handles execution
//! differently, but the sandbox setup (profile adjustment, bwrap, Landlock,
//! network filtering) is identical.

use std::path::PathBuf;

use crate::BwrapSandbox;
use crate::error::SandboxError;
use crate::netfilter;
use crate::profile::PolicyDefault;

/// Configuration for creating a sandboxed session.
///
/// Built by each entry point from its own CLI args / config,
/// then passed to [`prepare_sandbox`] for the common setup pipeline.
pub struct SandboxSessionConfig {
    /// Security profile defining isolation boundaries.
    pub profile: crate::Profile,
    /// Project directory to mount read-write inside the sandbox.
    pub project_dir: PathBuf,
    /// Additional domains to allow network access (CLI overrides).
    pub extra_allow_network: Vec<String>,
    /// Additional paths to mount read-write inside the sandbox (CLI overrides).
    pub extra_allow_paths: Vec<PathBuf>,
    /// Skip Landlock filesystem access control.
    pub no_landlock: bool,
}

/// A fully prepared sandbox, ready to spawn.
///
/// The [`command`](Self::command) is either a direct `bwrap` invocation
/// or an `nsenter` wrapping `bwrap` (when selective network filtering
/// is active). All handles must outlive the spawned child process.
pub struct PreparedSandbox {
    /// The command to spawn (bwrap or nsenter → bwrap).
    pub command: std::process::Command,
    /// Network namespace handle — must stay alive while the child runs.
    pub ns: Option<crate::NamespaceHandle>,
    /// TAP provider process (pasta or slirp4netns) — must stay alive while the child runs.
    pub tap: Option<crate::TapHandle>,
    /// Landlock policy JSON tempfile — bwrap bind-mounts this.
    pub policy_file: Option<tempfile::NamedTempFile>,
    /// The sandbox instance, kept for `apply_rlimits`.
    sandbox: BwrapSandbox,
}

impl PreparedSandbox {
    /// Apply rlimits (`RLIMIT_AS`, `RLIMIT_NPROC`, `RLIMIT_NOFILE`) to a child.
    ///
    /// Call this after spawning the child process. Logs a warning on failure.
    pub fn apply_rlimits(&self, pid: nix::unistd::Pid) -> Result<(), SandboxError> {
        self.sandbox.apply_rlimits(pid)
    }

    /// Access the resolved profile.
    pub const fn profile(&self) -> &crate::Profile {
        self.sandbox.profile()
    }
}

/// Build a fully prepared sandbox from the given configuration and inner command.
///
/// This is the single implementation of the sandbox setup pipeline that was
/// previously duplicated across `wrap.rs`, `record.rs`, and `claude.rs`.
///
/// # Pipeline
///
/// 1. Add `$HOME` as readonly bind (Claude Code needs `~/.claude/` for config)
/// 2. Create `BwrapSandbox` with project directory
/// 3. Apply CLI overrides (extra domains, paths)
/// 4. Merge plugin policy (`~/.claude` rw, MCP domains, `add_dirs`)
/// 5. Detect and enable `gleisner-sandbox-init` for Landlock-inside-bwrap
/// 6. Resolve selective network filter (TAP provider check)
/// 7. Build bwrap command with the inner command
/// 8. Set up namespace + TAP provider (pasta/slirp4netns) + nftables when filtering is needed
///
/// # Returns
///
/// A [`PreparedSandbox`] containing the ready-to-spawn `std::process::Command`
/// and handles that must outlive the child process.
pub fn prepare_sandbox(
    config: SandboxSessionConfig,
    inner_command: &[String],
) -> Result<PreparedSandbox, SandboxError> {
    let mut profile = config.profile;

    // ── 1. Add $HOME as readonly ──────────────────────────────────
    // Claude Code needs access to ~/.claude/ for config, hooks, MCP, etc.
    // The profile's deny paths (tmpfs overlays) shadow sensitive dirs.
    if let Ok(home) = std::env::var("HOME") {
        let home_path = PathBuf::from(&home);
        if !profile.filesystem.readonly_bind.contains(&home_path) {
            profile.filesystem.readonly_bind.push(home_path);
        }
    }

    // ── 2. Create sandbox ─────────────────────────────────────────
    let mut sandbox = BwrapSandbox::new(profile, config.project_dir)?;

    // ── 3. Apply CLI overrides ────────────────────────────────────
    if !config.extra_allow_network.is_empty() {
        sandbox.allow_domains(config.extra_allow_network);
    }
    if !config.extra_allow_paths.is_empty() {
        sandbox.allow_paths(config.extra_allow_paths);
    }

    // ── 4. Merge plugin policy ────────────────────────────────────
    apply_plugin_sandbox_policy(&mut sandbox);

    // ── 5. Enable Landlock ────────────────────────────────────────
    if !config.no_landlock {
        if let Some(init_bin) = detect_sandbox_init() {
            sandbox.enable_landlock(init_bin);
        } else {
            tracing::warn!("gleisner-sandbox-init not found — running without Landlock");
        }
    }

    // ── 6. Resolve network filter ─────────────────────────────────
    let profile_ref = sandbox.profile();
    let needs_filter = matches!(profile_ref.network.default, PolicyDefault::Deny)
        && (!profile_ref.network.allow_domains.is_empty()
            || !sandbox.extra_allow_domains().is_empty());

    let (filter, tap_provider) = if needs_filter {
        // Verify a TAP provider is available before resolving the filter.
        let provider = netfilter::preferred_tap_provider().map_err(|_| {
            let profile_name = sandbox.profile().name.clone();
            SandboxError::NetworkSetupFailed(format!(
                "no TAP provider found — install pasta (preferred) or slirp4netns for selective network filtering\n\
                 Hint: The profile '{profile_name}' declares allow_domains with network deny, \
                 which requires a TAP provider to create a filtered network namespace.\n\
                 Without it, use --profile carter-zimmerman for full network access, \
                 or install passt (emerge net-misc/passt) or slirp4netns.",
            ))
        })?;
        let network_policy = &sandbox.profile().network;
        let extra = sandbox.extra_allow_domains().to_vec();
        (
            Some(crate::NetworkFilter::resolve(network_policy, &extra)?),
            Some(provider),
        )
    } else {
        (None, None)
    };

    // ── 7. Build bwrap command ────────────────────────────────────
    let has_filter = filter.is_some();
    let (bwrap_cmd, policy_file) = sandbox.build_command(inner_command, has_filter);

    // ── 8. Set up namespace + TAP provider + firewall ──────────────
    // When filtering is active, we:
    // 1. Create a user+net namespace pair (NamespaceHandle)
    // 2. Start TAP provider (pasta or slirp4netns) targeting that namespace
    // 3. Apply firewall rules via nsenter (before bwrap starts)
    // 4. Wrap bwrap in nsenter to enter the pre-created namespace
    let (ns, tap, cmd) = if let Some(ref f) = filter {
        let ns = crate::NamespaceHandle::create()?;
        // SAFETY: tap_provider is always Some when filter is Some (set together above)
        let tap = crate::TapHandle::start(
            ns.pid(),
            tap_provider.expect("tap_provider set with filter"),
        )?;

        // Apply firewall rules before starting bwrap — bwrap's --unshare-user
        // creates a nested namespace that loses CAP_NET_ADMIN
        f.apply_firewall_via_nsenter(&ns)?;

        let mut nsenter = netfilter::nsenter_command(&ns);
        nsenter.arg(bwrap_cmd.get_program());
        nsenter.args(bwrap_cmd.get_args());

        (Some(ns), Some(tap), nsenter)
    } else {
        (None, None, bwrap_cmd)
    };

    Ok(PreparedSandbox {
        command: cmd,
        ns,
        tap,
        policy_file,
        sandbox,
    })
}

/// Merge the profile's `[plugins]` policy into the sandbox configuration.
///
/// - Mounts `~/.claude` as read-write (session state, settings)
/// - Expands and mounts plugin `add_dirs` as read-write
/// - Merges MCP network domains into the sandbox allowlist
fn apply_plugin_sandbox_policy(sandbox: &mut BwrapSandbox) {
    // ~/.claude needs to be writable for session state and settings
    if let Ok(home) = std::env::var("HOME") {
        sandbox.allow_paths(std::iter::once(PathBuf::from(format!("{home}/.claude"))));
    }

    let plugins = &sandbox.profile().plugins;
    let mcp_domains: Vec<String> = plugins.mcp_network_domains.clone();
    let add_dirs: Vec<PathBuf> = plugins
        .add_dirs
        .iter()
        .map(|p| crate::util::expand_tilde(p))
        .collect();
    sandbox.allow_domains(mcp_domains);
    sandbox.allow_paths(add_dirs);
}

/// Try to find the `gleisner-sandbox-init` binary.
///
/// Checks alongside the running binary first, then falls back to `PATH`.
pub fn detect_sandbox_init() -> Option<PathBuf> {
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
    use std::path::PathBuf;

    use crate::Profile;
    use crate::profile::{
        FilesystemPolicy, NetworkPolicy, PluginPolicy, PolicyDefault, ProcessPolicy, ResourceLimits,
    };

    use super::*;

    fn test_profile(network_default: PolicyDefault) -> Profile {
        Profile {
            name: "test-session".to_owned(),
            description: "test profile for session tests".to_owned(),
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

    /// Helper: collect command args as strings for assertions.
    fn args_of(cmd: &std::process::Command) -> Vec<String> {
        cmd.get_args()
            .filter_map(|a| a.to_str())
            .map(str::to_owned)
            .collect()
    }

    #[test]
    fn prepare_sandbox_builds_valid_command() {
        if which::which("bwrap").is_err() {
            return;
        }

        let config = SandboxSessionConfig {
            profile: test_profile(PolicyDefault::Allow),
            project_dir: PathBuf::from("/tmp/test-project"),
            extra_allow_network: vec![],
            extra_allow_paths: vec![],
            no_landlock: true,
        };

        let inner = vec!["/bin/echo".to_owned(), "hello".to_owned()];
        let prepared = prepare_sandbox(config, &inner).expect("should build sandbox");

        let args = args_of(&prepared.command);

        // Should contain bwrap fundamentals
        assert_eq!(
            prepared.command.get_program().to_str().unwrap(),
            "bwrap",
            "program should be bwrap"
        );
        assert!(
            args.iter().any(|a| a == "--die-with-parent"),
            "should die with parent"
        );

        // Inner command should appear at the end
        assert!(
            args.iter().any(|a| a == "/bin/echo"),
            "inner command should be present"
        );
        assert!(
            args.iter().any(|a| a == "hello"),
            "inner command args should be present"
        );

        // No network handles needed for Allow policy
        assert!(prepared.ns.is_none(), "no namespace for allow policy");
        assert!(prepared.tap.is_none(), "no TAP provider for allow policy");
    }

    #[test]
    fn prepare_sandbox_adds_home_readonly() {
        if which::which("bwrap").is_err() {
            return;
        }

        let config = SandboxSessionConfig {
            profile: test_profile(PolicyDefault::Allow),
            project_dir: PathBuf::from("/tmp/test-project"),
            extra_allow_network: vec![],
            extra_allow_paths: vec![],
            no_landlock: true,
        };

        let inner = vec!["/bin/true".to_owned()];
        let prepared = prepare_sandbox(config, &inner).expect("should build sandbox");

        let args = args_of(&prepared.command);

        // $HOME should appear as a readonly bind
        if let Ok(home) = std::env::var("HOME") {
            assert!(
                args.iter().any(|a| a == &home),
                "$HOME ({home}) should appear in bwrap args"
            );
        }
    }

    #[test]
    fn prepare_sandbox_merges_extra_domains() {
        if which::which("bwrap").is_err() {
            return;
        }

        let config = SandboxSessionConfig {
            profile: test_profile(PolicyDefault::Allow),
            project_dir: PathBuf::from("/tmp/test-project"),
            extra_allow_network: vec!["extra.example.com".to_owned()],
            extra_allow_paths: vec![],
            no_landlock: true,
        };

        let inner = vec!["/bin/true".to_owned()];
        let prepared = prepare_sandbox(config, &inner).expect("should build sandbox");

        // The profile is allow-all, so extra domains don't create filters,
        // but verify the profile is accessible and has the right name
        assert_eq!(prepared.profile().name, "test-session");
    }

    #[test]
    fn prepare_sandbox_merges_extra_paths() {
        if which::which("bwrap").is_err() {
            return;
        }

        let config = SandboxSessionConfig {
            profile: test_profile(PolicyDefault::Allow),
            project_dir: PathBuf::from("/tmp/test-project"),
            extra_allow_network: vec![],
            extra_allow_paths: vec![PathBuf::from("/opt/extra")],
            no_landlock: true,
        };

        let inner = vec!["/bin/true".to_owned()];
        let prepared = prepare_sandbox(config, &inner).expect("should build sandbox");

        let args = args_of(&prepared.command);

        // Extra paths should appear as read-write binds
        assert!(
            args.iter().any(|a| a == "/opt/extra"),
            "extra path should appear in bwrap args"
        );
    }

    #[test]
    fn prepare_sandbox_plugin_policy_adds_claude_dir() {
        if which::which("bwrap").is_err() {
            return;
        }

        let config = SandboxSessionConfig {
            profile: test_profile(PolicyDefault::Allow),
            project_dir: PathBuf::from("/tmp/test-project"),
            extra_allow_network: vec![],
            extra_allow_paths: vec![],
            no_landlock: true,
        };

        let inner = vec!["/bin/true".to_owned()];
        let prepared = prepare_sandbox(config, &inner).expect("should build sandbox");

        let args = args_of(&prepared.command);

        // ~/.claude should be added as read-write by apply_plugin_sandbox_policy
        if let Ok(home) = std::env::var("HOME") {
            let claude_dir = format!("{home}/.claude");
            assert!(
                args.iter().any(|a| a == &claude_dir),
                "~/.claude ({claude_dir}) should be in bwrap args as rw bind"
            );
        }
    }

    #[test]
    fn prepare_sandbox_deny_network_without_tap_provider_returns_error() {
        if which::which("bwrap").is_err() {
            return;
        }
        // This test verifies the error path when a TAP provider is needed
        // but not available. We can only test this reliably if neither pasta
        // nor slirp4netns is installed — skip otherwise.
        if netfilter::pasta_available() || netfilter::slirp4netns_available() {
            return;
        }

        let config = SandboxSessionConfig {
            profile: test_profile(PolicyDefault::Deny),
            project_dir: PathBuf::from("/tmp/test-project"),
            extra_allow_network: vec![],
            extra_allow_paths: vec![],
            no_landlock: true,
        };

        let inner = vec!["/bin/true".to_owned()];
        let result = prepare_sandbox(config, &inner);

        let err = match result {
            Err(e) => e.to_string(),
            Ok(_) => panic!("should error when deny-network profile needs TAP provider"),
        };
        assert!(
            err.contains("TAP provider") || err.contains("pasta") || err.contains("slirp4netns"),
            "error should mention TAP provider: {err}"
        );
    }

    #[test]
    fn detect_sandbox_init_returns_option() {
        // Just verify it doesn't panic — result depends on whether
        // gleisner-sandbox-init is built/installed
        let _result = detect_sandbox_init();
    }
}
