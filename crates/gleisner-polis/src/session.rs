//! Shared sandbox session setup.
//!
//! Provides the unified pipeline for creating a sandboxed Claude Code
//! session, used by `gleisner wrap`, `gleisner record`, and the TUI.
//! Each entry point builds its own inner command and handles execution
//! differently, but the sandbox setup (profile adjustment, bwrap, Landlock,
//! network filtering) is identical.

use std::path::{Path, PathBuf};

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
    /// slirp4netns process — must stay alive while the child runs.
    pub slirp: Option<crate::SlirpHandle>,
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
/// 6. Resolve selective network filter (slirp4netns check)
/// 7. Build bwrap command with the inner command
/// 8. Set up namespace + slirp4netns + nftables when filtering is needed
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

    let filter = if needs_filter {
        if !netfilter::slirp4netns_available() {
            let profile_name = sandbox.profile().name.clone();
            return Err(SandboxError::NetworkSetupFailed(format!(
                "slirp4netns not found — install slirp4netns for selective network filtering\n\
                 Hint: The profile '{profile_name}' declares allow_domains with network deny, \
                 which requires slirp4netns to create a filtered network namespace.\n\
                 Without it, use --profile carter-zimmerman for full network access, \
                 or install slirp4netns (apt install slirp4netns / dnf install slirp4netns).",
            )));
        }
        let network_policy = &sandbox.profile().network;
        let extra = sandbox.extra_allow_domains().to_vec();
        Some(crate::NetworkFilter::resolve(network_policy, &extra)?)
    } else {
        None
    };

    // ── 7. Build bwrap command ────────────────────────────────────
    let has_filter = filter.is_some();
    let (bwrap_cmd, policy_file) = sandbox.build_command(inner_command, has_filter);

    // ── 8. Set up namespace + slirp + firewall ────────────────────
    // When filtering is active, we:
    // 1. Create a user+net namespace pair (NamespaceHandle)
    // 2. Start slirp4netns targeting that namespace
    // 3. Apply firewall rules via nsenter (before bwrap starts)
    // 4. Wrap bwrap in nsenter to enter the pre-created namespace
    let (ns, slirp, cmd) = if let Some(ref f) = filter {
        let ns = crate::NamespaceHandle::create()?;
        let slirp = crate::SlirpHandle::start(ns.pid())?;

        // Apply firewall rules before starting bwrap — bwrap's --unshare-user
        // creates a nested namespace that loses CAP_NET_ADMIN
        f.apply_firewall_via_nsenter(&ns)?;

        let mut nsenter = netfilter::nsenter_command(&ns);
        nsenter.arg(bwrap_cmd.get_program());
        nsenter.args(bwrap_cmd.get_args());

        (Some(ns), Some(slirp), nsenter)
    } else {
        (None, None, bwrap_cmd)
    };

    Ok(PreparedSandbox {
        command: cmd,
        ns,
        slirp,
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
        .map(|p| crate::expand_tilde(p))
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

/// Resolve the `claude` binary path.
///
/// Checks common installation locations when `claude` isn't on PATH:
/// 1. `~/.npm-global/bin/claude` (npm global with custom prefix)
/// 2. `~/.local/bin/claude` (pipx, local installs)
/// 3. `~/.claude/local/bin/claude` (Claude's own installer)
///
/// Falls back to `"claude"` (relies on PATH) if none found.
pub fn resolve_claude_bin() -> String {
    if let Ok(home) = std::env::var("HOME") {
        let candidates = [
            format!("{home}/.npm-global/bin/claude"),
            format!("{home}/.local/bin/claude"),
            format!("{home}/.claude/local/bin/claude"),
        ];
        for candidate in &candidates {
            if Path::new(candidate).is_file() {
                return candidate.clone();
            }
        }
    }
    "claude".into()
}

/// Build the standard Claude CLI inner command.
///
/// Constructs `[claude_bin, --dangerously-skip-permissions (if enabled),
/// --disallowedTools (if any), ...extra_args]` — the common pattern
/// used by `wrap` and `record`.
pub fn build_claude_inner_command(
    claude_bin: &str,
    profile: &crate::Profile,
    extra_args: &[String],
) -> Vec<String> {
    let mut cmd = vec![claude_bin.to_owned()];

    if profile.plugins.skip_permissions {
        cmd.push("--dangerously-skip-permissions".into());
    }
    if !profile.plugins.disallowed_tools.is_empty() {
        cmd.push("--disallowedTools".into());
        cmd.push(profile.plugins.disallowed_tools.join(","));
    }

    cmd.extend(extra_args.iter().cloned());
    cmd
}
