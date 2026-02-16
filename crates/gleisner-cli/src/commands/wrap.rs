//! `gleisner wrap` — run Claude Code inside a sandbox without attestation.
//!
//! This is the simplest Gleisner command: it wraps Claude Code in a
//! bubblewrap sandbox using the specified profile, without recording
//! attestation data. Useful for day-to-day development where you want
//! isolation but don't need cryptographic provenance.

use std::path::PathBuf;

use clap::Args;
use color_eyre::eyre::{Result, eyre};

use gleisner_polis::profile::PolicyDefault;

/// Run Claude Code inside a Gleisner sandbox (isolation only, no attestation).
#[derive(Args)]
pub struct WrapArgs {
    /// Sandbox profile name or path to TOML file.
    ///
    /// Built-in profiles: konishi (default balanced), carter-zimmerman
    /// (permissive), ashton-laval (maximum isolation).
    #[arg(short, long, default_value = "konishi")]
    pub profile: String,

    /// Additional domains to allow network access.
    ///
    /// api.anthropic.com is always allowed in the default profile.
    /// Use this to add more domains (e.g., registry.npmjs.org).
    #[arg(long = "allow-network")]
    pub allow_network: Vec<String>,

    /// Additional paths to mount read-write inside the sandbox.
    #[arg(long = "allow-path")]
    pub allow_path: Vec<PathBuf>,

    /// Project directory (defaults to current directory).
    #[arg(short = 'd', long)]
    pub project_dir: Option<PathBuf>,

    /// Claude Code binary path (defaults to `claude` on PATH).
    #[arg(long, default_value = "claude")]
    pub claude_bin: String,

    /// Disable Landlock filesystem access control.
    ///
    /// By default, Landlock LSM rules are applied before spawning the
    /// sandbox for defense-in-depth. Use this flag to skip Landlock
    /// (e.g., on kernels without Landlock support).
    #[arg(long)]
    pub no_landlock: bool,

    /// Additional arguments to pass to Claude Code.
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    pub claude_args: Vec<String>,
}

/// Execute the `wrap` command.
///
/// # Errors
///
/// Returns an error if profile resolution, sandbox creation, or
/// the inner process fails.
#[allow(clippy::unused_async)] // async for consistency with other command handlers
pub async fn execute(args: WrapArgs) -> Result<()> {
    let project_dir = args
        .project_dir
        .unwrap_or_else(|| std::env::current_dir().expect("cannot determine cwd"));

    let profile = gleisner_polis::resolve_profile(&args.profile)?;

    tracing::info!(
        profile = %profile.name,
        project_dir = %project_dir.display(),
        claude_bin = %args.claude_bin,
        "starting sandboxed Claude Code session"
    );

    let mut sandbox = gleisner_polis::BwrapSandbox::new(profile, project_dir)?;

    // Apply CLI overrides
    if !args.allow_network.is_empty() {
        sandbox.allow_domains(args.allow_network);
    }
    if !args.allow_path.is_empty() {
        sandbox.allow_paths(args.allow_path);
    }

    // Resolve selective network filter if profile denies network but has allowed domains
    let profile = sandbox.profile();
    let needs_filter = matches!(profile.network.default, PolicyDefault::Deny)
        && (!profile.network.allow_domains.is_empty() || !sandbox.extra_allow_domains().is_empty());

    let filter = if needs_filter {
        if !gleisner_polis::netfilter::slirp4netns_available() {
            return Err(eyre!(
                "slirp4netns not found — install slirp4netns for selective network filtering\n\
                 Hint: The profile '{}' declares allow_domains with network deny, \
                 which requires slirp4netns to create a filtered network namespace.\n\
                 Without it, use --profile carter-zimmerman for full network access, \
                 or install slirp4netns (apt install slirp4netns / dnf install slirp4netns).",
                profile.name,
            ));
        }
        let network_policy = &sandbox.profile().network;
        let extra = sandbox.extra_allow_domains().to_vec();
        Some(gleisner_polis::NetworkFilter::resolve(
            network_policy,
            &extra,
        )?)
    } else {
        None
    };

    // Enable Landlock-inside-bwrap if the sandbox-init binary is available.
    // Landlock cannot be applied to the parent orchestrator (ABI v5+ restricts
    // mount namespace creation), so we use a trampoline binary inside bwrap.
    if !args.no_landlock {
        if let Some(init_bin) = detect_sandbox_init() {
            sandbox.enable_landlock(init_bin);
        } else {
            tracing::warn!("gleisner-sandbox-init not found — running without Landlock");
        }
    }

    // Detect Claude Code version for logging
    if let Some(version) = detect_claude_code_version(&args.claude_bin) {
        tracing::info!(claude_version = %version, "detected Claude Code version");
    }

    // Build command: claude [args...]
    let mut inner_command = vec![args.claude_bin];
    inner_command.extend(args.claude_args);

    let has_filter = filter.is_some();
    let (bwrap_cmd, _policy_file) = sandbox.build_command(&inner_command, has_filter);

    // When filtering is active, we need to:
    // 1. Create a user+net namespace pair (NamespaceHandle)
    // 2. Start slirp4netns targeting that namespace
    // 3. Apply firewall rules via nsenter (before bwrap starts)
    // 4. Run bwrap inside the namespace via nsenter
    // All handles must stay alive until the child exits.
    // _policy_file (if Landlock is enabled) must also stay alive — bwrap
    // bind-mounts the host tempfile into the sandbox.
    let (ns_handle, slirp, mut cmd) = if let Some(ref f) = filter {
        let ns = gleisner_polis::NamespaceHandle::create()?;
        let slirp = gleisner_polis::SlirpHandle::start(ns.pid())?;

        // Apply firewall rules before starting bwrap — bwrap's --unshare-user
        // creates a nested namespace that loses CAP_NET_ADMIN
        f.apply_firewall_via_nsenter(&ns)?;

        // Build nsenter command that wraps bwrap
        let mut nsenter = gleisner_polis::netfilter::nsenter_command(&ns);
        nsenter.arg(bwrap_cmd.get_program());
        nsenter.args(bwrap_cmd.get_args());

        (Some(ns), Some(slirp), nsenter)
    } else {
        (None, None, bwrap_cmd)
    };

    // Inherit stdin/stdout/stderr so Claude Code's interactive UI works
    cmd.stdin(std::process::Stdio::inherit());
    cmd.stdout(std::process::Stdio::inherit());
    cmd.stderr(std::process::Stdio::inherit());

    let status = cmd
        .status()
        .map_err(|e| eyre!("failed to spawn sandboxed process: {e}"))?;

    if status.success() {
        tracing::info!("sandboxed session completed successfully");
    } else {
        let code = status.code().unwrap_or(1);
        tracing::warn!(exit_code = code, "sandboxed session exited with error");
    }

    // Drop network handles before exit() — exit() skips destructors,
    // which would leak slirp4netns and namespace holder processes.
    drop(slirp);
    drop(ns_handle);

    std::process::exit(status.code().unwrap_or(1));
}

/// Detect Claude Code version by running `claude --version`.
fn detect_claude_code_version(bin: &str) -> Option<String> {
    std::process::Command::new(bin)
        .arg("--version")
        .output()
        .ok()
        .and_then(|out| String::from_utf8(out.stdout).ok())
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
}

/// Try to find the `gleisner-sandbox-init` binary.
///
/// Checks:
/// 1. Same directory as the running `gleisner` binary
/// 2. On `PATH` via `which`
fn detect_sandbox_init() -> Option<PathBuf> {
    // Check alongside the current executable
    if let Ok(exe) = std::env::current_exe() {
        let sibling = exe.with_file_name("gleisner-sandbox-init");
        if sibling.is_file() {
            return Some(sibling);
        }
    }

    // Fall back to PATH lookup
    which::which("gleisner-sandbox-init").ok()
}
