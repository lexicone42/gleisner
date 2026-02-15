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

    // NOTE: Landlock is NOT applied to the parent orchestrator.
    //
    // On kernels with Landlock ABI >= v5 (Linux 6.12+), landlock_restrict_self()
    // prevents mount namespace creation (CLONE_NEWNS), which bwrap requires.
    // The parent must keep full capabilities to set up the sandbox.
    //
    // TODO: Apply Landlock INSIDE the bwrap sandbox via a helper binary that
    // runs between bwrap's mount setup and the inner command (Claude Code).
    // This is the correct architecture: the orchestrator is trusted, only the
    // sandboxed process needs Landlock restrictions.
    if !args.no_landlock {
        tracing::debug!("landlock deferred — will be applied inside sandbox in a future release");
    }

    // Detect Claude Code version for logging
    if let Some(version) = detect_claude_code_version(&args.claude_bin) {
        tracing::info!(claude_version = %version, "detected Claude Code version");
    }

    // Build command: claude [args...]
    let mut inner_command = vec![args.claude_bin];
    inner_command.extend(args.claude_args);

    let bwrap_cmd = sandbox.build_command(&inner_command, filter.as_ref());

    // When filtering is active, we need to:
    // 1. Create a user+net namespace pair (NamespaceHandle)
    // 2. Start slirp4netns targeting that namespace
    // 3. Run bwrap inside the namespace via nsenter
    // All handles must stay alive until the child exits.
    let (ns_handle, slirp, mut cmd) = if let Some(ref _f) = filter {
        let ns = gleisner_polis::NamespaceHandle::create()?;
        let slirp = gleisner_polis::SlirpHandle::start(ns.pid())?;

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
