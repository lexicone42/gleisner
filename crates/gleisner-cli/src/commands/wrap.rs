//! `gleisner wrap` — run Claude Code inside a sandbox without attestation.
//!
//! This is the simplest Gleisner command: it wraps Claude Code in a
//! bubblewrap sandbox using the specified profile, without recording
//! attestation data. Useful for day-to-day development where you want
//! isolation but don't need cryptographic provenance.

use std::path::PathBuf;

use clap::Args;
use color_eyre::eyre::{Result, eyre};

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
    let project_dir = match args.project_dir {
        Some(d) => d,
        None => std::env::current_dir().map_err(|e| {
            eyre!("--project-dir not specified and current directory is inaccessible: {e}")
        })?,
    };

    let profile = gleisner_polis::resolve_profile(&args.profile)?;

    tracing::info!(
        profile = %profile.name,
        project_dir = %project_dir.display(),
        claude_bin = %args.claude_bin,
        "starting sandboxed Claude Code session"
    );

    // Detect Claude Code version for logging
    if let Some(version) = detect_claude_code_version(&args.claude_bin) {
        tracing::info!(claude_version = %version, "detected Claude Code version");
    }

    // Build inner command: claude [plugin flags...] [user args...]
    let inner_command =
        gleisner_polis::build_claude_inner_command(&args.claude_bin, &profile, &args.claude_args);

    let config = gleisner_polis::SandboxSessionConfig {
        profile,
        project_dir,
        extra_allow_network: args.allow_network,
        extra_allow_paths: args.allow_path,
        no_landlock: args.no_landlock,
    };

    let mut prepared = gleisner_polis::prepare_sandbox(config, &inner_command)?;

    // Inherit stdin/stdout/stderr so Claude Code's interactive UI works
    prepared.command.stdin(std::process::Stdio::inherit());
    prepared.command.stdout(std::process::Stdio::inherit());
    prepared.command.stderr(std::process::Stdio::inherit());

    let mut child = prepared
        .command
        .spawn()
        .map_err(|e| eyre!("failed to spawn sandboxed process: {e}"))?;

    // Apply rlimits (NOFILE, AS, NPROC) — fallback for cgroup limits and defense-in-depth.
    let child_pid = child.id();
    #[expect(clippy::cast_possible_wrap, reason = "PID fits in i32")]
    if let Err(e) = prepared.apply_rlimits(nix::unistd::Pid::from_raw(child_pid as i32)) {
        tracing::warn!(error = %e, "failed to apply rlimits — continuing without resource limits");
    }

    let status = child
        .wait()
        .map_err(|e| eyre!("failed to wait on sandboxed process: {e}"))?;

    if status.success() {
        tracing::info!("sandboxed session completed successfully");
    } else {
        let code = status.code().unwrap_or(1);
        tracing::warn!(exit_code = code, "sandboxed session exited with error");
    }

    // Drop prepared before exit() — exit() skips destructors,
    // which would leak slirp4netns and namespace holder processes.
    drop(prepared);

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
