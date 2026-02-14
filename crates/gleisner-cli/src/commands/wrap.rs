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
pub fn execute(args: WrapArgs) -> Result<()> {
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

    // Detect Claude Code version for logging
    if let Some(version) = detect_claude_code_version(&args.claude_bin) {
        tracing::info!(claude_version = %version, "detected Claude Code version");
    }

    // Build command: claude [args...]
    let mut inner_command = vec![args.claude_bin];
    inner_command.extend(args.claude_args);

    let mut cmd = sandbox.build_command(&inner_command);

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
