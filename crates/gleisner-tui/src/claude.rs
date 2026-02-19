//! Claude CLI subprocess driver.
//!
//! Spawns `claude -p --output-format stream-json --verbose --include-partial-messages` and provides
//! an async stream of parsed [`StreamEvent`]s.
//!
//! # Architecture
//!
//! ```text
//! TUI event loop
//!     ↓ spawn_query()
//! tokio::spawn → claude subprocess
//!     ↓ stdout (NDJSON lines)
//! parse each line → StreamEvent
//!     ↓ mpsc channel
//! TUI receives events → updates app state → re-renders
//! ```
//!
//! When sandboxing is enabled, the subprocess is wrapped in bubblewrap:
//!
//! ```text
//! tokio::spawn → bwrap → claude subprocess
//!                  ↑ filesystem/network/process isolation from profile
//! ```

use std::path::PathBuf;
use std::process::Stdio;

use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use crate::stream::{self, StreamEvent};

/// Sandbox wrapping configuration.
///
/// When present in [`QueryConfig`], the claude subprocess is launched
/// inside a bubblewrap sandbox with filesystem, network, and process
/// isolation defined by the profile.
#[derive(Debug, Clone)]
pub struct SandboxConfig {
    /// The security profile defining isolation boundaries.
    pub profile: gleisner_polis::profile::Profile,
    /// Project directory to mount read-write inside the sandbox.
    pub project_dir: PathBuf,
    /// Additional domains to allow network access (merged into profile).
    pub extra_allow_network: Vec<String>,
    /// Additional paths to mount read-write inside the sandbox.
    pub extra_allow_paths: Vec<PathBuf>,
}

/// Configuration for a Claude query.
#[derive(Debug, Clone)]
pub struct QueryConfig {
    /// The prompt to send.
    pub prompt: String,
    /// Tools to auto-approve (e.g. `Read`, `Bash`, `Glob`).
    pub allowed_tools: Vec<String>,
    /// Session ID to resume (for multi-turn conversations).
    pub resume_session: Option<String>,
    /// Working directory for the claude process.
    pub cwd: Option<String>,
    /// Path to the claude binary (defaults to "claude").
    pub claude_bin: String,
    /// Additional system prompt to append.
    pub system_prompt: Option<String>,
    /// Additional directories to grant tool access to.
    pub add_dirs: Vec<String>,
    /// Skip Claude Code's built-in permission checks.
    /// Gleisner's sandbox (bwrap, cgroups, nftables) provides the
    /// actual security boundary, making Claude Code's interactive
    /// permission prompts redundant and counterproductive in -p mode.
    pub skip_permissions: bool,
    /// Tools to explicitly deny. Useful for blocking dangerous MCP
    /// tool capabilities (e.g. serena's shell execution, playwright
    /// browser navigation) while keeping their analysis tools.
    pub disallowed_tools: Vec<String>,
    /// Optional sandbox configuration. When set, the claude command
    /// is wrapped in a bubblewrap sandbox.
    pub sandbox: Option<SandboxConfig>,
}

impl Default for QueryConfig {
    fn default() -> Self {
        // Grant access to exo-self directories so plugins can read/write
        // session notes, journal entries, and interest queues.
        let home = std::env::var("HOME").unwrap_or_default();
        let exo_self_dir = format!("{home}/.claude/exo-self");

        Self {
            prompt: String::new(),
            allowed_tools: vec![],
            resume_session: None,
            cwd: None,
            claude_bin: gleisner_polis::resolve_claude_bin(),
            system_prompt: None,
            add_dirs: vec![exo_self_dir],
            // Default to skipping permissions — gleisner IS the sandbox.
            skip_permissions: true,
            // Block MCP tools that duplicate sandbox-controlled capabilities.
            // Serena's shell execution bypasses sandbox process monitoring.
            // Playwright browser navigation is a network escape vector.
            disallowed_tools: vec![
                "mcp__plugin_serena_serena__execute_shell_command".into(),
                "mcp__plugin_serena_serena__create_text_file".into(),
            ],
            sandbox: None,
        }
    }
}

impl QueryConfig {
    /// Create a `QueryConfig` from a gleisner profile's plugin policy.
    ///
    /// Reads `skip_permissions`, `disallowed_tools`, and `add_dirs` from
    /// the profile's `[plugins]` section instead of using hardcoded defaults.
    pub fn from_profile(profile: &gleisner_polis::profile::Profile) -> Self {
        let plugins = &profile.plugins;

        let add_dirs = plugins
            .add_dirs
            .iter()
            .map(|p| gleisner_polis::expand_tilde(p).display().to_string())
            .collect();

        let disallowed_tools = plugins.disallowed_tools.clone();

        Self {
            prompt: String::new(),
            allowed_tools: vec![],
            resume_session: None,
            cwd: None,
            claude_bin: gleisner_polis::resolve_claude_bin(),
            system_prompt: None,
            add_dirs,
            skip_permissions: plugins.skip_permissions,
            disallowed_tools,
            sandbox: None,
        }
    }
}

/// Messages sent from the Claude driver task to the TUI.
#[derive(Debug)]
pub enum DriverMessage {
    /// A parsed stream event from the claude subprocess.
    Event(Box<StreamEvent>),
    /// The subprocess exited (with exit code).
    Exited(Option<i32>),
    /// An error occurred.
    Error(String),
    /// A line of stderr output from the subprocess.
    Stderr(String),
}

/// Spawn a Claude query as a background task.
///
/// Returns an `mpsc::Receiver` that streams [`DriverMessage`]s
/// as the subprocess produces output. The task runs until the
/// subprocess exits.
pub fn spawn_query(config: QueryConfig, buffer_size: usize) -> mpsc::Receiver<DriverMessage> {
    let (tx, rx) = mpsc::channel(buffer_size);

    tokio::spawn(async move {
        if let Err(e) = run_query(&config, &tx).await {
            let _ = tx.send(DriverMessage::Error(e.to_string())).await;
        }
    });

    rx
}

/// Handles to sandbox infrastructure that must outlive the subprocess.
///
/// Holds the [`PreparedSandbox`](gleisner_polis::PreparedSandbox) which
/// owns the namespace holder, TAP provider process, and Landlock policy
/// tempfile. Dropped automatically when the query future completes.
#[cfg(target_os = "linux")]
struct SandboxHandles {
    _prepared: Option<gleisner_polis::PreparedSandbox>,
}

#[cfg(not(target_os = "linux"))]
struct SandboxHandles;

/// Internal: run the claude subprocess and stream events.
///
/// When `config.sandbox` is set, wraps the claude invocation in a
/// bubblewrap sandbox with filesystem/network/process isolation.
/// If the profile declares `network.default = "deny"` with allowed
/// domains, sets up TAP networking (pasta/slirp4netns) + nftables for selective filtering
/// (matching the behavior of `gleisner wrap`).
async fn run_query(
    config: &QueryConfig,
    tx: &mpsc::Sender<DriverMessage>,
) -> color_eyre::Result<()> {
    // ── Build claude CLI arguments ──────────────────────────────
    let mut inner_args: Vec<String> = vec![
        "-p".into(),
        config.prompt.clone(),
        "--output-format".into(),
        "stream-json".into(),
        "--verbose".into(),
        "--include-partial-messages".into(),
    ];

    if config.skip_permissions {
        inner_args.push("--dangerously-skip-permissions".into());
    }

    if !config.allowed_tools.is_empty() {
        inner_args.push("--allowedTools".into());
        inner_args.push(config.allowed_tools.join(","));
    }

    if !config.disallowed_tools.is_empty() {
        inner_args.push("--disallowedTools".into());
        inner_args.push(config.disallowed_tools.join(","));
    }

    if let Some(ref session_id) = config.resume_session {
        inner_args.push("--resume".into());
        inner_args.push(session_id.clone());
    }

    if let Some(ref sys) = config.system_prompt {
        inner_args.push("--append-system-prompt".into());
        inner_args.push(sys.clone());
    }

    for dir in &config.add_dirs {
        inner_args.push("--add-dir".into());
        inner_args.push(dir.clone());
    }

    // ── Build the actual command — optionally wrapped in bwrap ──
    // _handles keeps PreparedSandbox alive until subprocess exits.
    let (mut cmd, _handles) = if let Some(ref sandbox_cfg) = config.sandbox {
        build_sandboxed_command(config, sandbox_cfg, inner_args)?
    } else {
        let mut tokio_cmd = Command::new(&config.claude_bin);
        tokio_cmd.args(&inner_args);

        if let Some(ref cwd) = config.cwd {
            tokio_cmd.current_dir(cwd);
        }

        #[cfg(target_os = "linux")]
        let handles = SandboxHandles { _prepared: None };
        #[cfg(not(target_os = "linux"))]
        let handles = SandboxHandles;

        (tokio_cmd, handles)
    };

    // Common settings for both sandboxed and unsandboxed
    cmd.env_remove("CLAUDECODE");
    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());

    info!(
        claude_bin = %config.claude_bin,
        sandboxed = config.sandbox.is_some(),
        "spawning claude subprocess"
    );
    let mut child = cmd.spawn()?;

    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| color_eyre::eyre::eyre!("failed to capture claude stdout"))?;

    // Forward stderr lines to the TUI as DriverMessage::Stderr
    if let Some(stderr) = child.stderr.take() {
        let stderr_tx = tx.clone();
        tokio::spawn(async move {
            let reader = BufReader::new(stderr);
            let mut lines = reader.lines();
            while let Ok(Some(line)) = lines.next_line().await {
                // sandbox-init status messages are informational — log only
                if line.starts_with("gleisner-sandbox-init:") {
                    debug!(line = %line, "sandbox-init status (suppressed from UI)");
                    continue;
                }
                if stderr_tx.send(DriverMessage::Stderr(line)).await.is_err() {
                    break;
                }
            }
        });
    }

    let reader = BufReader::new(stdout);
    let mut lines = reader.lines();

    // Read NDJSON lines and parse into events
    let mut line_count: u64 = 0;
    while let Some(line) = lines.next_line().await? {
        line_count += 1;
        if let Some(event) = stream::parse_event(&line) {
            debug!(line = line_count, event = ?std::mem::discriminant(&event), "parsed stream event");
            if tx
                .send(DriverMessage::Event(Box::new(event)))
                .await
                .is_err()
            {
                // Receiver dropped — TUI shut down
                break;
            }
        } else {
            warn!(line = line_count, raw = %line, "unparseable NDJSON line");
        }
    }

    // Wait for the process to exit
    let status = child.wait().await?;
    info!(?status, lines = line_count, "subprocess finished");
    let _ = tx.send(DriverMessage::Exited(status.code())).await;

    // _handles dropped here — kills TAP provider and namespace holder

    Ok(())
}

/// Build a tokio Command that runs claude inside a bwrap sandbox.
///
/// Uses the shared [`gleisner_polis::prepare_sandbox`] pipeline, then
/// converts the resulting `std::process::Command` to a `tokio::process::Command`.
/// The returned [`SandboxHandles`] must be kept alive until the subprocess exits.
#[cfg(target_os = "linux")]
fn build_sandboxed_command(
    config: &QueryConfig,
    sandbox_cfg: &SandboxConfig,
    inner_args: Vec<String>,
) -> color_eyre::Result<(Command, SandboxHandles)> {
    // Build full inner command: [claude_bin, ...args]
    let mut full_inner: Vec<String> = vec![config.claude_bin.clone()];
    full_inner.extend(inner_args);

    // Merge QueryConfig's add_dirs into extra paths so they're
    // accessible inside the sandbox (e.g., exo-self directories).
    let mut extra_paths: Vec<PathBuf> = config.add_dirs.iter().map(PathBuf::from).collect();
    extra_paths.extend(sandbox_cfg.extra_allow_paths.iter().cloned());

    let session_config = gleisner_polis::SandboxSessionConfig {
        profile: sandbox_cfg.profile.clone(),
        project_dir: sandbox_cfg.project_dir.clone(),
        extra_allow_network: sandbox_cfg.extra_allow_network.clone(),
        extra_allow_paths: extra_paths,
        no_landlock: false, // TUI always enables Landlock when available
    };

    let prepared = gleisner_polis::prepare_sandbox(session_config, &full_inner)?;

    // Convert std::process::Command → tokio::process::Command
    let mut tcmd = Command::new(prepared.command.get_program());
    tcmd.args(prepared.command.get_args());

    Ok((
        tcmd,
        SandboxHandles {
            _prepared: Some(prepared),
        },
    ))
}

/// Stub for non-Linux platforms — sandbox mode is not available.
#[cfg(not(target_os = "linux"))]
fn build_sandboxed_command(
    _config: &QueryConfig,
    _sandbox_cfg: &SandboxConfig,
    _inner_args: Vec<String>,
) -> color_eyre::Result<(Command, SandboxHandles)> {
    Err(color_eyre::eyre::eyre!("sandbox mode requires Linux"))
}
