//! Claude CLI subprocess driver.
//!
//! Spawns `claude -p --output-format stream-json --verbose` and provides
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

use std::path::{Path, PathBuf};
use std::process::Stdio;

use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;
use tokio::sync::mpsc;

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
}

/// Configuration for a Claude query.
#[derive(Debug, Clone)]
pub struct QueryConfig {
    /// The prompt to send.
    pub prompt: String,
    /// Tools to auto-approve (e.g. ["Read", "Bash", "Glob"]).
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
            claude_bin: "claude".into(),
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
            .map(|p| expand_tilde(p).display().to_string())
            .collect();

        let disallowed_tools = plugins.disallowed_tools.clone();

        Self {
            prompt: String::new(),
            allowed_tools: vec![],
            resume_session: None,
            cwd: None,
            claude_bin: "claude".into(),
            system_prompt: None,
            add_dirs,
            skip_permissions: plugins.skip_permissions,
            disallowed_tools,
            sandbox: None,
        }
    }
}

/// Expand `~` to the user's home directory.
fn expand_tilde(path: &Path) -> PathBuf {
    let s = path.display().to_string();
    if s.starts_with('~') {
        if let Ok(home) = std::env::var("HOME") {
            return PathBuf::from(home).join(path.strip_prefix("~").unwrap_or(path));
        }
    }
    path.to_path_buf()
}

/// Messages sent from the Claude driver task to the TUI.
#[derive(Debug)]
pub enum DriverMessage {
    /// A parsed stream event from the claude subprocess.
    Event(StreamEvent),
    /// The subprocess exited (with exit code).
    Exited(Option<i32>),
    /// An error occurred.
    Error(String),
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

/// Internal: run the claude subprocess and stream events.
///
/// When `config.sandbox` is set, wraps the claude invocation in a
/// bubblewrap sandbox with filesystem/network/process isolation.
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
    let mut cmd = if let Some(ref sandbox_cfg) = config.sandbox {
        build_sandboxed_command(config, sandbox_cfg, inner_args)?
    } else {
        let mut tokio_cmd = Command::new(&config.claude_bin);
        tokio_cmd.args(&inner_args);

        if let Some(ref cwd) = config.cwd {
            tokio_cmd.current_dir(cwd);
        }

        tokio_cmd
    };

    // Common settings for both sandboxed and unsandboxed
    cmd.env_remove("CLAUDECODE");
    cmd.stdout(Stdio::piped()).stderr(Stdio::inherit());

    let mut child = cmd.spawn()?;

    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| color_eyre::eyre::eyre!("failed to capture claude stdout"))?;

    let reader = BufReader::new(stdout);
    let mut lines = reader.lines();

    // Read NDJSON lines and parse into events
    while let Some(line) = lines.next_line().await? {
        if let Some(event) = stream::parse_event(&line) {
            if tx.send(DriverMessage::Event(event)).await.is_err() {
                // Receiver dropped — TUI shut down
                break;
            }
        }
    }

    // Wait for the process to exit
    let status = child.wait().await?;
    let _ = tx.send(DriverMessage::Exited(status.code())).await;

    Ok(())
}

/// Build a tokio Command that runs claude inside a bwrap sandbox.
///
/// The sandbox inherits isolation rules from the profile and adds:
/// - `$HOME` as readonly (claude needs `~/.claude/` for config)
/// - `~/.claude` as read-write (session state, settings)
/// - Plugin `add_dirs` as read-write (exo-self, etc.)
/// - MCP network domains merged into the sandbox allowlist
fn build_sandboxed_command(
    config: &QueryConfig,
    sandbox_cfg: &SandboxConfig,
    inner_args: Vec<String>,
) -> color_eyre::Result<Command> {
    let mut profile = sandbox_cfg.profile.clone();

    // Claude Code needs access to its config directory (~/.claude/).
    // Add $HOME as readonly so claude can find its settings, MCP config,
    // hooks, etc. The profile's deny paths (tmpfs overlays) will shadow
    // sensitive directories like ~/.ssh, ~/.aws within this bind.
    if let Ok(home) = std::env::var("HOME") {
        let home_path = PathBuf::from(&home);
        if !profile.filesystem.readonly_bind.contains(&home_path) {
            profile.filesystem.readonly_bind.push(home_path);
        }
    }

    let mut sandbox = gleisner_polis::BwrapSandbox::new(profile, sandbox_cfg.project_dir.clone())?;

    // ~/.claude needs to be read-write for session state and settings
    if let Ok(home) = std::env::var("HOME") {
        sandbox.allow_paths(std::iter::once(PathBuf::from(format!("{home}/.claude"))));
    }

    // Make plugin add_dirs accessible inside the sandbox (e.g. exo-self)
    sandbox.allow_paths(config.add_dirs.iter().map(PathBuf::from));

    // Merge MCP network domains into sandbox allowlist
    sandbox.allow_domains(
        sandbox_cfg
            .profile
            .plugins
            .mcp_network_domains
            .iter()
            .cloned(),
    );

    // Build inner command: [claude_bin, ...args]
    let mut full_inner: Vec<String> = vec![config.claude_bin.clone()];
    full_inner.extend(inner_args);

    // Build bwrap command (without NetworkFilter — uses simple --unshare-net)
    let std_cmd = sandbox.build_command(&full_inner, None);

    // Convert std::process::Command → tokio::process::Command
    let mut tokio_cmd = Command::new(std_cmd.get_program());
    tokio_cmd.args(std_cmd.get_args());

    Ok(tokio_cmd)
}
