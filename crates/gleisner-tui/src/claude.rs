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

// Attestation pipeline types — portable (compile everywhere).
use gleisner_scapes::stream::{EventBus, spawn_jsonl_writer};

#[cfg(target_os = "linux")]
use gleisner_polis::fs_monitor;
#[cfg(target_os = "linux")]
use tokio_util::sync::CancellationToken;

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
    /// Use Sigstore keyless signing for attestation bundles.
    /// Requires the `keyless` feature on gleisner-introdus.
    pub use_sigstore: bool,
    /// Pre-supplied OIDC token for headless Sigstore signing.
    /// If None with `use_sigstore`, falls back to ambient CI detection
    /// then interactive browser flow.
    pub sigstore_token: Option<String>,
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
            use_sigstore: false,
            sigstore_token: None,
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
            use_sigstore: false,
            sigstore_token: None,
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
    /// Attestation bundle was written successfully.
    AttestationComplete {
        /// Path to the written attestation bundle.
        path: PathBuf,
        /// Number of audit events recorded.
        event_count: u64,
        /// Path to the JSONL audit log for this session.
        audit_log_path: PathBuf,
    },
}

/// Handle to a running query — holds the receiver and a way to abort.
pub struct QueryHandle {
    /// Stream of driver messages.
    pub rx: mpsc::Receiver<DriverMessage>,
    /// Abort handle — dropping or calling `.abort()` kills the task.
    pub task: tokio::task::JoinHandle<()>,
}

/// Spawn a Claude query as a background task.
///
/// Returns a [`QueryHandle`] with a receiver that streams [`DriverMessage`]s
/// and a `JoinHandle` that can be aborted to kill the subprocess.
pub fn spawn_query(config: QueryConfig, buffer_size: usize) -> QueryHandle {
    let (tx, rx) = mpsc::channel(buffer_size);

    let task = tokio::spawn(async move {
        if let Err(e) = run_query(&config, &tx).await {
            let _ = tx.send(DriverMessage::Error(e.to_string())).await;
        }
    });

    QueryHandle { rx, task }
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
/// domains, sets up TAP networking (pasta) + nftables for selective filtering
/// (matching the behavior of `gleisner wrap`).
///
/// When sandboxed, also runs the attestation pipeline:
/// pre-session state capture → event bus + monitors → post-session
/// reconciliation → in-toto statement assembly → signing → bundle write.
#[allow(clippy::too_many_lines)]
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

    // ── Set up attestation pipeline (sandboxed sessions only) ───
    #[cfg(target_os = "linux")]
    #[allow(clippy::option_if_let_else)]
    let mut attest_state = if let Some(ref sandbox_cfg) = config.sandbox {
        match setup_attestation(
            &sandbox_cfg.project_dir,
            &sandbox_cfg.profile,
            // Always use local ECDSA for automatic attestation.
            // Sigstore keyless signing is interactive (OIDC browser flow)
            // and only works via the explicit /cosign TUI command.
            false,
            None,
        ) {
            Ok(state) => Some(state),
            Err(e) => {
                warn!(error = %e, "attestation setup failed — session will run without recording");
                None
            }
        }
    } else {
        None
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

    // ── Start attestation monitors (needs child PID) ────────────
    #[cfg(target_os = "linux")]
    if let Some(ref mut state) = attest_state {
        start_attestation_monitors(state, child.id().unwrap_or(0));
    }

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
    let exit_code = status.code().unwrap_or(1);
    info!(?status, lines = line_count, "subprocess finished");

    // Send Exited BEFORE attestation finalization so the TUI goes
    // Idle immediately. Attestation can take seconds (snapshot hashing,
    // signing) and the user shouldn't have to wait for it.
    let _ = tx.send(DriverMessage::Exited(status.code())).await;

    // ── Finalize attestation pipeline ───────────────────────────
    #[cfg(target_os = "linux")]
    if let Some(state) = attest_state {
        match finalize_attestation(state, exit_code).await {
            Ok(result) => {
                info!(
                    path = %result.path.display(),
                    events = result.event_count,
                    "attestation bundle written"
                );
                let _ = tx
                    .send(DriverMessage::AttestationComplete {
                        path: result.path,
                        event_count: result.event_count,
                        audit_log_path: result.audit_log_path,
                    })
                    .await;
            }
            Err(e) => {
                warn!(error = %e, "attestation finalization failed — session data not recorded");
            }
        }
    }

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

// ── Attestation pipeline (Linux only) ───────────────────────────────
//
// These types and functions wire the attestation recording pipeline
// (from gleisner-introdus + gleisner-scapes) into the TUI's subprocess
// lifecycle. The pipeline mirrors `gleisner record` but integrates with
// the TUI's async event-driven architecture rather than owning stdin/stdout.

/// Mutable state for an in-progress attestation recording.
#[cfg(target_os = "linux")]
struct AttestationState {
    /// Event bus that distributes audit events to consumers.
    bus: EventBus,
    /// Cloneable publisher handle — cloned for each monitor task.
    publisher: gleisner_scapes::stream::EventPublisher,
    /// Background task consuming events into `RecorderOutput`.
    recorder_handle: tokio::task::JoinHandle<gleisner_introdus::recorder::RecorderOutput>,
    /// Background task writing events to JSONL audit log.
    writer_handle: tokio::task::JoinHandle<()>,
    /// Pre-session filesystem snapshot for reconciliation.
    pre_snapshot: fs_monitor::FileSnapshot,
    /// Cancellation token for stopping monitors on session end.
    cancel: CancellationToken,
    /// Handles to spawned monitor tasks.
    monitor_handles: Vec<tokio::task::JoinHandle<()>>,
    /// Project directory being monitored.
    project_dir: PathBuf,
    /// `.gleisner/` directory for output files.
    gleisner_dir: PathBuf,
    /// Path to the JSONL audit log being written.
    audit_log_path: PathBuf,
    /// Path where the attestation bundle will be written.
    output_path: PathBuf,
    /// Patterns for ignoring paths in fs monitoring/snapshots.
    fs_ignore_patterns: Vec<String>,
    /// Captured Claude Code runtime context.
    cc_context: gleisner_introdus::claude_code::ClaudeCodeContext,
    /// Captured git state (if in a repo).
    git_state: Option<gleisner_introdus::vcs::GitState>,
    /// Profile name for provenance metadata.
    profile_name: String,
    /// SHA-256 of the profile TOML file.
    profile_digest: String,
    /// Network policy summary string.
    network_policy: String,
    /// Number of denied filesystem paths in the profile.
    filesystem_deny_count: usize,
    /// Use Sigstore keyless signing instead of local ECDSA.
    use_sigstore: bool,
    /// Pre-supplied OIDC token for headless Sigstore signing.
    /// Only read when the `keyless` feature is enabled.
    #[cfg_attr(not(feature = "keyless"), expect(dead_code))]
    sigstore_token: Option<String>,
}

/// Result of a successful attestation finalization.
#[cfg(target_os = "linux")]
struct AttestationResult {
    path: PathBuf,
    event_count: u64,
    audit_log_path: PathBuf,
}

/// Set up the attestation pipeline before spawning the subprocess.
///
/// Creates the event bus, subscribes the JSONL writer and session recorder,
/// captures pre-session state (git, Claude Code context, filesystem snapshot),
/// and prepares output paths.
#[cfg(target_os = "linux")]
fn setup_attestation(
    project_dir: &std::path::Path,
    profile: &gleisner_polis::profile::Profile,
    use_sigstore: bool,
    sigstore_token: Option<String>,
) -> color_eyre::Result<AttestationState> {
    use chrono::Utc;
    use color_eyre::eyre::eyre;

    let gleisner_dir = project_dir.join(".gleisner");
    std::fs::create_dir_all(&gleisner_dir)?;

    let timestamp = Utc::now().format("%Y%m%dT%H%M%SZ");
    let output_path = gleisner_dir.join(format!("attestation-{timestamp}.json"));
    let audit_log_path = gleisner_dir.join(format!("audit-{timestamp}.jsonl"));

    // Capture pre-session state
    let cc_context = gleisner_introdus::claude_code::ClaudeCodeContext::capture(project_dir);
    let git_state = gleisner_introdus::vcs::capture(project_dir).ok();

    if let Some(ref gs) = git_state {
        info!(
            commit = %gs.commit,
            branch = gs.branch.as_deref().unwrap_or("detached"),
            dirty = gs.dirty,
            "captured git state for attestation"
        );
    }

    // Hash the profile TOML for the provenance summary
    let profile_digest = hash_profile_by_name(&profile.name).unwrap_or_default();

    // Set up event bus + consumers
    let bus = EventBus::new();
    let rx_writer = bus.subscribe();
    let rx_recorder = bus.subscribe();
    let publisher = bus.publisher();

    let writer_handle = spawn_jsonl_writer(rx_writer, &audit_log_path)
        .map_err(|e| eyre!("failed to start audit log writer: {e}"))?;

    let recorder_handle = tokio::spawn(gleisner_introdus::recorder::run(rx_recorder));

    // Take pre-session filesystem snapshot
    let fs_ignore_patterns = vec![
        "target".to_owned(),
        ".git".to_owned(),
        "node_modules".to_owned(),
        ".gleisner".to_owned(),
    ];

    info!("capturing pre-session filesystem snapshot");
    let pre_snapshot = fs_monitor::snapshot_directory(project_dir, &fs_ignore_patterns);

    info!(
        output = %output_path.display(),
        audit_log = %audit_log_path.display(),
        "attestation pipeline initialized"
    );

    Ok(AttestationState {
        bus,
        publisher,
        recorder_handle,
        writer_handle,
        pre_snapshot,
        cancel: CancellationToken::new(),
        monitor_handles: Vec::new(),
        project_dir: project_dir.to_owned(),
        gleisner_dir,
        audit_log_path,
        output_path,
        fs_ignore_patterns,
        cc_context,
        git_state,
        profile_name: profile.name.clone(),
        profile_digest,
        network_policy: format!("{:?}", profile.network.default).to_lowercase(),
        filesystem_deny_count: profile.filesystem.deny.len(),
        use_sigstore,
        sigstore_token,
    })
}

/// Start filesystem and process monitors after the subprocess has spawned.
#[cfg(target_os = "linux")]
fn start_attestation_monitors(state: &mut AttestationState, child_pid: u32) {
    // Filesystem monitor (inotify — portable, no capabilities needed)
    let fs_config = gleisner_polis::FsMonitorConfig {
        mount_path: state.project_dir.clone(),
        ignore_patterns: state.fs_ignore_patterns.clone(),
    };
    let fs_publisher = state.publisher.clone();
    let fs_cancel = state.cancel.clone();
    let handle = tokio::spawn(async move {
        if let Err(e) = fs_monitor::run_fs_monitor(fs_config, fs_publisher, fs_cancel).await {
            warn!(error = %e, "filesystem monitor failed — continuing without fs monitoring");
        }
    });
    state.monitor_handles.push(handle);

    // Process monitor (/proc scanner)
    if child_pid > 0 {
        let proc_config = gleisner_polis::ProcMonitorConfig {
            root_pid: child_pid,
            poll_interval: gleisner_polis::ProcMonitorConfig::DEFAULT_POLL_INTERVAL,
        };
        let proc_publisher = state.publisher.clone();
        let proc_cancel = state.cancel.clone();
        let handle = tokio::spawn(async move {
            if let Err(e) =
                gleisner_polis::procmon::run_proc_monitor(proc_config, proc_publisher, proc_cancel)
                    .await
            {
                warn!(error = %e, "process monitor failed — continuing without proc monitoring");
            }
        });
        state.monitor_handles.push(handle);
    }

    info!(
        child_pid,
        monitors = state.monitor_handles.len(),
        "attestation monitors started"
    );
}

/// Finalize the attestation pipeline after the subprocess exits.
///
/// Cancels monitors, reconciles filesystem snapshots, closes the event
/// bus, awaits recorder output, assembles the in-toto statement, signs
/// it with a local key, and writes the attestation bundle to disk.
#[cfg(target_os = "linux")]
#[allow(clippy::too_many_lines, clippy::similar_names)]
async fn finalize_attestation(
    state: AttestationState,
    exit_code: i32,
) -> color_eyre::Result<AttestationResult> {
    use color_eyre::eyre::eyre;
    use gleisner_introdus::provenance::{
        BuildMetadata, Builder, ChainMetadata, ClaudeCodeEnvironment, Completeness,
        GleisnerProvenance, Invocation, SandboxProfileSummary,
    };
    use gleisner_introdus::signer::{LocalSigner, Signer, default_key_path};
    use gleisner_introdus::statement::InTotoStatement;

    // ── 1. Cancel monitors and await their completion ────────────
    state.cancel.cancel();
    for handle in state.monitor_handles {
        let _ = handle.await;
    }

    // ── 2. Post-session snapshot reconciliation ─────────────────
    info!("running post-session filesystem reconciliation");
    let after = fs_monitor::snapshot_directory(&state.project_dir, &state.fs_ignore_patterns);
    let seen = std::collections::HashSet::new();
    let stats =
        fs_monitor::reconcile_snapshots(&state.pre_snapshot, &after, &seen, &state.publisher);
    if stats.total_missed() > 0 {
        info!(
            missed_writes = stats.missed_writes,
            missed_creates = stats.missed_creates,
            missed_deletes = stats.missed_deletes,
            "reconciliation captured events missed by real-time monitor"
        );
    }

    // ── 3. Collect kernel denial events ────────────────────────
    // Landlock denials from the kernel audit log (if audisp is configured)
    // and nftables firewall denials from dmesg. These are post-hoc:
    // the denial events are written to kernel logs during the session
    // and we harvest them now, before closing the event bus.
    let session_end = chrono::Utc::now();
    let session_start = session_end - chrono::Duration::minutes(30);

    // Landlock denials (from audisp audit log, if available)
    let landlock_log = PathBuf::from("/var/log/gleisner/landlock-audit.log");
    if landlock_log.exists() {
        let audit_config = gleisner_polis::KernelAuditConfig {
            session_start,
            session_end,
            audit_log_path: landlock_log,
        };
        let landlock_count =
            gleisner_polis::collect_and_publish_denials(&audit_config, &state.publisher);
        if landlock_count > 0 {
            info!(count = landlock_count, "collected Landlock denial events");
        }
    }

    // Firewall denials (from dmesg — nftables/iptables log rules)
    match gleisner_polis::capture_firewall_denials_from_dmesg() {
        Ok(fw_events) if !fw_events.is_empty() => {
            let fw_count = fw_events.len();
            for event in fw_events {
                state.publisher.publish(event);
            }
            info!(
                count = fw_count,
                "collected firewall denial events from dmesg"
            );
        }
        Ok(_) => {}
        Err(e) => {
            warn!(error = %e, "could not capture firewall denials from dmesg");
        }
    }

    // ── 4. Close channels and await consumers ───────────────────
    // Drop publisher and bus to close the broadcast channel,
    // which causes recorder and writer tasks to complete.
    drop(state.publisher);
    drop(state.bus);

    let recorder_output = state
        .recorder_handle
        .await
        .map_err(|e| eyre!("recorder task panicked: {e}"))?;

    state
        .writer_handle
        .await
        .map_err(|e| eyre!("audit writer panicked: {e}"))?;

    // Hash the fully-written audit log
    let audit_log_digest =
        gleisner_introdus::recorder::hash_file(&state.audit_log_path).unwrap_or_default();

    info!(
        event_count = recorder_output.event_count,
        materials = recorder_output.materials.len(),
        subjects = recorder_output.subjects.len(),
        "session recording complete"
    );

    // ── 5. Find parent attestation for chaining ─────────────────
    let chain_metadata =
        match gleisner_introdus::chain::find_latest_attestation(&state.gleisner_dir) {
            Ok(Some(link)) => {
                info!(
                    parent = %link.path.display(),
                    digest = %link.payload_digest,
                    "linking to parent attestation"
                );
                Some(ChainMetadata {
                    parent_digest: link.payload_digest,
                    parent_path: link.path.display().to_string(),
                })
            }
            Ok(None) => {
                info!("no previous attestation found — starting new chain");
                None
            }
            Err(e) => {
                warn!(error = %e, "failed to discover parent attestation — starting new chain");
                None
            }
        };

    // ── 6. Assemble in-toto statement ───────────────────────────
    let mut materials = recorder_output.materials;
    if let Some(ref gs) = state.git_state {
        materials.push(gs.to_material());
    }

    let effective_model = state.cc_context.effective_model().map(str::to_owned);
    let api_base_url = state
        .cc_context
        .config
        .as_ref()
        .and_then(|c| c.api_base_url.clone())
        .unwrap_or_else(|| "https://api.anthropic.com".to_owned());

    let sandbox_summary = SandboxProfileSummary {
        name: state.profile_name.clone(),
        profile_digest: state.profile_digest,
        network_policy: state.network_policy,
        filesystem_deny_count: state.filesystem_deny_count,
    };

    let statement = InTotoStatement {
        statement_type: InTotoStatement::TYPE,
        subject: recorder_output.subjects,
        predicate_type: InTotoStatement::PREDICATE_TYPE,
        predicate: GleisnerProvenance {
            build_type: GleisnerProvenance::BUILD_TYPE,
            builder: Builder {
                id: gleisner_introdus::metadata::builder_id(),
            },
            invocation: Invocation {
                parameters: serde_json::json!({
                    "exit_code": exit_code,
                    "profile": state.profile_name,
                    "source": "tui",
                }),
                environment: ClaudeCodeEnvironment {
                    tool: "claude-code",
                    claude_code_version: state.cc_context.version,
                    model: effective_model,
                    claude_md_hash: state.cc_context.claude_md_hash,
                    context_hash: None,
                    sandboxed: true,
                    profile: state.profile_name,
                    api_base_url,
                },
            },
            metadata: BuildMetadata {
                build_started_on: recorder_output.start_time,
                build_finished_on: recorder_output.finish_time,
                completeness: Completeness {
                    parameters: true,
                    environment: true,
                    materials: false,
                },
            },
            materials,
            audit_log_digest,
            sandbox_profile: sandbox_summary,
            denial_count: recorder_output.denial_count,
            chain: chain_metadata,
        },
    };

    // ── 7. Sign and write ───────────────────────────────────────
    let bundle = if state.use_sigstore {
        #[cfg(feature = "keyless")]
        {
            let sigstore_bundle_path = state.output_path.with_extension("sigstore.json");
            let signer = gleisner_introdus::signer::SigstoreSigner::new(
                Some(sigstore_bundle_path),
                state.sigstore_token.clone(),
            );
            info!(signer = %Signer::description(&signer), "signing attestation (keyless)");
            signer
                .sign(&statement)
                .await
                .map_err(|e| eyre!("Sigstore signing failed: {e}"))?
        }
        #[cfg(not(feature = "keyless"))]
        {
            return Err(eyre!(
                "--sigstore requires building with `--features keyless`"
            ));
        }
    } else {
        let key_path = default_key_path();
        let signer = LocalSigner::load_or_generate(&key_path)
            .map_err(|e| eyre!("signing key error: {e}"))?;
        info!(signer = %signer.description(), "signing attestation (local key)");
        signer
            .sign(&statement)
            .await
            .map_err(|e| eyre!("signing failed: {e}"))?
    };

    let json = serde_json::to_string_pretty(&bundle)?;
    std::fs::write(&state.output_path, &json)?;

    info!(
        path = %state.output_path.display(),
        audit_log = %state.audit_log_path.display(),
        sigstore = state.use_sigstore,
        "attestation bundle written"
    );

    let event_count = recorder_output.event_count;
    Ok(AttestationResult {
        path: state.output_path,
        event_count,
        audit_log_path: state.audit_log_path,
    })
}

/// Hash a profile TOML file by name, searching the standard profile paths.
#[cfg(target_os = "linux")]
fn hash_profile_by_name(name: &str) -> Option<String> {
    use sha2::{Digest, Sha256};

    let search_dirs = [
        dirs_config_dir().map(|d| d.join("profiles")),
        Some(PathBuf::from("profiles")),
        Some(PathBuf::from("/usr/share/gleisner/profiles")),
    ];

    for dir in search_dirs.into_iter().flatten() {
        let candidate = dir.join(format!("{name}.toml"));
        if candidate.exists() {
            if let Ok(data) = std::fs::read(&candidate) {
                let mut hasher = Sha256::new();
                hasher.update(&data);
                return Some(format!("{:x}", hasher.finalize()));
            }
        }
    }
    None
}

/// Config directory: `~/.config/gleisner/`
#[cfg(target_os = "linux")]
fn dirs_config_dir() -> Option<PathBuf> {
    std::env::var("HOME")
        .ok()
        .map(|home| PathBuf::from(home).join(".config/gleisner"))
}
