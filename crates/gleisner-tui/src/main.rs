//! Gleisner TUI — entry point.
//!
//! An async Ratatui-based terminal interface that spawns `claude`
//! in headless mode and renders the stream-json output alongside
//! a security dashboard.

use std::path::PathBuf;
use std::time::Duration;

use crossterm::event::{self, Event, KeyEventKind};
use ratatui::DefaultTerminal;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use gleisner_tui::app::{App, Role, SessionState, TuiCommand, UserAction};
use gleisner_tui::claude::{DriverMessage, QueryConfig, SandboxConfig, spawn_query};
use gleisner_tui::ui;

#[tokio::main]
async fn main() -> color_eyre::Result<()> {
    color_eyre::install()?;

    let args: Vec<String> = std::env::args().collect();

    // Parse --debug flag — writes structured logs to a file
    let debug_mode = args.iter().any(|a| a == "--debug");
    if debug_mode {
        init_debug_logging()?;
    }

    // Parse --profile argument (default: konishi)
    let profile_name = args
        .iter()
        .position(|a| a == "--profile")
        .and_then(|i| args.get(i + 1))
        .cloned()
        .unwrap_or_else(|| "konishi".into());

    // Parse --sandbox flag — wraps claude in bubblewrap isolation
    let sandboxed = args.iter().any(|a| a == "--sandbox");

    // Parse --project-dir argument (default: current directory)
    let project_dir = args
        .iter()
        .position(|a| a == "--project-dir")
        .and_then(|i| args.get(i + 1))
        .map_or_else(
            || std::env::current_dir().unwrap_or_default(),
            PathBuf::from,
        );

    // Parse --claude-bin argument (default: "claude")
    // Useful for testing with a fake claude binary.
    let claude_bin = args
        .iter()
        .position(|a| a == "--claude-bin")
        .and_then(|i| args.get(i + 1))
        .cloned();

    // Load the gleisner security profile
    let profile = gleisner_polis::profile::resolve_profile(&profile_name)?;

    // Build sandbox config if --sandbox was passed
    let sandbox = if sandboxed {
        Some(SandboxConfig {
            profile: profile.clone(),
            project_dir: project_dir.clone(),
        })
    } else {
        None
    };

    info!(profile = %profile.name, sandbox = sandboxed, "starting gleisner-tui");

    let terminal = ratatui::init();
    let result = run(
        terminal,
        &profile,
        sandbox.as_ref(),
        claude_bin.as_deref(),
        debug_mode,
        &project_dir,
    );
    ratatui::restore();

    info!("gleisner-tui exited");
    result
}

fn run(
    mut terminal: DefaultTerminal,
    profile: &gleisner_polis::profile::Profile,
    sandbox: Option<&SandboxConfig>,
    claude_bin: Option<&str>,
    debug_mode: bool,
    project_dir: &std::path::Path,
) -> color_eyre::Result<()> {
    let mut app = App::new(&profile.name);

    let sandbox_indicator = if sandbox.is_some() { " [embodied]" } else { "" };
    app.push_message(
        Role::System,
        format!(
            "\u{27E8}gleisner\u{27E9} suit active — polis: {}{sandbox_indicator}",
            profile.name,
        ),
    );
    app.push_message(
        Role::System,
        "Channel ready. 'i' to open, Enter to transmit. /help for suit commands.",
    );
    if debug_mode {
        let log_path = dirs_log_dir().join("tui-debug.log");
        app.push_message(
            Role::System,
            format!("Debug logging: tail -f {}", log_path.display()),
        );
    }

    // Channel for receiving stream events from background Claude tasks.
    // None when no query is active.
    let mut stream_rx: Option<mpsc::Receiver<DriverMessage>> = None;

    loop {
        terminal.draw(|frame| ui::draw(frame, &app))?;

        // Poll for terminal events (keyboard) with a short timeout
        // so we also check for stream events frequently.
        if event::poll(Duration::from_millis(50))? {
            if let Event::Key(key) = event::read()? {
                if key.kind == KeyEventKind::Press {
                    if let Some(action) = app.handle_key(key) {
                        match action {
                            UserAction::Prompt(prompt) => {
                                info!(prompt_len = prompt.len(), session = ?app.session_id, "submitting prompt");
                                let mut config = QueryConfig::from_profile(profile);
                                config.prompt = prompt;
                                config.resume_session.clone_from(&app.session_id);
                                config.sandbox = sandbox.cloned();
                                if let Some(bin) = claude_bin {
                                    bin.clone_into(&mut config.claude_bin);
                                }
                                stream_rx = Some(spawn_query(config, 256));
                            }
                            UserAction::Command(cmd) => {
                                handle_command(&mut app, cmd, project_dir);
                            }
                        }
                    }
                }
            }
        }

        // Drain any pending stream events (non-blocking)
        if let Some(ref mut rx) = stream_rx {
            while let Ok(msg) = rx.try_recv() {
                match msg {
                    DriverMessage::Event(event) => {
                        debug!(event_type = ?std::mem::discriminant(&*event), "stream event");
                        app.handle_stream_event(*event);
                    }
                    DriverMessage::Exited(code) => {
                        info!(?code, "subprocess exited");
                        if app.session_state != SessionState::Idle {
                            app.session_state = SessionState::Idle;
                            if let Some(code) = code {
                                if code != 0 {
                                    app.push_message(
                                        Role::System,
                                        format!("[process exited with code {code}]"),
                                    );
                                }
                            }
                        }
                    }
                    DriverMessage::Error(err) => {
                        warn!(%err, "driver error");
                        app.session_state = SessionState::Idle;
                        app.push_message(Role::System, format!("[error] {err}"));
                    }
                    DriverMessage::Stderr(line) => {
                        debug!(line = %line, "subprocess stderr");
                        app.push_message(Role::System, format!("[stderr] {line}"));
                    }
                }
            }
        }

        // Clean up the receiver if the session is done
        if app.session_state == SessionState::Idle && stream_rx.is_some() {
            // Keep the receiver around briefly to drain final messages,
            // but if it's closed, drop it
            if let Some(ref mut rx) = stream_rx {
                if rx.try_recv().is_err() {
                    stream_rx = None;
                }
            }
        }

        if app.should_quit {
            break;
        }
    }

    Ok(())
}

/// Execute a TUI slash command and display results in the conversation.
fn handle_command(app: &mut App, cmd: TuiCommand, project_dir: &std::path::Path) {
    match cmd {
        TuiCommand::Sbom => {
            info!("running /sbom command");
            match gleisner_bridger::sbom::generate(project_dir) {
                Ok(bom) => {
                    app.push_message(
                        Role::System,
                        format!(
                            "SBOM generated: {} components (CycloneDX 1.5)",
                            bom.components.len()
                        ),
                    );
                }
                Err(e) => {
                    app.push_message(Role::System, format!("[error] SBOM generation failed: {e}"));
                }
            }
        }
        TuiCommand::Verify(path) => {
            info!(path = %path, "running /verify command");
            let verifier =
                gleisner_lacerta::Verifier::new(gleisner_lacerta::VerifyConfig::default());
            match verifier.verify_file(std::path::Path::new(&path)) {
                Ok(report) => {
                    let status = if report.passed { "PASS" } else { "FAIL" };
                    let mut lines = vec![format!("Verification: {status}")];
                    for outcome in &report.outcomes {
                        lines.push(format!("  {}", outcome.message()));
                    }
                    app.push_message(Role::System, lines.join("\n"));
                }
                Err(e) => {
                    app.push_message(Role::System, format!("[error] Verification failed: {e}"));
                }
            }
        }
        TuiCommand::Inspect(path) => {
            info!(path = %path, "running /inspect command");
            match std::fs::read_to_string(&path) {
                Ok(json) => match gleisner_lacerta::inspect::summarize(&json) {
                    Ok(summary) => {
                        let lines = [
                            format!("Statement: {}", summary.statement_type),
                            format!("Predicate: {}", summary.predicate_type),
                            format!("Builder:   {}", summary.builder_id),
                            format!("Started:   {}", summary.build_started),
                            format!("Finished:  {}", summary.build_finished),
                            format!("Subjects:  {}", summary.subject_count),
                            format!("Materials: {}", summary.material_count),
                            format!("Sandboxed: {}", summary.sandboxed),
                            format!("Audit log: {}", summary.has_audit_log),
                        ];
                        app.push_message(Role::System, lines.join("\n"));
                    }
                    Err(e) => {
                        app.push_message(Role::System, format!("[error] Inspect failed: {e}"));
                    }
                },
                Err(e) => {
                    app.push_message(
                        Role::System,
                        format!("[error] Cannot read bundle file: {e}"),
                    );
                }
            }
        }
        TuiCommand::Help => {
            let help = "\
Available commands:
  /sbom              Generate SBOM for current project
  /verify <path>     Verify an attestation bundle
  /inspect <path>    Inspect an attestation bundle
  /help              Show this help message";
            app.push_message(Role::System, help);
        }
    }
}

/// Initialize file-based debug logging.
///
/// Writes structured logs to `~/.local/share/gleisner/tui-debug.log`.
/// Monitor in real-time with:
/// ```bash
/// tail -f ~/.local/share/gleisner/tui-debug.log
/// ```
fn init_debug_logging() -> color_eyre::Result<()> {
    let data_dir = dirs_log_dir();
    std::fs::create_dir_all(&data_dir)?;

    let log_path = data_dir.join("tui-debug.log");

    // Truncate the log file at startup so each session starts clean.
    let file = std::fs::File::create(&log_path)?;

    tracing_subscriber::fmt()
        .with_writer(std::sync::Mutex::new(file))
        .with_ansi(false)
        .with_target(true)
        .with_level(true)
        .with_thread_ids(false)
        .init();

    info!(path = %log_path.display(), "debug logging enabled");
    Ok(())
}

/// Log directory: `~/.local/share/gleisner/`
fn dirs_log_dir() -> PathBuf {
    std::env::var("HOME").map_or_else(
        |_| PathBuf::from("/tmp/gleisner"),
        |home| PathBuf::from(home).join(".local/share/gleisner"),
    )
}
