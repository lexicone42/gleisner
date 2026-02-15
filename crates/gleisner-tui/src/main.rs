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

use gleisner_tui::app::{App, Role, SessionState};
use gleisner_tui::claude::{DriverMessage, QueryConfig, SandboxConfig, spawn_query};
use gleisner_tui::ui;

#[tokio::main]
async fn main() -> color_eyre::Result<()> {
    color_eyre::install()?;

    let args: Vec<String> = std::env::args().collect();

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

    // Load the gleisner security profile
    let profile = gleisner_polis::profile::resolve_profile(&profile_name)?;

    // Build sandbox config if --sandbox was passed
    let sandbox = if sandboxed {
        Some(SandboxConfig {
            profile: profile.clone(),
            project_dir,
        })
    } else {
        None
    };

    let terminal = ratatui::init();
    let result = run(terminal, profile, sandbox).await;
    ratatui::restore();
    result
}

async fn run(
    mut terminal: DefaultTerminal,
    profile: gleisner_polis::profile::Profile,
    sandbox: Option<SandboxConfig>,
) -> color_eyre::Result<()> {
    let mut app = App::new(&profile.name);

    let sandbox_indicator = if sandbox.is_some() {
        " [sandboxed]"
    } else {
        ""
    };
    app.push_message(
        Role::System,
        format!(
            "gleisner TUI v0.1.0 — profile: {} — {}{}",
            profile.name, profile.description, sandbox_indicator
        ),
    );
    app.push_message(
        Role::System,
        "Press 'i' to enter insert mode, type a prompt, press Enter to send to Claude.",
    );

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
                    // handle_key returns Some(prompt) if the user submitted
                    if let Some(prompt) = app.handle_key(key) {
                        let mut config = QueryConfig::from_profile(&profile);
                        config.prompt = prompt;
                        config.resume_session = app.session_id.clone();
                        config.sandbox = sandbox.clone();
                        stream_rx = Some(spawn_query(config, 256));
                    }
                }
            }
        }

        // Drain any pending stream events (non-blocking)
        if let Some(ref mut rx) = stream_rx {
            while let Ok(msg) = rx.try_recv() {
                match msg {
                    DriverMessage::Event(event) => {
                        app.handle_stream_event(event);
                    }
                    DriverMessage::Exited(code) => {
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
                        app.session_state = SessionState::Idle;
                        app.push_message(Role::System, format!("[error] {err}"));
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
