//! Gleisner TUI — entry point.
//!
//! An async Ratatui-based terminal interface that spawns `claude`
//! in headless mode and renders the stream-json output alongside
//! a security dashboard.

use std::path::PathBuf;
use std::time::Duration;

use crossterm::event::{self, Event, KeyEventKind};
use ratatui::DefaultTerminal;
use tracing::{debug, info, warn};

use gleisner_tui::app::{App, Role, SessionState, TuiCommand, UserAction};
use gleisner_tui::claude::{DriverMessage, QueryConfig, QueryHandle, SandboxConfig, spawn_query};
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

    // Parse --allow-network arguments (repeatable)
    let allow_network: Vec<String> = args
        .iter()
        .enumerate()
        .filter(|(_, a)| *a == "--allow-network")
        .filter_map(|(i, _)| args.get(i + 1).cloned())
        .collect();

    // Parse --allow-path arguments (repeatable)
    let allow_path: Vec<PathBuf> = args
        .iter()
        .enumerate()
        .filter(|(_, a)| *a == "--allow-path")
        .filter_map(|(i, _)| args.get(i + 1).map(PathBuf::from))
        .collect();

    // Parse --sigstore flag — use Sigstore keyless signing for attestations
    let use_sigstore = args.iter().any(|a| a == "--sigstore");

    // Parse --sigstore-token argument — pre-supplied OIDC JWT for headless signing.
    // Sigstore identity tokens have a 60-second lifetime, so they must be
    // obtained immediately before use. For interactive sessions (which can
    // last hours), use local ECDSA signing (the default) instead.
    // Sigstore keyless is designed for CI with ambient OIDC tokens.
    let sigstore_token = args
        .iter()
        .position(|a| a == "--sigstore-token")
        .and_then(|i| args.get(i + 1))
        .cloned();

    if use_sigstore && sigstore_token.is_none() {
        eprintln!(
            "\x1b[1;33mwarning:\x1b[0m --sigstore without --sigstore-token: \
             signing will use ambient CI credentials or fail.\n\
             For interactive use, local ECDSA signing (default, no --sigstore) is recommended.\n\
             Sigstore identity tokens expire in 60 seconds — too short for interactive sessions."
        );
    }

    // Load the gleisner security profile
    let profile = gleisner_polis::profile::resolve_profile(&profile_name)?;

    // Build sandbox config if --sandbox was passed
    let sandbox = if sandboxed {
        Some(SandboxConfig {
            profile: profile.clone(),
            project_dir: project_dir.clone(),
            extra_allow_network: allow_network,
            extra_allow_paths: allow_path,
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
        use_sigstore,
        sigstore_token.as_deref(),
    )
    .await;
    ratatui::restore();

    info!("gleisner-tui exited");
    result
}

#[allow(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    clippy::unused_async
)]
async fn run(
    mut terminal: DefaultTerminal,
    profile: &gleisner_polis::profile::Profile,
    sandbox: Option<&SandboxConfig>,
    claude_bin: Option<&str>,
    debug_mode: bool,
    project_dir: &std::path::Path,
    use_sigstore: bool,
    sigstore_token: Option<&str>,
) -> color_eyre::Result<()> {
    let mut app = App::new(&profile.name);
    app.security.sandbox_active = sandbox.is_some();

    let sandbox_indicator = if sandbox.is_some() { " [embodied]" } else { "" };
    let sigstore_indicator = if use_sigstore { " [sigstore]" } else { "" };
    app.push_message(
        Role::System,
        format!(
            "\u{27E8}gleisner\u{27E9} suit active — polis: {}{sandbox_indicator}{sigstore_indicator}",
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

    // Pre-flight: check nft log support for audit2allow network observability.
    #[cfg(target_os = "linux")]
    if sandbox.is_some() {
        if let Err(msg) = gleisner_polis::NetworkFilter::check_log_available() {
            app.push_message(Role::System, format!("[warn] {msg}"));
        }
    }

    // Active query handle — holds the message receiver and abort handle.
    let mut query: Option<QueryHandle> = None;
    // Background cosign state — active while waiting for /cosigncode.
    let mut cosign: Option<CosignState> = None;

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
                                config.use_sigstore = use_sigstore;
                                config.sigstore_token = sigstore_token.map(String::from);
                                if let Some(bin) = claude_bin {
                                    bin.clone_into(&mut config.claude_bin);
                                }
                                if config.sandbox.is_some() {
                                    app.security.recording = true;
                                }
                                query = Some(spawn_query(config, 256));
                            }
                            UserAction::Command(TuiCommand::Cosign(ref path_arg)) => {
                                if cosign.is_some() {
                                    app.push_message(
                                        Role::System,
                                        "[error] Cosign already in progress. Use /cosigncode <code> to complete.",
                                    );
                                } else {
                                    cosign =
                                        start_cosign(&mut app, path_arg.as_deref(), project_dir);
                                }
                            }
                            UserAction::Command(TuiCommand::CosignCode(ref code)) => {
                                if let Some(ref cs) = cosign {
                                    info!("sending authorization code to cosign flow");
                                    if cs.code_tx.send(code.clone()).is_err() {
                                        app.push_message(
                                            Role::System,
                                            "[error] Cosign flow has ended. Try /cosign again.",
                                        );
                                        cosign = None;
                                    } else {
                                        app.push_message(
                                            Role::System,
                                            "Code submitted, signing...",
                                        );
                                    }
                                } else {
                                    app.push_message(
                                        Role::System,
                                        "[error] No cosign in progress. Start with /cosign first.",
                                    );
                                }
                            }
                            UserAction::Command(cmd) => {
                                handle_command(&mut app, cmd, project_dir);
                            }
                            UserAction::Interrupt => {
                                info!("user interrupt — aborting current query");
                                if let Some(handle) = query.take() {
                                    handle.task.abort();
                                }
                                app.session_state = SessionState::Idle;
                                app.streaming_buffer.clear();
                                app.security.recording = false;
                                app.push_message(Role::System, "[interrupted]");
                            }
                        }
                    }
                }
            }
        }

        // Drain any pending stream events (non-blocking)
        if let Some(ref mut handle) = query {
            while let Ok(msg) = handle.rx.try_recv() {
                match msg {
                    DriverMessage::Event(event) => {
                        debug!(event_type = ?std::mem::discriminant(&*event), "stream event");
                        if app.security.recording {
                            app.security.attest_events += 1;
                        }
                        app.handle_stream_event(*event);
                    }
                    DriverMessage::AttestationComplete { path, event_count } => {
                        info!(path = %path.display(), events = event_count, "attestation complete");
                        app.security.recording = false;
                        app.security.pending_cosign = true;
                        app.push_message(
                            Role::System,
                            format!(
                                "Attestation recorded ({event_count} events): {}",
                                path.display()
                            ),
                        );
                    }
                    DriverMessage::Exited(code) => {
                        info!(?code, "subprocess exited");
                        if app.session_state != SessionState::Idle {
                            app.session_state = SessionState::Idle;
                            app.security.recording = false;
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

        // Redraw immediately if we drained any events, so the UI
        // doesn't wait for the next poll timeout to show new content.
        if query.is_some() {
            terminal.draw(|frame| ui::draw(frame, &app))?;
        }

        // Poll for cosign results (non-blocking)
        if let Some(ref cs) = cosign {
            while let Ok(result) = cs.result_rx.try_recv() {
                match result {
                    CosignResult::AuthUrl(url) => {
                        app.push_message(
                            Role::System,
                            format!(
                                "Open this URL in a browser:\n  {url}\n\
                                 Authenticate, then type: /cosigncode <code>"
                            ),
                        );
                    }
                    CosignResult::Success {
                        bundle_path,
                        sigstore_path,
                    } => {
                        info!(
                            bundle = %bundle_path.display(),
                            sigstore = %sigstore_path.display(),
                            "cosign complete"
                        );
                        app.security.pending_cosign = false;
                        app.security.cosigned = true;
                        app.push_message(
                            Role::System,
                            format!(
                                "Cosigned with Sigstore:\n  Bundle:   {}\n  Sigstore: {}",
                                bundle_path.display(),
                                sigstore_path.display()
                            ),
                        );
                        cosign = None;
                        break;
                    }
                    CosignResult::Error(e) => {
                        app.push_message(Role::System, format!("[error] Cosign failed: {e}"));
                        cosign = None;
                        break;
                    }
                }
            }
        }

        // Clean up the handle if the session is done
        if app.session_state == SessionState::Idle && query.is_some() {
            if let Some(ref mut handle) = query {
                if handle.rx.try_recv().is_err() {
                    query = None;
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
        TuiCommand::Cosign(_) | TuiCommand::CosignCode(_) => {
            // Handled in the event loop — needs access to cosign state.
        }
        TuiCommand::Help => {
            let help = "\
Available commands:
  /sbom              Generate SBOM for current project
  /verify <path>     Verify an attestation bundle
  /inspect <path>    Inspect an attestation bundle
  /cosign            Cosign attestation with Sigstore (starts OIDC flow)
  /cosign <token>    Cosign with a pre-obtained OIDC JWT (eyJ...)
  /cosigncode <code> Submit auth code from browser for in-progress cosign
  /help              Show this help message";
            app.push_message(Role::System, help);
        }
    }
}

/// State for an in-progress background cosign operation.
///
/// The OIDC auth flow runs on a separate thread (with its own tokio runtime)
/// so `prompt_for_code()` can block without freezing the TUI event loop.
/// The TUI displays the auth URL and accepts the code via `/cosigncode`.
struct CosignState {
    /// Send the authorization code to the background OIDC flow.
    code_tx: std::sync::mpsc::Sender<String>,
    /// Receive the signing result from the background thread.
    result_rx: std::sync::mpsc::Receiver<CosignResult>,
}

/// Result of a background cosign operation.
#[allow(dead_code)] // Variants constructed behind #[cfg(feature = "keyless")]
enum CosignResult {
    /// The auth URL is ready — display it to the user.
    AuthUrl(String),
    /// Signing completed successfully.
    Success {
        bundle_path: PathBuf,
        sigstore_path: PathBuf,
    },
    /// Signing failed.
    Error(String),
}

/// Start a background cosign flow for the latest (or specified) attestation bundle.
///
/// Returns a `CosignState` if the flow was started, or `None` if there was an
/// error (already reported to the user via app messages).
#[allow(clippy::too_many_lines)]
fn start_cosign(
    app: &mut App,
    path_arg: Option<&str>,
    project_dir: &std::path::Path,
) -> Option<CosignState> {
    // Detect JWT token vs file path
    let (bundle_path_arg, oidc_token) = match path_arg {
        Some(arg) if arg.starts_with("eyJ") => (None, Some(arg.to_owned())),
        other => (other, None),
    };

    // Find the bundle to cosign
    let gleisner_dir = project_dir.join(".gleisner");
    let bundle_path = if let Some(p) = bundle_path_arg {
        PathBuf::from(p)
    } else {
        match gleisner_introdus::chain::find_latest_attestation(&gleisner_dir) {
            Ok(Some(link)) => link.path,
            Ok(None) => {
                app.push_message(
                    Role::System,
                    "[error] No attestation bundles found in .gleisner/",
                );
                return None;
            }
            Err(e) => {
                app.push_message(Role::System, format!("[error] {e}"));
                return None;
            }
        }
    };

    // Load and parse the existing bundle
    let bundle_json = match std::fs::read_to_string(&bundle_path) {
        Ok(json) => json,
        Err(e) => {
            app.push_message(Role::System, format!("[error] Cannot read bundle: {e}"));
            return None;
        }
    };
    let bundle: gleisner_introdus::bundle::AttestationBundle =
        match serde_json::from_str(&bundle_json) {
            Ok(b) => b,
            Err(e) => {
                app.push_message(Role::System, format!("[error] Invalid bundle JSON: {e}"));
                return None;
            }
        };

    #[cfg(feature = "keyless")]
    {
        if oidc_token.is_some() {
            app.push_message(
                Role::System,
                format!(
                    "Cosigning with pre-supplied token: {}",
                    bundle_path.display()
                ),
            );
        } else {
            app.push_message(
                Role::System,
                format!("Starting Sigstore OIDC flow for: {}", bundle_path.display()),
            );
        }

        let sigstore_path = bundle_path.with_extension("sigstore.json");

        // Channels: TUI ←→ background thread
        let (code_tx, code_rx) = std::sync::mpsc::channel::<String>();
        let (result_tx, result_rx) = std::sync::mpsc::channel::<CosignResult>();

        let payload = bundle.payload.clone();
        let bp = bundle_path.clone();
        let sp = sigstore_path.clone();

        // Spawn the OIDC + signing flow on a separate thread with its own runtime.
        // This lets prompt_for_code() block without freezing the TUI.
        std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("tokio runtime for cosign");

            rt.block_on(async move {
                // Custom callback that sends URL to TUI and waits for code from TUI
                let callback = TuiAuthCallback {
                    result_tx: result_tx.clone(),
                    code_rx,
                };

                let token = if let Some(jwt) = oidc_token {
                    // Pre-supplied token — skip interactive flow
                    match sigstore_oidc::parse_identity_token(&jwt) {
                        Ok(t) => t,
                        Err(e) => {
                            let _ =
                                result_tx.send(CosignResult::Error(format!("invalid token: {e}")));
                            return;
                        }
                    }
                } else {
                    // Interactive OIDC via custom callback
                    let client = sigstore_oidc::OAuthClient::sigstore();
                    match client
                        .auth_with_options(callback, sigstore_oidc::AuthOptions { force_oob: true })
                        .await
                    {
                        Ok(t) => t,
                        Err(e) => {
                            let _ = result_tx
                                .send(CosignResult::Error(format!("OIDC auth failed: {e}")));
                            return;
                        }
                    }
                };

                // Sign with the obtained token
                let context = sigstore_sign::SigningContext::production();
                let signer = context.signer(token);
                match signer.sign_raw_statement(payload.as_bytes()).await {
                    Ok(sigstore_bundle) => {
                        // Write native Sigstore bundle
                        if let Ok(json) = serde_json::to_string_pretty(&sigstore_bundle) {
                            let _ = std::fs::write(&sp, &json);
                        }

                        // Build our attestation bundle format
                        let bundle_json =
                            serde_json::to_string_pretty(&sigstore_bundle).unwrap_or_default();
                        let bundle_value: serde_json::Value =
                            serde_json::from_str(&bundle_json).unwrap_or_default();

                        let cert_chain = bundle_value
                            .pointer("/verificationMaterial/certificate/rawBytes")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_owned();

                        let rekor_log_id = bundle_value
                            .pointer("/verificationMaterial/tlogEntries/0/logIndex")
                            .and_then(|v| v.as_str().or_else(|| v.as_i64().map(|_| "")))
                            .unwrap_or("")
                            .to_owned();

                        let cosigned = gleisner_introdus::bundle::AttestationBundle {
                            payload,
                            signature: String::new(),
                            verification_material:
                                gleisner_introdus::bundle::VerificationMaterial::Sigstore {
                                    certificate_chain: cert_chain,
                                    rekor_log_id,
                                },
                        };

                        if let Ok(json) = serde_json::to_string_pretty(&cosigned) {
                            if let Err(e) = std::fs::write(&bp, &json) {
                                let _ = result_tx.send(CosignResult::Error(format!(
                                    "failed to write bundle: {e}"
                                )));
                                return;
                            }
                        }

                        let _ = result_tx.send(CosignResult::Success {
                            bundle_path: bp,
                            sigstore_path: sp,
                        });
                    }
                    Err(e) => {
                        let _ = result_tx
                            .send(CosignResult::Error(format!("Sigstore signing failed: {e}")));
                    }
                }
            });
        });

        return Some(CosignState { code_tx, result_rx });
    }

    #[cfg(not(feature = "keyless"))]
    {
        let _ = (&bundle_path, &bundle, &oidc_token);
        app.push_message(
            Role::System,
            "[error] Sigstore keyless not available. Rebuild with: cargo build --features keyless",
        );
        None
    }
}

/// Custom OIDC auth callback that integrates with the TUI event loop.
///
/// Instead of reading from stdin (which doesn't work in TUI mode),
/// sends the auth URL to the TUI for display and blocks on a channel
/// waiting for the user to submit the code via `/cosigncode`.
#[cfg(feature = "keyless")]
struct TuiAuthCallback {
    result_tx: std::sync::mpsc::Sender<CosignResult>,
    code_rx: std::sync::mpsc::Receiver<String>,
}

#[cfg(feature = "keyless")]
impl sigstore_oidc::templates::HtmlTemplates for TuiAuthCallback {
    fn success_html(&self) -> &str {
        "<html><body><h1>Authentication successful!</h1><p>You can close this tab.</p></body></html>"
    }

    fn error_html(&self, error: &str) -> String {
        format!("<html><body><h1>Error</h1><p>{error}</p></body></html>")
    }
}

#[cfg(feature = "keyless")]
impl sigstore_oidc::AuthCallback for TuiAuthCallback {
    fn auth_url_ready(&self, url: &str, _mode: sigstore_oidc::AuthMode) {
        let _ = self.result_tx.send(CosignResult::AuthUrl(url.to_owned()));
    }

    fn prompt_for_code(&self) -> std::io::Result<String> {
        // Block this thread until the TUI sends the code via /cosigncode.
        // This runs on a separate thread so it doesn't freeze the TUI.
        self.code_rx.recv().map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::Other,
                "cosign cancelled — no code received",
            )
        })
    }

    fn waiting_for_redirect(&self) {}

    fn auth_complete(&self) {}
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
