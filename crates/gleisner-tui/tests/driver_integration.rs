//! Integration tests for the Claude driver pipeline.
//!
//! Uses dynamically-generated scripts to simulate the Claude CLI subprocess,
//! outputting stream-json fixtures to stdout. Tests exercise the full pipeline:
//! `spawn_query` → `QueryHandle` → app state.
//!
//! This is the layer that was previously untestable without a real
//! Claude API key or TTY.

use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::time::Duration;

use gleisner_tui::app::{App, Role, SessionState};
use gleisner_tui::claude::{DriverMessage, QueryConfig};

/// Path to a fixture file.
fn fixture_path(name: &str) -> String {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    format!("{manifest_dir}/tests/fixtures/{name}")
}

/// A fake-claude script and its owning temp directory.
///
/// The `TempDir` keeps the script file alive. When dropped, the
/// directory and script are cleaned up. The file is fully closed
/// before any test uses it (avoiding ETXTBSY).
struct FakeClaude {
    _dir: tempfile::TempDir,
    path: PathBuf,
}

/// Create a temp script that outputs a fixture file to stdout.
///
/// Each test gets its own independent script — no shared env vars,
/// no unsafe, and tests can run in parallel. The file is written
/// and closed before returning, avoiding "Text file busy" (ETXTBSY).
fn make_fake_claude(fixture_name: &str, stderr_msg: Option<&str>, exit_code: i32) -> FakeClaude {
    let fixture = fixture_path(fixture_name);
    let stderr_line = stderr_msg.map_or_else(String::new, |msg| format!("echo '{msg}' >&2\n"));
    let script = format!("#!/bin/bash\n{stderr_line}cat '{fixture}'\nexit {exit_code}\n");

    let dir = tempfile::tempdir().expect("failed to create temp dir");
    let script_path = dir.path().join("fake-claude.sh");
    std::fs::write(&script_path, script).expect("failed to write temp script");
    std::fs::set_permissions(&script_path, std::fs::Permissions::from_mode(0o755))
        .expect("failed to chmod temp script");

    FakeClaude {
        _dir: dir,
        path: script_path,
    }
}

/// Build a `QueryConfig` pointing at a fake-claude temp script.
fn config_for_fake(fake: &FakeClaude) -> QueryConfig {
    QueryConfig {
        claude_bin: fake.path.display().to_string(),
        prompt: "test".into(),
        // Don't add flags that fake-claude doesn't understand
        skip_permissions: false,
        disallowed_tools: vec![],
        add_dirs: vec![],
        ..QueryConfig::default()
    }
}

/// Collect all `DriverMessage`s from a receiver until it closes or timeout.
async fn collect_messages(
    mut rx: tokio::sync::mpsc::Receiver<DriverMessage>,
    timeout: Duration,
) -> Vec<DriverMessage> {
    let mut messages = Vec::new();
    let deadline = tokio::time::Instant::now() + timeout;

    loop {
        tokio::select! {
            msg = rx.recv() => {
                match msg {
                    Some(m) => messages.push(m),
                    None => break,
                }
            }
            () = tokio::time::sleep_until(deadline) => {
                break;
            }
        }
    }

    messages
}

// ─── Driver unit tests ──────────────────────────────────────────
//
// These tests use `multi_thread` to avoid a race condition in the
// default `current_thread` runtime. `spawn_query` puts the subprocess
// reader on a `tokio::spawn` task — on a single-threaded runtime,
// that task can only progress when the test yields. Under heavy
// parallel test load (e.g. full workspace `cargo test`), the OS may
// delay the runtime thread enough that the sender drops before the
// receiver collects any events, causing spurious "got 0 events" failures.

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn driver_delivers_events_from_simple_fixture() {
    let script = make_fake_claude("simple_response.jsonl", None, 0);
    let config = config_for_fake(&script);
    let handle = gleisner_tui::claude::spawn_query(config, 256);
    let messages = collect_messages(handle.rx, Duration::from_secs(10)).await;

    let event_count = messages
        .iter()
        .filter(|m| matches!(m, DriverMessage::Event(_)))
        .count();
    let has_exited = messages
        .iter()
        .any(|m| matches!(m, DriverMessage::Exited(_)));

    assert!(
        event_count >= 3,
        "expected at least 3 events (system + assistant + result), got {event_count}; \
         total messages: {}, types: {:?}",
        messages.len(),
        messages
            .iter()
            .map(std::mem::discriminant)
            .collect::<Vec<_>>()
    );
    assert!(has_exited, "expected Exited message");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn driver_delivers_events_from_tool_use_fixture() {
    let script = make_fake_claude("tool_use_response.jsonl", None, 0);
    let config = config_for_fake(&script);
    let handle = gleisner_tui::claude::spawn_query(config, 256);
    let messages = collect_messages(handle.rx, Duration::from_secs(10)).await;

    let event_count = messages
        .iter()
        .filter(|m| matches!(m, DriverMessage::Event(_)))
        .count();

    assert!(
        event_count >= 5,
        "expected at least 5 events for tool use fixture, got {event_count}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn driver_captures_stderr() {
    let script = make_fake_claude("simple_response.jsonl", Some("test stderr output"), 0);
    let config = config_for_fake(&script);
    let handle = gleisner_tui::claude::spawn_query(config, 256);
    let messages = collect_messages(handle.rx, Duration::from_secs(10)).await;

    let stderr_messages: Vec<&str> = messages
        .iter()
        .filter_map(|m| {
            if let DriverMessage::Stderr(s) = m {
                Some(s.as_str())
            } else {
                None
            }
        })
        .collect();

    assert!(
        stderr_messages
            .iter()
            .any(|s| s.contains("test stderr output")),
        "expected stderr message, got: {stderr_messages:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn driver_reports_nonzero_exit_code() {
    let script = make_fake_claude("simple_response.jsonl", None, 42);
    let config = config_for_fake(&script);
    let handle = gleisner_tui::claude::spawn_query(config, 256);
    let messages = collect_messages(handle.rx, Duration::from_secs(10)).await;

    let exit_code = messages.iter().find_map(|m| {
        if let DriverMessage::Exited(code) = m {
            *code
        } else {
            None
        }
    });

    assert_eq!(exit_code, Some(42), "expected exit code 42");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn driver_reports_spawn_error_for_missing_binary() {
    let config = QueryConfig {
        claude_bin: "/nonexistent/binary".into(),
        prompt: "test".into(),
        skip_permissions: false,
        disallowed_tools: vec![],
        add_dirs: vec![],
        ..QueryConfig::default()
    };

    let handle = gleisner_tui::claude::spawn_query(config, 256);
    let messages = collect_messages(handle.rx, Duration::from_secs(5)).await;

    let has_error = messages
        .iter()
        .any(|m| matches!(m, DriverMessage::Error(_)));

    assert!(has_error, "expected Error message for missing binary");
}

// ─── Full pipeline tests ────────────────────────────────────────

/// Process `DriverMessage`s through the `App`, mirroring the `main.rs` event loop.
fn process_messages(app: &mut App, messages: &[DriverMessage]) {
    for msg in messages {
        match msg {
            DriverMessage::Event(event) => {
                app.handle_stream_event((**event).clone());
            }
            DriverMessage::Exited(code) => {
                if app.session_state != SessionState::Idle {
                    app.session_state = SessionState::Idle;
                    if let Some(code) = code {
                        if *code != 0 {
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
            DriverMessage::Stderr(line) => {
                app.push_message(Role::System, format!("[stderr] {line}"));
            }
            DriverMessage::AttestationComplete {
                path, event_count, ..
            } => {
                app.security.recording = false;
                app.push_message(
                    Role::System,
                    format!(
                        "Attestation recorded ({event_count} events): {}",
                        path.display()
                    ),
                );
            }
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn full_pipeline_simple_response() {
    let script = make_fake_claude("simple_response.jsonl", None, 0);
    let config = config_for_fake(&script);
    let handle = gleisner_tui::claude::spawn_query(config, 256);
    let messages = collect_messages(handle.rx, Duration::from_secs(10)).await;

    let mut app = App::new("test-profile");
    app.session_state = SessionState::Streaming;
    process_messages(&mut app, &messages);

    assert_eq!(app.session_state, SessionState::Idle);
    assert!(app.session_id.is_some(), "expected session_id");
    assert!(app.security.cost_usd > 0.0, "expected cost > 0");

    let has_assistant = app
        .messages
        .iter()
        .any(|m| matches!(m.role, Role::Assistant));
    assert!(has_assistant, "expected assistant message");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn full_pipeline_tool_use_response() {
    let script = make_fake_claude("tool_use_response.jsonl", None, 0);
    let config = config_for_fake(&script);
    let handle = gleisner_tui::claude::spawn_query(config, 256);
    let messages = collect_messages(handle.rx, Duration::from_secs(10)).await;

    let mut app = App::new("test-profile");
    app.session_state = SessionState::Streaming;
    process_messages(&mut app, &messages);

    assert_eq!(app.session_state, SessionState::Idle);
    assert!(app.security.tool_calls > 0, "expected tool calls");
    assert!(
        app.security.file_reads > 0,
        "expected file reads from Read tool"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn full_pipeline_with_stderr_shows_in_conversation() {
    let script = make_fake_claude(
        "simple_response.jsonl",
        Some("Claude Code starting up..."),
        0,
    );
    let config = config_for_fake(&script);
    let handle = gleisner_tui::claude::spawn_query(config, 256);
    let messages = collect_messages(handle.rx, Duration::from_secs(10)).await;

    let mut app = App::new("test-profile");
    app.session_state = SessionState::Streaming;
    process_messages(&mut app, &messages);

    let has_stderr = app
        .messages
        .iter()
        .any(|m| m.content.contains("Claude Code starting up"));
    assert!(
        has_stderr,
        "expected stderr message in conversation. Messages: {:?}",
        app.messages.iter().map(|m| &m.content).collect::<Vec<_>>()
    );
}

/// When the fixture contains a `result` event, it transitions the app to Idle.
/// A subsequent nonzero exit code is correctly ignored — the session already
/// completed via the result event. The "exited with code" message only appears
/// when the process exits without producing a result event (crash/timeout).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn full_pipeline_nonzero_exit_after_result_is_ignored() {
    let script = make_fake_claude("simple_response.jsonl", None, 1);
    let config = config_for_fake(&script);
    let handle = gleisner_tui::claude::spawn_query(config, 256);
    let messages = collect_messages(handle.rx, Duration::from_secs(10)).await;

    let mut app = App::new("test-profile");
    app.session_state = SessionState::Streaming;
    process_messages(&mut app, &messages);

    // App should be idle (from the result event, not the exit code)
    assert_eq!(app.session_state, SessionState::Idle);

    // The "exited with code" message should NOT appear because the
    // result event already transitioned to Idle
    let has_exit_msg = app
        .messages
        .iter()
        .any(|m| m.content.contains("exited with code"));
    assert!(
        !has_exit_msg,
        "exit code message should be suppressed when result event already handled session end"
    );

    // But the assistant response should still be there
    let has_assistant = app
        .messages
        .iter()
        .any(|m| matches!(m.role, Role::Assistant));
    assert!(
        has_assistant,
        "expected assistant message despite nonzero exit"
    );
}
