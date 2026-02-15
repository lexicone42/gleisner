//! PTY-based integration tests for the gleisner TUI.
//!
//! These tests spawn the TUI binary inside a pseudo-terminal, send
//! keystrokes through the PTY master, and read back the rendered
//! output via a `vt100::Parser` (virtual terminal emulator).
//!
//! This approach lets us test the actual terminal rendering —
//! what the user would see — without needing a real display.
//!
//! # Architecture
//!
//! ```text
//! Test code ──write──→ PTY master ──→ PTY slave ──→ gleisner-tui
//!     ↑                                                  │
//!     └──── vt100::Parser ←── read ←── PTY master ←──────┘
//! ```
//!
//! The `vt100::Parser` processes ANSI escape sequences and maintains
//! a virtual screen buffer. We can query individual cells, search
//! for text, and assert on the rendered layout.

use std::io::{Read, Write};
use std::thread;
use std::time::Duration;

use portable_pty::{CommandBuilder, PtySize, native_pty_system};

/// Terminal dimensions for tests.
const COLS: u16 = 100;
const ROWS: u16 = 30;

/// How long to wait for the TUI to render after input.
const RENDER_DELAY: Duration = Duration::from_millis(500);

/// Initial startup delay for the TUI binary to initialize.
const STARTUP_DELAY: Duration = Duration::from_millis(1000);

/// A test harness that drives a TUI application through a PTY.
struct TuiHarness {
    /// Virtual terminal emulator — parses ANSI and maintains screen buffer.
    parser: vt100::Parser,
    /// Write end of the PTY — sends keystrokes to the TUI.
    writer: Box<dyn Write + Send>,
    /// Read end of the PTY — receives rendered output.
    reader: Box<dyn Read + Send>,
    /// The child process handle.
    _child: Box<dyn portable_pty::Child + Send + Sync>,
}

impl TuiHarness {
    /// Spawn the gleisner-tui binary in a PTY and wait for it to start.
    fn spawn() -> Self {
        let pty_system = native_pty_system();
        let pair = pty_system
            .openpty(PtySize {
                rows: ROWS,
                cols: COLS,
                pixel_width: 0,
                pixel_height: 0,
            })
            .expect("failed to open PTY pair");

        // Build command for the gleisner-tui binary.
        // cargo test builds binaries in the target directory.
        let mut cmd = CommandBuilder::new(env!("CARGO_BIN_EXE_gleisner-tui"));
        // Ensure the TUI gets a proper TERM variable
        cmd.env("TERM", "xterm-256color");

        let child = pair
            .slave
            .spawn_command(cmd)
            .expect("failed to spawn gleisner-tui in PTY");

        let reader = pair
            .master
            .try_clone_reader()
            .expect("failed to clone PTY reader");

        let writer = pair
            .master
            .take_writer()
            .expect("failed to take PTY writer");

        let parser = vt100::Parser::new(ROWS, COLS, 0);

        let mut harness = Self {
            parser,
            writer,
            reader,
            _child: child,
        };

        // Wait for initial render
        thread::sleep(STARTUP_DELAY);
        harness.read_output();

        harness
    }

    /// Read any available output from the PTY and feed it to the
    /// virtual terminal parser.
    fn read_output(&mut self) {
        let mut buf = [0u8; 8192];
        // Non-blocking read: portable-pty readers are blocking by default,
        // so we use a short timeout approach with a helper thread.
        let reader = &mut self.reader;

        // Try reading in a loop with small reads
        loop {
            // We can't set the reader to non-blocking easily with portable-pty,
            // so we do a timed read approach: try reading with a small buffer
            // and break when we've consumed everything available.
            match reader.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    self.parser.process(&buf[..n]);
                    // If we got a full buffer, there might be more
                    if n < buf.len() {
                        break;
                    }
                }
            }
        }
    }

    /// Send a string of characters to the TUI as if typed.
    fn type_str(&mut self, s: &str) {
        self.writer
            .write_all(s.as_bytes())
            .expect("failed to write to PTY");
        self.writer.flush().expect("failed to flush PTY writer");
        thread::sleep(RENDER_DELAY);
        self.read_output();
    }

    /// Send a single key (including control sequences).
    fn send_key(&mut self, bytes: &[u8]) {
        self.writer
            .write_all(bytes)
            .expect("failed to write key to PTY");
        self.writer.flush().expect("failed to flush PTY writer");
        thread::sleep(RENDER_DELAY);
        self.read_output();
    }

    /// Send Enter key (submits input in insert mode).
    fn press_enter(&mut self) {
        self.send_key(b"\r");
    }

    /// Send Alt+Enter.
    #[allow(dead_code)]
    fn press_alt_enter(&mut self) {
        // ESC followed by CR is the standard terminal encoding for Alt+Enter.
        self.send_key(b"\x1b\r");
    }

    /// Send Escape key.
    fn press_escape(&mut self) {
        self.send_key(b"\x1b");
    }

    /// Get the full screen contents as a string (rows joined by newlines).
    fn screen_text(&self) -> String {
        self.parser.screen().contents()
    }

    /// Get a specific row's text content (0-indexed).
    #[allow(dead_code)]
    fn row_text(&self, row: u16) -> String {
        self.parser.screen().contents_between(row, 0, row, COLS - 1)
    }

    /// Check whether a string appears anywhere on screen.
    fn screen_contains(&self, needle: &str) -> bool {
        self.screen_text().contains(needle)
    }

    /// Dump the screen contents to a string for debugging.
    /// Includes a border so it's easy to see the screen boundaries.
    fn dump_screen(&self) -> String {
        let divider = "─".repeat(COLS as usize);
        let text = self.screen_text();
        format!(
            "┌{divider}┐\n{text}\n└{divider}┘\n\
             (screen: {COLS}x{ROWS})"
        )
    }

    /// Spawn gleisner-tui with a custom `--claude-bin` binary.
    ///
    /// Used with fake-claude scripts to test the full submit→response flow
    /// without needing a real Claude API key.
    fn spawn_with_claude_bin(claude_bin: &str) -> Self {
        let pty_system = native_pty_system();
        let pair = pty_system
            .openpty(PtySize {
                rows: ROWS,
                cols: COLS,
                pixel_width: 0,
                pixel_height: 0,
            })
            .expect("failed to open PTY pair");

        let mut cmd = CommandBuilder::new(env!("CARGO_BIN_EXE_gleisner-tui"));
        cmd.env("TERM", "xterm-256color");
        cmd.args(["--claude-bin", claude_bin]);

        let child = pair
            .slave
            .spawn_command(cmd)
            .expect("failed to spawn gleisner-tui in PTY");

        let reader = pair
            .master
            .try_clone_reader()
            .expect("failed to clone PTY reader");

        let writer = pair
            .master
            .take_writer()
            .expect("failed to take PTY writer");

        let parser = vt100::Parser::new(ROWS, COLS, 0);

        let mut harness = Self {
            parser,
            writer,
            reader,
            _child: child,
        };

        thread::sleep(STARTUP_DELAY);
        harness.read_output();
        harness
    }
}

/// Create a fake-claude shell script that outputs a fixture file.
///
/// Returns a (`TempDir`, `script_path`) — the `TempDir` keeps the script
/// alive for the duration of the test.
fn make_fake_claude_script(fixture_name: &str) -> (tempfile::TempDir, String) {
    use std::os::unix::fs::PermissionsExt;

    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let fixture_path = format!("{manifest_dir}/tests/fixtures/{fixture_name}");

    let dir = tempfile::tempdir().expect("failed to create temp dir");
    let script_path = dir.path().join("fake-claude.sh");

    let script = format!("#!/bin/bash\ncat '{fixture_path}'\n");

    std::fs::write(&script_path, script).expect("failed to write fake-claude script");
    std::fs::set_permissions(&script_path, std::fs::Permissions::from_mode(0o755))
        .expect("failed to chmod fake-claude script");

    let path_str = script_path.display().to_string();
    (dir, path_str)
}

// ─── Tests ───────────────────────────────────────────────────────

#[test]
fn tui_starts_and_shows_title() {
    let harness = TuiHarness::spawn();

    eprintln!("=== Screen after startup ===\n{}", harness.dump_screen());

    // The title "gleisner" should appear in the top border
    assert!(
        harness.screen_contains("gleisner"),
        "expected 'gleisner' title on screen"
    );
}

#[test]
fn tui_shows_welcome_message() {
    let harness = TuiHarness::spawn();

    // The welcome system message should show the polis (profile) name
    assert!(
        harness.screen_contains("polis: konishi"),
        "expected welcome message on screen.\n{}",
        harness.dump_screen()
    );
}

#[test]
fn tui_shows_security_dashboard() {
    let harness = TuiHarness::spawn();

    // The security dashboard should show the profile name
    assert!(
        harness.screen_contains("konishi"),
        "expected profile name 'konishi' in security dashboard.\n{}",
        harness.dump_screen()
    );

    // Should show the "Telemetry" title
    assert!(
        harness.screen_contains("Telemetry"),
        "expected 'Telemetry' dashboard title.\n{}",
        harness.dump_screen()
    );
}

#[test]
fn tui_shows_normal_mode_by_default() {
    let harness = TuiHarness::spawn();

    assert!(
        harness.screen_contains("NORMAL"),
        "expected NORMAL mode indicator.\n{}",
        harness.dump_screen()
    );
}

#[test]
fn tui_switches_to_insert_mode() {
    let mut harness = TuiHarness::spawn();

    // Press 'i' to enter insert mode
    harness.type_str("i");

    assert!(
        harness.screen_contains("INSERT"),
        "expected INSERT mode after pressing 'i'.\n{}",
        harness.dump_screen()
    );
}

#[test]
fn tui_accepts_input_and_submits() {
    let mut harness = TuiHarness::spawn();

    // Enter insert mode
    harness.type_str("i");

    // Type a message
    harness.type_str("hello world");

    // The input should appear on screen
    assert!(
        harness.screen_contains("hello world"),
        "expected typed text on screen.\n{}",
        harness.dump_screen()
    );

    // Submit with Alt+Enter
    harness.press_enter();

    // Give extra time for the submit + stream error to render
    thread::sleep(Duration::from_millis(1000));
    harness.read_output();

    eprintln!("=== Screen after submit ===\n{}", harness.dump_screen());

    // Should see the user message in conversation
    assert!(
        harness.screen_contains("you"),
        "expected user badge on screen.\n{}",
        harness.dump_screen()
    );
}

#[test]
fn tui_returns_to_normal_mode_on_escape() {
    let mut harness = TuiHarness::spawn();

    // Enter insert mode
    harness.type_str("i");
    assert!(harness.screen_contains("INSERT"));

    // Press Escape
    harness.press_escape();

    // Give extra time for mode switch rendering
    thread::sleep(RENDER_DELAY);
    harness.read_output();

    assert!(
        harness.screen_contains("NORMAL"),
        "expected NORMAL mode after Escape.\n{}",
        harness.dump_screen()
    );
}

#[test]
fn tui_quits_on_q_in_normal_mode() {
    let mut harness = TuiHarness::spawn();

    // Press 'q' in normal mode — the process should exit
    harness.type_str("q");

    // Give the process time to exit
    thread::sleep(Duration::from_millis(500));

    // The screen should either be empty (process exited and terminal restored)
    // or we should no longer see the TUI elements
    // At minimum, we verify the harness doesn't panic
    eprintln!("=== Screen after quit ===\n{}", harness.dump_screen());
}

// ─── Fake-claude integration tests ──────────────────────────────

/// Full end-to-end test: user submits a prompt, fake-claude responds
/// with a fixture, and the assistant's response appears on screen.
#[test]
fn tui_shows_assistant_response_from_fake_claude() {
    let (_dir, script_path) = make_fake_claude_script("simple_response.jsonl");
    let mut harness = TuiHarness::spawn_with_claude_bin(&script_path);

    eprintln!(
        "=== Screen after startup (fake-claude) ===\n{}",
        harness.dump_screen()
    );

    // Enter insert mode
    harness.type_str("i");
    assert!(
        harness.screen_contains("INSERT"),
        "expected INSERT mode.\n{}",
        harness.dump_screen()
    );

    // Type a prompt and submit
    harness.type_str("what is 2+2");
    harness.press_enter();

    // Wait for the fake-claude output to be processed
    thread::sleep(Duration::from_millis(2000));
    harness.read_output();

    eprintln!(
        "=== Screen after submit (fake-claude) ===\n{}",
        harness.dump_screen()
    );

    // Should see the user message
    assert!(
        harness.screen_contains("you"),
        "expected user badge.\n{}",
        harness.dump_screen()
    );

    // The simple_response fixture has an assistant message with "4"
    // It should appear somewhere on screen
    let has_assistant_content = harness.screen_contains("claude") || harness.screen_contains("4");
    assert!(
        has_assistant_content,
        "expected assistant response on screen.\n{}",
        harness.dump_screen()
    );
}

/// Verify that stderr from fake-claude appears in the TUI conversation.
#[test]
fn tui_shows_stderr_from_subprocess() {
    use std::os::unix::fs::PermissionsExt;

    // Create a fake-claude that writes to stderr
    let dir = tempfile::tempdir().expect("temp dir");
    let script_path = dir.path().join("fake-claude.sh");
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let fixture = format!("{manifest_dir}/tests/fixtures/simple_response.jsonl");
    let script =
        format!("#!/bin/bash\necho 'STARTUP_ERROR: something went wrong' >&2\ncat '{fixture}'\n");
    std::fs::write(&script_path, script).expect("write");
    std::fs::set_permissions(&script_path, std::fs::Permissions::from_mode(0o755)).expect("chmod");

    let mut harness = TuiHarness::spawn_with_claude_bin(&script_path.display().to_string());

    // Submit a prompt
    harness.type_str("i");
    harness.type_str("test");
    harness.press_enter();

    // Wait for output
    thread::sleep(Duration::from_millis(2000));
    harness.read_output();

    eprintln!(
        "=== Screen after submit (stderr test) ===\n{}",
        harness.dump_screen()
    );

    // Should see the stderr message in the conversation
    assert!(
        harness.screen_contains("STARTUP_ERROR") || harness.screen_contains("[stderr]"),
        "expected stderr message on screen.\n{}",
        harness.dump_screen()
    );
}
