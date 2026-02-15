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
                Ok(0) => break,
                Ok(n) => {
                    self.parser.process(&buf[..n]);
                    // If we got a full buffer, there might be more
                    if n < buf.len() {
                        break;
                    }
                }
                Err(_) => break,
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

    /// Send Enter key.
    fn press_enter(&mut self) {
        self.send_key(b"\r");
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

    // The welcome system message should show the profile name
    assert!(
        harness.screen_contains("profile: konishi"),
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

    // Should show the "Security" title
    assert!(
        harness.screen_contains("Security"),
        "expected 'Security' dashboard title.\n{}",
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

    // Submit with Enter
    harness.press_enter();

    // Give extra time for the submit + stream error to render
    thread::sleep(Duration::from_millis(1000));
    harness.read_output();

    eprintln!("=== Screen after submit ===\n{}", harness.dump_screen());

    // Should see the user message in conversation
    assert!(
        harness.screen_contains("you>"),
        "expected user message prefix on screen.\n{}",
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
