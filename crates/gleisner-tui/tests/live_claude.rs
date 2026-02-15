//! Live integration tests that send real prompts through the TUI
//! to a real Claude subprocess and verify the response appears.
//!
//! These tests are expensive (API calls) and slow, so they're
//! gated behind `#[ignore]` by default. Run with:
//!
//! ```sh
//! cargo test -p gleisner-tui --test live_claude -- --ignored
//! ```
//!
//! The TUI spawns `claude -p --output-format stream-json` as a
//! subprocess. We observe the rendered output via the PTY harness
//! to verify the full pipeline: TUI → subprocess → stream-json
//! → parser → app state → UI render → terminal output.

use std::io::{Read, Write};
use std::thread;
use std::time::Duration;

use portable_pty::{CommandBuilder, PtySize, native_pty_system};

const COLS: u16 = 120;
const ROWS: u16 = 40;
const STARTUP_DELAY: Duration = Duration::from_millis(1500);
const RENDER_DELAY: Duration = Duration::from_millis(300);

struct TuiHarness {
    parser: vt100::Parser,
    writer: Box<dyn Write + Send>,
    reader: Box<dyn Read + Send>,
    _child: Box<dyn portable_pty::Child + Send + Sync>,
}

impl TuiHarness {
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

        let mut cmd = CommandBuilder::new(env!("CARGO_BIN_EXE_gleisner-tui"));
        cmd.env("TERM", "xterm-256color");
        // Ensure nested Claude doesn't think it's inside another Claude
        cmd.env("CLAUDECODE", "");

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

    fn read_output(&mut self) {
        let mut buf = [0u8; 8192];
        loop {
            match self.reader.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    self.parser.process(&buf[..n]);
                    if n < buf.len() {
                        break;
                    }
                }
            }
        }
    }

    fn type_str(&mut self, s: &str) {
        self.writer.write_all(s.as_bytes()).unwrap();
        self.writer.flush().unwrap();
        thread::sleep(RENDER_DELAY);
        self.read_output();
    }

    fn send_key(&mut self, bytes: &[u8]) {
        self.writer.write_all(bytes).unwrap();
        self.writer.flush().unwrap();
        thread::sleep(RENDER_DELAY);
        self.read_output();
    }

    fn press_enter(&mut self) {
        self.send_key(b"\r");
    }

    fn screen_text(&self) -> String {
        self.parser.screen().contents()
    }

    fn screen_contains(&self, needle: &str) -> bool {
        self.screen_text().contains(needle)
    }

    fn dump_screen(&self) -> String {
        let divider = "─".repeat(COLS as usize);
        let text = self.screen_text();
        format!("┌{divider}┐\n{text}\n└{divider}┘")
    }

    /// Wait up to `timeout` for a string to appear on screen.
    fn wait_for_text(&mut self, needle: &str, timeout: Duration) -> bool {
        let start = std::time::Instant::now();
        while start.elapsed() < timeout {
            if self.screen_contains(needle) {
                return true;
            }
            thread::sleep(Duration::from_millis(200));
            self.read_output();
        }
        false
    }
}

/// Send a simple prompt to Claude through the TUI and verify we get a response.
///
/// This tests the full pipeline: keyboard → input → submit → spawn claude
/// → stream-json → parser → app state → UI render.
#[test]
#[ignore = "requires claude binary and API access, costs money"]
fn live_simple_prompt_gets_response() {
    let mut harness = TuiHarness::spawn();

    // Verify TUI started
    assert!(
        harness.screen_contains("gleisner"),
        "TUI didn't start properly.\n{}",
        harness.dump_screen()
    );

    // Enter insert mode and type a simple prompt
    harness.type_str("i");
    harness.type_str("What is 2+2? Reply with just the number.");
    harness.press_enter();

    eprintln!("=== Submitted prompt, waiting for response ===");
    eprintln!("{}", harness.dump_screen());

    // Should see the user message
    assert!(
        harness.wait_for_text("you>", Duration::from_secs(5)),
        "didn't see user message.\n{}",
        harness.dump_screen()
    );

    // Should see STREAMING indicator (may be brief)
    // Don't assert on this as it might disappear before we check

    // Wait for Claude's response (up to 60 seconds)
    let got_response = harness.wait_for_text("claude>", Duration::from_secs(60));

    eprintln!("=== Final screen ===");
    eprintln!("{}", harness.dump_screen());

    assert!(
        got_response,
        "didn't see Claude's response within 60 seconds.\n{}",
        harness.dump_screen()
    );

    // The answer should contain "4" somewhere
    assert!(
        harness.screen_contains("4"),
        "expected '4' in response.\n{}",
        harness.dump_screen()
    );

    // Security dashboard should show activity
    assert!(
        harness.screen_contains("Turns:"),
        "expected Turns counter in dashboard.\n{}",
        harness.dump_screen()
    );

    // Cost should be displayed (non-zero after API call)
    assert!(
        harness.screen_contains("$0."),
        "expected cost to be displayed.\n{}",
        harness.dump_screen()
    );
}

/// Send a prompt that triggers tool use and verify tool call appears in the dashboard.
#[test]
#[ignore = "requires claude binary and API access, costs money"]
fn live_tool_use_updates_dashboard() {
    let mut harness = TuiHarness::spawn();

    harness.type_str("i");
    harness.type_str("Read the file crates/gleisner-tui/src/lib.rs");
    harness.press_enter();

    // Wait for tool call to appear
    let saw_tool = harness.wait_for_text("[Read]", Duration::from_secs(60));

    eprintln!("=== After tool use ===");
    eprintln!("{}", harness.dump_screen());

    assert!(
        saw_tool,
        "didn't see [Read] tool call indicator.\n{}",
        harness.dump_screen()
    );

    // File reads counter should increment
    let saw_reads = harness.wait_for_text("File reads:", Duration::from_secs(5));
    assert!(
        saw_reads,
        "didn't see File reads counter.\n{}",
        harness.dump_screen()
    );

    // Wait for response to complete
    harness.wait_for_text("claude>", Duration::from_secs(30));

    eprintln!("=== Final screen ===");
    eprintln!("{}", harness.dump_screen());
}

/// Verify that the STREAMING indicator appears and disappears.
#[test]
#[ignore = "requires claude binary and API access, costs money"]
fn live_streaming_indicator_lifecycle() {
    let mut harness = TuiHarness::spawn();

    // Confirm we start without STREAMING
    assert!(
        !harness.screen_contains("STREAMING"),
        "STREAMING indicator should not be visible before submit"
    );

    harness.type_str("i");
    harness.type_str("Say hello");
    harness.press_enter();

    // STREAMING should appear briefly
    // (it may disappear fast for simple prompts, so don't require it)

    // Wait for response to complete
    let completed = harness.wait_for_text("claude>", Duration::from_secs(60));
    assert!(completed, "response didn't arrive");

    // After response, STREAMING should be gone
    // Give a moment for the state to settle
    thread::sleep(Duration::from_secs(2));
    harness.read_output();

    assert!(
        !harness.screen_contains("STREAMING"),
        "STREAMING indicator should disappear after response completes.\n{}",
        harness.dump_screen()
    );
}
