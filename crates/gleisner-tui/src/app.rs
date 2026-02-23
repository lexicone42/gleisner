//! Application state for the gleisner TUI.
//!
//! Holds the conversation history, security dashboard state, and
//! manages transitions between input modes. Processes stream events
//! from the Claude CLI subprocess.

use std::collections::VecDeque;

use crate::stream::{ContentBlock, StreamEvent, UserContentBlock};

/// A single entry in the conversation.
#[derive(Debug, Clone)]
pub struct Message {
    /// Who sent this message.
    pub role: Role,
    /// The text content.
    pub content: String,
}

/// The sender of a message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// The human user.
    User,
    /// The AI assistant.
    Assistant,
    /// A tool call or result.
    Tool,
    /// System/status information.
    System,
}

/// Security dashboard counters, fed by the stream events.
#[allow(clippy::struct_excessive_bools)] // dashboard counters, not configuration flags
#[derive(Debug, Default, Clone)]
pub struct SecurityState {
    /// Number of file reads observed (Read tool calls).
    pub file_reads: u64,
    /// Number of file writes observed (Write/Edit tool calls).
    pub file_writes: u64,
    /// Number of tool calls executed.
    pub tool_calls: u64,
    /// Current sandbox profile name.
    pub profile: String,
    /// Whether attestation recording is active.
    pub recording: bool,
    /// Total cost in USD for this session.
    pub cost_usd: f64,
    /// Number of agent turns.
    pub turns: u32,
    /// Whether the exo-self plugin is active (detected from hooks).
    pub exo_self_active: bool,
    /// Number of active plugins detected from the init event.
    pub plugin_count: usize,
    /// Permission mode from the init event.
    pub permission_mode: String,
    /// Total tokens used (input + cache + output) across all prompts.
    pub tokens_used: u64,
    /// Context window size from the model.
    pub context_window: u64,
    /// An attestation was recorded but not yet cosigned with Sigstore.
    pub pending_cosign: bool,
    /// The current session's attestation has been cosigned with Sigstore.
    pub cosigned: bool,
    /// Whether the sandbox (bwrap) is active for this session.
    pub sandbox_active: bool,
    /// Number of attestation events recorded during this session.
    pub attest_events: u64,
}

/// The input mode determines how keystrokes are interpreted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputMode {
    /// Normal mode — navigation and commands.
    Normal,
    /// Insert mode — typing into the input field.
    Insert,
}

/// A TUI-local command (not sent to Claude).
#[derive(Debug, Clone)]
pub enum TuiCommand {
    /// Generate SBOM for the current project.
    Sbom,
    /// Verify an attestation bundle.
    Verify(String),
    /// Inspect an attestation bundle.
    Inspect(String),
    /// Cosign the latest attestation with Sigstore keyless signing.
    Cosign(Option<String>),
    /// Submit the OIDC authorization code for an in-progress cosign flow.
    CosignCode(String),
    /// Learn from the last session's audit log and generate a widened profile.
    Learn,
    /// Show available TUI commands.
    Help,
}

/// What the user submitted — either a Claude prompt or a local command.
#[derive(Debug, Clone)]
pub enum UserAction {
    /// Send this prompt to Claude.
    Prompt(String),
    /// Execute a local TUI command.
    Command(TuiCommand),
    /// Interrupt the current streaming session (Ctrl-C / Esc while streaming).
    Interrupt,
}

/// Whether the app is idle or waiting for Claude.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    /// Ready for user input.
    Idle,
    /// Waiting for Claude to respond.
    Streaming,
}

/// Top-level application state.
#[derive(Debug)]
pub struct App {
    /// Conversation history (bounded).
    pub messages: VecDeque<Message>,
    /// The current user input buffer.
    pub input: String,
    /// Current input mode.
    pub input_mode: InputMode,
    /// Security dashboard state.
    pub security: SecurityState,
    /// Whether the app should exit.
    pub should_quit: bool,
    /// Scroll offset for the conversation view.
    pub scroll_offset: u16,
    /// Current session state (idle vs streaming).
    pub session_state: SessionState,
    /// Session ID for multi-turn continuation.
    pub session_id: Option<String>,
    /// Model name from the init event.
    pub model: Option<String>,
    /// Claude Code version from the init event.
    pub claude_version: Option<String>,
    /// Accumulates text from streaming deltas for live display.
    /// Cleared when the full assistant event arrives.
    pub streaming_buffer: String,
    /// Path to the audit log from the most recent sandboxed session.
    pub last_audit_log: Option<std::path::PathBuf>,
}

impl App {
    /// Maximum messages to keep in history.
    const MAX_MESSAGES: usize = 1000;

    /// Create a new app with default state.
    pub fn new(profile: &str) -> Self {
        Self {
            messages: VecDeque::with_capacity(Self::MAX_MESSAGES),
            input: String::new(),
            input_mode: InputMode::Normal,
            security: SecurityState {
                profile: profile.to_owned(),
                ..SecurityState::default()
            },
            should_quit: false,
            scroll_offset: 0,
            session_state: SessionState::Idle,
            session_id: None,
            model: None,
            claude_version: None,
            streaming_buffer: String::new(),
            last_audit_log: None,
        }
    }

    /// Add a message to the conversation.
    pub fn push_message(&mut self, role: Role, content: impl Into<String>) {
        if self.messages.len() >= Self::MAX_MESSAGES {
            self.messages.pop_front();
        }
        self.messages.push_back(Message {
            role,
            content: content.into(),
        });
        // Auto-scroll to bottom when new messages arrive
        self.scroll_offset = 0;
    }

    /// Submit the current input as a user message or TUI command.
    ///
    /// Returns `None` if input was empty or already streaming.
    /// Slash commands (`/sbom`, `/verify`, `/inspect`, `/help`) are
    /// parsed locally and returned as `UserAction::Command`.
    pub fn submit_input(&mut self) -> Option<UserAction> {
        if self.session_state == SessionState::Streaming {
            return None;
        }
        let text = self.input.trim().to_owned();
        if text.is_empty() {
            return None;
        }
        self.input.clear();

        // Parse slash commands
        if let Some(rest) = text.strip_prefix('/') {
            let mut parts = rest.splitn(2, ' ');
            let cmd = parts.next().unwrap_or("");
            let arg = parts.next().unwrap_or("").to_owned();

            let tui_cmd = match cmd {
                "sbom" => Some(TuiCommand::Sbom),
                "verify" if !arg.is_empty() => Some(TuiCommand::Verify(arg)),
                "inspect" if !arg.is_empty() => Some(TuiCommand::Inspect(arg)),
                "verify" | "inspect" => {
                    self.push_message(
                        Role::System,
                        format!("/{cmd} requires a file path argument"),
                    );
                    return None;
                }
                "cosign" if arg.is_empty() => Some(TuiCommand::Cosign(None)),
                "cosign" => Some(TuiCommand::Cosign(Some(arg))),
                "cosigncode" if !arg.is_empty() => Some(TuiCommand::CosignCode(arg)),
                "cosigncode" => {
                    self.push_message(
                        Role::System,
                        "/cosigncode requires the authorization code from the browser",
                    );
                    return None;
                }
                "learn" => Some(TuiCommand::Learn),
                "help" => Some(TuiCommand::Help),
                _ => None,
            };

            if let Some(cmd) = tui_cmd {
                self.push_message(Role::User, &text);
                return Some(UserAction::Command(cmd));
            }
            // Unknown slash command — treat as normal prompt to Claude
        }

        self.push_message(Role::User, &text);
        self.session_state = SessionState::Streaming;
        Some(UserAction::Prompt(text))
    }

    /// Process a stream event from the Claude subprocess.
    pub fn handle_stream_event(&mut self, event: StreamEvent) {
        match event {
            StreamEvent::System(sys) => self.handle_system_event(sys),
            StreamEvent::Assistant(ref asst) => self.handle_assistant_event(asst),
            StreamEvent::User(ref user) => self.handle_user_event(user),
            StreamEvent::Result(result) => self.handle_result_event(result),
            StreamEvent::StreamDelta(ref delta) => self.handle_stream_delta(delta),
        }
    }

    /// Handle system events (init, hooks).
    fn handle_system_event(&mut self, sys: crate::stream::SystemEvent) {
        match sys.subtype.as_str() {
            "init" => {
                if let Some(sid) = sys.session_id {
                    self.session_id = Some(sid);
                }
                if let Some(model) = sys.model {
                    self.model = Some(model);
                }
                if let Some(ver) = sys.claude_code_version {
                    self.claude_version = Some(ver);
                }
                if let Some(ref plugins) = sys.plugins {
                    self.security.plugin_count = plugins.len();
                    self.security.exo_self_active =
                        plugins.iter().any(|p| p.name.contains("exo-self"));
                }
                if let Some(perm) = sys.permission_mode {
                    self.security.permission_mode = perm;
                }
            }
            // Detect exo-self from hook events too (fires before init)
            "hook_started" => {
                if let Some(ref name) = sys.hook_name {
                    if name.contains("exo-self") || name.contains("exo_self") {
                        self.security.exo_self_active = true;
                    }
                }
            }
            _ => {}
        }
    }

    /// Handle streaming delta events for live text display.
    ///
    /// Extracts text from `content_block_delta` events and appends to the
    /// streaming buffer. The buffer is rendered as a live message in the UI
    /// and cleared when the full `assistant` event arrives.
    fn handle_stream_delta(&mut self, delta: &crate::stream::StreamDeltaEvent) {
        if let Some(ref event) = delta.event {
            // content_block_delta with text_delta contains partial text
            if event.get("type").and_then(|t| t.as_str()) == Some("content_block_delta") {
                if let Some(text) = event
                    .get("delta")
                    .and_then(|d| d.get("text"))
                    .and_then(|t| t.as_str())
                {
                    self.streaming_buffer.push_str(text);
                }
            }
        }
    }

    /// Handle assistant messages (text output, tool calls).
    fn handle_assistant_event(&mut self, asst: &crate::stream::AssistantEvent) {
        // Clear streaming buffer — the full message supersedes the live preview.
        self.streaming_buffer.clear();
        for block in &asst.message.content {
            match block {
                ContentBlock::Text { text } => {
                    self.push_message(Role::Assistant, text);
                }
                ContentBlock::ToolUse { name, input, .. } => {
                    self.security.tool_calls += 1;
                    self.update_tool_counters(name);

                    // Show a compact summary with tool icon
                    let icon = tool_icon(name);
                    let summary = format_tool_call(name, input);
                    self.push_message(Role::Tool, format!("{icon} {summary}"));
                }
                ContentBlock::Thinking { thinking } => {
                    if !thinking.is_empty() {
                        let preview = if thinking.len() > 100 {
                            format!("{}...", &thinking[..100])
                        } else {
                            thinking.clone()
                        };
                        self.push_message(Role::System, format!("[thinking] {preview}"));
                    }
                }
            }
        }
    }

    /// Handle user messages (tool results).
    fn handle_user_event(&mut self, user: &crate::stream::UserEvent) {
        for block in &user.message.content {
            match block {
                UserContentBlock::ToolResult {
                    content, is_error, ..
                } => {
                    let preview = format_tool_result(content, *is_error);
                    self.push_message(Role::Tool, preview);
                }
            }
        }
    }

    /// Handle result events (session complete).
    fn handle_result_event(&mut self, result: crate::stream::ResultEvent) {
        self.streaming_buffer.clear();
        self.session_state = SessionState::Idle;

        if let Some(sid) = result.session_id {
            self.session_id = Some(sid);
        }
        if let Some(cost) = result.total_cost_usd {
            self.security.cost_usd += cost;
        }
        if let Some(turns) = result.num_turns {
            self.security.turns += turns;
        }
        // Extract context usage from modelUsage.
        //
        // input_tokens is cumulative across all agentic turns in this query.
        // cache_read/cache_creation are subsets of input_tokens (not additive).
        // output_tokens are generated tokens, not context window usage.
        //
        // To estimate current context fullness, divide by turn count.
        if let Some(ref usage_map) = result.model_usage {
            let mut ctx_window = 0u64;
            let mut primary_input = 0u64;
            for usage in usage_map.values() {
                if usage.context_window > ctx_window {
                    ctx_window = usage.context_window;
                    primary_input = usage.input_tokens;
                }
            }
            let turns = u64::from(result.num_turns.unwrap_or(1).max(1));
            self.security.tokens_used = primary_input / turns;
            self.security.context_window = ctx_window;
        }

        if result.is_error {
            self.push_message(
                Role::System,
                format!("[error] Session ended with error: {}", result.subtype),
            );
        }
    }

    /// Update security counters based on tool name.
    fn update_tool_counters(&mut self, tool_name: &str) {
        match tool_name {
            "Read" => self.security.file_reads += 1,
            "Write" | "Edit" => self.security.file_writes += 1,
            _ => {
                // MCP tools: serena's read_file, replace_content, etc.
                if tool_name.contains("read_file") || tool_name.contains("get_symbols") {
                    self.security.file_reads += 1;
                } else if tool_name.contains("replace_content")
                    || tool_name.contains("replace_symbol")
                    || tool_name.contains("insert_after")
                    || tool_name.contains("insert_before")
                    || tool_name.contains("create_text_file")
                    || tool_name.contains("rename_symbol")
                {
                    self.security.file_writes += 1;
                }
            }
        }
    }

    /// Lines to scroll per Page Up/Down press.
    const PAGE_SCROLL: u16 = 20;

    /// Handle a key event.
    pub fn handle_key(&mut self, key: crossterm::event::KeyEvent) -> Option<UserAction> {
        use crossterm::event::{KeyCode, KeyModifiers};

        let is_streaming = self.session_state == SessionState::Streaming;

        // Ctrl+C: interrupt during streaming, ignored otherwise.
        // Use 'q' in normal mode to quit — prevents accidental session kill.
        if key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL) {
            if is_streaming {
                return Some(UserAction::Interrupt);
            }
            return None;
        }

        match self.input_mode {
            InputMode::Normal => {
                match key.code {
                    KeyCode::Char('q') if !is_streaming => self.should_quit = true,
                    KeyCode::Char('i') => self.input_mode = InputMode::Insert,
                    KeyCode::Esc if is_streaming => {
                        return Some(UserAction::Interrupt);
                    }
                    KeyCode::Up | KeyCode::Char('k') => {
                        self.scroll_offset = self.scroll_offset.saturating_add(1);
                    }
                    KeyCode::Down | KeyCode::Char('j') => {
                        self.scroll_offset = self.scroll_offset.saturating_sub(1);
                    }
                    KeyCode::PageUp => {
                        self.scroll_offset = self.scroll_offset.saturating_add(Self::PAGE_SCROLL);
                    }
                    KeyCode::PageDown => {
                        self.scroll_offset = self.scroll_offset.saturating_sub(Self::PAGE_SCROLL);
                    }
                    KeyCode::Home | KeyCode::Char('g') => {
                        self.scroll_offset = u16::MAX;
                    }
                    KeyCode::End | KeyCode::Char('G') => {
                        self.scroll_offset = 0;
                    }
                    _ => {}
                }
                None
            }
            InputMode::Insert => match key.code {
                KeyCode::Esc if is_streaming => Some(UserAction::Interrupt),
                KeyCode::Esc => {
                    self.input_mode = InputMode::Normal;
                    None
                }
                KeyCode::Enter => self.submit_input(),
                KeyCode::Backspace => {
                    self.input.pop();
                    None
                }
                KeyCode::Char(c) => {
                    self.input.push(c);
                    None
                }
                _ => None,
            },
        }
    }
}

impl Default for App {
    fn default() -> Self {
        Self::new("konishi")
    }
}

/// Short icon prefix for a tool name (ASCII-only for terminal compatibility).
fn tool_icon(name: &str) -> &'static str {
    match name {
        "Read" => "[R]",
        "Write" => "[W]",
        "Edit" => "[E]",
        "Bash" => "[$]",
        "Glob" => "[?]",
        "Grep" => "[/]",
        "Task" => "[>]",
        "WebFetch" | "WebSearch" => "[~]",
        _ => {
            if name.contains("read_file") || name.contains("get_symbols") {
                "[R]"
            } else if name.contains("replace_")
                || name.contains("insert_")
                || name.contains("create_text")
            {
                "[W]"
            } else if name.contains("search") || name.contains("find_") {
                "[/]"
            } else if name.contains("browser") || name.contains("playwright") {
                "[~]"
            } else {
                "[.]"
            }
        }
    }
}

/// Format a tool call for display (compact one-line summary).
fn format_tool_call(
    name: &str,
    input: &std::collections::HashMap<String, serde_json::Value>,
) -> String {
    // Helper: extract a file path argument and shorten to filename only
    let file_arg = |key: &str| -> String {
        let path = input.get(key).and_then(|v| v.as_str()).unwrap_or("?");
        path.rsplit('/').next().unwrap_or(path).to_owned()
    };

    match name {
        "Read" | "Write" | "Edit" => file_arg("file_path"),
        "Bash" => {
            let cmd = input.get("command").and_then(|v| v.as_str()).unwrap_or("?");
            if cmd.len() > 60 {
                format!("{}...", &cmd[..57])
            } else {
                cmd.to_owned()
            }
        }
        "Glob" => {
            let pattern = input.get("pattern").and_then(|v| v.as_str()).unwrap_or("?");
            pattern.to_owned()
        }
        "Grep" => {
            let pattern = input.get("pattern").and_then(|v| v.as_str()).unwrap_or("?");
            pattern.to_owned()
        }
        _ => {
            // MCP tools: extract the short name after the last "__"
            // rsplit("__").next() always returns Some on non-empty strings
            let short = name.rsplit("__").next().unwrap_or(name);
            let arg = input
                .get("relative_path")
                .or_else(|| input.get("name_path_pattern"))
                .or_else(|| input.get("name_path"))
                .or_else(|| input.get("query"))
                .or_else(|| input.get("substring_pattern"))
                .or_else(|| input.get("project"))
                .or_else(|| input.get("libraryName"))
                .or_else(|| input.get("url"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if arg.is_empty() {
                short.to_owned()
            } else {
                let short_arg = if arg.len() > 40 {
                    format!("{}...", &arg[..37])
                } else {
                    arg.to_owned()
                };
                format!("{short} {short_arg}")
            }
        }
    }
}

/// Format a tool result for display (compact preview with line count).
fn format_tool_result(content: &serde_json::Value, is_error: bool) -> String {
    let prefix = if is_error { "ERR" } else { "ok" };
    let (first_line, total_lines) = match content {
        serde_json::Value::String(s) => {
            let fl = s.lines().next().unwrap_or("");
            (truncate_line(fl, 80), s.lines().count())
        }
        serde_json::Value::Array(arr) => {
            // Tool results can be an array of content blocks
            let texts: Vec<&str> = arr
                .iter()
                .filter_map(|v| v.get("text").and_then(|t| t.as_str()))
                .collect();
            let joined = texts.join(" ");
            let fl = joined.lines().next().unwrap_or("").to_owned();
            let count = joined.lines().count();
            (truncate_line(&fl, 80), count)
        }
        _ => ("...".to_owned(), 0),
    };
    if total_lines > 1 {
        format!("  -> [{prefix}] {first_line} (+{} lines)", total_lines - 1)
    } else {
        format!("  -> [{prefix}] {first_line}")
    }
}

/// Truncate a string to `max` display chars with `...` suffix.
fn truncate_line(s: &str, max: usize) -> String {
    if s.chars().count() > max {
        let truncated: String = s.chars().take(max.saturating_sub(3)).collect();
        format!("{truncated}...")
    } else {
        s.to_owned()
    }
}
