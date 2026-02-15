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
}

/// The input mode determines how keystrokes are interpreted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputMode {
    /// Normal mode — navigation and commands.
    Normal,
    /// Insert mode — typing into the input field.
    Insert,
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

    /// Submit the current input as a user message.
    /// Returns the submitted text, or `None` if input was empty or already streaming.
    pub fn submit_input(&mut self) -> Option<String> {
        if self.session_state == SessionState::Streaming {
            return None;
        }
        let text = self.input.trim().to_owned();
        if text.is_empty() {
            return None;
        }
        self.input.clear();
        self.push_message(Role::User, &text);
        self.session_state = SessionState::Streaming;
        Some(text)
    }

    /// Process a stream event from the Claude subprocess.
    pub fn handle_stream_event(&mut self, event: StreamEvent) {
        match event {
            StreamEvent::System(sys) => self.handle_system_event(sys),
            StreamEvent::Assistant(asst) => self.handle_assistant_event(asst),
            StreamEvent::User(user) => self.handle_user_event(user),
            StreamEvent::Result(result) => self.handle_result_event(result),
            StreamEvent::StreamDelta(_) => {
                // TODO: handle partial message deltas for real-time streaming
            }
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
            "hook_response" => {}
            _ => {}
        }
    }

    /// Handle assistant messages (text output, tool calls).
    fn handle_assistant_event(&mut self, asst: crate::stream::AssistantEvent) {
        for block in &asst.message.content {
            match block {
                ContentBlock::Text { text } => {
                    self.push_message(Role::Assistant, text);
                }
                ContentBlock::ToolUse { name, input, .. } => {
                    self.security.tool_calls += 1;
                    self.update_tool_counters(name);

                    // Show a compact summary of the tool call
                    let summary = format_tool_call(name, input);
                    self.push_message(Role::Tool, format!("[{name}] {summary}"));
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
    fn handle_user_event(&mut self, user: crate::stream::UserEvent) {
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

    /// Handle a key event.
    pub fn handle_key(&mut self, key: crossterm::event::KeyEvent) -> Option<String> {
        use crossterm::event::KeyCode;

        match self.input_mode {
            InputMode::Normal => {
                match key.code {
                    KeyCode::Char('q') => self.should_quit = true,
                    KeyCode::Char('i') => self.input_mode = InputMode::Insert,
                    KeyCode::Up => self.scroll_offset = self.scroll_offset.saturating_add(1),
                    KeyCode::Down => self.scroll_offset = self.scroll_offset.saturating_sub(1),
                    _ => {}
                }
                None
            }
            InputMode::Insert => match key.code {
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

/// Format a tool call for display (compact one-line summary).
fn format_tool_call(
    name: &str,
    input: &std::collections::HashMap<String, serde_json::Value>,
) -> String {
    match name {
        "Read" => {
            let path = input
                .get("file_path")
                .and_then(|v| v.as_str())
                .unwrap_or("?");
            // Show just the filename, not the full path
            let short = path.rsplit('/').next().unwrap_or(path);
            short.to_owned()
        }
        "Write" => {
            let path = input
                .get("file_path")
                .and_then(|v| v.as_str())
                .unwrap_or("?");
            let short = path.rsplit('/').next().unwrap_or(path);
            short.to_owned()
        }
        "Edit" => {
            let path = input
                .get("file_path")
                .and_then(|v| v.as_str())
                .unwrap_or("?");
            let short = path.rsplit('/').next().unwrap_or(path);
            short.to_owned()
        }
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
            if let Some(short) = name.rsplit("__").next() {
                // Try to extract a meaningful argument
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
            } else {
                format!("{name}(...)")
            }
        }
    }
}

/// Format a tool result for display (compact preview).
fn format_tool_result(content: &serde_json::Value, is_error: bool) -> String {
    let prefix = if is_error { "ERR" } else { "ok" };
    let text = match content {
        serde_json::Value::String(s) => {
            let first_line = s.lines().next().unwrap_or("");
            if first_line.len() > 80 {
                format!("{}...", &first_line[..77])
            } else {
                first_line.to_owned()
            }
        }
        serde_json::Value::Array(arr) => {
            // Tool results can be an array of content blocks
            let texts: Vec<&str> = arr
                .iter()
                .filter_map(|v| v.get("text").and_then(|t| t.as_str()))
                .collect();
            let joined = texts.join(" ");
            let first_line = joined.lines().next().unwrap_or("");
            if first_line.len() > 80 {
                format!("{}...", &first_line[..77])
            } else {
                first_line.to_owned()
            }
        }
        _ => "...".to_owned(),
    };
    format!("  → [{prefix}] {text}")
}
