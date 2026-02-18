//! UI rendering for the gleisner TUI.
//!
//! Uses Ratatui's immediate-mode rendering to draw the conversation,
//! input field, security dashboard, and scrollbar.
//!
//! # Message rendering
//!
//! Each message is split by newlines. The role prefix appears as a
//! badge on its own line; content lines are indented. Code fences
//! (triple backticks) get distinct styling with a `│` gutter. A blank line
//! separates messages for visual breathing room.

use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{
    Block, Borders, Paragraph, Scrollbar, ScrollbarOrientation, ScrollbarState, Wrap,
};

use crate::app::{App, InputMode, Message, Role, SessionState};

/// The title shown in the top border.
/// Angle brackets evoke a digital tag — the Gleisner suit's identifier.
const TITLE: &str = " \u{27E8}gleisner\u{27E9} ";

/// Content indent (two spaces for all message content lines).
const INDENT: &str = "  ";

/// Render the entire UI.
pub fn draw(frame: &mut Frame, app: &App) {
    // Main layout: conversation + security sidebar
    let outer = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Min(40),    // conversation area
            Constraint::Length(28), // security dashboard
        ])
        .split(frame.area());

    // Left side: conversation + input + status
    // Input height grows with text wrapping: 2 (borders) + number of wrapped lines.
    let input_inner_width = outer[0].width.saturating_sub(2) as usize; // minus left+right borders
    let input_lines = if input_inner_width == 0 {
        1
    } else {
        // Each line of input text wraps at the inner width.
        let len = app.input.len().max(1);
        ((len - 1) / input_inner_width + 1).min(6) // cap at 6 lines to avoid eating the conversation
    };
    #[allow(clippy::cast_possible_truncation)]
    let input_height = input_lines as u16 + 2; // +2 for top+bottom borders

    let left = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Min(4),               // messages
            Constraint::Length(input_height), // input (grows with wrapping)
            Constraint::Length(1),            // status bar
        ])
        .split(outer[0]);

    draw_messages(frame, app, left[0]);
    draw_input(frame, app, left[1]);
    draw_status_bar(frame, app, left[2]);
    draw_security_dashboard(frame, app, outer[1]);
}

// ─── Message rendering ─────────────────────────────────────────

/// Render a single message into lines.
///
/// Layout per message:
/// ```text
///  role     ← badge (colored background)
///   content  ← indented, one line per `\n` in the original
///   │ code   ← code blocks get a gutter marker
///             ← blank line separator
/// ```
fn render_message(lines: &mut Vec<Line<'static>>, msg: &Message) {
    let text_style = text_style_for(msg.role);

    // Tool messages are compact — no badge, just indented with a marker.
    if msg.role == Role::Tool {
        for line in msg.content.lines() {
            lines.push(Line::from(Span::styled(format!("  {line}"), text_style)));
        }
        return;
    }

    // Role badge on its own line.
    lines.push(role_badge(msg.role));

    // Content lines with code block detection and markdown rendering.
    let mut in_code_block = false;
    let code_style = Style::default().fg(Color::Rgb(180, 180, 180));
    let fence_style = Style::default().fg(Color::DarkGray);
    let header_style = Style::default()
        .fg(Color::Cyan)
        .add_modifier(Modifier::BOLD);
    let bullet_style = Style::default().fg(Color::Yellow);

    for line in msg.content.lines() {
        if line.starts_with("```") {
            in_code_block = !in_code_block;
            lines.push(Line::from(Span::styled(
                format!("{INDENT}{line}"),
                fence_style,
            )));
        } else if in_code_block {
            lines.push(Line::from(Span::styled(
                format!("{INDENT}\u{2502} {line}"),
                code_style,
            )));
        } else if line.starts_with('#') {
            // Markdown headers: # Header, ## Subheader, etc.
            let content = line.trim_start_matches('#').trim_start();
            lines.push(Line::from(Span::styled(
                format!("{INDENT}{content}"),
                header_style,
            )));
        } else if line.starts_with("- ") || line.starts_with("* ") {
            // Bullet lists
            let content = &line[2..];
            let mut spans = vec![Span::styled(format!("{INDENT}\u{2022} "), bullet_style)];
            spans.extend(parse_inline_markdown(content, text_style));
            lines.push(Line::from(spans));
        } else if line.len() > 2
            && line.chars().next().is_some_and(|c| c.is_ascii_digit())
            && line.contains(". ")
        {
            // Numbered lists: "1. item", "2. item", etc.
            if let Some(dot_pos) = line.find(". ") {
                let num = &line[..dot_pos];
                let content = &line[dot_pos + 2..];
                let mut spans = vec![Span::styled(format!("{INDENT}{num}. "), bullet_style)];
                spans.extend(parse_inline_markdown(content, text_style));
                lines.push(Line::from(spans));
            } else {
                lines.push(Line::from(parse_indented_inline(line, text_style)));
            }
        } else {
            // Regular text with inline markdown (bold, code)
            lines.push(Line::from(parse_indented_inline(line, text_style)));
        }
    }

    // Blank line after each message for visual separation.
    lines.push(Line::from(""));
}

/// Parse inline markdown (bold, inline code) and return styled spans.
///
/// Handles `**bold**` and `` `code` `` markers within a single line.
fn parse_inline_markdown(text: &str, base_style: Style) -> Vec<Span<'static>> {
    let bold_style = base_style.add_modifier(Modifier::BOLD);
    let code_style = Style::default().fg(Color::Rgb(180, 180, 180));

    let mut spans = Vec::new();
    let mut remaining = text;

    while !remaining.is_empty() {
        // Look for the next marker: ** or `
        let bold_pos = remaining.find("**");
        let code_pos = remaining.find('`');

        match (bold_pos, code_pos) {
            (Some(bp), Some(cp)) if bp <= cp => {
                // Bold marker comes first
                if bp > 0 {
                    spans.push(Span::styled(remaining[..bp].to_owned(), base_style));
                }
                remaining = &remaining[bp + 2..];
                if let Some(end) = remaining.find("**") {
                    spans.push(Span::styled(remaining[..end].to_owned(), bold_style));
                    remaining = &remaining[end + 2..];
                } else {
                    // No closing ** — treat as literal
                    spans.push(Span::styled(format!("**{remaining}"), base_style));
                    remaining = "";
                }
            }
            (Some(_), Some(cp)) => {
                // Code marker comes first
                if cp > 0 {
                    spans.push(Span::styled(remaining[..cp].to_owned(), base_style));
                }
                remaining = &remaining[cp + 1..];
                if let Some(end) = remaining.find('`') {
                    spans.push(Span::styled(remaining[..end].to_owned(), code_style));
                    remaining = &remaining[end + 1..];
                } else {
                    spans.push(Span::styled(format!("`{remaining}"), base_style));
                    remaining = "";
                }
            }
            (Some(bp), None) => {
                if bp > 0 {
                    spans.push(Span::styled(remaining[..bp].to_owned(), base_style));
                }
                remaining = &remaining[bp + 2..];
                if let Some(end) = remaining.find("**") {
                    spans.push(Span::styled(remaining[..end].to_owned(), bold_style));
                    remaining = &remaining[end + 2..];
                } else {
                    spans.push(Span::styled(format!("**{remaining}"), base_style));
                    remaining = "";
                }
            }
            (None, Some(cp)) => {
                if cp > 0 {
                    spans.push(Span::styled(remaining[..cp].to_owned(), base_style));
                }
                remaining = &remaining[cp + 1..];
                if let Some(end) = remaining.find('`') {
                    spans.push(Span::styled(remaining[..end].to_owned(), code_style));
                    remaining = &remaining[end + 1..];
                } else {
                    spans.push(Span::styled(format!("`{remaining}"), base_style));
                    remaining = "";
                }
            }
            (None, None) => {
                spans.push(Span::styled(remaining.to_owned(), base_style));
                remaining = "";
            }
        }
    }

    spans
}

/// Parse a line with INDENT prefix + inline markdown.
fn parse_indented_inline(line: &str, base_style: Style) -> Vec<Span<'static>> {
    let mut spans = vec![Span::styled(INDENT.to_owned(), base_style)];
    spans.extend(parse_inline_markdown(line, base_style));
    spans
}

/// Create a role badge `Line` (colored background, bold).
fn role_badge(role: Role) -> Line<'static> {
    let (label, style) = match role {
        Role::User => (
            " you ",
            Style::default()
                .fg(Color::Black)
                .bg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Role::Assistant => (
            " claude ",
            Style::default()
                .fg(Color::Black)
                .bg(Color::Green)
                .add_modifier(Modifier::BOLD),
        ),
        Role::System => (
            " suit ",
            Style::default()
                .fg(Color::Black)
                .bg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        ),
        Role::Tool => (" tool ", Style::default().fg(Color::DarkGray)),
    };
    Line::from(Span::styled(label.to_owned(), style))
}

/// Text style for message content.
fn text_style_for(role: Role) -> Style {
    match role {
        Role::User | Role::Assistant => Style::default().fg(Color::White),
        Role::Tool | Role::System => Style::default().fg(Color::DarkGray),
    }
}

/// Render the streaming buffer as a live assistant message being typed.
fn render_streaming_text(lines: &mut Vec<Line<'static>>, text: &str) {
    let text_style = Style::default().fg(Color::White);
    let cursor_style = Style::default()
        .fg(Color::Green)
        .add_modifier(Modifier::RAPID_BLINK);

    // Badge
    lines.push(role_badge(Role::Assistant));

    if text.is_empty() {
        // Show cursor on empty line
        lines.push(Line::from(vec![
            Span::styled(INDENT.to_owned(), text_style),
            Span::styled("\u{258c}", cursor_style),
        ]));
        return;
    }

    let content_lines: Vec<&str> = text.lines().collect();
    let last_idx = content_lines.len().saturating_sub(1);

    for (i, line) in content_lines.iter().enumerate() {
        if i == last_idx {
            // Last line gets the blinking cursor.
            lines.push(Line::from(vec![
                Span::styled(format!("{INDENT}{line}"), text_style),
                Span::styled("\u{258c}", cursor_style),
            ]));
        } else {
            lines.push(Line::from(Span::styled(
                format!("{INDENT}{line}"),
                text_style,
            )));
        }
    }

    // If text ends with newline, cursor goes on a new line.
    if text.ends_with('\n') {
        lines.push(Line::from(vec![
            Span::styled(INDENT.to_owned(), text_style),
            Span::styled("\u{258c}", cursor_style),
        ]));
    }
}

// ─── Conversation area ──────────────────────────────────────────

/// Render the conversation message area with scrollbar.
fn draw_messages(frame: &mut Frame, app: &App, area: Rect) {
    let mut lines: Vec<Line> = Vec::new();

    for msg in &app.messages {
        render_message(&mut lines, msg);
    }

    // Render streaming state.
    if app.session_state == SessionState::Streaming {
        if app.streaming_buffer.is_empty() {
            // Show a "thinking" indicator while waiting for first delta.
            lines.push(role_badge(Role::Assistant));
            lines.push(Line::from(Span::styled(
                format!("{INDENT}\u{2026}"),
                Style::default()
                    .fg(Color::DarkGray)
                    .add_modifier(Modifier::DIM),
            )));
        } else {
            render_streaming_text(&mut lines, &app.streaming_buffer);
        }
    }

    if lines.is_empty() {
        lines.push(Line::from(Span::styled(
            format!("{INDENT}Press 'i' to enter insert mode, then type a message."),
            Style::default().fg(Color::DarkGray),
        )));
    }

    let block = Block::default()
        .title(TITLE)
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Blue));

    // Calculate scroll position.
    // scroll_offset=0 means "at the bottom" (auto-scroll).
    // Increasing scroll_offset means "scrolled up by N lines".
    let visible_height = area.height.saturating_sub(2) as usize; // minus borders
    let total_lines = lines.len();
    let max_scroll = total_lines.saturating_sub(visible_height);
    let scroll_pos = max_scroll.saturating_sub(app.scroll_offset as usize);

    #[allow(clippy::cast_possible_truncation)]
    let paragraph = Paragraph::new(lines)
        .block(block)
        .wrap(Wrap { trim: false })
        .scroll((scroll_pos as u16, 0));

    frame.render_widget(paragraph, area);

    // Scrollbar (only shown when content overflows).
    if total_lines > visible_height {
        let mut scrollbar_state = ScrollbarState::new(max_scroll).position(scroll_pos);
        let scrollbar = Scrollbar::new(ScrollbarOrientation::VerticalRight)
            .begin_symbol(Some("\u{2191}"))
            .end_symbol(Some("\u{2193}"));
        frame.render_stateful_widget(scrollbar, area, &mut scrollbar_state);
    }
}

// ─── Input field ────────────────────────────────────────────────

/// Render the input field.
///
/// Enter submits the prompt. Esc returns to normal mode.
fn draw_input(frame: &mut Frame, app: &App, area: Rect) {
    let (border_color, title) = match app.input_mode {
        InputMode::Normal => (Color::DarkGray, " NORMAL "),
        InputMode::Insert => (Color::Yellow, " INSERT "),
    };

    let block = Block::default()
        .title(title)
        .borders(Borders::ALL)
        .border_style(Style::default().fg(border_color));

    let input = Paragraph::new(app.input.as_str())
        .block(block)
        .wrap(Wrap { trim: false });
    frame.render_widget(input, area);

    // Show cursor in insert mode, accounting for line wrapping.
    if app.input_mode == InputMode::Insert {
        let inner_width = area.width.saturating_sub(2) as usize; // minus left+right borders
        #[allow(clippy::cast_possible_truncation)]
        let (cursor_x, cursor_y) = if inner_width == 0 {
            (area.x + 1, area.y + 1)
        } else {
            let col = app.input.len() % inner_width;
            let row = app.input.len() / inner_width;
            (area.x + col as u16 + 1, area.y + row as u16 + 1)
        };
        frame.set_cursor_position((cursor_x, cursor_y));
    }
}

// ─── Status bar ─────────────────────────────────────────────────

/// Render the bottom status bar.
///
/// Layout: `[profile] model STREAMING mode    t:N $0.1234 #session`
fn draw_status_bar(frame: &mut Frame, app: &App, area: Rect) {
    let mut left_spans: Vec<Span> = Vec::new();

    // Profile badge.
    left_spans.push(Span::styled(
        format!(" {} ", app.security.profile),
        Style::default()
            .fg(Color::Black)
            .bg(Color::Blue)
            .add_modifier(Modifier::BOLD),
    ));
    left_spans.push(Span::raw(" "));

    // Model name.
    if let Some(ref model) = app.model {
        left_spans.push(Span::styled(
            model.clone(),
            Style::default().fg(Color::Cyan),
        ));
        left_spans.push(Span::raw(" "));
    }

    // Streaming indicator — "LINKED" means the polis link is active.
    if app.session_state == SessionState::Streaming {
        left_spans.push(Span::styled(
            " LINKED ",
            Style::default()
                .fg(Color::Black)
                .bg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ));
        left_spans.push(Span::raw(" "));
    }

    // Mode hint.
    let mode = match app.input_mode {
        InputMode::Normal => "q:quit i:insert j/k:scroll PgUp/Dn g/G:top/bot",
        InputMode::Insert => "Esc:normal Enter:send",
    };
    left_spans.push(Span::styled(
        mode.to_owned(),
        Style::default().fg(Color::DarkGray),
    ));

    // Right-aligned info: turns, cost, session ID.
    let mut right_spans: Vec<Span> = Vec::new();

    if app.security.turns > 0 {
        right_spans.push(Span::styled(
            format!("t:{} ", app.security.turns),
            Style::default().fg(Color::DarkGray),
        ));
    }

    if app.security.cost_usd > 0.0 {
        right_spans.push(Span::styled(
            format!("${:.4} ", app.security.cost_usd),
            Style::default().fg(Color::DarkGray),
        ));
    }

    if let Some(ref sid) = app.session_id {
        let short_sid = &sid[..sid.len().min(8)];
        right_spans.push(Span::styled(
            format!("#{short_sid}"),
            Style::default().fg(Color::DarkGray),
        ));
    }

    // Compute padding to right-align.
    let left_width: usize = left_spans.iter().map(|s| s.content.len()).sum();
    let right_width: usize = right_spans.iter().map(|s| s.content.len()).sum();
    let padding = (area.width as usize).saturating_sub(left_width + right_width);

    let mut spans = left_spans;
    if padding > 0 {
        spans.push(Span::raw(" ".repeat(padding)));
    }
    spans.extend(right_spans);

    let status = Paragraph::new(Line::from(spans));
    frame.render_widget(status, area);
}

// ─── Security dashboard ─────────────────────────────────────────

/// Render the security dashboard sidebar.
fn draw_security_dashboard(frame: &mut Frame, app: &App, area: Rect) {
    let sec = &app.security;

    let recording_indicator = if sec.recording { "REC" } else { "---" };
    let recording_color = if sec.recording {
        Color::Red
    } else {
        Color::DarkGray
    };

    let exo_self_indicator = if sec.exo_self_active {
        Span::styled(
            "ACTIVE",
            Style::default()
                .fg(Color::Green)
                .add_modifier(Modifier::BOLD),
        )
    } else {
        Span::styled("---", Style::default().fg(Color::DarkGray))
    };

    let perm_mode = if sec.permission_mode.is_empty() {
        "---"
    } else {
        &sec.permission_mode
    };

    let lines = vec![
        Line::from(""),
        Line::from(vec![
            Span::raw("  Profile: "),
            Span::styled(&sec.profile, Style::default().fg(Color::Cyan)),
        ]),
        Line::from(vec![
            Span::raw("  Mode:    "),
            Span::styled(perm_mode, Style::default().fg(Color::White)),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::raw("  Attestation: "),
            Span::styled(
                recording_indicator,
                Style::default()
                    .fg(recording_color)
                    .add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(vec![Span::raw("  Exo-self:    "), exo_self_indicator]),
        Line::from(""),
        Line::from(Span::styled(
            "  \u{2500}\u{2500} Sensors \u{2500}\u{2500}",
            Style::default()
                .fg(Color::DarkGray)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(format!("  File reads:  {}", sec.file_reads)),
        Line::from(format!("  File writes: {}", sec.file_writes)),
        Line::from(format!("  Tool calls:  {}", sec.tool_calls)),
        Line::from(format!("  Plugins:     {}", sec.plugin_count)),
        Line::from(""),
        Line::from(Span::styled(
            "  \u{2500}\u{2500} Link \u{2500}\u{2500}",
            Style::default()
                .fg(Color::DarkGray)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(format!("  Turns: {}", sec.turns)),
        Line::from(format!("  Cost:  ${:.4}", sec.cost_usd)),
    ];

    let block = Block::default()
        .title(" Telemetry ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Magenta));

    let dashboard = Paragraph::new(lines).block(block);
    frame.render_widget(dashboard, area);
}
