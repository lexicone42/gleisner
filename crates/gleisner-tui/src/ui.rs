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
    Block, BorderType, Borders, Padding, Paragraph, Scrollbar, ScrollbarOrientation,
    ScrollbarState, Wrap,
};
use unicode_width::UnicodeWidthChar;

// ─── Palette ────────────────────────────────────────────────────
// Inspired by magitek armor plating — brushed steel frame, green conduit glow.
const STEEL: Color = Color::Rgb(130, 148, 180);
const STEEL_DIM: Color = Color::Rgb(80, 95, 120);
const CONDUIT: Color = Color::Rgb(80, 200, 130);
const CONDUIT_DIM: Color = Color::Rgb(50, 140, 90);
const AMBER: Color = Color::Rgb(230, 180, 80);

use crate::app::{App, InputMode, Message, Role, SessionState};

/// The title shown in the top border.
/// Angle brackets evoke a digital tag — the Gleisner suit's identifier.
const TITLE: &str = " \u{27E8}gleisner\u{27E9} ";

/// Content indent (two spaces for all message content lines).
const INDENT: &str = "  ";

/// Render the entire UI.
pub fn draw(frame: &mut Frame, app: &App) {
    // Main layout: conversation + security sidebar.
    // Sidebar gets a fixed width — its content (label + value) never needs
    // more than ~28 columns. The conversation area takes all remaining space,
    // which minimizes wrapping on narrow terminals.
    let outer = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Min(40),    // conversation area (takes remaining)
            Constraint::Length(30), // security dashboard (fixed width)
        ])
        .split(frame.area());

    // Left side: conversation + input + status
    // Input height grows with text wrapping: 2 (borders) + number of wrapped lines.
    // Uses display-width-based line splitting (same algorithm as draw_input)
    // so the reserved height always matches the rendered content.
    let input_inner_width = outer[0].width.saturating_sub(2) as usize; // minus left+right borders
    let input_visual_lines = visual_line_count_for_input(&app.input, input_inner_width);
    #[allow(clippy::cast_possible_truncation)]
    let input_height = (input_visual_lines.min(6)) as u16 + 2; // cap at 6 lines + borders

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
    let header_style = Style::default().fg(STEEL).add_modifier(Modifier::BOLD);
    let bullet_style = Style::default().fg(AMBER);

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
///
/// Uses the palette colors to keep badges visually consistent with
/// the border hierarchy.
fn role_badge(role: Role) -> Line<'static> {
    let (label, style) = match role {
        Role::User => (
            " you ",
            Style::default()
                .fg(Color::Black)
                .bg(STEEL)
                .add_modifier(Modifier::BOLD),
        ),
        Role::Assistant => (
            " claude ",
            Style::default()
                .fg(Color::Black)
                .bg(CONDUIT)
                .add_modifier(Modifier::BOLD),
        ),
        Role::System => (
            " suit ",
            Style::default()
                .fg(Color::Black)
                .bg(AMBER)
                .add_modifier(Modifier::BOLD),
        ),
        Role::Tool => (" tool ", Style::default().fg(STEEL_DIM)),
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
        .fg(CONDUIT)
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
            "Press 'i' to enter insert mode, then type a message.",
            Style::default().fg(STEEL_DIM),
        )));
    }

    // Compute visual line count: each Line wraps based on its display width
    // vs the inner width of the conversation area.
    // This is critical for correct scroll math — Paragraph::scroll() operates
    // on visual (post-wrap) lines, not logical lines.
    let inner_width = area.width.saturating_sub(2 + 2) as usize; // borders + horizontal padding
    let visible_height = area.height.saturating_sub(2) as usize;

    let visual_line_count: usize = lines
        .iter()
        .map(|line| {
            let w = line.width();
            if w == 0 || inner_width == 0 {
                1
            } else {
                w.div_ceil(inner_width)
            }
        })
        .sum();

    let has_overflow = visual_line_count > visible_height;
    let scroll_hint = if has_overflow && app.scroll_offset > 0 {
        Line::from(Span::styled(
            format!(" \u{2191}{} ", app.scroll_offset),
            Style::default().fg(STEEL_DIM),
        ))
        .right_aligned()
    } else {
        Line::default()
    };

    let mut block = Block::default()
        .title_top(Line::from(TITLE).left_aligned())
        .borders(Borders::ALL)
        .border_type(BorderType::Double)
        .border_style(Style::default().fg(STEEL))
        .padding(Padding::horizontal(1));

    if has_overflow {
        block = block.title_bottom(scroll_hint);
    }

    // Calculate scroll position using visual line count.
    // scroll_offset=0 means "at the bottom" (auto-scroll).
    // Increasing scroll_offset means "scrolled up by N lines".
    let max_scroll = visual_line_count.saturating_sub(visible_height);
    let scroll_pos = max_scroll.saturating_sub(app.scroll_offset as usize);

    #[allow(clippy::cast_possible_truncation)]
    let paragraph = Paragraph::new(lines)
        .block(block)
        .wrap(Wrap { trim: false })
        .scroll((scroll_pos as u16, 0));

    frame.render_widget(paragraph, area);

    // Scrollbar (only shown when content overflows).
    if has_overflow {
        let mut scrollbar_state = ScrollbarState::new(max_scroll).position(scroll_pos);
        let scrollbar = Scrollbar::new(ScrollbarOrientation::VerticalRight)
            .begin_symbol(Some("\u{2191}"))
            .end_symbol(Some("\u{2193}"));
        frame.render_stateful_widget(scrollbar, area, &mut scrollbar_state);
    }
}

// ─── Display-width helpers ──────────────────────────────────────

/// Compute the display width of a string (Unicode-aware).
fn display_width(s: &str) -> usize {
    s.chars()
        .map(|c| UnicodeWidthChar::width(c).unwrap_or(0))
        .sum()
}

/// Split a string into visual lines by character display width.
///
/// Unlike Ratatui's `Wrap`, this breaks at exact column boundaries
/// (no word-level heuristics), so cursor math can use the same split points.
fn split_by_display_width(text: &str, max_width: usize) -> Vec<String> {
    if max_width == 0 {
        return vec![text.to_owned()];
    }
    let mut lines = Vec::new();
    let mut current = String::new();
    let mut current_width = 0;

    for ch in text.chars() {
        let ch_width = UnicodeWidthChar::width(ch).unwrap_or(0);
        if current_width + ch_width > max_width && !current.is_empty() {
            lines.push(std::mem::take(&mut current));
            current_width = 0;
        }
        current.push(ch);
        current_width += ch_width;
    }
    // Always push the last segment (even if empty — shows the prompt on an empty input)
    lines.push(current);
    lines
}

/// Count how many visual lines the input text occupies (for layout height calculation).
fn visual_line_count_for_input(input: &str, inner_width: usize) -> usize {
    let display = format!("\u{276F} {input}"); // ❯ + space + text
    split_by_display_width(&display, inner_width).len()
}

// ─── Input field ────────────────────────────────────────────────

/// Render the input field with a REPL-style prompt.
///
/// In insert mode the border lights up and a `❯` prompt appears.
/// Enter submits, Esc returns to normal mode.
///
/// Uses character-level wrapping (not word-level) so the cursor position
/// is always correct. Ratatui's `Paragraph::wrap()` breaks at word boundaries
/// which makes cursor positioning unpredictable; manual splitting avoids that.
fn draw_input(frame: &mut Frame, app: &App, area: Rect) {
    let is_insert = app.input_mode == InputMode::Insert;

    let (border_color, mode_label) = if is_insert {
        (AMBER, " INSERT ")
    } else {
        (STEEL_DIM, " NORMAL ")
    };

    let block = Block::default()
        .title_top(Line::from(mode_label).left_aligned())
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(border_color));

    let prompt_style = if is_insert {
        Style::default().fg(CONDUIT).add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(STEEL_DIM)
    };
    let text_style = if is_insert {
        Style::default().fg(Color::White)
    } else {
        Style::default().fg(Color::DarkGray)
    };

    // Build the full display string: prompt + input text.
    // Then split into visual lines by character display width.
    let inner_width = area.width.saturating_sub(2) as usize; // minus left+right borders
    let prompt_str = "\u{276F} "; // ❯ + space
    let display = format!("{prompt_str}{}", app.input);

    let visual_lines = split_by_display_width(&display, inner_width);

    // Render each visual line with appropriate styling.
    // The prompt characters get prompt_style, the rest gets text_style.
    let prompt_display_width = display_width(prompt_str);
    let lines: Vec<Line> = visual_lines
        .iter()
        .enumerate()
        .map(|(row, text)| {
            if row == 0 && text.len() >= prompt_str.len() {
                // First line: split into prompt + content spans
                Line::from(vec![
                    Span::styled(prompt_str.to_owned(), prompt_style),
                    Span::styled(text[prompt_str.len()..].to_owned(), text_style),
                ])
            } else {
                Line::from(Span::styled(text.clone(), text_style))
            }
        })
        .collect();

    // No Wrap — we already split into visual lines, so rendering matches cursor math.
    let paragraph = Paragraph::new(lines).block(block);
    frame.render_widget(paragraph, area);

    // Cursor position: end of the last visual line.
    if is_insert {
        let cursor_row = visual_lines.len().saturating_sub(1);
        let cursor_col = visual_lines
            .last()
            .map_or(prompt_display_width, |l| display_width(l));
        #[allow(clippy::cast_possible_truncation)]
        frame.set_cursor_position((
            area.x + cursor_col as u16 + 1, // +1 for left border
            area.y + cursor_row as u16 + 1, // +1 for top border
        ));
    }
}

// ─── Status bar ─────────────────────────────────────────────────

/// Render the bottom status bar.
///
/// Compact layout inspired by Claude Code's REPL:
/// `[profile] model  LINKED  q:quit ...    t:3 $0.12 #abc123`
fn draw_status_bar(frame: &mut Frame, app: &App, area: Rect) {
    let sep = Span::styled(" \u{2502} ", Style::default().fg(STEEL_DIM)); // │ separator

    let mut left_spans: Vec<Span> = Vec::new();

    // Profile badge — pill style.
    left_spans.push(Span::styled(
        format!(" {} ", app.security.profile),
        Style::default()
            .fg(Color::Black)
            .bg(STEEL)
            .add_modifier(Modifier::BOLD),
    ));

    // Model name.
    if let Some(ref model) = app.model {
        left_spans.push(sep.clone());
        left_spans.push(Span::styled(model.clone(), Style::default().fg(STEEL)));
    }

    // Streaming indicator — "LINKED" means the polis link is active.
    if app.session_state == SessionState::Streaming {
        left_spans.push(Span::raw(" "));
        left_spans.push(Span::styled(
            " LINKED ",
            Style::default()
                .fg(Color::Black)
                .bg(CONDUIT)
                .add_modifier(Modifier::BOLD),
        ));
    }

    // Mode hints — dimmed, only the essentials.
    left_spans.push(sep.clone());
    let mode = match app.input_mode {
        InputMode::Normal => "q:quit i:insert j/k:scroll",
        InputMode::Insert => "Esc:normal Enter:send",
    };
    left_spans.push(Span::styled(mode, Style::default().fg(STEEL_DIM)));

    // Right-aligned info: turns, cost, session ID.
    let mut right_spans: Vec<Span> = Vec::new();

    if app.security.turns > 0 {
        right_spans.push(Span::styled(
            format!("t:{}", app.security.turns),
            Style::default().fg(STEEL_DIM),
        ));
    }

    if app.security.cost_usd > 0.0 {
        if !right_spans.is_empty() {
            right_spans.push(sep.clone());
        }
        right_spans.push(Span::styled(
            format!("${:.4}", app.security.cost_usd),
            Style::default().fg(CONDUIT_DIM),
        ));
    }

    if let Some(ref sid) = app.session_id {
        let short_sid = &sid[..sid.len().min(8)];
        if !right_spans.is_empty() {
            right_spans.push(sep);
        }
        right_spans.push(Span::styled(
            format!("#{short_sid}"),
            Style::default().fg(STEEL_DIM),
        ));
    }

    // Compute padding to right-align.
    let left_width: usize = left_spans.iter().map(|s| s.content.len()).sum();
    let right_width: usize = right_spans.iter().map(|s| s.content.len()).sum();
    let gap = (area.width as usize).saturating_sub(left_width + right_width);

    let mut spans = left_spans;
    if gap > 0 {
        spans.push(Span::raw(" ".repeat(gap)));
    }
    spans.extend(right_spans);

    let status = Paragraph::new(Line::from(spans));
    frame.render_widget(status, area);
}

// ─── Security dashboard ─────────────────────────────────────────

/// Render the security dashboard sidebar.
///
/// Three sections: suit state (profile, sandbox, attestation),
/// live sensors (reads, writes, tools), and link stats (turns, cost, context).
/// Context window uses a visual bar for at-a-glance usage.
#[allow(clippy::too_many_lines, clippy::cast_precision_loss)]
fn draw_security_dashboard(frame: &mut Frame, app: &App, area: Rect) {
    let sec = &app.security;
    let label_style = Style::default().fg(STEEL_DIM);
    let value_style = Style::default().fg(Color::White);
    let section_style = Style::default()
        .fg(CONDUIT_DIM)
        .add_modifier(Modifier::BOLD);

    // ── Sandbox indicator ──
    let sandbox_span = if sec.sandbox_active {
        Span::styled(
            "\u{25CF} bwrap",
            Style::default().fg(CONDUIT).add_modifier(Modifier::BOLD),
        )
    } else {
        Span::styled("\u{25CB} off", label_style)
    };

    // ── Attest indicator (shows live event count while recording) ──
    let attest_spans: Vec<Span> = if sec.recording {
        vec![
            Span::styled(
                "\u{25CF} REC",
                Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
            ),
            Span::styled(format!(" {}", sec.attest_events), value_style),
        ]
    } else if sec.attest_events > 0 {
        // Recording finished, show final count dimmed
        vec![
            Span::styled("\u{25CB} ", label_style),
            Span::styled(format!("{}", sec.attest_events), label_style),
        ]
    } else {
        vec![Span::styled("\u{25CB} ---", label_style)]
    };

    // ── Cosign indicator ──
    let cosign_span = if sec.cosigned {
        Span::styled(
            "\u{25CF} signed",
            Style::default().fg(CONDUIT).add_modifier(Modifier::BOLD),
        )
    } else if sec.pending_cosign {
        Span::styled(
            "\u{25CF} /cosign",
            Style::default().fg(AMBER).add_modifier(Modifier::BOLD),
        )
    } else {
        Span::styled("\u{25CB} ---", label_style)
    };

    let exo_self_span = if sec.exo_self_active {
        Span::styled(
            "\u{25CF} active",
            Style::default().fg(CONDUIT).add_modifier(Modifier::BOLD),
        )
    } else {
        Span::styled("\u{25CB} ---", label_style)
    };

    let perm_mode = if sec.permission_mode.is_empty() {
        "---"
    } else {
        &sec.permission_mode
    };

    // ── Context window bar ──
    // 10-column bar: █ for used, ░ for free, colored by usage level.
    let ctx_line = if sec.context_window > 0 {
        let pct = (sec.tokens_used as f64 / sec.context_window as f64) * 100.0;
        let color = if pct > 80.0 {
            Color::Red
        } else if pct > 60.0 {
            AMBER
        } else {
            CONDUIT
        };
        let bar_width: usize = 10;
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let filled = ((pct / 100.0) * bar_width as f64).round() as usize;
        let empty = bar_width.saturating_sub(filled);
        vec![
            Span::styled("Ctx ", label_style),
            Span::styled("\u{2588}".repeat(filled), Style::default().fg(color)),
            Span::styled("\u{2591}".repeat(empty), Style::default().fg(STEEL_DIM)),
            Span::styled(format!(" {pct:.0}%"), Style::default().fg(color)),
        ]
    } else {
        vec![
            Span::styled("Ctx ", label_style),
            Span::styled("---", label_style),
        ]
    };

    let mut lines = vec![
        // ── State ──
        Line::from(Span::styled("\u{2500} State \u{2500}", section_style)),
        Line::from(vec![
            Span::styled("Profile ", label_style),
            Span::styled(&sec.profile, Style::default().fg(CONDUIT)),
        ]),
        Line::from(vec![
            Span::styled("Mode    ", label_style),
            Span::styled(perm_mode, value_style),
        ]),
        Line::from(vec![Span::styled("Sandbox ", label_style), sandbox_span]),
    ];

    // Attest line uses a Vec<Span> (variable number of spans)
    let mut attest_line = vec![Span::styled("Attest  ", label_style)];
    attest_line.extend(attest_spans);
    lines.push(Line::from(attest_line));

    lines.extend([
        Line::from(vec![Span::styled("Cosign  ", label_style), cosign_span]),
        Line::from(vec![Span::styled("Exo     ", label_style), exo_self_span]),
        Line::from(""),
        // ── Sensors ──
        Line::from(Span::styled("\u{2500} Sensors \u{2500}", section_style)),
        Line::from(vec![
            Span::styled("Reads  ", label_style),
            Span::styled(format!("{}", sec.file_reads), value_style),
        ]),
        Line::from(vec![
            Span::styled("Writes ", label_style),
            Span::styled(format!("{}", sec.file_writes), value_style),
        ]),
        Line::from(vec![
            Span::styled("Tools  ", label_style),
            Span::styled(format!("{}", sec.tool_calls), value_style),
        ]),
        Line::from(vec![
            Span::styled("MCP    ", label_style),
            Span::styled(format!("{}", sec.plugin_count), value_style),
        ]),
        Line::from(""),
        // ── Link ──
        Line::from(Span::styled("\u{2500} Link \u{2500}", section_style)),
        Line::from(vec![
            Span::styled("Turns  ", label_style),
            Span::styled(format!("{}", sec.turns), value_style),
        ]),
        Line::from(vec![
            Span::styled("Cost   ", label_style),
            Span::styled(
                format!("${:.4}", sec.cost_usd),
                Style::default().fg(CONDUIT),
            ),
        ]),
        Line::from(ctx_line),
    ]);

    let block = Block::default()
        .title_top(Line::from(" Telemetry ").left_aligned())
        .borders(Borders::ALL)
        .border_type(BorderType::Thick)
        .border_style(Style::default().fg(CONDUIT))
        .padding(Padding::new(1, 1, 1, 0));

    let dashboard = Paragraph::new(lines)
        .block(block)
        .wrap(Wrap { trim: false });
    frame.render_widget(dashboard, area);
}
