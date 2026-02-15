//! UI rendering for the gleisner TUI.
//!
//! Uses Ratatui's immediate-mode rendering to draw the conversation,
//! input field, and security dashboard.

use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Wrap};

use crate::app::{App, InputMode, Role, SessionState};

/// The title shown in the top border.
const TITLE: &str = " gleisner ";

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

    // Left side: conversation + input
    let left = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Min(4),    // messages
            Constraint::Length(3), // input
            Constraint::Length(1), // status bar
        ])
        .split(outer[0]);

    draw_messages(frame, app, left[0]);
    draw_input(frame, app, left[1]);
    draw_status_bar(frame, app, left[2]);

    // Right side: security dashboard
    draw_security_dashboard(frame, app, outer[1]);
}

/// Render the conversation message area.
fn draw_messages(frame: &mut Frame, app: &App, area: Rect) {
    let mut lines: Vec<Line> = Vec::new();

    for msg in &app.messages {
        let (prefix, style) = match msg.role {
            Role::User => ("you> ", Style::default().fg(Color::Cyan)),
            Role::Assistant => ("claude> ", Style::default().fg(Color::Green)),
            Role::Tool => ("  ", Style::default().fg(Color::DarkGray)),
            Role::System => ("sys> ", Style::default().fg(Color::Yellow)),
        };

        lines.push(Line::from(vec![
            Span::styled(prefix, style.add_modifier(Modifier::BOLD)),
            Span::styled(&msg.content, style),
        ]));
    }

    if lines.is_empty() {
        lines.push(Line::from(Span::styled(
            "Press 'i' to enter insert mode, then type a message.",
            Style::default().fg(Color::DarkGray),
        )));
    }

    let block = Block::default()
        .title(TITLE)
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Blue));

    let paragraph = Paragraph::new(lines)
        .block(block)
        .wrap(Wrap { trim: false })
        .scroll((app.scroll_offset, 0));

    frame.render_widget(paragraph, area);
}

/// Render the input field.
fn draw_input(frame: &mut Frame, app: &App, area: Rect) {
    let (border_color, title) = match app.input_mode {
        InputMode::Normal => (Color::DarkGray, " NORMAL "),
        InputMode::Insert => (Color::Yellow, " INSERT "),
    };

    let block = Block::default()
        .title(title)
        .borders(Borders::ALL)
        .border_style(Style::default().fg(border_color));

    let input = Paragraph::new(app.input.as_str()).block(block);
    frame.render_widget(input, area);

    // Show cursor in insert mode
    if app.input_mode == InputMode::Insert {
        #[allow(clippy::cast_possible_truncation)]
        let cursor_x = area.x + app.input.len() as u16 + 1;
        let cursor_y = area.y + 1;
        frame.set_cursor_position((cursor_x, cursor_y));
    }
}

/// Render the bottom status bar.
fn draw_status_bar(frame: &mut Frame, app: &App, area: Rect) {
    let mode = match app.input_mode {
        InputMode::Normal => "NORMAL | q:quit i:insert",
        InputMode::Insert => "INSERT | Esc:normal Enter:send",
    };

    let streaming_indicator = match app.session_state {
        SessionState::Idle => Span::raw(""),
        SessionState::Streaming => Span::styled(
            " STREAMING ",
            Style::default()
                .fg(Color::Black)
                .bg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        ),
    };

    let cost = if app.security.cost_usd > 0.0 {
        Span::styled(
            format!(" ${:.4} ", app.security.cost_usd),
            Style::default().fg(Color::DarkGray),
        )
    } else {
        Span::raw("")
    };

    let status = Paragraph::new(Line::from(vec![
        Span::styled(
            format!(" {} ", app.security.profile),
            Style::default()
                .fg(Color::Black)
                .bg(Color::Blue)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw(" "),
        streaming_indicator,
        Span::styled(mode, Style::default().fg(Color::DarkGray)),
        cost,
    ]));

    frame.render_widget(status, area);
}

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

    let lines = vec![
        Line::from(""),
        Line::from(vec![
            Span::raw("  Profile: "),
            Span::styled(&sec.profile, Style::default().fg(Color::Cyan)),
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
            "  ── Activity ──",
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
            "  ── Session ──",
            Style::default()
                .fg(Color::DarkGray)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(format!("  Turns: {}", sec.turns)),
        Line::from(format!("  Cost:  ${:.4}", sec.cost_usd)),
    ];

    let block = Block::default()
        .title(" Security ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Magenta));

    let dashboard = Paragraph::new(lines).block(block);
    frame.render_widget(dashboard, area);
}
