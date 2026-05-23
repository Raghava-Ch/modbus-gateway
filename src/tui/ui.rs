// tui/ui.rs — Ratatui widget layout and rendering

use ratatui::{
    Frame,
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span, Text},
    widgets::{
        Bar, BarChart, BarGroup, Block, Borders, List, ListItem, Paragraph, Wrap,
    },
};

use crate::metrics::{TrafficDirection, TrafficEvent};

use super::app::TuiApp;

// ─────────────────────────────────────────────────────────────────────────────
// Colour palette
// ─────────────────────────────────────────────────────────────────────────────

const ACCENT: Color = Color::Rgb(82, 175, 255);   // bright blue
const SUCCESS: Color = Color::Rgb(80, 220, 120);  // green
const WARN: Color = Color::Rgb(255, 185, 60);     // amber
const ERR: Color = Color::Rgb(255, 80, 80);       // red
const MUTED: Color = Color::Rgb(100, 110, 130);   // grey
const BG_DARK: Color = Color::Rgb(18, 20, 28);    // near-black
const BG_PANEL: Color = Color::Rgb(24, 28, 40);   // panel background

// ─────────────────────────────────────────────────────────────────────────────
// draw() — top-level frame layout
// ─────────────────────────────────────────────────────────────────────────────

/// Render the full TUI into `frame`.
pub fn draw(frame: &mut Frame, app: &TuiApp) {
    let area = frame.area();

    // Show help overlay and return early.
    if app.show_help() {
        draw_help_overlay(frame, area);
        return;
    }

    // ── Vertical split: header / body / log ───────────────────────────────────
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),  // header
            Constraint::Min(10),    // body
            Constraint::Length(7),  // log pane
        ])
        .split(area);

    draw_header(frame, app, rows[0]);
    draw_body(frame, app, rows[1]);
    draw_log_pane(frame, app, rows[2]);
}

// ─────────────────────────────────────────────────────────────────────────────
// Header
// ─────────────────────────────────────────────────────────────────────────────

fn draw_header(frame: &mut Frame, app: &TuiApp, area: Rect) {
    let metrics = app.metrics();
    let cs = app.capture_state();
    let uptime = metrics.uptime();
    let h = uptime.as_secs() / 3600;
    let m = (uptime.as_secs() % 3600) / 60;
    let s = uptime.as_secs() % 60;

    let pcap_badge = if cs.pcap_on() {
        Span::styled(" ● PCAP ", Style::default().fg(ERR).add_modifier(Modifier::BOLD))
    } else {
        Span::styled(" ○ PCAP ", Style::default().fg(MUTED))
    };
    let csv_badge = if cs.csv_on() {
        Span::styled(" ● CSV ", Style::default().fg(WARN).add_modifier(Modifier::BOLD))
    } else {
        Span::styled(" ○ CSV ", Style::default().fg(MUTED))
    };

    let title = Line::from(vec![
        Span::styled(" ◈ MODBUS GATEWAY ", Style::default().fg(ACCENT).add_modifier(Modifier::BOLD)),
        Span::styled(
            format!("v{} ", app.version()),
            Style::default().fg(MUTED),
        ),
        Span::styled("│ ", Style::default().fg(MUTED)),
        Span::styled(
            format!(
                "⬆ Fwd: {:>6}  ⚠ Miss: {:>4}  ✗ Timeout: {:>4}",
                metrics.forwards.load(std::sync::atomic::Ordering::Relaxed),
                metrics.routing_misses.load(std::sync::atomic::Ordering::Relaxed),
                metrics.timeouts.load(std::sync::atomic::Ordering::Relaxed),
            ),
            Style::default().fg(SUCCESS),
        ),
        Span::styled("  │ ", Style::default().fg(MUTED)),
        pcap_badge,
        csv_badge,
        Span::styled("  │ ", Style::default().fg(MUTED)),
        Span::styled(
            format!("⏱ Uptime {:02}:{:02}:{:02}", h, m, s),
            Style::default().fg(ACCENT),
        ),
        Span::styled("  [? help]", Style::default().fg(MUTED)),
    ]);

    let header = Paragraph::new(title)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(ACCENT))
                .style(Style::default().bg(BG_DARK)),
        )
        .alignment(Alignment::Left);

    frame.render_widget(header, area);
}

// ─────────────────────────────────────────────────────────────────────────────
// Body: left pane (routing/stats) + right pane (traffic + histogram)
// ─────────────────────────────────────────────────────────────────────────────

fn draw_body(frame: &mut Frame, app: &TuiApp, area: Rect) {
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(28), Constraint::Percentage(72)])
        .split(area);

    draw_routing_pane(frame, app, cols[0]);
    draw_traffic_pane(frame, app, cols[1]);
}

// ── Left: routing table + stats ───────────────────────────────────────────────

fn draw_routing_pane(frame: &mut Frame, app: &TuiApp, area: Rect) {
    let focus_border = if app.focus() == 0 { ACCENT } else { MUTED };

    // Routing table items (placeholder — Phase 4 will read the live router).
    let ds_names = app.downstream_names();
    let mut items: Vec<ListItem> = ds_names
        .iter()
        .enumerate()
        .map(|(i, name)| {
            ListItem::new(Line::from(vec![
                Span::styled(format!(" ▸ ch{i} → "), Style::default().fg(MUTED)),
                Span::styled(name.as_str(), Style::default().fg(SUCCESS).add_modifier(Modifier::BOLD)),
            ]))
        })
        .collect();

    if items.is_empty() {
        items.push(ListItem::new(Span::styled(
            " (no routes configured)",
            Style::default().fg(WARN),
        )));
    }

    // Stats block
    let metrics = app.metrics();
    let stats = vec![
        ListItem::new(Line::from(vec![
            Span::styled("─ Stats ─", Style::default().fg(MUTED)),
        ])),
        ListItem::new(Line::from(vec![
            Span::styled(" Fwd:  ", Style::default().fg(MUTED)),
            Span::styled(
                format!("{:>8}", metrics.forwards.load(std::sync::atomic::Ordering::Relaxed)),
                Style::default().fg(SUCCESS),
            ),
        ])),
        ListItem::new(Line::from(vec![
            Span::styled(" Miss: ", Style::default().fg(MUTED)),
            Span::styled(
                format!("{:>8}", metrics.routing_misses.load(std::sync::atomic::Ordering::Relaxed)),
                Style::default().fg(WARN),
            ),
        ])),
        ListItem::new(Line::from(vec![
            Span::styled(" T/O:  ", Style::default().fg(MUTED)),
            Span::styled(
                format!("{:>8}", metrics.timeouts.load(std::sync::atomic::Ordering::Relaxed)),
                Style::default().fg(ERR),
            ),
        ])),
        ListItem::new(Line::from(vec![
            Span::styled(" Disc: ", Style::default().fg(MUTED)),
            Span::styled(
                format!("{:>8}", metrics.disconnects.load(std::sync::atomic::Ordering::Relaxed)),
                Style::default().fg(ERR),
            ),
        ])),
    ];

    let all_items: Vec<ListItem> = items.into_iter().chain(stats).collect();

    let list = List::new(all_items)
        .block(
            Block::default()
                .title(" ◈ ROUTING ")
                .title_style(Style::default().fg(ACCENT).add_modifier(Modifier::BOLD))
                .borders(Borders::ALL)
                .border_style(Style::default().fg(focus_border))
                .style(Style::default().bg(BG_PANEL)),
        );

    frame.render_widget(list, area);
}

// ── Right: traffic list + latency histogram ────────────────────────────────────

fn draw_traffic_pane(frame: &mut Frame, app: &TuiApp, area: Rect) {
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(6), Constraint::Length(6)])
        .split(area);

    draw_traffic_list(frame, app, rows[0]);
    draw_latency_histogram(frame, app, rows[1]);
}

fn draw_traffic_list(frame: &mut Frame, app: &TuiApp, area: Rect) {
    let focus_border = if app.focus() == 1 { ACCENT } else { MUTED };
    let events = app.traffic_events();

    let items: Vec<ListItem> = events
        .iter()
        .rev()
        .take(area.height.saturating_sub(2) as usize)
        .map(|ev| format_traffic_event(ev))
        .collect();

    let placeholder_items = if items.is_empty() {
        vec![ListItem::new(Span::styled(
            " Waiting for traffic…",
            Style::default().fg(MUTED),
        ))]
    } else {
        items
    };

    let list = List::new(placeholder_items)
        .block(
            Block::default()
                .title(" ◈ LIVE TRAFFIC ")
                .title_style(Style::default().fg(ACCENT).add_modifier(Modifier::BOLD))
                .borders(Borders::ALL)
                .border_style(Style::default().fg(focus_border))
                .style(Style::default().bg(BG_PANEL)),
        );

    frame.render_widget(list, area);
}

fn format_traffic_event(ev: &TrafficEvent) -> ListItem<'_> {
    let ts = ev.timestamp.format("%H:%M:%S%.3f");
    let dir_color = match ev.direction {
        TrafficDirection::UpstreamRx => ACCENT,
        TrafficDirection::DownstreamTx => SUCCESS,
        TrafficDirection::DownstreamRx => WARN,
        TrafficDirection::UpstreamTx => ERR,
    };
    let dir_str = match ev.direction {
        TrafficDirection::UpstreamRx => "↓ RX",
        TrafficDirection::DownstreamTx => "↑ TX",
        TrafficDirection::DownstreamRx => "↓ RX",
        TrafficDirection::UpstreamTx => "↑ TX",
    };

    // Parse basic Modbus TCP fields for display (best-effort).
    let detail = if ev.frame.len() >= 8 {
        let unit = ev.frame[6];
        let fc = ev.frame[7];
        format!("Unit {:3} FC 0x{:02X}  {} bytes", unit, fc, ev.frame.len())
    } else {
        format!("{} bytes (raw)", ev.frame.len())
    };

    ListItem::new(Line::from(vec![
        Span::styled(format!(" {ts} "), Style::default().fg(MUTED)),
        Span::styled(dir_str, Style::default().fg(dir_color).add_modifier(Modifier::BOLD)),
        Span::styled(format!("  ch{} ", ev.channel_idx), Style::default().fg(MUTED)),
        Span::styled(detail, Style::default().fg(Color::White)),
    ]))
}

fn draw_latency_histogram(frame: &mut Frame, app: &TuiApp, area: Rect) {
    let buckets = app.metrics().latency_buckets();

    let bars = vec![
        Bar::default()
            .value(buckets.under_1ms_pct as u64)
            .label(Line::from("<1ms"))
            .style(Style::default().fg(SUCCESS)),
        Bar::default()
            .value(buckets.one_to_5ms_pct as u64)
            .label(Line::from("1-5ms"))
            .style(Style::default().fg(WARN)),
        Bar::default()
            .value(buckets.over_5ms_pct as u64)
            .label(Line::from(">5ms"))
            .style(Style::default().fg(ERR)),
    ];

    let group = BarGroup::default().bars(&bars);
    let chart = BarChart::default()
        .block(
            Block::default()
                .title(" ◈ LATENCY (%) ")
                .title_style(Style::default().fg(ACCENT).add_modifier(Modifier::BOLD))
                .borders(Borders::ALL)
                .border_style(Style::default().fg(MUTED))
                .style(Style::default().bg(BG_PANEL)),
        )
        .data(group)
        .max(100)
        .bar_width(6)
        .bar_gap(2);

    frame.render_widget(chart, area);
}

// ─────────────────────────────────────────────────────────────────────────────
// Log pane
// ─────────────────────────────────────────────────────────────────────────────

fn draw_log_pane(frame: &mut Frame, app: &TuiApp, area: Rect) {
    let focus_border = if app.focus() == 2 { ACCENT } else { MUTED };

    // tui-logger widget integration placeholder — Phase 2 will wire the
    // tracing subscriber. For now render the tui-logger smart widget.
    let widget = tui_logger::TuiLoggerSmartWidget::default()
        .style_error(Style::default().fg(ERR))
        .style_warn(Style::default().fg(WARN))
        .style_info(Style::default().fg(Color::White))
        .style_debug(Style::default().fg(MUTED))
        .style_trace(Style::default().fg(MUTED))
        .output_separator('│')
        .output_timestamp(Some("%H:%M:%S%.3f".to_string()))
        .output_level(Some(tui_logger::TuiLoggerLevelOutput::Abbreviated))
        .output_target(false)
        .output_file(false)
        .output_line(false)
        .title_log(" ◈ LOGS ")
        .title_target(" TARGETS ")
        .border_style(Style::default().fg(focus_border));

    frame.render_widget(widget, area);
}

// ─────────────────────────────────────────────────────────────────────────────
// Help overlay
// ─────────────────────────────────────────────────────────────────────────────

fn draw_help_overlay(frame: &mut Frame, area: Rect) {
    let help_text = vec![
        Line::from(vec![Span::styled(
            " Keybindings ",
            Style::default().fg(ACCENT).add_modifier(Modifier::BOLD),
        )]),
        Line::from(""),
        Line::from(vec![
            Span::styled("  q / Ctrl+C ", Style::default().fg(WARN).add_modifier(Modifier::BOLD)),
            Span::raw("  Graceful shutdown"),
        ]),
        Line::from(vec![
            Span::styled("  Tab        ", Style::default().fg(ACCENT)),
            Span::raw("  Cycle pane focus"),
        ]),
        Line::from(vec![
            Span::styled("  ↑ / ↓     ", Style::default().fg(ACCENT)),
            Span::raw("  Scroll active pane"),
        ]),
        Line::from(vec![
            Span::styled("  p          ", Style::default().fg(ACCENT)),
            Span::raw("  Toggle PCAP capture"),
        ]),
        Line::from(vec![
            Span::styled("  c          ", Style::default().fg(ACCENT)),
            Span::raw("  Toggle CSV capture"),
        ]),
        Line::from(vec![
            Span::styled("  l          ", Style::default().fg(ACCENT)),
            Span::raw("  Cycle log verbosity"),
        ]),
        Line::from(vec![
            Span::styled("  ?          ", Style::default().fg(ACCENT)),
            Span::raw("  Toggle this help"),
        ]),
    ];

    // Centre the overlay.
    let width = 48u16.min(area.width);
    let height = (help_text.len() as u16 + 4).min(area.height);
    let x = area.x + (area.width.saturating_sub(width)) / 2;
    let y = area.y + (area.height.saturating_sub(height)) / 2;
    let popup_area = Rect::new(x, y, width, height);

    let overlay = Paragraph::new(Text::from(help_text))
        .block(
            Block::default()
                .title(" Help — press ? to close ")
                .title_style(Style::default().fg(ACCENT).add_modifier(Modifier::BOLD))
                .borders(Borders::ALL)
                .border_style(Style::default().fg(ACCENT))
                .style(Style::default().bg(BG_DARK)),
        )
        .wrap(Wrap { trim: false });

    frame.render_widget(ratatui::widgets::Clear, popup_area);
    frame.render_widget(overlay, popup_area);
}
