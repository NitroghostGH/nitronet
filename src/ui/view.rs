//! Drawing. Layout from top to bottom: the network panel (traffic graph),
//! the tab bar with the filter, the table, the detail pane, and the key hints.
//! This file has the frame, the header, the shared table code, the footer and
//! help; each tab's table and detail pane are in its own `*_view.rs`.

use ratatui::Frame;
use ratatui::layout::{Alignment, Constraint, Layout, Margin, Rect};
use ratatui::style::{Color, Modifier};
use ratatui::text::{Line, Span, Text};
use ratatui::widgets::{
    Block, BorderType, Cell, Clear, HighlightSpacing, Paragraph, Row, Scrollbar,
    ScrollbarOrientation, ScrollbarState, Table, TableState,
};

use super::devices_view::{draw_device_detail, draw_devices};
use super::fmt::human;
use super::procs_view::{draw_detail, draw_procs};
use super::sockets_view::draw_sockets;
use super::theme::theme;
use super::widgets::{Col, Graph, fit_columns, graph_max};
use super::{App, Tab};
use crate::sampler::Source;

pub(super) const SPACING: u16 = 2;
/// The table's selection marker ("▌ ") takes this many columns.
pub(super) const MARKER: u16 = 2;

pub fn draw(app: &mut App, f: &mut Frame) {
    let area = f.area();
    let compact = area.height < 22 || area.width < 70;
    let [header, body, footer] = Layout::vertical([
        Constraint::Length(if compact { 1 } else { 8 }),
        Constraint::Fill(1),
        Constraint::Length(1),
    ])
    .areas(area);

    if compact {
        draw_header_compact(app, f, header);
    } else {
        draw_header(app, f, header);
    }

    let views = app.proc_views();
    let socks = app.sock_rows();
    let devs = app.dev_rows();
    let pkts = app.pkt_rows();
    let flows = app.shown_flows();
    app.sync_selection(&views, &socks, &devs, &pkts, flows.as_deref());
    let flows = flows.unwrap_or_default();
    let tabs = tab_title(
        app,
        body,
        [views.len(), socks.len(), devs.len(), pkts.len()],
    );

    match app.tab {
        Tab::Procs => {
            let detail_h = (body.height / 3).clamp(11, 16);
            let with_detail = app.show_detail && body.height >= detail_h + 8 && !views.is_empty();
            let [table, detail] = Layout::vertical([
                Constraint::Fill(1),
                Constraint::Length(if with_detail { detail_h } else { 0 }),
            ])
            .areas(body);
            draw_procs(app, f, table, &views, tabs);
            if with_detail {
                let sel = app.proc_state.selected().unwrap_or(0).min(views.len() - 1);
                draw_detail(app, f, detail, &views[sel]);
            }
        }
        Tab::Sockets => draw_sockets(app, f, body, &socks, tabs),
        Tab::Devices => {
            let detail_h = (body.height / 3).clamp(11, 16);
            let with_detail = app.show_detail && body.height >= detail_h + 8 && !devs.is_empty();
            let [table, detail] = Layout::vertical([
                Constraint::Fill(1),
                Constraint::Length(if with_detail { detail_h } else { 0 }),
            ])
            .areas(body);
            draw_devices(app, f, table, &devs, tabs);
            if with_detail {
                let sel = app.dev_state.selected().unwrap_or(0).min(devs.len() - 1);
                draw_device_detail(app, f, detail, devs[sel]);
            }
        }
        Tab::Packets => super::packets_view::draw(app, f, body, &pkts, &flows, tabs),
    }

    draw_footer(app, f, footer);
    if app.show_help {
        draw_help(f, area);
    }
    if app.show_diagram {
        super::diagram::draw(app, f, area);
    }
}

// ------------------------------------------------------------------ header

fn source_badge(app: &App) -> Vec<Span<'static>> {
    let t = theme();
    let mut spans = match &app.snap.source {
        Source::Ebpf { .. } => vec![
            Span::styled("● ", t.fg(t.good)),
            Span::styled("eBPF", t.fg(t.text)),
        ],
        Source::TcpInfo { .. } => {
            vec![
                Span::styled("● ", t.fg(t.warn)),
                Span::styled("tcp_info · TCP only", t.fg(t.text)),
            ]
        }
    };
    spans.push(Span::styled(format!("  {}", fmt_interval(app)), t.muted()));
    if app.snap.baseline {
        spans.push(Span::styled("  measuring…", t.muted()));
    }
    if app.paused {
        spans.push(Span::raw("  "));
        spans.push(Span::styled(" PAUSED ", t.badge(t.warn)));
    }
    spans
}

fn fmt_interval(app: &App) -> String {
    let s = app.interval.as_secs_f64();
    if s.fract() == 0.0 {
        format!("{s:.0}s")
    } else {
        format!("{s}s")
    }
}

fn draw_header(app: &mut App, f: &mut Frame, area: Rect) {
    let t = theme();
    let s = &app.snap;

    let mut bottom_left = vec![
        Span::raw(" "),
        Span::styled("attributed ", t.muted()),
        Span::styled(format!("↓{}/s", human(s.seen_rate.0)), t.fg(t.rx)),
        Span::raw(" "),
        Span::styled(format!("↑{}/s", human(s.seen_rate.1)), t.fg(t.tx)),
        Span::styled(" · ", t.faint()),
        Span::styled(s.sockets.len().to_string(), t.fg(t.text)),
        Span::styled(" sockets · ", t.muted()),
        Span::styled(
            s.sockets
                .iter()
                .filter(|r| r.sock.is_listening())
                .count()
                .to_string(),
            t.fg(t.text),
        ),
        Span::styled(" listening ", t.muted()),
    ];
    if s.closed_sockets > 0 {
        bottom_left.pop();
        bottom_left.push(Span::styled(" listening · ", t.muted()));
        bottom_left.push(Span::styled(s.closed_sockets.to_string(), t.fg(t.text)));
        bottom_left.push(Span::styled(" closed ", t.muted()));
    }
    let mut bottom_right = Vec::new();
    if let Source::TcpInfo { reason } = &s.source {
        bottom_right.push(Span::styled(format!(" {} ", reason.short()), t.fg(t.warn)));
    }
    if !s.is_root && s.hidden_procs > 0 {
        bottom_right.push(Span::styled(
            format!(" {} processes hidden · run as root ", s.hidden_procs),
            t.fg(t.warn),
        ));
    }

    let mut title = vec![
        Span::raw(" "),
        Span::styled("nitronet", t.fg(t.accent).add_modifier(Modifier::BOLD)),
    ];
    title.push(Span::styled(
        if s.nic_rate.is_some() {
            " · network "
        } else {
            " · attributed traffic "
        },
        t.muted(),
    ));
    let mut badges = source_badge(app);
    badges.push(Span::raw(" "));

    let block = panel()
        .title(Line::from(title))
        .title_top(Line::from(badges).right_aligned())
        .title_bottom(Line::from(bottom_left))
        .title_bottom(Line::from(bottom_right).right_aligned());
    let inner = block.inner(area);
    f.render_widget(block, area);

    let [stats, graph] = Layout::horizontal([Constraint::Length(32), Constraint::Fill(1)])
        .spacing(2)
        .areas(inner.inner(Margin::new(1, 0)));

    let (now_in, now_out) = (
        app.history.total_in.back().copied(),
        app.history.total_out.back().copied(),
    );
    let total = s.nic_total;
    let stat = |arrow: &str,
                label: &str,
                color: Color,
                now: Option<f64>,
                peak: f64,
                total: Option<u64>| {
        vec![
            Line::from(vec![
                Span::styled(format!("{arrow} "), t.fg(color)),
                Span::styled(label.to_string(), t.muted()),
            ]),
            Line::from(vec![
                Span::raw("  "),
                Span::styled(format!("{}/s", human(now.unwrap_or(0.0))), t.title()),
            ]),
            Line::from(vec![
                Span::styled("  peak ", t.faint()),
                Span::styled(human(peak), t.muted()),
                Span::styled(if total.is_some() { "  total " } else { "" }, t.faint()),
                Span::styled(
                    total.map(|b| human(b as f64)).unwrap_or_default(),
                    t.muted(),
                ),
            ]),
        ]
    };
    let mut lines = stat(
        "↓",
        "download",
        t.rx,
        now_in,
        app.history.peak.0,
        total.map(|t| t.0),
    );
    lines.extend(stat(
        "↑",
        "upload",
        t.tx,
        now_out,
        app.history.peak.1,
        total.map(|t| t.1),
    ));
    f.render_widget(Paragraph::new(lines), stats);

    draw_mirrored_graph(
        f,
        graph,
        &app.history.total_in.iter().copied().collect::<Vec<_>>(),
        &app.history.total_out.iter().copied().collect::<Vec<_>>(),
    );
}

/// Download grows up from the middle and upload grows down from it, each with
/// its own scale. The scale is labelled in the outer corner.
pub(super) fn draw_mirrored_graph(f: &mut Frame, area: Rect, data_in: &[f64], data_out: &[f64]) {
    let t = theme();
    if area.width < 4 || area.height < 2 {
        return;
    }
    let [top, bottom] = Layout::vertical([
        Constraint::Length(area.height.div_ceil(2)),
        Constraint::Fill(1),
    ])
    .areas(area);
    let visible = area.width as usize * 2;
    let (max_in, max_out) = (graph_max(data_in, visible), graph_max(data_out, visible));
    f.render_widget(
        Graph {
            data: data_in,
            max: max_in,
            base: t.rx_dim,
            peak: t.rx,
            down: false,
        },
        top,
    );
    f.render_widget(
        Graph {
            data: data_out,
            max: max_out,
            base: t.tx_dim,
            peak: t.tx,
            down: true,
        },
        bottom,
    );

    let label =
        |v: f64| Line::from(Span::styled(format!(" {}/s", human(v)), t.faint())).right_aligned();
    f.render_widget(label(max_in), Rect { height: 1, ..top });
    f.render_widget(
        label(max_out),
        Rect {
            y: bottom.bottom().saturating_sub(1),
            height: 1,
            ..bottom
        },
    );
}

fn draw_header_compact(app: &App, f: &mut Frame, area: Rect) {
    let t = theme();
    let (rx, tx) = app.snap.nic_rate.unwrap_or(app.snap.seen_rate);
    let mut spans = vec![
        Span::styled(" nitronet ", t.badge(t.accent)),
        Span::raw("  "),
        Span::styled(format!("↓ {}/s", human(rx)), t.fg(t.rx)),
        Span::raw("  "),
        Span::styled(format!("↑ {}/s", human(tx)), t.fg(t.tx)),
        Span::raw("   "),
    ];
    spans.extend(source_badge(app));
    f.render_widget(Paragraph::new(Line::from(spans)), area);
}

// ------------------------------------------------------------------ tabs

/// The view switcher, drawn into the table panel's top border. The active
/// view is a filled pill. Click regions are recorded for the mouse.
fn tab_title(app: &mut App, panel: Rect, counts: [usize; 4]) -> Line<'static> {
    let t = theme();
    app.hit.tabs.clear();
    // Block titles start one cell in from the corner.
    let mut x = panel.x + 1;
    let mut spans = Vec::new();
    let [n_procs, n_socks, n_devs, n_pkts] = counts;
    for (tab, name, n) in [
        (Tab::Procs, "Processes", n_procs),
        (Tab::Sockets, "Sockets", n_socks),
        (Tab::Devices, "Devices", n_devs),
        (Tab::Packets, "Packets", n_pkts),
    ] {
        let active = app.tab == tab;
        let label = format!(" {name} {n} ");
        let w = label.chars().count() as u16;
        if active {
            spans.push(Span::styled(label, t.badge(t.accent)));
        } else {
            spans.push(Span::styled(format!(" {name} "), t.muted()));
            spans.push(Span::styled(format!("{n} "), t.faint()));
        }
        spans.push(Span::styled("─", t.fg(t.border)));
        app.hit.tabs.push((Rect::new(x, panel.y, w, 1), tab));
        x += w + 1;
    }
    spans.pop();
    Line::from(spans)
}

/// The filter, drawn into the table panel's bottom border.
pub(super) fn filter_line(app: &App) -> Line<'static> {
    let t = theme();
    if app.editing_filter {
        Line::from(vec![
            Span::styled(" / ", t.fg(t.accent).add_modifier(Modifier::BOLD)),
            Span::styled(app.filter.clone(), t.fg(t.text)),
            Span::styled("▏", t.fg(t.accent)),
            Span::styled("  enter keep · esc clear ", t.faint()),
        ])
    } else if !app.filter.is_empty() {
        Line::from(vec![
            Span::styled(" filter ", t.muted()),
            Span::styled(format!(" {} ", app.filter), t.badge(t.accent)),
            Span::styled("  esc clear ", t.faint()),
        ])
    } else {
        Line::default()
    }
}

// ------------------------------------------------------------------ tables

pub(super) fn panel() -> Block<'static> {
    let t = theme();
    Block::bordered()
        .border_type(BorderType::Rounded)
        .border_style(t.fg(t.border))
}

fn sort_arrow(desc: bool) -> &'static str {
    if desc { " ▾" } else { " ▴" }
}

/// Draws a responsive table into a bordered panel: columns that don't fit are
/// dropped by priority, and there's a scrollbar and an empty-state message.
/// The rows a table on `area` can show this frame. ratatui keeps the scroll
/// offset, or moves it just enough to show the selection, so a screenful
/// either side of both covers it. Callers build cells only for these rows
/// and pass empty ones for the rest, which keeps a frame cheap with
/// thousands of packets.
pub(super) fn table_window(app: &App, len: usize, area: Rect) -> std::ops::Range<usize> {
    let state = match app.tab {
        Tab::Procs => &app.proc_state,
        Tab::Sockets => &app.sock_state,
        Tab::Devices => &app.dev_state,
        Tab::Packets if app.pkt_flows => &app.flow_state,
        Tab::Packets => &app.pkt_state,
    };
    let h = area.height as usize;
    let last = len.saturating_sub(1);
    let sel = state.selected().unwrap_or(0).min(last);
    let off = state.offset().min(last);
    let lo = off.min(sel).saturating_sub(h);
    let hi = (off.max(sel) + h + 1).min(len);
    lo..hi
}

/// Draws a table. `rows` has one entry per row; rows outside `table_window`
/// may be empty.
#[allow(clippy::too_many_arguments)]
pub(super) fn draw_table(
    app: &mut App,
    f: &mut Frame,
    area: Rect,
    block: Block<'static>,
    cols: &[Col],
    sorted: (usize, bool),
    rows: Vec<Vec<Cell<'static>>>,
    empty: &str,
) {
    let t = theme();
    let inner = block.inner(area);
    f.render_widget(block, area);
    let inner = inner.inner(Margin::new(1, 0));
    let len = rows.len();

    let avail = inner.width.saturating_sub(MARKER);
    let shown = fit_columns(cols, avail, SPACING);
    let header = Row::new(shown.iter().map(|&i| {
        let c = &cols[i];
        let mut spans = vec![Span::styled(c.title, t.header())];
        if i == sorted.0 {
            spans.push(Span::styled(
                sort_arrow(sorted.1),
                t.fg(t.accent).add_modifier(Modifier::BOLD),
            ));
        }
        let line = Line::from(spans);
        Cell::from(if c.right { line.right_aligned() } else { line })
    }));
    let rows = rows.into_iter().map(|cells| {
        if cells.is_empty() {
            return Row::default();
        }
        let mut cells: Vec<Option<Cell>> = cells.into_iter().map(Some).collect();
        Row::new(
            shown
                .iter()
                .map(|&i| cells[i].take().unwrap_or_default())
                .collect::<Vec<_>>(),
        )
    });
    let widths: Vec<Constraint> = shown.iter().map(|&i| cols[i].constraint()).collect();

    let state = match app.tab {
        Tab::Procs => &mut app.proc_state,
        Tab::Sockets => &mut app.sock_state,
        Tab::Devices => &mut app.dev_state,
        Tab::Packets if app.pkt_flows => &mut app.flow_state,
        Tab::Packets => &mut app.pkt_state,
    };
    clamp(state, len);
    let table = Table::new(rows, widths)
        .header(header)
        .column_spacing(SPACING)
        .row_highlight_style(t.selected())
        .highlight_symbol(Text::from(Span::styled("▌ ", t.fg(t.accent))))
        .highlight_spacing(HighlightSpacing::Always);
    f.render_stateful_widget(table, inner, state);
    let offset = state.offset();

    app.hit.rows = Rect {
        y: inner.y + 1,
        height: inner.height.saturating_sub(1),
        ..inner
    };

    if len == 0 {
        let msg = Paragraph::new(Line::from(Span::styled(empty.to_string(), t.muted())))
            .alignment(Alignment::Center);
        let mid = Rect {
            y: inner.y + inner.height / 2,
            height: 1,
            ..inner
        };
        f.render_widget(msg, mid);
    }

    let visible = inner.height.saturating_sub(1) as usize;
    if len > visible {
        let mut sb = ScrollbarState::new(len.saturating_sub(visible)).position(offset);
        f.render_stateful_widget(
            Scrollbar::new(ScrollbarOrientation::VerticalRight)
                .begin_symbol(None)
                .end_symbol(None)
                .track_symbol(Some("│"))
                .track_style(t.fg(t.border))
                .thumb_symbol("┃")
                .thumb_style(t.fg(t.muted)),
            area.inner(Margin::new(0, 1)),
            &mut sb,
        );
    }
}

fn clamp(state: &mut TableState, len: usize) {
    let sel = state.selected().unwrap_or(0);
    state.select(if len == 0 {
        None
    } else {
        Some(sel.min(len - 1))
    });
}

pub(super) fn empty_message(app: &App, what: &str) -> String {
    if app.filter.is_empty() {
        format!("no {what}")
    } else {
        format!("no {what} match “{}”", app.filter)
    }
}

// ------------------------------------------------------------------ footer & help

fn draw_footer(app: &App, f: &mut Frame, area: Rect) {
    let t = theme();
    if let Some(msg) = app.flash_text() {
        let line = Line::from(vec![
            Span::styled(" ▸ ", t.fg(t.accent).add_modifier(Modifier::BOLD)),
            Span::styled(msg.to_string(), t.fg(t.text)),
        ]);
        f.render_widget(Paragraph::new(line), area);
        return;
    }
    let mut hints: Vec<(&str, &str)> = if app.tab == Tab::Packets {
        // There are many keys here, so the packet ones go first.
        super::packets_view::hints(app)
    } else {
        vec![
            ("q", "quit"),
            ("?", "help"),
            ("/", "filter"),
            ("tab", "switch"),
            ("s", "sort"),
        ]
    };
    match app.tab {
        Tab::Procs => {
            hints.push(("c", "capture packets"));
            hints.push((
                "g",
                if app.group_by_program {
                    "ungroup"
                } else {
                    "group"
                },
            ));
            hints.push((
                "enter",
                if app.show_detail {
                    "hide detail"
                } else {
                    "detail"
                },
            ));
        }
        Tab::Sockets => hints.push((
            "l",
            if app.listening_only {
                "all sockets"
            } else {
                "listening"
            },
        )),
        Tab::Devices => {
            hints.push(("p", "probe ports"));
            hints.push(("R", "rescan"));
            hints.push((
                "enter",
                if app.show_detail {
                    "hide detail"
                } else {
                    "detail"
                },
            ));
        }
        Tab::Packets => {}
    }
    if app.tab != Tab::Packets {
        hints.push(("space", if app.paused { "resume" } else { "pause" }));
        hints.push(("H", "how it works"));
    }

    let mut spans = vec![Span::raw(" ")];
    let mut used = 1;
    for (k, label) in hints {
        let w = k.chars().count() + label.chars().count() + 3;
        if used + w > area.width as usize {
            break;
        }
        spans.push(Span::styled(
            k.to_string(),
            t.fg(t.accent).add_modifier(Modifier::BOLD),
        ));
        spans.push(Span::styled(format!(" {label}  "), t.muted()));
        used += w;
    }
    f.render_widget(Paragraph::new(Line::from(spans)), area);
}

fn draw_help(f: &mut Frame, area: Rect) {
    let t = theme();
    let sections: [(&str, &[(&str, &str)]); 5] = [
        (
            "navigate",
            &[
                ("↑ ↓  j k", "move selection"),
                ("PgUp PgDn", "move by a page"),
                ("Home End", "first / last row"),
                ("tab ← →  1-4", "switch view"),
                ("mouse", "click rows and tabs, wheel scrolls"),
            ],
        ),
        (
            "view",
            &[
                ("/", "filter: all words match, !word excludes"),
                ("s  r", "cycle sort · reverse it"),
                ("g", "group processes by program"),
                ("l", "only listening sockets"),
                ("enter  d", "toggle the detail pane"),
            ],
        ),
        (
            "devices",
            &[
                ("p", "check the device's common ports"),
                ("R  F5", "rescan the network now"),
            ],
        ),
        (
            "packets",
            &[
                ("c", "capture the selected program (root)"),
                ("i", "sent · received · both"),
                ("e", "all · data · unencrypted · logins"),
                ("f", "conversations; enter opens one"),
                ("t", "payload as text or hex"),
                ("[  ]", "scroll the payload"),
                ("x", "clear the captured list"),
            ],
        ),
        (
            "general",
            &[
                ("space", "pause the display"),
                ("?", "this help"),
                ("H", "how nitronet works (diagram)"),
                ("q  esc", "quit"),
            ],
        ),
    ];
    let mut lines = Vec::new();
    for (i, (name, keys)) in sections.iter().enumerate() {
        if i > 0 {
            lines.push(Line::default());
        }
        lines.push(Line::from(Span::styled(name.to_uppercase(), t.header())));
        for (k, d) in keys.iter() {
            lines.push(Line::from(vec![
                Span::styled(
                    format!("  {k:<14}"),
                    t.fg(t.accent).add_modifier(Modifier::BOLD),
                ),
                Span::styled(d.to_string(), t.fg(t.text)),
            ]));
        }
    }
    lines.push(Line::default());
    lines.push(Line::from(Span::styled("COLORS", t.header())));
    lines.push(Line::from(vec![
        Span::styled("  ↓ download", t.fg(t.rx)),
        Span::styled("   ↑ upload", t.fg(t.tx)),
    ]));
    lines.push(Line::from(vec![
        Span::styled("  ports ", t.muted()),
        Span::styled("tcp", t.fg(t.tcp)),
        Span::styled(" · ", t.faint()),
        Span::styled("udp", t.fg(t.udp)),
        Span::styled(" · ", t.faint()),
        Span::styled("both", t.fg(t.good)),
    ]));
    lines.push(Line::default());
    lines.push(Line::from(Span::styled("press any key to close", t.faint())).centered());

    let h = (lines.len() as u16 + 2).min(area.height);
    let popup = area.centered(
        Constraint::Length(64.min(area.width)),
        Constraint::Length(h),
    );
    f.render_widget(Clear, popup);
    let block = Block::bordered()
        .border_type(BorderType::Rounded)
        .border_style(t.fg(t.border_focus))
        .title(Line::from(vec![
            Span::raw(" "),
            Span::styled("keys", t.title()),
            Span::raw(" "),
        ]));
    f.render_widget(
        Paragraph::new(lines).block(block.padding(ratatui::widgets::Padding::horizontal(1))),
        popup,
    );
}
