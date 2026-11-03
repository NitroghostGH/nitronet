//! Drawing. Layout from top to bottom: the network panel (traffic graph),
//! the tab bar with the filter, the table, the detail pane, and the key hints.

use std::collections::HashSet;
use std::net::SocketAddr;

use ratatui::Frame;
use ratatui::layout::{Alignment, Constraint, Layout, Margin, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span, Text};
use ratatui::widgets::{
    Block, BorderType, Cell, Clear, HighlightSpacing, Paragraph, Row, Scrollbar,
    ScrollbarOrientation, ScrollbarState, Table, TableState,
};

use super::fmt::{ago, amount, elide_end, elide_middle, fmt_addr, fmt_rtt, human, short_v6};
use super::theme::{Theme, theme};
use super::widgets::{Col, Graph, col, fit_columns, graph_max, traffic_bar};
use super::{App, DevSort, ProcSort, ProcView, SockSort, Tab};
use crate::lan::discover::fmt_mac;
use crate::lan::identify::{PROBE_PORTS, port_name};
use crate::lan::{DevKey, Device, Method};
use crate::netlink::Proto;
use crate::sampler::{Owner, SockRow, Source};
use std::net::Ipv6Addr;

const SPACING: u16 = 2;
/// The table's selection marker ("▌ ") takes this many columns.
const MARKER: u16 = 2;

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
    app.sync_selection(&views, &socks, &devs);
    let tabs = tab_title(app, body, [views.len(), socks.len(), devs.len()]);

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
    }

    draw_footer(app, f, footer);
    if app.show_help {
        draw_help(f, area);
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
        bottom_right.push(Span::styled(
            format!(" {} ", reason.lines().next().unwrap_or_default()),
            t.fg(t.warn),
        ));
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
fn draw_mirrored_graph(f: &mut Frame, area: Rect, data_in: &[f64], data_out: &[f64]) {
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
fn tab_title(app: &mut App, panel: Rect, counts: [usize; 3]) -> Line<'static> {
    let t = theme();
    app.hit.tabs.clear();
    // Block titles start one cell in from the corner.
    let mut x = panel.x + 1;
    let mut spans = Vec::new();
    let [n_procs, n_socks, n_devs] = counts;
    for (tab, name, n) in [
        (Tab::Procs, "Processes", n_procs),
        (Tab::Sockets, "Sockets", n_socks),
        (Tab::Devices, "Devices", n_devs),
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
fn filter_line(app: &App) -> Line<'static> {
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

fn panel() -> Block<'static> {
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
#[allow(clippy::too_many_arguments)]
fn draw_table(
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

fn empty_message(app: &App, what: &str) -> String {
    if app.filter.is_empty() {
        format!("no {what}")
    } else {
        format!("no {what} match “{}”", app.filter)
    }
}

const PROC_COLS: [Col; 11] = [
    col("PID", 7, 3).right(),
    col("PROGRAM", 16, 0).flex(),
    col("SERVICE", 18, 5),
    col("USER", 9, 4),
    col("↓ RATE", 10, 1).right(),
    col("↑ RATE", 10, 1).right(),
    col("TRAFFIC", 14, 6),
    col("↓ TOTAL", 10, 2).right(),
    col("↑ TOTAL", 10, 2).right(),
    col("CONN", 4, 3).right(),
    col("PORTS", 22, 7),
];

fn draw_procs(app: &mut App, f: &mut Frame, area: Rect, views: &[ProcView], tabs: Line<'static>) {
    let t = theme();
    let max_rate = views
        .iter()
        .map(|v| v.row.rate_in + v.row.rate_out)
        .fold(0.0, f64::max);
    let rows = views.iter().map(|v| proc_cells(t, v, max_rate)).collect();
    let (sorted_col, desc) = match app.proc_sort {
        ProcSort::Rate => (4, true),
        ProcSort::Total => (7, true),
        ProcSort::Name => (1, false),
        ProcSort::Pid => (0, false),
    };
    let mut info = vec![Span::styled(" sort ", t.faint())];
    info.push(Span::styled(
        match app.proc_sort {
            ProcSort::Rate => "rate",
            ProcSort::Total => "total",
            ProcSort::Name => "name",
            ProcSort::Pid => "pid",
        },
        t.muted(),
    ));
    if app.group_by_program {
        info.push(Span::styled(" · ", t.faint()));
        info.push(Span::styled("grouped by program", t.fg(t.accent)));
    }
    info.push(Span::raw(" "));
    let block = panel()
        .title(tabs)
        .title_top(Line::from(info).right_aligned())
        .title_bottom(filter_line(app));
    let empty = empty_message(app, "processes");
    draw_table(
        app,
        f,
        area,
        block,
        &PROC_COLS,
        (sorted_col, desc != app.reverse),
        rows,
        &empty,
    );
}

fn proc_cells(t: &Theme, v: &ProcView, max_rate: f64) -> Vec<Cell<'static>> {
    let r = &v.row;
    let pseudo = !matches!(r.owner, Owner::Pid(_));
    let pid = match (r.owner, v.owners.len()) {
        (_, n) if n > 1 => Span::styled(format!("×{n}"), t.fg(t.accent)),
        (Owner::Pid(p), _) => Span::styled(p.to_string(), t.muted()),
        _ => Span::styled("—", t.faint()),
    };
    let mut name = vec![Span::styled(
        r.name.clone(),
        if pseudo {
            t.muted().add_modifier(Modifier::ITALIC)
        } else if r.alive {
            t.fg(t.text)
        } else {
            t.muted()
        },
    )];
    if !r.alive {
        name.push(Span::styled(
            "  exited",
            t.faint().add_modifier(Modifier::ITALIC),
        ));
    }
    let user_style = if r.user == "root" {
        t.fg(t.warn)
    } else {
        t.muted()
    };
    let conn = if r.sockets == 0 {
        Span::styled("·", t.faint())
    } else {
        Span::styled(r.sockets.to_string(), t.muted())
    };
    vec![
        Cell::from(Line::from(pid).right_aligned()),
        Cell::from(Line::from(name)),
        Cell::from(Span::styled(
            elide_end(r.unit.as_deref().unwrap_or(""), 18),
            t.muted(),
        )),
        Cell::from(Span::styled(elide_end(&r.user, 9), user_style)),
        Cell::from(amount(Some(r.rate_in), t.rx)),
        Cell::from(amount(Some(r.rate_out), t.tx)),
        Cell::from(traffic_bar(
            r.rate_in,
            r.rate_out,
            max_rate,
            PROC_COLS[6].width,
        )),
        Cell::from(amount(Some(r.total_in as f64), t.text)),
        Cell::from(amount(Some(r.total_out as f64), t.text)),
        Cell::from(Line::from(conn).right_aligned()),
        Cell::from(ports_line(&r.listening, PROC_COLS[10].width as usize)),
    ]
}

/// Listening ports colored by protocol (a port open on both TCP and UDP is
/// shown once, in the "both" color), cut off with "+N" if too long.
fn ports_line(ports: &[(Proto, u16)], width: usize) -> Line<'static> {
    let t = theme();
    let mut merged: Vec<(u16, Color)> = Vec::new();
    let mut sorted = ports.to_vec();
    sorted.sort_by_key(|&(proto, port)| (port, proto));
    for (proto, port) in sorted {
        match merged.last_mut() {
            Some((p, c)) if *p == port => *c = t.good,
            _ => merged.push((port, proto_color(t, proto))),
        }
    }
    let mut spans = Vec::new();
    let mut used = 0;
    for (i, (port, color)) in merged.iter().enumerate() {
        let s = port.to_string();
        let rest = merged.len() - i;
        let more = format!("+{rest}");
        let need = s.len() + usize::from(i > 0);
        if used + need + if rest > 1 { more.len() + 1 } else { 0 } > width {
            spans.push(Span::styled(format!(" {more}"), t.muted()));
            break;
        }
        if i > 0 {
            spans.push(Span::raw(" "));
        }
        spans.push(Span::styled(s, t.fg(*color)));
        used += need;
    }
    Line::from(spans)
}

fn proto_color(t: &Theme, p: Proto) -> Color {
    match p {
        Proto::Tcp => t.tcp,
        Proto::Udp => t.udp,
    }
}

const SOCK_COLS: [Col; 11] = [
    col("PROTO", 5, 0),
    col("LOCAL", 22, 0).flex(),
    col("REMOTE", 22, 1).flex(),
    col("STATE", 11, 1),
    col("PROCESS", 16, 0),
    col("PID", 7, 4).right(),
    col("↓ RATE", 10, 2).right(),
    col("↑ RATE", 10, 2).right(),
    col("TRAFFIC", 12, 6),
    col("↓ BYTES", 10, 3).right(),
    col("↑ BYTES", 10, 3).right(),
];

fn draw_sockets(app: &mut App, f: &mut Frame, area: Rect, idx: &[usize], tabs: Line<'static>) {
    let t = theme();
    let socks: Vec<&SockRow> = idx.iter().map(|&i| &app.snap.sockets[i]).collect();
    let names = app.owner_names();
    // Work out how wide the two flexible address columns will be, so the
    // addresses can be shortened in the middle rather than cut off at the end.
    let avail = area.width.saturating_sub(4 + MARKER);
    let shown = fit_columns(&SOCK_COLS, avail, SPACING);
    let fixed: u16 = shown
        .iter()
        .filter(|&&i| !SOCK_COLS[i].flex)
        .map(|&i| SOCK_COLS[i].width + SPACING)
        .sum();
    let n_flex = shown.iter().filter(|&&i| SOCK_COLS[i].flex).count().max(1) as u16;
    let addr_w = (avail.saturating_sub(fixed + SPACING) / n_flex).max(8) as usize;

    let max_rate = socks
        .iter()
        .map(|s| s.rate_in.unwrap_or(0.0) + s.rate_out.unwrap_or(0.0))
        .fold(0.0, f64::max);
    let rows = socks
        .iter()
        .map(|s| {
            let name = names
                .iter()
                .find(|(o, _)| *o == s.owner)
                .map_or("?", |(_, n)| n.as_str());
            sock_cells(t, s, name, addr_w, max_rate)
        })
        .collect();
    let (sorted_col, desc) = match app.sock_sort {
        SockSort::Rate => (6, true),
        SockSort::Port => (1, false),
        SockSort::State => (3, false),
        SockSort::Program => (4, false),
    };
    let mut info = vec![Span::styled(" sort ", t.faint())];
    info.push(Span::styled(
        match app.sock_sort {
            SockSort::Rate => "rate",
            SockSort::Port => "port",
            SockSort::State => "state",
            SockSort::Program => "program",
        },
        t.muted(),
    ));
    if app.listening_only {
        info.push(Span::styled(" · ", t.faint()));
        info.push(Span::styled("listening only", t.fg(t.good)));
    }
    info.push(Span::raw(" "));
    let block = panel()
        .title(tabs)
        .title_top(Line::from(info).right_aligned())
        .title_bottom(filter_line(app));
    let empty = empty_message(app, "sockets");
    draw_table(
        app,
        f,
        area,
        block,
        &SOCK_COLS,
        (sorted_col, desc != app.reverse),
        rows,
        &empty,
    );
}

fn sock_cells(
    t: &Theme,
    s: &SockRow,
    name: &str,
    addr_w: usize,
    max_rate: f64,
) -> Vec<Cell<'static>> {
    let pseudo = !matches!(s.owner, Owner::Pid(_));
    let pid = match s.owner {
        Owner::Pid(p) => Span::styled(p.to_string(), t.muted()),
        _ => Span::styled("—", t.faint()),
    };
    let bytes = |b: Option<u64>| amount(b.map(|b| b as f64), t.text);
    vec![
        Cell::from(Span::styled(
            s.sock.proto.as_str(),
            t.fg(proto_color(t, s.sock.proto))
                .add_modifier(Modifier::BOLD),
        )),
        Cell::from(addr_line(s.sock.local, addr_w)),
        Cell::from(addr_line(s.sock.remote, addr_w)),
        Cell::from(Span::styled(
            s.sock.state_str(),
            state_style(t, s.sock.state_str()),
        )),
        Cell::from(Span::styled(
            elide_end(name, 16),
            if pseudo {
                t.muted().add_modifier(Modifier::ITALIC)
            } else {
                t.fg(t.text)
            },
        )),
        Cell::from(Line::from(pid).right_aligned()),
        Cell::from(amount(s.rate_in, t.rx)),
        Cell::from(amount(s.rate_out, t.tx)),
        Cell::from(traffic_bar(
            s.rate_in.unwrap_or(0.0),
            s.rate_out.unwrap_or(0.0),
            max_rate,
            SOCK_COLS[8].width,
        )),
        Cell::from(bytes(s.bytes.map(|b| b.0))),
        Cell::from(bytes(s.bytes.map(|b| b.1))),
    ]
}

/// An address with the host muted and the port bright, since the port is
/// usually what you're scanning for.
fn addr_line(a: SocketAddr, width: usize) -> Line<'static> {
    let t = theme();
    let s = elide_middle(&fmt_addr(a), width);
    if s == "*" {
        return Line::from(Span::styled("*", t.faint()));
    }
    match s.rfind(':') {
        Some(i) => Line::from(vec![
            Span::styled(s[..i].to_string(), t.muted()),
            Span::styled(s[i..].to_string(), t.fg(t.text)),
        ]),
        None => Line::from(Span::styled(s, t.muted())),
    }
}

fn state_style(t: &Theme, state: &str) -> Style {
    match state {
        "LISTEN" => t.fg(t.good),
        "ESTAB" => t.fg(t.text),
        "UNCONN" => t.muted(),
        "TIME-WAIT" | "CLOSE" => t.faint(),
        "SYN-SENT" | "SYN-RECV" | "NEW-SYN-RECV" => t.fg(t.accent),
        _ => t.fg(t.warn),
    }
}

// ------------------------------------------------------------------ detail

fn draw_detail(app: &App, f: &mut Frame, area: Rect, v: &ProcView) {
    let t = theme();
    let r = &v.row;
    let mut sub = Vec::new();
    match (r.owner, v.owners.len()) {
        (_, n) if n > 1 => sub.push(format!("{n} processes")),
        (Owner::Pid(p), _) => sub.push(format!("pid {p}")),
        _ => {}
    }
    sub.push(r.user.clone());
    if let Some(u) = &r.unit {
        sub.push(format!("{u}.service"));
    }
    let title = Line::from(vec![
        Span::raw(" "),
        Span::styled(r.name.clone(), t.title()),
        Span::styled(format!("  {} ", sub.join(" · ")), t.muted()),
    ]);
    let block = panel().title(title);
    let inner = block.inner(area).inner(Margin::new(1, 0));
    f.render_widget(block, area);

    let [stats, graph, conns] = Layout::horizontal([
        Constraint::Length(24),
        Constraint::Fill(2),
        Constraint::Fill(3),
    ])
    .spacing(3)
    .areas(inner);

    // Stats
    let kv = |k: &str, v: Vec<Span<'static>>| {
        let mut spans = vec![Span::styled(format!("{k:<10}"), t.faint())];
        spans.extend(v);
        Line::from(spans)
    };
    let mut lines = vec![
        kv(
            "download",
            vec![Span::styled(format!("{}/s", human(r.rate_in)), t.fg(t.rx))],
        ),
        kv(
            "upload",
            vec![Span::styled(format!("{}/s", human(r.rate_out)), t.fg(t.tx))],
        ),
        Line::default(),
        kv(
            "total ↓",
            vec![Span::styled(human(r.total_in as f64), t.fg(t.text))],
        ),
        kv(
            "total ↑",
            vec![Span::styled(human(r.total_out as f64), t.fg(t.text))],
        ),
        kv(
            "sockets",
            vec![Span::styled(r.sockets.to_string(), t.fg(t.text))],
        ),
    ];
    if !r.listening.is_empty() {
        let mut l = vec![Span::styled(format!("{:<10}", "listening"), t.faint())];
        l.extend(ports_line(&r.listening, stats.width.saturating_sub(10) as usize).spans);
        lines.push(Line::from(l));
    }
    f.render_widget(Paragraph::new(lines), stats);

    // Graph
    let (si, so) = app.history.series(&v.owners);
    draw_mirrored_graph(f, graph, &si, &so);

    // Connections, busiest first
    let owners: HashSet<Owner> = v.owners.iter().copied().collect();
    let mut socks: Vec<&SockRow> = app
        .snap
        .sockets
        .iter()
        .filter(|s| owners.contains(&s.owner))
        .collect();
    let rate = |s: &SockRow| s.rate_in.unwrap_or(0.0) + s.rate_out.unwrap_or(0.0);
    socks.sort_by(|a, b| {
        rate(b)
            .total_cmp(&rate(a))
            .then(a.sock.is_listening().cmp(&b.sock.is_listening()))
    });
    let addr_w = conns.width.saturating_sub(4 + 11 + 10 + 10 + 3) as usize;
    let rows: Vec<Row> = socks
        .iter()
        .map(|s| {
            let peer = if s.sock.is_listening() {
                s.sock.local
            } else {
                s.sock.remote
            };
            let mut conn = vec![Span::styled(
                format!("{:<4}", s.sock.proto.as_str()),
                t.fg(proto_color(t, s.sock.proto)),
            )];
            conn.extend(addr_line(peer, addr_w.max(8)).spans);
            Row::new(vec![
                Cell::from(Line::from(conn)),
                Cell::from(Span::styled(
                    s.sock.state_str(),
                    state_style(t, s.sock.state_str()),
                )),
                Cell::from(amount(s.rate_in, t.rx)),
                Cell::from(amount(s.rate_out, t.tx)),
            ])
        })
        .collect();
    let n = rows.len();
    let table = Table::new(
        rows,
        [
            Constraint::Fill(1),
            Constraint::Length(11),
            Constraint::Length(10),
            Constraint::Length(10),
        ],
    )
    .column_spacing(1)
    .header(Row::new(vec![
        Cell::from(Line::from(vec![
            Span::styled("CONNECTIONS", t.header()),
            Span::styled(format!(" {n}"), t.muted()),
        ])),
        Cell::from(Span::styled("STATE", t.header())),
        Cell::from(Line::from(Span::styled("↓", t.header())).right_aligned()),
        Cell::from(Line::from(Span::styled("↑", t.header())).right_aligned()),
    ]));
    f.render_widget(table, conns);
    if n == 0 {
        f.render_widget(
            Paragraph::new(Span::styled("no open sockets", t.muted())),
            Rect {
                y: conns.y + 1,
                height: 1,
                ..conns
            },
        );
    }
}

// ------------------------------------------------------------------ footer & help

fn draw_footer(app: &App, f: &mut Frame, area: Rect) {
    let t = theme();
    let mut hints: Vec<(&str, &str)> = vec![
        ("q", "quit"),
        ("?", "help"),
        ("/", "filter"),
        ("tab", "switch"),
        ("s", "sort"),
    ];
    match app.tab {
        Tab::Procs => {
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
    }
    hints.push(("space", if app.paused { "resume" } else { "pause" }));

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
    let sections: [(&str, &[(&str, &str)]); 4] = [
        (
            "navigate",
            &[
                ("↑ ↓  j k", "move selection"),
                ("PgUp PgDn", "move by a page"),
                ("Home End", "first / last row"),
                ("tab ← →  1-3", "switch view"),
                ("mouse", "click rows and tabs, wheel scrolls"),
            ],
        ),
        (
            "view",
            &[
                ("/", "filter by name, port, user, address"),
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
            "general",
            &[
                ("space", "pause the display"),
                ("?", "this help"),
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
        Constraint::Length(56.min(area.width)),
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

// ------------------------------------------------------------------ devices

const DEV_COLS: [Col; 9] = [
    col("", 1, 0),
    col("IP", 15, 0),
    col("NAME", 18, 0).flex(),
    col("IPV6", 25, 4),
    col("VENDOR", 24, 2),
    col("MAC", 17, 5),
    col("RTT", 8, 3).right(),
    col("SEEN", 6, 1).right(),
    col("", 20, 6),
];

/// The scanner's status for the panel border: interface, range, method and
/// progress (or how long ago the last scan finished).
fn scan_info(app: &App, wide: bool) -> Line<'static> {
    let t = theme();
    let s = &app.lan_state;
    let Some(iface) = &s.iface else {
        let msg = s
            .error
            .clone()
            .unwrap_or_else(|| "starting scanner…".into());
        return Line::from(Span::styled(format!(" {msg} "), t.fg(t.warn))).right_aligned();
    };
    let mut spans = vec![
        Span::styled(format!(" {} ", iface.name), t.fg(t.text)),
        Span::styled(iface.range(), t.muted()),
    ];
    // IPv6: the prefix, or why it isn't being scanned.
    spans.push(Span::styled(" + ", t.faint()));
    match (&s.ipv6_error, iface.range6()) {
        (Some(_), _) => spans.push(Span::styled("IPv6 failed", t.fg(t.warn))),
        (None, _) if !iface.has_ipv6() => spans.push(Span::styled("no IPv6", t.faint())),
        (None, Some(r)) if wide => spans.push(Span::styled(r, t.muted())),
        (None, Some(_)) => spans.push(Span::styled("IPv6", t.muted())),
        (None, None) => spans.push(Span::styled("IPv6 link-local", t.muted())),
    }
    match s.method {
        Some(Method::Arp) => {
            spans.push(Span::styled(" · ", t.faint()));
            spans.push(Span::styled("ARP", t.fg(t.good)));
        }
        Some(_) => {
            spans.push(Span::styled(" · ", t.faint()));
            spans.push(Span::styled("ping · root finds more", t.fg(t.warn)));
        }
        None => {}
    }
    spans.push(Span::styled(" · ", t.faint()));
    match (s.scanning, s.last_scan) {
        (Some((done, total)), _) => {
            let w = 10usize;
            let filled = (done * w).checked_div(total).unwrap_or(0).min(w);
            spans.push(Span::styled("scanning ", t.fg(t.accent)));
            spans.push(Span::styled("━".repeat(filled), t.fg(t.accent)));
            spans.push(Span::styled("─".repeat(w - filled), t.faint()));
            if total > 0 {
                spans.push(Span::styled(format!(" {done}/{total}"), t.muted()));
            }
        }
        (None, Some(at)) => {
            spans.push(Span::styled("scanned ", t.faint()));
            spans.push(Span::styled(ago(at), t.muted()));
            if ago(at) != "now" {
                spans.push(Span::styled(" ago", t.faint()));
            }
        }
        (None, None) => spans.push(Span::styled("not scanned", t.faint())),
    }
    spans.push(Span::raw(" "));
    Line::from(spans).right_aligned()
}

fn draw_devices(app: &mut App, f: &mut Frame, area: Rect, devs: &[DevKey], tabs: Line<'static>) {
    let t = theme();
    let ours = app
        .lan_state
        .iface
        .as_ref()
        .map(|i| i.ipv6.as_slice())
        .unwrap_or(&[]);
    let rows = devs
        .iter()
        .map(|k| dev_cells(t, &app.lan_state.devices[k], ours))
        .collect();
    let (sorted_col, desc) = match app.dev_sort {
        DevSort::Ip => (1, false),
        DevSort::Name => (2, false),
        DevSort::Vendor => (4, false),
        DevSort::Seen => (7, false),
    };
    let block = panel()
        .title(tabs)
        .title_top(scan_info(app, area.width >= 150))
        .title_bottom(filter_line(app));
    let s = &app.lan_state;
    let empty = if app.lan.is_none() && s.scans == 0 && s.devices.is_empty() {
        "the scanner isn't running".to_string()
    } else if let (None, Some(e)) = (&s.iface, &s.error) {
        e.clone()
    } else if s.scans == 0 {
        format!(
            "scanning {}…",
            s.iface.as_ref().map(|i| i.range()).unwrap_or_default()
        )
    } else {
        empty_message(app, "devices")
    };
    draw_table(
        app,
        f,
        area,
        block,
        &DEV_COLS,
        (sorted_col, desc != app.reverse),
        rows,
        &empty,
    );
}

fn dev_cells(t: &Theme, d: &Device, ours: &[(Ipv6Addr, u8)]) -> Vec<Cell<'static>> {
    let dot = if d.online {
        Span::styled("●", t.fg(t.good))
    } else {
        Span::styled("○", t.faint())
    };
    let ip_style = if d.online { t.fg(t.text) } else { t.muted() };
    let name = match &d.name {
        Some(n) => Span::styled(n.clone(), if d.online { t.fg(t.text) } else { t.muted() }),
        None => Span::styled("—", t.faint()),
    };
    let vendor = match (&d.vendor, d.random_mac()) {
        (Some(v), _) => Span::styled(elide_end(v, 24), t.muted()),
        (None, true) => Span::styled("private address", t.faint().add_modifier(Modifier::ITALIC)),
        (None, false) => Span::styled("—", t.faint()),
    };
    let mac = d.mac.as_ref().map(fmt_mac).unwrap_or_default();
    let rtt = match d.rtt {
        Some(r) => {
            let style = match r.as_millis() {
                0..10 => t.fg(t.good),
                10..100 => t.fg(t.text),
                _ => t.fg(t.warn),
            };
            Span::styled(fmt_rtt(r), style)
        }
        None => Span::styled("—", t.faint()),
    };
    let seen = if d.online {
        Span::styled("now", t.fg(t.good))
    } else {
        Span::styled(ago(d.last_seen), t.muted())
    };
    // An IPv6-only device shows its IPv6 address in the IP column too, so it
    // has one on narrow terminals where the IPV6 column is dropped.
    let ip = match (d.ipv4, d.ipv6.first()) {
        (Some(v4), _) => Span::styled(v4.to_string(), ip_style),
        (None, Some(a)) => Span::styled(v6_tail(&short_v6(a, ours), 15), ip_style),
        (None, None) => Span::styled("—", t.faint()),
    };
    let mut v6 = Vec::new();
    if let Some(a) = d.ipv6.first() {
        let more = d.ipv6.len() - 1;
        let width = if more > 0 { 22 } else { 25 };
        let style = if a.is_unicast_link_local() {
            t.faint()
        } else {
            t.muted()
        };
        v6.push(Span::styled(elide_middle(&short_v6(a, ours), width), style));
        if more > 0 {
            v6.push(Span::styled(format!(" +{more}"), t.faint()));
        }
    }
    vec![
        Cell::from(dot),
        Cell::from(ip),
        Cell::from(name),
        Cell::from(Line::from(v6)),
        Cell::from(vendor),
        Cell::from(Span::styled(mac, t.faint())),
        Cell::from(Line::from(rtt).right_aligned()),
        Cell::from(Line::from(seen).right_aligned()),
        Cell::from(Line::from(device_tags(t, d))),
    ]
}

/// The trailing groups of an IPv6 address that fit in `w` columns, e.g.
/// "…:aa10:7b3c". The end of an address is what tells devices apart.
pub(super) fn v6_tail(a: &str, w: usize) -> String {
    if a.chars().count() <= w {
        return a.to_string();
    }
    let mut out = String::new();
    for g in a.rsplit(':') {
        let next = format!(":{g}{out}");
        if next.chars().count() + 1 > w {
            break;
        }
        out = next;
    }
    format!("…{out}")
}

fn device_tags(t: &Theme, d: &Device) -> Vec<Span<'static>> {
    let mut tags = Vec::new();
    let mut tag = |text: &'static str, style: Style| {
        if !tags.is_empty() {
            tags.push(Span::raw(" "));
        }
        tags.push(Span::styled(text, style));
    };
    if d.is_self {
        tag("this machine", t.fg(t.accent));
    }
    if d.is_gateway {
        tag("gateway", t.fg(t.tcp));
    }
    if d.new {
        tag("new", t.fg(t.warn).add_modifier(Modifier::BOLD));
    }
    if d.random_mac() {
        tag("random MAC", t.faint());
    }
    tags
}

fn draw_device_detail(app: &App, f: &mut Frame, area: Rect, key: DevKey) {
    let t = theme();
    let Some(d) = app.lan_state.devices.get(&key) else {
        return;
    };
    let primary = d
        .primary_ip()
        .map(|ip| ip.to_string())
        .unwrap_or_else(|| "?".into());
    let mut title = vec![Span::raw(" ")];
    title.push(Span::styled(
        d.name.clone().unwrap_or_else(|| primary.clone()),
        t.title(),
    ));
    let mut sub = Vec::new();
    if d.name.is_some() {
        sub.push(primary);
    }
    sub.extend(d.vendor.clone());
    if !sub.is_empty() {
        title.push(Span::styled(format!("  {} ", sub.join(" · ")), t.muted()));
    } else {
        title.push(Span::raw(" "));
    }
    let block = panel().title(Line::from(title));
    let inner = block.inner(area).inner(Margin::new(1, 0));
    f.render_widget(block, area);

    // Wide enough for a full IPv6 address when there is room.
    let info_w = if d.ipv6.is_empty() {
        36
    } else {
        (inner.width / 3).clamp(36, 52)
    };
    let [info, ports, traffic] = Layout::horizontal([
        Constraint::Length(info_w),
        Constraint::Fill(1),
        Constraint::Fill(2),
    ])
    .spacing(3)
    .areas(inner);

    // Facts
    let kv = |k: &str, v: Span<'static>| {
        Line::from(vec![Span::styled(format!("{k:<11}"), t.faint()), v])
    };
    let mut lines = vec![
        kv(
            "status",
            if d.online {
                Span::styled("online", t.fg(t.good))
            } else {
                Span::styled(
                    format!("offline · last seen {} ago", ago(d.last_seen)),
                    t.fg(t.warn),
                )
            },
        ),
        kv(
            "ipv4",
            match d.ipv4 {
                Some(a) => Span::styled(a.to_string(), t.fg(t.text)),
                None => Span::styled("—", t.faint()),
            },
        ),
    ];
    // Every IPv6 address, up to three, then a count.
    let room = (info_w as usize).saturating_sub(11);
    for (i, a) in d.ipv6.iter().take(3).enumerate() {
        let style = if a.is_unicast_link_local() {
            t.muted()
        } else {
            t.fg(t.text)
        };
        lines.push(kv(
            if i == 0 { "ipv6" } else { "" },
            Span::styled(elide_middle(&a.to_string(), room), style),
        ));
    }
    if d.ipv6.len() > 3 {
        lines.push(kv(
            "",
            Span::styled(format!("+{} more", d.ipv6.len() - 3), t.faint()),
        ));
    }
    lines.extend([kv(
        "mac",
        Span::styled(
            d.mac.as_ref().map(fmt_mac).unwrap_or_else(|| "—".into()),
            t.fg(t.text),
        ),
    )]);
    if d.random_mac() {
        lines.push(kv(
            "",
            Span::styled(
                "randomized for privacy",
                t.faint().add_modifier(Modifier::ITALIC),
            ),
        ));
    }
    lines.push(kv(
        "vendor",
        Span::styled(d.vendor.clone().unwrap_or_else(|| "—".into()), t.fg(t.text)),
    ));
    lines.push(kv(
        "rtt",
        Span::styled(
            d.rtt.map(fmt_rtt).unwrap_or_else(|| "—".into()),
            t.fg(t.text),
        ),
    ));
    let first = ago(d.first_seen);
    lines.push(kv(
        "first seen",
        Span::styled(
            if first == "now" {
                "just now".into()
            } else {
                format!("{first} ago")
            },
            t.fg(t.text),
        ),
    ));
    let tags = device_tags(t, d);
    if !tags.is_empty() {
        let mut l = vec![Span::styled(format!("{:<11}", ""), t.faint())];
        l.extend(tags);
        lines.push(Line::from(l));
    }
    f.render_widget(Paragraph::new(lines), info);

    // Open ports
    let n = PROBE_PORTS.len();
    let mut lines = vec![Line::from(Span::styled("OPEN PORTS", t.header()))];
    match (&d.ports, d.probing) {
        (_, true) => lines.push(Line::from(Span::styled(
            format!("checking {n} common ports…"),
            t.fg(t.accent),
        ))),
        (Some(open), false) if open.is_empty() => lines.push(Line::from(Span::styled(
            format!("none of {n} common ports open"),
            t.muted(),
        ))),
        (Some(open), false) => {
            for p in open {
                lines.push(Line::from(vec![
                    Span::styled(format!("{p:<6}"), t.fg(t.good)),
                    Span::styled(port_name(*p).to_string(), t.muted()),
                ]));
            }
        }
        (None, false) => lines.push(Line::from(vec![
            Span::styled("press ", t.faint()),
            Span::styled("p", t.fg(t.accent).add_modifier(Modifier::BOLD)),
            Span::styled(format!(" to check {n} common ports"), t.faint()),
        ])),
    }
    f.render_widget(Paragraph::new(lines), ports);

    // This machine's traffic with the device, joined from the socket table.
    let mut socks: Vec<&SockRow> = app
        .snap
        .sockets
        .iter()
        .filter(|s| !d.is_self && d.has_ip(s.sock.remote.ip()))
        .collect();
    socks.sort_by(|a, b| {
        let r = |s: &SockRow| s.rate_in.unwrap_or(0.0) + s.rate_out.unwrap_or(0.0);
        r(b).total_cmp(&r(a))
    });
    let names = app.owner_names();
    let rows: Vec<Row> = socks
        .iter()
        .map(|s| {
            let name = names
                .iter()
                .find(|(o, _)| *o == s.owner)
                .map_or("?", |(_, n)| n.as_str());
            Row::new(vec![
                Cell::from(Span::styled(elide_end(name, 16), t.fg(t.text))),
                Cell::from(Line::from(vec![
                    Span::styled(s.sock.proto.as_str(), t.fg(proto_color(t, s.sock.proto))),
                    Span::styled(format!(" :{}", s.sock.remote.port()), t.muted()),
                ])),
                Cell::from(amount(s.rate_in, t.rx)),
                Cell::from(amount(s.rate_out, t.tx)),
            ])
        })
        .collect();
    let count = rows.len();
    let table = Table::new(
        rows,
        [
            Constraint::Length(18),
            Constraint::Length(12),
            Constraint::Length(10),
            Constraint::Length(10),
        ],
    )
    .column_spacing(1)
    .header(Row::new(vec![
        Cell::from(Line::from(vec![
            Span::styled("FROM THIS MACHINE", t.header()),
            Span::styled(format!(" {count}"), t.muted()),
        ])),
        Cell::default(),
        Cell::from(Line::from(Span::styled("↓", t.header())).right_aligned()),
        Cell::from(Line::from(Span::styled("↑", t.header())).right_aligned()),
    ]));
    f.render_widget(table, traffic);
    if count == 0 {
        let msg = if d.is_self {
            "this is this machine"
        } else {
            "no open connections to this device"
        };
        f.render_widget(
            Paragraph::new(Span::styled(msg, t.muted())),
            Rect {
                y: traffic.y + 1,
                height: 1,
                ..traffic
            },
        );
    }
}
