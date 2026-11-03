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

use super::fmt::{amount, elide_end, elide_middle, fmt_addr, human};
use super::theme::{Theme, theme};
use super::widgets::{Col, Graph, col, fit_columns, graph_max, traffic_bar};
use super::{App, ProcSort, ProcView, SockSort, Tab};
use crate::netlink::Proto;
use crate::sampler::{Owner, SockRow, Source};

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
    app.sync_selection(&views, &socks);
    let tabs = tab_title(app, body, [views.len(), socks.len()]);

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
fn tab_title(app: &mut App, panel: Rect, counts: [usize; 2]) -> Line<'static> {
    let t = theme();
    app.hit.tabs.clear();
    // Block titles start one cell in from the corner.
    let mut x = panel.x + 1;
    let mut spans = Vec::new();
    let [n_procs, n_socks] = counts;
    for (tab, name, n) in [
        (Tab::Procs, "Processes", n_procs),
        (Tab::Sockets, "Sockets", n_socks),
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
    let sections: [(&str, &[(&str, &str)]); 3] = [
        (
            "navigate",
            &[
                ("↑ ↓  j k", "move selection"),
                ("PgUp PgDn", "move by a page"),
                ("Home End", "first / last row"),
                ("tab ← →  1 2", "switch view"),
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
            "general",
            &[
                ("space  p", "pause the display"),
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
