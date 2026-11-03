//! The Processes tab: its table and the detail pane for the selected program.

use std::collections::HashSet;

use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Margin, Rect};
use ratatui::style::{Color, Modifier};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Cell, Paragraph, Row, Table};

use super::fmt::{amount, elide_end, human};
use super::sockets_view::{addr_line, state_style};
use super::theme::{Theme, theme};
use super::view::{
    draw_mirrored_graph, draw_table, empty_message, filter_line, panel, table_window,
};
use super::widgets::{Col, col, traffic_bar};
use super::{App, ProcSort, ProcView};
use crate::netlink::Proto;
use crate::sampler::{Owner, SockRow};

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

pub(super) fn draw_procs(
    app: &mut App,
    f: &mut Frame,
    area: Rect,
    views: &[ProcView],
    tabs: Line<'static>,
) {
    let t = theme();
    let max_rate = views
        .iter()
        .map(|v| v.row.rate_in + v.row.rate_out)
        .fold(0.0, f64::max);
    let win = table_window(app, views.len(), area);
    let rows = views
        .iter()
        .enumerate()
        .map(|(i, v)| {
            if !win.contains(&i) {
                return Vec::new();
            }
            let captured = app.is_captured(&v.row);
            proc_cells(t, v, max_rate, captured)
        })
        .collect();
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
        (sorted_col, desc != app.reverse.procs),
        rows,
        &empty,
    );
}

fn proc_cells(t: &Theme, v: &ProcView, max_rate: f64, captured: bool) -> Vec<Cell<'static>> {
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
    if captured {
        name.insert(0, Span::styled("● ", t.fg(t.warn)));
    }
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

pub(super) fn proto_color(t: &Theme, p: Proto) -> Color {
    match p {
        Proto::Tcp => t.tcp,
        Proto::Udp => t.udp,
    }
}

// ------------------------------------------------------------------ detail

pub(super) fn draw_detail(app: &App, f: &mut Frame, area: Rect, v: &ProcView) {
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
    if matches!(r.owner, Owner::Pid(_)) {
        lines.push(Line::default());
        lines.push(if app.is_captured(r) {
            let n = app.packets.iter().filter(|p| p.program == r.name).count();
            kv(
                "capture",
                vec![
                    Span::styled("● ", t.fg(t.warn)),
                    Span::styled(format!("{n} packets"), t.fg(t.text)),
                ],
            )
        } else {
            kv("capture", vec![Span::styled("off · c starts", t.faint())])
        });
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
