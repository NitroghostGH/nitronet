//! The Sockets tab.

use std::net::SocketAddr;

use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::Cell;

use super::fmt::{amount, elide_end, elide_middle, fmt_addr};
use super::procs_view::proto_color;
use super::theme::{Theme, theme};
use super::view::{MARKER, SPACING, draw_table, empty_message, filter_line, panel, table_window};
use super::widgets::{Col, col, fit_columns, traffic_bar};
use super::{App, SockSort};
use crate::sampler::{Owner, SockRow};

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

pub(super) fn draw_sockets(
    app: &mut App,
    f: &mut Frame,
    area: Rect,
    idx: &[usize],
    tabs: Line<'static>,
) {
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
    let win = table_window(app, socks.len(), area);
    let rows = socks
        .iter()
        .enumerate()
        .map(|(i, s)| {
            if !win.contains(&i) {
                return Vec::new();
            }
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
        (sorted_col, desc != app.reverse.socks),
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
pub(super) fn addr_line(a: SocketAddr, width: usize) -> Line<'static> {
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

pub(super) fn state_style(t: &Theme, state: &str) -> Style {
    match state {
        "LISTEN" => t.fg(t.good),
        "ESTAB" => t.fg(t.text),
        "UNCONN" => t.muted(),
        "TIME-WAIT" | "CLOSE" => t.faint(),
        "SYN-SENT" | "SYN-RECV" | "NEW-SYN-RECV" => t.fg(t.accent),
        _ => t.fg(t.warn),
    }
}
