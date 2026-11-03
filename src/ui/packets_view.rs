//! Drawing the Packets tab: the packet list or the conversations list, the
//! filters in the border, and the detail pane (headers plus the payload as
//! hex or text).

use std::net::SocketAddr;

use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Margin, Rect};
use ratatui::style::Style;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Cell, Paragraph};

use super::fmt::{elide_end, elide_middle, human};
use super::theme::{Theme, theme};
use super::view::{addr_line, draw_table, empty_message, filter_line, panel};
use super::widgets::{Col, col};
use super::{App, ContentFilter, DirFilter, Flow, FlowSort};
use crate::packet::{self, Content, Endpoint, L4, Packet};
use crate::sampler::{Owner, Source};

/// Lays out the tab: the list, and the detail pane under it.
pub fn draw(
    app: &mut App,
    f: &mut Frame,
    body: Rect,
    pkts: &[usize],
    flows: &[Flow],
    tabs: Line<'static>,
) {
    let len = if app.pkt_flows {
        flows.len()
    } else {
        pkts.len()
    };
    let detail_h = (body.height / 2).clamp(12, 24);
    let with_detail = app.show_detail && body.height >= detail_h + 8 && len > 0;
    let [table, detail] = Layout::vertical([
        Constraint::Fill(1),
        Constraint::Length(if with_detail { detail_h } else { 0 }),
    ])
    .areas(body);
    if app.pkt_flows {
        draw_flows(app, f, table, flows, tabs);
        if with_detail {
            let sel = app.flow_state.selected().unwrap_or(0).min(len - 1);
            draw_flow_detail(f, detail, &flows[sel]);
        }
    } else {
        draw_packets(app, f, table, pkts, tabs);
        if with_detail {
            let sel = app.pkt_state.selected().unwrap_or(0).min(len - 1);
            draw_packet_detail(app, f, detail, pkts[sel]);
        }
    }
}

/// Footer key hints, most useful first (the footer cuts off the rest).
pub fn hints(app: &App) -> Vec<(&'static str, &'static str)> {
    let mut h = Vec::new();
    if app.pkt_flows {
        h.push(("enter", "open conversation"));
        h.push(("f", "packets"));
        h.push(("s", "sort"));
    } else if app.pkt_flow.is_some() {
        h.push(("esc", "back to conversations"));
    } else {
        h.push(("f", "conversations"));
    }
    h.push(("i", "direction"));
    h.push(("e", "content"));
    if !app.pkt_flows {
        h.push(("t", if app.pkt_text { "hex" } else { "text" }));
        h.push(("[ ]", "scroll payload"));
    }
    h.push(("/", "filter"));
    if !app.capturing.is_empty() {
        h.push(("c", "stop capturing"));
    }
    h.push(("x", "clear"));
    h.push(("H", "how capture works"));
    h.push(("space", if app.paused { "resume" } else { "pause" }));
    h.push(("?", "help"));
    h.push(("q", "quit"));
    h
}

/// The border's right side: what's captured, which filters are on, how many
/// rows pass them.
fn status_line(app: &App, shown: usize, what: &str) -> Line<'static> {
    let t = theme();
    let mut s = Vec::new();
    if app.capturing.is_empty() {
        s.push(Span::styled(" not capturing", t.faint()));
    } else {
        s.push(Span::styled(" ● ", t.fg(t.warn)));
        s.push(Span::styled("capturing ", t.muted()));
        let names: Vec<&str> = app.capturing.iter().map(String::as_str).collect();
        s.push(Span::styled(elide_end(&names.join(", "), 32), t.fg(t.text)));
    }
    let chip = |s: &mut Vec<Span<'static>>, text: &str| {
        s.push(Span::styled(" · ", t.faint()));
        s.push(Span::styled(text.to_string(), t.fg(t.accent)));
    };
    if app.pkt_dir != DirFilter::Both {
        chip(&mut s, app.pkt_dir.label());
    }
    if app.pkt_content != ContentFilter::All {
        chip(&mut s, app.pkt_content.label());
    }
    let total = app.packets.len();
    s.push(Span::styled(" · ", t.faint()));
    if app.pkt_flows {
        s.push(Span::styled(format!("{shown} {what}"), t.muted()));
    } else if shown == total {
        s.push(Span::styled(format!("{total} {what}"), t.muted()));
    } else {
        s.push(Span::styled(
            format!("{shown} of {total} {what}"),
            t.muted(),
        ));
    }
    if app.capture_dropped > 0 {
        s.push(Span::styled(" · ", t.faint()));
        s.push(Span::styled(
            format!("{} dropped", app.capture_dropped),
            t.fg(t.warn),
        ));
    }
    s.push(Span::raw(" "));
    Line::from(s).right_aligned()
}

fn empty_text(app: &App, what: &str) -> String {
    if !matches!(app.snap.source, Source::Ebpf { .. }) {
        "capturing packets needs eBPF: run nitronet as root".to_string()
    } else if !app.filter.is_empty() {
        empty_message(app, what)
    } else if !app.packets.is_empty() {
        format!(
            "no {what} pass the filters ({}, {}) · i and e change them",
            app.pkt_dir.label(),
            app.pkt_content.label()
        )
    } else if app.capturing.is_empty() {
        "nothing captured · select a program in Processes (1) and press c".to_string()
    } else {
        let names: Vec<&str> = app.capturing.iter().map(String::as_str).collect();
        format!("waiting for packets from {}…", names.join(", "))
    }
}

// ------------------------------------------------------------------ packets

const PKT_COLS: [Col; 8] = [
    col("TIME", 12, 3),
    col("PROGRAM", 15, 1),
    col("", 1, 0),
    col("PROTO", 5, 0),
    col("REMOTE", 30, 0),
    col("LOCAL", 22, 5),
    col("LEN", 6, 2).right(),
    col("INFO", 24, 0).flex(),
];

fn draw_packets(app: &mut App, f: &mut Frame, area: Rect, idx: &[usize], tabs: Line<'static>) {
    let t = theme();
    let rows = idx.iter().map(|&i| pkt_cells(t, &app.packets[i])).collect();
    let mut block = panel()
        .title(tabs)
        .title_top(status_line(app, idx.len(), "packets"))
        .title_bottom(filter_line(app));
    if let Some(k) = &app.pkt_flow {
        block = block.title_bottom(
            Line::from(vec![
                Span::styled(" conversation ", t.muted()),
                Span::styled(
                    format!(
                        "{} ⇄ {} ",
                        k.program,
                        elide_middle(&k.remote.to_string(), 40)
                    ),
                    t.badge(t.accent),
                ),
                Span::styled(" esc back ", t.faint()),
            ])
            .right_aligned(),
        );
    }
    let empty = empty_text(app, "packets");
    draw_table(
        app,
        f,
        area,
        block,
        &PKT_COLS,
        (0, app.reverse),
        rows,
        &empty,
    );
}

/// An address, with the port bright when there is one.
fn endpoint_line(e: Endpoint, width: usize) -> Line<'static> {
    match e.1 {
        Some(port) => addr_line(SocketAddr::new(e.0, port), width),
        None => Line::from(Span::styled(
            elide_middle(&e.0.to_string(), width),
            theme().muted(),
        )),
    }
}

fn content_style(t: &Theme, c: Content) -> Style {
    match c {
        Content::Plain(_) => t.fg(t.good),
        Content::Binary | Content::Compressed => t.fg(t.text),
        Content::Encrypted(_) | Content::Empty => t.muted(),
    }
}

fn pkt_cells(t: &Theme, p: &Packet) -> Vec<Cell<'static>> {
    let dir = if p.outgoing {
        Span::styled("→", t.fg(t.tx))
    } else {
        Span::styled("←", t.fg(t.rx))
    };
    let (proto, info) = match &p.head {
        Some(d) => {
            let color = match d.l4 {
                L4::Tcp { .. } => t.fg(t.tcp),
                L4::Udp => t.fg(t.udp),
                _ => t.fg(t.text),
            };
            (Span::styled(d.proto(), color), d.info.clone())
        }
        None => (Span::styled("?", t.faint()), "unreadable header".into()),
    };
    let (local, remote) = match p.ends() {
        Some((l, r)) => (endpoint_line(l, 22), endpoint_line(r, 30)),
        None => (Line::default(), Line::default()),
    };
    vec![
        Cell::from(Span::styled(packet::clock(p.at), t.muted())),
        Cell::from(Span::styled(elide_end(&p.program, 15), t.fg(t.text))),
        Cell::from(dir),
        Cell::from(proto),
        Cell::from(remote),
        Cell::from(local),
        Cell::from(Line::from(Span::styled(p.len.to_string(), t.muted())).right_aligned()),
        Cell::from(info_line(t, &info, p.content)),
    ]
}

/// The info column. The part after two spaces says what the payload is, and
/// is green when it's readable, dim when encrypted.
fn info_line(t: &Theme, info: &str, content: Content) -> Line<'static> {
    match info.split_once("  ") {
        Some((head, app)) => Line::from(vec![
            Span::styled(head.to_string(), t.muted()),
            Span::raw("  "),
            Span::styled(app.to_string(), content_style(t, content)),
        ]),
        None => Line::from(Span::styled(info.to_string(), t.muted())),
    }
}

fn kv(t: &Theme, k: &str, v: Vec<Span<'static>>) -> Line<'static> {
    let mut spans = vec![Span::styled(format!("{k:<10}"), t.faint())];
    spans.extend(v);
    Line::from(spans)
}

/// Text cut into lines of `w` characters, the first labelled `k`.
fn wrapped(t: &Theme, k: &str, text: &str, w: usize, style: Style) -> Vec<Line<'static>> {
    let chars: Vec<char> = text.chars().collect();
    chars
        .chunks(w.max(8))
        .enumerate()
        .map(|(i, c)| {
            kv(
                t,
                if i == 0 { k } else { "" },
                vec![Span::styled(c.iter().collect::<String>(), style)],
            )
        })
        .collect()
}

fn draw_packet_detail(app: &mut App, f: &mut Frame, area: Rect, i: usize) {
    let t = theme();
    let p = &app.packets[i];
    let pid = match p.owner {
        Owner::Pid(pid) => format!("pid {pid}"),
        _ => String::new(),
    };
    let title = Line::from(vec![
        Span::raw(" "),
        Span::styled(p.program.clone(), t.title()),
        Span::styled(format!("  {pid} · packet #{} ", p.id + 1), t.muted()),
    ]);
    let block = panel().title(title);
    let inner = block.inner(area).inner(Margin::new(1, 0));
    f.render_widget(block, area);

    // Hex: 16 bytes per line when there's room, else 8. Text gets what's left
    // after the fields.
    let per = if inner.width >= 44 + 3 + 71 { 16 } else { 8 };
    let right = if app.pkt_text {
        Constraint::Fill(1)
    } else {
        Constraint::Length((6 + per * 3 + 1 + per) as u16)
    };
    let left = if app.pkt_text {
        Constraint::Length(inner.width.saturating_sub(3) / 2)
    } else {
        Constraint::Fill(1)
    };
    let [fields, bytes] = Layout::horizontal([left, right]).spacing(3).areas(inner);

    let text = |s: String| Span::styled(s, t.fg(t.text));
    let dim = |s: String| Span::styled(s, t.muted());
    let w = fields.width.saturating_sub(10) as usize;
    let mut lines = vec![
        kv(t, "time", vec![text(packet::clock(p.at))]),
        kv(
            t,
            "direction",
            vec![if p.outgoing {
                Span::styled("→ sent", t.fg(t.tx))
            } else {
                Span::styled("← received", t.fg(t.rx))
            }],
        ),
    ];
    match &p.head {
        Some(d) => {
            lines.push(kv(
                t,
                "from",
                endpoint_line(Endpoint(d.src, d.sport), w).spans,
            ));
            lines.push(kv(
                t,
                "to",
                endpoint_line(Endpoint(d.dst, d.dport), w).spans,
            ));
            let hop = if d.version == 4 { "ttl" } else { "hop limit" };
            lines.push(kv(
                t,
                "protocol",
                vec![
                    text(format!("{} over IPv{}", d.proto(), d.version)),
                    dim(format!(" · {hop} {}", d.ttl)),
                ],
            ));
            match d.l4 {
                L4::Tcp {
                    flags,
                    seq,
                    ack,
                    window,
                } => lines.push(kv(
                    t,
                    "tcp",
                    vec![
                        text(packet::tcp_flags(flags)),
                        dim(format!(" seq {seq} · ack {ack} · win {window}")),
                    ],
                )),
                L4::Icmp { kind, code } => {
                    lines.push(kv(t, "icmp", vec![dim(format!("type {kind} code {code}"))]))
                }
                _ => {}
            }
            lines.push(kv(
                t,
                "size",
                vec![
                    text(format!("{} B", p.len)),
                    dim(format!(" · payload {} B", d.payload_len)),
                ],
            ));
        }
        None => lines.push(kv(t, "size", vec![text(format!("{} B", p.len))])),
    }
    let captured = if p.data.len() as u32 >= p.len {
        "whole packet".to_string()
    } else {
        format!("first {} B", p.data.len())
    };
    lines.push(kv(t, "captured", vec![dim(captured)]));
    lines.push(kv(
        t,
        "content",
        vec![Span::styled(p.content.label(), content_style(t, p.content))],
    ));
    if let Some(d) = &p.head {
        lines.push(Line::default());
        lines.extend(wrapped(t, "info", &d.info, w, t.fg(t.text)));
    }
    f.render_widget(Paragraph::new(lines), fields);

    if app.pkt_text {
        draw_payload_text(app, f, bytes, i);
    } else {
        draw_hex(app, f, bytes, i, per);
    }
}

/// The bytes as a hex dump: headers dim, payload bright.
fn draw_hex(app: &mut App, f: &mut Frame, area: Rect, i: usize, per: usize) {
    let t = theme();
    let p = &app.packets[i];
    let payload_at = p.head.as_ref().map_or(0, |d| d.payload_at);
    let total = p.data.len().div_ceil(per);
    let visible = area.height.saturating_sub(1) as usize;
    let max_scroll = total.saturating_sub(visible);
    app.pkt_scroll = app.pkt_scroll.min(max_scroll);
    let p = &app.packets[i];
    let mut out = vec![Line::from(vec![
        Span::styled("BYTES", t.header()),
        Span::styled(format!(" {}", p.data.len()), t.muted()),
        Span::styled(
            if max_scroll > 0 {
                " · [ ] scroll · t text"
            } else {
                " · t text"
            },
            t.faint(),
        ),
    ])];
    for row in app.pkt_scroll..(app.pkt_scroll + visible).min(total) {
        let off = row * per;
        let mut spans = vec![Span::styled(format!("{off:04x}  "), t.faint())];
        let end = (off + per).min(p.data.len());
        for (k, b) in p.data[off..end].iter().enumerate() {
            if k > 0 {
                spans.push(Span::styled(if k % 8 == 0 { "·" } else { " " }, t.faint()));
            }
            let style = if off + k < payload_at {
                t.muted()
            } else {
                t.fg(t.text)
            };
            spans.push(Span::styled(format!("{b:02x}"), style));
        }
        let pad = (per - (end - off)) * 3;
        spans.push(Span::raw(" ".repeat(pad + 2)));
        for (k, &b) in p.data[off..end].iter().enumerate() {
            let style = if off + k < payload_at {
                t.faint()
            } else {
                t.fg(t.accent)
            };
            spans.push(Span::styled(packet::printable(&[b], 1), style));
        }
        out.push(Line::from(spans));
    }
    if p.data.is_empty() {
        out.push(Line::from(Span::styled("no bytes captured", t.muted())));
    }
    f.render_widget(Paragraph::new(out), area);
}

/// The payload as text lines, wrapped. Bytes that aren't printable show as
/// dim dots, so binary and encrypted payloads look like what they are.
fn draw_payload_text(app: &mut App, f: &mut Frame, area: Rect, i: usize) {
    let t = theme();
    let p = &app.packets[i];
    let w = (area.width as usize).max(8);
    let mut rows: Vec<Line<'static>> = Vec::new();
    for raw in p.payload().split(|&b| b == b'\n') {
        let raw = raw.strip_suffix(b"\r").unwrap_or(raw);
        if raw.is_empty() {
            rows.push(Line::default());
            continue;
        }
        for chunk in raw.chunks(w) {
            // Runs of printable and unprintable bytes, styled apart.
            let mut spans: Vec<Span<'static>> = Vec::new();
            let mut run = String::new();
            let mut run_plain = true;
            for &b in chunk {
                let plain = (0x20..0x7f).contains(&b) || b == b'\t';
                if plain != run_plain && !run.is_empty() {
                    let style = if run_plain { t.fg(t.text) } else { t.faint() };
                    spans.push(Span::styled(std::mem::take(&mut run), style));
                }
                run_plain = plain;
                run.push(match b {
                    b'\t' => ' ',
                    b if plain => b as char,
                    _ => '.',
                });
            }
            if !run.is_empty() {
                let style = if run_plain { t.fg(t.text) } else { t.faint() };
                spans.push(Span::styled(run, style));
            }
            rows.push(Line::from(spans));
        }
    }
    let visible = area.height.saturating_sub(1) as usize;
    let max_scroll = rows.len().saturating_sub(visible);
    app.pkt_scroll = app.pkt_scroll.min(max_scroll);
    let p = &app.packets[i];
    let shown = p.payload().len();
    let mut out = vec![Line::from(vec![
        Span::styled("PAYLOAD", t.header()),
        Span::styled(format!(" {shown} B as text"), t.muted()),
        Span::styled(
            if max_scroll > 0 {
                " · [ ] scroll · t hex"
            } else {
                " · t hex"
            },
            t.faint(),
        ),
    ])];
    if shown == 0 {
        out.push(Line::from(Span::styled("no payload", t.muted())));
    }
    out.extend(rows.into_iter().skip(app.pkt_scroll).take(visible));
    f.render_widget(Paragraph::new(out), area);
}

// ------------------------------------------------------------------ conversations

const FLOW_COLS: [Col; 9] = [
    col("LAST", 12, 3),
    col("PROGRAM", 15, 1),
    col("PROTO", 5, 0),
    col("REMOTE", 30, 0),
    col("LOCAL", 22, 6),
    col("PKTS", 5, 2).right(),
    col("↓ BYTES", 9, 4).right(),
    col("↑ BYTES", 9, 4).right(),
    col("WHAT", 24, 0).flex(),
];

fn draw_flows(app: &mut App, f: &mut Frame, area: Rect, flows: &[Flow], tabs: Line<'static>) {
    let t = theme();
    let rows = flows.iter().map(|fl| flow_cells(t, fl)).collect();
    let (sorted, desc) = match app.flow_sort {
        FlowSort::Recent => (0, true),
        FlowSort::Program => (1, false),
        FlowSort::Packets => (5, true),
        FlowSort::Bytes => (6, true),
    };
    let block = panel()
        .title(tabs)
        .title_top(status_line(app, flows.len(), "conversations"))
        .title_bottom(filter_line(app))
        .title_bottom(
            Line::from(vec![
                Span::styled(" sort ", t.faint()),
                Span::styled(app.flow_sort.label(), t.muted()),
                Span::styled(" · enter opens · f back to packets ", t.faint()),
            ])
            .right_aligned(),
        );
    let empty = empty_text(app, "conversations");
    draw_table(
        app,
        f,
        area,
        block,
        &FLOW_COLS,
        (sorted, desc != app.reverse),
        rows,
        &empty,
    );
}

fn flow_cells(t: &Theme, fl: &Flow) -> Vec<Cell<'static>> {
    let proto = match fl.key.proto {
        "TCP" => Span::styled("TCP", t.fg(t.tcp)),
        "UDP" => Span::styled("UDP", t.fg(t.udp)),
        p => Span::styled(p, t.fg(t.text)),
    };
    let what_style = if !fl.names.is_empty() {
        t.fg(t.good)
    } else {
        t.muted()
    };
    let bytes = |b: u64| Line::from(Span::styled(human(b as f64), t.muted())).right_aligned();
    vec![
        Cell::from(Span::styled(packet::clock(fl.last), t.muted())),
        Cell::from(Span::styled(elide_end(&fl.key.program, 15), t.fg(t.text))),
        Cell::from(proto),
        Cell::from(endpoint_line(fl.key.remote, 30)),
        Cell::from(endpoint_line(fl.key.local, 22)),
        Cell::from(
            Line::from(Span::styled(fl.packets().to_string(), t.fg(t.text))).right_aligned(),
        ),
        Cell::from(bytes(fl.bytes_in)),
        Cell::from(bytes(fl.bytes_out)),
        Cell::from(Span::styled(fl.what(), what_style)),
    ]
}

fn draw_flow_detail(f: &mut Frame, area: Rect, fl: &Flow) {
    let t = theme();
    let pid = match fl.owner {
        Owner::Pid(pid) => format!("pid {pid} · "),
        _ => String::new(),
    };
    let title = Line::from(vec![
        Span::raw(" "),
        Span::styled(fl.key.program.clone(), t.title()),
        Span::styled(format!("  {pid}conversation "), t.muted()),
    ]);
    let block = panel().title(title).title_bottom(
        Line::from(Span::styled(" enter shows its packets ", t.faint())).right_aligned(),
    );
    let inner = block.inner(area).inner(Margin::new(1, 0));
    f.render_widget(block, area);
    let [fields, seen] = Layout::horizontal([Constraint::Fill(1), Constraint::Fill(1)])
        .spacing(3)
        .areas(inner);

    let text = |s: String| Span::styled(s, t.fg(t.text));
    let dim = |s: String| Span::styled(s, t.muted());
    let w = fields.width.saturating_sub(10) as usize;
    let mut mix = Vec::new();
    for (n, label, style) in [
        (fl.plain, "plain", t.fg(t.good)),
        (fl.binary, "binary", t.fg(t.text)),
        (fl.encrypted, "encrypted", t.muted()),
        (fl.empty, "empty", t.faint()),
    ] {
        if n > 0 {
            if !mix.is_empty() {
                mix.push(Span::styled(" · ", t.faint()));
            }
            mix.push(Span::styled(format!("{n} {label}"), style));
        }
    }
    let span = match fl.last.duration_since(fl.first) {
        Ok(d) if fl.packets() > 1 => format!(" · over {:.1}s", d.as_secs_f64()),
        _ => String::new(),
    };
    let lines = vec![
        kv(t, "remote", endpoint_line(fl.key.remote, w).spans),
        kv(t, "local", endpoint_line(fl.key.local, w).spans),
        kv(t, "protocol", vec![text(fl.key.proto.to_string())]),
        kv(
            t,
            "packets",
            vec![
                text(format!("{}", fl.packets())),
                Span::styled(format!(" · {} sent", fl.sent), t.fg(t.tx)),
                Span::styled(format!(" · {} received", fl.received), t.fg(t.rx)),
            ],
        ),
        kv(
            t,
            "bytes",
            vec![
                Span::styled(format!("↓ {}", human(fl.bytes_in as f64)), t.fg(t.rx)),
                Span::raw("  "),
                Span::styled(format!("↑ {}", human(fl.bytes_out as f64)), t.fg(t.tx)),
            ],
        ),
        kv(
            t,
            "time",
            vec![
                text(format!(
                    "{} → {}",
                    packet::clock(fl.first),
                    packet::clock(fl.last)
                )),
                dim(span),
            ],
        ),
        kv(t, "content", mix),
    ];
    f.render_widget(Paragraph::new(lines), fields);

    let mut out = vec![Line::from(Span::styled("READABLE IN IT", t.header()))];
    if fl.names.is_empty() {
        out.push(Line::from(Span::styled(
            match fl.encrypted_why {
                Some(why) => format!("nothing: it's encrypted ({why})"),
                None => "nothing recognized".into(),
            },
            t.muted(),
        )));
    }
    let sw = seen.width as usize;
    for n in &fl.names {
        let mut chars: Vec<char> = n.chars().collect();
        if chars.len() > sw.saturating_sub(2) {
            chars.truncate(sw.saturating_sub(3));
            chars.push('…');
        }
        out.push(Line::from(vec![
            Span::styled("· ", t.fg(t.accent)),
            Span::styled(chars.into_iter().collect::<String>(), t.fg(t.good)),
        ]));
    }
    f.render_widget(Paragraph::new(out), seen);
}
