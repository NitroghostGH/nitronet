//! The "how it works" overlay (H): a diagram of what nitronet reads, what it
//! sends, and how the pieces join up, filled in with what it is doing on this
//! machine right now.

use ratatui::Frame;
use ratatui::layout::{Constraint, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, Clear, Padding, Paragraph};

use super::fmt::{ago, elide_end};
use super::theme::{Theme, theme};
use super::{App, ContentFilter, DirFilter, Tab};
use crate::lan::Method;
use crate::sampler::Source;

/// Width of the arrow between the two boxes.
const LINK: usize = 7;

#[derive(Clone, Copy)]
enum Link {
    /// Data flows from the left box into nitronet.
    Right,
    /// nitronet sends something out to the left box.
    Left,
    None,
}

/// One row inside a pair of boxes. Text that starts with two spaces is a
/// detail line and is drawn dimmer.
struct Row(String, Link, String);

fn row(l: impl Into<String>, link: Link, r: impl Into<String>) -> Row {
    Row(l.into(), link, r.into())
}

fn fit(s: &str, w: usize) -> String {
    let s = elide_end(s, w);
    format!("{s:<w$}")
}

/// Two boxes side by side, `inner` columns wide each, with arrows between.
fn boxes(t: &Theme, inner: usize, left: &str, right: &str, rows: &[Row]) -> Vec<Line<'static>> {
    let border = t.fg(t.border_focus);
    let top = |title: &str| {
        let title = elide_end(title, inner.saturating_sub(3));
        let rest = inner.saturating_sub(title.chars().count() + 2);
        vec![
            Span::styled("╭─ ", border),
            Span::styled(title, t.header()),
            Span::styled(format!(" {}╮", "─".repeat(rest)), border),
        ]
    };
    let bottom = Span::styled(format!("╰{}╯", "─".repeat(inner + 1)), border);
    let text = |s: &str| {
        let style = if s.starts_with("  ") {
            t.muted()
        } else {
            t.fg(t.text)
        };
        Span::styled(fit(s, inner), style)
    };

    let mut out = Vec::new();
    let mut l = top(left);
    l.push(Span::raw(" ".repeat(LINK)));
    l.extend(top(right));
    out.push(Line::from(l));
    for Row(a, link, b) in rows {
        let arrow = match link {
            Link::Right => Span::styled(format!("{}▶", "─".repeat(LINK - 1)), t.fg(t.accent)),
            Link::Left => Span::styled(format!("◀{}", "─".repeat(LINK - 1)), t.fg(t.warn)),
            Link::None => Span::raw(" ".repeat(LINK)),
        };
        out.push(Line::from(vec![
            Span::styled("│ ", border),
            text(a),
            Span::styled("│", border),
            arrow,
            Span::styled("│ ", border),
            text(b),
            Span::styled("│", border),
        ]));
    }
    out.push(Line::from(vec![
        bottom.clone(),
        Span::raw(" ".repeat(LINK)),
        bottom,
    ]));
    out
}

fn heading(t: &Theme, name: &str, sub: &str) -> Line<'static> {
    Line::from(vec![
        Span::styled(name.to_string(), t.title()),
        Span::styled(format!("  {sub}"), t.muted()),
    ])
}

/// A "now:" status line under a section.
fn status(t: &Theme, parts: Vec<Span<'static>>) -> Line<'static> {
    let mut spans = vec![Span::styled("now  ", t.faint())];
    spans.extend(parts);
    Line::from(spans)
}

/// Text placed under the right-hand box, for what comes out of it.
fn under_right(inner: usize, s: Span<'static>) -> Line<'static> {
    let indent = inner + 2 + LINK + 2;
    Line::from(vec![Span::raw(" ".repeat(indent)), s])
}

pub fn lines(app: &App, width: u16) -> Vec<Line<'static>> {
    if app.tab == Tab::Packets {
        return capture_lines(app, width);
    }
    let t = theme();
    // Each box's inner width, from the room available.
    let inner = ((width as usize).saturating_sub(LINK + 6) / 2).clamp(24, 38);
    let mut out = vec![Line::default()];
    let ok = |s: String| Span::styled(s, t.fg(t.good));
    let warn = |s: String| Span::styled(s, t.fg(t.warn));
    let dim = |s: &str| Span::styled(s.to_string(), t.muted());

    // ---------------------------------------------------------------- traffic
    out.push(heading(t, "TRAFFIC", "the Processes and Sockets tabs"));
    out.push(Line::default());
    let ebpf = matches!(app.snap.source, Source::Ebpf { .. });
    let mut rows = vec![
        row("socket table", Link::Right, "1  list every TCP/UDP socket"),
        row(
            "  NETLINK_SOCK_DIAG, like ss",
            Link::None,
            "  addresses, state, owner uid",
        ),
        row("/proc/<pid>/fd", Link::Right, "2  socket inode → process"),
        row(
            "  socket:[inode] links",
            Link::None,
            "  name, user, systemd unit",
        ),
    ];
    if ebpf {
        rows.push(row(
            "eBPF on the root cgroup",
            Link::Right,
            "3  bytes in/out per socket",
        ));
        rows.push(row(
            "  counts every packet (root)",
            Link::None,
            "  rate = Δbytes ÷ Δtime",
        ));
    } else {
        rows.push(row(
            "tcp_info in the socket dump",
            Link::Right,
            "3  bytes in/out per socket",
        ));
        rows.push(row(
            "  TCP only, no root needed",
            Link::None,
            "  rate = Δbytes ÷ Δtime",
        ));
    }
    rows.push(row("/proc/net/dev", Link::Right, "4  network card totals"));
    rows.push(row(
        "  physical interfaces only",
        Link::None,
        "  the graph at the top",
    ));
    let every = format!("nitronet · every {}", fmt_interval(app));
    out.extend(boxes(t, inner, "kernel", &every, &rows));
    out.push(under_right(inner, Span::styled("▼", t.fg(t.accent))));
    out.push(under_right(inner, dim("summed per process → Processes")));
    out.push(under_right(inner, dim("one row per socket → Sockets")));
    out.push(Line::default());
    out.push(status(
        t,
        match &app.snap.source {
            Source::Ebpf { .. } => vec![ok("eBPF is counting every socket, TCP and UDP".into())],
            Source::TcpInfo { reason } => vec![
                warn("tcp_info only (TCP, no UDP)".into()),
                Span::styled(format!(" · {reason}"), t.muted()),
            ],
        },
    ));
    out.push(Line::default());

    // ---------------------------------------------------------------- devices
    let s = &app.lan_state;
    out.push(heading(t, "DEVICES", "the Devices tab"));
    out.push(Line::default());
    let (range4, range6, has6, ifname) = match &s.iface {
        Some(i) => (
            i.range(),
            i.range6().unwrap_or_else(|| "link-local".into()),
            i.has_ipv6(),
            i.name.clone(),
        ),
        None => ("local subnet".into(), "local link".into(), true, "?".into()),
    };
    let arp = match s.method {
        Some(m) => m == Method::Arp,
        None => app.snap.is_root,
    };
    let mut rows = Vec::new();
    if arp {
        rows.push(row(
            format!("IPv4 {range4}"),
            Link::Left,
            "ARP who-has, every address",
        ));
        rows.push(row(
            "  every host must answer ARP",
            Link::None,
            "  3 passes, raw socket (root)",
        ));
    } else {
        rows.push(row(
            format!("IPv4 {range4}"),
            Link::Left,
            "ping every address",
        ));
        rows.push(row(
            "  the kernel ARPs each one",
            Link::None,
            "  no root needed",
        ));
    }
    if has6 {
        rows.push(row(
            format!("IPv6 {range6}"),
            Link::Left,
            "ping ff02::1 (all nodes)",
        ));
        rows.push(row(
            "  every IPv6 host joins ff02::1",
            Link::None,
            "  from link-local + global",
        ));
    } else {
        rows.push(row("IPv6: none on this link", Link::None, "IPv6 skipped"));
    }
    rows.push(row(
        "kernel neighbor table",
        Link::Right,
        "IP → MAC (netlink)",
    ));
    rows.push(row(
        "  filled in by the probes",
        Link::None,
        "  IPv4 + IPv6 joined by MAC",
    ));
    rows.push(row("", Link::None, "MAC prefix → vendor (hwdata)"));
    rows.push(row("", Link::None, "reverse DNS / mDNS → name"));
    rows.push(row("", Link::None, "p: TCP connect to 25 ports"));
    out.extend(boxes(
        t,
        inner,
        &format!("your network · {ifname}"),
        "nitronet",
        &rows,
    ));
    out.push(under_right(
        inner,
        dim("scans when you first open Devices,"),
    ));
    out.push(under_right(inner, dim("then every 60s (R rescans now)")));
    out.push(Line::default());
    let now = match (s.scanning, s.last_scan) {
        (Some((done, total)), _) => vec![ok(format!("scanning… {done}/{total}"))],
        (None, Some(at)) => {
            let online = s.devices.values().filter(|d| d.online).count();
            let when = match ago(at).as_str() {
                "now" => "just now".to_string(),
                a => format!("{a} ago"),
            };
            vec![
                ok(format!("{online} devices online")),
                Span::styled(format!(", {} with IPv6", s.devices_v6), t.fg(t.text)),
                Span::styled(format!(" · scanned {when}"), t.muted()),
            ]
        }
        (None, None) => vec![dim("not scanned yet · press 3 to open Devices")],
    };
    out.push(status(t, now));
    if let Some(e) = &s.ipv6_error {
        out.push(status(t, vec![warn(format!("IPv6 scan failed: {e}"))]));
    }
    out.push(Line::default());

    // ---------------------------------------------------------------- packets
    out.push(heading(
        t,
        "PACKETS",
        "the Packets tab · only programs you press c on",
    ));
    out.push(Line::default());
    let rows = vec![
        row("socket on the capture list", Link::None, ""),
        row("  or made by a captured program", Link::None, ""),
        row(
            "→ copy its first 2 KB",
            Link::Right,
            "1  match socket → program",
        ),
        row(
            "  into a ring buffer",
            Link::None,
            "  same owners as Processes",
        ),
        row(
            "other programs' packets",
            Link::None,
            "2  decode IP, TCP, UDP, ICMP",
        ),
        row(
            "  pass by, never copied",
            Link::None,
            "  DNS name, TLS server name,",
        ),
        row("", Link::None, "  HTTP request line, QUIC"),
        row("", Link::None, "3  keep the last 5000, in memory"),
    ];
    out.extend(boxes(
        t,
        inner,
        "kernel · eBPF, every packet",
        "nitronet",
        &rows,
    ));
    out.push(under_right(
        inner,
        dim("most traffic is encrypted (TLS, QUIC):"),
    ));
    out.push(under_right(inner, dim("you see who and when, not what")));
    out.push(under_right(
        inner,
        dim("(H on the Packets tab explains more)"),
    ));
    out.push(Line::default());
    out.push(status(t, capture_status(app)));
    out.push(Line::default());
    limits(&mut out);
    out
}

/// "now: capturing firefox · 120 packets", or why capture can't run.
fn capture_status(app: &App) -> Vec<Span<'static>> {
    let t = theme();
    if !matches!(app.snap.source, Source::Ebpf { .. }) {
        return vec![Span::styled(
            "needs eBPF: run nitronet as root",
            t.fg(t.warn),
        )];
    }
    if app.capturing.is_empty() {
        return vec![Span::styled(
            "not capturing · press c on a program in Processes",
            t.muted(),
        )];
    }
    let names: Vec<&str> = app.capturing.iter().map(String::as_str).collect();
    let mut v = vec![
        Span::styled(format!("capturing {}", names.join(", ")), t.fg(t.good)),
        Span::styled(
            format!(" · {} packets kept", app.packets.len()),
            t.fg(t.text),
        ),
    ];
    if app.capture_dropped > 0 {
        v.push(Span::styled(
            format!(" · {} dropped", app.capture_dropped),
            t.fg(t.warn),
        ));
    }
    v
}

/// The H page on the Packets tab: how capture works in detail, how packets
/// are labeled, and the keys for going through them.
fn capture_lines(app: &App, width: u16) -> Vec<Line<'static>> {
    let t = theme();
    let inner = ((width as usize).saturating_sub(LINK + 6) / 2).clamp(24, 38);
    let mut out = vec![Line::default()];

    out.push(heading(t, "CAPTURE", "what happens to each packet"));
    out.push(Line::default());
    let every = fmt_interval(app);
    let rows = vec![
        row("a packet is sent or arrives", Link::None, ""),
        row("  for any program at all", Link::None, ""),
        row("is its socket on the list?", Link::None, ""),
        row(
            format!("  updated every {every} from Sockets"),
            Link::None,
            "",
        ),
        row("or opened by a captured name?", Link::None, ""),
        row("  catches new processes at once", Link::None, ""),
        row(
            "yes: copy its first 2 KB",
            Link::Right,
            "1  read the ring buffer",
        ),
        row(
            "  into an 8 MB ring buffer",
            Link::None,
            "  a thread drains it often",
        ),
        row(
            "no: untouched, never copied",
            Link::None,
            "2  socket → program",
        ),
        row("", Link::None, "3  decode IP, TCP, UDP, ICMP"),
        row("", Link::None, "  DNS, TLS name, HTTP, QUIC"),
        row("", Link::None, "4  label the content (below)"),
        row("", Link::None, "5  keep the last 5000, in memory"),
    ];
    out.extend(boxes(t, inner, "kernel · eBPF", "nitronet", &rows));
    out.push(Line::default());
    out.push(status(t, capture_status(app)));
    out.push(Line::default());

    out.push(heading(
        t,
        "CONTENT",
        "how each packet is labeled · e filters on this",
    ));
    out.push(Line::default());
    let label = |name: &'static str, color, lines: &[&str]| -> Vec<Line<'static>> {
        lines
            .iter()
            .enumerate()
            .map(|(i, l)| {
                Line::from(vec![
                    Span::styled(
                        format!("{:<11}", if i == 0 { name } else { "" }),
                        t.fg(color).add_modifier(Modifier::BOLD),
                    ),
                    Span::styled(l.to_string(), t.fg(t.text)),
                ])
            })
            .collect()
    };
    out.extend(label(
        "empty",
        t.muted,
        &["no payload: connection setup (SYN), acknowledgements, teardown (FIN)"],
    ));
    out.extend(label(
        "plain",
        t.good,
        &[
            "readable: DNS, HTTP, NTP, DHCP, an SSH greeting, a TLS ClientHello",
            "(its server name travels in clear), or a payload that's mostly text",
        ],
    ));
    out.extend(label(
        "encrypted",
        t.muted,
        &[
            "TLS records and QUIC; every later packet of a connection once it has",
            "been seen to be TLS, QUIC or SSH; ports such as 443, 853, 993 and 22;",
            "or bytes that look random (high entropy) and aren't one of these:",
        ],
    ));
    out.extend(label(
        "compressed",
        t.text,
        &[
            "random-looking bytes in an HTTP conversation (a gzip or brotli body),",
            "or data starting like gzip, zstd or xz. Not encrypted, just packed",
        ],
    ));
    out.extend(label(
        "binary",
        t.text,
        &["anything else: not text and not random, e.g. a game's own protocol"],
    ));
    out.push(Line::from(Span::styled(
        "These are guesses from the bytes. Nothing is decrypted.",
        t.muted(),
    )));
    out.push(Line::default());

    out.push(heading(t, "GOING THROUGH THEM", "keys on this tab"));
    out.push(Line::default());
    let key = |k: &str, what: &str, now: Option<String>| {
        let mut v = vec![
            Span::styled(
                format!("{k:<5}"),
                t.fg(t.accent).add_modifier(Modifier::BOLD),
            ),
            Span::styled(what.to_string(), t.fg(t.text)),
        ];
        if let Some(n) = now {
            v.push(Span::styled(format!("  now: {n}"), t.fg(t.good)));
        }
        Line::from(v)
    };
    let dir_now = (app.pkt_dir != DirFilter::Both).then(|| app.pkt_dir.label().to_string());
    let content_now =
        (app.pkt_content != ContentFilter::All).then(|| app.pkt_content.label().to_string());
    out.push(key(
        "i",
        "sent and received → sent only → received only",
        dir_now,
    ));
    out.push(key("e", "all → with data → unencrypted only", content_now));
    out.push(key(
        "f",
        "conversations: one row per connection, with what was readable in it",
        None,
    ));
    out.push(key(
        "",
        "enter lists a conversation's packets, esc goes back",
        None,
    ));
    out.push(key(
        "/",
        "filter: every word must match, !word excludes (\"dns !mdns\")",
        (!app.filter.is_empty()).then(|| format!("\"{}\"", app.filter)),
    ));
    out.push(key("t", "show the payload as text instead of hex", None));
    out.push(key("[ ]", "scroll the payload", None));
    out.push(key(
        "r",
        "newest first · x clears the list · space pauses",
        None,
    ));
    out.push(key(
        "c",
        "stop capturing the selected packet's program",
        None,
    ));
    out.push(Line::from(Span::styled(
        "With the newest packet selected the list follows new ones, like tail -f.",
        t.muted(),
    )));
    out.push(Line::default());
    limits(&mut out);
    out
}

fn limits(out: &mut Vec<Line<'static>>) {
    let t = theme();
    out.push(heading(t, "WHAT IT DOESN'T DO", ""));
    out.push(Line::default());
    for line in [
        "reads no packet contents, except for programs you choose to capture (c),",
        "  and those stay in memory: nothing is saved to disk",
        "sends packets only on your local network, and only once you open Devices",
        "the eBPF programs detach by themselves when nitronet exits, even if killed",
        "name lookups go through your system resolver, which may ask your router",
        "  or your ISP's DNS server",
        "writes no files",
    ] {
        let (bullet, text) = match line.strip_prefix("  ") {
            Some(rest) => ("  ", rest),
            None => ("· ", line),
        };
        out.push(Line::from(vec![
            Span::styled(bullet, t.fg(t.accent)),
            Span::styled(text, t.fg(t.text)),
        ]));
    }
}

fn fmt_interval(app: &App) -> String {
    let ms = app.interval.as_millis();
    if ms.is_multiple_of(1000) {
        format!("{}s", ms / 1000)
    } else {
        format!("{:.1}s", ms as f64 / 1000.0)
    }
}

pub fn draw(app: &mut App, f: &mut Frame, area: Rect) {
    let t = theme();
    let w = 92.min(area.width);
    // Border plus one column of padding each side.
    let lines = lines(app, w.saturating_sub(4));
    let content = lines.len() as u16;
    let h = (content + 2).min(area.height);
    let max = content.saturating_sub(h.saturating_sub(2));
    app.diagram_scroll = app.diagram_scroll.min(max);

    let popup = area.centered(Constraint::Length(w), Constraint::Length(h));
    f.render_widget(Clear, popup);
    let hint = if max > 0 {
        "↑↓ scroll · any other key closes"
    } else {
        "any key closes"
    };
    let block = Block::bordered()
        .border_type(BorderType::Rounded)
        .border_style(t.fg(t.border_focus))
        .title(Line::from(vec![
            Span::raw(" "),
            Span::styled(
                if app.tab == Tab::Packets {
                    "how packet capture works"
                } else {
                    "how nitronet works"
                },
                t.title(),
            ),
            Span::raw(" "),
        ]))
        .title_bottom(
            Line::from(Span::styled(
                format!(" {hint} "),
                Style::default()
                    .patch(t.faint())
                    .add_modifier(Modifier::ITALIC),
            ))
            .right_aligned(),
        )
        .padding(Padding::horizontal(1));
    f.render_widget(
        Paragraph::new(lines)
            .block(block)
            .scroll((app.diagram_scroll, 0)),
        popup,
    );
}
