//! The Devices tab: the LAN scan, its table and the detail pane.

use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Margin, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Cell, Paragraph, Row, Table};

use super::fmt::{ago, amount, elide_end, elide_middle, fmt_rtt, short_v6};
use super::procs_view::proto_color;
use super::theme::{Theme, theme};
use super::view::{draw_table, empty_message, filter_line, panel, table_window};
use super::widgets::{Col, col};
use super::{App, DevSort};
use crate::lan::discover::fmt_mac;
use crate::lan::identify::{PROBE_PORTS, port_name};
use crate::lan::{DevKey, Device, Method};
use crate::sampler::SockRow;
use std::net::Ipv6Addr;

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

pub(super) fn draw_devices(
    app: &mut App,
    f: &mut Frame,
    area: Rect,
    devs: &[DevKey],
    tabs: Line<'static>,
) {
    let t = theme();
    let ours = app
        .lan_state
        .iface
        .as_ref()
        .map(|i| i.ipv6.as_slice())
        .unwrap_or(&[]);
    let win = table_window(app, devs.len(), area);
    let rows = devs
        .iter()
        .enumerate()
        .map(|(i, k)| {
            if !win.contains(&i) {
                return Vec::new();
            }
            dev_cells(t, &app.lan_state.devices[k], ours)
        })
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
        (sorted_col, desc != app.reverse.devs),
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

pub(super) fn draw_device_detail(app: &App, f: &mut Frame, area: Rect, key: DevKey) {
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
