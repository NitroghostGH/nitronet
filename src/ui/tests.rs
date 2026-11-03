//! Rendering tests on a synthetic, deterministic snapshot. The ignored
//! `snapshots` test also writes colored HTML renders for visual review:
//!   cargo test snapshots -- --ignored
//! writes to target/snapshots/*.html (or $NITRONET_SNAPSHOT_DIR).

use std::fmt::Write as _;
use std::net::SocketAddr;
use std::time::Duration;

use ratatui::Terminal;
use ratatui::backend::TestBackend;
use ratatui::buffer::Buffer;
use ratatui::crossterm::event::{KeyCode, KeyEvent};
use ratatui::style::{Color, Modifier};

use super::App;
use crate::netlink::{Proto, SockInfo};
use crate::sampler::{Owner, ProcRow, Snapshot, SockRow, Source};

struct P {
    pid: u32,
    name: &'static str,
    unit: Option<&'static str>,
    user: &'static str,
    /// Peak (in, out) bytes/s; the actual rate follows a wave over time.
    rate: (f64, f64),
    socks: &'static [(&'static str, &'static str, &'static str, u8)], // proto, local, remote, state
}

const K: f64 = 1024.0;
const M: f64 = 1024.0 * 1024.0;

const PROCS: &[P] = &[
    P {
        pid: 1050831,
        name: "firefox",
        unit: None,
        user: "nitro",
        rate: (2.4 * M, 310.0 * K),
        socks: &[
            (
                "tcp",
                "[2001:db8:322e:0:32c5:99ff:feaa:bb02]:37422",
                "[2600:9000:246a:4400:1:a3fa:7cc0:93a1]:443",
                1,
            ),
            ("tcp", "192.168.0.74:51122", "142.250.70.206:443", 1),
            ("tcp", "192.168.0.74:51130", "151.101.1.140:443", 1),
            ("udp", "192.168.0.74:56519", "142.250.70.206:443", 1),
        ],
    },
    P {
        pid: 739794,
        name: "steam",
        unit: None,
        user: "nitro",
        rate: (9.8 * M, 120.0 * K),
        socks: &[
            ("tcp", "192.168.0.74:44391", "23.62.150.16:443", 1),
            ("tcp", "0.0.0.0:27036", "0.0.0.0:0", 10),
            ("udp", "0.0.0.0:27036", "0.0.0.0:0", 7),
        ],
    },
    P {
        pid: 4138993,
        name: "Discord",
        unit: None,
        user: "nitro",
        rate: (48.0 * K, 22.0 * K),
        socks: &[
            ("tcp", "192.168.0.74:36102", "162.159.135.234:443", 1),
            ("tcp", "127.0.0.1:6463", "0.0.0.0:0", 10),
        ],
    },
    P {
        pid: 2210,
        name: "syncthing",
        unit: Some("syncthing@nitro"),
        user: "nitro",
        rate: (380.0 * K, 1.6 * M),
        socks: &[
            ("tcp", "0.0.0.0:22000", "0.0.0.0:0", 10),
            ("udp", "0.0.0.0:22000", "0.0.0.0:0", 7),
            ("udp", "0.0.0.0:21027", "0.0.0.0:0", 7),
            ("tcp", "192.168.0.74:22000", "192.168.0.31:51544", 1),
        ],
    },
    P {
        pid: 674,
        name: "systemd-resolve",
        unit: Some("systemd-resolved"),
        user: "systemd-resolve",
        rate: (3.1 * K, 1.4 * K),
        socks: &[
            ("tcp", "127.0.0.53:53", "0.0.0.0:0", 10),
            ("udp", "127.0.0.53:53", "0.0.0.0:0", 7),
            ("udp", "0.0.0.0:5353", "0.0.0.0:0", 7),
            ("tcp", "0.0.0.0:5355", "0.0.0.0:0", 10),
        ],
    },
    P {
        pid: 1002,
        name: "sshd",
        unit: Some("sshd"),
        user: "root",
        rate: (0.9 * K, 6.2 * K),
        socks: &[
            ("tcp", "0.0.0.0:22", "0.0.0.0:0", 10),
            ("tcp", "192.168.0.74:22", "192.168.0.31:60122", 1),
        ],
    },
    P {
        pid: 1196,
        name: "caddy",
        unit: Some("caddy"),
        user: "caddy",
        rate: (12.0 * K, 140.0 * K),
        socks: &[
            ("tcp", "0.0.0.0:80", "0.0.0.0:0", 10),
            ("tcp", "0.0.0.0:443", "0.0.0.0:0", 10),
            ("udp", "0.0.0.0:443", "0.0.0.0:0", 7),
            ("tcp", "0.0.0.0:8800", "0.0.0.0:0", 10),
            ("tcp", "0.0.0.0:8801", "0.0.0.0:0", 10),
            ("tcp", "0.0.0.0:8802", "0.0.0.0:0", 10),
        ],
    },
    P {
        pid: 1275,
        name: "mpd",
        unit: Some("mpd"),
        user: "nitro",
        rate: (0.0, 0.0),
        socks: &[("tcp", "127.0.0.1:6600", "0.0.0.0:0", 10)],
    },
    P {
        pid: 704,
        name: "systemd-network",
        unit: Some("systemd-networkd"),
        user: "systemd-network",
        rate: (0.0, 0.0),
        socks: &[("udp", "[fe80::32c5:99ff:feaa:bb02]:546", "[::]:0", 7)],
    },
    P {
        pid: 658685,
        name: "signal-desktop",
        unit: None,
        user: "nitro",
        rate: (0.4 * K, 0.2 * K),
        socks: &[("tcp", "192.168.0.74:40122", "76.223.92.165:443", 1)],
    },
    P {
        pid: 1500012,
        name: "claude",
        unit: None,
        user: "nitro",
        rate: (14.0 * K, 3.0 * K),
        socks: &[
            ("tcp", "192.168.0.74:48200", "160.79.104.10:443", 1),
            ("tcp", "192.168.0.74:48210", "160.79.104.10:443", 8),
        ],
    },
    P {
        pid: 1876864,
        name: "claude",
        unit: None,
        user: "nitro",
        rate: (2.0 * K, 1.0 * K),
        socks: &[("tcp", "192.168.0.74:48300", "160.79.104.10:443", 1)],
    },
];

fn addr(s: &str) -> SocketAddr {
    s.parse().unwrap()
}

/// Rate multiplier at time step `k`, unique per process so the graphs differ.
fn wave(k: usize, seed: u32) -> f64 {
    let x = k as f64 / 9.0 + seed as f64;
    let burst = if (k + seed as usize * 7) % 37 < 5 {
        1.0
    } else {
        0.0
    };
    ((x.sin() * 0.5 + 0.5) * 0.6 + burst * 0.4).max(0.02)
}

pub(crate) fn fixture(k: usize) -> Snapshot {
    let mut sockets = Vec::new();
    let mut procs = Vec::new();
    let mut cookie = 1;
    for p in PROCS {
        let w = wave(k, p.pid % 97);
        let owner = Owner::Pid(p.pid);
        let n_active = p.socks.iter().filter(|s| s.3 == 1).count().max(1) as f64;
        let mut listening = Vec::new();
        for (i, &(proto, local, remote, state)) in p.socks.iter().enumerate() {
            let proto = if proto == "tcp" {
                Proto::Tcp
            } else {
                Proto::Udp
            };
            let sock = SockInfo {
                proto,
                state,
                local: addr(local),
                remote: addr(remote),
                uid: 1000,
                inode: cookie as u32,
                cookie,
                bytes_out: None,
                bytes_in: None,
            };
            cookie += 1;
            if sock.is_listening() {
                listening.push((proto, sock.local.port()));
            }
            let share = if state == 1 {
                (1.0 / n_active) * (1.0 - i as f64 * 0.1).max(0.2)
            } else {
                0.0
            };
            let (ri, ro) = (p.rate.0 * w * share, p.rate.1 * w * share);
            let life = (k as f64 + 40.0) * 3.0;
            sockets.push(SockRow {
                sock,
                owner,
                rate_in: Some(ri),
                rate_out: Some(ro),
                bytes: Some(((ri * life) as u64, (ro * life) as u64)),
            });
        }
        listening.sort_unstable();
        listening.dedup();
        let (ri, ro) = (p.rate.0 * w, p.rate.1 * w);
        procs.push(ProcRow {
            owner,
            name: p.name.into(),
            unit: p.unit.map(Into::into),
            user: p.user.into(),
            alive: true,
            rate_in: if p.rate.0 > 0.0 { ri } else { 0.0 },
            rate_out: if p.rate.1 > 0.0 { ro } else { 0.0 },
            total_in: (p.rate.0 * 0.4 * (k as f64 + 60.0)) as u64,
            total_out: (p.rate.1 * 0.4 * (k as f64 + 60.0)) as u64,
            sockets: p.socks.len(),
            listening,
        });
    }
    // An exited process, a socket we couldn't attribute, and the kernel's TIME_WAIT sockets.
    procs.push(ProcRow {
        owner: Owner::Pid(3349885),
        name: "curl".into(),
        unit: None,
        user: "nitro".into(),
        alive: false,
        rate_in: 0.0,
        rate_out: 0.0,
        total_in: 5_900_000,
        total_out: 41_000,
        sockets: 0,
        listening: vec![],
    });
    let kernel_sock = SockInfo {
        proto: Proto::Tcp,
        state: 6,
        local: addr("192.168.0.74:51000"),
        remote: addr("142.250.70.206:443"),
        uid: 0,
        inode: 0,
        cookie: 9999,
        bytes_out: None,
        bytes_in: None,
    };
    sockets.push(SockRow {
        sock: kernel_sock,
        owner: Owner::Kernel,
        rate_in: Some(0.0),
        rate_out: Some(0.0),
        bytes: Some((0, 0)),
    });
    procs.push(ProcRow {
        owner: Owner::Kernel,
        name: "(kernel)".into(),
        unit: None,
        user: "-".into(),
        alive: true,
        rate_in: 0.0,
        rate_out: 0.0,
        total_in: 0,
        total_out: 0,
        sockets: 1,
        listening: vec![],
    });

    let seen_rate = procs
        .iter()
        .fold((0.0, 0.0), |(i, o), p| (i + p.rate_in, o + p.rate_out));
    Snapshot {
        sockets,
        procs,
        nic_rate: Some((seen_rate.0 * 1.04, seen_rate.1 * 1.03)),
        nic_total: Some((
            (k as f64 * 4.0 * M) as u64 + 812 * 1024 * 1024,
            (k as f64 * 0.9 * M) as u64 + 96 * 1024 * 1024,
        )),
        seen_rate,
        hidden_procs: 0,
        is_root: true,
        baseline: false,
        source: Source::Ebpf {
            tracks_creators: true,
        },
        closed_sockets: 3,
    }
}

/// An app with 300 samples of history.
fn app() -> App {
    let mut app = App::new(fixture(0), Duration::from_secs(1));
    for k in 1..300 {
        app.set_snapshot(fixture(k));
    }
    app
}

fn key(app: &mut App, c: KeyCode) {
    assert!(!app.on_key(KeyEvent::from(c)));
}

fn render(app: &mut App, w: u16, h: u16) -> Buffer {
    let mut term = Terminal::new(TestBackend::new(w, h)).unwrap();
    term.draw(|f| super::view::draw(app, f)).unwrap();
    term.backend().buffer().clone()
}

fn buffer_text(b: &Buffer) -> String {
    let mut s = String::new();
    for y in 0..b.area.height {
        for x in 0..b.area.width {
            s.push_str(b[(x, y)].symbol());
        }
        s.push('\n');
    }
    s
}

/// Every view at every size renders without panicking.
#[test]
fn renders_everywhere() {
    for (w, h) in [
        (220, 60),
        (160, 45),
        (120, 36),
        (100, 30),
        (80, 24),
        (60, 18),
        (40, 10),
        (20, 5),
        (1, 1),
    ] {
        let mut a = app();
        render(&mut a, w, h);
        key(&mut a, KeyCode::Char('g'));
        render(&mut a, w, h);
        key(&mut a, KeyCode::Char('2'));
        render(&mut a, w, h);
        key(&mut a, KeyCode::Char('l'));
        render(&mut a, w, h);
        key(&mut a, KeyCode::Char('?'));
        render(&mut a, w, h);
    }
}

#[test]
fn filter_narrows_rows() {
    let mut a = app();
    key(&mut a, KeyCode::Char('/'));
    for c in "sync".chars() {
        key(&mut a, KeyCode::Char(c));
    }
    let names: Vec<String> = a.proc_views().into_iter().map(|v| v.row.name).collect();
    assert_eq!(names, vec!["syncthing"]);
    let text = buffer_text(&render(&mut a, 160, 45));
    assert!(text.contains("syncthing") && !text.contains("firefox"));
    key(&mut a, KeyCode::Enter);
    key(&mut a, KeyCode::Esc); // clears the filter rather than quitting
    assert!(a.filter.is_empty());
    assert!(a.on_key(KeyEvent::from(KeyCode::Esc))); // now it quits
}

#[test]
fn grouping_merges_same_program() {
    let mut a = app();
    key(&mut a, KeyCode::Char('g'));
    let claude = a
        .proc_views()
        .into_iter()
        .find(|v| v.row.name == "claude")
        .unwrap();
    assert_eq!(claude.owners.len(), 2);
}

#[test]
fn narrow_terminal_keeps_essential_columns() {
    let mut a = app();
    let text = buffer_text(&render(&mut a, 80, 24));
    assert!(text.contains("PROGRAM") && text.contains("↓ RATE"));
    assert!(!text.contains("SERVICE")); // low priority, dropped
}

// ------------------------------------------------------------------ HTML snapshots

fn css(c: Color) -> Option<String> {
    Some(match c {
        Color::Rgb(r, g, b) => format!("#{r:02x}{g:02x}{b:02x}"),
        Color::Reset => return None,
        Color::Black => "#000".into(),
        Color::Red => "#e06c75".into(),
        Color::Green => "#98c379".into(),
        Color::Yellow => "#e5c07b".into(),
        Color::Blue => "#61afef".into(),
        Color::Magenta => "#c678dd".into(),
        Color::Cyan => "#56b6c2".into(),
        Color::Gray => "#abb2bf".into(),
        Color::DarkGray => "#5c6370".into(),
        Color::White => "#fff".into(),
        _ => "#abb2bf".into(),
    })
}

fn to_html(b: &Buffer, title: &str) -> String {
    let mut out = String::new();
    let _ = write!(
        out,
        "<!doctype html><meta charset=utf-8><title>{title}</title><style>\
         body{{margin:0;background:#1e2030;}}\
         pre{{margin:0;padding:12px;font:15px/1.25 'JetBrains Mono','DejaVu Sans Mono',monospace;color:#c8d3f5;}}\
         span{{white-space:pre}}i{{display:inline-block;width:1ch;font-style:inherit;overflow:visible}}</style><pre>"
    );
    for y in 0..b.area.height {
        let mut x = 0;
        while x < b.area.width {
            let c = &b[(x, y)];
            let style = (c.fg, c.bg, c.modifier);
            let mut text = String::new();
            while x < b.area.width && (b[(x, y)].fg, b[(x, y)].bg, b[(x, y)].modifier) == style {
                let sym = b[(x, y)].symbol();
                match sym {
                    "<" => text.push_str("&lt;"),
                    ">" => text.push_str("&gt;"),
                    "&" => text.push_str("&amp;"),
                    // Pin non-ASCII glyphs to one cell: browsers draw braille and
                    // arrows from fallback fonts with different widths.
                    s if !s.is_ascii() => {
                        let _ = write!(text, "<i>{s}</i>");
                    }
                    s => text.push_str(s),
                }
                x += 1;
            }
            let (mut fg, mut bg) = (css(style.0), css(style.1));
            if style.2.contains(Modifier::REVERSED) {
                std::mem::swap(&mut fg, &mut bg);
                fg = fg.or(Some("#1e2030".into()));
                bg = bg.or(Some("#c8d3f5".into()));
            }
            let mut st = String::new();
            if let Some(fg) = fg {
                let _ = write!(st, "color:{fg};");
            }
            if let Some(bg) = bg {
                let _ = write!(st, "background:{bg};");
            }
            if style.2.contains(Modifier::BOLD) {
                st.push_str("font-weight:bold;");
            }
            if style.2.contains(Modifier::ITALIC) {
                st.push_str("font-style:italic;");
            }
            if style.2.contains(Modifier::DIM) {
                st.push_str("opacity:.6;");
            }
            let _ = write!(out, "<span style=\"{st}\">{text}</span>");
        }
        out.push('\n');
    }
    out.push_str("</pre>");
    out
}

#[test]
#[ignore]
fn snapshots() {
    let dir = std::env::var("NITRONET_SNAPSHOT_DIR").unwrap_or_else(|_| "target/snapshots".into());
    std::fs::create_dir_all(&dir).unwrap();
    let shots: &[(&str, u16, u16, &[KeyCode])] = &[
        ("procs", 180, 46, &[]),
        (
            "procs-selected",
            180,
            46,
            &[KeyCode::Down, KeyCode::Down, KeyCode::Down],
        ),
        ("grouped", 180, 46, &[KeyCode::Char('g')]),
        ("sockets", 180, 46, &[KeyCode::Char('2')]),
        (
            "filter",
            180,
            46,
            &[KeyCode::Char('/'), KeyCode::Char('s'), KeyCode::Char('y')],
        ),
        ("help", 180, 46, &[KeyCode::Char('?')]),
        ("medium", 120, 34, &[]),
        ("small", 80, 24, &[]),
    ];
    for (name, w, h, keys) in shots {
        let mut a = app();
        for k in keys.iter() {
            key(&mut a, *k);
        }
        let b = render(&mut a, *w, *h);
        std::fs::write(format!("{dir}/{name}.html"), to_html(&b, name)).unwrap();
    }
}

/// Renders real data from this machine (unprivileged, tcp_info mode) in every view.
#[test]
fn renders_live_data() {
    let mut sampler = crate::sampler::Sampler::new(false).expect("netlink sock_diag available");
    let mut a = App::new(sampler.sample().unwrap(), Duration::from_millis(200));
    std::thread::sleep(Duration::from_millis(200));
    a.set_snapshot(sampler.sample().unwrap());
    for keys in [
        &[][..],
        &[KeyCode::Char('g')],
        &[KeyCode::Char('2')],
        &[KeyCode::Char('l')],
    ] {
        for k in keys {
            key(&mut a, *k);
        }
        let text = buffer_text(&render(&mut a, 160, 45));
        assert!(text.contains("Processes") && text.contains("Sockets"));
    }
}
