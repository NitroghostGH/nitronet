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
use crate::packet::Content;
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
            uid: Some(1000),
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
        uid: Some(1000),
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
        uid: None,
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

/// A scanned home network. 192.168.0.31 is the peer of the fixture's
/// syncthing and sshd connections, so its detail pane shows traffic.
pub(crate) fn lan_fixture() -> crate::lan::LanState {
    use crate::lan::discover::Iface;
    use crate::lan::{LanState, Method, test_device};
    use std::net::Ipv4Addr;
    use std::time::Instant;

    let ip = |d: u8| Ipv4Addr::new(192, 168, 0, d);
    let ago = |s: u64| {
        Instant::now()
            .checked_sub(Duration::from_secs(s))
            .unwrap_or_else(Instant::now)
    };
    let mut s = LanState {
        iface: Some(Iface {
            name: "eno1".into(),
            index: 2,
            ip: ip(74),
            prefix: 24,
            mac: Some([0x30, 0xc5, 0x99, 0xaa, 0xbb, 0x02]),
            gateway: Some(ip(1)),
            ipv6: vec![
                ("2001:db8:322e:0:32c5:99ff:feaa:bb02".parse().unwrap(), 64),
                ("fe80::32c5:99ff:feaa:bb02".parse().unwrap(), 64),
            ],
            first: ip(1),
            count: 254,
            truncated: false,
        }),
        method: Some(Method::Arp),
        scans: 4,
        last_scan: Some(ago(12)),
        vendors_available: true,
        ..LanState::default()
    };
    let mut add = |d: crate::lan::Device| {
        s.devices.insert(d.key, d);
    };
    let v6 = |a: &str| -> std::net::Ipv6Addr { a.parse().unwrap() };
    let mut gw = test_device(
        ip(1),
        Some([0x1c, 0x61, 0xb4, 0xaa, 0xbb, 0x01]),
        None,
        Some("TP-Link Systems"),
    );
    gw.is_gateway = true;
    gw.ipv6 = vec![
        v6("2001:db8:322e:0:1e61:b4ff:feaa:bb01"),
        v6("fe80::1e61:b4ff:feaa:bb01"),
    ];
    add(gw);
    let mut nas = test_device(
        ip(20),
        Some([0x00, 0x11, 0x32, 0xaa, 0xbb, 0x07]),
        Some("nas.lan"),
        Some("Synology"),
    );
    nas.ports = Some(vec![22, 80, 443, 445, 5000]);
    nas.ipv6 = vec![
        v6("2001:db8:322e:0:211:32ff:feaa:bb07"),
        v6("fd00::20"),
        v6("fe80::211:32ff:feaa:bb07"),
    ];
    add(nas);
    add(test_device(
        ip(31),
        Some([0x3c, 0x22, 0xfb, 0x10, 0x20, 0x30]),
        Some("laptop.local"),
        Some("Apple"),
    ));
    let mut pi = test_device(
        ip(42),
        Some([0xdc, 0xa6, 0x32, 0x01, 0x02, 0x03]),
        Some("pihole.lan"),
        Some("Raspberry Pi Trading"),
    );
    pi.new = true;
    add(pi);
    add(test_device(
        ip(71),
        Some([0x08, 0x36, 0xc9, 0xaa, 0xbb, 0x05]),
        None,
        Some("NETGEAR"),
    ));
    let mut me = test_device(
        ip(74),
        Some([0x30, 0xc5, 0x99, 0xaa, 0xbb, 0x02]),
        Some("desktop"),
        Some("ASUSTek COMPUTER"),
    );
    me.is_self = true;
    me.ipv6 = vec![
        v6("2001:db8:322e:0:32c5:99ff:feaa:bb02"),
        v6("fe80::32c5:99ff:feaa:bb02"),
    ];
    me.rtt = None;
    add(me);
    let mut printer = test_device(
        ip(90),
        Some([0x3c, 0x2a, 0xf4, 0x55, 0x66, 0x77]),
        Some("HP-LaserJet.local"),
        Some("Brother Industries"),
    );
    printer.probing = true;
    add(printer);
    add(test_device(
        ip(155),
        Some([0xd6, 0xfa, 0xc4, 0xaa, 0xbb, 0x04]),
        None,
        None,
    ));
    add(test_device(
        ip(156),
        Some([0x58, 0x24, 0x29, 0xaa, 0xbb, 0x06]),
        Some("Living-Room.local"),
        Some("Google"),
    ));
    add(test_device(
        ip(226),
        Some([0xc8, 0x4a, 0xa0, 0xaa, 0xbb, 0x03]),
        Some("PS5-AABB03.local"),
        Some("Sony Interactive Entertainment"),
    ));
    // A phone seen only over IPv6.
    let mut phone = test_device(
        ip(0),
        Some([0x7a, 0x11, 0x22, 0x33, 0x44, 0x55]),
        None,
        None,
    );
    phone.ipv4 = None;
    phone.ipv6 = vec![
        v6("2001:db8:322e:0:9c1:5e2d:aa10:7b3c"),
        v6("fe80::781f:22ff:fe33:4455"),
    ];
    add(phone);
    let mut old = test_device(
        ip(240),
        Some([0xa4, 0x83, 0xe7, 0x00, 0x00, 0x01]),
        Some("old-tablet.local"),
        Some("Apple"),
    );
    old.online = false;
    old.last_seen = ago(7 * 60);
    add(old);
    s.devices_v6 = s
        .devices
        .values()
        .filter(|d| d.online && !d.ipv6.is_empty())
        .count();
    s
}

/// An app with 300 samples of history, a scanned LAN, and packets captured
/// from curl and firefox.
fn app() -> App {
    let mut app = App::new(fixture(0), Duration::from_secs(1));
    for k in 1..300 {
        app.set_snapshot(fixture(k));
    }
    app.lan_state = lan_fixture();
    app.capturing = [("curl".to_string(), 1000), ("firefox".to_string(), 1000)].into();
    app.add_packets(packet_fixture(0));
    app
}

/// A curl HTTPS request (DNS, handshake, TLS) and some firefox traffic.
pub(crate) fn packet_fixture(first_id: u64) -> Vec<crate::packet::Packet> {
    use crate::packet::tests::{client_hello, dns_query, ipv4};
    use crate::packet::{Packet, decode};
    const TCP: u8 = 6;
    const UDP: u8 = 17;
    let me = [192, 168, 0, 74];
    let site = [93, 184, 215, 14];
    let stub = [127, 0, 0, 53];
    let mut answer = dns_query("example.com", 1);
    answer[2] = 0x81;
    answer[3] = 0x80;
    answer[7] = 1;
    answer.extend_from_slice(&[0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 93, 184, 215, 14]);
    let mut server_hello = vec![22, 3, 3, 0, 90, 2, 0, 0, 86];
    server_hello.extend_from_slice(&[0; 90]);
    let mut tls_data = vec![23, 3, 3, 5, 120];
    tls_data.extend((0..300).map(|i| (i * 37 % 256) as u8));
    let mut ipv6 = vec![0u8; 40 + 20 + 5];
    ipv6[0] = 0x60;
    ipv6[6] = TCP;
    ipv6[7] = 58;
    let a: std::net::Ipv6Addr = "2001:db8:322e:0:32c5:99ff:feaa:bb02".parse().unwrap();
    let b: std::net::Ipv6Addr = "2600:9000:246a:4400:1:a3fa:7cc0:93a1".parse().unwrap();
    ipv6[8..24].copy_from_slice(&a.octets());
    ipv6[24..40].copy_from_slice(&b.octets());
    ipv6[40..42].copy_from_slice(&37422u16.to_be_bytes());
    ipv6[42..44].copy_from_slice(&443u16.to_be_bytes());
    ipv6[52] = 5 << 4;
    ipv6[53] = 0x18;
    ipv6[60..65].copy_from_slice(&[23, 3, 3, 0, 0]);

    let curl = (Owner::Pid(1203344), "curl");
    let firefox = (Owner::Pid(1050831), "firefox");
    // (program, outgoing, bytes, wire length or 0 for all of them)
    type Sample<'a> = ((Owner, &'a str), bool, Vec<u8>, u32);
    let list: Vec<Sample> = vec![
        (
            curl,
            true,
            ipv4(UDP, me, stub, 40112, 53, 0, &dns_query("example.com", 1)),
            0,
        ),
        (curl, false, ipv4(UDP, stub, me, 53, 40112, 0, &answer), 0),
        (curl, true, ipv4(TCP, me, site, 51644, 443, 0x02, &[]), 0),
        (curl, false, ipv4(TCP, site, me, 443, 51644, 0x12, &[]), 0),
        (curl, true, ipv4(TCP, me, site, 51644, 443, 0x10, &[]), 0),
        (
            curl,
            true,
            ipv4(
                TCP,
                me,
                site,
                51644,
                443,
                0x18,
                &client_hello("example.com"),
            ),
            0,
        ),
        (
            curl,
            false,
            ipv4(TCP, site, me, 443, 51644, 0x18, &server_hello),
            0,
        ),
        (
            curl,
            false,
            ipv4(TCP, site, me, 443, 51644, 0x18, &tls_data),
            2920,
        ),
        (
            firefox,
            true,
            ipv4(
                UDP,
                me,
                [142, 250, 70, 206],
                56519,
                443,
                0,
                &[0xc3, 0, 0, 0, 1, 8],
            ),
            1250,
        ),
        (
            firefox,
            true,
            ipv4(
                TCP,
                me,
                [192, 168, 0, 31],
                41822,
                8080,
                0x18,
                b"GET /status HTTP/1.1\r\nHost: nas\r\n\r\n",
            ),
            0,
        ),
        (firefox, true, ipv6, 0),
        (curl, true, ipv4(TCP, me, site, 51644, 443, 0x11, &[]), 0),
    ];
    let start = std::time::SystemTime::UNIX_EPOCH + Duration::from_secs(1_790_000_000);
    let mut classifier = crate::packet::Classifier::default();
    list.into_iter()
        .enumerate()
        .map(|(i, ((owner, name), outgoing, data, len))| {
            let len = if len == 0 { data.len() as u32 } else { len };
            Packet {
                id: first_id + i as u64,
                at: start + Duration::from_millis(first_id * 1000 + i as u64 * 37),
                owner,
                program: name.into(),
                outgoing,
                len,
                head: decode(&data, len),
                data,
                content: crate::packet::Content::Empty,
                secret: None,
            }
        })
        .map(|mut p| {
            classifier.apply(&mut p);
            p
        })
        .collect()
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
        key(&mut a, KeyCode::Char('3'));
        render(&mut a, w, h);
        key(&mut a, KeyCode::Char('s'));
        render(&mut a, w, h);
        key(&mut a, KeyCode::Char('4'));
        render(&mut a, w, h);
        key(&mut a, KeyCode::Up);
        key(&mut a, KeyCode::Char(']'));
        render(&mut a, w, h);
        key(&mut a, KeyCode::Char('?'));
        render(&mut a, w, h);
    }
    // An empty, never-scanned LAN renders its empty state.
    let mut a = app();
    a.lan_state = crate::lan::LanState::default();
    key(&mut a, KeyCode::Char('3'));
    let text = buffer_text(&render(&mut a, 160, 45));
    assert!(text.contains("the scanner isn't running"));
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
        ("devices", 180, 46, &[KeyCode::Char('3')]),
        (
            "devices-peer",
            180,
            46,
            &[KeyCode::Char('3'), KeyCode::Down, KeyCode::Down],
        ),
        ("devices-nas", 180, 46, &[KeyCode::Char('3'), KeyCode::Down]),
        (
            "packets",
            180,
            46,
            &[
                KeyCode::Char('4'),
                KeyCode::Up,
                KeyCode::Up,
                KeyCode::Up,
                KeyCode::Up,
                KeyCode::Up,
                KeyCode::Up,
            ],
        ),
        ("packets-newest", 120, 34, &[KeyCode::Char('4')]),
        (
            "packets-unencrypted-text",
            180,
            46,
            &[
                KeyCode::Char('4'),
                KeyCode::Char('e'),
                KeyCode::Char('e'),
                KeyCode::Char('t'),
            ],
        ),
        (
            "packets-conversations",
            180,
            46,
            &[KeyCode::Char('4'), KeyCode::Char('f')],
        ),
        (
            "diagram-packets",
            180,
            60,
            &[KeyCode::Char('4'), KeyCode::Char('H')],
        ),
        ("packets-small", 80, 24, &[KeyCode::Char('4'), KeyCode::Up]),
        ("diagram", 180, 46, &[KeyCode::Char('H')]),
        (
            "diagram-small",
            80,
            24,
            &[KeyCode::Char('H'), KeyCode::PageDown],
        ),
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

fn selected_name(a: &App) -> String {
    let views = a.proc_views();
    views[a.proc_state.selected().unwrap()].row.name.clone()
}

/// The highlight follows the selected process as changing rates re-sort the
/// list, rather than staying on a row number while items slide underneath it.
#[test]
fn selection_follows_item_when_rates_reorder() {
    let mut a = app();
    render(&mut a, 160, 45);
    key(&mut a, KeyCode::Down);
    key(&mut a, KeyCode::Down);
    let picked = selected_name(&a);
    let start_row = a.proc_state.selected();
    let mut moved = 0;
    for k in 300..420 {
        a.set_snapshot(fixture(k));
        render(&mut a, 160, 45);
        assert_eq!(selected_name(&a), picked, "selection drifted at step {k}");
        moved += usize::from(a.proc_state.selected() != start_row);
    }
    assert!(
        moved > 0,
        "the fixture never re-sorted {picked}, so this test proves nothing"
    );

    // Moving from there continues from the item's current row.
    let row = a.proc_state.selected().unwrap();
    key(&mut a, KeyCode::Down);
    assert_eq!(a.proc_state.selected(), Some(row + 1));
}

#[test]
fn socket_selection_follows_cookie() {
    let mut a = app();
    key(&mut a, KeyCode::Char('2'));
    render(&mut a, 160, 45);
    key(&mut a, KeyCode::Down);
    let cookie = a.sock_sel.unwrap();
    let mut moved = false;
    let start = a.sock_state.selected();
    for k in 300..420 {
        a.set_snapshot(fixture(k));
        render(&mut a, 160, 45);
        let rows = a.sock_rows();
        assert_eq!(
            a.snap.sockets[rows[a.sock_state.selected().unwrap()]]
                .sock
                .cookie,
            cookie
        );
        moved |= a.sock_state.selected() != start;
    }
    assert!(moved);
}

/// When the selected process disappears, the highlight stays on the same row.
#[test]
fn vanished_item_keeps_row() {
    let mut a = app();
    render(&mut a, 160, 45);
    for _ in 0..3 {
        key(&mut a, KeyCode::Down);
    }
    let (row, picked) = (a.proc_state.selected(), selected_name(&a));
    let mut snap = fixture(299);
    snap.procs.retain(|p| p.name != picked);
    a.set_snapshot(snap);
    render(&mut a, 160, 45);
    assert_eq!(a.proc_state.selected(), row);
    assert_ne!(selected_name(&a), picked);
}

#[test]
fn grouping_keeps_the_selected_program() {
    let mut a = app();
    a.proc_sel = Some(super::ProcKey::Owner(Owner::Pid(1876864))); // the second "claude"
    render(&mut a, 160, 45);
    assert_eq!(selected_name(&a), "claude");
    key(&mut a, KeyCode::Char('g'));
    render(&mut a, 160, 45);
    assert_eq!(selected_name(&a), "claude");
    assert_eq!(
        a.proc_views()[a.proc_state.selected().unwrap()]
            .owners
            .len(),
        2
    );
    key(&mut a, KeyCode::Char('g'));
    render(&mut a, 160, 45);
    assert_eq!(selected_name(&a), "claude");
}

#[test]
fn devices_tab_lists_sorts_and_follows_selection() {
    use std::net::Ipv4Addr;
    let mut a = app();
    key(&mut a, KeyCode::Char('3'));
    let text = buffer_text(&render(&mut a, 180, 46));
    for want in [
        "Devices 12",
        "PS5-AABB03.local",
        "gateway",
        "this machine",
        "private address",
        "eno1",
        "2001:db8:322e::/64",
        "IPV6",
        "…:9c1:5e2d:aa10:7b3c",
    ] {
        assert!(text.contains(want), "missing {want:?}");
    }
    let ipv4 = |a: &App, k: &crate::lan::DevKey| a.lan_state.devices[k].ipv4;
    // Default order is by IP; select the Pi (row 3), then sort by name: still the Pi.
    for _ in 0..3 {
        key(&mut a, KeyCode::Down);
    }
    render(&mut a, 180, 46);
    let pi = Some(Ipv4Addr::new(192, 168, 0, 42));
    assert_eq!(ipv4(&a, &a.dev_sel.unwrap()), pi);
    key(&mut a, KeyCode::Char('s'));
    render(&mut a, 180, 46);
    let rows = a.dev_rows();
    assert_eq!(ipv4(&a, &rows[a.dev_state.selected().unwrap()]), pi);
    // Name order puts unnamed devices last.
    let last = rows.last().unwrap();
    assert!(a.lan_state.devices[last].name.is_none());
    // Back to IP order: the IPv6-only phone sorts after every IPv4 device.
    for _ in 0..3 {
        key(&mut a, KeyCode::Char('s'));
    }
    assert_eq!(ipv4(&a, a.dev_rows().last().unwrap()), None);

    // The filter matches vendors...
    key(&mut a, KeyCode::Char('/'));
    for c in "sony".chars() {
        key(&mut a, KeyCode::Char(c));
    }
    let rows = a.dev_rows();
    assert_eq!(rows.len(), 1);
    assert_eq!(ipv4(&a, &rows[0]), Some(Ipv4Addr::new(192, 168, 0, 226)));
    // ...and IPv6 addresses.
    key(&mut a, KeyCode::Esc);
    key(&mut a, KeyCode::Char('/'));
    for c in "fd00::".chars() {
        key(&mut a, KeyCode::Char(c));
    }
    let rows = a.dev_rows();
    assert_eq!(rows.len(), 1);
    assert_eq!(ipv4(&a, &rows[0]), Some(Ipv4Addr::new(192, 168, 0, 20)));
}

/// Scans the real network (unprivileged) and writes the Devices tab to
/// target/snapshots/devices-live.html. It's ignored because it sends packets.
#[test]
#[ignore]
fn live_devices_snapshot() {
    let mut a = app();
    a.lan_state = crate::lan::scan_blocking();
    assert!(
        a.lan_state.scans > 0,
        "scan did not finish: {:?}",
        a.lan_state.error
    );
    key(&mut a, KeyCode::Char('3'));
    // Select this machine.
    a.dev_sel = a
        .lan_state
        .devices
        .values()
        .find(|d| d.is_self)
        .map(|d| d.key);
    let b = render(&mut a, 180, 46);
    let dir = std::env::var("NITRONET_SNAPSHOT_DIR").unwrap_or_else(|_| "target/snapshots".into());
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        format!("{dir}/devices-live.html"),
        to_html(&b, "devices-live"),
    )
    .unwrap();
    println!(
        "{}",
        buffer_text(&b)
            .lines()
            .skip(8)
            .take(14)
            .collect::<Vec<_>>()
            .join("\n")
    );
}

#[test]
fn ipv6_tail_fits_by_group() {
    assert_eq!(
        super::view::v6_tail("…:9c1:5e2d:aa10:7b3c", 15),
        "…:aa10:7b3c"
    );
    assert_eq!(super::view::v6_tail("fe80::1", 15), "fe80::1");
}

#[test]
fn diagram_opens_scrolls_and_closes() {
    let mut a = app();
    key(&mut a, KeyCode::Char('H'));
    assert!(a.show_diagram);
    let text = buffer_text(&render(&mut a, 180, 60));
    for want in [
        "how nitronet works",
        "TRAFFIC",
        "DEVICES",
        "NETLINK_SOCK_DIAG",
        "IPv4 192.168.0.0/24",
        "IPv6 2001:db8:322e::/64",
        "ff02::1",
        "ARP who-has",
        "11 devices online, 4 with IPv6",
        "PACKETS",
        "capturing curl, firefox · 12 packets",
    ] {
        assert!(text.contains(want), "missing {want:?}");
    }
    // Small terminals scroll instead of cutting it off.
    render(&mut a, 80, 24);
    key(&mut a, KeyCode::End);
    let text = buffer_text(&render(&mut a, 80, 24));
    assert!(text.contains("writes no files"));
    assert!(a.diagram_scroll > 0);
    // Every size renders without panicking.
    for (w, h) in [(20, 5), (40, 12), (60, 20), (120, 30), (250, 80)] {
        render(&mut a, w, h);
    }
    // Any other key closes it without acting on it.
    let tab = a.tab;
    key(&mut a, KeyCode::Char('2'));
    assert!(!a.show_diagram);
    assert_eq!(a.tab, tab);
}

#[test]
fn diagram_boxes_line_up() {
    // Every row of a box pair is as wide as its top border.
    let a = app();
    for w in [60, 88] {
        let lines = super::diagram::lines(&a, w);
        let mut width = None;
        for l in &lines {
            let text: String = l.spans.iter().map(|s| s.content.as_ref()).collect();
            let starts_box = text.starts_with('╭');
            if starts_box {
                width = Some(l.width());
            }
            if text.starts_with('│') || text.starts_with('╰') {
                assert_eq!(Some(l.width()), width, "misaligned at width {w}: {text:?}");
            }
        }
    }
}

#[test]
fn packets_tab_lists_follows_and_filters() {
    let mut a = app();
    key(&mut a, KeyCode::Char('4'));
    let text = buffer_text(&render(&mut a, 180, 46));
    for want in [
        "Packets 12",
        "capturing curl, firefox",
        "A? example.com",
        "A example.com → 93.184.215.14",
        "TLS ClientHello → example.com",
        "GET /status HTTP/1.1",
        "QUIC Initial",
        "[S.]",
        "7cc0:93a1]:443",
        "BYTES",
    ] {
        assert!(text.contains(want), "missing {want:?}");
    }
    // The newest packet is selected, and stays selected as more arrive.
    let newest = |a: &App| a.packets.back().unwrap().id;
    let sel = |a: &App| {
        let rows = a.pkt_rows();
        a.packets[rows[a.pkt_state.selected().unwrap()]].id
    };
    assert_eq!(sel(&a), newest(&a));
    a.add_packets(packet_fixture(100));
    render(&mut a, 180, 46);
    assert_eq!(sel(&a), newest(&a));
    // Moving up pins the selection to that packet.
    key(&mut a, KeyCode::Up);
    let pinned = sel(&a);
    a.add_packets(packet_fixture(200));
    render(&mut a, 180, 46);
    assert_eq!(sel(&a), pinned);
    // End resumes following.
    key(&mut a, KeyCode::End);
    a.add_packets(packet_fixture(300));
    render(&mut a, 180, 46);
    assert_eq!(sel(&a), newest(&a));

    // The filter searches the decoded info too.
    a.filter = "clienthello".into();
    assert_eq!(a.pkt_rows().len(), 4);
    a.filter.clear();

    // The truncated packet says so, and its bytes scroll.
    a.pkt_sel = Some(7);
    let text = buffer_text(&render(&mut a, 180, 46));
    assert!(text.contains("first 345 B"), "{text}");
    key(&mut a, KeyCode::Char(']'));
    render(&mut a, 180, 46);
    assert!(a.pkt_scroll > 0);

    // c stops capturing the selected packet's program; x clears the list.
    key(&mut a, KeyCode::Char('c'));
    assert!(!a.capturing.contains_key("curl") && a.capture_dirty);
    let text = buffer_text(&render(&mut a, 180, 46));
    assert!(text.contains("stopped capturing curl"));
    key(&mut a, KeyCode::Char('x'));
    assert!(a.packets.is_empty());
    let text = buffer_text(&render(&mut a, 180, 46));
    assert!(text.contains("waiting for packets from firefox"));
}

#[test]
fn c_toggles_capture_on_processes() {
    let mut a = app();
    a.capturing.clear();
    // firefox is the first row, sorted by rate in the fixture.
    let text = buffer_text(&render(&mut a, 180, 46));
    assert!(!text.contains("● firefox"));
    let name = selected_name(&a);
    key(&mut a, KeyCode::Char('c'));
    assert!(a.capturing.contains_key(&name) && a.capture_dirty);
    let text = buffer_text(&render(&mut a, 180, 46));
    assert!(text.contains(&format!("● {name}")), "{text}");
    assert!(text.contains(&format!("capturing {name} · press 4")));
    key(&mut a, KeyCode::Char('c'));
    assert!(a.capturing.is_empty());

    // Without eBPF the Packets tab explains why it's empty.
    let mut a = app();
    a.packets.clear();
    a.snap.source = Source::TcpInfo {
        reason: "eBPF needs root".into(),
    };
    key(&mut a, KeyCode::Char('4'));
    let text = buffer_text(&render(&mut a, 180, 46));
    assert!(text.contains("needs eBPF: run nitronet as root"));
}

#[test]
fn packet_direction_and_content_filters() {
    let mut a = app();
    key(&mut a, KeyCode::Char('4'));
    let shown = |a: &App| -> Vec<crate::packet::Packet> {
        a.pkt_rows().iter().map(|&i| a.packets[i].clone()).collect()
    };
    key(&mut a, KeyCode::Char('i'));
    assert!(shown(&a).iter().all(|p| p.outgoing));
    let text = buffer_text(&render(&mut a, 180, 46));
    assert!(
        text.contains("sent only") && text.contains("8 of 12 packets"),
        "{text}"
    );
    key(&mut a, KeyCode::Char('i'));
    assert!(shown(&a).iter().all(|p| !p.outgoing));
    key(&mut a, KeyCode::Char('i'));
    assert_eq!(shown(&a).len(), 12);

    // with data: handshake and ack packets go.
    key(&mut a, KeyCode::Char('e'));
    assert!(shown(&a).iter().all(|p| p.content != Content::Empty));
    assert_eq!(shown(&a).len(), 8);
    // unencrypted: DNS, the ClientHello and the plain HTTP request.
    key(&mut a, KeyCode::Char('e'));
    let infos: Vec<String> = shown(&a)
        .iter()
        .map(|p| p.app_info().unwrap().to_string())
        .collect();
    assert_eq!(
        infos,
        [
            "DNS A? example.com",
            "DNS A example.com → 93.184.215.14",
            "TLS ClientHello → example.com",
            "GET /status HTTP/1.1",
        ]
    );
    let text = buffer_text(&render(&mut a, 180, 46));
    assert!(text.contains("unencrypted") && !text.contains("TLS data"));
    assert!(
        text.contains("plain · HTTP"),
        "the selected packet's content label"
    );
    // Filters that hide everything say how to undo them.
    key(&mut a, KeyCode::Char('i'));
    key(&mut a, KeyCode::Char('i'));
    a.filter = "zzz".into();
    let text = buffer_text(&render(&mut a, 180, 46));
    assert!(text.contains("no packets match"));
}

#[test]
fn filter_words_must_all_match_and_bang_excludes() {
    let mut a = app();
    a.filter = "example.com !dns".into();
    assert_eq!(a.pkt_rows().len(), 1);
    a.filter = "curl 443".into();
    assert_eq!(a.pkt_rows().len(), 7);
    a.filter = "curl !".into();
    assert_eq!(a.pkt_rows().len(), 9);
    // The same rules apply on every tab.
    a.filter = "fire !fox".into();
    assert!(a.proc_views().is_empty());
    a.filter = "systemd !resolve".into();
    assert!(
        a.proc_views()
            .iter()
            .all(|v| !v.row.name.contains("resolve"))
    );
    assert!(!a.proc_views().is_empty());
}

#[test]
fn conversations_group_packets_and_open() {
    let mut a = app();
    key(&mut a, KeyCode::Char('4'));
    key(&mut a, KeyCode::Char('f'));
    assert!(a.pkt_flows);
    let flows = a.flows();
    assert_eq!(flows.len(), 5);
    let https = flows
        .iter()
        .position(|f| f.key.program == "curl" && f.key.proto == "TCP")
        .unwrap();
    assert_eq!(flows[https].packets(), 7);
    assert_eq!((flows[https].sent, flows[https].received), (4, 3));
    assert_eq!(flows[https].what(), "TLS ClientHello → example.com");
    a.move_to(|_, _| https);
    let text = buffer_text(&render(&mut a, 180, 46));
    for want in [
        "5 conversations",
        "READABLE IN IT",
        "4 sent · 3 received",
        "enter opens",
    ] {
        assert!(text.contains(want), "missing {want:?}");
    }

    // enter lists its packets from the first; esc goes back.
    key(&mut a, KeyCode::Enter);
    assert!(!a.pkt_flows && a.pkt_flow.is_some());
    assert_eq!(a.pkt_rows().len(), 7);
    let text = buffer_text(&render(&mut a, 180, 46));
    assert!(text.contains("esc back") && text.contains("[S]"));
    let first = a.pkt_rows()[a.pkt_state.selected().unwrap()];
    assert_eq!(a.packets[first].head.as_ref().unwrap().info, "[S]");
    key(&mut a, KeyCode::Esc);
    assert!(a.pkt_flows && a.pkt_flow.is_none());
    assert_eq!(a.flow_sel.as_ref().unwrap().program, "curl");

    // s sorts conversations; the unencrypted filter applies to them too.
    key(&mut a, KeyCode::Char('s'));
    assert_eq!(a.flow_sort, super::FlowSort::Bytes);
    key(&mut a, KeyCode::Char('e'));
    key(&mut a, KeyCode::Char('e'));
    assert_eq!(a.flows().len(), 3);
}

#[test]
fn payload_shows_as_text() {
    let mut a = app();
    key(&mut a, KeyCode::Char('4'));
    a.filter = "status".into();
    render(&mut a, 180, 46);
    key(&mut a, KeyCode::Char('t'));
    let text = buffer_text(&render(&mut a, 180, 46));
    assert!(
        text.contains("PAYLOAD") && text.contains("Host: nas"),
        "{text}"
    );
    key(&mut a, KeyCode::Char('t'));
    let text = buffer_text(&render(&mut a, 180, 46));
    assert!(text.contains("BYTES"));
}

#[test]
fn h_on_packets_explains_capture() {
    let mut a = app();
    key(&mut a, KeyCode::Char('4'));
    key(&mut a, KeyCode::Char('e'));
    key(&mut a, KeyCode::Char('H'));
    let text = buffer_text(&render(&mut a, 180, 70));
    for want in [
        "how packet capture works",
        "CAPTURE",
        "is its socket on the list?",
        "8 MB ring buffer",
        "CONTENT",
        "look random",
        "GOING THROUGH THEM",
        "now: with data",
        "capturing curl, firefox · 12 packets kept",
    ] {
        assert!(text.contains(want), "missing {want:?}");
    }
    // Small terminals scroll to the end.
    render(&mut a, 80, 24);
    key(&mut a, KeyCode::End);
    let text = buffer_text(&render(&mut a, 80, 24));
    assert!(text.contains("writes no files"));
    // Its boxes line up too.
    for w in [60, 88] {
        let mut width = None;
        for l in &super::diagram::lines(&a, w) {
            let text: String = l.spans.iter().map(|s| s.content.as_ref()).collect();
            if text.starts_with('╭') {
                width = Some(l.width());
            }
            if text.starts_with('│') || text.starts_with('╰') {
                assert_eq!(Some(l.width()), width, "misaligned: {text:?}");
            }
            // The full-size popup (92 columns) has 88 inside.
            assert!(w < 88 || l.width() <= 88, "too wide: {text:?}");
        }
    }
}

/// A router login sent over plain HTTP: firefox opens a new connection and
/// POSTs a form with the password in it.
fn login_packets(first_id: u64) -> Vec<crate::packet::Packet> {
    use crate::packet::tests::ipv4;
    use crate::packet::{Classifier, Packet, decode};
    let (me, router) = ([192, 168, 0, 74], [192, 168, 0, 1]);
    let mut body = b"POST /login HTTP/1.1\r\nHost: 192.168.0.1\r\n".to_vec();
    body.extend_from_slice(&b"Accept: */*\r\n".repeat(20));
    body.extend_from_slice(b"\r\nusername=admin&password=hunter2");
    let list = [
        (true, ipv4(6, me, router, 50100, 80, 0x02, &[])),
        (false, ipv4(6, router, me, 80, 50100, 0x12, &[])),
        (true, ipv4(6, me, router, 50100, 80, 0x18, &body)),
        (
            false,
            ipv4(
                6,
                router,
                me,
                80,
                50100,
                0x18,
                b"HTTP/1.1 302 Found\r\n\r\n",
            ),
        ),
    ];
    let mut c = Classifier::default();
    list.into_iter()
        .enumerate()
        .map(|(i, (outgoing, data))| {
            let len = data.len() as u32;
            let mut p = Packet {
                id: first_id + i as u64,
                at: std::time::SystemTime::UNIX_EPOCH + Duration::from_millis(i as u64 * 2),
                owner: Owner::Pid(1050831),
                program: "firefox".into(),
                outgoing,
                len,
                head: decode(&data, len),
                data,
                content: crate::packet::Content::Empty,
                secret: None,
            };
            c.apply(&mut p);
            p
        })
        .collect()
}

#[test]
fn logins_in_clear_are_flagged_and_searchable() {
    let mut a = app();
    a.add_packets(login_packets(1000));
    key(&mut a, KeyCode::Char('4'));
    let post = a.packets.iter().find(|p| p.secret.is_some()).unwrap();
    assert_eq!(post.secret, Some("password field"));
    assert_eq!(a.packets.iter().filter(|p| p.secret.is_some()).count(), 1);

    // e, three times: only logins in clear.
    for _ in 0..3 {
        key(&mut a, KeyCode::Char('e'));
    }
    assert_eq!(a.pkt_content, super::ContentFilter::Secrets);
    let rows = a.pkt_rows();
    assert_eq!(rows.len(), 1);
    let text = buffer_text(&render(&mut a, 180, 46));
    assert!(text.contains("logins in clear · 1 of 16 packets"), "{text}");
    assert!(text.contains("⚠ [P.]"), "{text}");
    assert!(text.contains("⚠ password field, unencrypted"), "{text}");
    key(&mut a, KeyCode::Char('e'));

    // The filter searches payloads; the match is highlighted and scrolled to,
    // in hex and in text.
    key(&mut a, KeyCode::Char('/'));
    for c in "hunter2".chars() {
        key(&mut a, KeyCode::Char(c));
    }
    key(&mut a, KeyCode::Enter);
    assert_eq!(a.pkt_rows().len(), 1);
    let b = render(&mut a, 180, 46);
    assert!(a.pkt_scroll > 0, "the hex dump should scroll to the match");
    let found = super::theme::theme().badge(super::theme::theme().warn);
    let highlighted = |b: &Buffer| -> String {
        let mut s = String::new();
        for y in 0..b.area.height {
            for x in 0..b.area.width {
                if b[(x, y)].style().bg == found.bg && b[(x, y)].bg != Color::Reset {
                    s.push_str(b[(x, y)].symbol());
                }
            }
        }
        s
    };
    // Here the match straddles two rows: "h" ends one, "unter2" starts the next.
    let h = highlighted(&b);
    assert!(
        h.contains("68") && h.contains("756e74657232") && h.contains("unter2"),
        "{h}"
    );
    key(&mut a, KeyCode::Char('t'));
    let b = render(&mut a, 180, 46);
    assert!(buffer_text(&b).contains("username=admin&password=hunter2"));
    assert!(highlighted(&b).contains("hunter2"));

    // Its conversation carries the warning and lists the exchange.
    key(&mut a, KeyCode::Char('f'));
    let flows = a.flows();
    assert_eq!(flows.len(), 1);
    assert_eq!(flows[0].secrets, 1);
    a.filter.clear();
    a.flow_sel = Some(flows[0].key.clone());
    let text = buffer_text(&render(&mut a, 180, 46));
    for want in [
        "⚠ password field · POST /login HTTP/1.1",
        "⚠ password field unencrypted",
        "PACKETS 4",
        "+0.002 ←",
        "+0.004 →",
    ] {
        assert!(text.contains(want), "missing {want:?}\n{text}");
    }
}

#[test]
fn conversations_respect_exclusions_and_open_on_a_shown_packet() {
    let mut a = app();
    a.add_packets(login_packets(1000));
    key(&mut a, KeyCode::Char('4'));
    key(&mut a, KeyCode::Char('f'));
    let login = |a: &App| a.flows().into_iter().find(|f| f.key.local.1 == Some(50100));
    let all = a.flows().len();
    assert!(login(&a).is_some());
    // Only the POST has "hunter2". "!hunter2" must still drop the whole
    // conversation, though its other packets don't contain it.
    a.filter = "!hunter2".into();
    assert!(login(&a).is_none());
    assert_eq!(a.flows().len(), all - 1);
    // Wanted words can come from different packets of it.
    a.filter = "hunter2 [S] !nothing-like-this".into();
    assert_eq!(a.flows().len(), 1);
    assert!(login(&a).is_some());
    a.filter.clear();

    // With only packets that carry data shown, the handshake is hidden, so
    // opening the conversation selects its first shown packet instead.
    key(&mut a, KeyCode::Char('e'));
    a.flow_sel = Some(login(&a).unwrap().key);
    key(&mut a, KeyCode::Enter);
    assert!(!a.pkt_flows);
    let rows = a.pkt_rows();
    let sel = a.pkt_sel.expect("a packet is selected");
    assert_eq!(a.packets[rows[0]].id, sel);
    let p = a.packets.iter().find(|p| p.id == sel).unwrap();
    assert!(p.head.as_ref().unwrap().payload_len > 0);
}

#[test]
fn r_reverses_only_the_list_on_screen() {
    let mut a = app();
    a.add_packets(login_packets(1000));
    key(&mut a, KeyCode::Char('1'));
    key(&mut a, KeyCode::Char('r'));
    key(&mut a, KeyCode::Char('4'));
    key(&mut a, KeyCode::Char('f'));
    key(&mut a, KeyCode::Char('r'));
    let r = a.reverse;
    assert!(r.procs && r.flows);
    assert!(!r.socks && !r.devs && !r.pkts);
    // s resets only its own list's order.
    key(&mut a, KeyCode::Char('1'));
    key(&mut a, KeyCode::Char('s'));
    assert!(!a.reverse.procs && a.reverse.flows);
}
