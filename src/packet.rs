//! Decoding captured packets for display: IPv4/IPv6, TCP/UDP/ICMP headers, and
//! a one-line summary of what the payload looks like (DNS question, TLS
//! server name, HTTP request line, QUIC, SSH banner).
//!
//! Everything read from a packet is untrusted. Text taken from payloads is
//! cut down to printable ASCII before it reaches the terminal, so a packet
//! can't smuggle in escape sequences.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::SystemTime;

use crate::sampler::Owner;

/// A captured packet, attributed and decoded.
#[derive(Clone, Debug)]
pub struct Packet {
    /// Increasing number, unique for this run.
    pub id: u64,
    pub at: SystemTime,
    pub owner: Owner,
    pub program: String,
    pub outgoing: bool,
    /// Whole packet length from the IP header on; `data` may hold less.
    pub len: u32,
    pub data: Vec<u8>,
    pub head: Option<Decoded>,
    /// What the payload looks like. Set by `Classifier`.
    pub content: Content,
    /// What kind of login secret the payload carries unencrypted, if any
    /// ("password field", "HTTP Basic login"). Set by `Classifier`.
    pub secret: Option<&'static str>,
}

impl Packet {
    /// (local, remote) addresses, if the headers were readable.
    pub fn ends(&self) -> Option<(Endpoint, Endpoint)> {
        let d = self.head.as_ref()?;
        let src = Endpoint(d.src, d.sport);
        let dst = Endpoint(d.dst, d.dport);
        Some(if self.outgoing {
            (src, dst)
        } else {
            (dst, src)
        })
    }

    /// The captured part of the payload.
    pub fn payload(&self) -> &[u8] {
        match &self.head {
            Some(d) => self.data.get(d.payload_at..).unwrap_or_default(),
            None => &[],
        }
    }

    /// The application-level part of the info ("TLS ClientHello → x"), if any.
    pub fn app_info(&self) -> Option<&str> {
        self.head.as_ref()?.info.split_once("  ").map(|(_, a)| a)
    }

    /// The connection this packet belongs to, for grouping into conversations.
    pub fn flow(&self) -> Option<FlowKey> {
        let d = self.head.as_ref()?;
        let (local, remote) = self.ends()?;
        Some(FlowKey {
            program: self.program.clone(),
            proto: d.proto(),
            local,
            remote,
        })
    }
}

/// One conversation: a program's traffic between two endpoints.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct FlowKey {
    pub program: String,
    pub proto: &'static str,
    pub local: Endpoint,
    pub remote: Endpoint,
}

/// What a packet's payload is, as far as can be told from its bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Content {
    /// No payload: connection setup and teardown, acknowledgements.
    Empty,
    /// Readable: a cleartext protocol, or mostly text. The reason says which.
    Plain(&'static str),
    /// Encrypted, and why we think so.
    Encrypted(&'static str),
    /// Payload that is neither text nor random-looking (some binary protocol).
    Binary,
    /// Random-looking, but in a conversation that is plain HTTP (a gzip or
    /// brotli body), or starting with a compression format's magic bytes.
    Compressed,
}

impl Content {
    pub fn label(&self) -> String {
        match self {
            Content::Empty => "empty".into(),
            Content::Plain(why) => format!("plain · {why}"),
            Content::Encrypted(why) => format!("encrypted · {why}"),
            Content::Binary => "binary".into(),
            Content::Compressed => "compressed".into(),
        }
    }
    /// Whether the payload is sent unencrypted: plain, compressed, or an
    /// unrecognized binary format.
    pub fn unencrypted_data(&self) -> bool {
        matches!(
            self,
            Content::Plain(_) | Content::Binary | Content::Compressed
        )
    }
}

/// An address with a port, when the protocol has ports.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Endpoint(pub IpAddr, pub Option<u16>);

impl std::fmt::Display for Endpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self.1 {
            Some(p) => write!(f, "{}", SocketAddr::new(self.0, p)),
            None => write!(f, "{}", self.0),
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum L4 {
    Tcp {
        flags: u8,
        seq: u32,
        ack: u32,
        window: u16,
    },
    Udp,
    Icmp {
        kind: u8,
        code: u8,
    },
    Other(u8),
}

#[derive(Clone, Debug, PartialEq)]
pub struct Decoded {
    pub version: u8,
    pub src: IpAddr,
    pub dst: IpAddr,
    pub ttl: u8,
    pub sport: Option<u16>,
    pub dport: Option<u16>,
    pub l4: L4,
    /// Where the payload starts in the captured bytes (may be past the end).
    pub payload_at: usize,
    /// Payload length on the wire.
    pub payload_len: usize,
    /// One-line description, e.g. "[S.] seq 0" or "DNS A? example.com".
    pub info: String,
}

impl Decoded {
    pub fn proto(&self) -> &'static str {
        match (&self.l4, self.version) {
            (L4::Tcp { .. }, _) => "TCP",
            (L4::Udp, _) => "UDP",
            (L4::Icmp { .. }, 4) => "ICMP",
            (L4::Icmp { .. }, _) => "ICMP6",
            (L4::Other(_), _) => "IP",
        }
    }
}

/// Captured packets kept for the UI.
pub const MAX_PACKETS: usize = 5000;

const TCP: u8 = 6;
const UDP: u8 = 17;
const ICMP: u8 = 1;
const ICMP6: u8 = 58;

/// Decodes a packet that starts at its IP header. `wire_len` is its full
/// length, which can exceed `data` when only the start was captured.
pub fn decode(data: &[u8], wire_len: u32) -> Option<Decoded> {
    let wire = wire_len as usize;
    let (version, src, dst, ttl, mut proto, mut at, fragment) = match data.first()? >> 4 {
        4 => {
            let ihl = (data[0] & 0x0f) as usize * 4;
            if data.len() < 20 || ihl < 20 {
                return None;
            }
            let ip = |o: usize| {
                IpAddr::V4(Ipv4Addr::new(
                    data[o],
                    data[o + 1],
                    data[o + 2],
                    data[o + 3],
                ))
            };
            let frag = u16::from_be_bytes([data[6], data[7]]) & 0x1fff != 0;
            (4, ip(12), ip(16), data[8], data[9], ihl, frag)
        }
        6 => {
            if data.len() < 40 {
                return None;
            }
            let ip = |o: usize| {
                let b: [u8; 16] = data[o..o + 16].try_into().unwrap();
                IpAddr::V6(Ipv6Addr::from(b))
            };
            (6, ip(8), ip(24), data[7], data[6], 40, false)
        }
        _ => return None,
    };
    // Skip IPv6 extension headers.
    let mut fragment = fragment;
    if version == 6 {
        for _ in 0..8 {
            match proto {
                0 | 43 | 60 => {
                    let len = (*data.get(at + 1)? as usize + 1) * 8;
                    proto = *data.get(at)?;
                    at += len;
                }
                44 => {
                    let off = u16::from_be_bytes([*data.get(at + 2)?, *data.get(at + 3)?]) & 0xfff8;
                    fragment = off != 0;
                    proto = *data.get(at)?;
                    at += 8;
                }
                _ => break,
            }
        }
    }
    let mut d = Decoded {
        version,
        src,
        dst,
        ttl,
        sport: None,
        dport: None,
        l4: L4::Other(proto),
        payload_at: at,
        payload_len: wire.saturating_sub(at),
        info: String::new(),
    };
    if fragment {
        d.info = "fragment".into();
        return Some(d);
    }
    let l4 = data.get(at..).unwrap_or_default();
    let be16 = |o: usize| u16::from_be_bytes([l4[o], l4[o + 1]]);
    let be32 = |o: usize| u32::from_be_bytes([l4[o], l4[o + 1], l4[o + 2], l4[o + 3]]);
    match proto {
        TCP if l4.len() >= 20 => {
            let doff = (l4[12] >> 4) as usize * 4;
            let flags = l4[13];
            d.sport = Some(be16(0));
            d.dport = Some(be16(2));
            d.l4 = L4::Tcp {
                flags,
                seq: be32(4),
                ack: be32(8),
                window: be16(14),
            };
            d.payload_at = at + doff.max(20);
            d.payload_len = wire.saturating_sub(d.payload_at);
            let payload = data.get(d.payload_at..).unwrap_or_default();
            d.info = tcp_flags(flags);
            if d.payload_len > 0 {
                d.info.push_str(&format!(" len {}", d.payload_len));
            }
            if let Some(app) = tcp_app(payload, d.sport, d.dport) {
                d.info.push_str("  ");
                d.info.push_str(&app);
            }
        }
        UDP if l4.len() >= 8 => {
            d.sport = Some(be16(0));
            d.dport = Some(be16(2));
            d.l4 = L4::Udp;
            d.payload_at = at + 8;
            d.payload_len = wire.saturating_sub(d.payload_at);
            let payload = data.get(d.payload_at..).unwrap_or_default();
            d.info = format!("len {}", d.payload_len);
            if let Some(app) = udp_app(payload, be16(0), be16(2)) {
                d.info = format!("len {}  {app}", d.payload_len);
            }
        }
        ICMP | ICMP6 if l4.len() >= 4 => {
            d.l4 = L4::Icmp {
                kind: l4[0],
                code: l4[1],
            };
            d.payload_at = at + 4;
            d.payload_len = wire.saturating_sub(d.payload_at);
            d.info = icmp_name(proto == ICMP6, l4[0], l4[1]);
            if matches!((proto, l4[0]), (ICMP, 0 | 8) | (ICMP6, 128 | 129)) && l4.len() >= 8 {
                d.info.push_str(&format!(" id {} seq {}", be16(4), be16(6)));
            }
        }
        TCP | UDP | ICMP | ICMP6 => d.info = "truncated header".into(),
        p => d.info = format!("protocol {p}"),
    }
    Some(d)
}

/// tcpdump-style flags: [S] SYN, [S.] SYN-ACK, [P.] data, [F.] FIN, [R] reset.
pub fn tcp_flags(f: u8) -> String {
    let mut s = String::from("[");
    for (bit, c) in [
        (0x02, 'S'),
        (0x01, 'F'),
        (0x04, 'R'),
        (0x08, 'P'),
        (0x20, 'U'),
    ] {
        if f & bit != 0 {
            s.push(c);
        }
    }
    if f & 0x10 != 0 {
        s.push('.');
    }
    if s.len() == 1 {
        s.push_str("none");
    }
    s.push(']');
    s
}

fn tcp_app(p: &[u8], sport: Option<u16>, dport: Option<u16>) -> Option<String> {
    if p.is_empty() {
        return None;
    }
    if let Some(t) = tls(p) {
        return Some(t);
    }
    // DNS over TCP has a two-byte length prefix.
    if sport == Some(53) || dport == Some(53) {
        return p.get(2..).and_then(dns).map(|d| format!("DNS {d}"));
    }
    for m in [
        "GET ", "POST ", "PUT ", "HEAD ", "DELETE ", "OPTIONS ", "PATCH ", "CONNECT ", "HTTP/1.",
    ] {
        if p.starts_with(m.as_bytes()) {
            return Some(first_line(p));
        }
    }
    if p.starts_with(b"SSH-") {
        return Some(first_line(p));
    }
    None
}

fn first_line(p: &[u8]) -> String {
    let end = p
        .iter()
        .position(|&b| b == b'\r' || b == b'\n')
        .unwrap_or(p.len());
    printable(&p[..end], 120)
}

/// Payload text made safe for the terminal: printable ASCII only, at most
/// `max` characters.
pub fn printable(b: &[u8], max: usize) -> String {
    let mut s: String = b
        .iter()
        .take(max)
        .map(|&c| {
            if (0x20..0x7f).contains(&c) {
                c as char
            } else {
                '.'
            }
        })
        .collect();
    if b.len() > max {
        s.push('…');
    }
    s
}

fn tls(p: &[u8]) -> Option<String> {
    let (&ty, rest) = p.split_first()?;
    if !(20..=23).contains(&ty) || rest.first() != Some(&3) || rest.get(1).is_none_or(|v| *v > 4) {
        return None;
    }
    Some(match ty {
        20 => "TLS change cipher spec".into(),
        21 => "TLS alert".into(),
        22 => match p.get(5) {
            Some(1) => match sni(p) {
                Some(name) => format!("TLS ClientHello → {name}"),
                None => "TLS ClientHello".into(),
            },
            Some(2) => "TLS ServerHello".into(),
            _ => "TLS handshake".into(),
        },
        _ => "TLS data (encrypted)".into(),
    })
}

/// The server name from a TLS ClientHello, if it's in the captured bytes.
pub fn sni(p: &[u8]) -> Option<String> {
    // record header (5), handshake header (4), version (2), random (32)
    let mut i = 5 + 4 + 2 + 32;
    let sid = *p.get(i)? as usize;
    i += 1 + sid;
    let suites = u16::from_be_bytes([*p.get(i)?, *p.get(i + 1)?]) as usize;
    i += 2 + suites;
    let comp = *p.get(i)? as usize;
    i += 1 + comp;
    let ext_end = i + 2 + u16::from_be_bytes([*p.get(i)?, *p.get(i + 1)?]) as usize;
    i += 2;
    while i + 4 <= ext_end.min(p.len()) {
        let ty = u16::from_be_bytes([p[i], p[i + 1]]);
        let len = u16::from_be_bytes([p[i + 2], p[i + 3]]) as usize;
        if ty == 0 {
            // server_name list: u16 list length, u8 type, u16 name length, name
            let n = u16::from_be_bytes([*p.get(i + 7)?, *p.get(i + 8)?]) as usize;
            let name = p.get(i + 9..i + 9 + n)?;
            return Some(printable(name, 100));
        }
        i += 4 + len;
    }
    None
}

fn udp_app(p: &[u8], sport: u16, dport: u16) -> Option<String> {
    let port = |n: u16| sport == n || dport == n;
    if port(53) || port(5353) || port(5355) {
        let label = if port(5353) {
            "mDNS"
        } else if port(5355) {
            "LLMNR"
        } else {
            "DNS"
        };
        return dns(p).map(|d| format!("{label} {d}"));
    }
    if port(443) && !p.is_empty() {
        let b = p[0];
        return Some(if b & 0x80 != 0 {
            match (b >> 4) & 3 {
                0 => "QUIC Initial",
                1 => "QUIC 0-RTT",
                2 => "QUIC Handshake",
                _ => "QUIC Retry",
            }
            .to_string()
        } else {
            "QUIC data (encrypted)".into()
        });
    }
    if port(123) {
        return Some("NTP".into());
    }
    if port(67) || port(68) {
        return Some("DHCP".into());
    }
    if port(1900) {
        return Some(first_line(p));
    }
    None
}

/// "A? example.com" for a query, "A example.com → 93.184.216.34 (+1)" for an answer.
pub fn dns(p: &[u8]) -> Option<String> {
    if p.len() < 12 {
        return None;
    }
    let response = p[2] & 0x80 != 0;
    let rcode = p[3] & 0x0f;
    let qd = u16::from_be_bytes([p[4], p[5]]);
    let an = u16::from_be_bytes([p[6], p[7]]) as usize;
    let mut i = 12;
    let (qname, q_type) = if qd > 0 {
        let (name, next) = dns_name(p, i)?;
        let ty = u16::from_be_bytes([*p.get(next)?, *p.get(next + 1)?]);
        i = next + 4;
        (name, ty)
    } else {
        (String::new(), 0)
    };
    let ty = rr_type(q_type);
    if !response {
        return Some(format!("{ty}? {qname}"));
    }
    if rcode == 3 {
        return Some(format!("{ty} {qname} → no such name"));
    }
    if rcode != 0 {
        return Some(format!("{ty} {qname} → error {rcode}"));
    }
    // The first address in the answers.
    let mut first = None;
    for _ in 0..an.min(32) {
        let (_, next) = dns_name(p, i)?;
        let rty = u16::from_be_bytes([*p.get(next)?, *p.get(next + 1)?]);
        let rlen = u16::from_be_bytes([*p.get(next + 8)?, *p.get(next + 9)?]) as usize;
        let rdata = p.get(next + 10..next + 10 + rlen)?;
        if first.is_none() {
            first = match (rty, rlen) {
                (1, 4) => Some(Ipv4Addr::new(rdata[0], rdata[1], rdata[2], rdata[3]).to_string()),
                (28, 16) => Some(Ipv6Addr::from(<[u8; 16]>::try_from(rdata).ok()?).to_string()),
                _ => None,
            };
        }
        i = next + 10 + rlen;
    }
    let answer = match (first, an) {
        (_, 0) => "no answers".to_string(),
        (Some(a), 1) => a,
        (Some(a), n) => format!("{a} (+{})", n - 1),
        (None, n) => format!("{n} answers"),
    };
    Some(format!("{ty} {qname} → {answer}"))
}

/// Reads a possibly-compressed name. Returns it and the offset just past it.
fn dns_name(p: &[u8], mut i: usize) -> Option<(String, usize)> {
    let mut labels: Vec<String> = Vec::new();
    let mut end = None;
    for _ in 0..64 {
        let len = *p.get(i)? as usize;
        match len {
            0 => {
                let next = end.unwrap_or(i + 1);
                let name = if labels.is_empty() {
                    ".".into()
                } else {
                    labels.join(".")
                };
                return Some((name, next));
            }
            l if l & 0xc0 == 0xc0 => {
                let ptr = ((l & 0x3f) << 8) | *p.get(i + 1)? as usize;
                end.get_or_insert(i + 2);
                i = ptr;
            }
            l => {
                labels.push(printable(p.get(i + 1..i + 1 + l)?, 63));
                i += 1 + l;
            }
        }
    }
    None
}

fn rr_type(t: u16) -> String {
    match t {
        1 => "A".into(),
        2 => "NS".into(),
        5 => "CNAME".into(),
        6 => "SOA".into(),
        12 => "PTR".into(),
        15 => "MX".into(),
        16 => "TXT".into(),
        28 => "AAAA".into(),
        33 => "SRV".into(),
        64 => "SVCB".into(),
        65 => "HTTPS".into(),
        255 => "ANY".into(),
        t => format!("type{t}"),
    }
}

fn icmp_name(v6: bool, kind: u8, code: u8) -> String {
    let s = if v6 {
        match kind {
            1 => "destination unreachable",
            2 => "packet too big",
            3 => "time exceeded",
            128 => "echo request",
            129 => "echo reply",
            133 => "router solicitation",
            134 => "router advertisement",
            135 => "neighbor solicitation",
            136 => "neighbor advertisement",
            143 => "multicast listener report",
            _ => "",
        }
    } else {
        match kind {
            0 => "echo reply",
            3 => "destination unreachable",
            5 => "redirect",
            8 => "echo request",
            11 => "time exceeded",
            _ => "",
        }
    };
    if s.is_empty() {
        format!("type {kind} code {code}")
    } else {
        s.into()
    }
}

/// Ports whose traffic is encrypted by convention (TLS, QUIC, SSH...).
const ENCRYPTED_PORTS: &[(&str, u16, &str)] = &[
    ("TCP", 443, "HTTPS port"),
    ("UDP", 443, "QUIC port"),
    ("TCP", 853, "DNS-over-TLS port"),
    ("UDP", 853, "DNS-over-QUIC port"),
    ("TCP", 22, "SSH port"),
    ("TCP", 993, "IMAPS port"),
    ("TCP", 995, "POP3S port"),
    ("TCP", 465, "SMTPS port"),
    ("TCP", 636, "LDAPS port"),
    ("TCP", 5223, "TLS port"),
    ("TCP", 8443, "HTTPS port"),
    ("UDP", 51820, "WireGuard port"),
];

/// Sorts packets into empty, plain, encrypted, compressed and binary. It
/// remembers which conversations turned out to be encrypted, so the middle of
/// a TLS stream (segments that don't start a TLS record) is still marked
/// encrypted, and which speak HTTP, so their compressed bodies aren't.
#[derive(Default)]
pub struct Classifier {
    encrypted: HashMap<FlowKey, &'static str>,
    /// Conversations seen speaking HTTP, whose random-looking packets are
    /// compressed bodies rather than encryption.
    http: HashSet<FlowKey>,
}

/// Remembered conversations are forgotten in bulk past this many.
const MAX_FLOWS: usize = 50_000;

/// The reason `guess` gives for high-entropy bytes. Only a hint, so it isn't
/// remembered for the rest of the conversation.
const RANDOM: &str = "looks random";
const SSH_GREETING: &str = "SSH greeting";
/// FTP, SMTP (and submission), POP3 and IMAP: where login commands are
/// sent as lines of text. Elsewhere "PASS ..." or "x LOGIN y z" is just text.
const MAIL_FTP_PORTS: &[u16] = &[21, 25, 110, 143, 587, 2525];

impl Classifier {
    /// Sets `p.content`, and adds a hint to the info line when the decoder
    /// didn't say what the payload is.
    pub fn apply(&mut self, p: &mut Packet) {
        let flow = p.flow();
        let content = self.classify(p, flow.as_ref());
        match (content, flow) {
            // A protocol known to be encrypted (TLS, QUIC, SSH, its port): the
            // rest of the conversation is too, even mid-record segments.
            (Content::Encrypted(why), Some(f)) if why != RANDOM => self.remember_encrypted(f, why),
            // The greeting is readable, but everything after it is encrypted,
            // whatever the port.
            (Content::Plain(SSH_GREETING), Some(f)) => self.remember_encrypted(f, "SSH"),
            (Content::Plain("HTTP"), Some(f)) => {
                if self.http.len() > MAX_FLOWS {
                    self.http.clear();
                }
                self.http.insert(f);
            }
            _ => {}
        }
        p.content = content;
        if content.unencrypted_data()
            && let Some(d) = &p.head
        {
            let mail_or_ftp = [d.sport, d.dport]
                .iter()
                .any(|p| p.is_some_and(|p| MAIL_FTP_PORTS.contains(&p)));
            p.secret = credentials(
                p.payload(),
                mail_or_ftp && content != Content::Plain("HTTP"),
            );
        }
        let preview = match content {
            Content::Plain("text") => Some(printable_line(p.payload(), 80)),
            Content::Encrypted(why) => Some(format!("encrypted ({why})")),
            Content::Compressed => Some("compressed".to_string()),
            _ => None,
        };
        if let (Some(extra), Some(d)) = (preview, p.head.as_mut())
            && !d.info.contains("  ")
        {
            d.info.push_str("  ");
            d.info.push_str(&extra);
        }
    }

    fn remember_encrypted(&mut self, f: FlowKey, why: &'static str) {
        if self.encrypted.len() > MAX_FLOWS {
            self.encrypted.clear();
        }
        self.encrypted.entry(f).or_insert(why);
    }

    fn classify(&self, p: &Packet, flow: Option<&FlowKey>) -> Content {
        let Some(d) = &p.head else {
            return Content::Binary;
        };
        if matches!(d.l4, L4::Icmp { .. }) {
            return Content::Plain("ICMP");
        }
        if d.payload_len == 0 || d.info == "fragment" {
            return Content::Empty;
        }
        let payload = p.payload();
        let app = p.app_info().unwrap_or("");
        let ports = [d.sport, d.dport];
        // Recognized protocols first.
        if app.starts_with("TLS ClientHello") {
            return Content::Plain("TLS hello, server name in clear");
        }
        if app.starts_with("TLS") {
            return Content::Encrypted("TLS");
        }
        if app.starts_with("QUIC") {
            return Content::Encrypted("QUIC");
        }
        if app.starts_with("SSH-") {
            return Content::Plain(SSH_GREETING);
        }
        for (prefix, why) in [
            ("DNS", "DNS"),
            ("mDNS", "mDNS"),
            ("LLMNR", "LLMNR"),
            ("NTP", "NTP"),
            ("DHCP", "DHCP"),
        ] {
            if app.starts_with(prefix) && !ports.contains(&Some(853)) {
                return Content::Plain(why);
            }
        }
        if !app.is_empty() && looks_like_http(app) {
            return Content::Plain("HTTP");
        }
        // Then what this conversation was earlier, and well-known ports.
        if let Some(why) = flow.and_then(|f| self.encrypted.get(f)) {
            return Content::Encrypted(why);
        }
        if ports.contains(&Some(22)) && d.proto() == "TCP" {
            return Content::Encrypted("SSH");
        }
        for &(proto, port, why) in ENCRYPTED_PORTS {
            if d.proto() == proto && ports.contains(&Some(port)) {
                return Content::Encrypted(why);
            }
        }
        // Finally, the bytes themselves.
        match guess(payload) {
            Content::Encrypted(RANDOM)
                if compressed_magic(payload) || flow.is_some_and(|f| self.http.contains(f)) =>
            {
                Content::Compressed
            }
            c => c,
        }
    }
}

/// Where `needle` first appears in `hay`, ignoring ASCII case.
pub fn find_ignore_case(hay: &[u8], needle: &[u8]) -> Option<usize> {
    find_ignore_case_from(hay, needle, 0)
}

/// Like `find_ignore_case`, starting at `from`.
pub fn find_ignore_case_from(hay: &[u8], needle: &[u8], from: usize) -> Option<usize> {
    let (&first, rest) = needle.split_first()?;
    let first = first.to_ascii_lowercase();
    let last = hay.len().checked_sub(needle.len())?;
    (from..=last).find(|&i| {
        hay[i].to_ascii_lowercase() == first
            && hay[i + 1..i + needle.len()].eq_ignore_ascii_case(rest)
    })
}

/// What kind of login secret a readable payload carries, if any: a password
/// field in a form, JSON or query string, an HTTP Authorization header, or
/// (with `commands`, on a mail or FTP connection) the login commands of FTP,
/// POP3, SMTP and IMAP.
pub fn credentials(b: &[u8], commands: bool) -> Option<&'static str> {
    // Header names and commands are case-insensitive.
    let find = |needle: &[u8]| find_ignore_case(b, needle);
    let at_line_start = |i: usize| i == 0 || b[i - 1] == b'\n';
    if let Some(i) = find(b"authorization: basic ")
        && at_line_start(i)
    {
        // base64 of "user:password": anyone can decode it.
        return Some("HTTP Basic login");
    }
    if let Some(i) = find(b"authorization:")
        && at_line_start(i)
    {
        return Some("HTTP Authorization header");
    }
    // A password-like key followed by a value: form fields and query strings
    // (password=…), JSON ("password": "…").
    for key in [&b"password"[..], b"passwd", b"passphrase", b"pwd", b"pass"] {
        let mut from = 0;
        while let Some(i) = find_ignore_case_from(b, key, from) {
            from = i + 1;
            // The key must be a whole word: "pass" in "bypass=" doesn't count.
            let before = if i == 0 { b' ' } else { b[i - 1] };
            if before.is_ascii_alphanumeric() {
                continue;
            }
            let rest = &b[i + key.len()..];
            let value = match rest {
                [b'=', v, ..] => *v,
                [b'"', b':', ..] => {
                    let v = rest[2..].iter().find(|c| **c != b' ');
                    match v {
                        Some(b'"') => rest[2..]
                            .iter()
                            .skip_while(|c| **c == b' ')
                            .nth(1)
                            .copied()
                            .unwrap_or(b'"'),
                        _ => b'"',
                    }
                }
                _ => continue,
            };
            // An empty value isn't a password being sent.
            if !matches!(value, b'&' | b'"' | b'\r' | b'\n' | b' ') {
                return Some("password field");
            }
        }
    }
    if !commands {
        return None;
    }
    // These protocols end each command with CRLF.
    for line in b.split(|&c| c == b'\n') {
        let Some(line) = line.strip_suffix(b"\r") else {
            continue;
        };
        let mut words = line.split(|&c| c == b' ').filter(|w| !w.is_empty());
        let (first, second) = (words.next().unwrap_or(b""), words.next());
        if first.eq_ignore_ascii_case(b"PASS") && second.is_some() {
            return Some("PASS command (FTP, POP3)");
        }
        if first.eq_ignore_ascii_case(b"AUTH")
            && second.is_some_and(|s| {
                s.eq_ignore_ascii_case(b"PLAIN") || s.eq_ignore_ascii_case(b"LOGIN")
            })
        {
            return Some("SMTP login");
        }
        // IMAP: "a001 LOGIN user password".
        if second.is_some_and(|s| s.eq_ignore_ascii_case(b"LOGIN")) && words.nth(1).is_some() {
            return Some("IMAP login");
        }
    }
    None
}

/// Whether bytes start like gzip, zstd or xz data.
fn compressed_magic(b: &[u8]) -> bool {
    b.starts_with(&[0x1f, 0x8b, 0x08])
        || b.starts_with(&[0x28, 0xb5, 0x2f, 0xfd])
        || b.starts_with(&[0xfd, b'7', b'z', b'X', b'Z', 0])
}

fn looks_like_http(app: &str) -> bool {
    app.starts_with("HTTP/1.")
        || app.ends_with(" HTTP/1.1")
        || app.ends_with(" HTTP/1.0")
        || app.starts_with("NOTIFY ")
        || app.starts_with("M-SEARCH ")
}

/// Text, random-looking (encrypted or compressed), or other binary.
fn guess(b: &[u8]) -> Content {
    if b.len() < 16 {
        return Content::Binary;
    }
    let text = b
        .iter()
        .filter(|&&c| (0x20..0x7f).contains(&c) || matches!(c, b'\r' | b'\n' | b'\t'))
        .count();
    if text * 100 >= b.len() * 90 {
        return Content::Plain("text");
    }
    // Shannon entropy in bits per byte. Random data of n bytes can reach at
    // most log2(n), so compare against that for short payloads.
    let mut counts = [0u32; 256];
    for &c in b {
        counts[c as usize] += 1;
    }
    let n = b.len() as f64;
    let h: f64 = counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let q = c as f64 / n;
            -q * q.log2()
        })
        .sum();
    let max = n.min(256.0).log2();
    if b.len() >= 64 && h >= 0.9 * max {
        Content::Encrypted(RANDOM)
    } else {
        Content::Binary
    }
}

/// The first line of a payload, made safe for the terminal.
pub fn printable_line(b: &[u8], max: usize) -> String {
    let end = b
        .iter()
        .position(|&c| c == b'\r' || c == b'\n')
        .unwrap_or(b.len());
    printable(&b[..end], max)
}

/// Local wall-clock time of day with milliseconds: "14:03:27.512".
pub fn clock(t: SystemTime) -> String {
    let d = t.duration_since(SystemTime::UNIX_EPOCH).unwrap_or_default();
    let secs = d.as_secs() as libc::time_t;
    // SAFETY: tm is plain data; localtime_r fills it from a valid time_t.
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    let ok = !unsafe { libc::localtime_r(&secs, &mut tm) }.is_null();
    let (h, m, s) = if ok {
        (tm.tm_hour as u64, tm.tm_min as u64, tm.tm_sec as u64)
    } else {
        let s = d.as_secs() % 86400;
        (s / 3600, s / 60 % 60, s % 60)
    };
    format!("{h:02}:{m:02}:{s:02}.{:03}", d.subsec_millis())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// Builds an IPv4 packet around a TCP or UDP payload.
    pub(crate) fn ipv4(
        proto: u8,
        src: [u8; 4],
        dst: [u8; 4],
        sport: u16,
        dport: u16,
        flags: u8,
        payload: &[u8],
    ) -> Vec<u8> {
        let l4_len = if proto == TCP { 20 } else { 8 };
        let total = 20 + l4_len + payload.len();
        let mut p = vec![0u8; total];
        p[0] = 0x45;
        p[2..4].copy_from_slice(&(total as u16).to_be_bytes());
        p[8] = 64;
        p[9] = proto;
        p[12..16].copy_from_slice(&src);
        p[16..20].copy_from_slice(&dst);
        p[20..22].copy_from_slice(&sport.to_be_bytes());
        p[22..24].copy_from_slice(&dport.to_be_bytes());
        if proto == TCP {
            p[24..28].copy_from_slice(&1000u32.to_be_bytes());
            p[32] = 5 << 4;
            p[33] = flags;
            p[34..36].copy_from_slice(&502u16.to_be_bytes());
        } else {
            p[24..26].copy_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
        }
        p[20 + l4_len..].copy_from_slice(payload);
        p
    }

    pub(crate) fn dns_query(name: &str, ty: u16) -> Vec<u8> {
        let mut q = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        for label in name.split('.') {
            q.push(label.len() as u8);
            q.extend_from_slice(label.as_bytes());
        }
        q.push(0);
        q.extend_from_slice(&ty.to_be_bytes());
        q.extend_from_slice(&[0, 1]);
        q
    }

    pub(crate) fn client_hello(name: &str) -> Vec<u8> {
        let mut ext = Vec::new();
        // An unrelated extension first, as browsers do.
        ext.extend_from_slice(&[0x00, 0x17, 0x00, 0x00]);
        let n = name.len() as u16;
        ext.extend_from_slice(&[0x00, 0x00]);
        ext.extend_from_slice(&(n + 5).to_be_bytes());
        ext.extend_from_slice(&(n + 3).to_be_bytes());
        ext.push(0);
        ext.extend_from_slice(&n.to_be_bytes());
        ext.extend_from_slice(name.as_bytes());
        let mut body = vec![0x03, 0x03];
        body.extend_from_slice(&[7; 32]);
        body.push(0); // session id
        body.extend_from_slice(&[0, 2, 0x13, 0x01]); // one cipher suite
        body.extend_from_slice(&[1, 0]); // compression
        body.extend_from_slice(&(ext.len() as u16).to_be_bytes());
        body.extend_from_slice(&ext);
        let mut hs = vec![1, 0];
        hs.extend_from_slice(&(body.len() as u16).to_be_bytes());
        hs.extend_from_slice(&body);
        let mut rec = vec![22, 3, 1];
        rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        rec.extend_from_slice(&hs);
        rec
    }

    #[test]
    fn decodes_tcp_with_app_hints() {
        let syn = ipv4(TCP, [192, 168, 0, 74], [1, 1, 1, 1], 51000, 443, 0x02, &[]);
        let d = decode(&syn, syn.len() as u32).unwrap();
        assert_eq!(d.proto(), "TCP");
        assert_eq!((d.sport, d.dport), (Some(51000), Some(443)));
        assert_eq!(d.info, "[S]");

        let hello = client_hello("example.com");
        let p = ipv4(
            TCP,
            [192, 168, 0, 74],
            [1, 1, 1, 1],
            51000,
            443,
            0x18,
            &hello,
        );
        let d = decode(&p, p.len() as u32).unwrap();
        assert_eq!(d.payload_len, hello.len());
        assert_eq!(
            d.info,
            format!("[P.] len {}  TLS ClientHello → example.com", hello.len())
        );

        let get = b"GET /index.html HTTP/1.1\r\nHost: x\r\n\r\n";
        let p = ipv4(TCP, [10, 0, 0, 1], [10, 0, 0, 2], 40000, 80, 0x18, get);
        let d = decode(&p, p.len() as u32).unwrap();
        assert!(d.info.ends_with("GET /index.html HTTP/1.1"), "{}", d.info);

        // Only the start was captured, but the length comes from the wire.
        let d = decode(&p[..44], 9000).unwrap();
        assert_eq!(d.payload_len, 9000 - 40);
    }

    #[test]
    fn decodes_dns_quic_and_icmp() {
        let q = dns_query("nitro.example.org", 28);
        let p = ipv4(UDP, [192, 168, 0, 74], [192, 168, 0, 1], 41000, 53, 0, &q);
        let d = decode(&p, p.len() as u32).unwrap();
        assert_eq!(
            d.info,
            format!("len {}  DNS AAAA? nitro.example.org", q.len())
        );

        // A response with a compressed answer name and one A record.
        let mut r = dns_query("example.com", 1);
        r[2] = 0x81;
        r[3] = 0x80;
        r[7] = 1;
        r.extend_from_slice(&[0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 93, 184, 216, 34]);
        assert_eq!(dns(&r).unwrap(), "A example.com → 93.184.216.34");
        r[3] = 0x83;
        assert_eq!(dns(&r).unwrap(), "A example.com → no such name");
        // A pointer loop gives up rather than spinning.
        let mut lp = dns_query("a", 1);
        lp[12] = 0xc0;
        lp[13] = 12;
        assert_eq!(dns(&lp), None);

        let p = ipv4(
            UDP,
            [192, 168, 0, 74],
            [1, 1, 1, 1],
            41000,
            443,
            0,
            &[0xc3, 0, 0, 0, 1],
        );
        assert!(
            decode(&p, p.len() as u32)
                .unwrap()
                .info
                .ends_with("QUIC Initial")
        );

        let mut ping = vec![0u8; 28];
        ping[0] = 0x45;
        ping[9] = ICMP;
        ping[20] = 8;
        ping[25] = 7;
        ping[27] = 3;
        let d = decode(&ping, 28).unwrap();
        assert_eq!(
            (d.proto(), d.info.as_str()),
            ("ICMP", "echo request id 7 seq 3")
        );
    }

    #[test]
    fn decodes_ipv6_and_rejects_junk() {
        let mut p = vec![0u8; 40 + 8 + 3];
        p[0] = 0x60;
        p[6] = UDP;
        p[7] = 255;
        p[8..24].copy_from_slice(&"fe80::1".parse::<Ipv6Addr>().unwrap().octets());
        p[24..40].copy_from_slice(&"ff02::fb".parse::<Ipv6Addr>().unwrap().octets());
        p[40..42].copy_from_slice(&5353u16.to_be_bytes());
        p[42..44].copy_from_slice(&5353u16.to_be_bytes());
        let d = decode(&p, p.len() as u32).unwrap();
        assert_eq!(d.src.to_string(), "fe80::1");
        assert_eq!((d.version, d.ttl, d.payload_len), (6, 255, 3));

        assert_eq!(decode(&[], 0), None);
        assert_eq!(decode(&[0x45, 0, 0], 3), None);
        assert_eq!(decode(&[0x99; 60], 60), None);
        // A TCP header cut short still gives the addresses.
        let t = ipv4(TCP, [1, 2, 3, 4], [5, 6, 7, 8], 1, 2, 0x10, &[]);
        let d = decode(&t[..30], 40).unwrap();
        assert_eq!((d.info.as_str(), d.sport), ("truncated header", None));
    }

    fn packet(data: Vec<u8>, outgoing: bool) -> Packet {
        let len = data.len() as u32;
        Packet {
            id: 0,
            at: SystemTime::UNIX_EPOCH,
            owner: Owner::Kernel,
            program: "test".into(),
            outgoing,
            len,
            head: decode(&data, len),
            data,
            content: Content::Empty,
            secret: None,
        }
    }

    #[test]
    fn classifies_content_and_remembers_encrypted_flows() {
        let me = [10, 0, 0, 2];
        let srv = [10, 0, 0, 9];
        let mut c = Classifier::default();
        let mut run = |data: Vec<u8>, out: bool| {
            let mut p = packet(data, out);
            c.apply(&mut p);
            (p.content, p.head.unwrap().info)
        };
        // A TLS conversation on an unusual port.
        let (k, _) = run(ipv4(TCP, me, srv, 5000, 7000, 0x02, &[]), true);
        assert_eq!(k, Content::Empty);
        let (k, _) = run(
            ipv4(TCP, me, srv, 5000, 7000, 0x18, &client_hello("x.test")),
            true,
        );
        assert_eq!(k, Content::Plain("TLS hello, server name in clear"));
        let mut rec = vec![23, 3, 3, 0, 200];
        rec.extend([0x41; 200]);
        let (k, _) = run(ipv4(TCP, srv, me, 7000, 5000, 0x18, &rec), false);
        assert_eq!(k, Content::Encrypted("TLS"));
        // A later segment mid-record is still known to be encrypted.
        let (k, info) = run(ipv4(TCP, srv, me, 7000, 5000, 0x10, &[0x41; 100]), false);
        assert_eq!(k, Content::Encrypted("TLS"));
        assert!(info.ends_with("encrypted (TLS)"), "{info}");

        // Plain protocols and text.
        let get = b"GET /a HTTP/1.1\r\nHost: b\r\n\r\n";
        let (k, _) = run(ipv4(TCP, me, srv, 5001, 8080, 0x18, get), true);
        assert_eq!(k, Content::Plain("HTTP"));
        let (k, info) = run(
            ipv4(
                TCP,
                me,
                srv,
                5002,
                6667,
                0x18,
                b"PRIVMSG #rust :hello there\r\n",
            ),
            true,
        );
        assert_eq!(k, Content::Plain("text"));
        assert!(info.ends_with("PRIVMSG #rust :hello there"), "{info}");
        let (k, _) = run(
            ipv4(UDP, me, srv, 5003, 53, 0, &dns_query("a.test", 1)),
            true,
        );
        assert_eq!(k, Content::Plain("DNS"));

        // Ports and the bytes themselves.
        let (k, _) = run(ipv4(TCP, me, srv, 5004, 443, 0x18, &[1, 2, 3]), true);
        assert_eq!(k, Content::Encrypted("HTTPS port"));
        let random: Vec<u8> = (0..512u32)
            .map(|i| (i.wrapping_mul(2654435761) >> 13) as u8)
            .collect();
        let (k, _) = run(ipv4(UDP, me, srv, 5005, 9999, 0, &random), true);
        assert_eq!(k, Content::Encrypted("looks random"));
        let (k, _) = run(ipv4(UDP, me, srv, 5006, 9999, 0, &[0u8; 100]), true);
        assert_eq!(k, Content::Binary);
        assert!(Content::Binary.unencrypted_data() && !Content::Empty.unencrypted_data());

        // Random-looking bytes are only a hint: the conversation isn't marked
        // encrypted, so readable text later on it is still plain.
        let (k, _) = run(ipv4(TCP, me, srv, 5007, 9000, 0x18, &random), true);
        assert_eq!(k, Content::Encrypted("looks random"));
        let (k, _) = run(
            ipv4(
                TCP,
                me,
                srv,
                5007,
                9000,
                0x18,
                b"user=admin&password=hunter2",
            ),
            true,
        );
        assert_eq!(k, Content::Plain("text"));

        // On an HTTP conversation they're a compressed body, and so is
        // anything starting with gzip's magic bytes.
        let (k, _) = run(
            ipv4(
                TCP,
                srv,
                me,
                80,
                5008,
                0x18,
                b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\n\r\n",
            ),
            false,
        );
        assert_eq!(k, Content::Plain("HTTP"));
        let (k, info) = run(ipv4(TCP, srv, me, 80, 5008, 0x18, &random), false);
        assert_eq!(k, Content::Compressed);
        assert!(info.ends_with("compressed"), "{info}");
        let mut gz = vec![0x1f, 0x8b, 0x08, 0];
        gz.extend(&random);
        let (k, _) = run(ipv4(UDP, me, srv, 5009, 9999, 0, &gz), true);
        assert_eq!(k, Content::Compressed);
        assert!(Content::Compressed.unencrypted_data());
    }

    #[test]
    fn finds_credentials_in_clear() {
        let yes: &[(&[u8], &str)] = &[
            (b"username=admin&password=hunter2", "password field"),
            (b"user=a&pwd=x", "password field"),
            (b"GET /login?user=a&pass=b HTTP/1.1\r\n", "password field"),
            (
                br#"{"username":"a","password": "hunter2"}"#,
                "password field",
            ),
            (
                b"GET / HTTP/1.1\r\nAuthorization: Basic YTpi\r\n\r\n",
                "HTTP Basic login",
            ),
            (
                b"GET / HTTP/1.1\r\nauthorization: Bearer xyz\r\n\r\n",
                "HTTP Authorization header",
            ),
            (b"PASS hunter2\r\n", "PASS command (FTP, POP3)"),
            (b"AUTH PLAIN AGFAYg==\r\n", "SMTP login"),
            (b"a001 LOGIN alice hunter2\r\n", "IMAP login"),
        ];
        for (b, want) in yes {
            assert_eq!(
                credentials(b, true),
                Some(*want),
                "{}",
                String::from_utf8_lossy(b)
            );
        }
        let no: &[&[u8]] = &[
            b"GET /forgot-password HTTP/1.1\r\n",
            b"bypass=1&compass=north",
            b"password=&user=a",
            br#"{"password": ""}"#,
            b"The password is never sent.",
            b"X-Authorization-Hint: none\r\n",
            b"a001 LOGOUT\r\n",
            // A line not ended with CRLF isn't a command.
            b"PASS hunter2\n",
        ];
        for b in no {
            assert_eq!(credentials(b, true), None, "{}", String::from_utf8_lossy(b));
        }
        // Login commands count only on mail and FTP connections: elsewhere
        // they are ordinary words.
        for b in [
            &b"Please login to continue\r\n"[..],
            b"Pass the salt please\r\n",
            b"PASS hunter2\r\n",
        ] {
            assert_eq!(
                credentials(b, false),
                None,
                "{}",
                String::from_utf8_lossy(b)
            );
        }
        // Set on readable packets only.
        let mut c = Classifier::default();
        let mut p = packet(
            ipv4(
                TCP,
                [10, 0, 0, 2],
                [10, 0, 0, 1],
                5000,
                80,
                0x18,
                b"user=a&password=b",
            ),
            true,
        );
        c.apply(&mut p);
        assert_eq!(p.secret, Some("password field"));
        let mut p = packet(
            ipv4(
                TCP,
                [10, 0, 0, 2],
                [10, 0, 0, 1],
                5000,
                443,
                0x18,
                b"user=a&password=b",
            ),
            true,
        );
        c.apply(&mut p);
        assert_eq!(p.secret, None);
        // A login command on an IMAP connection, but not the same words in a
        // web page.
        let tcp = |dport: u16, data: &[u8]| {
            packet(
                ipv4(TCP, [10, 0, 0, 2], [10, 0, 0, 1], 5000, dport, 0x18, data),
                true,
            )
        };
        let mut p = tcp(143, b"a001 LOGIN alice hunter2\r\n");
        c.apply(&mut p);
        assert_eq!(p.secret, Some("IMAP login"));
        let mut p = tcp(8080, b"Please login to continue, then pass go\r\n");
        c.apply(&mut p);
        assert_eq!(p.secret, None);
    }

    #[test]
    fn dns_over_tcp_is_labelled() {
        let mut q = vec![0, 29, 0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
        q.extend_from_slice(b"\x07example\x03com\x00\x00\x01\x00\x01");
        let p = ipv4(TCP, [10, 0, 0, 2], [10, 0, 0, 1], 5000, 53, 0x18, &q);
        let info = decode(&p, p.len() as u32).unwrap().info;
        assert!(info.contains("DNS A? example.com"), "{info}");
    }

    #[test]
    fn ssh_on_any_port_is_remembered_as_encrypted() {
        let mut c = Classifier::default();
        let tcp = |sport, dport, data: &[u8]| {
            packet(
                ipv4(TCP, [10, 0, 0, 2], [10, 0, 0, 1], sport, dport, 0x18, data),
                true,
            )
        };
        let mut hello = tcp(5000, 2222, b"SSH-2.0-OpenSSH_9.9\r\n");
        c.apply(&mut hello);
        assert_eq!(hello.content, Content::Plain("SSH greeting"));
        // Later packets of that conversation, either way, are SSH.
        let mut later = tcp(5000, 2222, b"username=a&password=b but encrypted, honestly");
        c.apply(&mut later);
        assert_eq!(later.content, Content::Encrypted("SSH"));
        assert_eq!(later.secret, None);
        let mut back = tcp(2222, 5000, b"some bytes from the server side....");
        back.outgoing = false;
        back.head.as_mut().unwrap().src = "10.0.0.1".parse().unwrap();
        back.head.as_mut().unwrap().dst = "10.0.0.2".parse().unwrap();
        c.apply(&mut back);
        assert_eq!(back.content, Content::Encrypted("SSH"));
    }

    #[test]
    fn payload_text_is_terminal_safe() {
        assert_eq!(printable(b"ok\x1b[31mred\x07", 100), "ok.[31mred.");
        assert_eq!(printable("é".as_bytes(), 100), "..");
        assert_eq!(printable(b"abcdef", 3), "abc…");
        let get = b"GET /\x1b]0;pwned\x07 HTTP/1.1\r\n";
        let p = ipv4(TCP, [10, 0, 0, 1], [10, 0, 0, 2], 40000, 80, 0x18, get);
        let info = decode(&p, p.len() as u32).unwrap().info;
        assert!(!info.chars().any(|c| c.is_control()), "{info:?}");
        assert_eq!(tcp_flags(0x12), "[S.]");
        assert_eq!(tcp_flags(0x11), "[F.]");
        assert_eq!(tcp_flags(0x04), "[R]");
    }
}
