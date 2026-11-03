//! Text formatting: byte amounts, addresses, truncation.

use std::net::SocketAddr;

use ratatui::style::Color;
use ratatui::text::{Line, Span};

use super::theme::theme;

const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];

fn split(b: f64) -> (String, &'static str) {
    let mut v = b.max(0.0);
    let mut i = 0;
    // Step up at 1000 rather than 1024, so values never need four digits ("1018 KiB").
    while v >= 1000.0 && i < UNITS.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    let num = if i == 0 || v >= 100.0 {
        format!("{v:.0}")
    } else if v < 1.0 {
        format!("{v:.2}")
    } else {
        format!("{v:.1}")
    };
    (num, UNITS[i])
}

/// Binary-unit byte count: "512 B", "1.4 KiB", "312 MiB".
pub fn human(b: f64) -> String {
    let (n, u) = split(b);
    format!("{n} {u}")
}

/// A right-aligned amount with the number in `color` and the unit dimmed.
/// Zero shows as a faint dot and `None` as a faint dash, so idle rows recede.
pub fn amount(v: Option<f64>, color: Color) -> Line<'static> {
    let t = theme();
    let line = match v {
        None => Line::from(Span::styled("—", t.faint())),
        Some(v) if v < 0.5 => Line::from(Span::styled("·", t.faint())),
        Some(v) => {
            let (n, u) = split(v);
            Line::from(vec![
                Span::styled(n, t.fg(color)),
                Span::styled(format!(" {u:<3}"), t.muted()),
            ])
        }
    };
    line.right_aligned()
}

/// Shows wildcard addresses as "*" or "*:port", the way `ss` does.
pub fn fmt_addr(a: SocketAddr) -> String {
    match (a.ip().is_unspecified(), a.port()) {
        (true, 0) => "*".into(),
        (true, p) => format!("*:{p}"),
        _ => a.to_string(),
    }
}

/// Shortens `s` to `max` chars by cutting the middle, so the port at the end of
/// a long IPv6 address stays visible.
pub fn elide_middle(s: &str, max: usize) -> String {
    let n = s.chars().count();
    if n <= max || max < 3 {
        return s.to_string();
    }
    let tail = max / 2;
    let head = max - tail - 1;
    let mut out: String = s.chars().take(head).collect();
    out.push('…');
    out.extend(s.chars().skip(n - tail));
    out
}

/// Cuts `s` to `max` chars with a trailing ellipsis.
pub fn elide_end(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    let mut out: String = s.chars().take(max.saturating_sub(1)).collect();
    out.push('…');
    out
}

/// Compact age: "now", "42s", "5m", "3h".
pub fn ago(t: std::time::Instant) -> String {
    let s = t.elapsed().as_secs();
    match s {
        0..5 => "now".into(),
        5..60 => format!("{s}s"),
        60..3600 => format!("{}m", s / 60),
        _ => format!("{}h", s / 3600),
    }
}

/// Round-trip time: "0.9 ms", "48 ms", "1.2 s".
pub fn fmt_rtt(d: std::time::Duration) -> String {
    let ms = d.as_secs_f64() * 1000.0;
    if ms < 10.0 {
        format!("{ms:.1} ms")
    } else if ms < 1000.0 {
        format!("{ms:.0} ms")
    } else {
        format!("{:.1} s", ms / 1000.0)
    }
}

/// A compact IPv6 address for a narrow column. Inside one of our own
/// prefixes only the interface part is shown ("…:ccb3:1923:75a6:cc01"), since
/// the prefix is the same for every device; anything else is shown in full.
pub fn short_v6(a: &std::net::Ipv6Addr, ours: &[(std::net::Ipv6Addr, u8)]) -> String {
    let bits = u128::from(*a);
    let local = !a.is_unicast_link_local()
        && ours.iter().any(|(p, len)| {
            *len > 0 && *len <= 64 && (bits ^ u128::from(*p)) >> (128 - *len as u32) == 0
        });
    if !local {
        return a.to_string();
    }
    let iid: Vec<String> = a.segments()[4..].iter().map(|g| format!("{g:x}")).collect();
    format!("…:{}", iid.join(":"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats() {
        assert_eq!(human(512.0), "512 B");
        assert_eq!(human(1536.0), "1.5 KiB");
        assert_eq!(human(300.0 * 1024.0 * 1024.0), "300 MiB");
        assert_eq!(human(1018.0 * 1024.0), "0.99 MiB");
        assert_eq!(fmt_addr("0.0.0.0:22".parse().unwrap()), "*:22");
        assert_eq!(fmt_addr("[::]:0".parse().unwrap()), "*");
        assert_eq!(fmt_addr("[::1]:80".parse().unwrap()), "[::1]:80");
        assert_eq!(elide_middle("abcdef", 6), "abcdef");
        assert_eq!(
            elide_middle("[2001:db8:322e:0:32c5:99ff:feaa:bb02]:37422", 20),
            "[2001:db8…b02]:37422"
        );
        assert_eq!(elide_end("wayland-wm@hyprland.desktop", 10), "wayland-w…");
        let ours = [("2001:db8:322e:0:32c5:99ff:feaa:bb02".parse().unwrap(), 64)];
        let a = "2001:db8:322e:0:ccb3:1923:75a6:cc01".parse().unwrap();
        assert_eq!(short_v6(&a, &ours), "…:ccb3:1923:75a6:cc01");
        let other = "2001:db8::1".parse().unwrap();
        assert_eq!(short_v6(&other, &ours), "2001:db8::1");
        let ll = "fe80::ca4a:a0ff:feaa:bb03".parse().unwrap();
        assert_eq!(short_v6(&ll, &ours), "fe80::ca4a:a0ff:feaa:bb03");
    }
}
