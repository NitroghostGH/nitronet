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
    }
}
