//! Colors and styles. It never sets a background except on the selected row
//! and on badges, so transparent terminals stay transparent. When NO_COLOR is
//! set (https://no-color.org), every color resets and only bold/dim/reverse remain.

use std::sync::OnceLock;

use ratatui::style::{Color, Modifier, Style};

pub struct Theme {
    pub text: Color,
    pub muted: Color,
    pub faint: Color,
    pub border: Color,
    pub border_focus: Color,
    pub surface: Color,
    pub accent: Color,
    pub on_accent: Color,
    pub rx: Color,
    pub rx_dim: Color,
    pub tx: Color,
    pub tx_dim: Color,
    pub good: Color,
    pub warn: Color,
    pub tcp: Color,
    pub udp: Color,
    pub color: bool,
}

const fn rgb(hex: u32) -> Color {
    Color::Rgb((hex >> 16) as u8, (hex >> 8) as u8, hex as u8)
}

static THEME: OnceLock<Theme> = OnceLock::new();

pub fn theme() -> &'static Theme {
    THEME.get_or_init(|| {
        let no_color = std::env::var_os("NO_COLOR").is_some_and(|v| !v.is_empty());
        if no_color {
            Theme::plain()
        } else {
            Theme::dark()
        }
    })
}

impl Theme {
    fn dark() -> Self {
        Self {
            text: rgb(0xc8d3f5),
            muted: rgb(0x828bb8),
            faint: rgb(0x444a73),
            border: rgb(0x3b4261),
            border_focus: rgb(0x65bcff),
            surface: rgb(0x2a3050),
            accent: rgb(0x65bcff),
            on_accent: rgb(0x1b1d2b),
            rx: rgb(0x4fd6be),
            rx_dim: rgb(0x1f5a52),
            tx: rgb(0xc099ff),
            tx_dim: rgb(0x4b3a75),
            good: rgb(0xc3e88d),
            warn: rgb(0xffc777),
            tcp: rgb(0x82aaff),
            udp: rgb(0xffc777),
            color: true,
        }
    }

    fn plain() -> Self {
        let r = Color::Reset;
        Self {
            text: r,
            muted: r,
            faint: r,
            border: r,
            border_focus: r,
            surface: r,
            accent: r,
            on_accent: r,
            rx: r,
            rx_dim: r,
            tx: r,
            tx_dim: r,
            good: r,
            warn: r,
            tcp: r,
            udp: r,
            color: false,
        }
    }

    pub fn fg(&self, c: Color) -> Style {
        Style::new().fg(c)
    }
    pub fn muted(&self) -> Style {
        let s = Style::new().fg(self.muted);
        if self.color {
            s
        } else {
            s.add_modifier(Modifier::DIM)
        }
    }
    pub fn faint(&self) -> Style {
        let s = Style::new().fg(self.faint);
        if self.color {
            s
        } else {
            s.add_modifier(Modifier::DIM)
        }
    }
    pub fn title(&self) -> Style {
        Style::new().fg(self.text).add_modifier(Modifier::BOLD)
    }
    pub fn header(&self) -> Style {
        Style::new().fg(self.muted).add_modifier(Modifier::BOLD)
    }
    pub fn selected(&self) -> Style {
        if self.color {
            Style::new().bg(self.surface).add_modifier(Modifier::BOLD)
        } else {
            Style::new().add_modifier(Modifier::REVERSED)
        }
    }
    /// A filled pill such as the active tab or a status badge.
    pub fn badge(&self, bg: Color) -> Style {
        if self.color {
            Style::new()
                .fg(self.on_accent)
                .bg(bg)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::new().add_modifier(Modifier::REVERSED | Modifier::BOLD)
        }
    }
}

/// Linear blend of two RGB colors. Non-RGB colors (NO_COLOR) just return `b`.
pub fn blend(a: Color, b: Color, t: f64) -> Color {
    match (a, b) {
        (Color::Rgb(r1, g1, b1), Color::Rgb(r2, g2, b2)) => {
            let t = t.clamp(0.0, 1.0);
            let mix = |x: u8, y: u8| (x as f64 + (y as f64 - x as f64) * t).round() as u8;
            Color::Rgb(mix(r1, r2), mix(g1, g2), mix(b1, b2))
        }
        _ => b,
    }
}
