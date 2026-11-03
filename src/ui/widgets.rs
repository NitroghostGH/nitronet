//! Custom widgets: a gradient braille area graph, inline traffic bars, and
//! responsive table columns.

use ratatui::buffer::Buffer;
use ratatui::layout::{Constraint, Rect};
use ratatui::style::{Color, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::Widget;

use super::theme::{blend, theme};

/// Braille dot bits: [column][row from top].
const DOTS: [[u8; 4]; 2] = [[0x01, 0x02, 0x04, 0x40], [0x08, 0x10, 0x20, 0x80]];

/// A filled area graph drawn with braille dots (2×4 per cell). Each cell holds
/// two samples, so the graph scrolls by half a cell per sample. The newest
/// sample is at the right edge. `down` grows the area from the top edge
/// downward, so two graphs can be stacked mirror-image (download above, upload below).
pub struct Graph<'a> {
    pub data: &'a [f64],
    pub max: f64,
    /// Color at the baseline, blended toward `peak` at the far edge.
    pub base: Color,
    pub peak: Color,
    pub down: bool,
}

impl Widget for Graph<'_> {
    fn render(self, area: Rect, buf: &mut Buffer) {
        if area.is_empty() || self.max <= 0.0 {
            return;
        }
        let cols = area.width as usize * 2;
        let rows = area.height as usize * 4;
        let n = self.data.len();
        let heights: Vec<usize> = (0..cols)
            .map(|j| {
                let Some(idx) = (n + j).checked_sub(cols) else {
                    return 0;
                };
                let v = self.data[idx];
                if v <= 0.0 {
                    0
                } else {
                    ((v / self.max) * rows as f64)
                        .ceil()
                        .clamp(1.0, rows as f64) as usize
                }
            })
            .collect();

        for cy in 0..area.height as usize {
            // How far this cell row sits from the baseline (0 = at it, 1 = far edge).
            let t = if self.down {
                cy as f64 / (area.height as f64 - 1.0).max(1.0)
            } else {
                (area.height as usize - 1 - cy) as f64 / (area.height as f64 - 1.0).max(1.0)
            };
            let color = blend(self.base, self.peak, t);
            for cx in 0..area.width as usize {
                let mut bits = 0u8;
                for side in 0..2 {
                    let h = heights[cx * 2 + side];
                    for (dy, &bit) in DOTS[side].iter().enumerate() {
                        let dot_row = cy * 4 + dy; // from the top
                        let level = if self.down {
                            dot_row + 1
                        } else {
                            rows - dot_row
                        };
                        if level <= h {
                            bits |= bit;
                        }
                    }
                }
                if bits != 0 {
                    let ch = char::from_u32(0x2800 + bits as u32).unwrap_or(' ');
                    buf[(area.x + cx as u16, area.y + cy as u16)]
                        .set_char(ch)
                        .set_style(Style::new().fg(color));
                }
            }
        }
    }
}

/// Upper bound for a graph so recent peaks don't touch the edge. The floor of
/// 1 KiB/s keeps background chatter from filling an idle graph.
pub fn graph_max(data: &[f64], visible: usize) -> f64 {
    let start = data.len().saturating_sub(visible);
    data[start..]
        .iter()
        .copied()
        .fold(0.0, f64::max)
        .max(1024.0)
        * 1.1
}

/// An inline bar: the download share in rx color, then upload in tx color, on a
/// faint track. Its length is relative to the busiest row (`max`), with
/// half-cell precision.
pub fn traffic_bar(rate_in: f64, rate_out: f64, max: f64, width: u16) -> Line<'static> {
    let t = theme();
    let width = width as usize;
    let total = rate_in + rate_out;
    if total < 0.5 || max <= 0.0 || width == 0 {
        return Line::from(" ".repeat(width));
    }
    let halves = ((total / max) * (width * 2) as f64)
        .ceil()
        .clamp(1.0, (width * 2) as f64) as usize;
    let in_halves = ((rate_in / total) * halves as f64).round() as usize;
    let color_of = |half: usize| if half < in_halves { t.rx } else { t.tx };
    // Each cell covers two halves: "━" when both are filled, "╸" when only the left is.
    let mut spans: Vec<Span<'static>> = Vec::new();
    for cell in 0..width {
        let (h0, h1) = (cell * 2, cell * 2 + 1);
        let (sym, color) = if h1 < halves {
            ("━", color_of(h0))
        } else if h0 < halves {
            ("╸", color_of(h0))
        } else {
            ("─", t.faint)
        };
        match spans.last_mut() {
            Some(last)
                if last.style.fg == Some(color) && (sym != "╸") && !last.content.ends_with('╸') =>
            {
                last.content.to_mut().push_str(sym)
            }
            _ => spans.push(Span::styled(sym, t.fg(color))),
        }
    }
    Line::from(spans)
}

/// A table column. Columns with the lowest `prio` are kept first when the
/// terminal is too narrow for all of them.
#[derive(Clone, Copy)]
pub struct Col {
    pub title: &'static str,
    pub width: u16,
    pub flex: bool,
    pub prio: u8,
    pub right: bool,
}

pub const fn col(title: &'static str, width: u16, prio: u8) -> Col {
    Col {
        title,
        width,
        flex: false,
        prio,
        right: false,
    }
}

impl Col {
    pub const fn right(mut self) -> Self {
        self.right = true;
        self
    }
    pub const fn flex(mut self) -> Self {
        self.flex = true;
        self
    }
    pub fn constraint(&self) -> Constraint {
        if self.flex {
            Constraint::Fill(1)
        } else {
            Constraint::Length(self.width)
        }
    }
}

/// Picks which columns fit in `avail` cells, keeping their original order.
pub fn fit_columns(cols: &[Col], avail: u16, spacing: u16) -> Vec<usize> {
    let mut order: Vec<usize> = (0..cols.len()).collect();
    order.sort_by_key(|&i| (cols[i].prio, i));
    let mut used = 0u16;
    let mut chosen = Vec::new();
    for i in order {
        let w = cols[i].width + if chosen.is_empty() { 0 } else { spacing };
        if used + w <= avail {
            used += w;
            chosen.push(i);
        }
    }
    chosen.sort_unstable();
    chosen
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text(l: &Line) -> String {
        l.spans.iter().map(|s| s.content.as_ref()).collect()
    }

    #[test]
    fn bars_have_fixed_width() {
        for (i, o, m) in [
            (0.0, 0.0, 10.0),
            (5.0, 5.0, 10.0),
            (1.0, 0.0, 1000.0),
            (3.0, 7.0, 10.0),
            (10.0, 0.0, 10.0),
        ] {
            assert_eq!(
                text(&traffic_bar(i, o, m, 12)).chars().count(),
                12,
                "{i} {o} {m}"
            );
        }
    }

    #[test]
    fn narrow_terminals_drop_low_priority_columns() {
        let cols = [col("A", 10, 0), col("B", 10, 2), col("C", 10, 1)];
        assert_eq!(fit_columns(&cols, 100, 1), vec![0, 1, 2]);
        assert_eq!(fit_columns(&cols, 21, 1), vec![0, 2]);
        assert_eq!(fit_columns(&cols, 5, 1), Vec::<usize>::new());
    }

    #[test]
    fn graph_fills_from_baseline() {
        let mut buf = Buffer::empty(Rect::new(0, 0, 1, 2));
        let g = Graph {
            data: &[10.0, 5.0],
            max: 10.0,
            base: Color::Reset,
            peak: Color::Reset,
            down: false,
        };
        g.render(buf.area, &mut buf);
        assert_eq!(buf[(0, 0)].symbol(), "⡇"); // top cell: only the taller left column reaches it
        assert_eq!(buf[(0, 1)].symbol(), "⣿");
    }
}
