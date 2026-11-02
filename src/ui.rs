//! ratatui front end: a Processes tab and a Sockets tab.

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use ratatui::DefaultTerminal;
use ratatui::Frame;
use ratatui::crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use ratatui::layout::{Constraint, Layout};
use ratatui::style::{Color, Modifier, Style, Stylize};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Cell, Paragraph, Row, Table, TableState, Tabs};

use crate::sampler::{Owner, ProcRow, Sampler, Snapshot, SockRow, Source};

pub fn run(
    terminal: &mut DefaultTerminal,
    mut sampler: Sampler,
    first: Snapshot,
    interval: Duration,
) -> io::Result<()> {
    let mut app = App::new(first);
    let mut next = Instant::now() + interval;
    loop {
        terminal.draw(|f| app.draw(f))?;
        let timeout = next.saturating_duration_since(Instant::now());
        if event::poll(timeout)?
            && let Event::Key(k) = event::read()?
            && k.kind == KeyEventKind::Press
            && app.on_key(k)
        {
            return Ok(());
        }
        if Instant::now() >= next {
            // Keep sampling while paused so the totals stay accurate; just don't show new data.
            let snap = sampler.sample()?;
            if !app.paused {
                app.snap = snap;
            }
            next = Instant::now() + interval;
        }
    }
}

#[derive(Clone, Copy, PartialEq)]
enum Tab {
    Procs,
    Sockets,
}

#[derive(Clone, Copy)]
enum ProcSort {
    Rate,
    Total,
    Name,
    Pid,
}

#[derive(Clone, Copy)]
enum SockSort {
    Rate,
    Port,
    State,
    Program,
}

struct App {
    snap: Snapshot,
    tab: Tab,
    proc_sort: ProcSort,
    sock_sort: SockSort,
    group_by_program: bool,
    listening_only: bool,
    paused: bool,
    proc_state: TableState,
    sock_state: TableState,
}

/// A process row as shown. When grouped by program, `count` > 1.
struct ProcView {
    row: ProcRow,
    count: usize,
}

impl App {
    fn new(snap: Snapshot) -> Self {
        Self {
            snap,
            tab: Tab::Procs,
            proc_sort: ProcSort::Rate,
            sock_sort: SockSort::Rate,
            group_by_program: false,
            listening_only: false,
            paused: false,
            proc_state: TableState::default().with_selected(0),
            sock_state: TableState::default().with_selected(0),
        }
    }

    /// Returns true when the user asks to quit.
    fn on_key(&mut self, k: KeyEvent) -> bool {
        let state = match self.tab {
            Tab::Procs => &mut self.proc_state,
            Tab::Sockets => &mut self.sock_state,
        };
        let sel = state.selected().unwrap_or(0);
        match k.code {
            KeyCode::Char('q') | KeyCode::Esc => return true,
            KeyCode::Char('c') if k.modifiers.contains(KeyModifiers::CONTROL) => return true,
            KeyCode::Tab | KeyCode::BackTab => {
                self.tab = if self.tab == Tab::Procs {
                    Tab::Sockets
                } else {
                    Tab::Procs
                }
            }
            KeyCode::Char('1') => self.tab = Tab::Procs,
            KeyCode::Char('2') => self.tab = Tab::Sockets,
            KeyCode::Down | KeyCode::Char('j') => state.select(Some(sel.saturating_add(1))),
            KeyCode::Up | KeyCode::Char('k') => state.select(Some(sel.saturating_sub(1))),
            KeyCode::PageDown => state.select(Some(sel.saturating_add(20))),
            KeyCode::PageUp => state.select(Some(sel.saturating_sub(20))),
            KeyCode::Home => state.select(Some(0)),
            KeyCode::End => state.select(Some(usize::MAX)),
            KeyCode::Char('s') => match self.tab {
                Tab::Procs => {
                    self.proc_sort = match self.proc_sort {
                        ProcSort::Rate => ProcSort::Total,
                        ProcSort::Total => ProcSort::Name,
                        ProcSort::Name => ProcSort::Pid,
                        ProcSort::Pid => ProcSort::Rate,
                    }
                }
                Tab::Sockets => {
                    self.sock_sort = match self.sock_sort {
                        SockSort::Rate => SockSort::Port,
                        SockSort::Port => SockSort::State,
                        SockSort::State => SockSort::Program,
                        SockSort::Program => SockSort::Rate,
                    }
                }
            },
            KeyCode::Char('g') => self.group_by_program = !self.group_by_program,
            KeyCode::Char('l') => self.listening_only = !self.listening_only,
            KeyCode::Char(' ') | KeyCode::Char('p') => self.paused = !self.paused,
            _ => {}
        }
        false
    }

    fn draw(&mut self, f: &mut Frame) {
        let [header, tabs, body, footer] = Layout::vertical([
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Min(0),
            Constraint::Length(1),
        ])
        .areas(f.area());

        f.render_widget(Paragraph::new(self.header_line()), header);
        f.render_widget(
            Tabs::new(["1 Processes", "2 Sockets"])
                .select(if self.tab == Tab::Procs { 0 } else { 1 })
                .highlight_style(Style::new().bold().reversed()),
            tabs,
        );
        match self.tab {
            Tab::Procs => self.draw_procs(f, body),
            Tab::Sockets => self.draw_sockets(f, body),
        }
        f.render_widget(Paragraph::new(self.footer_line()).dark_gray(), footer);
    }

    fn header_line(&self) -> Line<'static> {
        let s = &self.snap;
        let mut spans = vec![Span::raw(" nitronet ").bold().reversed(), Span::raw("  ")];
        if let Some((rx, tx)) = s.nic_rate {
            spans.push(Span::raw("NIC "));
            spans.push(Span::raw(format!("↓{}/s ", human(rx))).fg(Color::Cyan));
            spans.push(Span::raw(format!("↑{}/s", human(tx))).fg(Color::Magenta));
            spans.push(Span::raw("   "));
        }
        spans.push(Span::raw("attributed "));
        spans.push(Span::raw(format!("↓{}/s ", human(s.seen_rate.0))).fg(Color::Cyan));
        spans.push(Span::raw(format!("↑{}/s", human(s.seen_rate.1))).fg(Color::Magenta));
        spans.push(Span::raw(format!("   {} sockets   ", s.sockets.len())));
        spans.push(match &s.source {
            Source::Ebpf { .. } => Span::raw("eBPF: TCP+UDP").green(),
            Source::TcpInfo { reason } => {
                let reason = reason.lines().next().unwrap_or_default();
                Span::raw(format!("tcp_info: TCP only ({reason})")).yellow()
            }
        });
        if s.baseline {
            spans.push(Span::raw("   measuring…").dark_gray());
        }
        if self.paused {
            spans.push(Span::raw("   PAUSED").yellow().bold());
        }
        if !s.is_root && s.hidden_procs > 0 {
            spans.push(
                Span::raw(format!(
                    "   {} processes hidden, run as root to see them",
                    s.hidden_procs
                ))
                .yellow(),
            );
        }
        Line::from(spans)
    }

    fn footer_line(&self) -> Line<'static> {
        let mut parts = vec!["q quit", "tab switch", "↑↓ move"];
        let sort = match self.tab {
            Tab::Procs => match self.proc_sort {
                ProcSort::Rate => "s sort:rate",
                ProcSort::Total => "s sort:total",
                ProcSort::Name => "s sort:name",
                ProcSort::Pid => "s sort:pid",
            },
            Tab::Sockets => match self.sock_sort {
                SockSort::Rate => "s sort:rate",
                SockSort::Port => "s sort:port",
                SockSort::State => "s sort:state",
                SockSort::Program => "s sort:program",
            },
        };
        parts.push(sort);
        match self.tab {
            Tab::Procs => parts.push(if self.group_by_program {
                "g group:program"
            } else {
                "g group:pid"
            }),
            Tab::Sockets => parts.push(if self.listening_only {
                "l listening:only"
            } else {
                "l listening:all"
            }),
        }
        parts.push("space pause");
        Line::from(format!(" {}", parts.join("  ")))
    }

    fn proc_views(&self) -> Vec<ProcView> {
        let mut views: Vec<ProcView> = if self.group_by_program {
            let mut groups: HashMap<String, ProcView> = HashMap::new();
            let mut others = Vec::new();
            for p in &self.snap.procs {
                if !matches!(p.owner, Owner::Pid(_)) {
                    others.push(ProcView {
                        row: p.clone(),
                        count: 1,
                    });
                    continue;
                }
                match groups.get_mut(&p.name) {
                    None => {
                        groups.insert(
                            p.name.clone(),
                            ProcView {
                                row: p.clone(),
                                count: 1,
                            },
                        );
                    }
                    Some(g) => {
                        let r = &mut g.row;
                        g.count += 1;
                        r.alive |= p.alive;
                        r.rate_in += p.rate_in;
                        r.rate_out += p.rate_out;
                        r.total_in += p.total_in;
                        r.total_out += p.total_out;
                        r.sockets += p.sockets;
                        r.listening.extend_from_slice(&p.listening);
                        r.listening.sort_unstable();
                        r.listening.dedup();
                        if r.unit != p.unit {
                            r.unit = Some("*".into());
                        }
                        if r.user != p.user {
                            r.user = "*".into();
                        }
                        r.owner = r.owner.min(p.owner);
                    }
                }
            }
            groups.into_values().chain(others).collect()
        } else {
            self.snap
                .procs
                .iter()
                .map(|p| ProcView {
                    row: p.clone(),
                    count: 1,
                })
                .collect()
        };

        let rate = |v: &ProcView| v.row.rate_in + v.row.rate_out;
        let total = |v: &ProcView| v.row.total_in + v.row.total_out;
        match self.proc_sort {
            ProcSort::Rate => views.sort_by(|a, b| {
                rate(b)
                    .total_cmp(&rate(a))
                    .then(total(b).cmp(&total(a)))
                    .then(a.row.name.cmp(&b.row.name))
            }),
            ProcSort::Total => {
                views.sort_by(|a, b| total(b).cmp(&total(a)).then(a.row.name.cmp(&b.row.name)))
            }
            ProcSort::Name => views.sort_by(|a, b| {
                a.row
                    .name
                    .to_lowercase()
                    .cmp(&b.row.name.to_lowercase())
                    .then(a.row.owner.cmp(&b.row.owner))
            }),
            ProcSort::Pid => views.sort_by_key(|v| v.row.owner),
        }
        views
    }

    fn draw_procs(&mut self, f: &mut Frame, area: ratatui::layout::Rect) {
        let views = self.proc_views();
        let rows = views.iter().map(|v| {
            let r = &v.row;
            let pid = match (r.owner, v.count) {
                (_, n) if n > 1 => format!("×{n}"),
                (Owner::Pid(p), _) => p.to_string(),
                _ => "-".into(),
            };
            let listening = r
                .listening
                .iter()
                .map(|(proto, port)| format!("{}:{port}", proto.as_str()))
                .collect::<Vec<_>>()
                .join(" ");
            let row = Row::new(vec![
                Cell::from(pid),
                Cell::from(r.user.clone()),
                Cell::from(r.name.clone()),
                Cell::from(r.unit.clone().unwrap_or_default()),
                rate_cell(Some(r.rate_in), Color::Cyan),
                rate_cell(Some(r.rate_out), Color::Magenta),
                Cell::from(Line::from(human(r.total_in as f64)).right_aligned()),
                Cell::from(Line::from(human(r.total_out as f64)).right_aligned()),
                Cell::from(Line::from(r.sockets.to_string()).right_aligned()),
                Cell::from(listening),
            ]);
            if r.alive {
                row
            } else {
                row.dark_gray().italic()
            }
        });
        let widths = [
            Constraint::Length(7),
            Constraint::Length(10),
            Constraint::Min(15),
            Constraint::Length(18),
            Constraint::Length(10),
            Constraint::Length(10),
            Constraint::Length(10),
            Constraint::Length(10),
            Constraint::Length(5),
            Constraint::Min(14),
        ];
        let header = [
            "PID",
            "USER",
            "PROGRAM",
            "SERVICE",
            "↓/s",
            "↑/s",
            "↓ total",
            "↑ total",
            "SOCK",
            "LISTENING",
        ];
        clamp(&mut self.proc_state, views.len());
        f.render_stateful_widget(table(rows, widths, header), area, &mut self.proc_state);
    }

    fn draw_sockets(&mut self, f: &mut Frame, area: ratatui::layout::Rect) {
        let names: HashMap<Owner, &str> = self
            .snap
            .procs
            .iter()
            .map(|p| (p.owner, p.name.as_str()))
            .collect();
        let name = |s: &SockRow| names.get(&s.owner).copied().unwrap_or("?");
        let mut socks: Vec<&SockRow> = self
            .snap
            .sockets
            .iter()
            .filter(|s| !self.listening_only || s.sock.is_listening())
            .collect();
        let rate = |s: &SockRow| s.rate_in.unwrap_or(0.0) + s.rate_out.unwrap_or(0.0);
        let port_key = |s: &SockRow| (s.sock.local.port(), s.sock.proto);
        match self.sock_sort {
            SockSort::Rate => socks.sort_by(|a, b| {
                rate(b)
                    .total_cmp(&rate(a))
                    .then(port_key(a).cmp(&port_key(b)))
            }),
            SockSort::Port => socks.sort_by_key(|s| port_key(s)),
            SockSort::State => socks.sort_by_key(|s| (s.sock.state_str(), port_key(s))),
            SockSort::Program => socks.sort_by_key(|s| (name(s).to_lowercase(), port_key(s))),
        }

        let rows = socks.iter().map(|s| {
            let pid = match s.owner {
                Owner::Pid(p) => p.to_string(),
                _ => "-".into(),
            };
            let total = |b: Option<u64>| match b {
                Some(b) => human(b as f64),
                None => "—".into(),
            };
            let (b_in, b_out) = (s.bytes.map(|b| b.0), s.bytes.map(|b| b.1));
            let row = Row::new(vec![
                Cell::from(s.sock.proto.as_str()),
                Cell::from(elide_middle(&fmt_addr(s.sock.local), ADDR_WIDTH)),
                Cell::from(elide_middle(&fmt_addr(s.sock.remote), ADDR_WIDTH)),
                Cell::from(s.sock.state_str()),
                Cell::from(pid),
                Cell::from(name(s).to_string()),
                rate_cell(s.rate_in, Color::Cyan),
                rate_cell(s.rate_out, Color::Magenta),
                Cell::from(Line::from(total(b_in)).right_aligned()),
                Cell::from(Line::from(total(b_out)).right_aligned()),
            ]);
            if s.sock.is_listening() {
                row.green()
            } else {
                row
            }
        });
        let widths = [
            Constraint::Length(5),
            Constraint::Length(ADDR_WIDTH as u16),
            Constraint::Length(ADDR_WIDTH as u16),
            Constraint::Length(12),
            Constraint::Length(7),
            Constraint::Length(16),
            Constraint::Length(10),
            Constraint::Length(10),
            Constraint::Length(10),
            Constraint::Length(10),
        ];
        let header = [
            "PROTO",
            "LOCAL",
            "REMOTE",
            "STATE",
            "PID",
            "PROGRAM",
            "↓/s",
            "↑/s",
            "↓ bytes",
            "↑ bytes",
        ];
        clamp(&mut self.sock_state, socks.len());
        f.render_stateful_widget(table(rows, widths, header), area, &mut self.sock_state);
    }
}

fn table<'a>(
    rows: impl IntoIterator<Item = Row<'a>>,
    widths: impl IntoIterator<Item = Constraint>,
    header: impl IntoIterator<Item = &'a str>,
) -> Table<'a> {
    Table::new(rows, widths)
        .header(Row::new(header).style(Style::new().bold().add_modifier(Modifier::UNDERLINED)))
        .row_highlight_style(Style::new().reversed())
        .column_spacing(1)
}

fn clamp(state: &mut TableState, len: usize) {
    let sel = state.selected().unwrap_or(0);
    state.select(if len == 0 {
        None
    } else {
        Some(sel.min(len - 1))
    });
}

fn rate_cell(rate: Option<f64>, color: Color) -> Cell<'static> {
    let line = match rate {
        None => Line::from("—").dark_gray(),
        Some(r) if r < 1.0 => Line::from("·").dark_gray(),
        Some(r) => Line::from(human(r)).fg(color),
    };
    Cell::from(line.right_aligned())
}

/// Binary-unit byte count: "512 B", "1.4 KiB", "3.0 MiB".
pub fn human(b: f64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut v = b;
    let mut i = 0;
    while v >= 1024.0 && i < UNITS.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{v:.0} B")
    } else {
        format!("{v:.1} {}", UNITS[i])
    }
}

const ADDR_WIDTH: usize = 32;

/// Shortens `s` to `max` chars by cutting the middle, so the port at the end of
/// a long IPv6 address stays visible.
fn elide_middle(s: &str, max: usize) -> String {
    let n = s.chars().count();
    if n <= max {
        return s.to_string();
    }
    let tail = max / 2;
    let head = max - tail - 1;
    let mut out: String = s.chars().take(head).collect();
    out.push('…');
    out.extend(s.chars().skip(n - tail));
    out
}

/// Shows wildcard addresses as "*" or "*:port", the way `ss` does.
pub fn fmt_addr(a: SocketAddr) -> String {
    match (a.ip().is_unspecified(), a.port()) {
        (true, 0) => "*".into(),
        (true, p) => format!("*:{p}"),
        _ => a.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;
    use ratatui::crossterm::event::KeyEvent;

    /// Renders every view from live data. Run with `--nocapture` to see the screens.
    #[test]
    fn renders_all_views() {
        let mut sampler = Sampler::new(false).expect("netlink sock_diag available");
        sampler.sample().unwrap();
        std::thread::sleep(Duration::from_millis(300));
        let mut app = App::new(sampler.sample().unwrap());
        let mut term = Terminal::new(TestBackend::new(170, 24)).unwrap();
        let press = |app: &mut App, c| assert!(!app.on_key(KeyEvent::from(KeyCode::Char(c))));

        for keys in [&[][..], &['g'], &['2'], &['l', 's']] {
            for &k in keys {
                press(&mut app, k);
            }
            term.draw(|f| app.draw(f)).unwrap();
            println!("{}", term.backend());
        }
        press(&mut app, 'j');
        assert!(app.on_key(KeyEvent::from(KeyCode::Char('q'))));
    }

    #[test]
    fn formats() {
        assert_eq!(human(512.0), "512 B");
        assert_eq!(human(1536.0), "1.5 KiB");
        assert_eq!(fmt_addr("0.0.0.0:22".parse().unwrap()), "*:22");
        assert_eq!(fmt_addr("[::]:0".parse().unwrap()), "*");
        assert_eq!(fmt_addr("[::1]:80".parse().unwrap()), "[::1]:80");
        assert_eq!(elide_middle("abcdef", 6), "abcdef");
        assert_eq!(
            elide_middle("[2001:db8:322e:0:32c5:99ff:feaa:bb02]:37422", 20),
            "[2001:db8…b02]:37422"
        );
    }
}
