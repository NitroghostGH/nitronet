//! ratatui front end: app state, the event loop, and input handling.
//! Drawing is in `view.rs`.

mod fmt;
mod theme;
mod view;
mod widgets;

#[cfg(test)]
mod tests;

use std::collections::{HashMap, VecDeque};
use std::io;
use std::time::{Duration, Instant};

use ratatui::DefaultTerminal;
use ratatui::crossterm::event::{
    self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEvent, KeyEventKind,
    KeyModifiers, MouseButton, MouseEvent, MouseEventKind,
};
use ratatui::crossterm::execute;
use ratatui::layout::{Position, Rect};
use ratatui::widgets::TableState;

pub use fmt::{fmt_addr, human};

use crate::sampler::{Owner, ProcRow, Sampler, Snapshot, SockRow};

/// Samples kept for graphs. That's enough to fill a 300-column-wide graph at
/// two samples per cell.
const HISTORY: usize = 600;

pub fn run(
    terminal: &mut DefaultTerminal,
    mut sampler: Sampler,
    first: Snapshot,
    interval: Duration,
) -> io::Result<()> {
    let _mouse = MouseCapture::enable();
    let mut app = App::new(first, interval);
    let mut next = Instant::now() + interval;
    loop {
        terminal.draw(|f| view::draw(&mut app, f))?;
        let timeout = next.saturating_duration_since(Instant::now());
        if event::poll(timeout)? {
            let quit = match event::read()? {
                Event::Key(k) if k.kind == KeyEventKind::Press => app.on_key(k),
                Event::Mouse(m) => {
                    app.on_mouse(m);
                    false
                }
                _ => false,
            };
            if quit {
                return Ok(());
            }
        }
        if Instant::now() >= next {
            // Keep sampling while paused so totals stay accurate; just don't show it.
            let snap = sampler.sample()?;
            if !app.paused {
                app.set_snapshot(snap);
            }
            next = Instant::now() + interval;
        }
    }
}

/// Turns on mouse reporting for its lifetime. It is also turned off on panic,
/// since ratatui's own panic hook only restores raw mode and the alternate screen.
struct MouseCapture;

impl MouseCapture {
    fn enable() -> Self {
        let _ = execute!(io::stdout(), EnableMouseCapture);
        let prev = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            let _ = execute!(io::stdout(), DisableMouseCapture);
            prev(info);
        }));
        MouseCapture
    }
}

impl Drop for MouseCapture {
    fn drop(&mut self) {
        let _ = execute!(io::stdout(), DisableMouseCapture);
    }
}

#[derive(Clone, Copy, PartialEq, Debug)]
pub(crate) enum Tab {
    Procs,
    Sockets,
}

#[derive(Clone, Copy, PartialEq, Debug)]
pub(crate) enum ProcSort {
    Rate,
    Total,
    Name,
    Pid,
}

#[derive(Clone, Copy, PartialEq, Debug)]
pub(crate) enum SockSort {
    Rate,
    Port,
    State,
    Program,
}

/// Rate history: a whole-machine series, plus one per owner for the detail pane.
#[derive(Default)]
pub(crate) struct History {
    pub total_in: VecDeque<f64>,
    pub total_out: VecDeque<f64>,
    pub peak: (f64, f64),
    owners: HashMap<Owner, VecDeque<(f64, f64)>>,
}

fn push_capped<T>(q: &mut VecDeque<T>, v: T) {
    if q.len() == HISTORY {
        q.pop_front();
    }
    q.push_back(v);
}

impl History {
    fn push(&mut self, snap: &Snapshot) {
        let (rx, tx) = snap.nic_rate.unwrap_or(snap.seen_rate);
        push_capped(&mut self.total_in, rx);
        push_capped(&mut self.total_out, tx);
        self.peak = (self.peak.0.max(rx), self.peak.1.max(tx));

        let mut now: HashMap<Owner, (f64, f64)> = snap
            .procs
            .iter()
            .filter(|p| p.alive)
            .map(|p| (p.owner, (p.rate_in, p.rate_out)))
            .collect();
        for (owner, q) in self.owners.iter_mut() {
            push_capped(q, now.remove(owner).unwrap_or((0.0, 0.0)));
        }
        for (owner, v) in now {
            let mut q = VecDeque::new();
            q.push_back(v);
            self.owners.insert(owner, q);
        }
        // Forget owners that have been silent for the whole window.
        self.owners
            .retain(|_, q| q.iter().any(|&(i, o)| i > 0.0 || o > 0.0) || q.len() < HISTORY);
    }

    /// The summed (in, out) series for a set of owners, aligned at the newest sample.
    pub fn series(&self, owners: &[Owner]) -> (Vec<f64>, Vec<f64>) {
        let len = owners
            .iter()
            .filter_map(|o| self.owners.get(o))
            .map(|q| q.len())
            .max()
            .unwrap_or(0);
        let (mut i, mut o) = (vec![0.0; len], vec![0.0; len]);
        for q in owners.iter().filter_map(|o| self.owners.get(o)) {
            let off = len - q.len();
            for (k, &(a, b)) in q.iter().enumerate() {
                i[off + k] += a;
                o[off + k] += b;
            }
        }
        (i, o)
    }
}

/// A process row as shown. When grouped by program it may stand for several pids.
pub(crate) struct ProcView {
    pub row: ProcRow,
    pub owners: Vec<Owner>,
}

/// Which process row is selected, stored by identity rather than by row
/// number. That way the highlight follows the item when the list re-sorts
/// as rates change.
#[derive(Clone, PartialEq, Debug)]
pub(crate) enum ProcKey {
    Owner(Owner),
    /// A row grouped by program name.
    Program(String),
}

impl ProcView {
    fn key(&self, grouped: bool) -> ProcKey {
        match self.row.owner {
            Owner::Pid(_) if grouped => ProcKey::Program(self.row.name.clone()),
            owner => ProcKey::Owner(owner),
        }
    }

    /// Whether this row is the one `key` refers to. This holds across a
    /// grouping toggle: a pid matches the group that contains it, and a program
    /// name matches the first ungrouped process with that name.
    fn is(&self, key: &ProcKey) -> bool {
        match key {
            ProcKey::Owner(o) => self.owners.contains(o),
            ProcKey::Program(name) => {
                matches!(self.row.owner, Owner::Pid(_)) && self.row.name == *name
            }
        }
    }
}

/// Screen regions from the last frame, used to route mouse clicks.
#[derive(Default)]
pub(crate) struct HitMap {
    pub tabs: Vec<(Rect, Tab)>,
    /// The table's row area (below the header row).
    pub rows: Rect,
}

pub(crate) struct App {
    pub snap: Snapshot,
    pub interval: Duration,
    pub tab: Tab,
    pub proc_sort: ProcSort,
    pub sock_sort: SockSort,
    pub reverse: bool,
    pub group_by_program: bool,
    pub listening_only: bool,
    pub paused: bool,
    pub show_detail: bool,
    pub show_help: bool,
    pub filter: String,
    pub editing_filter: bool,
    pub proc_state: TableState,
    pub sock_state: TableState,
    /// The selected items by identity; the TableStates hold their current row.
    pub proc_sel: Option<ProcKey>,
    pub sock_sel: Option<u64>,
    pub history: History,
    pub hit: HitMap,
}

impl App {
    pub fn new(snap: Snapshot, interval: Duration) -> Self {
        let mut app = Self {
            snap,
            interval,
            tab: Tab::Procs,
            proc_sort: ProcSort::Rate,
            sock_sort: SockSort::Rate,
            reverse: false,
            group_by_program: false,
            listening_only: false,
            paused: false,
            show_detail: true,
            show_help: false,
            filter: String::new(),
            editing_filter: false,
            proc_state: TableState::default().with_selected(0),
            sock_state: TableState::default().with_selected(0),
            proc_sel: None,
            sock_sel: None,
            history: History::default(),
            hit: HitMap::default(),
        };
        app.history.push(&app.snap);
        app
    }

    pub fn set_snapshot(&mut self, snap: Snapshot) {
        self.history.push(&snap);
        self.snap = snap;
    }

    fn state(&mut self) -> &mut TableState {
        match self.tab {
            Tab::Procs => &mut self.proc_state,
            Tab::Sockets => &mut self.sock_state,
        }
    }

    pub fn set_tab(&mut self, tab: Tab) {
        self.tab = tab;
    }

    /// Points each table's highlight at the row where its selected item is now.
    /// If the item is gone (the process exited or the socket closed), the
    /// highlight stays on the same row and takes whatever item is there.
    /// This runs before every draw and every move.
    pub fn sync_selection(&mut self, views: &[ProcView], socks: &[usize]) {
        let row = match &self.proc_sel {
            Some(key) => views.iter().position(|v| v.is(key)),
            None => None,
        };
        let row = row.unwrap_or_else(|| self.proc_state.selected().unwrap_or(0));
        self.select_proc(views, row);

        let row = self.sock_sel.and_then(|cookie| {
            socks
                .iter()
                .position(|&i| self.snap.sockets[i].sock.cookie == cookie)
        });
        let row = row.unwrap_or_else(|| self.sock_state.selected().unwrap_or(0));
        self.select_sock(socks, row);
    }

    fn select_proc(&mut self, views: &[ProcView], row: usize) {
        if views.is_empty() {
            // Keep the key: if a filter hid the item, it comes back once the filter is cleared.
            self.proc_state.select(None);
            return;
        }
        let row = row.min(views.len() - 1);
        self.proc_state.select(Some(row));
        self.proc_sel = Some(views[row].key(self.group_by_program));
    }

    fn select_sock(&mut self, socks: &[usize], row: usize) {
        if socks.is_empty() {
            self.sock_state.select(None);
            return;
        }
        let row = row.min(socks.len() - 1);
        self.sock_state.select(Some(row));
        self.sock_sel = Some(self.snap.sockets[socks[row]].sock.cookie);
    }

    /// Moves the current tab's selection. `to` maps (current row, row count) to the new row.
    fn move_to(&mut self, to: impl FnOnce(usize, usize) -> usize) {
        let views = self.proc_views();
        let socks = self.sock_rows();
        self.sync_selection(&views, &socks);
        match self.tab {
            Tab::Procs => {
                let row = to(self.proc_state.selected().unwrap_or(0), views.len());
                self.select_proc(&views, row);
            }
            Tab::Sockets => {
                let row = to(self.sock_state.selected().unwrap_or(0), socks.len());
                self.select_sock(&socks, row);
            }
        }
    }

    fn move_by(&mut self, delta: isize) {
        self.move_to(|cur, _| cur.saturating_add_signed(delta));
    }

    /// Returns true when the user asks to quit.
    pub fn on_key(&mut self, k: KeyEvent) -> bool {
        if k.code == KeyCode::Char('c') && k.modifiers.contains(KeyModifiers::CONTROL) {
            return true;
        }
        if self.editing_filter {
            let before = self.filter.len();
            match k.code {
                KeyCode::Enter => self.editing_filter = false,
                KeyCode::Esc => {
                    self.filter.clear();
                    self.editing_filter = false;
                }
                KeyCode::Backspace => {
                    self.filter.pop();
                }
                KeyCode::Char('u') if k.modifiers.contains(KeyModifiers::CONTROL) => {
                    self.filter.clear()
                }
                KeyCode::Char(c) => self.filter.push(c),
                KeyCode::Down => self.move_by(1),
                KeyCode::Up => self.move_by(-1),
                _ => {}
            }
            // New filter text means a new result list, so jump back to the top.
            if self.filter.len() != before {
                self.move_to(|_, _| 0);
            }
            return false;
        }
        if self.show_help {
            // Any key closes help; q still quits.
            self.show_help = false;
            return k.code == KeyCode::Char('q');
        }
        match k.code {
            KeyCode::Char('q') => return true,
            KeyCode::Esc => {
                if self.filter.is_empty() {
                    return true;
                } else {
                    self.filter.clear();
                }
            }
            KeyCode::Char('?') | KeyCode::F(1) => self.show_help = true,
            KeyCode::Char('/') => self.editing_filter = true,
            KeyCode::Tab | KeyCode::BackTab | KeyCode::Left | KeyCode::Right => {
                self.set_tab(if self.tab == Tab::Procs {
                    Tab::Sockets
                } else {
                    Tab::Procs
                })
            }
            KeyCode::Char('1') => self.set_tab(Tab::Procs),
            KeyCode::Char('2') => self.set_tab(Tab::Sockets),
            KeyCode::Down | KeyCode::Char('j') => self.move_by(1),
            KeyCode::Up | KeyCode::Char('k') => self.move_by(-1),
            KeyCode::PageDown => self.move_by(20),
            KeyCode::PageUp => self.move_by(-20),
            KeyCode::Home => self.move_to(|_, _| 0),
            KeyCode::End => self.move_to(|_, len| len.saturating_sub(1)),
            KeyCode::Char('s') => self.cycle_sort(),
            KeyCode::Char('r') => self.reverse = !self.reverse,
            KeyCode::Char('g') => self.group_by_program = !self.group_by_program,
            KeyCode::Char('l') => self.listening_only = !self.listening_only,
            KeyCode::Enter | KeyCode::Char('d') => self.show_detail = !self.show_detail,
            KeyCode::Char(' ') | KeyCode::Char('p') => self.paused = !self.paused,
            _ => {}
        }
        false
    }

    fn cycle_sort(&mut self) {
        self.reverse = false;
        match self.tab {
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
        }
    }

    pub fn on_mouse(&mut self, m: MouseEvent) {
        let pos = Position::new(m.column, m.row);
        match m.kind {
            MouseEventKind::ScrollDown => self.move_by(3),
            MouseEventKind::ScrollUp => self.move_by(-3),
            MouseEventKind::Down(MouseButton::Left) => {
                if self.show_help {
                    self.show_help = false;
                    return;
                }
                if let Some(&(_, tab)) = self.hit.tabs.iter().find(|(r, _)| r.contains(pos)) {
                    self.set_tab(tab);
                } else if self.hit.rows.contains(pos) {
                    let row = self.state().offset() + (m.row - self.hit.rows.y) as usize;
                    self.move_to(|_, _| row);
                }
            }
            _ => {}
        }
    }

    /// Indices into `app.snap.sockets` of the rows to show, filtered and sorted.
    pub fn sock_rows(&self) -> Vec<usize> {
        let app = self;
        let names = app.owner_names();
        let name = |s: &SockRow| {
            names
                .iter()
                .find(|(o, _)| *o == s.owner)
                .map_or("?", |(_, n)| n.as_str())
        };
        let all = &app.snap.sockets;
        let mut idx: Vec<usize> = (0..all.len())
            .filter(|&i| !app.listening_only || all[i].sock.is_listening())
            .filter(|&i| {
                let s = &all[i];
                let pid = match s.owner {
                    Owner::Pid(p) => p.to_string(),
                    _ => String::new(),
                };
                app.matches(&[
                    s.sock.proto.as_str(),
                    &fmt_addr(s.sock.local),
                    &fmt_addr(s.sock.remote),
                    s.sock.state_str(),
                    name(s),
                    &pid,
                ])
            })
            .collect();
        let rate = |i: &usize| all[*i].rate_in.unwrap_or(0.0) + all[*i].rate_out.unwrap_or(0.0);
        let port_key = |i: &usize| (all[*i].sock.local.port(), all[*i].sock.proto);
        match app.sock_sort {
            SockSort::Rate => idx.sort_by(|a, b| {
                rate(b)
                    .total_cmp(&rate(a))
                    .then(port_key(a).cmp(&port_key(b)))
            }),
            SockSort::Port => idx.sort_by_key(port_key),
            SockSort::State => idx.sort_by_key(|i| (all[*i].sock.state_str(), port_key(i))),
            SockSort::Program => idx.sort_by_key(|i| (name(&all[*i]).to_lowercase(), port_key(i))),
        }
        if app.reverse {
            idx.reverse();
        }
        idx
    }

    pub fn owner_names(&self) -> Vec<(Owner, String)> {
        let app = self;
        app.snap
            .procs
            .iter()
            .map(|p| (p.owner, p.name.clone()))
            .collect()
    }

    pub fn matches(&self, fields: &[&str]) -> bool {
        if self.filter.is_empty() {
            return true;
        }
        let needle = self.filter.to_lowercase();
        fields.iter().any(|f| f.to_lowercase().contains(&needle))
    }

    /// The process rows to show: grouped, filtered and sorted.
    pub fn proc_views(&self) -> Vec<ProcView> {
        let mut views: Vec<ProcView> = Vec::new();
        if self.group_by_program {
            let mut index: HashMap<String, usize> = HashMap::new();
            for p in &self.snap.procs {
                let key = match p.owner {
                    Owner::Pid(_) => p.name.clone(),
                    // Keep pseudo-owners such as "(kernel)" separate per uid.
                    other => format!("{other:?}"),
                };
                match index.get(&key) {
                    None => {
                        index.insert(key, views.len());
                        views.push(ProcView {
                            row: p.clone(),
                            owners: vec![p.owner],
                        });
                    }
                    Some(&i) => {
                        let g = &mut views[i];
                        let r = &mut g.row;
                        g.owners.push(p.owner);
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
        } else {
            views = self
                .snap
                .procs
                .iter()
                .map(|p| ProcView {
                    row: p.clone(),
                    owners: vec![p.owner],
                })
                .collect();
        }

        views.retain(|v| {
            let r = &v.row;
            let pid = match r.owner {
                Owner::Pid(p) => p.to_string(),
                _ => String::new(),
            };
            let ports: Vec<String> = r.listening.iter().map(|(_, p)| p.to_string()).collect();
            let mut fields = vec![
                r.name.as_str(),
                r.user.as_str(),
                pid.as_str(),
                r.unit.as_deref().unwrap_or(""),
            ];
            fields.extend(ports.iter().map(String::as_str));
            self.matches(&fields)
        });

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
        if self.reverse {
            views.reverse();
        }
        views
    }
}
