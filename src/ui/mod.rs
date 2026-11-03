//! ratatui front end: app state, the event loop, and input handling.
//! Drawing is in `view.rs`.

mod diagram;
mod fmt;
mod packets;
mod packets_view;
mod theme;
mod view;
mod widgets;

#[cfg(test)]
mod tests;

use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};
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

use crate::lan::{DevKey, Lan, LanState};
use crate::packet::{FlowKey, Packet};
use crate::sampler::{Owner, ProcRow, Sampler, Snapshot, SockRow};
pub(crate) use packets::{ContentFilter, DirFilter, Flow, FlowSort};

/// Samples kept for graphs. That's enough to fill a 300-column-wide graph at
/// two samples per cell.
const HISTORY: usize = 600;
/// Captured packets kept for the Packets tab; older ones scroll away.
const MAX_PACKETS: usize = 5000;
/// How long a status message stays in the footer.
const FLASH: Duration = Duration::from_secs(4);

pub fn run(
    terminal: &mut DefaultTerminal,
    mut sampler: Sampler,
    first: Snapshot,
    interval: Duration,
) -> io::Result<()> {
    let _mouse = MouseCapture::enable();
    let mut app = App::new(first, interval);
    app.lan = Some(Lan::start());
    let mut next = Instant::now() + interval;
    let mut lan_version = 0;
    let mut lan_auto = false;
    loop {
        if let Some(lan) = &app.lan {
            if let Some(s) = lan.snapshot_since(lan_version) {
                lan_version = s.version;
                app.lan_state = s;
            }
            // Rescan every minute only while the Devices tab is open.
            let auto = app.tab == Tab::Devices;
            if auto != lan_auto {
                lan_auto = auto;
                lan.set_auto(auto);
            }
        }
        if app.capture_dirty {
            app.capture_dirty = false;
            let names: HashSet<String> = app.capturing.iter().cloned().collect();
            if let Err(e) = sampler.set_capture(&names) {
                app.capturing.clear();
                app.flash(e);
            }
        }
        // While paused, packets wait in the sampler and appear on resume.
        if !app.capturing.is_empty() && !app.paused {
            let packets = sampler.take_packets();
            app.add_packets(packets);
            app.capture_dropped = sampler.capture_dropped();
        }
        terminal.draw(|f| view::draw(&mut app, f))?;
        let mut timeout = next.saturating_duration_since(Instant::now());
        // Redraw often while a scan or port probe runs, so progress is live,
        // and while capturing, so packets appear as they arrive.
        let busy =
            app.lan_state.scanning.is_some() || app.lan_state.devices.values().any(|d| d.probing);
        if busy {
            timeout = timeout.min(Duration::from_millis(150));
        } else if !app.capturing.is_empty() {
            timeout = timeout.min(Duration::from_millis(250));
        }
        if let Some((_, at)) = &app.flash {
            timeout = timeout.min(
                FLASH
                    .saturating_sub(at.elapsed())
                    .max(Duration::from_millis(50)),
            );
        }
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
    Devices,
    Packets,
}

#[derive(Clone, Copy, PartialEq, Debug)]
pub(crate) enum DevSort {
    Ip,
    Name,
    Vendor,
    Seen,
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
    /// The "how it works" overlay, and how far it is scrolled.
    pub show_diagram: bool,
    pub diagram_scroll: u16,
    pub filter: String,
    pub editing_filter: bool,
    pub proc_state: TableState,
    pub sock_state: TableState,
    /// The selected items by identity; the TableStates hold their current row.
    pub proc_sel: Option<ProcKey>,
    pub sock_sel: Option<u64>,
    pub dev_state: TableState,
    pub dev_sel: Option<DevKey>,
    pub dev_sort: DevSort,
    /// The LAN scanner (None in tests) and its latest state.
    pub lan: Option<Lan>,
    pub lan_state: LanState,
    /// Captured packets, oldest first.
    pub packets: VecDeque<Packet>,
    pub pkt_state: TableState,
    /// The selected packet's id. None follows the newest packet, like `tail -f`.
    pub pkt_sel: Option<u64>,
    /// The packet the highlight is on, and how far its hex dump is scrolled.
    pub pkt_cur: Option<u64>,
    pub pkt_scroll: usize,
    /// Set when the highlight moves to another packet: the payload view then
    /// scrolls to the first filter match in it.
    pub pkt_jump: bool,
    /// `i`, `e`: which packets to show.
    pub pkt_dir: DirFilter,
    pub pkt_content: ContentFilter,
    /// `f`: show conversations instead of packets.
    pub pkt_flows: bool,
    /// The conversation opened with enter: only its packets are listed.
    pub pkt_flow: Option<FlowKey>,
    /// `t`: show the payload as text rather than hex.
    pub pkt_text: bool,
    pub flow_state: TableState,
    pub flow_sel: Option<FlowKey>,
    pub flow_sort: FlowSort,
    /// Programs (by name) whose packets are captured.
    pub capturing: BTreeSet<String>,
    /// Set when `capturing` changed and the sampler needs telling.
    pub capture_dirty: bool,
    pub capture_dropped: u64,
    /// A short status message for the footer, and when it was set.
    pub flash: Option<(String, Instant)>,
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
            show_diagram: false,
            diagram_scroll: 0,
            filter: String::new(),
            editing_filter: false,
            proc_state: TableState::default().with_selected(0),
            sock_state: TableState::default().with_selected(0),
            proc_sel: None,
            sock_sel: None,
            dev_state: TableState::default().with_selected(0),
            dev_sel: None,
            dev_sort: DevSort::Ip,
            lan: None,
            lan_state: LanState::default(),
            packets: VecDeque::new(),
            pkt_state: TableState::default(),
            pkt_sel: None,
            pkt_cur: None,
            pkt_scroll: 0,
            pkt_jump: false,
            pkt_dir: DirFilter::Both,
            pkt_content: ContentFilter::All,
            pkt_flows: false,
            pkt_flow: None,
            pkt_text: false,
            flow_state: TableState::default(),
            flow_sel: None,
            flow_sort: FlowSort::Recent,
            capturing: BTreeSet::new(),
            capture_dirty: false,
            capture_dropped: 0,
            flash: None,
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
            Tab::Devices => &mut self.dev_state,
            Tab::Packets if self.pkt_flows => &mut self.flow_state,
            Tab::Packets => &mut self.pkt_state,
        }
    }

    pub fn flash(&mut self, msg: impl Into<String>) {
        self.flash = Some((msg.into(), Instant::now()));
    }

    /// The footer message, if it's recent.
    pub fn flash_text(&self) -> Option<&str> {
        self.flash
            .as_ref()
            .filter(|(_, at)| at.elapsed() < FLASH)
            .map(|(m, _)| m.as_str())
    }

    pub fn add_packets(&mut self, packets: Vec<Packet>) {
        self.packets.extend(packets);
        if self.packets.len() > MAX_PACKETS {
            let extra = self.packets.len() - MAX_PACKETS;
            self.packets.drain(..extra);
        }
    }

    /// Starts or stops capturing a program's packets.
    fn toggle_capture(&mut self, name: String) {
        if self.capturing.remove(&name) {
            self.flash(format!("stopped capturing {name}"));
        } else {
            self.flash(format!("capturing {name} · press 4 to watch its packets"));
            self.capturing.insert(name);
        }
        self.capture_dirty = true;
    }

    /// Switches view. The first visit to Devices starts the LAN scanner, so
    /// nitronet never sweeps the network unless asked.
    pub fn set_tab(&mut self, tab: Tab) {
        self.tab = tab;
        if tab == Tab::Devices && self.lan_state.scans == 0 && self.lan_state.scanning.is_none() {
            self.rescan();
        }
    }

    fn rescan(&mut self) {
        if let Some(lan) = &self.lan {
            lan.scan_now();
            // Show "scanning" at once rather than after the next snapshot.
            self.lan_state.scanning.get_or_insert((0, 0));
        }
    }

    /// Points each table's highlight at the row where its selected item is now.
    /// If the item is gone (the process exited or the socket closed), the
    /// highlight stays on the same row and takes whatever item is there.
    /// This runs before every draw and every move.
    pub fn sync_selection(
        &mut self,
        views: &[ProcView],
        socks: &[usize],
        devs: &[DevKey],
        pkts: &[usize],
        flows: &[Flow],
    ) {
        let row = self
            .flow_sel
            .as_ref()
            .and_then(|k| flows.iter().position(|f| f.key == *k));
        let row = row.unwrap_or_else(|| self.flow_state.selected().unwrap_or(0));
        self.select_flow(flows, row);

        let row = match self.pkt_sel {
            None => self.newest_row(pkts),
            Some(id) => pkts
                .iter()
                .position(|&i| self.packets[i].id == id)
                .unwrap_or_else(|| self.pkt_state.selected().unwrap_or(0)),
        };
        self.select_pkt(pkts, row);

        let row = self
            .dev_sel
            .and_then(|ip| devs.iter().position(|d| *d == ip));
        let row = row.unwrap_or_else(|| self.dev_state.selected().unwrap_or(0));
        self.select_dev(devs, row);

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

    /// The row of the newest packet: the last, or the first when reversed.
    fn newest_row(&self, pkts: &[usize]) -> usize {
        if self.reverse {
            0
        } else {
            pkts.len().saturating_sub(1)
        }
    }

    fn select_pkt(&mut self, pkts: &[usize], row: usize) {
        if pkts.is_empty() {
            self.pkt_state.select(None);
            return;
        }
        let row = row.min(pkts.len() - 1);
        self.pkt_state.select(Some(row));
        let id = self.packets[pkts[row]].id;
        if self.pkt_cur != Some(id) {
            self.pkt_cur = Some(id);
            self.pkt_scroll = 0;
            self.pkt_jump = true;
        }
        // On the newest row, keep following new packets.
        self.pkt_sel = (row != self.newest_row(pkts)).then_some(id);
    }

    fn select_flow(&mut self, flows: &[Flow], row: usize) {
        if flows.is_empty() {
            self.flow_state.select(None);
            return;
        }
        let row = row.min(flows.len() - 1);
        self.flow_state.select(Some(row));
        self.flow_sel = Some(flows[row].key.clone());
    }

    /// Enter on a conversation: list just its packets, from its first one.
    fn open_flow(&mut self) {
        let Some(key) = self.flow_sel.clone() else {
            return;
        };
        let first = self
            .packets
            .iter()
            .find(|p| p.flow().as_ref() == Some(&key))
            .map(|p| p.id);
        self.pkt_flow = Some(key);
        self.pkt_flows = false;
        self.pkt_sel = first;
    }

    /// Back from a conversation's packets to the list of conversations.
    fn close_flow(&mut self) {
        self.pkt_flow = None;
        self.pkt_flows = true;
    }

    fn select_dev(&mut self, devs: &[DevKey], row: usize) {
        if devs.is_empty() {
            self.dev_state.select(None);
            return;
        }
        let row = row.min(devs.len() - 1);
        self.dev_state.select(Some(row));
        self.dev_sel = Some(devs[row]);
    }

    /// Moves the current tab's selection. `to` maps (current row, row count) to the new row.
    fn move_to(&mut self, to: impl FnOnce(usize, usize) -> usize) {
        let views = self.proc_views();
        let socks = self.sock_rows();
        let devs = self.dev_rows();
        let pkts = self.pkt_rows();
        let flows = self.flows();
        self.sync_selection(&views, &socks, &devs, &pkts, &flows);
        match self.tab {
            Tab::Procs => {
                let row = to(self.proc_state.selected().unwrap_or(0), views.len());
                self.select_proc(&views, row);
            }
            Tab::Sockets => {
                let row = to(self.sock_state.selected().unwrap_or(0), socks.len());
                self.select_sock(&socks, row);
            }
            Tab::Devices => {
                let row = to(self.dev_state.selected().unwrap_or(0), devs.len());
                self.select_dev(&devs, row);
            }
            Tab::Packets if self.pkt_flows => {
                let row = to(self.flow_state.selected().unwrap_or(0), flows.len());
                self.select_flow(&flows, row);
            }
            Tab::Packets => {
                let row = to(self.pkt_state.selected().unwrap_or(0), pkts.len());
                self.select_pkt(&pkts, row);
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
                self.pkt_jump = true;
                self.move_to(|_, _| 0);
            }
            return false;
        }
        if self.show_diagram {
            // Arrows scroll; any other key closes; q still quits.
            let s = &mut self.diagram_scroll;
            match k.code {
                KeyCode::Down | KeyCode::Char('j') => *s = s.saturating_add(1),
                KeyCode::Up | KeyCode::Char('k') => *s = s.saturating_sub(1),
                KeyCode::PageDown | KeyCode::Char(' ') => *s = s.saturating_add(10),
                KeyCode::PageUp => *s = s.saturating_sub(10),
                KeyCode::Home => *s = 0,
                KeyCode::End => *s = u16::MAX,
                KeyCode::Char('q') => return true,
                _ => self.show_diagram = false,
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
                if self.tab == Tab::Packets && self.pkt_flow.is_some() {
                    self.close_flow();
                } else if self.filter.is_empty() {
                    return true;
                } else {
                    self.filter.clear();
                }
            }
            KeyCode::Char('?') | KeyCode::F(1) => self.show_help = true,
            KeyCode::Char('H') => {
                self.show_diagram = true;
                self.diagram_scroll = 0;
            }
            KeyCode::Char('/') => self.editing_filter = true,
            KeyCode::Tab | KeyCode::Right => self.set_tab(match self.tab {
                Tab::Procs => Tab::Sockets,
                Tab::Sockets => Tab::Devices,
                Tab::Devices => Tab::Packets,
                Tab::Packets => Tab::Procs,
            }),
            KeyCode::BackTab | KeyCode::Left => self.set_tab(match self.tab {
                Tab::Procs => Tab::Packets,
                Tab::Sockets => Tab::Procs,
                Tab::Devices => Tab::Sockets,
                Tab::Packets => Tab::Devices,
            }),
            KeyCode::Char('1') => self.set_tab(Tab::Procs),
            KeyCode::Char('2') => self.set_tab(Tab::Sockets),
            KeyCode::Char('3') => self.set_tab(Tab::Devices),
            KeyCode::Char('4') => self.set_tab(Tab::Packets),
            KeyCode::Char('c') => self.capture_key(),
            KeyCode::Char('x') if self.tab == Tab::Packets => {
                self.packets.clear();
                self.pkt_sel = None;
                self.pkt_flow = None;
            }
            KeyCode::Char('i') if self.tab == Tab::Packets => self.pkt_dir = self.pkt_dir.next(),
            KeyCode::Char('e') if self.tab == Tab::Packets => {
                self.pkt_content = self.pkt_content.next()
            }
            KeyCode::Char('f') if self.tab == Tab::Packets => {
                if self.pkt_flow.is_some() {
                    self.close_flow();
                } else {
                    self.pkt_flows = !self.pkt_flows;
                }
            }
            KeyCode::Char('t') if self.tab == Tab::Packets => {
                self.pkt_text = !self.pkt_text;
                self.pkt_scroll = 0;
                self.pkt_jump = true;
            }
            KeyCode::Enter if self.tab == Tab::Packets && self.pkt_flows => self.open_flow(),
            KeyCode::Char(']') if self.tab == Tab::Packets => {
                self.pkt_scroll = self.pkt_scroll.saturating_add(4)
            }
            KeyCode::Char('[') if self.tab == Tab::Packets => {
                self.pkt_scroll = self.pkt_scroll.saturating_sub(4)
            }
            KeyCode::Char('R') | KeyCode::F(5) => self.rescan(),
            KeyCode::Char('p') if self.tab == Tab::Devices => {
                if let (Some(lan), Some(key)) = (&self.lan, self.dev_sel) {
                    lan.probe(key);
                    if let Some(d) = self.lan_state.devices.get_mut(&key) {
                        d.probing = true;
                    }
                }
            }
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
            KeyCode::Char(' ') => self.paused = !self.paused,
            _ => {}
        }
        false
    }

    /// `c`: on Processes, start or stop capturing the selected program; on
    /// Packets, stop capturing the selected packet's program.
    fn capture_key(&mut self) {
        let name = match self.tab {
            Tab::Procs => {
                let views = self.proc_views();
                let row = self.proc_state.selected();
                match row.and_then(|r| views.get(r)) {
                    Some(v) if matches!(v.row.owner, Owner::Pid(_)) => Some(v.row.name.clone()),
                    Some(_) => {
                        self.flash("only programs can be captured, not kernel or unresolved rows");
                        None
                    }
                    None => None,
                }
            }
            Tab::Packets => {
                let program = if self.pkt_flows {
                    self.flow_sel.as_ref().map(|k| k.program.clone())
                } else {
                    let pkts = self.pkt_rows();
                    let row = self.pkt_state.selected();
                    row.and_then(|r| pkts.get(r))
                        .map(|&i| self.packets[i].program.clone())
                };
                match program {
                    Some(name) if self.capturing.contains(&name) => Some(name),
                    _ if self.capturing.is_empty() => {
                        self.flash("select a program in Processes (1) and press c to capture it");
                        None
                    }
                    _ => None,
                }
            }
            _ => {
                self.flash("press c on a program in Processes (1) to capture its packets");
                None
            }
        };
        if let Some(n) = name {
            self.toggle_capture(n);
        }
    }

    fn cycle_sort(&mut self) {
        match self.tab {
            Tab::Packets if self.pkt_flows => {
                self.reverse = false;
                self.flow_sort = self.flow_sort.next();
                return;
            }
            // Packets are always in time order (r reverses).
            Tab::Packets => return,
            _ => self.reverse = false,
        }
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
            Tab::Devices => {
                self.dev_sort = match self.dev_sort {
                    DevSort::Ip => DevSort::Name,
                    DevSort::Name => DevSort::Vendor,
                    DevSort::Vendor => DevSort::Seen,
                    DevSort::Seen => DevSort::Ip,
                }
            }
            Tab::Packets => {}
        }
    }

    pub fn on_mouse(&mut self, m: MouseEvent) {
        let pos = Position::new(m.column, m.row);
        if self.show_diagram {
            match m.kind {
                MouseEventKind::ScrollDown => {
                    self.diagram_scroll = self.diagram_scroll.saturating_add(3)
                }
                MouseEventKind::ScrollUp => {
                    self.diagram_scroll = self.diagram_scroll.saturating_sub(3)
                }
                MouseEventKind::Down(_) => self.show_diagram = false,
                _ => {}
            }
            return;
        }
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

    /// The device rows to show, filtered and sorted.
    pub fn dev_rows(&self) -> Vec<DevKey> {
        let devs = &self.lan_state.devices;
        let mut keys: Vec<DevKey> = devs
            .values()
            .filter(|d| {
                let ips: Vec<String> = d.ips().map(|ip| ip.to_string()).collect();
                let mac = d
                    .mac
                    .as_ref()
                    .map(crate::lan::discover::fmt_mac)
                    .unwrap_or_default();
                let mut fields: Vec<&str> = ips.iter().map(String::as_str).collect();
                fields.push(&mac);
                fields.extend(d.name.as_deref());
                fields.extend(d.vendor.as_deref());
                if d.is_gateway {
                    fields.push("gateway");
                }
                self.matches(&fields)
            })
            .map(|d| d.key)
            .collect();
        let d = |k: &DevKey| &devs[k];
        match self.dev_sort {
            // IPv4 order; IPv6-only devices after, by address.
            DevSort::Ip => {
                keys.sort_by_key(|k| (d(k).ipv4.is_none(), d(k).ipv4, d(k).ipv6.first().copied()))
            }
            // Unnamed devices go last.
            DevSort::Name => keys.sort_by_key(|k| {
                (
                    d(k).name.is_none(),
                    d(k).name.as_ref().map(|n| n.to_lowercase()),
                )
            }),
            DevSort::Vendor => keys.sort_by_key(|k| {
                (
                    d(k).vendor.is_none(),
                    d(k).vendor.as_ref().map(|v| v.to_lowercase()),
                )
            }),
            DevSort::Seen => {
                keys.sort_by_key(|k| (!d(k).online, std::cmp::Reverse(d(k).last_seen)))
            }
        }
        if self.reverse {
            keys.reverse();
        }
        keys
    }

    /// The filter: every word must appear in some field, and a word starting
    /// with `!` must appear in none ("dns !mdns", "firefox 443").
    pub fn matches(&self, fields: &[&str]) -> bool {
        self.matches_with_bytes(fields, &[])
    }

    /// `matches`, where `bytes` (a packet's payload) counts as a field too.
    pub fn matches_with_bytes(&self, fields: &[&str], bytes: &[u8]) -> bool {
        if self.filter.trim().is_empty() {
            return true;
        }
        let fields: Vec<String> = fields.iter().map(|f| f.to_lowercase()).collect();
        let hit = |w: &str| {
            fields.iter().any(|f| f.contains(w))
                || crate::packet::find_ignore_case(bytes, w.as_bytes()).is_some()
        };
        self.filter
            .to_lowercase()
            .split_whitespace()
            .all(|w| match w.strip_prefix('!') {
                Some("") => true,
                Some(not) => !hit(not),
                None => hit(w),
            })
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
