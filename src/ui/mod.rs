//! ratatui front end: app state, the event loop and selection. Keys and
//! mouse are in `input.rs`, the rows each tab lists in `lists.rs`, and
//! drawing in `view.rs` and the `*_view.rs` files.

mod devices_view;
mod diagram;
mod fmt;
mod history;
mod input;
mod lists;
mod packets;
mod packets_view;
mod procs_view;
mod query;
mod sockets_view;
mod theme;
mod view;
mod widgets;

#[cfg(test)]
mod tests;

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::io;
use std::time::{Duration, Instant};

use ratatui::DefaultTerminal;
use ratatui::crossterm::event::{
    self, DisableMouseCapture, EnableMouseCapture, Event, KeyEventKind,
};
use ratatui::crossterm::execute;
use ratatui::layout::Rect;
use ratatui::widgets::TableState;

pub use fmt::{fmt_addr, human};

use crate::lan::{DevKey, Lan, LanState};
use crate::packet::{FlowKey, Packet};
use crate::sampler::{Owner, ProcRow, Sampler, Snapshot};
use history::History;
pub(crate) use packets::{ContentFilter, DirFilter, Flow, FlowSort};

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
            let targets: HashMap<String, u32> =
                app.capturing.iter().map(|(n, &u)| (n.clone(), u)).collect();
            if let Err(e) = sampler.set_capture(&targets) {
                app.capturing.clear();
                app.flash(e);
            }
            if app.capturing.is_empty() {
                // The last packets read before the stop.
                app.add_packets(sampler.take_packets());
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
            // A failed sample (e.g. netlink busy) is shown and retried, rather
            // than closing the program.
            match sampler.sample() {
                Ok(snap) if !app.paused => app.set_snapshot(snap),
                Ok(_) => {}
                Err(e) => app.flash(format!("couldn't read sockets: {e}")),
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

/// Which lists `r` has reversed. Each list has its own, so reversing one
/// doesn't flip the others.
#[derive(Clone, Copy, Default, Debug)]
pub struct Reversed {
    pub procs: bool,
    pub socks: bool,
    pub devs: bool,
    pub pkts: bool,
    pub flows: bool,
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
    pub reverse: Reversed,
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
    /// Captured program names, each with the uid it is captured for.
    pub capturing: BTreeMap<String, u32>,
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
            reverse: Reversed::default(),
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
            capturing: BTreeMap::new(),
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
        if self.packets.len() > crate::packet::MAX_PACKETS {
            let extra = self.packets.len() - crate::packet::MAX_PACKETS;
            self.packets.drain(..extra);
        }
    }

    /// Whether a process row's packets are being captured: its name is, for
    /// its user. Another user's process with the same name isn't.
    pub fn is_captured(&self, row: &ProcRow) -> bool {
        matches!(row.owner, Owner::Pid(_))
            && self
                .capturing
                .get(&row.name)
                .is_some_and(|u| row.uid.is_none_or(|r| r == *u))
    }

    /// Starts or stops capturing a program's packets. `uid` is the user
    /// whose processes of that name are captured; None only stops.
    fn toggle_capture(&mut self, name: String, uid: Option<u32>) {
        if self.capturing.remove(&name).is_some() {
            self.flash(format!("stopped capturing {name}"));
        } else if let Some(uid) = uid {
            self.flash(format!("capturing {name} · press 4 to watch its packets"));
            self.capturing.insert(name, uid);
        } else {
            return;
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
        flows: Option<&[Flow]>,
    ) {
        // Conversations are listed only while shown (see `shown_flows`).
        if let Some(flows) = flows {
            let row = self
                .flow_sel
                .as_ref()
                .and_then(|k| flows.iter().position(|f| f.key == *k));
            let row = row.unwrap_or_else(|| self.flow_state.selected().unwrap_or(0));
            self.select_flow(flows, row);
        }

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
        if self.reverse.pkts {
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

    /// The conversations, when they are on screen. Grouping every packet
    /// into conversations is the costliest list, so it isn't done otherwise.
    pub fn shown_flows(&self) -> Option<Vec<Flow>> {
        (self.tab == Tab::Packets && self.pkt_flows).then(|| self.flows())
    }

    /// Enter on a conversation: list just its packets, from its first one.
    fn open_flow(&mut self) {
        let Some(key) = self.flow_sel.clone() else {
            return;
        };
        self.pkt_flow = Some(key);
        self.pkt_flows = false;
        // The top row as shown: `i`, `e` and `/` may hide the conversation's
        // first packet, and `r` puts the newest on top.
        self.pkt_sel = self.pkt_rows().first().map(|&i| self.packets[i].id);
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
        let flows = self.shown_flows();
        self.sync_selection(&views, &socks, &devs, &pkts, flows.as_deref());
        let flows = flows.unwrap_or_default();
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
}
