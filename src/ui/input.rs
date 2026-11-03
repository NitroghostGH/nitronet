//! Keys and mouse.

use ratatui::crossterm::event::{
    KeyCode, KeyEvent, KeyModifiers, MouseButton, MouseEvent, MouseEventKind,
};
use ratatui::layout::Position;

use super::{App, DevSort, ProcSort, SockSort, Tab};
use crate::sampler::Owner;

impl App {
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
            KeyCode::Char('r') => {
                let r = self.reversed_mut();
                *r = !*r;
            }
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
                    Some(v) if self.capturing.contains_key(&v.row.name) => {
                        Some((v.row.name.clone(), None))
                    }
                    Some(v) if matches!(v.row.owner, Owner::Pid(_)) && v.row.uid.is_none() => {
                        self.flash(format!(
                            "{} runs as several users: press g to ungroup and pick one",
                            v.row.name
                        ));
                        None
                    }
                    Some(v) if matches!(v.row.owner, Owner::Pid(_)) => {
                        Some((v.row.name.clone(), v.row.uid))
                    }
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
                    Some(name) if self.capturing.contains_key(&name) => Some((name, None)),
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
        if let Some((n, uid)) = name {
            self.toggle_capture(n, uid);
        }
    }

    /// The reversed flag of the list on screen.
    fn reversed_mut(&mut self) -> &mut bool {
        match self.tab {
            Tab::Procs => &mut self.reverse.procs,
            Tab::Sockets => &mut self.reverse.socks,
            Tab::Devices => &mut self.reverse.devs,
            Tab::Packets if self.pkt_flows => &mut self.reverse.flows,
            Tab::Packets => &mut self.reverse.pkts,
        }
    }

    fn cycle_sort(&mut self) {
        match self.tab {
            Tab::Packets if self.pkt_flows => {
                self.reverse.flows = false;
                self.flow_sort = self.flow_sort.next();
                return;
            }
            // Packets are always in time order (r reverses).
            Tab::Packets => return,
            _ => *self.reversed_mut() = false,
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
}
