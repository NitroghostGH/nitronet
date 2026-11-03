//! Turns repeated socket and /proc snapshots into per-socket and per-process
//! rates and running totals.
//!
//! There are two byte-count sources:
//!   * eBPF (root): per-socket packet bytes for TCP and UDP, counted from the
//!     moment nitronet starts. This includes sockets that close between samples.
//!   * tcp_info (fallback): the kernel's per-socket TCP payload counters, read
//!     with the sock_diag dump. TCP only, and short-lived sockets are missed.

use std::collections::{HashMap, HashSet};
use std::io;
use std::time::Instant;

use crate::bpf::{self, Capture, Entry, RawPacket, Tracker};
use crate::netlink::{Diag, Proto, SockInfo};
use crate::packet::{self, Classifier, Content, Packet};
use crate::procfs::{self, ProcMap};

/// Captured packets held for the UI (for example while it is paused).
/// Packets kept while waiting for the UI (e.g. while paused). It is the
/// number the UI keeps, so nothing waits only to be thrown away there.
const PENDING: usize = crate::packet::MAX_PACKETS;
/// Programs that exited are remembered for their totals, up to this many.
/// Past that, the ones that moved the least are forgotten.
const MAX_DEAD: usize = 1000;

/// Who a socket belongs to.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub enum Owner {
    Pid(u32),
    /// We know the socket's uid but couldn't find its process (usually because
    /// we lack permission to read that process's fds).
    Uid(u32),
    /// No fd holds the socket (TIME_WAIT and similar). The kernel owns it.
    Kernel,
}

#[derive(Clone, Debug)]
pub enum Source {
    Ebpf {
        /// Whether new sockets record their creating pid (the sock_create program loaded).
        tracks_creators: bool,
    },
    TcpInfo {
        /// Why eBPF isn't in use.
        reason: String,
    },
}

pub struct SockRow {
    pub sock: SockInfo,
    pub owner: Owner,
    /// Bytes per second over the last interval. None means not measurable.
    pub rate_in: Option<f64>,
    pub rate_out: Option<f64>,
    /// Cumulative (in, out) bytes: since nitronet started for eBPF, or over the
    /// socket's whole lifetime for tcp_info.
    pub bytes: Option<(u64, u64)>,
}

#[derive(Clone)]
pub struct ProcRow {
    pub owner: Owner,
    pub name: String,
    pub unit: Option<String>,
    pub user: String,
    /// False once the process has no sockets and no traffic. We keep it for its totals.
    pub alive: bool,
    pub rate_in: f64,
    pub rate_out: f64,
    /// Bytes counted for this owner since nitronet started.
    pub total_in: u64,
    pub total_out: u64,
    pub sockets: usize,
    pub listening: Vec<(Proto, u16)>,
}

pub struct Snapshot {
    pub sockets: Vec<SockRow>,
    pub procs: Vec<ProcRow>,
    /// Physical-interface (rx, tx) bytes/s, a reference for the attributed sum.
    pub nic_rate: Option<(f64, f64)>,
    /// Physical-interface (rx, tx) bytes since nitronet started.
    pub nic_total: Option<(u64, u64)>,
    /// Sum of all attributed rates.
    pub seen_rate: (f64, f64),
    pub hidden_procs: usize,
    pub is_root: bool,
    /// True for the first tcp_info sample: it only sets the baseline, so rates are 0.
    pub baseline: bool,
    pub source: Source,
    /// Sockets that closed since the last sample but had traffic counted by eBPF.
    pub closed_sockets: usize,
}

struct Acc {
    name: String,
    unit: Option<String>,
    user: String,
    total_in: u64,
    total_out: u64,
}

pub struct Sampler {
    diag: Diag,
    tracker: Option<Tracker>,
    source: Source,
    users: HashMap<u32, String>,
    is_root: bool,
    last: Option<Instant>,
    /// cookie -> (bytes_in, bytes_out) seen in the previous sample.
    prev: HashMap<u64, (u64, u64)>,
    /// cookie -> owner from the previous sample. When a socket closes, its
    /// last bytes still go to the process that owned it.
    seen: HashMap<u64, Owner>,
    nic_prev: Option<(u64, u64)>,
    nic_start: Option<(u64, u64)>,
    acc: HashMap<Owner, Acc>,
    /// Packet capture, running while any program is chosen for it.
    capture: Option<Capture>,
    capture_names: HashSet<String>,
    /// Running processes with a captured name, refreshed each sample.
    capture_pids: HashSet<u32>,
    pending: Vec<Packet>,
    pending_lost: u64,
    next_packet: u64,
    classifier: Classifier,
}

impl Sampler {
    pub fn new(use_ebpf: bool) -> io::Result<Self> {
        let diag = Diag::open()?;
        // SAFETY: geteuid has no preconditions.
        let is_root = unsafe { libc::geteuid() } == 0;
        let (tracker, source) = if !use_ebpf {
            (
                None,
                Source::TcpInfo {
                    reason: "disabled with --no-ebpf".into(),
                },
            )
        } else {
            match bpf::Tracker::start() {
                Ok(t) => {
                    let tracks_creators = t.tracks_creators;
                    (Some(t), Source::Ebpf { tracks_creators })
                }
                Err(e) if e.kind() == io::ErrorKind::PermissionDenied => (
                    None,
                    Source::TcpInfo {
                        reason: "eBPF needs root".into(),
                    },
                ),
                Err(e) => (
                    None,
                    Source::TcpInfo {
                        reason: format!("eBPF unavailable: {e}"),
                    },
                ),
            }
        };
        Ok(Self {
            diag,
            tracker,
            source,
            users: procfs::users(),
            is_root,
            last: None,
            prev: HashMap::new(),
            seen: HashMap::new(),
            nic_prev: None,
            nic_start: None,
            acc: HashMap::new(),
            capture: None,
            capture_names: HashSet::new(),
            capture_pids: HashSet::new(),
            pending: Vec::new(),
            pending_lost: 0,
            next_packet: 0,
            classifier: Classifier::default(),
        })
    }

    pub fn source(&self) -> &Source {
        &self.source
    }

    fn user(&self, uid: u32) -> String {
        self.users
            .get(&uid)
            .cloned()
            .unwrap_or_else(|| uid.to_string())
    }

    pub fn sample(&mut self) -> io::Result<Snapshot> {
        // Attribute captured packets while their sockets are still known.
        self.drain_capture();
        let now = Instant::now();
        let socks = self.diag.dump_all()?;
        let pm = procfs::scan();
        if self.capture.is_some() {
            self.capture_pids = procfs::pids_named(&self.capture_names);
        }
        let nic = procfs::nic_totals();
        let mut entries = match &self.tracker {
            Some(t) => Some(t.read_all()?),
            None => None,
        };

        let ebpf = entries.is_some();
        let baseline = self.last.is_none() && !ebpf;
        let dt = self
            .last
            .map(|t| now.duration_since(t).as_secs_f64())
            .filter(|d| *d > 0.0);
        let per_sec = |bytes: u64| dt.map_or(0.0, |dt| bytes as f64 / dt);
        // eBPF counters start at zero when nitronet starts, so a cookie we haven't
        // seen yet counts in full. tcp_info counters cover the socket's whole
        // life, so on the first sample they only set the baseline.
        let count_unseen = ebpf || self.last.is_some();

        let mut next_prev = HashMap::with_capacity(socks.len());
        let mut next_seen = HashMap::with_capacity(socks.len());
        let mut live: HashMap<Owner, ProcRow> = HashMap::new();
        let mut rows = Vec::with_capacity(socks.len());

        for sock in socks {
            let entry = entries.as_mut().and_then(|m| m.remove(&sock.cookie));
            let owner = self.resolve(&sock, &pm, entry.as_ref());
            let counters = if ebpf {
                Some(entry.as_ref().map_or((0, 0), |e| (e.rx, e.tx)))
            } else {
                sock.bytes_in.zip(sock.bytes_out)
            };
            let (d_in, d_out) = match counters {
                Some(c) => {
                    next_prev.insert(sock.cookie, c);
                    delta(c, self.prev.get(&sock.cookie).copied(), count_unseen)
                }
                None => (0, 0),
            };
            next_seen.insert(sock.cookie, owner);

            let row = self.live_row(&mut live, owner, &pm, sock.uid, entry.as_ref());
            row.rate_in += per_sec(d_in);
            row.rate_out += per_sec(d_out);
            row.sockets += 1;
            if sock.is_listening() {
                row.listening.push((sock.proto, sock.local.port()));
            }
            account(&mut self.acc, owner, row, d_in, d_out);

            let (rate_in, rate_out) = match counters {
                Some(_) => (Some(per_sec(d_in)), Some(per_sec(d_out))),
                None => (None, None),
            };
            rows.push(SockRow {
                sock,
                owner,
                rate_in,
                rate_out,
                bytes: counters,
            });
        }

        // eBPF entries with no matching socket: sockets that closed since the last
        // sample, or ones outside this network namespace (e.g. containers). Count
        // their remaining bytes, then delete them so the map doesn't fill up.
        let mut closed_sockets = 0;
        if let (Some(tracker), Some(rest)) = (&self.tracker, entries) {
            for (cookie, e) in rest {
                tracker.remove(cookie);
                let (d_in, d_out) = delta((e.rx, e.tx), self.prev.get(&cookie).copied(), true);
                if d_in == 0 && d_out == 0 {
                    continue;
                }
                closed_sockets += 1;
                let owner = self.seen.get(&cookie).copied().unwrap_or(if e.pid != 0 {
                    Owner::Pid(e.pid)
                } else {
                    Owner::Uid(e.uid)
                });
                // Not every socket is closed: some are outside the dump (in a
                // container's network namespace, or ping and raw sockets). The
                // entry was just deleted, so if the socket sends again its new
                // entry has no creator. Remember the owner for it.
                next_seen.insert(cookie, owner);
                let row = self.live_row(&mut live, owner, &pm, e.uid, Some(&e));
                row.rate_in += per_sec(d_in);
                row.rate_out += per_sec(d_out);
                account(&mut self.acc, owner, row, d_in, d_out);
            }
        }

        // Drop owners that are gone and never moved any data. This keeps a
        // churn of short-lived pids from growing the map forever.
        self.acc
            .retain(|k, a| live.contains_key(k) || a.total_in > 0 || a.total_out > 0);
        forget_dead(&mut self.acc, &live);

        let mut procs: Vec<ProcRow> = Vec::with_capacity(self.acc.len());
        for (owner, acc) in &self.acc {
            let row = match live.remove(owner) {
                Some(mut r) => {
                    r.listening.sort_unstable();
                    r.listening.dedup();
                    r
                }
                None => ProcRow {
                    owner: *owner,
                    name: acc.name.clone(),
                    unit: acc.unit.clone(),
                    user: acc.user.clone(),
                    alive: false,
                    rate_in: 0.0,
                    rate_out: 0.0,
                    total_in: 0,
                    total_out: 0,
                    sockets: 0,
                    listening: Vec::new(),
                },
            };
            procs.push(ProcRow {
                total_in: acc.total_in,
                total_out: acc.total_out,
                ..row
            });
        }

        let nic_rate = match (self.nic_prev, nic, dt) {
            (Some((prx, ptx)), Some((rx, tx)), Some(_)) => Some((
                per_sec(rx.saturating_sub(prx)),
                per_sec(tx.saturating_sub(ptx)),
            )),
            _ => None,
        };
        let seen_rate = procs
            .iter()
            .fold((0.0, 0.0), |(i, o), p| (i + p.rate_in, o + p.rate_out));

        if self.nic_start.is_none() {
            self.nic_start = nic;
        }
        let nic_total = match (self.nic_start, nic) {
            (Some((srx, stx)), Some((rx, tx))) => {
                Some((rx.saturating_sub(srx), tx.saturating_sub(stx)))
            }
            _ => None,
        };

        self.prev = next_prev;
        self.seen = next_seen;
        self.nic_prev = nic;
        self.last = Some(now);
        self.update_capture_targets();

        Ok(Snapshot {
            sockets: rows,
            procs,
            nic_rate,
            nic_total,
            seen_rate,
            hidden_procs: pm.hidden,
            is_root: self.is_root,
            baseline,
            source: self.source.clone(),
            closed_sockets,
        })
    }

    /// Picks an owner for a socket in the dump. The order is: the process
    /// holding its fd now; the owner from the last sample (keeps a TIME_WAIT
    /// socket's final bytes with its process); the pid eBPF saw create it; and
    /// finally the kernel or the bare uid.
    fn resolve(&self, sock: &SockInfo, pm: &ProcMap, entry: Option<&Entry>) -> Owner {
        if let Some(&pid) = pm.owner.get(&sock.inode) {
            return Owner::Pid(pid);
        }
        if let Some(&o) = self.seen.get(&sock.cookie) {
            return o;
        }
        if let Some(e) = entry.filter(|e| e.pid != 0) {
            return Owner::Pid(e.pid);
        }
        if sock.inode == 0 {
            Owner::Kernel
        } else {
            Owner::Uid(sock.uid)
        }
    }

    /// Captures packets from the programs named (as in /proc/<pid>/comm), or
    /// stops capturing when the set is empty. The error is ready to show.
    pub fn set_capture(&mut self, names: &HashSet<String>) -> Result<(), String> {
        if names.is_empty() {
            self.drain_capture();
            self.capture = None;
            self.capture_names.clear();
            self.capture_pids.clear();
            return Ok(());
        }
        let Some(tracker) = &self.tracker else {
            return Err(match &self.source {
                Source::TcpInfo { reason } if reason == "eBPF needs root" => {
                    "capturing packets needs eBPF: run nitronet as root".to_string()
                }
                Source::TcpInfo { reason } => format!(
                    "capturing packets needs eBPF, which isn't running ({})",
                    reason.lines().next().unwrap_or_default()
                ),
                Source::Ebpf { .. } => "eBPF isn't running".to_string(),
            });
        };
        if self.capture.is_none() {
            self.capture = Some(
                tracker
                    .capture()
                    .map_err(|e| format!("can't start capture: {e}"))?,
            );
        }
        self.capture_names = names.clone();
        self.capture_pids = procfs::pids_named(names);
        self.update_capture_targets();
        Ok(())
    }

    /// Tells the capture programs which sockets belong to captured programs.
    fn update_capture_targets(&mut self) {
        let Some(cap) = &mut self.capture else {
            return;
        };
        let cookies: HashSet<u64> = self
            .seen
            .iter()
            .filter(|(_, o)| {
                matches!(o, Owner::Pid(_))
                    && self
                        .acc
                        .get(o)
                        .is_some_and(|a| self.capture_names.contains(&a.name))
            })
            .map(|(c, _)| *c)
            .collect();
        cap.set_targets(&self.capture_names, &self.capture_pids, &cookies);
    }

    /// Captured packets since the last call, oldest first.
    pub fn take_packets(&mut self) -> Vec<Packet> {
        self.drain_capture();
        std::mem::take(&mut self.pending)
    }

    /// Packets matched but not kept because a buffer was full.
    pub fn capture_dropped(&self) -> u64 {
        self.capture.as_ref().map_or(0, |c| c.dropped()) + self.pending_lost
    }

    fn drain_capture(&mut self) {
        let Some(cap) = &self.capture else {
            return;
        };
        let raw = cap.take();
        if raw.is_empty() {
            return;
        }
        let mut cache: HashMap<u64, (Owner, String)> = HashMap::new();
        for r in raw {
            let (owner, program) = cache
                .entry(r.cookie)
                .or_insert_with(|| self.packet_owner(r.cookie))
                .clone();
            let RawPacket {
                at,
                len,
                outgoing,
                data,
                ..
            } = r;
            let mut p = Packet {
                id: self.next_packet,
                at,
                owner,
                program,
                outgoing,
                len,
                head: packet::decode(&data, len),
                data,
                content: Content::Empty,
                secret: None,
            };
            self.classifier.apply(&mut p);
            self.pending.push(p);
            self.next_packet += 1;
        }
        if self.pending.len() > PENDING {
            let extra = self.pending.len() - PENDING;
            self.pending.drain(..extra);
            self.pending_lost += extra as u64;
        }
    }

    /// Who a captured packet's socket belongs to: the owner from the last
    /// sample, or else the process eBPF saw create it.
    fn packet_owner(&self, cookie: u64) -> (Owner, String) {
        if let Some(o) = self.seen.get(&cookie)
            && let Some(a) = self.acc.get(o)
        {
            return (*o, a.name.clone());
        }
        match self.tracker.as_ref().and_then(|t| t.lookup(cookie)) {
            Some(e) if e.pid != 0 => {
                let name = procfs::read_process(e.pid)
                    .map(|p| p.name)
                    .unwrap_or(e.comm);
                (Owner::Pid(e.pid), name)
            }
            _ => (Owner::Kernel, "?".into()),
        }
    }

    fn live_row<'a>(
        &self,
        live: &'a mut HashMap<Owner, ProcRow>,
        owner: Owner,
        pm: &ProcMap,
        uid: u32,
        entry: Option<&Entry>,
    ) -> &'a mut ProcRow {
        live.entry(owner).or_insert_with(|| {
            let (name, unit, user) = self.describe(owner, pm, uid, entry);
            ProcRow {
                owner,
                name,
                unit,
                user,
                alive: true,
                rate_in: 0.0,
                rate_out: 0.0,
                total_in: 0,
                total_out: 0,
                sockets: 0,
                listening: Vec::new(),
            }
        })
    }
}

/// Adds bytes to an owner's running totals. This is a free function so it can
/// run while other fields of the sampler are borrowed.
fn account(accs: &mut HashMap<Owner, Acc>, owner: Owner, row: &ProcRow, d_in: u64, d_out: u64) {
    let fresh = || Acc {
        name: row.name.clone(),
        unit: row.unit.clone(),
        user: row.user.clone(),
        total_in: 0,
        total_out: 0,
    };
    let acc = accs.entry(owner).or_insert_with(fresh);
    // The pid now runs something else: it was reused by a new process (or
    // the process exec'd another program). Start over, so the new program
    // isn't shown, or captured, under the old one's name and totals.
    if acc.name != row.name || acc.user != row.user {
        *acc = fresh();
    }
    acc.unit.clone_from(&row.unit);
    acc.total_in += d_in;
    acc.total_out += d_out;
}

/// Keeps at most MAX_DEAD exited owners, dropping the ones that moved least.
fn forget_dead(accs: &mut HashMap<Owner, Acc>, live: &HashMap<Owner, ProcRow>) {
    let mut dead: Vec<(u64, Owner)> = accs
        .iter()
        .filter(|(o, _)| !live.contains_key(o))
        .map(|(o, a)| (a.total_in.saturating_add(a.total_out), *o))
        .collect();
    if dead.len() <= MAX_DEAD {
        return;
    }
    dead.sort_unstable();
    for (_, o) in &dead[..dead.len() - MAX_DEAD] {
        accs.remove(o);
    }
}

impl Sampler {
    fn describe(
        &self,
        owner: Owner,
        pm: &ProcMap,
        uid: u32,
        entry: Option<&Entry>,
    ) -> (String, Option<String>, String) {
        match owner {
            Owner::Pid(pid) => {
                // Prefer /proc. A process that has exited is known only by eBPF's comm.
                if let Some(p) = pm
                    .procs
                    .get(&pid)
                    .cloned()
                    .or_else(|| procfs::read_process(pid))
                {
                    return (p.name, p.unit, self.user(p.uid));
                }
                let name = entry
                    .map(|e| e.comm.clone())
                    .filter(|c| !c.is_empty())
                    .unwrap_or_else(|| "?".into());
                let previous = self.acc.get(&owner);
                match previous {
                    Some(a) => (a.name.clone(), a.unit.clone(), a.user.clone()),
                    // eBPF's uid comes from the creating process. A TIME_WAIT
                    // socket's own uid reads as 0, so prefer eBPF's.
                    None => (name, None, self.user(entry.map_or(uid, |e| e.uid))),
                }
            }
            Owner::Uid(uid) => {
                let name = if self.is_root {
                    "(unresolved)"
                } else {
                    "(needs root)"
                };
                (name.into(), None, self.user(uid))
            }
            Owner::Kernel => ("(kernel)".into(), None, "-".into()),
        }
    }
}

/// Bytes since the previous reading. A counter that went down was reset
/// (e.g. the eBPF map evicted the entry), so it counts from zero.
fn delta(cur: (u64, u64), prev: Option<(u64, u64)>, count_unseen: bool) -> (u64, u64) {
    let one = |c: u64, p: u64| if c >= p { c - p } else { c };
    match prev {
        Some(p) => (one(cur.0, p.0), one(cur.1, p.1)),
        None if count_unseen => cur,
        None => (0, 0),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(owner: Owner, name: &str) -> ProcRow {
        ProcRow {
            owner,
            name: name.into(),
            unit: None,
            user: "nitro".into(),
            alive: true,
            rate_in: 0.0,
            rate_out: 0.0,
            total_in: 0,
            total_out: 0,
            sockets: 0,
            listening: Vec::new(),
        }
    }

    #[test]
    fn a_reused_pid_starts_over() {
        let mut accs = HashMap::new();
        let pid = Owner::Pid(4242);
        account(&mut accs, pid, &row(pid, "firefox"), 100, 50);
        account(&mut accs, pid, &row(pid, "firefox"), 10, 5);
        assert_eq!((accs[&pid].total_in, accs[&pid].total_out), (110, 55));
        // The pid now belongs to another program.
        account(&mut accs, pid, &row(pid, "evil"), 1, 2);
        let a = &accs[&pid];
        assert_eq!((a.name.as_str(), a.total_in, a.total_out), ("evil", 1, 2));
    }

    #[test]
    fn exited_programs_are_capped() {
        let mut accs = HashMap::new();
        let mut live = HashMap::new();
        for pid in 0..(MAX_DEAD as u32 + 50) {
            let o = Owner::Pid(pid);
            account(&mut accs, o, &row(o, "short"), u64::from(pid) + 1, 0);
        }
        let alive = Owner::Pid(0);
        live.insert(alive, row(alive, "short"));
        forget_dead(&mut accs, &live);
        assert_eq!(accs.len(), MAX_DEAD + 1);
        // The live one stays even though it moved least; the smallest dead go.
        assert!(accs.contains_key(&alive));
        assert!(!accs.contains_key(&Owner::Pid(1)));
        assert!(accs.contains_key(&Owner::Pid(MAX_DEAD as u32 + 49)));
    }

    #[test]
    fn deltas() {
        assert_eq!(delta((100, 50), Some((40, 50)), false), (60, 0));
        assert_eq!(delta((100, 50), None, true), (100, 50));
        assert_eq!(delta((100, 50), None, false), (0, 0));
        assert_eq!(delta((10, 50), Some((40, 20)), true), (10, 30)); // reset counter
    }
}

#[cfg(test)]
mod live {
    use super::*;

    /// Needs root and network: sudo -E cargo test live_curl -- --ignored --nocapture
    #[test]
    #[ignore]
    fn live_curl_capture() {
        let mut s = Sampler::new(true).unwrap();
        s.sample().unwrap();
        s.set_capture(&HashSet::from(["curl".to_string()])).unwrap();
        // Unrelated traffic from this process must not show up.
        let _ = std::net::TcpStream::connect("1.1.1.1:80");
        let out = std::process::Command::new("curl")
            .args([
                "-sS",
                "-o",
                "/dev/null",
                "-w",
                "%{http_code}",
                "https://example.com/",
            ])
            .output()
            .unwrap();
        eprintln!("curl: {}", String::from_utf8_lossy(&out.stdout));
        std::thread::sleep(std::time::Duration::from_millis(300));
        s.sample().unwrap();
        let pk = s.take_packets();
        for p in &pk {
            let d = p.head.as_ref().unwrap();
            let (l, r) = p.ends().unwrap();
            eprintln!(
                "{} {} {:>5} {} {} {} {} [{}]",
                p.program,
                if p.outgoing { "→" } else { "←" },
                p.len,
                d.proto(),
                l,
                r,
                d.info,
                p.content.label()
            );
        }
        eprintln!("{} packets, {} dropped", pk.len(), s.capture_dropped());
        assert!(pk.iter().all(|p| p.program == "curl"));
        assert!(pk.iter().any(|p| {
            p.head
                .as_ref()
                .unwrap()
                .info
                .contains("ClientHello → example.com")
        }));
        s.set_capture(&HashSet::new()).unwrap();
    }

    /// The router login case: a program whose connections are opened by a
    /// differently named thread (Firefox's "Socket Thread") sends a form on
    /// a brand-new connection, faster than a refresh. The whole exchange must
    /// be captured, and the form readable.
    /// sudo -E cargo test live_new_connection -- --ignored --nocapture
    #[test]
    #[ignore]
    fn live_new_connection_from_another_thread() {
        use std::io::{Read, Write};
        let me = std::fs::read_to_string("/proc/self/comm").unwrap();
        let me = me.trim_end().to_string();
        let mut s = Sampler::new(true).unwrap();
        s.sample().unwrap();
        s.set_capture(&HashSet::from([me.clone()])).unwrap();

        let server = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let to = server.local_addr().unwrap();
        let client = std::thread::Builder::new()
            .name("Socket Thread".into())
            .spawn(move || {
                let mut c = std::net::TcpStream::connect(to).unwrap();
                c.write_all(b"POST /login HTTP/1.1\r\nHost: router\r\nContent-Length: 30\r\n\r\n")
                    .unwrap();
                c.write_all(b"username=admin&password=hunter2").unwrap();
                let mut buf = [0u8; 64];
                let _ = c.read(&mut buf);
            })
            .unwrap();
        let (mut conn, _) = server.accept().unwrap();
        let mut buf = [0u8; 256];
        let _ = conn.read(&mut buf);
        conn.write_all(b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n")
            .unwrap();
        client.join().unwrap();
        drop(conn);
        std::thread::sleep(std::time::Duration::from_millis(200));
        s.sample().unwrap();
        let pk = s.take_packets();
        for p in &pk {
            eprintln!(
                "{} {} {} [{}]",
                p.program,
                if p.outgoing { "→" } else { "←" },
                p.head.as_ref().unwrap().info,
                p.content.label()
            );
        }
        let has = |what: &str| {
            pk.iter().any(|p| {
                p.outgoing
                    && p.content.unencrypted_data()
                    && String::from_utf8_lossy(p.payload()).contains(what)
            })
        };
        assert!(
            pk.iter()
                .any(|p| p.head.as_ref().unwrap().info.starts_with("[S]")),
            "the first SYN is missing"
        );
        assert!(has("POST /login") && has("password=hunter2"));
        s.set_capture(&HashSet::new()).unwrap();
    }
}
