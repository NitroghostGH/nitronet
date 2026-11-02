//! Turns repeated socket and /proc snapshots into per-socket and per-process
//! rates and running totals.
//!
//! There are two byte-count sources:
//!   * eBPF (root): per-socket packet bytes for TCP and UDP, counted from the
//!     moment nitronet starts. This includes sockets that close between samples.
//!   * tcp_info (fallback): the kernel's per-socket TCP payload counters, read
//!     with the sock_diag dump. TCP only, and short-lived sockets are missed.

use std::collections::HashMap;
use std::io;
use std::time::Instant;

use crate::bpf::{self, Entry, Tracker};
use crate::netlink::{Diag, Proto, SockInfo};
use crate::procfs::{self, ProcMap};

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
    acc: HashMap<Owner, Acc>,
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
            acc: HashMap::new(),
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
        let now = Instant::now();
        let socks = self.diag.dump_all()?;
        let pm = procfs::scan();
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

        self.prev = next_prev;
        self.seen = next_seen;
        self.nic_prev = nic;
        self.last = Some(now);

        Ok(Snapshot {
            sockets: rows,
            procs,
            nic_rate,
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
    let acc = accs.entry(owner).or_insert_with(|| Acc {
        name: row.name.clone(),
        unit: row.unit.clone(),
        user: row.user.clone(),
        total_in: 0,
        total_out: 0,
    });
    acc.total_in += d_in;
    acc.total_out += d_out;
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
    use super::delta;

    #[test]
    fn deltas() {
        assert_eq!(delta((100, 50), Some((40, 50)), false), (60, 0));
        assert_eq!(delta((100, 50), None, true), (100, 50));
        assert_eq!(delta((100, 50), None, false), (0, 0));
        assert_eq!(delta((10, 50), Some((40, 20)), true), (10, 30)); // reset counter
    }
}
