//! LAN device discovery. A background thread sweeps the local subnet on
//! request and then every minute, and pings the IPv6 all-nodes group at the
//! same time. Addresses are joined into devices by MAC, so a dual-stack host
//! is one device. It names devices (reverse DNS, which on systemd-resolved
//! also covers mDNS and LLMNR) and identifies vendors from MAC prefixes. The
//! UI takes a copy of the shared state whenever it has changed.

pub mod discover;
pub mod identify;

use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::mpsc::{self, RecvTimeoutError, Sender};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use crate::netlink::{NUD_REACHABLE, Neighbor};
use discover::{Iface, Mac, Reply6};
use identify::Vendors;

/// Time between automatic rescans while the Devices tab is open.
pub const RESCAN: Duration = Duration::from_secs(60);
const NAME_WORKERS: usize = 8;
/// Devices kept at most. A /22 has 1022 addresses, and devices with IPv6 add
/// a few more; past this, the ones offline longest are forgotten.
const MAX_DEVICES: usize = 2048;
/// Devices offline this long are forgotten.
const FORGET_AFTER: Duration = Duration::from_secs(24 * 3600);

/// What identifies a device across scans: its MAC, or an address when the
/// MAC isn't known (yet).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub enum DevKey {
    Mac(Mac),
    V4(Ipv4Addr),
    V6(Ipv6Addr),
}

#[derive(Clone, Debug)]
pub struct Device {
    pub key: DevKey,
    pub ipv4: Option<Ipv4Addr>,
    /// In display order: global, unique local, link-local.
    pub ipv6: Vec<Ipv6Addr>,
    pub mac: Option<Mac>,
    pub name: Option<String>,
    pub vendor: Option<String>,
    /// Round-trip time of the last ARP or ping reply.
    pub rtt: Option<Duration>,
    pub first_seen: Instant,
    pub last_seen: Instant,
    /// Answered in the most recent scan.
    pub online: bool,
    pub is_self: bool,
    pub is_gateway: bool,
    /// First appeared after the initial scan.
    pub new: bool,
    /// Open common ports, once probed.
    pub ports: Option<Vec<u16>>,
    pub probing: bool,
    name_tried: bool,
}

impl Device {
    fn new(key: DevKey, now: Instant, new: bool) -> Self {
        Self {
            key,
            ipv4: None,
            ipv6: Vec::new(),
            mac: None,
            name: None,
            vendor: None,
            rtt: None,
            first_seen: now,
            last_seen: now,
            online: true,
            is_self: false,
            is_gateway: false,
            new,
            ports: None,
            probing: false,
            name_tried: false,
        }
    }

    pub fn random_mac(&self) -> bool {
        self.mac.as_ref().is_some_and(identify::is_random_mac)
    }

    /// Every address, IPv4 first.
    pub fn ips(&self) -> impl Iterator<Item = IpAddr> + '_ {
        self.ipv4
            .map(IpAddr::V4)
            .into_iter()
            .chain(self.ipv6.iter().map(|a| IpAddr::V6(*a)))
    }

    /// The address to show and to probe: IPv4, else the best IPv6.
    pub fn primary_ip(&self) -> Option<IpAddr> {
        self.ips().next()
    }

    /// Whether `ip` (including an IPv4-mapped IPv6 address) belongs to this device.
    pub fn has_ip(&self, ip: IpAddr) -> bool {
        let ip = ip.to_canonical();
        self.ips().any(|a| a == ip)
    }

    fn overlaps(&self, o: &Obs) -> bool {
        (o.v4.is_some() && self.ipv4 == o.v4) || o.v6.iter().any(|a| self.ipv6.contains(a))
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Method {
    /// Raw ARP (root): finds every device.
    Arp,
    /// Ping sweep plus the kernel's neighbor table.
    Ping,
    /// UDP nudges plus the kernel's neighbor table.
    Udp,
}

#[derive(Clone, Default)]
pub struct LanState {
    pub iface: Option<Iface>,
    pub error: Option<String>,
    pub method: Option<Method>,
    pub devices: BTreeMap<DevKey, Device>,
    /// (addresses swept, total) while a scan runs.
    pub scanning: Option<(usize, usize)>,
    pub last_scan: Option<Instant>,
    pub scans: u32,
    pub vendors_available: bool,
    /// Why the IPv6 scan failed, if it did.
    pub ipv6_error: Option<String>,
    pub devices_v6: usize,
    /// Goes up whenever the scanner changes anything, so the UI can tell when
    /// it needs a fresh copy.
    pub version: u64,
}

enum Cmd {
    Scan,
    Probe(DevKey),
    /// Whether to rescan every RESCAN (while the Devices tab is open).
    Auto(bool),
}

pub struct Lan {
    state: Arc<Mutex<LanState>>,
    tx: Sender<Cmd>,
}

/// Locks the state to change it. Every use bumps the version.
fn lock(state: &Mutex<LanState>) -> MutexGuard<'_, LanState> {
    let mut s = read(state);
    s.version += 1;
    s
}

fn read(state: &Mutex<LanState>) -> MutexGuard<'_, LanState> {
    // A panicked worker leaves usable data behind; keep going with it.
    state.lock().unwrap_or_else(|e| e.into_inner())
}

impl Lan {
    /// Starts the worker thread. It stays idle until the first `scan_now`.
    pub fn start() -> Self {
        let state = Arc::new(Mutex::new(LanState::default()));
        let (tx, rx) = mpsc::channel();
        let worker_state = Arc::clone(&state);
        std::thread::Builder::new()
            .name("lan-scan".into())
            .spawn(move || worker(worker_state, rx))
            .expect("spawn scanner thread");
        Self { state, tx }
    }

    pub fn scan_now(&self) {
        let _ = self.tx.send(Cmd::Scan);
    }

    pub fn probe(&self, key: DevKey) {
        let _ = self.tx.send(Cmd::Probe(key));
    }

    /// Rescans every minute while on, as long as the Devices tab is open.
    pub fn set_auto(&self, on: bool) {
        let _ = self.tx.send(Cmd::Auto(on));
    }

    pub fn snapshot(&self) -> LanState {
        read(&self.state).clone()
    }

    /// A copy of the state, if it changed since `version`.
    pub fn snapshot_since(&self, version: u64) -> Option<LanState> {
        let s = read(&self.state);
        (s.version != version).then(|| s.clone())
    }
}

fn worker(state: Arc<Mutex<LanState>>, rx: mpsc::Receiver<Cmd>) {
    let vendors = Vendors::load();
    // SAFETY: geteuid has no preconditions.
    let is_root = unsafe { libc::geteuid() } == 0;
    {
        let mut s = lock(&state);
        s.vendors_available = !vendors.is_empty();
        match discover::find_iface() {
            Ok(i) => s.iface = Some(i),
            Err(e) => s.error = Some(e.to_string()),
        }
    }
    let mut auto = false;
    let mut last: Option<Instant> = None;
    loop {
        let next = last.filter(|_| auto).map(|t| t + RESCAN);
        let wait = next.map_or(Duration::from_secs(3600), |n| {
            n.saturating_duration_since(Instant::now())
        });
        let scan = match rx.recv_timeout(wait) {
            Ok(Cmd::Scan) => true,
            Ok(Cmd::Probe(key)) => {
                start_probe(&state, key);
                false
            }
            Ok(Cmd::Auto(on)) => {
                auto = on;
                // Back on the tab after a while away: catch up now.
                on && last.is_some_and(|t| t.elapsed() >= RESCAN)
            }
            Err(RecvTimeoutError::Timeout) => next.is_some(),
            Err(RecvTimeoutError::Disconnected) => return,
        };
        if scan {
            run_scan(&state, &vendors, is_root);
            last = Some(Instant::now());
        }
    }
}

fn start_probe(state: &Arc<Mutex<LanState>>, key: DevKey) {
    let (ip, scope) = {
        let mut s = lock(state);
        let index = s.iface.as_ref().map_or(0, |i| i.index);
        match s.devices.get_mut(&key) {
            Some(d) if !d.probing => {
                let Some(ip) = d.primary_ip() else { return };
                d.probing = true;
                let scope = match ip {
                    IpAddr::V6(a) => discover::scope_for(&a, index),
                    IpAddr::V4(_) => 0,
                };
                (ip, scope)
            }
            _ => return,
        }
    };
    let state = Arc::clone(state);
    std::thread::spawn(move || {
        let open = identify::probe(ip, scope);
        if let Some(d) = lock(&state).devices.get_mut(&key) {
            d.ports = Some(open);
            d.probing = false;
        }
    });
}

fn hostname() -> Option<String> {
    std::fs::read_to_string("/proc/sys/kernel/hostname")
        .ok()
        .map(|s| crate::text::clean(s.trim()))
}

fn run_scan(state: &Arc<Mutex<LanState>>, vendors: &Vendors, is_root: bool) {
    let Some(iface) = lock(state).iface.clone() else {
        return;
    };
    let targets: Vec<Ipv4Addr> = iface.targets().collect();
    let total = targets.len();
    lock(state).scanning = Some((0, total));
    // IPv6 discovery runs alongside the IPv4 sweep, so it adds no time.
    let v6 = iface.has_ipv6().then(|| {
        let iface = iface.clone();
        std::thread::spawn(move || discover::ping6_all_nodes(&iface))
    });
    // Progress is reported as addresses covered, scaled from (requests sent, planned).
    let progress = |done: usize, planned: usize| {
        lock(state).scanning = Some(((done * total / planned.max(1)).min(total), total));
    };

    let mut errors = Vec::new();
    let arp = if is_root {
        discover::arp_sweep(&iface, &targets, &progress)
            .map_err(|e| errors.push(format!("ARP: {e}")))
            .ok()
    } else {
        None
    };
    let (method, replies) = match arp {
        Some(r) => (Method::Arp, r),
        None => match discover::ping_sweep(&targets, &progress) {
            Ok(r) => (Method::Ping, r),
            Err(e) => {
                errors.push(format!("ping: {e}"));
                let _ = discover::udp_nudge(&targets, &progress);
                (Method::Udp, Vec::new())
            }
        },
    };

    // Who answered, with MACs. A raw ARP sweep is authoritative. Otherwise the
    // kernel's neighbor table (which our packets just refreshed) fills in MACs
    // and devices that ignore ping.
    let in_range = |ip: &Ipv4Addr| {
        let (a, b) = (u32::from(iface.first), u32::from(iface.first) + iface.count);
        (a..b).contains(&u32::from(*ip))
    };
    let mut seen: BTreeMap<Ipv4Addr, (Option<Mac>, Option<Duration>)> = BTreeMap::new();
    for r in replies.into_iter().filter(|r| in_range(&r.ip)) {
        seen.insert(r.ip, (r.mac, r.rtt));
    }
    let table = discover::arp_table(iface.index);
    for (ip, mac) in table.into_iter().filter(|(ip, _)| in_range(ip)) {
        match seen.get_mut(&ip) {
            Some(entry) => entry.0 = entry.0.or(Some(mac)),
            None if method != Method::Arp => {
                seen.insert(ip, (Some(mac), None));
            }
            None => {}
        }
    }

    let (replies6, ipv6_error) = match v6.map(|h| h.join()) {
        None => (Vec::new(), None),
        Some(Ok(Ok(r))) => (r, None),
        Some(Ok(Err(e))) => (Vec::new(), Some(e.to_string())),
        Some(Err(_)) => (Vec::new(), Some("IPv6 scan failed".into())),
    };
    let mut neigh6 = if iface.has_ipv6() {
        discover::neighbors6(iface.index)
    } else {
        Vec::new()
    };
    // A host can reply before the kernel has its MAC; make the kernel ask.
    let known: HashSet<IpAddr> = neigh6.iter().map(|n| n.ip).collect();
    let unresolved: Vec<Ipv6Addr> = replies6
        .iter()
        .map(|r| r.ip)
        .filter(|a| !known.contains(&IpAddr::V6(*a)))
        .collect();
    if !unresolved.is_empty() {
        discover::nudge6(&unresolved, iface.index);
        neigh6 = discover::neighbors6(iface.index);
    }
    let mut obs = observations(seen, &replies6, &neigh6);
    let mut own_v6: Vec<Ipv6Addr> = iface.ipv6.iter().map(|(a, _)| *a).collect();
    discover::sort_v6(&mut own_v6);
    let me = Obs {
        mac: iface.mac,
        v4: Some(iface.ip),
        v6: own_v6,
        rtt: None,
        router: false,
    };
    // Our own MAC can't be a neighbor; drop it if it somehow is.
    obs.retain(|o| iface.mac.is_none() || o.mac != iface.mac);

    let now = Instant::now();
    let mut s = lock(state);
    let first_scan = s.scans == 0;
    for d in s.devices.values_mut() {
        d.online = false;
    }
    let mut index = ip_index(&s.devices);
    let observed = obs
        .into_iter()
        .map(|o| (o, false))
        .chain(std::iter::once((me, true)));
    for (o, is_self) in observed {
        let d = upsert(&mut s.devices, &mut index, &o, now, !first_scan);
        d.online = true;
        d.last_seen = now;
        d.mac = o.mac.or(d.mac);
        if let Some(v4) = o.v4 {
            if d.ipv4.is_none() && d.name.is_none() {
                // A new address may have a name the old one didn't.
                d.name_tried = false;
            }
            d.ipv4 = Some(v4);
        }
        if !o.v6.is_empty() {
            d.ipv6 = o.v6;
        }
        if o.rtt.is_some() {
            d.rtt = o.rtt;
        }
        d.is_self = is_self;
        d.is_gateway = o.router || (iface.gateway.is_some() && d.ipv4 == iface.gateway);
        if d.vendor.is_none() {
            d.vendor = d.mac.as_ref().and_then(|m| vendors.lookup(m));
        }
        if d.is_self && d.name.is_none() {
            d.name = hostname();
            d.name_tried = true;
        }
        for ip in d.ips() {
            index.insert(ip, d.key);
        }
    }
    forget_old(&mut s.devices, now);
    s.ipv6_error = ipv6_error;
    s.devices_v6 = s
        .devices
        .values()
        .filter(|d| d.online && !d.ipv6.is_empty())
        .count();
    s.method = Some(method);
    s.error = (!errors.is_empty() && method != Method::Arp).then(|| errors.join("; "));
    s.scanning = None;
    s.last_scan = Some(now);
    s.scans += 1;

    let index = iface.index;
    let pending: Vec<(DevKey, Vec<(IpAddr, u32)>)> = s
        .devices
        .values_mut()
        .filter(|d| !d.name_tried)
        .map(|d| {
            d.name_tried = true;
            let ips = d
                .ips()
                .map(|ip| match ip {
                    IpAddr::V6(a) => (ip, discover::scope_for(&a, index)),
                    IpAddr::V4(_) => (ip, 0),
                })
                .collect();
            (d.key, ips)
        })
        .collect();
    drop(s);
    resolve_names(state, pending);
}

/// What one scan saw of one device.
#[derive(Debug, Default)]
struct Obs {
    mac: Option<Mac>,
    v4: Option<Ipv4Addr>,
    v6: Vec<Ipv6Addr>,
    rtt: Option<Duration>,
    router: bool,
}

/// Joins the IPv4 results, IPv6 echo replies and IPv6 neighbor entries into
/// one observation per device, matching addresses up by MAC.
fn observations(
    seen4: BTreeMap<Ipv4Addr, (Option<Mac>, Option<Duration>)>,
    replies6: &[Reply6],
    neigh6: &[Neighbor],
) -> Vec<Obs> {
    let mut by_mac: BTreeMap<Mac, Obs> = BTreeMap::new();
    let mut loose = Vec::new();
    for (ip, (mac, rtt)) in seen4 {
        let o = Obs {
            mac,
            v4: Some(ip),
            rtt,
            ..Obs::default()
        };
        match mac {
            Some(m) => {
                by_mac.insert(m, o);
            }
            None => loose.push(o),
        }
    }
    let new_mac = |m: Mac| Obs {
        mac: Some(m),
        ..Obs::default()
    };
    let mac6: HashMap<Ipv6Addr, &Neighbor> = neigh6
        .iter()
        .filter_map(|n| match n.ip {
            IpAddr::V6(a) => Some((a, n)),
            IpAddr::V4(_) => None,
        })
        .collect();
    for r in replies6 {
        match mac6.get(&r.ip) {
            Some(n) => {
                let o = by_mac.entry(n.mac).or_insert_with(|| new_mac(n.mac));
                o.v6.push(r.ip);
                // Prefer the IPv4 round trip: it is what the other rows show.
                o.rtt = o.rtt.or(Some(r.rtt));
                o.router |= n.router;
            }
            // Still unresolved, but an EUI-64 address names its MAC.
            None => match discover::eui64_mac(&r.ip).and_then(|m| by_mac.get_mut(&m)) {
                Some(o) => {
                    o.v6.push(r.ip);
                    o.rtt = o.rtt.or(Some(r.rtt));
                }
                None => loose.push(Obs {
                    v6: vec![r.ip],
                    rtt: Some(r.rtt),
                    ..Obs::default()
                }),
            },
        }
    }
    // Other neighbor entries add addresses to devices seen in this scan. On
    // their own they count only when the kernel confirmed them recently, since
    // a stale entry may be for a device that has left.
    let replied: HashSet<Ipv6Addr> = replies6.iter().map(|r| r.ip).collect();
    for (ip, n) in &mac6 {
        if replied.contains(ip) {
            continue;
        }
        let fresh = n.state & NUD_REACHABLE != 0;
        let o = match by_mac.get_mut(&n.mac) {
            Some(o) => o,
            None if fresh => by_mac.entry(n.mac).or_insert_with(|| new_mac(n.mac)),
            None => continue,
        };
        o.v6.push(*ip);
        o.router |= n.router;
    }
    by_mac
        .into_values()
        .chain(loose)
        .map(|mut o| {
            discover::sort_v6(&mut o.v6);
            o
        })
        .collect()
}

/// Which device has each address, to find a device by address without
/// going through them all. Entries can go stale as devices change address,
/// so a hit is checked against the device itself.
type IpIndex = HashMap<IpAddr, DevKey>;

fn ip_index(devices: &BTreeMap<DevKey, Device>) -> IpIndex {
    devices
        .values()
        .flat_map(|d| d.ips().map(move |ip| (ip, d.key)))
        .collect()
}

/// The devices that share an address with an observation.
fn overlapping(devices: &BTreeMap<DevKey, Device>, index: &IpIndex, o: &Obs) -> Vec<DevKey> {
    let mut keys: Vec<DevKey> =
        o.v4.map(IpAddr::V4)
            .into_iter()
            .chain(o.v6.iter().map(|a| IpAddr::V6(*a)))
            .filter_map(|ip| index.get(&ip))
            .filter(|k| devices.get(k).is_some_and(|d| d.overlaps(o)))
            .copied()
            .collect();
    keys.dedup();
    keys
}

/// Finds the device an observation belongs to, or adds it. Entries made
/// before the device's MAC was known are folded into the MAC-keyed one.
fn upsert<'a>(
    devices: &'a mut BTreeMap<DevKey, Device>,
    index: &mut IpIndex,
    o: &Obs,
    now: Instant,
    new: bool,
) -> &'a mut Device {
    let key = match o.mac {
        Some(m) => {
            let key = DevKey::Mac(m);
            let orphans: Vec<DevKey> = overlapping(devices, index, o)
                .into_iter()
                .filter(|k| devices[k].mac.is_none())
                .collect();
            for k in orphans {
                if let Some(mut d) = devices.remove(&k)
                    && !devices.contains_key(&key)
                {
                    d.key = key;
                    for ip in d.ips() {
                        index.insert(ip, key);
                    }
                    devices.insert(key, d);
                }
            }
            key
        }
        None => overlapping(devices, index, o)
            .first()
            .copied()
            .or(o.v4.map(DevKey::V4))
            .or(o.v6.first().map(|a| DevKey::V6(*a)))
            .expect("an observation has an address"),
    };
    devices.entry(key).or_insert_with(|| {
        let mut d = Device::new(key, now, new);
        d.ipv4 = o.v4;
        d.ipv6 = o.v6.clone();
        d
    })
}

/// Forgets devices offline for a day, then the ones offline longest while
/// there are more than MAX_DEVICES.
fn forget_old(devices: &mut BTreeMap<DevKey, Device>, now: Instant) {
    devices.retain(|_, d| d.online || now.duration_since(d.last_seen) < FORGET_AFTER);
    if devices.len() > MAX_DEVICES {
        let mut offline: Vec<(Instant, DevKey)> = devices
            .values()
            .filter(|d| !d.online && !d.is_self)
            .map(|d| (d.last_seen, d.key))
            .collect();
        offline.sort();
        for (_, k) in offline.into_iter().take(devices.len() - MAX_DEVICES) {
            devices.remove(&k);
        }
    }
}

/// Reverse lookups on a few worker threads, since a lookup that fails can take
/// seconds while mDNS times out.
fn resolve_names(state: &Arc<Mutex<LanState>>, jobs: Vec<(DevKey, Vec<(IpAddr, u32)>)>) {
    if jobs.is_empty() {
        return;
    }
    let queue = Arc::new(Mutex::new(jobs));
    for _ in 0..NAME_WORKERS {
        let (queue, state) = (Arc::clone(&queue), Arc::clone(state));
        std::thread::spawn(move || {
            loop {
                let Some((key, ips)) = queue.lock().unwrap_or_else(|e| e.into_inner()).pop() else {
                    return;
                };
                // systemd's nss-myhostname answers "_gateway" for the default
                // gateway. That's already shown as a tag, so prefer no name.
                let name = ips.into_iter().find_map(|(ip, scope)| {
                    discover::reverse_lookup(ip, scope).filter(|n| n != "_gateway")
                });
                if let Some(name) = name
                    && let Some(d) = lock(&state).devices.get_mut(&key)
                {
                    d.name = Some(name);
                }
            }
        });
    }
}

/// Runs one scan synchronously and waits a moment for names, for `--scan`.
pub fn scan_blocking() -> LanState {
    let lan = Lan::start();
    lan.scan_now();
    let start = Instant::now();
    // Wait for the scan to finish, then give name lookups up to 4 more seconds.
    loop {
        std::thread::sleep(Duration::from_millis(100));
        let s = lan.snapshot();
        if s.error.is_some() && s.iface.is_none() {
            return s;
        }
        if s.scans > 0 {
            break;
        }
        if start.elapsed() > Duration::from_secs(60) {
            return s;
        }
    }
    let done = Instant::now();
    while done.elapsed() < Duration::from_secs(4) {
        std::thread::sleep(Duration::from_millis(200));
        if lan.snapshot().devices.values().all(|d| d.name.is_some()) {
            break;
        }
    }
    lan.snapshot()
}

#[cfg(test)]
pub(crate) fn test_device(
    ip: Ipv4Addr,
    mac: Option<Mac>,
    name: Option<&str>,
    vendor: Option<&str>,
) -> Device {
    let key = mac.map_or(DevKey::V4(ip), DevKey::Mac);
    let mut d = Device::new(key, Instant::now(), false);
    d.ipv4 = Some(ip);
    d.mac = mac;
    d.name = name.map(Into::into);
    d.vendor = vendor.map(Into::into);
    d.rtt = Some(Duration::from_micros(
        800 + u32::from(ip).wrapping_mul(2654435761) as u64 % 9000,
    ));
    d.name_tried = true;
    d
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::netlink::NUD_VALID;

    const PS5: Mac = [0xc8, 0x4a, 0xa0, 0xaa, 0xbb, 0x03];
    const PHONE: Mac = [0xd6, 0xfa, 0xc4, 0xaa, 0xbb, 0x04];
    const GONE: Mac = [0xa4, 0x83, 0xe7, 0, 0, 1];
    const WIN: Mac = [0x00, 0x15, 0x5d, 1, 2, 3];

    fn v6(s: &str) -> Ipv6Addr {
        s.parse().unwrap()
    }

    fn neigh(ip: &str, mac: Mac, state: u16) -> Neighbor {
        Neighbor {
            ip: IpAddr::V6(v6(ip)),
            mac,
            ifindex: 2,
            state,
            router: false,
        }
    }

    #[test]
    fn joins_ipv4_and_ipv6_by_mac() {
        let ms = Duration::from_millis;
        let mut seen4 = BTreeMap::new();
        seen4.insert(Ipv4Addr::new(192, 168, 0, 226), (Some(PS5), Some(ms(1))));
        seen4.insert(Ipv4Addr::new(192, 168, 0, 50), (Some(WIN), Some(ms(2))));
        let replies = [
            Reply6 {
                ip: v6("fe80::ca4a:a0ff:feaa:bb03"),
                rtt: ms(3),
            },
            Reply6 {
                ip: v6("2001:db8:322e:0:ccb3:1923:75a6:cc01"),
                rtt: ms(3),
            },
            Reply6 {
                ip: v6("2001:db8:322e:0:bfc8:33ea:21a4:2d75"),
                rtt: ms(4),
            },
            // No neighbor entry: stays a device of its own...
            Reply6 {
                ip: v6("fe80::99"),
                rtt: ms(5),
            },
            // ...unless it's EUI-64 for a MAC seen this scan.
            Reply6 {
                ip: v6("2001:db8::ca4a:a0ff:feaa:bb03"),
                rtt: ms(5),
            },
        ];
        let stale = 0x04;
        let neigh6 = [
            neigh("fe80::ca4a:a0ff:feaa:bb03", PS5, stale),
            neigh("2001:db8:322e:0:ccb3:1923:75a6:cc01", PS5, stale),
            neigh("2001:db8:322e:0:bfc8:33ea:21a4:2d75", PHONE, stale),
            // Windows ignores multicast ping, but its entry joins its IPv4 device.
            neigh("fe80::1234", WIN, stale),
            // A stale entry for a device not seen this scan is ignored...
            neigh("fe80::dead", GONE, stale),
            // ...but a fresh one is a device.
            neigh("fe80::beef", [2, 0, 0, 0, 0, 9], NUD_REACHABLE),
        ];
        assert!(NUD_VALID & stale != 0);
        let obs = observations(seen4, &replies, &neigh6);
        let by = |m: Mac| obs.iter().find(|o| o.mac == Some(m));

        let ps5 = by(PS5).unwrap();
        assert_eq!(ps5.v4, Some(Ipv4Addr::new(192, 168, 0, 226)));
        // Global first, and the IPv4 round trip is kept.
        assert_eq!(
            ps5.v6,
            [
                v6("2001:db8::ca4a:a0ff:feaa:bb03"),
                v6("2001:db8:322e:0:ccb3:1923:75a6:cc01"),
                v6("fe80::ca4a:a0ff:feaa:bb03")
            ]
        );
        assert_eq!(ps5.rtt, Some(ms(1)));

        let phone = by(PHONE).unwrap();
        assert_eq!((phone.v4, phone.rtt), (None, Some(ms(4))));
        assert_eq!(by(WIN).unwrap().v6, [v6("fe80::1234")]);
        assert!(by(GONE).is_none());
        assert!(by([2, 0, 0, 0, 0, 9]).is_some());
        assert!(
            obs.iter()
                .any(|o| o.mac.is_none() && o.v6 == [v6("fe80::99")])
        );
        // PS5, Windows, phone, the fresh entry, and fe80::99.
        assert_eq!(obs.len(), 5);
    }

    #[test]
    fn mac_less_entry_is_folded_into_mac_entry() {
        let now = Instant::now();
        let mut devices = BTreeMap::new();
        let ip = Ipv4Addr::new(192, 168, 0, 9);
        let first = Obs {
            v4: Some(ip),
            ..Obs::default()
        };
        let mut index = IpIndex::new();
        upsert(&mut devices, &mut index, &first, now, false).name = Some("printer".into());
        index = ip_index(&devices);
        assert!(devices.contains_key(&DevKey::V4(ip)));

        let second = Obs {
            v4: Some(ip),
            mac: Some(PS5),
            ..Obs::default()
        };
        let d = upsert(&mut devices, &mut index, &second, now, false);
        assert_eq!(d.key, DevKey::Mac(PS5));
        assert_eq!(d.name.as_deref(), Some("printer"));
        assert_eq!(devices.len(), 1);

        // Seen again without a MAC (e.g. a ping reply): same device.
        let third = Obs {
            v4: Some(ip),
            ..Obs::default()
        };
        assert_eq!(
            upsert(&mut devices, &mut index, &third, now, false).key,
            DevKey::Mac(PS5)
        );
        assert_eq!(devices.len(), 1);
    }

    #[test]
    fn forgets_devices_offline_for_long() {
        let now = Instant::now() + 2 * FORGET_AFTER;
        let mut devices = BTreeMap::new();
        for i in 0..(MAX_DEVICES + 10) as u32 {
            let ip = Ipv4Addr::from(0x0a00_0000 + i);
            let mut d = Device::new(DevKey::V4(ip), now, false);
            d.ipv4 = Some(ip);
            // The first ten are online; the rest went offline one by one.
            d.online = i < 10;
            d.last_seen = now - Duration::from_secs(u64::from(i));
            devices.insert(d.key, d);
        }
        let mut gone = Device::new(DevKey::V4(Ipv4Addr::new(10, 9, 9, 9)), now, false);
        gone.online = false;
        gone.last_seen = now - FORGET_AFTER - Duration::from_secs(1);
        devices.insert(gone.key, gone);

        forget_old(&mut devices, now);
        assert_eq!(devices.len(), MAX_DEVICES);
        assert!(!devices.contains_key(&DevKey::V4(Ipv4Addr::new(10, 9, 9, 9))));
        // Online devices stay; the ones offline longest went first.
        assert!(devices.values().filter(|d| d.online).count() == 10);
        let last = Ipv4Addr::from(0x0a00_0000 + (MAX_DEVICES + 9) as u32);
        assert!(!devices.contains_key(&DevKey::V4(last)));
    }

    #[test]
    fn device_addresses() {
        let mut d = test_device(Ipv4Addr::new(192, 168, 0, 5), Some(PS5), None, None);
        d.ipv6 = vec![v6("2001:db8::5")];
        assert!(d.has_ip("::ffff:192.168.0.5".parse().unwrap()));
        assert!(d.has_ip("2001:db8::5".parse().unwrap()));
        assert!(!d.has_ip("2001:db8::6".parse().unwrap()));
        assert_eq!(d.primary_ip(), Some("192.168.0.5".parse().unwrap()));
    }
}
