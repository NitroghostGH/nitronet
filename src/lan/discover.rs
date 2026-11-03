//! Finding devices on the local subnet, using libc only:
//!   * root: raw ARP requests on an AF_PACKET socket (what `arp-scan` does).
//!     This finds every device, including ones that block ping, and gets MACs
//!     and response times directly.
//!   * otherwise: an ICMP ping sweep over an unprivileged ping socket (or UDP
//!     packets to the discard port if ping sockets aren't allowed). Either way
//!     the kernel ARP-resolves every address, and the MACs are then read from
//!     the neighbor table.
//!
//! IPv6 subnets are far too big to sweep, so IPv6 hosts are found by pinging
//! the all-nodes multicast group (ff02::1), which every IPv6 host joins. That
//! runs once from our link-local address and once from each global one, since
//! hosts answer from an address in the same scope. The neighbor table then
//! maps each responding address to a MAC.

use std::collections::{HashMap, HashSet};
use std::ffi::CString;
use std::fs;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::time::{Duration, Instant};

pub type Mac = [u8; 6];

#[derive(Clone, Debug)]
pub struct Iface {
    pub name: String,
    pub index: u32,
    pub ip: Ipv4Addr,
    pub prefix: u8,
    pub mac: Option<Mac>,
    pub gateway: Option<Ipv4Addr>,
    /// Our IPv6 addresses on this interface, with prefix lengths.
    pub ipv6: Vec<(Ipv6Addr, u8)>,
    /// The addresses to scan: the subnet's hosts, capped at a /22. On a larger
    /// subnet only the /24 around our address is scanned (and `truncated` is set).
    pub first: Ipv4Addr,
    pub count: u32,
    pub truncated: bool,
}

impl Iface {
    pub fn targets(&self) -> impl Iterator<Item = Ipv4Addr> + '_ {
        let start = u32::from(self.first);
        (start..start + self.count)
            .map(Ipv4Addr::from)
            .filter(move |&ip| ip != self.ip)
    }

    /// The scanned range in CIDR form, e.g. "192.168.0.0/24".
    pub fn range(&self) -> String {
        let (net, prefix) = if self.truncated {
            (u32::from(self.ip) & 0xffff_ff00, 24)
        } else {
            (u32::from(self.ip) & mask(self.prefix), self.prefix)
        };
        format!("{}/{prefix}", Ipv4Addr::from(net))
    }

    /// The first routable IPv6 prefix, e.g. "2001:db8:322e::/64".
    pub fn range6(&self) -> Option<String> {
        let (ip, prefix) = self
            .ipv6
            .iter()
            .filter(|(a, _)| v6_rank(a) < 2)
            .min_by_key(|(a, _)| v6_rank(a))?;
        let bits = u128::from(*ip);
        let net = if *prefix == 0 {
            0
        } else {
            bits & (u128::MAX << (128 - *prefix as u32))
        };
        Some(format!("{}/{prefix}", Ipv6Addr::from(net)))
    }

    pub fn has_ipv6(&self) -> bool {
        !self.ipv6.is_empty()
    }
}

/// Display order for a host's IPv6 addresses: global, then unique local
/// (fc00::/7), then link-local (fe80::/10), then anything else.
pub fn v6_rank(a: &Ipv6Addr) -> u8 {
    if a.is_unicast_link_local() {
        2
    } else if a.is_unique_local() {
        1
    } else if a.segments()[0] & 0xe000 == 0x2000 {
        0
    } else {
        3
    }
}

/// Sorts and dedups addresses in display order.
pub fn sort_v6(addrs: &mut Vec<Ipv6Addr>) {
    addrs.sort_by_key(|a| (v6_rank(a), *a));
    addrs.dedup();
}

fn mask(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix as u32)
    }
}

/// The interface the default route uses, falling back to the first interface
/// that is up, not loopback, and has an IPv4 address.
pub fn find_iface() -> io::Result<Iface> {
    let (route_if, gateway) = default_route().unzip();
    let all = if_addrs()?;
    let v4: Vec<(String, Ipv4Addr, u8)> = all
        .iter()
        .filter_map(|(n, ip, p)| match ip {
            IpAddr::V4(ip) => Some((n.clone(), *ip, *p)),
            IpAddr::V6(_) => None,
        })
        .collect();
    let (name, ip, prefix) = route_if
        .and_then(|r| v4.iter().find(|a| a.0 == r).cloned())
        .or_else(|| v4.first().cloned())
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                "no network interface with an IPv4 address",
            )
        })?;

    let cname = CString::new(name.clone()).map_err(io::Error::other)?;
    // SAFETY: cname is a valid NUL-terminated string.
    let index = unsafe { libc::if_nametoindex(cname.as_ptr()) };
    let mac = fs::read_to_string(format!("/sys/class/net/{name}/address"))
        .ok()
        .and_then(|s| parse_mac(s.trim()));

    let (net, bcast) = (u32::from(ip) & mask(prefix), u32::from(ip) | !mask(prefix));
    let (first, count, truncated) = if prefix >= 31 {
        (ip, 0, false)
    } else if prefix >= 22 {
        (Ipv4Addr::from(net + 1), bcast - net - 1, false)
    } else {
        (Ipv4Addr::from((u32::from(ip) & 0xffff_ff00) + 1), 254, true)
    };
    let ipv6 = all
        .iter()
        .filter(|(n, _, _)| *n == name)
        .filter_map(|(_, ip, p)| match ip {
            IpAddr::V6(ip) => Some((*ip, *p)),
            IpAddr::V4(_) => None,
        })
        .collect();
    Ok(Iface {
        name,
        index,
        ip,
        prefix,
        mac,
        gateway: gateway.flatten(),
        ipv6,
        first,
        count,
        truncated,
    })
}

/// (interface, gateway) of the IPv4 default route, from /proc/net/route.
fn default_route() -> Option<(String, Option<Ipv4Addr>)> {
    let s = fs::read_to_string("/proc/net/route").ok()?;
    for line in s.lines().skip(1) {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 8 || f[1] != "00000000" || f[7] != "00000000" {
            continue;
        }
        // The kernel prints the network-order address as a native-endian u32.
        let gw = u32::from_str_radix(f[2], 16)
            .ok()
            .map(|v| Ipv4Addr::from(v.to_ne_bytes()));
        return Some((f[0].to_string(), gw.filter(|g| !g.is_unspecified())));
    }
    None
}

/// (interface, address, prefix length) for every IPv4 and IPv6 address on an
/// interface that is up and not loopback.
fn if_addrs() -> io::Result<Vec<(String, IpAddr, u8)>> {
    let mut head: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: getifaddrs fills `head` with a list that we free below.
    if unsafe { libc::getifaddrs(&mut head) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let mut out = Vec::new();
    let mut cur = head;
    while !cur.is_null() {
        // SAFETY: cur is a node of the list returned by getifaddrs.
        let ifa = unsafe { &*cur };
        cur = ifa.ifa_next;
        let flags = ifa.ifa_flags as libc::c_int;
        if ifa.ifa_addr.is_null()
            || ifa.ifa_netmask.is_null()
            || flags & libc::IFF_UP == 0
            || flags & libc::IFF_LOOPBACK != 0
        {
            continue;
        }
        // SAFETY: ifa_name is a valid C string for the list's lifetime.
        let name = || {
            unsafe { std::ffi::CStr::from_ptr(ifa.ifa_name) }
                .to_string_lossy()
                .into_owned()
        };
        // SAFETY: ifa_addr is non-null; sa_family tells us the concrete type.
        match unsafe { (*ifa.ifa_addr).sa_family } as libc::c_int {
            libc::AF_INET => {
                // SAFETY: both are AF_INET sockaddrs, so sockaddr_in is the right type.
                let (addr, netmask) = unsafe {
                    (
                        *(ifa.ifa_addr as *const libc::sockaddr_in),
                        *(ifa.ifa_netmask as *const libc::sockaddr_in),
                    )
                };
                let ip = Ipv4Addr::from(addr.sin_addr.s_addr.to_ne_bytes());
                let prefix = u32::from_be(netmask.sin_addr.s_addr).count_ones() as u8;
                out.push((name(), IpAddr::V4(ip), prefix));
            }
            libc::AF_INET6 => {
                // SAFETY: both are AF_INET6 sockaddrs, so sockaddr_in6 is the right type.
                let (addr, netmask) = unsafe {
                    (
                        *(ifa.ifa_addr as *const libc::sockaddr_in6),
                        *(ifa.ifa_netmask as *const libc::sockaddr_in6),
                    )
                };
                let ip = Ipv6Addr::from(addr.sin6_addr.s6_addr);
                let prefix = u128::from_be_bytes(netmask.sin6_addr.s6_addr).count_ones() as u8;
                out.push((name(), IpAddr::V6(ip), prefix));
            }
            _ => {}
        }
    }
    // SAFETY: head came from getifaddrs and is freed exactly once.
    unsafe { libc::freeifaddrs(head) };
    Ok(out)
}

pub fn parse_mac(s: &str) -> Option<Mac> {
    let mut mac = [0u8; 6];
    let mut parts = s.split(':');
    for b in mac.iter_mut() {
        *b = u8::from_str_radix(parts.next()?, 16).ok()?;
    }
    parts.next().is_none().then_some(mac)
}

pub fn fmt_mac(m: &Mac) -> String {
    m.iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

/// One device that answered during a sweep.
#[derive(Clone, Debug)]
pub struct Reply {
    pub ip: Ipv4Addr,
    pub mac: Option<Mac>,
    pub rtt: Option<Duration>,
}

/// How long to keep listening after the last request.
const LINGER: Duration = Duration::from_millis(1500);
/// How long to listen between retry passes.
const RETRY_GAP: Duration = Duration::from_millis(500);
/// Passes for an ARP sweep. Each retry only re-asks the silent addresses.
const ARP_ROUNDS: usize = 3;
const PING_ROUNDS: usize = 2;
/// Pause between requests, so a /22 sweep takes about a second instead of
/// bursting 1000 packets at once.
const PACE: Duration = Duration::from_micros(800);

fn fd_from(r: libc::c_int) -> io::Result<OwnedFd> {
    if r < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: r is a fresh descriptor that we now own.
    Ok(unsafe { OwnedFd::from_raw_fd(r) })
}

/// Waits up to `timeout` for the socket to become readable.
fn readable(fd: &OwnedFd, timeout: Duration) -> bool {
    let mut p = libc::pollfd {
        fd: fd.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: p is a single valid pollfd.
    unsafe { libc::poll(&mut p, 1, timeout.as_millis().min(i32::MAX as u128) as i32) > 0 }
}

/// Sends a request to each target with `send` and collects replies with
/// `recv` (which returns Ok(None) when nothing is pending). It makes `rounds`
/// passes, and each pass after the first only re-asks targets that haven't
/// answered: Wi-Fi devices in power save often sleep through a single
/// broadcast. After each pass it keeps listening for a while. `progress` gets
/// (requests sent, planned total).
fn sweep(
    targets: &[Ipv4Addr],
    rounds: usize,
    fd: &OwnedFd,
    mut send: impl FnMut(usize, usize, Ipv4Addr) -> io::Result<()>,
    mut recv: impl FnMut() -> io::Result<Option<(Ipv4Addr, Option<Mac>)>>,
    progress: &dyn Fn(usize, usize),
) -> io::Result<Vec<Reply>> {
    let mut sent_at: HashMap<Ipv4Addr, Instant> = HashMap::new();
    let mut got: HashMap<Ipv4Addr, Reply> = HashMap::new();
    let mut drain = |sent_at: &HashMap<Ipv4Addr, Instant>,
                     got: &mut HashMap<Ipv4Addr, Reply>|
     -> io::Result<()> {
        while let Some((ip, mac)) = recv()? {
            let rtt = sent_at.get(&ip).map(|t| t.elapsed());
            got.entry(ip).or_insert(Reply { ip, mac, rtt });
        }
        Ok(())
    };
    let total = targets.len() * rounds;
    let mut sent = 0;
    for round in 0..rounds {
        let pending: Vec<Ipv4Addr> = targets
            .iter()
            .copied()
            .filter(|ip| !got.contains_key(ip))
            .collect();
        for &ip in &pending {
            sent_at.insert(ip, Instant::now());
            // A send can fail for one address (e.g. EHOSTUNREACH); keep going.
            let _ = send(round, sent, ip);
            drain(&sent_at, &mut got)?;
            sent += 1;
            if sent % 16 == 0 {
                progress(round * targets.len() + sent.min(targets.len()), total);
            }
            std::thread::sleep(PACE);
        }
        progress((round + 1) * targets.len(), total);
        let linger = if round + 1 == rounds {
            LINGER
        } else {
            RETRY_GAP
        };
        let end = Instant::now() + linger;
        while let Some(left) = end.checked_duration_since(Instant::now()) {
            if readable(fd, left) {
                drain(&sent_at, &mut got)?;
            }
        }
        sent = 0;
    }
    Ok(got.into_values().collect())
}

/// ARP sweep over a raw packet socket. It needs CAP_NET_RAW (root).
pub fn arp_sweep(
    iface: &Iface,
    targets: &[Ipv4Addr],
    progress: &dyn Fn(usize, usize),
) -> io::Result<Vec<Reply>> {
    const ETH_P_ARP: u16 = 0x0806;
    let my_mac = iface
        .mac
        .ok_or_else(|| io::Error::other("interface has no MAC address"))?;
    // SAFETY: plain syscall; the result is checked.
    let fd = fd_from(unsafe {
        libc::socket(
            libc::AF_PACKET,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
            ETH_P_ARP.to_be() as libc::c_int,
        )
    })?;
    // SAFETY: sockaddr_ll is plain data, and all zeroes is valid.
    let mut ll: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
    ll.sll_family = libc::AF_PACKET as u16;
    ll.sll_protocol = ETH_P_ARP.to_be();
    ll.sll_ifindex = iface.index as i32;
    ll.sll_halen = 6;
    ll.sll_addr[..6].copy_from_slice(&[0xff; 6]);
    let ll_len = size_of::<libc::sockaddr_ll>() as libc::socklen_t;
    // SAFETY: ll is a valid sockaddr_ll of the stated length.
    if unsafe { libc::bind(fd.as_raw_fd(), (&raw const ll).cast(), ll_len) } < 0 {
        return Err(io::Error::last_os_error());
    }

    // Ethernet header + ARP request, with the target address filled in per send.
    let mut frame = [0u8; 42];
    frame[0..6].copy_from_slice(&[0xff; 6]);
    frame[6..12].copy_from_slice(&my_mac);
    frame[12..14].copy_from_slice(&ETH_P_ARP.to_be_bytes());
    frame[14..22].copy_from_slice(&[0, 1, 8, 0, 6, 4, 0, 1]); // ethernet, IPv4, request
    frame[22..28].copy_from_slice(&my_mac);
    frame[28..32].copy_from_slice(&iface.ip.octets());

    let known: HashMap<Ipv4Addr, Mac> = neighbors4(iface.index, true).into_iter().collect();
    let raw = fd.as_raw_fd();
    let mut buf = [0u8; 128];
    sweep(
        targets,
        ARP_ROUNDS,
        &fd,
        |round, _, ip| {
            // Broadcast first. On retries, send directly to a MAC the kernel
            // already knows: sleeping Wi-Fi clients often ignore broadcast ARP
            // but answer unicast, which the access point buffers for them.
            let dst = match known.get(&ip) {
                Some(mac) if round > 0 => *mac,
                _ => [0xff; 6],
            };
            frame[0..6].copy_from_slice(&dst);
            frame[38..42].copy_from_slice(&ip.octets());
            // SAFETY: frame and ll are valid for the stated lengths.
            let r = unsafe {
                libc::sendto(
                    raw,
                    frame.as_ptr().cast(),
                    frame.len(),
                    0,
                    (&raw const ll).cast(),
                    ll_len,
                )
            };
            if r < 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok(())
            }
        },
        || loop {
            // SAFETY: buf is valid for writes of buf.len() bytes.
            let n = unsafe { libc::recv(raw, buf.as_mut_ptr().cast(), buf.len(), 0) };
            if n < 0 {
                let e = io::Error::last_os_error();
                return if e.kind() == io::ErrorKind::WouldBlock {
                    Ok(None)
                } else {
                    Err(e)
                };
            }
            let f = &buf[..n as usize];
            // Only ARP replies (op 2). Our own requests are seen here too.
            if f.len() >= 42 && f[12..14] == ETH_P_ARP.to_be_bytes() && f[20..22] == [0, 2] {
                let mac: Mac = f[22..28].try_into().unwrap();
                let ip = Ipv4Addr::new(f[28], f[29], f[30], f[31]);
                return Ok(Some((ip, Some(mac))));
            }
        },
        progress,
    )
}

/// Ping sweep over an unprivileged ICMP socket. Replies give round-trip
/// times, and the kernel ARP-resolves every target while sending.
pub fn ping_sweep(targets: &[Ipv4Addr], progress: &dyn Fn(usize, usize)) -> io::Result<Vec<Reply>> {
    // SAFETY: plain syscall; the result is checked.
    let fd = fd_from(unsafe {
        libc::socket(
            libc::AF_INET,
            libc::SOCK_DGRAM | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
            libc::IPPROTO_ICMP,
        )
    })?;
    let raw = fd.as_raw_fd();
    let mut buf = [0u8; 256];
    sweep(
        targets,
        PING_ROUNDS,
        &fd,
        |_, seq, ip| {
            // Echo request; the kernel fills in the identifier and checksum for ping sockets.
            let mut pkt = [0u8; 16];
            pkt[0] = 8;
            pkt[6..8].copy_from_slice(&(seq as u16).to_be_bytes());
            pkt[8..16].copy_from_slice(b"nitronet");
            let sa = sockaddr_in(ip, 0);
            // SAFETY: pkt and sa are valid for the stated lengths.
            let r = unsafe {
                libc::sendto(
                    raw,
                    pkt.as_ptr().cast(),
                    pkt.len(),
                    0,
                    (&raw const sa).cast(),
                    size_of::<libc::sockaddr_in>() as libc::socklen_t,
                )
            };
            if r < 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok(())
            }
        },
        || loop {
            // SAFETY: zeroed sockaddr_in is valid; buf and from are valid for writes.
            let mut from: libc::sockaddr_in = unsafe { std::mem::zeroed() };
            let mut len = size_of::<libc::sockaddr_in>() as libc::socklen_t;
            let n = unsafe {
                libc::recvfrom(
                    raw,
                    buf.as_mut_ptr().cast(),
                    buf.len(),
                    0,
                    (&raw mut from).cast(),
                    &mut len,
                )
            };
            if n < 0 {
                let e = io::Error::last_os_error();
                return if e.kind() == io::ErrorKind::WouldBlock {
                    Ok(None)
                } else {
                    Err(e)
                };
            }
            if n >= 1 && buf[0] == 0 {
                // echo reply
                return Ok(Some((
                    Ipv4Addr::from(from.sin_addr.s_addr.to_ne_bytes()),
                    None,
                )));
            }
        },
        progress,
    )
}

/// The fallback when ping sockets aren't allowed: a UDP packet to the discard
/// port of each address still makes the kernel ARP-resolve it.
pub fn udp_nudge(targets: &[Ipv4Addr], progress: &dyn Fn(usize, usize)) -> io::Result<()> {
    let sock = std::net::UdpSocket::bind("0.0.0.0:0")?;
    let n = targets.len();
    for (i, ip) in targets.iter().enumerate() {
        let _ = sock.send_to(&[], (*ip, 9));
        if i % 16 == 0 {
            progress(i + 1, n);
        }
        std::thread::sleep(PACE);
    }
    progress(n, n);
    std::thread::sleep(LINGER);
    Ok(())
}

fn sockaddr_in(ip: Ipv4Addr, port: u16) -> libc::sockaddr_in {
    libc::sockaddr_in {
        sin_family: libc::AF_INET as libc::sa_family_t,
        sin_port: port.to_be(),
        sin_addr: libc::in_addr {
            s_addr: u32::from_ne_bytes(ip.octets()),
        },
        sin_zero: [0; 8],
    }
}

/// Usable entries for interface `index` in the kernel's ARP table.
pub fn arp_table(index: u32) -> Vec<(Ipv4Addr, Mac)> {
    neighbors4(index, false)
}

/// IPv4 neighbor entries with a MAC. With `any_state`, this also includes
/// entries the kernel has stopped trusting, which are still useful as unicast
/// ARP targets.
fn neighbors4(index: u32, any_state: bool) -> Vec<(Ipv4Addr, Mac)> {
    crate::netlink::neighbors(libc::AF_INET)
        .unwrap_or_default()
        .into_iter()
        .filter(|n| n.ifindex == index && (any_state || n.state & crate::netlink::NUD_VALID != 0))
        .filter_map(|n| match n.ip {
            IpAddr::V4(ip) => Some((ip, n.mac)),
            IpAddr::V6(_) => None,
        })
        .collect()
}

/// IPv6 neighbor entries on interface `index` that are usable.
pub fn neighbors6(index: u32) -> Vec<crate::netlink::Neighbor> {
    crate::netlink::neighbors(libc::AF_INET6)
        .unwrap_or_default()
        .into_iter()
        .filter(|n| {
            n.ifindex == index && n.state & crate::netlink::NUD_VALID != 0 && n.ip.is_ipv6()
        })
        .collect()
}

// --------------------------------------------------------------------- IPv6

/// The MAC inside an EUI-64 interface identifier (ab:cd:ef:ff:fe:12:34:56 with
/// the universal/local bit flipped), which hosts without privacy addresses use.
pub fn eui64_mac(a: &Ipv6Addr) -> Option<Mac> {
    let o = a.octets();
    if o[11] != 0xff || o[12] != 0xfe {
        return None;
    }
    Some([o[8] ^ 0x02, o[9], o[10], o[13], o[14], o[15]])
}

/// Sends a UDP datagram to each address so the kernel resolves its MAC
/// (neighbor solicitation), then waits briefly for the answers.
pub fn nudge6(addrs: &[Ipv6Addr], index: u32) {
    if addrs.is_empty() {
        return;
    }
    let Ok(sock) = std::net::UdpSocket::bind("[::]:0") else {
        return;
    };
    for a in addrs {
        let to = std::net::SocketAddrV6::new(*a, 9, 0, scope_for(a, index));
        let _ = sock.send_to(&[], to);
    }
    std::thread::sleep(Duration::from_millis(400));
}

/// One IPv6 address that answered the all-nodes ping.
#[derive(Clone, Debug)]
pub struct Reply6 {
    pub ip: Ipv6Addr,
    pub rtt: Duration,
}

const ALL_NODES: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1);
const PING6_ROUNDS: usize = 2;
const ICMP6_ECHO_REQUEST: u8 = 128;
const ICMP6_ECHO_REPLY: u8 = 129;

/// An ICMPv6 echo socket bound to one of our addresses. It is an
/// unprivileged ping socket when allowed, else a raw socket (root).
struct Ping6 {
    fd: OwnedFd,
    /// Raw sockets see every ICMPv6 packet, so replies are matched by identifier.
    raw_id: Option<u16>,
}

fn sockaddr_in6(ip: Ipv6Addr, scope: u32) -> libc::sockaddr_in6 {
    // SAFETY: sockaddr_in6 is plain data, and all zeroes is valid.
    let mut sa: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
    sa.sin6_family = libc::AF_INET6 as libc::sa_family_t;
    sa.sin6_addr.s6_addr = ip.octets();
    sa.sin6_scope_id = scope;
    sa
}

/// The scope id an address needs: the interface for link-local, else none.
pub fn scope_for(ip: &Ipv6Addr, index: u32) -> u32 {
    if ip.is_unicast_link_local() { index } else { 0 }
}

fn setsockopt_int(
    fd: &OwnedFd,
    level: libc::c_int,
    opt: libc::c_int,
    v: libc::c_int,
) -> io::Result<()> {
    // SAFETY: v is a live c_int of the stated size.
    let r = unsafe {
        libc::setsockopt(
            fd.as_raw_fd(),
            level,
            opt,
            (&raw const v).cast(),
            size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if r < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn ping6_socket(index: u32, src: Ipv6Addr) -> io::Result<Ping6> {
    let open = |ty| {
        // SAFETY: plain syscall; the result is checked.
        fd_from(unsafe {
            libc::socket(
                libc::AF_INET6,
                ty | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
                libc::IPPROTO_ICMPV6,
            )
        })
    };
    let (fd, raw_id) = match open(libc::SOCK_DGRAM) {
        Ok(fd) => (fd, None),
        Err(e) => match open(libc::SOCK_RAW) {
            Ok(fd) => (fd, Some(std::process::id() as u16)),
            Err(_) => return Err(e),
        },
    };
    let sa = sockaddr_in6(src, scope_for(&src, index));
    // SAFETY: sa is a valid sockaddr_in6 of the stated length.
    if unsafe {
        libc::bind(
            fd.as_raw_fd(),
            (&raw const sa).cast(),
            size_of::<libc::sockaddr_in6>() as libc::socklen_t,
        )
    } < 0
    {
        return Err(io::Error::last_os_error());
    }
    setsockopt_int(
        &fd,
        libc::IPPROTO_IPV6,
        libc::IPV6_MULTICAST_IF,
        index as libc::c_int,
    )?;
    setsockopt_int(&fd, libc::IPPROTO_IPV6, libc::IPV6_MULTICAST_HOPS, 1)?;
    Ok(Ping6 { fd, raw_id })
}

impl Ping6 {
    fn send(&self, index: u32, seq: u16) -> io::Result<()> {
        // Echo request: type, code, checksum (the kernel fills it in), id, seq, payload.
        let mut pkt = [0u8; 16];
        pkt[0] = ICMP6_ECHO_REQUEST;
        pkt[4..6].copy_from_slice(&self.raw_id.unwrap_or(0).to_be_bytes());
        pkt[6..8].copy_from_slice(&seq.to_be_bytes());
        pkt[8..16].copy_from_slice(b"nitronet");
        let sa = sockaddr_in6(ALL_NODES, index);
        // SAFETY: pkt and sa are valid for the stated lengths.
        let r = unsafe {
            libc::sendto(
                self.fd.as_raw_fd(),
                pkt.as_ptr().cast(),
                pkt.len(),
                0,
                (&raw const sa).cast(),
                size_of::<libc::sockaddr_in6>() as libc::socklen_t,
            )
        };
        if r < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    /// The source of the next pending echo reply, or None when nothing is pending.
    fn recv(&self, buf: &mut [u8]) -> io::Result<Option<Ipv6Addr>> {
        loop {
            // SAFETY: zeroed sockaddr_in6 is valid; buf and from are valid for writes.
            let mut from: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
            let mut len = size_of::<libc::sockaddr_in6>() as libc::socklen_t;
            let n = unsafe {
                libc::recvfrom(
                    self.fd.as_raw_fd(),
                    buf.as_mut_ptr().cast(),
                    buf.len(),
                    0,
                    (&raw mut from).cast(),
                    &mut len,
                )
            };
            if n < 0 {
                let e = io::Error::last_os_error();
                return if e.kind() == io::ErrorKind::WouldBlock {
                    Ok(None)
                } else {
                    Err(e)
                };
            }
            let p = &buf[..n as usize];
            // Both socket kinds deliver the ICMPv6 message without the IPv6 header.
            let ours = match self.raw_id {
                None => true,
                Some(id) => p.len() >= 6 && p[4..6] == id.to_be_bytes(),
            };
            if !p.is_empty() && p[0] == ICMP6_ECHO_REPLY && ours {
                return Ok(Some(Ipv6Addr::from(from.sin6_addr.s6_addr)));
            }
        }
    }
}

/// Pings ff02::1 on the interface from each of our IPv6 addresses, twice,
/// and returns every other address that answered.
pub fn ping6_all_nodes(iface: &Iface) -> io::Result<Vec<Reply6>> {
    let mut socks = Vec::new();
    let mut err = None;
    for (src, _) in &iface.ipv6 {
        match ping6_socket(iface.index, *src) {
            Ok(s) => socks.push(s),
            Err(e) => err = Some(e),
        }
    }
    if socks.is_empty() {
        return Err(err.unwrap_or_else(|| io::Error::other("no IPv6 address on the interface")));
    }
    let mine: HashSet<Ipv6Addr> = iface.ipv6.iter().map(|(a, _)| *a).collect();
    let mut got: HashMap<Ipv6Addr, Duration> = HashMap::new();
    let mut buf = [0u8; 256];
    for round in 0..PING6_ROUNDS {
        let sent = Instant::now();
        for s in &socks {
            let _ = s.send(iface.index, round as u16);
        }
        let end = sent
            + if round + 1 == PING6_ROUNDS {
                LINGER
            } else {
                Duration::from_secs(1)
            };
        while let Some(left) = end.checked_duration_since(Instant::now()) {
            let mut fds: Vec<libc::pollfd> = socks
                .iter()
                .map(|s| libc::pollfd {
                    fd: s.fd.as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                })
                .collect();
            // SAFETY: fds is a live array of fds.len() pollfds.
            let r = unsafe {
                libc::poll(
                    fds.as_mut_ptr(),
                    fds.len() as libc::nfds_t,
                    left.as_millis().min(i32::MAX as u128) as i32,
                )
            };
            if r <= 0 {
                continue;
            }
            for (s, p) in socks.iter().zip(&fds) {
                if p.revents & libc::POLLIN == 0 {
                    continue;
                }
                while let Some(ip) = s.recv(&mut buf)? {
                    if !mine.contains(&ip) {
                        got.entry(ip).or_insert_with(|| sent.elapsed());
                    }
                }
            }
        }
    }
    Ok(got
        .into_iter()
        .map(|(ip, rtt)| Reply6 { ip, rtt })
        .collect())
}

/// The name for an address (reverse DNS, mDNS or LLMNR, as the system's
/// resolver is set up). `scope` is the interface for a link-local IPv6 address.
pub fn reverse_lookup(ip: IpAddr, scope: u32) -> Option<String> {
    let (v4, v6);
    let (sa, len): (*const libc::sockaddr, usize) = match ip {
        IpAddr::V4(ip) => {
            v4 = sockaddr_in(ip, 0);
            ((&raw const v4).cast(), size_of::<libc::sockaddr_in>())
        }
        IpAddr::V6(ip) => {
            v6 = sockaddr_in6(ip, scope);
            ((&raw const v6).cast(), size_of::<libc::sockaddr_in6>())
        }
    };
    let mut host = [0 as libc::c_char; 256];
    // SAFETY: sa and host are valid for the stated lengths. getnameinfo is thread-safe.
    let r = unsafe {
        libc::getnameinfo(
            sa,
            len as libc::socklen_t,
            host.as_mut_ptr(),
            host.len() as libc::socklen_t,
            std::ptr::null_mut(),
            0,
            libc::NI_NAMEREQD,
        )
    };
    if r != 0 {
        return None;
    }
    // SAFETY: on success getnameinfo wrote a NUL-terminated string.
    let name = unsafe { std::ffi::CStr::from_ptr(host.as_ptr()) }.to_string_lossy();
    // Names come from DNS, mDNS or LLMNR answers, which anyone can send.
    let name = crate::text::clean(&name);
    (!name.is_empty() && !restates_address(&name, ip)).then_some(name)
}

/// ISPs give IPv6 addresses generated names like
/// "2001-db8-322e-0-ccb3-1923-75a6-cc01.ip6.example.net", and a resolver may
/// echo a link-local address back. Neither says anything about the device.
fn restates_address(name: &str, ip: IpAddr) -> bool {
    let IpAddr::V6(ip) = ip else { return false };
    let tokens: HashSet<String> = name
        .split(['-', '.', ':', '%'])
        .map(|t| t.trim_start_matches('0').to_lowercase())
        .collect();
    let hits = ip.segments()[4..]
        .iter()
        .filter(|g| **g != 0 && tokens.contains(&format!("{g:x}")))
        .count();
    hits >= 3
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn macs() {
        assert_eq!(
            parse_mac("1c:61:b4:aa:bb:01"),
            Some([0x1c, 0x61, 0xb4, 0xaa, 0xbb, 0x01])
        );
        assert_eq!(parse_mac("1c:61:b4:2a:31"), None);
        assert_eq!(parse_mac("1c:61:b4:aa:bb:01:00"), None);
        assert_eq!(
            fmt_mac(&[0x1c, 0x61, 0xb4, 0xaa, 0xbb, 0x01]),
            "1c:61:b4:aa:bb:01"
        );
    }

    #[test]
    fn ranges() {
        let base = Iface {
            name: "x".into(),
            index: 1,
            ip: Ipv4Addr::new(192, 168, 0, 74),
            prefix: 24,
            mac: None,
            gateway: None,
            ipv6: vec![
                ("fe80::32c5:99ff:feaa:bb02".parse().unwrap(), 64),
                ("2001:db8:322e:0:32c5:99ff:feaa:bb02".parse().unwrap(), 64),
            ],
            first: Ipv4Addr::new(192, 168, 0, 1),
            count: 254,
            truncated: false,
        };
        assert_eq!(base.range(), "192.168.0.0/24");
        assert_eq!(base.targets().count(), 253); // all hosts except ourselves
        assert!(base.targets().all(|ip| ip != base.ip));
        let wide = Iface {
            prefix: 16,
            truncated: true,
            ..base.clone()
        };
        assert_eq!(wide.range(), "192.168.0.0/24");
        assert_eq!(mask(24), 0xffff_ff00);
        assert_eq!(base.range6().as_deref(), Some("2001:db8:322e::/64"));
    }

    #[test]
    fn ipv6_order_and_names() {
        let mut a: Vec<Ipv6Addr> = ["fe80::1", "fd00::5", "2001:db8::1", "fe80::1"]
            .iter()
            .map(|s| s.parse().unwrap())
            .collect();
        sort_v6(&mut a);
        let a: Vec<String> = a.iter().map(|a| a.to_string()).collect();
        assert_eq!(a, ["2001:db8::1", "fd00::5", "fe80::1"]);

        let ip: Ipv6Addr = "2001:db8:322e:0:ccb3:1923:75a6:cc01".parse().unwrap();
        assert_eq!(
            eui64_mac(&"2001:db8:322e:0:1e61:b4ff:feaa:bb01".parse().unwrap()),
            Some([0x1c, 0x61, 0xb4, 0xaa, 0xbb, 0x01])
        );
        assert_eq!(eui64_mac(&ip), None);
        let ip = IpAddr::V6(ip);
        assert!(restates_address(
            "2001-db8-322e-0-ccb3-1923-75a6-cc01.ip6.isp.example",
            ip
        ));
        assert!(!restates_address("PS5-AABB03.local", ip));
        let ll: Ipv6Addr = "fe80::ca4a:a0ff:feaa:bb03".parse().unwrap();
        assert!(restates_address(
            "fe80::ca4a:a0ff:feaa:bb03%2",
            IpAddr::V6(ll)
        ));
    }
}
