//! Minimal NETLINK_SOCK_DIAG client. This is the same kernel interface `ss`
//! uses to list sockets. It is written by hand on top of `libc` (already in
//! the tree through crossterm), so no netlink crate is needed.
//!
//! Layouts come from <linux/netlink.h>, <linux/inet_diag.h> and <linux/tcp.h>.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

const NETLINK_SOCK_DIAG: libc::c_int = 4;
const SOCK_DIAG_BY_FAMILY: u16 = 20;
const NLM_F_REQUEST: u16 = 0x01;
const NLM_F_DUMP: u16 = 0x300;
const NLMSG_ERROR: u16 = 2;
const NLMSG_DONE: u16 = 3;
const INET_DIAG_INFO: u16 = 2;
const NLA_TYPE_MASK: u16 = 0x3fff;

const NLMSG_HDRLEN: usize = 16;
/// struct inet_diag_req_v2
const REQ_LEN: usize = 56;
/// struct inet_diag_msg
const MSG_LEN: usize = 72;
/// Offsets into struct tcp_info. These fields exist since Linux 4.1.
const TCPI_BYTES_ACKED: usize = 120;
const TCPI_BYTES_RECEIVED: usize = 128;

pub const TCP_ESTABLISHED: u8 = 1;
pub const TCP_CLOSE: u8 = 7;
pub const TCP_LISTEN: u8 = 10;

#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub enum Proto {
    Tcp,
    Udp,
}

impl Proto {
    pub fn as_str(self) -> &'static str {
        match self {
            Proto::Tcp => "tcp",
            Proto::Udp => "udp",
        }
    }
}

#[derive(Clone, Debug)]
pub struct SockInfo {
    pub proto: Proto,
    pub state: u8,
    pub local: SocketAddr,
    pub remote: SocketAddr,
    pub uid: u32,
    /// Socket inode. It is 0 for sockets that no fd owns, such as TIME_WAIT.
    pub inode: u32,
    /// Kernel-unique socket id, which stays the same for the socket's lifetime.
    pub cookie: u64,
    /// Bytes the peer acknowledged over this socket's lifetime (TCP only).
    pub bytes_out: Option<u64>,
    /// Bytes received over this socket's lifetime (TCP only).
    pub bytes_in: Option<u64>,
}

impl SockInfo {
    /// True for a TCP socket that is listening, or a UDP socket that is
    /// bound but not connected (the UDP form of "listening").
    pub fn is_listening(&self) -> bool {
        match self.proto {
            Proto::Tcp => self.state == TCP_LISTEN,
            Proto::Udp => self.state == TCP_CLOSE && self.remote.port() == 0,
        }
    }

    pub fn state_str(&self) -> &'static str {
        if self.proto == Proto::Udp {
            return if self.state == TCP_ESTABLISHED {
                "ESTAB"
            } else {
                "UNCONN"
            };
        }
        match self.state {
            1 => "ESTAB",
            2 => "SYN-SENT",
            3 => "SYN-RECV",
            4 => "FIN-WAIT-1",
            5 => "FIN-WAIT-2",
            6 => "TIME-WAIT",
            7 => "CLOSE",
            8 => "CLOSE-WAIT",
            9 => "LAST-ACK",
            10 => "LISTEN",
            11 => "CLOSING",
            12 => "NEW-SYN-RECV",
            _ => "?",
        }
    }
}

pub struct Diag {
    fd: OwnedFd,
    seq: u32,
    buf: Vec<u8>,
}

impl Diag {
    pub fn open() -> io::Result<Self> {
        // SAFETY: plain syscall. Its result is checked before being wrapped.
        let fd = unsafe {
            libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_DGRAM | libc::SOCK_CLOEXEC,
                NETLINK_SOCK_DIAG,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            // SAFETY: fd is a fresh, valid descriptor that we own.
            fd: unsafe { OwnedFd::from_raw_fd(fd) },
            seq: 0,
            // The kernel caps netlink dump messages at 32 KiB, so 64 KiB is always enough.
            buf: vec![0; 64 * 1024],
        })
    }

    /// Dumps every TCP and UDP socket (IPv4 and IPv6) in this network namespace.
    pub fn dump_all(&mut self) -> io::Result<Vec<SockInfo>> {
        let mut out = Vec::new();
        for proto in [Proto::Tcp, Proto::Udp] {
            for family in [libc::AF_INET, libc::AF_INET6] {
                self.dump(proto, family as u8, &mut out)?;
            }
        }
        Ok(out)
    }

    fn dump(&mut self, proto: Proto, family: u8, out: &mut Vec<SockInfo>) -> io::Result<()> {
        self.seq = self.seq.wrapping_add(1);
        let seq = self.seq;

        let mut req = [0u8; NLMSG_HDRLEN + REQ_LEN];
        req[0..4].copy_from_slice(&((NLMSG_HDRLEN + REQ_LEN) as u32).to_ne_bytes());
        req[4..6].copy_from_slice(&SOCK_DIAG_BY_FAMILY.to_ne_bytes());
        req[6..8].copy_from_slice(&(NLM_F_REQUEST | NLM_F_DUMP).to_ne_bytes());
        req[8..12].copy_from_slice(&seq.to_ne_bytes());
        let r = &mut req[NLMSG_HDRLEN..];
        r[0] = family;
        r[1] = match proto {
            Proto::Tcp => libc::IPPROTO_TCP as u8,
            Proto::Udp => libc::IPPROTO_UDP as u8,
        };
        // Extensions bitmask: ask for tcp_info. UDP has no byte counters to report.
        r[2] = match proto {
            Proto::Tcp => 1 << (INET_DIAG_INFO - 1),
            Proto::Udp => 0,
        };
        r[4..8].copy_from_slice(&u32::MAX.to_ne_bytes()); // all states

        // SAFETY: sockaddr_nl is plain data, and all zeroes is a valid value.
        let mut addr: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        addr.nl_family = libc::AF_NETLINK as libc::sa_family_t;
        // SAFETY: the pointers and lengths describe live, correctly sized buffers.
        let sent = unsafe {
            libc::sendto(
                self.fd.as_raw_fd(),
                req.as_ptr().cast(),
                req.len(),
                0,
                (&raw const addr).cast(),
                size_of::<libc::sockaddr_nl>() as libc::socklen_t,
            )
        };
        if sent < 0 {
            return Err(io::Error::last_os_error());
        }

        loop {
            // SAFETY: buf is a live, writable buffer of buf.len() bytes.
            let n = unsafe {
                libc::recv(
                    self.fd.as_raw_fd(),
                    self.buf.as_mut_ptr().cast(),
                    self.buf.len(),
                    0,
                )
            };
            if n < 0 {
                let e = io::Error::last_os_error();
                if e.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(e);
            }
            let data = &self.buf[..n as usize];
            let mut off = 0;
            while off + NLMSG_HDRLEN <= data.len() {
                let len = u32_at(data, off) as usize;
                if len < NLMSG_HDRLEN || off + len > data.len() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "bad netlink message length",
                    ));
                }
                let ty = u16_at(data, off + 4);
                let msg_seq = u32_at(data, off + 8);
                let body = &data[off + NLMSG_HDRLEN..off + len];
                off += align4(len);
                if msg_seq != seq {
                    continue;
                }
                match ty {
                    NLMSG_DONE => return Ok(()),
                    NLMSG_ERROR => {
                        let err = if body.len() >= 4 {
                            u32_at(body, 0) as i32
                        } else {
                            0
                        };
                        if err != 0 {
                            return Err(io::Error::from_raw_os_error(-err));
                        }
                    }
                    SOCK_DIAG_BY_FAMILY => {
                        if let Some(s) = parse_msg(proto, body) {
                            out.push(s);
                        }
                    }
                    _ => {}
                }
            }
        }
    }
}

fn parse_msg(proto: Proto, m: &[u8]) -> Option<SockInfo> {
    if m.len() < MSG_LEN {
        return None;
    }
    let family = m[0] as libc::c_int;
    let ip = |b: &[u8]| -> Option<IpAddr> {
        match family {
            libc::AF_INET => Some(IpAddr::V4(Ipv4Addr::new(b[0], b[1], b[2], b[3]))),
            libc::AF_INET6 => Some(IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(b).ok()?))),
            _ => None,
        }
    };
    // inet_diag_sockid: the ports are big-endian; the addresses are raw network-order bytes.
    let sport = u16::from_be_bytes([m[4], m[5]]);
    let dport = u16::from_be_bytes([m[6], m[7]]);
    let local = SocketAddr::new(ip(&m[8..24])?, sport);
    let remote = SocketAddr::new(ip(&m[24..40])?, dport);
    let cookie = u32_at(m, 44) as u64 | (u32_at(m, 48) as u64) << 32;

    let mut info = SockInfo {
        proto,
        state: m[1],
        local,
        remote,
        uid: u32_at(m, 64),
        inode: u32_at(m, 68),
        cookie,
        bytes_out: None,
        bytes_in: None,
    };

    // Walk the attributes (struct rtattr) that follow the fixed message.
    let mut off = MSG_LEN;
    while off + 4 <= m.len() {
        let alen = u16_at(m, off) as usize;
        let aty = u16_at(m, off + 2) & NLA_TYPE_MASK;
        if alen < 4 || off + alen > m.len() {
            break;
        }
        let payload = &m[off + 4..off + alen];
        if aty == INET_DIAG_INFO && payload.len() >= TCPI_BYTES_RECEIVED + 8 {
            info.bytes_out = Some(u64_at(payload, TCPI_BYTES_ACKED));
            info.bytes_in = Some(u64_at(payload, TCPI_BYTES_RECEIVED));
        }
        off += align4(alen);
    }
    Some(info)
}

const fn align4(n: usize) -> usize {
    (n + 3) & !3
}

fn u16_at(b: &[u8], o: usize) -> u16 {
    u16::from_ne_bytes([b[o], b[o + 1]])
}

fn u32_at(b: &[u8], o: usize) -> u32 {
    u32::from_ne_bytes(b[o..o + 4].try_into().unwrap())
}

fn u64_at(b: &[u8], o: usize) -> u64 {
    u64::from_ne_bytes(b[o..o + 8].try_into().unwrap())
}
