//! Packet capture for chosen programs, in eBPF with no extra crates.
//!
//! Two more cgroup_skb programs (ingress and egress) are attached only while
//! at least one program is being captured, and detached as soon as none are.
//! For each packet they check whether its socket belongs to a captured
//! program, in one of three ways:
//!   * the socket's cookie is in `socks`. nitronet fills this from the socket
//!     table each refresh, which covers sockets that existed before capture
//!     started and sockets a server accepted.
//!   * the main map says which thread created the socket (its comm and
//!     uid), and that name is in `comms` with that uid. This catches a new
//!     process from its very first packet, so even a short-lived `curl` is
//!     seen in full. The uid matters because any user can give a process
//!     any name: another user's "firefox" isn't the one you chose.
//!   * the main map says which process created it, and that pid is in
//!     `pids` (every running process with a captured name and user). This catches new
//!     sockets made by a thread with a different name, like Firefox's
//!     "Socket Thread", from their first packet too.
//!
//! A matching packet's first SNAP bytes (from the IP header on) are copied
//! into a ring buffer, which a reader thread drains. Packets from any other
//! program are left alone: their bytes are never copied anywhere.
//!
//! Like the counting programs, these always return 1 (let the packet through)
//! and are dry-run before attaching.

use std::collections::{HashMap, HashSet, VecDeque};
use std::io;
use std::os::fd::{AsRawFd, OwnedFd};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, SystemTime};

use super::*;

/// Ring buffer size. It holds about 4000 full-size records, which the reader
/// thread drains every few milliseconds under load.
const RING: u32 = 8 << 20;
/// Record layout: { u64 ktime_ns; u64 cookie; u32 len; u32 dir; u32 caplen; u32 pad; u8 data[SNAP] }
const R_TS: i16 = 0;
const R_COOKIE: i16 = 8;
const R_LEN: i16 = 16;
const R_DIR: i16 = 20;
const R_CAPLEN: i16 = 24;
const R_PAD: i16 = 28;
const HDR: usize = 32;
/// Bytes kept per packet. Enough for headers plus the start of the payload:
/// a whole DNS message, an HTTP request line, or a TLS ClientHello with its
/// server name (post-quantum key shares make those about 1.8 KB).
pub const SNAP: usize = 2048 - HDR;
const RECORD: usize = HDR + SNAP;
/// Packets waiting for the UI. Past this the oldest are dropped and counted.
const QUEUE: usize = 20_000;

const RINGBUF_BUSY: u32 = 1 << 31;
const RINGBUF_DISCARD: u32 = 1 << 30;

/// A captured packet as the kernel handed it over.
#[derive(Clone, Debug)]
pub struct RawPacket {
    pub at: SystemTime,
    pub cookie: u64,
    /// Length of the whole packet (from the IP header), which may be more than
    /// `data` holds. Outgoing TCP can be a 64 KB batch the NIC splits later.
    pub len: u32,
    pub outgoing: bool,
    /// The first bytes, starting at the IP header.
    pub data: Vec<u8>,
}

pub struct Capture {
    socks: Map,
    comms: Map,
    pids: Map,
    drops: Map,
    cur_socks: HashSet<u64>,
    cur_comms: HashSet<([u8; 16], u32)>,
    cur_pids: HashSet<u32>,
    queue: Arc<Mutex<VecDeque<RawPacket>>>,
    /// Packets dropped because nitronet's queue was full.
    lost: Arc<AtomicU64>,
    stop: Arc<AtomicBool>,
    reader: Option<JoinHandle<()>>,
    // Dropping these detaches the programs.
    _links: Vec<OwnedFd>,
    _progs: Vec<OwnedFd>,
}

impl Capture {
    pub(super) fn start(main: &Map) -> io::Result<Self> {
        let socks = Map::create(BPF_MAP_TYPE_HASH, 8, 1, 16384, "nn_cap_socks")?;
        // comm -> the uid it is captured for
        let comms = Map::create(BPF_MAP_TYPE_HASH, 16, 4, 256, "nn_cap_comms")?;
        let pids = Map::create(BPF_MAP_TYPE_HASH, 4, 1, 4096, "nn_cap_pids")?;
        let drops = Map::create(BPF_MAP_TYPE_ARRAY, 4, 8, 1, "nn_cap_drops")?;
        let ring = Map::create(BPF_MAP_TYPE_RINGBUF, 0, 0, RING, "nn_cap_ring")?;
        let maps = Maps {
            main: main.as_raw_fd(),
            socks: socks.as_raw_fd(),
            comms: comms.as_raw_fd(),
            pids: pids.as_raw_fd(),
            drops: drops.as_raw_fd(),
            ring: ring.as_raw_fd(),
        };
        let ingress = load(
            BPF_PROG_TYPE_CGROUP_SKB,
            BPF_CGROUP_INET_INGRESS,
            &capture_prog(&maps, false),
            "nn_cap_in",
        )?;
        let egress = load(
            BPF_PROG_TYPE_CGROUP_SKB,
            BPF_CGROUP_INET_EGRESS,
            &capture_prog(&maps, true),
            "nn_cap_out",
        )?;
        dry_run(&ingress)?;
        dry_run(&egress)?;
        let ring = Ring::map(ring.fd)?;

        let queue = Arc::new(Mutex::new(VecDeque::new()));
        let lost = Arc::new(AtomicU64::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let reader = {
            let (queue, lost, stop) = (queue.clone(), lost.clone(), stop.clone());
            std::thread::Builder::new()
                .name("capture".into())
                .spawn(move || read_loop(ring, &queue, &lost, &stop))?
        };
        let mut cap = Self {
            socks,
            comms,
            pids,
            drops,
            cur_socks: HashSet::new(),
            cur_comms: HashSet::new(),
            cur_pids: HashSet::new(),
            queue,
            lost,
            stop,
            reader: Some(reader),
            _links: Vec::new(),
            _progs: Vec::new(),
        };
        let cgroup = open_root_cgroup()?;
        cap._links
            .push(link(&ingress, &cgroup, BPF_CGROUP_INET_INGRESS)?);
        cap._links
            .push(link(&egress, &cgroup, BPF_CGROUP_INET_EGRESS)?);
        cap._progs.extend([ingress, egress]);
        Ok(cap)
    }

    /// Sets what to capture: program names (as in /proc/<pid>/comm) with the
    /// uid each is captured for, the pids of the processes that match, and
    /// the cookies of their current sockets. Only the differences are written.
    pub fn set_targets(
        &mut self,
        targets: &HashMap<String, u32>,
        pids: &HashSet<u32>,
        cookies: &HashSet<u64>,
    ) {
        let comms: HashSet<([u8; 16], u32)> =
            targets.iter().map(|(n, &uid)| (comm_key(n), uid)).collect();
        sync(&self.comms, &mut self.cur_comms, &comms, |(c, uid)| {
            (c.to_vec(), uid.to_ne_bytes().to_vec())
        });
        // pid 0 marks sockets created before nitronet started.
        let pids: HashSet<u32> = pids.iter().copied().filter(|&p| p != 0).collect();
        sync(&self.pids, &mut self.cur_pids, &pids, |p| {
            (p.to_ne_bytes().to_vec(), vec![1])
        });
        sync(&self.socks, &mut self.cur_socks, cookies, |c| {
            (c.to_ne_bytes().to_vec(), vec![1])
        });
    }

    /// Takes the packets captured since the last call, oldest first.
    pub fn take(&self) -> Vec<RawPacket> {
        let mut q = self.queue.lock().unwrap_or_else(|e| e.into_inner());
        q.drain(..).collect()
    }

    /// Packets matched but not kept because a buffer was full.
    pub fn dropped(&self) -> u64 {
        let mut v = [0u8; 8];
        let kernel = match self.drops.lookup(&0u32.to_ne_bytes(), &mut v) {
            Ok(()) => u64::from_ne_bytes(v),
            Err(_) => 0,
        };
        kernel + self.lost.load(Ordering::Relaxed)
    }
}

impl Drop for Capture {
    fn drop(&mut self) {
        // Detach first so nothing new arrives, then stop the reader.
        self._links.clear();
        self.stop.store(true, Ordering::Relaxed);
        if let Some(r) = self.reader.take() {
            let _ = r.join();
        }
    }
}

/// Makes `map` (recorded in `cur`) hold the entries in `want`; `bytes` gives
/// an entry's (key, value). A full map just means some entries are missing,
/// so failed inserts are skipped and tried again next time.
fn sync<K: Copy + Eq + std::hash::Hash>(
    map: &Map,
    cur: &mut HashSet<K>,
    want: &HashSet<K>,
    bytes: impl Fn(&K) -> (Vec<u8>, Vec<u8>),
) {
    // Deletes go first, so an entry whose value changed is written afresh.
    for k in cur.difference(want) {
        map.delete(&bytes(k).0);
    }
    cur.retain(|k| want.contains(k));
    for k in want {
        let (key, value) = bytes(k);
        if !cur.contains(k) && map.update(&key, &value).is_ok() {
            cur.insert(*k);
        }
    }
}

/// /proc/<pid>/comm and the kernel's task comm are the same 15 bytes plus a NUL.
fn comm_key(name: &str) -> [u8; 16] {
    let mut k = [0u8; 16];
    let b = name.as_bytes();
    let n = b.len().min(15);
    k[..n].copy_from_slice(&b[..n]);
    k
}

// ---------------------------------------------------------------- program

struct Maps {
    main: RawFd,
    socks: RawFd,
    comms: RawFd,
    pids: RawFd,
    drops: RawFd,
    ring: RawFd,
}

/// fp-16 holds a u32 zero, the key into the drops array.
const ZERO: i16 = -16;

/// Copies packets of captured sockets into the ring buffer. It always returns
/// 1, which lets the packet through.
fn capture_prog(m: &Maps, outgoing: bool) -> Vec<Insn> {
    let mut a = Asm::default();
    a.i(mov(R6, R1)); // r6 = skb
    a.i(call(FN_GET_SOCKET_COOKIE));
    a.jeq(R0, 0, "out");
    a.i(stx_dw(R10, KEY, R0));

    // Is this socket on the list?
    a.lookup(m.socks);
    a.jne(R0, 0, "capture");
    // Otherwise, was it created by a thread with a captured name, run by the
    // user it is captured for? key = &entry.comm, value = uid
    a.lookup(m.main);
    a.jeq(R0, 0, "out");
    a.i(mov(R7, R0)); // r7 = entry
    a.i(mov(R2, R0));
    a.i(add_imm(R2, V_COMM as i32));
    a.ld_map(m.comms);
    a.i(call(FN_MAP_LOOKUP_ELEM));
    a.jeq(R0, 0, "by_pid");
    a.i(ldx_w(R1, R0, 0)); // the uid captured for
    a.i(ldx_w(R2, R7, V_UID)); // the uid that created the socket
    a.jeq_reg(R1, R2, "capture");
    // Or by any thread of a captured process? key = &entry.pid
    a.label("by_pid");
    a.i(mov(R2, R7));
    a.i(add_imm(R2, V_PID as i32));
    a.ld_map(m.pids);
    a.i(call(FN_MAP_LOOKUP_ELEM));
    a.jeq(R0, 0, "out");

    // r8 = min(skb->len, SNAP), and at least 1
    a.label("capture");
    a.i(ldx_w(R8, R6, 0));
    a.jlt(R8, 1, "out");
    a.jle(R8, SNAP as i32, "sized");
    a.i(mov_imm(R8, SNAP as i32));
    a.label("sized");

    a.ld_map(m.ring);
    a.i(mov_imm(R2, RECORD as i32));
    a.i(mov_imm(R3, 0));
    a.i(call(FN_RINGBUF_RESERVE));
    a.jne(R0, 0, "reserved");
    // The ring is full: count the drop.
    a.i(st_w(R10, ZERO, 0));
    a.ld_map(m.drops);
    a.i(mov(R2, R10));
    a.i(add_imm(R2, ZERO as i32));
    a.i(call(FN_MAP_LOOKUP_ELEM));
    a.jeq(R0, 0, "out");
    a.i(mov_imm(R1, 1));
    a.i(atomic_add_dw(R0, 0, R1));
    a.ja("out");

    a.label("reserved");
    a.i(mov(R7, R0)); // r7 = record
    a.i(call(FN_KTIME_GET_NS));
    a.i(stx_dw(R7, R_TS, R0));
    a.i(ldx_dw(R1, R10, KEY));
    a.i(stx_dw(R7, R_COOKIE, R1));
    a.i(ldx_w(R1, R6, 0));
    a.i(stx_w(R7, R_LEN, R1));
    a.i(st_w(R7, R_DIR, outgoing as i32));
    a.i(stx_w(R7, R_CAPLEN, R8));
    a.i(st_w(R7, R_PAD, 0));
    // bpf_skb_load_bytes(skb, 0, record + HDR, r8)
    a.i(mov(R1, R6));
    a.i(mov_imm(R2, 0));
    a.i(mov(R3, R7));
    a.i(add_imm(R3, HDR as i32));
    a.i(mov(R4, R8));
    a.i(call(FN_SKB_LOAD_BYTES));
    a.jeq(R0, 0, "submit");
    a.i(st_w(R7, R_CAPLEN, 0));
    a.label("submit");
    a.i(mov(R1, R7));
    a.i(mov_imm(R2, 0));
    a.i(call(FN_RINGBUF_SUBMIT));

    a.label("out");
    a.i(mov_imm(R0, 1));
    a.i(exit());
    a.finish()
}

// ---------------------------------------------------------------- ring buffer

/// A BPF ring buffer mapped into our memory. The kernel maps the data area
/// twice in a row, so a record that wraps around the end reads contiguously.
struct Ring {
    fd: OwnedFd,
    consumer: *mut u8,
    producer: *mut u8,
    page: usize,
}

// SAFETY: only the reader thread touches the mappings once it is spawned.
unsafe impl Send for Ring {}

impl Ring {
    fn map(fd: OwnedFd) -> io::Result<Self> {
        // SAFETY: sysconf has no preconditions.
        let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as usize;
        let mmap = |len: usize, prot: libc::c_int, off: usize| {
            // SAFETY: a fresh shared mapping of the ring fd; the kernel checks the bounds.
            let p = unsafe {
                libc::mmap(
                    std::ptr::null_mut(),
                    len,
                    prot,
                    libc::MAP_SHARED,
                    fd.as_raw_fd(),
                    off as libc::off_t,
                )
            };
            if p == libc::MAP_FAILED {
                Err(io::Error::last_os_error())
            } else {
                Ok(p as *mut u8)
            }
        };
        let consumer = mmap(page, libc::PROT_READ | libc::PROT_WRITE, 0)?;
        let producer = match mmap(page + 2 * RING as usize, libc::PROT_READ, page) {
            Ok(p) => p,
            Err(e) => {
                // SAFETY: consumer was mapped above with this length.
                unsafe { libc::munmap(consumer.cast(), page) };
                return Err(e);
            }
        };
        Ok(Ring {
            fd,
            consumer,
            producer,
            page,
        })
    }

    /// Hands each committed record to `f`, then frees its space.
    fn drain(&self, mut f: impl FnMut(&[u8])) {
        // SAFETY: both positions are aligned u64s at the start of their pages,
        // which stay mapped for our lifetime.
        let (cons_pos, prod_pos) = unsafe {
            (
                &*(self.consumer as *const AtomicU64),
                &*(self.producer as *const AtomicU64),
            )
        };
        // SAFETY: the data pages follow the producer page in the same mapping.
        let data = unsafe { self.producer.add(self.page) };
        let mask = RING as u64 - 1;
        let mut cons = cons_pos.load(Ordering::Acquire);
        let prod = prod_pos.load(Ordering::Acquire);
        while cons < prod {
            // SAFETY: cons & mask is inside the ring, and record headers are
            // 8-byte aligned.
            let hdr = unsafe { &*(data.add((cons & mask) as usize) as *const AtomicU32) };
            let word = hdr.load(Ordering::Acquire);
            if word & RINGBUF_BUSY != 0 {
                break; // still being written
            }
            let len = (word & !(RINGBUF_BUSY | RINGBUF_DISCARD)) as usize;
            // Our program only reserves RECORD bytes. Anything longer means
            // the ring is not what we think it is: stop rather than read past it.
            if len > RECORD {
                break;
            }
            if word & RINGBUF_DISCARD == 0 {
                // SAFETY: the record is at most RECORD bytes, and the data
                // pages are mapped twice, so a record that wraps around the
                // end is still contiguous here.
                let rec = unsafe {
                    std::slice::from_raw_parts(data.add((cons & mask) as usize + 8), len)
                };
                f(rec);
            }
            cons += (len as u64 + 8 + 7) & !7;
            cons_pos.store(cons, Ordering::Release);
        }
    }

    fn wait(&self, timeout: Duration) {
        let mut pfd = libc::pollfd {
            fd: self.fd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: one valid pollfd.
        unsafe { libc::poll(&mut pfd, 1, timeout.as_millis() as libc::c_int) };
    }
}

impl Drop for Ring {
    fn drop(&mut self) {
        // SAFETY: these are the mappings made in `map`, with the same lengths.
        unsafe {
            libc::munmap(self.consumer.cast(), self.page);
            libc::munmap(self.producer.cast(), self.page + 2 * RING as usize);
        }
    }
}

fn read_loop(ring: Ring, queue: &Mutex<VecDeque<RawPacket>>, lost: &AtomicU64, stop: &AtomicBool) {
    let mut batch = Vec::new();
    while !stop.load(Ordering::Relaxed) {
        ring.wait(Duration::from_millis(100));
        // ktime_get_ns is CLOCK_MONOTONIC; turn it into wall-clock time.
        let (now, mono) = (SystemTime::now(), monotonic_ns());
        ring.drain(|rec| {
            if let Some(p) = parse_record(rec, now, mono) {
                batch.push(p);
            }
        });
        if batch.is_empty() {
            continue;
        }
        let mut q = queue.lock().unwrap_or_else(|e| e.into_inner());
        q.extend(batch.drain(..));
        if q.len() > QUEUE {
            let extra = q.len() - QUEUE;
            q.drain(..extra);
            lost.fetch_add(extra as u64, Ordering::Relaxed);
        }
    }
}

fn monotonic_ns() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: ts is a valid timespec to write into.
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64
}

fn parse_record(rec: &[u8], now: SystemTime, mono_now: u64) -> Option<RawPacket> {
    if rec.len() < HDR {
        return None;
    }
    let u64_at = |o: i16| u64::from_ne_bytes(rec[o as usize..o as usize + 8].try_into().unwrap());
    let u32_at = |o: i16| u32::from_ne_bytes(rec[o as usize..o as usize + 4].try_into().unwrap());
    let caplen = (u32_at(R_CAPLEN) as usize).min(rec.len() - HDR);
    let age = Duration::from_nanos(mono_now.saturating_sub(u64_at(R_TS)));
    Some(RawPacket {
        at: now.checked_sub(age).unwrap_or(now),
        cookie: u64_at(R_COOKIE),
        len: u32_at(R_LEN),
        outgoing: u32_at(R_DIR) != 0,
        data: rec[HDR..HDR + caplen].to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A ring laid out like the kernel's (consumer page, producer page, data),
    /// in anonymous memory, without the data area's double mapping.
    fn fake_ring() -> Ring {
        // SAFETY: sysconf has no preconditions.
        let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as usize;
        let anon = |len: usize| {
            // SAFETY: a fresh private anonymous mapping.
            let p = unsafe {
                libc::mmap(
                    std::ptr::null_mut(),
                    len,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                    -1,
                    0,
                )
            };
            assert_ne!(p, libc::MAP_FAILED);
            p as *mut u8
        };
        Ring {
            fd: OwnedFd::from(std::fs::File::open("/dev/null").unwrap()),
            consumer: anon(page),
            producer: anon(page + 2 * RING as usize),
            page,
        }
    }

    /// Writes a record header and data at ring position `pos`; returns the next.
    fn put(r: &Ring, pos: u64, word: u32, data: &[u8]) -> u64 {
        // SAFETY: pos is inside the data area, which follows the producer page.
        unsafe {
            let at = r.producer.add(r.page + pos as usize);
            (at as *mut u32).write(word);
            std::ptr::copy_nonoverlapping(data.as_ptr(), at.add(8), data.len());
        }
        pos + ((data.len() as u64 + 8 + 7) & !7)
    }

    fn positions(r: &Ring) -> (u64, u64) {
        // SAFETY: both pages start with an aligned u64.
        unsafe { (*(r.consumer as *const u64), *(r.producer as *const u64)) }
    }

    fn set_producer(r: &Ring, pos: u64) {
        // SAFETY: as above; the fake producer page is writable.
        unsafe { (r.producer as *mut u64).write(pos) };
    }

    #[test]
    fn ring_reader_skips_discarded_and_stops_at_busy_or_corrupt() {
        let r = fake_ring();
        // put returns where the next record starts.
        let two = put(&r, 0, 3, b"one");
        let three = put(&r, two, RINGBUF_DISCARD | 3, b"two");
        let four = put(&r, three, 5, b"three");
        let end = put(&r, four, RINGBUF_BUSY | 4, b"four");
        set_producer(&r, end);
        let mut got = Vec::new();
        r.drain(|rec| got.push(rec.to_vec()));
        assert_eq!(got, vec![b"one".to_vec(), b"three".to_vec()]);
        // Stopped at the record still being written.
        assert_eq!(positions(&r).0, four);

        // A length the program can't produce: stop there rather than read it.
        let r = fake_ring();
        let a = put(&r, 0, 2, b"ok");
        let end = put(&r, a, RECORD as u32 + 1, b"bad");
        set_producer(&r, end);
        let mut n = 0;
        r.drain(|_| n += 1);
        assert_eq!((n, positions(&r).0), (1, a));
    }

    #[test]
    fn program_jumps_resolve_and_end_in_allow() {
        let m = Maps {
            main: 3,
            socks: 4,
            comms: 5,
            pids: 8,
            drops: 6,
            ring: 7,
        };
        for out in [false, true] {
            let prog = capture_prog(&m, out);
            let n = prog.len();
            assert_eq!((prog[n - 2].code, prog[n - 2].imm), (0xb7, 1));
            assert_eq!(prog[n - 1].code, 0x95);
            for (i, ins) in prog.iter().enumerate() {
                if ins.code & 0x07 == 0x05 && ins.code != 0x85 && ins.code != 0x95 {
                    let t = i as isize + 1 + ins.off as isize;
                    assert!(ins.off > 0 && (t as usize) < n, "jump at {i} lands at {t}");
                }
            }
        }
    }

    #[test]
    fn parses_records_and_comm_keys() {
        let mut rec = vec![0u8; HDR + 4];
        rec[0..8].copy_from_slice(&1_000_000_000u64.to_ne_bytes());
        rec[8..16].copy_from_slice(&77u64.to_ne_bytes());
        rec[16..20].copy_from_slice(&1500u32.to_ne_bytes());
        rec[20..24].copy_from_slice(&1u32.to_ne_bytes());
        rec[24..28].copy_from_slice(&99u32.to_ne_bytes()); // claims more than is there
        rec[HDR..].copy_from_slice(&[0x45, 0, 0, 1]);
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(100);
        let p = parse_record(&rec, now, 3_000_000_000).unwrap();
        assert_eq!((p.cookie, p.len, p.outgoing), (77, 1500, true));
        assert_eq!(p.data, [0x45, 0, 0, 1]);
        assert_eq!(p.at, SystemTime::UNIX_EPOCH + Duration::from_secs(98));

        assert_eq!(&comm_key("curl")[..5], b"curl\0");
        assert_eq!(comm_key("a-very-long-program-name")[15], 0);
    }

    /// Needs root: sudo -E cargo test live_capture -- --ignored
    #[test]
    #[ignore = "needs root (eBPF)"]
    fn live_capture() {
        use std::net::UdpSocket;
        let tracker = Tracker::start().expect("eBPF (run as root)");
        let mut cap = tracker.capture().expect("capture");
        let rx = UdpSocket::bind("127.0.0.1:0").unwrap();
        let to = rx.local_addr().unwrap();

        // By cookie: a socket that existed before capture was set up.
        let old = UdpSocket::bind("127.0.0.1:0").unwrap();
        let mut cookie = 0u64;
        let mut len = 8 as libc::socklen_t;
        // SAFETY: SO_COOKIE writes a u64.
        unsafe {
            libc::getsockopt(
                old.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_COOKIE,
                (&raw mut cookie).cast(),
                &mut len,
            )
        };
        // By name: a socket created by a thread whose comm is on the list,
        // for this user. The same name captured for another user doesn't match.
        // SAFETY: getuid has no preconditions.
        let me = unsafe { libc::getuid() };
        let names = HashMap::from([
            ("nn_cap_test".to_string(), me),
            ("nn_cap_spoof".to_string(), me.wrapping_add(1)),
        ]);
        cap.set_targets(&names, &HashSet::new(), &HashSet::from([cookie]));
        old.send_to(b"by-cookie", to).unwrap();
        std::thread::Builder::new()
            .name("nn_cap_test".into())
            .spawn(move || {
                let s = UdpSocket::bind("127.0.0.1:0").unwrap();
                s.send_to(b"by-name", to).unwrap();
            })
            .unwrap()
            .join()
            .unwrap();
        std::thread::Builder::new()
            .name("nn_cap_spoof".into())
            .spawn(move || {
                let s = UdpSocket::bind("127.0.0.1:0").unwrap();
                s.send_to(b"spoofed", to).unwrap();
            })
            .unwrap()
            .join()
            .unwrap();
        // Not captured: an unrelated socket.
        UdpSocket::bind("127.0.0.1:0")
            .unwrap()
            .send_to(b"ignored", to)
            .unwrap();
        // By process: with this test's pid on the list, a new socket from a
        // thread with another name (like Firefox's "Socket Thread").
        let pids = HashSet::from([std::process::id()]);
        cap.set_targets(&names, &pids, &HashSet::from([cookie]));
        std::thread::Builder::new()
            .name("other thread".into())
            .spawn(move || {
                let s = UdpSocket::bind("127.0.0.1:0").unwrap();
                s.send_to(b"by-pid", to).unwrap();
            })
            .unwrap()
            .join()
            .unwrap();
        std::thread::sleep(Duration::from_millis(300));
        let got = cap.take();
        let payloads: Vec<(bool, String)> = got
            .iter()
            .map(|p| {
                (
                    p.outgoing,
                    String::from_utf8_lossy(&p.data[28..]).into_owned(),
                )
            })
            .collect();
        eprintln!("{payloads:?} dropped {}", cap.dropped());
        // Each captured send is seen leaving (egress); the receive is on `rx`,
        // which isn't captured.
        assert!(payloads.contains(&(true, "by-cookie".into())));
        assert!(payloads.contains(&(true, "by-name".into())));
        assert!(payloads.contains(&(true, "by-pid".into())));
        assert!(!payloads.iter().any(|(_, s)| s == "ignored"));
        assert!(!payloads.iter().any(|(_, s)| s == "spoofed"));
        assert!(
            got.iter()
                .all(|p| p.data[0] == 0x45 && p.len == p.data.len() as u32)
        );
    }
}
