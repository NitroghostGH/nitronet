//! Per-socket byte counting with eBPF, using no extra crates. The bytecode is
//! assembled below by hand and loaded through the raw bpf(2) syscall.
//!
//! Three small programs run, all attached to the root cgroup (so every process):
//!   * cgroup_skb ingress / egress: add each packet's length to the map entry
//!     for its socket cookie (the same id `sock_diag` reports). TCP and UDP alike.
//!   * cgroup/sock_create: when a socket is created, record the creating pid,
//!     uid and comm. This lets us attribute sockets that close before we ever
//!     see them in a sock_diag dump. If the kernel rejects it, it is skipped.
//!
//! The programs are attached through BPF links, which are tied to our file
//! descriptors. The kernel detaches everything when nitronet exits, even on
//! SIGKILL. Before attaching, the packet programs are dry-run with
//! BPF_PROG_TEST_RUN to confirm they let the packet through.
//!
//! Constants and offsets are from <linux/bpf.h> and were checked with offsetof().

use std::collections::HashMap;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

mod capture;
pub use capture::{Capture, RawPacket};

// bpf(2) commands
const BPF_MAP_CREATE: libc::c_long = 0;
const BPF_MAP_LOOKUP_ELEM: libc::c_long = 1;
const BPF_MAP_UPDATE_ELEM: libc::c_long = 2;
const BPF_MAP_DELETE_ELEM: libc::c_long = 3;
const BPF_PROG_LOAD: libc::c_long = 5;
const BPF_PROG_TEST_RUN: libc::c_long = 10;
const BPF_MAP_LOOKUP_BATCH: libc::c_long = 24;
const BPF_LINK_CREATE: libc::c_long = 28;

const BPF_MAP_TYPE_HASH: u32 = 1;
const BPF_MAP_TYPE_ARRAY: u32 = 2;
const BPF_MAP_TYPE_LRU_HASH: u32 = 9;
const BPF_MAP_TYPE_RINGBUF: u32 = 27;
const BPF_PROG_TYPE_CGROUP_SKB: u32 = 8;
const BPF_PROG_TYPE_CGROUP_SOCK: u32 = 9;
const BPF_CGROUP_INET_INGRESS: u32 = 0;
const BPF_CGROUP_INET_EGRESS: u32 = 1;
const BPF_CGROUP_INET_SOCK_CREATE: u32 = 2;

// helper function ids
const FN_MAP_LOOKUP_ELEM: i32 = 1;
const FN_MAP_UPDATE_ELEM: i32 = 2;
const FN_KTIME_GET_NS: i32 = 5;
const FN_GET_CURRENT_PID_TGID: i32 = 14;
const FN_GET_CURRENT_UID_GID: i32 = 15;
const FN_GET_CURRENT_COMM: i32 = 16;
const FN_GET_SOCKET_COOKIE: i32 = 46;
const FN_SKB_LOAD_BYTES: i32 = 26;
const FN_GET_SOCKET_UID: i32 = 47;
const FN_RINGBUF_RESERVE: i32 = 131;
const FN_RINGBUF_SUBMIT: i32 = 132;
const BPF_ANY: i32 = 0;
const BPF_NOEXIST: i32 = 1;

const MAX_ENTRIES: u32 = 65536;

// Map value layout: struct { u64 rx; u64 tx; u32 uid; u32 pid; char comm[16]; }
const V_RX: i16 = 0;
const V_TX: i16 = 8;
const V_UID: i16 = 16;
const V_PID: i16 = 20;
const V_COMM: i16 = 24;
const VALUE_SIZE: usize = 40;

/// One map entry: everything we know about a socket cookie.
#[derive(Clone, Debug, Default)]
pub struct Entry {
    pub rx: u64,
    pub tx: u64,
    pub uid: u32,
    /// pid that created the socket, or 0 if it was created before nitronet started.
    pub pid: u32,
    pub comm: String,
}

pub struct Tracker {
    map: OwnedFd,
    /// True when the sock_create program loaded, so new sockets record their pid.
    pub tracks_creators: bool,
    // Dropping these detaches the programs.
    _links: Vec<OwnedFd>,
    _progs: Vec<OwnedFd>,
}

impl Tracker {
    pub fn start() -> io::Result<Self> {
        let map = create_map()?;
        let fd = map.as_raw_fd();

        let ingress = load(
            BPF_PROG_TYPE_CGROUP_SKB,
            BPF_CGROUP_INET_INGRESS,
            &skb_prog(fd, V_RX),
            "nn_ingress",
        )?;
        let egress = load(
            BPF_PROG_TYPE_CGROUP_SKB,
            BPF_CGROUP_INET_EGRESS,
            &skb_prog(fd, V_TX),
            "nn_egress",
        )?;
        dry_run(&ingress)?;
        dry_run(&egress)?;
        let sock_create = load(
            BPF_PROG_TYPE_CGROUP_SOCK,
            BPF_CGROUP_INET_SOCK_CREATE,
            &sock_create_prog(fd),
            "nn_sock_create",
        )
        .ok();

        let tracker = Self {
            map,
            tracks_creators: false,
            _links: Vec::new(),
            _progs: Vec::new(),
        };
        // The dry runs added entries for a dummy socket. Clear them before going live.
        for cookie in tracker.read_all()?.into_keys() {
            tracker.remove(cookie);
        }

        let cgroup = open_root_cgroup()?;
        let mut tracker = tracker;
        tracker
            ._links
            .push(link(&ingress, &cgroup, BPF_CGROUP_INET_INGRESS)?);
        tracker
            ._links
            .push(link(&egress, &cgroup, BPF_CGROUP_INET_EGRESS)?);
        if let Some(sc) = &sock_create
            && let Ok(l) = link(sc, &cgroup, BPF_CGROUP_INET_SOCK_CREATE)
        {
            tracker._links.push(l);
            tracker.tracks_creators = true;
        }
        tracker._progs.extend([ingress, egress]);
        tracker._progs.extend(sock_create);
        Ok(tracker)
    }

    /// Reads all entries. The counters are cumulative since the entry was created.
    pub fn read_all(&self) -> io::Result<HashMap<u64, Entry>> {
        const CHUNK: usize = 4096;
        let mut out = HashMap::new();
        let mut keys = vec![0u64; CHUNK];
        let mut values = vec![0u8; CHUNK * VALUE_SIZE];
        // The batch token for hash maps is a u32 bucket index. Use 8 bytes to be safe.
        let (mut token_in, mut token_out) = (0u64, 0u64);
        let mut first = true;
        loop {
            let mut a = Attr::new();
            a.u64(
                0,
                if first {
                    0
                } else {
                    (&raw const token_in) as u64
                },
            )
            .u64(8, (&raw mut token_out) as u64)
            .u64(16, keys.as_mut_ptr() as u64)
            .u64(24, values.as_mut_ptr() as u64)
            .u32(32, CHUNK as u32)
            .u32(36, self.map.as_raw_fd() as u32);
            let res = sys_bpf(BPF_MAP_LOOKUP_BATCH, &mut a);
            let count = a.get_u32(32) as usize;
            for i in 0..count.min(CHUNK) {
                out.insert(
                    keys[i],
                    parse_value(&values[i * VALUE_SIZE..(i + 1) * VALUE_SIZE]),
                );
            }
            match res {
                Ok(_) => {}
                Err(e) if e.raw_os_error() == Some(libc::ENOENT) => return Ok(out),
                Err(e) => return Err(e),
            }
            token_in = token_out;
            first = false;
        }
    }

    /// The entry for one socket, if eBPF has seen it.
    pub fn lookup(&self, cookie: u64) -> Option<Entry> {
        let mut v = [0u8; VALUE_SIZE];
        map_lookup(&self.map, &cookie.to_ne_bytes(), &mut v)
            .ok()
            .map(|()| parse_value(&v))
    }

    /// Starts capturing packets for chosen programs. See `capture.rs`.
    pub fn capture(&self) -> io::Result<Capture> {
        Capture::start(&self.map)
    }

    pub fn remove(&self, cookie: u64) {
        map_delete(&self.map, &cookie.to_ne_bytes());
    }
}

fn parse_value(v: &[u8]) -> Entry {
    let u64_at = |o: i16| u64::from_ne_bytes(v[o as usize..o as usize + 8].try_into().unwrap());
    let u32_at = |o: i16| u32::from_ne_bytes(v[o as usize..o as usize + 4].try_into().unwrap());
    let comm = &v[V_COMM as usize..V_COMM as usize + 16];
    let len = comm.iter().position(|&b| b == 0).unwrap_or(16);
    Entry {
        rx: u64_at(V_RX),
        tx: u64_at(V_TX),
        uid: u32_at(V_UID),
        pid: u32_at(V_PID),
        comm: crate::text::clean(&String::from_utf8_lossy(&comm[..len])),
    }
}

// ---------------------------------------------------------------- programs

/// Stack layout shared by both programs: the u64 cookie key at fp-8 and the
/// 40-byte value at fp-48.
const KEY: i16 = -8;
const VAL: i16 = -48;

/// Adds skb->len to the `field` counter (rx or tx) of the packet's socket.
/// It always returns 1, which lets the packet through.
fn skb_prog(map: RawFd, field: i16) -> Vec<Insn> {
    let mut a = Asm::default();
    a.i(mov(R6, R1)); // r6 = skb; callee-saved across helper calls
    a.i(call(FN_GET_SOCKET_COOKIE)); // r0 = cookie(skb->sk), 0 if no socket
    a.jeq(R0, 0, "out");
    a.i(stx_dw(R10, KEY, R0));

    // Fast path: the entry exists, so add atomically.
    a.lookup(map);
    a.jeq(R0, 0, "create");
    a.i(ldx_w(R1, R6, 0)); // skb->len
    a.i(atomic_add_dw(R0, field, R1));
    a.ja("out");

    // Slow path: create {len, uid}.
    a.label("create");
    a.zero_value();
    a.i(ldx_w(R1, R6, 0));
    a.i(stx_dw(R10, VAL + field, R1));
    a.i(mov(R1, R6));
    a.i(call(FN_GET_SOCKET_UID));
    a.i(stx_w(R10, VAL + V_UID, R0));
    a.update(map, BPF_NOEXIST);
    a.jeq(R0, 0, "out");

    // Another CPU created the entry first, so add to theirs.
    a.lookup(map);
    a.jeq(R0, 0, "out");
    a.i(ldx_w(R1, R6, 0));
    a.i(atomic_add_dw(R0, field, R1));

    a.label("out");
    a.i(mov_imm(R0, 1));
    a.i(exit());
    a.finish()
}

/// Records {pid, uid, comm} for every new socket. It always returns 1, which
/// allows the socket to be created.
fn sock_create_prog(map: RawFd) -> Vec<Insn> {
    let mut a = Asm::default();
    a.i(call(FN_GET_SOCKET_COOKIE)); // r1 = ctx (struct bpf_sock *)
    a.jeq(R0, 0, "out");
    a.i(stx_dw(R10, KEY, R0));
    a.zero_value();
    a.i(call(FN_GET_CURRENT_PID_TGID));
    a.i(rsh_imm(R0, 32)); // tgid = the userspace pid
    a.i(stx_w(R10, VAL + V_PID, R0));
    a.i(call(FN_GET_CURRENT_UID_GID));
    a.i(stx_w(R10, VAL + V_UID, R0)); // low 32 bits = uid
    a.i(mov(R1, R10));
    a.i(add_imm(R1, (VAL + V_COMM) as i32));
    a.i(mov_imm(R2, 16));
    a.i(call(FN_GET_CURRENT_COMM));
    a.update(map, BPF_ANY);
    a.label("out");
    a.i(mov_imm(R0, 1));
    a.i(exit());
    a.finish()
}

// ---------------------------------------------------------------- assembler

#[derive(Clone, Copy)]
#[repr(C)]
struct Insn {
    code: u8,
    regs: u8, // dst in the low nibble, src in the high nibble
    off: i16,
    imm: i32,
}

const R0: u8 = 0;
const R1: u8 = 1;
const R2: u8 = 2;
const R3: u8 = 3;
const R4: u8 = 4;
const R6: u8 = 6;
const R7: u8 = 7;
const R8: u8 = 8;
const R10: u8 = 10;

const fn insn(code: u8, dst: u8, src: u8, off: i16, imm: i32) -> Insn {
    Insn {
        code,
        regs: (src << 4) | dst,
        off,
        imm,
    }
}
const fn mov(dst: u8, src: u8) -> Insn {
    insn(0xbf, dst, src, 0, 0)
}
const fn mov_imm(dst: u8, imm: i32) -> Insn {
    insn(0xb7, dst, 0, 0, imm)
}
const fn add_imm(dst: u8, imm: i32) -> Insn {
    insn(0x07, dst, 0, 0, imm)
}
const fn rsh_imm(dst: u8, imm: i32) -> Insn {
    insn(0x77, dst, 0, 0, imm)
}
const fn ldx_w(dst: u8, src: u8, off: i16) -> Insn {
    insn(0x61, dst, src, off, 0)
}
const fn ldx_dw(dst: u8, src: u8, off: i16) -> Insn {
    insn(0x79, dst, src, off, 0)
}
const fn st_w(dst: u8, off: i16, imm: i32) -> Insn {
    insn(0x62, dst, 0, off, imm)
}
const fn stx_dw(dst: u8, off: i16, src: u8) -> Insn {
    insn(0x7b, dst, src, off, 0)
}
const fn stx_w(dst: u8, off: i16, src: u8) -> Insn {
    insn(0x63, dst, src, off, 0)
}
const fn st_dw(dst: u8, off: i16, imm: i32) -> Insn {
    insn(0x7a, dst, 0, off, imm)
}
/// lock *(u64 *)(dst + off) += src
const fn atomic_add_dw(dst: u8, off: i16, src: u8) -> Insn {
    insn(0xdb, dst, src, off, 0 /* BPF_ADD */)
}
const fn call(helper: i32) -> Insn {
    insn(0x85, 0, 0, 0, helper)
}
const fn exit() -> Insn {
    insn(0x95, 0, 0, 0, 0)
}

/// A tiny assembler with named labels, so jump offsets aren't counted by hand.
#[derive(Default)]
struct Asm {
    insns: Vec<Insn>,
    labels: HashMap<&'static str, usize>,
    fixups: Vec<(usize, &'static str)>,
}

impl Asm {
    fn i(&mut self, x: Insn) {
        self.insns.push(x);
    }
    fn label(&mut self, name: &'static str) {
        self.labels.insert(name, self.insns.len());
    }
    /// A conditional jump comparing `reg` with `imm` (BPF_JMP | op | BPF_K).
    fn jmp(&mut self, op: u8, reg: u8, imm: i32, target: &'static str) {
        self.fixups.push((self.insns.len(), target));
        self.i(insn(op | 0x05, reg, 0, 0, imm));
    }
    fn jeq(&mut self, reg: u8, imm: i32, target: &'static str) {
        self.jmp(0x10, reg, imm, target);
    }
    /// Jumps if dst == src (BPF_JMP | BPF_JEQ | BPF_X).
    fn jeq_reg(&mut self, dst: u8, src: u8, target: &'static str) {
        self.fixups.push((self.insns.len(), target));
        self.i(insn(0x1d, dst, src, 0, 0));
    }
    fn jne(&mut self, reg: u8, imm: i32, target: &'static str) {
        self.jmp(0x50, reg, imm, target);
    }
    /// Unsigned reg < imm.
    fn jlt(&mut self, reg: u8, imm: i32, target: &'static str) {
        self.jmp(0xa0, reg, imm, target);
    }
    /// Unsigned reg <= imm.
    fn jle(&mut self, reg: u8, imm: i32, target: &'static str) {
        self.jmp(0xb0, reg, imm, target);
    }
    fn ja(&mut self, target: &'static str) {
        self.fixups.push((self.insns.len(), target));
        self.i(insn(0x05, 0, 0, 0, 0));
    }
    /// r1 = map (ld_imm64 with BPF_PSEUDO_MAP_FD, which takes two slots)
    fn ld_map(&mut self, map: RawFd) {
        self.i(insn(0x18, R1, 1, 0, map));
        self.i(insn(0, 0, 0, 0, 0));
    }
    /// r0 = bpf_map_lookup_elem(map, fp+KEY)
    fn lookup(&mut self, map: RawFd) {
        self.ld_map(map);
        self.i(mov(R2, R10));
        self.i(add_imm(R2, KEY as i32));
        self.i(call(FN_MAP_LOOKUP_ELEM));
    }
    /// r0 = bpf_map_update_elem(map, fp+KEY, fp+VAL, flags)
    fn update(&mut self, map: RawFd, flags: i32) {
        self.ld_map(map);
        self.i(mov(R2, R10));
        self.i(add_imm(R2, KEY as i32));
        self.i(mov(R3, R10));
        self.i(add_imm(R3, VAL as i32));
        self.i(mov_imm(R4, flags));
        self.i(call(FN_MAP_UPDATE_ELEM));
    }
    fn zero_value(&mut self) {
        for o in (0..VALUE_SIZE as i16).step_by(8) {
            self.i(st_dw(R10, VAL + o, 0));
        }
    }
    fn finish(mut self) -> Vec<Insn> {
        for (at, name) in self.fixups {
            let target = self.labels[name];
            self.insns[at].off = (target as isize - at as isize - 1) as i16;
        }
        self.insns
    }
}

// ---------------------------------------------------------------- syscalls

/// union bpf_attr is 168 bytes as of these headers. The kernel accepts any
/// size and requires the bytes it doesn't know about to be zero.
#[repr(C, align(8))]
struct Attr([u8; 168]);

impl Attr {
    fn new() -> Self {
        Attr([0; 168])
    }
    fn u32(&mut self, off: usize, v: u32) -> &mut Self {
        self.0[off..off + 4].copy_from_slice(&v.to_ne_bytes());
        self
    }
    fn u64(&mut self, off: usize, v: u64) -> &mut Self {
        self.0[off..off + 8].copy_from_slice(&v.to_ne_bytes());
        self
    }
    fn get_u32(&self, off: usize) -> u32 {
        u32::from_ne_bytes(self.0[off..off + 4].try_into().unwrap())
    }
}

fn sys_bpf(cmd: libc::c_long, attr: &mut Attr) -> io::Result<RawFd> {
    // SAFETY: attr is a live, zero-padded bpf_attr. Any pointers stored in it
    // point to buffers that outlive this call.
    let r = unsafe { libc::syscall(libc::SYS_bpf, cmd, attr.0.as_mut_ptr(), attr.0.len()) };
    if r < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(r as RawFd)
    }
}

fn sys_bpf_fd(cmd: libc::c_long, attr: &mut Attr) -> io::Result<OwnedFd> {
    let fd = sys_bpf(cmd, attr)?;
    // SAFETY: on success these commands return a new fd that we own.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn create_map() -> io::Result<OwnedFd> {
    let mut a = Attr::new();
    a.u32(0, BPF_MAP_TYPE_LRU_HASH)
        .u32(4, 8)
        .u32(8, VALUE_SIZE as u32)
        .u32(12, MAX_ENTRIES);
    a.0[28..28 + 8].copy_from_slice(b"nitronet");
    sys_bpf_fd(BPF_MAP_CREATE, &mut a).map_err(|e| context(e, "creating eBPF map"))
}

/// Creates a map other than the main one.
fn new_map(ty: u32, key: u32, value: u32, max: u32, name: &str) -> io::Result<OwnedFd> {
    let mut a = Attr::new();
    a.u32(0, ty).u32(4, key).u32(8, value).u32(12, max);
    let n = name.len().min(15);
    a.0[28..28 + n].copy_from_slice(&name.as_bytes()[..n]);
    sys_bpf_fd(BPF_MAP_CREATE, &mut a).map_err(|e| context(e, &format!("creating eBPF map {name}")))
}

fn map_lookup(map: &OwnedFd, key: &[u8], value: &mut [u8]) -> io::Result<()> {
    let mut a = Attr::new();
    a.u32(0, map.as_raw_fd() as u32)
        .u64(8, key.as_ptr() as u64)
        .u64(16, value.as_mut_ptr() as u64);
    sys_bpf(BPF_MAP_LOOKUP_ELEM, &mut a).map(|_| ())
}

fn map_update(map: &OwnedFd, key: &[u8], value: &[u8]) -> io::Result<()> {
    let mut a = Attr::new();
    a.u32(0, map.as_raw_fd() as u32)
        .u64(8, key.as_ptr() as u64)
        .u64(16, value.as_ptr() as u64)
        .u64(24, BPF_ANY as u64);
    sys_bpf(BPF_MAP_UPDATE_ELEM, &mut a).map(|_| ())
}

fn map_delete(map: &OwnedFd, key: &[u8]) {
    let mut a = Attr::new();
    a.u32(0, map.as_raw_fd() as u32).u64(8, key.as_ptr() as u64);
    let _ = sys_bpf(BPF_MAP_DELETE_ELEM, &mut a);
}

fn load(prog_type: u32, attach_type: u32, insns: &[Insn], name: &str) -> io::Result<OwnedFd> {
    const LICENSE: &[u8] = b"Dual MIT/GPL\0";
    let attempt = |log: Option<&mut Vec<u8>>| {
        let mut a = Attr::new();
        a.u32(0, prog_type)
            .u32(4, insns.len() as u32)
            .u64(8, insns.as_ptr() as u64)
            .u64(16, LICENSE.as_ptr() as u64)
            .u32(68, attach_type);
        let n = name.len().min(15);
        a.0[48..48 + n].copy_from_slice(&name.as_bytes()[..n]);
        if let Some(log) = log {
            a.u32(24, 1)
                .u32(28, log.len() as u32)
                .u64(32, log.as_mut_ptr() as u64);
        }
        sys_bpf_fd(BPF_PROG_LOAD, &mut a)
    };
    attempt(None).map_err(|e| {
        // Load again with the verifier log on, to explain the failure.
        let mut log = vec![0u8; 64 * 1024];
        let _ = attempt(Some(&mut log));
        let end = log.iter().position(|&b| b == 0).unwrap_or(log.len());
        let text = String::from_utf8_lossy(&log[..end]);
        let tail: Vec<&str> = text
            .lines()
            .rev()
            .take(6)
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect();
        context(
            e,
            &format!("loading eBPF program {name}\n{}", tail.join("\n")),
        )
    })
}

/// Runs a packet program once on a dummy IPv4 packet and checks that it
/// returns 1 (allow). This is a final guard against attaching something that
/// drops traffic.
fn dry_run(prog: &OwnedFd) -> io::Result<()> {
    let mut pkt = [0u8; 14 + 20];
    pkt[12] = 0x08; // ethertype IPv4
    pkt[14] = 0x45; // IPv4, 20-byte header
    pkt[17] = 20; // total length
    let mut a = Attr::new();
    a.u32(0, prog.as_raw_fd() as u32)
        .u32(8, pkt.len() as u32)
        .u64(16, pkt.as_ptr() as u64)
        .u32(32, 2);
    sys_bpf(BPF_PROG_TEST_RUN, &mut a).map_err(|e| context(e, "dry-running eBPF program"))?;
    match a.get_u32(4) {
        1 => Ok(()),
        r => Err(io::Error::other(format!(
            "eBPF self-test failed: program returned {r}, expected 1 (allow)"
        ))),
    }
}

fn open_root_cgroup() -> io::Result<OwnedFd> {
    // Pure cgroup v2 mounts at /sys/fs/cgroup; hybrid setups put it at .../unified.
    let mut last = io::Error::from(io::ErrorKind::NotFound);
    for path in [c"/sys/fs/cgroup", c"/sys/fs/cgroup/unified"] {
        // SAFETY: path is a valid NUL-terminated string.
        let fd = unsafe {
            libc::open(
                path.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
            )
        };
        if fd >= 0 {
            // SAFETY: fd is fresh and ours.
            return Ok(unsafe { OwnedFd::from_raw_fd(fd) });
        }
        last = io::Error::last_os_error();
    }
    Err(context(last, "opening the cgroup v2 root"))
}

fn link(prog: &OwnedFd, cgroup: &OwnedFd, attach_type: u32) -> io::Result<OwnedFd> {
    let mut a = Attr::new();
    a.u32(0, prog.as_raw_fd() as u32)
        .u32(4, cgroup.as_raw_fd() as u32)
        .u32(8, attach_type);
    sys_bpf_fd(BPF_LINK_CREATE, &mut a).map_err(|e| context(e, "attaching eBPF program to cgroup"))
}

fn context(e: io::Error, what: &str) -> io::Error {
    io::Error::new(e.kind(), format!("{what}: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jumps_resolve_and_programs_end_in_allow() {
        for prog in [skb_prog(3, V_RX), skb_prog(3, V_TX), sock_create_prog(3)] {
            let n = prog.len();
            // The last two instructions must be r0 = 1; exit.
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
    fn parses_value() {
        let mut v = [0u8; VALUE_SIZE];
        v[0..8].copy_from_slice(&100u64.to_ne_bytes());
        v[8..16].copy_from_slice(&7u64.to_ne_bytes());
        v[16..20].copy_from_slice(&1000u32.to_ne_bytes());
        v[20..24].copy_from_slice(&42u32.to_ne_bytes());
        v[24..28].copy_from_slice(b"curl");
        let e = parse_value(&v);
        assert_eq!(
            (e.rx, e.tx, e.uid, e.pid, e.comm.as_str()),
            (100, 7, 1000, 42, "curl")
        );
    }
}
