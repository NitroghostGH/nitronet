# nitronet

A terminal UI that shows which ports are open, which program or systemd service owns each socket, and how much traffic (TCP and UDP) each one moves.

```
cargo build --release
sudo ./target/release/nitronet             # full mode: eBPF counting of TCP+UDP, every process attributed
./target/release/nitronet                  # unprivileged: TCP only (tcp_info), your own processes only
./target/release/nitronet --once           # plain-text report, good for scripts
./target/release/nitronet --no-ebpf        # root, but don't load eBPF
./target/release/nitronet --scan           # list the devices on your local network and exit
```

Keys: `?` help · `H` how it works (a diagram of what nitronet reads and sends, filled in with what it is doing on your machine; on the Packets tab it explains capture instead) · `q` quit · `/` filter (every word must match, `!word` excludes) · `tab` `←` `→` `1`-`4` switch view · `↑↓ PgUp PgDn Home End` move · `s` cycle sort · `r` reverse · `g` group processes by program · `l` listening sockets only · `p` check a device's ports · `R` rescan devices · `c` capture a program's packets (Processes) or stop (Packets) · on Packets: `i` sent/received · `e` all/with data/unencrypted · `f` conversations (`enter` opens one, `esc` goes back) · `t` payload as text or hex · `[` `]` scroll it · `x` clear · `enter` toggle detail pane · `space` pause. The mouse works too: click tabs and rows, scroll with the wheel. Hold shift to select text while mouse capture is on.

The UI uses truecolor and never paints the terminal background, so transparent terminals stay transparent. Set `NO_COLOR=1` for a monochrome version. Narrow terminals drop the less important columns, and below 70×22 the traffic graph collapses into a one-line header.

UI changes can be reviewed without a terminal: `cargo test snapshots -- --ignored` writes colored HTML renders of every view (from deterministic fixture data) to `target/snapshots/`.

## How it works

| What | Source |
|---|---|
| Socket list, states, uid, inode, cookie | netlink `NETLINK_SOCK_DIAG` (what `ss` uses), see `src/netlink.rs` |
| Bytes in/out (root) | eBPF `cgroup_skb` ingress/egress programs on the root cgroup add each packet's length to a map keyed by socket cookie, see `src/bpf.rs` |
| Creator of short-lived sockets (root) | eBPF `cgroup/sock_create` program records pid, uid and comm when each socket is created |
| Bytes in/out (fallback) | `tcp_info.bytes_received` / `bytes_acked` from the same sock_diag dump |
| Socket → process | `/proc/<pid>/fd/*` links to `socket:[inode]` |
| Process → service | innermost `.service` in `/proc/<pid>/cgroup` |
| NIC reference rate | `/proc/net/dev`, physical interfaces only (those with `/sys/class/net/<if>/device`) |

### The eBPF part

No `aya`, no clang, no libbpf. The programs (a few dozen instructions each) are assembled in Rust by a small label-resolving assembler and loaded with the raw `bpf(2)` syscall through `libc`. The struct offsets and constants were checked against `<linux/bpf.h>` with `offsetof()`.

Safety:
- The packet programs always return 1 (allow). Before attaching, each one is dry-run with `BPF_PROG_TEST_RUN` on a dummy packet, and nitronet refuses to attach if it would drop the packet. A unit test also checks that every jump lands inside the program and that every program ends in `r0 = 1; exit`.
- They're attached with **BPF links**, which belong to nitronet's file descriptors, so the kernel detaches them when nitronet exits. That includes `kill -9` (checked via `/proc/kallsyms`).
- The capture programs (below) are only attached while you're capturing something, and are detached when you stop.
- The map is an LRU hash capped at 65,536 sockets. Entries for closed sockets are deleted after their final bytes are counted.

If eBPF can't be loaded (not root, old kernel, or the verifier refuses), nitronet says why and falls back to tcp_info.

### Devices (LAN scanner)

The **Devices** tab lists what's on your local network. Nothing is sent until you first open it. After that it rescans every minute (`R` rescans now). It scans the subnet of the default-route interface, up to a /22. On a larger subnet it scans the /24 around your address.

| What | How |
|---|---|
| Discovery (root) | Raw ARP requests on an `AF_PACKET` socket, three passes. Retries only ask silent addresses, and go unicast to MACs the kernel already knows, because sleeping Wi-Fi phones often ignore broadcast ARP. Finds devices that block ping. |
| Discovery (no root) | Ping sweep over an unprivileged ICMP socket (UDP to the discard port if ping sockets are disabled). The kernel resolves every address, and MACs are read from its neighbor table (netlink `RTM_GETNEIGH`). Stale neighbor entries can make a device that just left look online. |
| Discovery (IPv6) | A /64 is far too big to sweep, so it pings the all-nodes multicast group `ff02::1`, which every IPv6 host joins. It does this once from the link-local address and once from each global address, because hosts answer from an address in the same scope. It runs alongside the IPv4 sweep, so it adds no time, and needs no root. MACs come from the IPv6 neighbor table. |
| One row per device | IPv4 and IPv6 addresses are joined by MAC, so a dual-stack device is one row. An address whose MAC the kernel hasn't learned yet is resolved with a UDP datagram, or decoded from an EUI-64 address. Hosts that ignore multicast ping (Windows) still get their IPv6 addresses from the neighbor table when IPv4 found them. |
| Names | `getnameinfo` reverse lookups, which on systemd-resolved include mDNS (`PS5-AABB03.local`) and LLMNR. Tried on IPv4 first, then IPv6. ISP-generated IPv6 names that just restate the address (`2001-db8-…ip6.example.net`) are ignored. |
| Vendor | MAC prefix looked up in the IEEE registry from the `hwdata` package (`/usr/share/hwdata/oui.txt`). Randomized "private" MACs are flagged instead. |
| Open ports | `p` on a device tries TCP connects to 25 common ports (ssh, http, smb, printers, Chromecast, AirPlay, Plex…). This only happens when asked. |

The detail pane also shows which of your programs are talking to the selected device, from the socket table.

### Packets (capture)

Press `c` on a program in the Processes tab to capture its packets, then watch them in the **Packets** tab (`4`). Press `c` again (on either tab) to stop. Needs root, since it uses eBPF.

| What | How |
|---|---|
| Choosing packets | Two more `cgroup_skb` programs (`src/bpf/capture.rs`) check each packet's socket: is its cookie on the capture list (refreshed from the socket table each second), or was it created by a captured program (the comm `sock_create` recorded)? The second check catches a new process from its very first packet, so a quick `curl` is seen in full, SYN included. |
| Copying | A matching packet's first 2 KB (from the IP header) go into an 8 MB BPF ring buffer that a reader thread drains. Packets from other programs are never copied. If a buffer fills, the packets are counted as dropped and shown in the panel border. |
| Decoding | `src/packet.rs`: IPv4/IPv6, TCP flags/seq/ack, UDP, ICMP, plus a summary of the payload: DNS questions and answers, the TLS server name from a ClientHello, HTTP request and status lines, QUIC packet types, SSH banners. Payload text is cut down to printable ASCII before it reaches the terminal, so a packet can't send escape sequences. |
| Labeling | Each packet is labeled **empty** (no payload: SYN, ACK, FIN), **plain** (DNS, HTTP, NTP, DHCP, an SSH greeting, a TLS ClientHello whose server name is in clear, or mostly-text payload), **encrypted** (TLS records, QUIC, any later packet of a connection already seen to be TLS/QUIC/SSH, conventional ports like 443/853/993/22, or high-entropy bytes), **compressed** (high-entropy bytes in an HTTP conversation, such as a gzip body, or data starting with gzip/zstd/xz magic) or **binary** (anything else). "Looks random" alone is never remembered for the connection, so plain text later in it still shows as plain. It's a guess from the bytes; nothing is decrypted. |
| Going through them | `i` shows sent, received or both. `e` shows all, only packets with data, or only unencrypted ones. `f` switches to **conversations**: one row per connection with packet and byte counts and what was readable in it (DNS names, TLS server names, HTTP lines), sortable with `s`; `enter` lists that conversation's packets and `esc` goes back. `t` shows the payload as text instead of hex. The filter takes several words, all of which must match, and `!word` excludes (`dns !mdns`). The border shows which filters are on and how many packets pass. |
| Showing | Newest at the bottom, and the list follows new packets while the last row is selected (`r` puts newest on top). The detail pane shows the decoded headers and a hex dump with the headers dimmed. The last 5000 packets are kept in memory, and nothing is written to disk. |

Most traffic is encrypted (TLS, QUIC), so you see who a program talks to, when, and how much, but not what it says. DNS lookups usually come from `systemd-resolved` rather than the program itself, so capture that too to see them.

### What the numbers mean

- **eBPF mode:** bytes at the IP layer (including headers and retransmits) for TCP and UDP, counted from when nitronet started. The "attributed" header total should be close to the NIC total, with loopback traffic as the main difference.
- **tcp_info mode:** TCP payload bytes. On the Sockets tab, **↓/↑ bytes** cover the socket's whole lifetime.
- **↓/↑ total** on the Processes tab is what nitronet has counted for that program since it started. Exited processes stay listed, greyed out.

## Known limits

- In tcp_info mode, UDP isn't measured and sockets that open and close between samples are missed. eBPF mode covers both.
- The port list (sock_diag) only covers the current network namespace. eBPF still counts container traffic and attributes it by creating pid and comm, but container sockets don't appear on the Sockets tab.
- IPv6 discovery finds hosts that answer multicast ping or that the kernel has talked to recently. A device that does neither, and has no IPv4 address, won't show.
- Packet capture sees what the program's sockets send and receive at the IP layer. Outgoing TCP shows as large batches (up to 64 KB) before the network card splits them into segments. Only the first 2 KB of each is kept.
- Loopback traffic is counted in eBPF mode (both directions, since the packet passes egress and then ingress).

## Dependencies

The only direct dependencies are `ratatui` (default features off, only the `crossterm` backend) and `libc`. crossterm already pulls in `libc`, so listing it directly adds nothing. Netlink, eBPF loading, the ring buffer reader, packet decoding, /proc parsing, argument parsing and formatting are written by hand against std and libc. About 63 crates are compiled on Linux, all of them from ratatui/crossterm. `Cargo.lock` has more entries because it also pins Windows-only crates that never get built here. Build with `--locked` to keep the lockfile fixed.
