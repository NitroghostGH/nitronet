mod bpf;
mod lan;
mod netlink;
mod packet;
mod procfs;
mod sampler;
mod text;
mod ui;

use std::error::Error;
use std::process::ExitCode;
use std::time::Duration;

use sampler::{Owner, Sampler, Source};

const HELP: &str = "\
nitronet: shows open ports and per-program network traffic

USAGE:
    nitronet [OPTIONS]

OPTIONS:
    -i, --interval <SECS>   Refresh interval in seconds [default: 1]
        --once              Take two samples one interval apart, print a text report, and exit
        --scan              Scan the local network for devices, print them, and exit
        --no-ebpf           Don't load eBPF programs; use TCP-only tcp_info counters
    -h, --help              Show this help

As root, nitronet attaches small eBPF programs to the root cgroup. They count
TCP and UDP bytes per socket, including sockets that open and close between
refreshes. They detach automatically when nitronet exits. Without root (or
with --no-ebpf), only TCP traffic is measured, from the kernel's per-socket
tcp_info counters, and other users' processes can't be attributed.";

struct Args {
    interval: Duration,
    once: bool,
    scan: bool,
    ebpf: bool,
}

fn parse_args() -> Result<Option<Args>, String> {
    let mut args = Args {
        interval: Duration::from_secs(1),
        once: false,
        scan: false,
        ebpf: true,
    };
    let mut it = std::env::args().skip(1);
    while let Some(a) = it.next() {
        match a.as_str() {
            "-h" | "--help" => return Ok(None),
            "--once" => args.once = true,
            "--no-ebpf" => args.ebpf = false,
            "--scan" => args.scan = true,
            "-i" | "--interval" => {
                let v = it.next().ok_or("--interval needs a value")?;
                let secs: f64 = v.parse().map_err(|_| format!("invalid interval: {v}"))?;
                if !(0.1..=3600.0).contains(&secs) {
                    return Err("interval must be between 0.1 and 3600 seconds".into());
                }
                args.interval = Duration::from_secs_f64(secs);
            }
            other => return Err(format!("unknown argument: {other} (see --help)")),
        }
    }
    Ok(Some(args))
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("nitronet: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), Box<dyn Error>> {
    let Some(args) = parse_args()? else {
        println!("{HELP}");
        return Ok(());
    };
    if args.scan {
        print_devices(&lan::scan_blocking());
        return Ok(());
    }
    let mut sampler = Sampler::new(args.ebpf)?;
    // A failure other than missing permissions is worth showing in full (it may include the verifier log).
    if let Source::TcpInfo { reason } = sampler.source()
        && reason.starts_with("eBPF unavailable")
    {
        eprintln!("nitronet: {reason}\nnitronet: falling back to tcp_info (TCP only)");
    }
    let first = sampler.sample()?;

    if args.once {
        std::thread::sleep(args.interval);
        print_report(&sampler.sample()?);
        return Ok(());
    }

    let mut terminal = ratatui::init();
    let result = ui::run(&mut terminal, sampler, first, args.interval);
    ratatui::restore();
    Ok(result?)
}

fn print_report(s: &sampler::Snapshot) {
    use ui::{fmt_addr, human};

    if let Some((rx, tx)) = s.nic_rate {
        println!("NIC  down {}/s  up {}/s", human(rx), human(tx));
    }
    let source = match &s.source {
        Source::Ebpf {
            tracks_creators: true,
        } => "eBPF, TCP+UDP".to_string(),
        Source::Ebpf {
            tracks_creators: false,
        } => "eBPF, TCP+UDP, no creator tracking".to_string(),
        Source::TcpInfo { reason } => format!(
            "tcp_info, TCP only: {}",
            reason.lines().next().unwrap_or_default()
        ),
    };
    println!(
        "seen down {}/s  up {}/s  ({} sockets, {} closed during sample; {source})",
        human(s.seen_rate.0),
        human(s.seen_rate.1),
        s.sockets.len(),
        s.closed_sockets
    );
    if !s.is_root && s.hidden_procs > 0 {
        println!(
            "note: {} processes hidden; run as root to attribute them",
            s.hidden_procs
        );
    }

    let pid = |o: Owner| match o {
        Owner::Pid(p) => p.to_string(),
        _ => "-".into(),
    };

    println!(
        "\n{:>7}  {:<10} {:<16} {:<18} {:>10} {:>10}  {:>4}  LISTENING",
        "PID", "USER", "PROGRAM", "SERVICE", "DOWN/s", "UP/s", "SOCK"
    );
    let mut procs: Vec<_> = s.procs.iter().filter(|p| p.alive).collect();
    procs.sort_by(|a, b| {
        (b.rate_in + b.rate_out)
            .total_cmp(&(a.rate_in + a.rate_out))
            .then(a.owner.cmp(&b.owner))
    });
    for p in procs {
        let listening: Vec<String> = p
            .listening
            .iter()
            .map(|(pr, port)| format!("{}:{port}", pr.as_str()))
            .collect();
        println!(
            "{:>7}  {:<10.10} {:<16.16} {:<18.18} {:>10} {:>10}  {:>4}  {}",
            pid(p.owner),
            p.user,
            p.name,
            p.unit.as_deref().unwrap_or(""),
            human(p.rate_in),
            human(p.rate_out),
            p.sockets,
            listening.join(" ")
        );
    }

    let names: std::collections::HashMap<_, _> =
        s.procs.iter().map(|p| (p.owner, p.name.as_str())).collect();
    let mut listening: Vec<_> = s.sockets.iter().filter(|r| r.sock.is_listening()).collect();
    listening.sort_by_key(|r| (r.sock.local.port(), r.sock.proto));
    println!(
        "\n{:<5} {:<40} {:>7}  PROGRAM",
        "PROTO", "LISTENING ON", "PID"
    );
    for r in listening {
        println!(
            "{:<5} {:<40} {:>7}  {}",
            r.sock.proto.as_str(),
            fmt_addr(r.sock.local),
            pid(r.owner),
            names.get(&r.owner).copied().unwrap_or("?")
        );
    }
}

fn print_devices(s: &lan::LanState) {
    let Some(iface) = &s.iface else {
        eprintln!(
            "nitronet: {}",
            s.error.as_deref().unwrap_or("no usable network interface")
        );
        return;
    };
    let method = match s.method {
        Some(lan::Method::Arp) => "ARP sweep",
        Some(lan::Method::Ping) => "ping sweep + neighbor table (run as root for a full ARP sweep)",
        Some(lan::Method::Udp) => "UDP nudge + neighbor table (run as root for a full ARP sweep)",
        None => "not scanned",
    };
    let v6 = match (&s.ipv6_error, iface.range6()) {
        (Some(e), _) => format!(" · IPv6 failed: {e}"),
        (None, _) if !iface.has_ipv6() => " · no IPv6 on this interface".into(),
        (None, Some(r)) => format!(" + {r} (all-nodes ping)"),
        (None, None) => " + IPv6 link-local (all-nodes ping)".into(),
    };
    let ifname = text::clean(&iface.name);
    println!("{} on {} · {method}{v6}", iface.range(), ifname);
    if let Some(e) = &s.error {
        println!("note: {e}");
    }
    println!(
        "\n{:<15}  {:<17}  {:>8}  {:<28}  NAME",
        "IP", "MAC", "RTT", "VENDOR"
    );
    let mut devs: Vec<&lan::Device> = s.devices.values().filter(|d| d.online).collect();
    devs.sort_by_key(|d| (d.ipv4.is_none(), d.ipv4, d.ipv6.first().copied()));
    for d in devs {
        let vendor = match (&d.vendor, d.random_mac()) {
            (Some(v), _) => v.clone(),
            (None, true) => "(private address)".into(),
            (None, false) => String::new(),
        };
        let mut name = d.name.clone().unwrap_or_default();
        if d.is_self {
            name.push_str("  [this machine]");
        }
        if d.is_gateway {
            name.push_str("  [gateway]");
        }
        println!(
            "{:<15}  {:<17}  {:>8}  {:<28.28}  {name}",
            d.ipv4
                .map(|a| a.to_string())
                .unwrap_or_else(|| "(IPv6 only)".into()),
            d.mac
                .as_ref()
                .map(lan::discover::fmt_mac)
                .unwrap_or_default(),
            d.rtt
                .map(|r| format!("{:.1}ms", r.as_secs_f64() * 1000.0))
                .unwrap_or_default(),
            vendor,
        );
        for a in &d.ipv6 {
            println!("  {a}");
        }
    }
}
