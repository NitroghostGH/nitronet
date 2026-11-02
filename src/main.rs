mod bpf;
mod netlink;
mod procfs;
mod sampler;
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
    ebpf: bool,
}

fn parse_args() -> Result<Option<Args>, String> {
    let mut args = Args {
        interval: Duration::from_secs(1),
        once: false,
        ebpf: true,
    };
    let mut it = std::env::args().skip(1);
    while let Some(a) = it.next() {
        match a.as_str() {
            "-h" | "--help" => return Ok(None),
            "--once" => args.once = true,
            "--no-ebpf" => args.ebpf = false,
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
