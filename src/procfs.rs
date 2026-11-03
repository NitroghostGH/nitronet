//! Reads /proc and /sys with std only: maps socket inodes to processes, finds
//! systemd units, and reads interface counters.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::ErrorKind;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

#[derive(Clone, Debug)]
pub struct Process {
    pub name: String,
    /// The systemd service this process runs under, if any (e.g. "sshd").
    pub unit: Option<String>,
    pub uid: u32,
}

#[derive(Default)]
pub struct ProcMap {
    /// Socket inode -> pid. A socket shared across fork() goes to the lowest pid.
    pub owner: HashMap<u32, u32>,
    pub procs: HashMap<u32, Process>,
    /// Userspace processes whose fds we were not allowed to read.
    pub hidden: usize,
}

pub fn scan() -> ProcMap {
    let mut map = ProcMap::default();
    let Ok(dir) = fs::read_dir("/proc") else {
        return map;
    };
    let mut pids: Vec<u32> = dir
        .filter_map(|e| e.ok()?.file_name().to_str()?.parse().ok())
        .collect();
    pids.sort_unstable();

    for pid in pids {
        let fds = match fs::read_dir(format!("/proc/{pid}/fd")) {
            Ok(d) => d,
            Err(e) => {
                // Kernel threads have an empty cmdline, so don't count them as hidden.
                if e.kind() == ErrorKind::PermissionDenied
                    && fs::read(format!("/proc/{pid}/cmdline")).is_ok_and(|c| !c.is_empty())
                {
                    map.hidden += 1;
                }
                continue;
            }
        };
        let mut has_socket = false;
        for fd in fds.flatten() {
            let Ok(target) = fs::read_link(fd.path()) else {
                continue;
            };
            let inode = target
                .to_str()
                .and_then(|s| s.strip_prefix("socket:["))
                .and_then(|s| s.strip_suffix(']'))
                .and_then(|s| s.parse::<u32>().ok());
            if let Some(inode) = inode {
                map.owner.entry(inode).or_insert(pid);
                has_socket = true;
            }
        }
        if has_socket && let Some(p) = read_process(pid) {
            map.procs.insert(pid, p);
        }
    }
    map
}

/// The pids of every running process whose name (comm) is in `targets`,
/// run by the uid it maps to. Any user can name a process anything, so the
/// name alone doesn't say it is the program chosen.
pub fn pids_matching(targets: &HashMap<String, u32>) -> HashSet<u32> {
    let Ok(dir) = fs::read_dir("/proc") else {
        return HashSet::new();
    };
    dir.filter_map(|e| e.ok()?.file_name().to_str()?.parse::<u32>().ok())
        .filter(|pid| {
            let Ok(comm) = fs::read_to_string(format!("/proc/{pid}/comm")) else {
                return false;
            };
            let Some(&uid) = targets.get(crate::text::clean(comm.trim_end_matches('\n')).as_str())
            else {
                return false;
            };
            fs::metadata(format!("/proc/{pid}")).is_ok_and(|m| m.uid() == uid)
        })
        .collect()
}

/// Reads a process's name, service and uid. Returns None if it has exited.
pub fn read_process(pid: u32) -> Option<Process> {
    // Any user can set their own processes' names, escape codes included.
    let name = crate::text::clean(
        fs::read_to_string(format!("/proc/{pid}/comm"))
            .ok()?
            .trim_end_matches('\n'),
    );
    let unit = fs::read_to_string(format!("/proc/{pid}/cgroup"))
        .ok()
        .and_then(|s| unit_from_cgroup(&s));
    let uid = fs::metadata(format!("/proc/{pid}"))
        .map(|m| m.uid())
        .unwrap_or(u32::MAX);
    Some(Process { name, unit, uid })
}

/// cgroup v2 gives one line like "0::/system.slice/sshd.service". The process
/// belongs to a service only if the innermost cgroup is a .service. This way
/// apps launched inside user@1000.service are not all reported as "user@1000".
fn unit_from_cgroup(s: &str) -> Option<String> {
    let path = s.lines().find_map(|l| l.strip_prefix("0::"))?;
    let leaf = path.rsplit('/').next()?;
    // Users can create cgroups in their own systemd session, with any name.
    leaf.strip_suffix(".service").map(crate::text::clean)
}

/// uid -> user name from /etc/passwd (local users only).
pub fn users() -> HashMap<u32, String> {
    fs::read_to_string("/etc/passwd")
        .unwrap_or_default()
        .lines()
        .filter_map(|l| {
            let mut f = l.split(':');
            let name = f.next()?;
            let uid = f.nth(1)?.parse().ok()?;
            Some((uid, name.to_string()))
        })
        .collect()
}

/// Total (rx, tx) bytes over physical interfaces. An interface counts as
/// physical if it has a /sys/class/net/<if>/device link. Skipping virtual ones
/// (lo, bridges, veth, tun/wg) avoids counting the same packet twice.
pub fn nic_totals() -> Option<(u64, u64)> {
    let s = fs::read_to_string("/proc/net/dev").ok()?;
    let (mut rx, mut tx) = (0, 0);
    for line in s.lines().skip(2) {
        let Some((name, rest)) = line.split_once(':') else {
            continue;
        };
        if !Path::new("/sys/class/net")
            .join(name.trim())
            .join("device")
            .exists()
        {
            continue;
        }
        let f: Vec<u64> = rest
            .split_whitespace()
            .filter_map(|x| x.parse().ok())
            .collect();
        if f.len() >= 9 {
            rx += f[0];
            tx += f[8];
        }
    }
    Some((rx, tx))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cgroup_units() {
        assert_eq!(
            unit_from_cgroup("0::/system.slice/sshd.service\n").as_deref(),
            Some("sshd")
        );
        assert_eq!(
            unit_from_cgroup(
                "0::/user.slice/user-1000.slice/user@1000.service/session.slice/pipewire.service\n"
            )
            .as_deref(),
            Some("pipewire")
        );
        assert_eq!(
            unit_from_cgroup(
                "0::/user.slice/user-1000.slice/user@1000.service/app.slice/app-firefox-1.scope\n"
            ),
            None
        );
        // A user can name a cgroup in their own session with escape codes.
        assert_eq!(
            unit_from_cgroup("0::/user.slice/user@1000.service/\x1b[2Jx.service\n").as_deref(),
            Some("?[2Jx")
        );
    }
}
